/*
 * Copyright (C) 2001-2013 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <steely/version.h>
#include <steely/sched.h>
#include <steely/clock.h>
#include <steely/timer.h>
#include <steely/heap.h>
#include <steely/intr.h>
#include <steely/ppd.h>
#include <steely/pipe.h>
#include <steely/select.h>
#include <steely/vdso.h>
#include <steely/coreclk.h>
#include <steely/fd.h>
#include "rtdm/internal.h"
#include "posix/internal.h"
#include "procfs.h"

/**
 * @defgroup steely Steely
 *
 * Steely supplements the native Linux kernel in dual kernel
 * configurations. It deals with all time-critical activities, such as
 * handling interrupts, and scheduling real-time threads. The Steely
 * kernel has higher priority over all the native kernel activities.
 *
 * Steely provides an implementation of the POSIX and RTDM interfaces
 * based on a set of generic RTOS building blocks.
 */

static unsigned long clockfreq_arg;
module_param_named(clockfreq, clockfreq_arg, ulong, 0444);

#ifdef CONFIG_SMP
static unsigned long supported_cpus_arg = -1;
module_param_named(supported_cpus, supported_cpus_arg, ulong, 0444);
#endif /* CONFIG_SMP */

static unsigned long sysheap_size_arg;
module_param_named(sysheap_size, sysheap_size_arg, ulong, 0444);

static char init_state_arg[16] = "enabled";
module_param_string(state, init_state_arg, sizeof(init_state_arg), 0444);

static BLOCKING_NOTIFIER_HEAD(state_notifier_list);

struct steely_pipeline steely_pipeline;
EXPORT_SYMBOL_GPL(steely_pipeline);

DEFINE_PER_CPU(struct steely_machine_cpudata, steely_machine_cpudata);
EXPORT_PER_CPU_SYMBOL_GPL(steely_machine_cpudata);

atomic_t steely_runstate = ATOMIC_INIT(STEELY_STATE_WARMUP);
EXPORT_SYMBOL_GPL(steely_runstate);

struct steely_ppd steely_kernel_ppd = {
	.exe_path = "vmlinux",
};
EXPORT_SYMBOL_GPL(steely_kernel_ppd);

#ifdef CONFIG_STEELY_DEBUG
#define boot_debug_notice "[DEBUG]"
#else
#define boot_debug_notice ""
#endif

#ifdef CONFIG_ENABLE_DEFAULT_TRACERS
#define boot_trace_notice "[TRACE]"
#else
#define boot_trace_notice ""
#endif

#define boot_state_notice						\
	({								\
		realtime_core_state() == STEELY_STATE_STOPPED ?		\
			"[STOPPED]" : "";				\
	})

void steely_add_state_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_register(&state_notifier_list, nb);
}
EXPORT_SYMBOL_GPL(steely_add_state_chain);

void steely_remove_state_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&state_notifier_list, nb);
}
EXPORT_SYMBOL_GPL(steely_remove_state_chain);

void steely_call_state_chain(enum steely_run_states newstate)
{
	blocking_notifier_call_chain(&state_notifier_list, newstate, NULL);
}
EXPORT_SYMBOL_GPL(steely_call_state_chain);

static void sys_shutdown(void)
{
	struct xnthread *thread, *tmp;
	struct xnsched *sched;
	void *membase;
	int cpu;
	spl_t s;

	if (realtime_core_state() == STEELY_STATE_RUNNING)
		xnclock_core_release();

#ifdef CONFIG_SMP
	free_percpu_irq(IPIPE_RESCHEDULE_IPI, &steely_machine_cpudata);
#endif

	xnlock_get_irqsave(&nklock, s);

	/* NOTE: &nkthreadq can't be empty (root thread(s)). */
	list_for_each_entry_safe(thread, tmp, &nkthreadq, glink) {
		if (!xnthread_test_state(thread, XNROOT))
			xnthread_cancel(thread);
	}

	xnsched_run();

	for_each_online_cpu(cpu) {
		sched = xnsched_struct(cpu);
		xnsched_destroy(sched);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnregistry_cleanup();
	membase = xnheap_get_membase(&steely_heap);
	xnheap_destroy(&steely_heap);
	xnheap_vfree(membase);
}

static int __init mach_setup(void)
{
	int ret, sirq;

	if (steely_machine.init) {
		ret = steely_machine.init();
		if (ret) {
			printk(STEELY_ERR "machine.init() failed\n");
			return ret;
		}
	}

	irq_push_stage(&steely_pipeline.stage, "Steely");
	dovetail_get_hrclock(&steely_pipeline.clock_data);

	if (clockfreq_arg == 0)
		clockfreq_arg = steely_pipeline.clock_data.hrclock_freq;

	if (clockfreq_arg == 0) {
		printk(STEELY_ERR "null clock frequency? Aborting.\n");
		ret = -ENODEV;
		goto fail;
	}

	steely_pipeline.clock_freq = clockfreq_arg;

	sirq = irq_create_direct_mapping(synthetic_irq_domain);
	if (sirq == 0) {
		ret = -EAGAIN;
		goto fail;
	}

	steely_pipeline.escalate_virq = sirq;
	ret = request_percpu_irq_flags(sirq, __xnsched_run_handler,
				       "Steely domain escalation",
				       IRQF_PIPELINED,
				       &steely_machine_cpudata);
	if (ret)
		goto fail_escalate_request;

	ret = xnclock_init(steely_pipeline.clock_freq);
	if (ret)
		goto fail_clock;

	return 0;

fail_clock:
	free_percpu_irq(steely_pipeline.escalate_virq,
			&steely_machine_cpudata);
fail_escalate_request:
	irq_dispose_mapping(steely_pipeline.escalate_virq);
fail:
	irq_pop_stage(&steely_pipeline.stage);

	if (steely_machine.cleanup)
		steely_machine.cleanup();

	return ret;
}

static inline int __init mach_late_setup(void)
{
	if (steely_machine.late_init)
		return steely_machine.late_init();

	return 0;
}

static __init void mach_cleanup(void)
{
	xnclock_cleanup();
	free_percpu_irq(steely_pipeline.escalate_virq, &steely_machine_cpudata);
	irq_dispose_mapping(steely_pipeline.escalate_virq);
	irq_pop_stage(&steely_pipeline.stage);
}

static struct {
	const char *label;
	enum steely_run_states state;
} init_states[] __initdata = {
	{ "disabled", STEELY_STATE_DISABLED },
	{ "stopped", STEELY_STATE_STOPPED },
	{ "enabled", STEELY_STATE_WARMUP },
};
	
static void __init setup_init_state(void)
{
	static char warn_bad_state[] __initdata =
		STEELY_WARNING "invalid init state '%s'\n";
	int n;

	for (n = 0; n < ARRAY_SIZE(init_states); n++)
		if (strcmp(init_states[n].label, init_state_arg) == 0) {
			set_realtime_core_state(init_states[n].state);
			return;
		}

	printk(warn_bad_state, init_state_arg);
}

static __init int sys_init(void)
{
	struct xnsched *sched;
	void *heapaddr;
	u32 heapsize;
	int ret, cpu;

	if (sysheap_size_arg == 0)
		sysheap_size_arg = CONFIG_STEELY_SYS_HEAPSZ;

	heapsize = sysheap_size_arg * 1024;
	heapaddr = xnheap_vmalloc(heapsize);
	if (heapaddr == NULL)
		return -ENOMEM;

	ret = xnheap_init(&steely_heap, heapaddr, heapsize);
	if (ret) {
		xnheap_vfree(heapaddr);
		return ret;
	}

	xnheap_set_name(&steely_heap, "system heap");

#ifdef CONFIG_SMP
	ret = request_percpu_irq_flags(IPIPE_RESCHEDULE_IPI,
				       __xnsched_run_handler,
				       "Steely reschedule",
				       IRQF_PIPELINED,
				       &steely_machine_cpudata);
	if (ret) {
		xnheap_destroy(&steely_heap);
		xnheap_vfree(heapaddr);
		return ret;
	}
#endif

	for_each_online_cpu(cpu) {
		sched = &per_cpu(nksched, cpu);
		xnsched_init(sched, cpu);
	}

	xnregistry_init();

	/*
	 * If starting in stopped mode, do all initializations, but do
	 * not enable the core timer.
	 */
	if (realtime_core_state() == STEELY_STATE_WARMUP) {
		ret = xnclock_core_takeover();
		if (ret) {
			sys_shutdown();
			return ret;
		}
		set_realtime_core_state(STEELY_STATE_RUNNING);
	}

	return 0;
}

static int __init steely_init(void)
{
	int ret, __maybe_unused cpu;

	setup_init_state();

	if (!realtime_core_enabled()) {
		printk(STEELY_WARNING "disabled on kernel command line\n");
		return 0;
	}

#ifdef CONFIG_SMP
	cpumask_clear(&xnsched_realtime_cpus);
	for_each_online_cpu(cpu) {
		if (supported_cpus_arg & (1UL << cpu))
			cpumask_set_cpu(cpu, &xnsched_realtime_cpus);
	}
	if (cpumask_empty(&xnsched_realtime_cpus)) {
		printk(STEELY_WARNING "disabled via empty real-time CPU mask\n");
		set_realtime_core_state(STEELY_STATE_DISABLED);
		return 0;
	}
	steely_cpu_affinity = xnsched_realtime_cpus;
#endif /* CONFIG_SMP */

	xnsched_register_classes();

	ret = xnprocfs_init_tree();
	if (ret)
		goto fail;

	ret = mach_setup();
	if (ret)
		goto cleanup_proc;

	xnintr_mount();

	ret = xnpipe_mount();
	if (ret)
		goto cleanup_mach;

	ret = xnselect_mount();
	if (ret)
		goto cleanup_pipe;

	ret = sys_init();
	if (ret)
		goto cleanup_select;

	ret = mach_late_setup();
	if (ret)
		goto cleanup_sys;

	ret = rtdm_init();
	if (ret)
		goto cleanup_sys;

	ret = steely_interface_init();
	if (ret)
		goto cleanup_rtdm;

	rtdm_fd_init();

	printk(STEELY_INFO "Steely v%s (%s) %s%s%s\n",
	       STEELY_VERSION_STRING,
	       STEELY_VERSION_NAME,
	       boot_debug_notice,
	       boot_trace_notice,
	       boot_state_notice);

	return 0;

cleanup_rtdm:
	rtdm_cleanup();
cleanup_sys:
	sys_shutdown();
cleanup_select:
	xnselect_umount();
cleanup_pipe:
	xnpipe_umount();
cleanup_mach:
	mach_cleanup();
cleanup_proc:
	xnprocfs_cleanup_tree();
fail:
	set_realtime_core_state(STEELY_STATE_DISABLED);
	printk(STEELY_ERR "init failed, code %d\n", ret);

	return ret;
}
device_initcall(steely_init);

/**
 * @ingroup steely
 * @defgroup steely_core Steely kernel
 *
 * The Steely core is a co-kernel which supplements the Linux kernel
 * for delivering real-time services with very low latency. It
 * implements a set of generic RTOS building blocks, which the
 * Steely/POSIX and Steely/RTDM APIs are based on.  Steely has higher
 * priority over the Linux kernel activities.
 *
 * @{
 *
 * @page steely-core-tags Dual kernel service tags
 *
 * The Steely kernel services may be restricted to particular calling
 * contexts, or entail specific side-effects. To describe this
 * information, each service documented by this section bears a set of
 * tags when applicable.
 *
 * The table below matches the tags used throughout the documentation
 * with the description of their meaning for the caller.
 *
 * @par
 * <b>Context tags</b>
 * <TABLE>
 * <TR><TH>Tag</TH> <TH>Context on entry</TH></TR>
 * <TR><TD>primary-only</TD>	<TD>Must be called from a Steely task in primary mode</TD></TR>
 * <TR><TD>primary-timed</TD>	<TD>Requires a Steely task in primary mode if timed</TD></TR>
 * <TR><TD>coreirq-only</TD>	<TD>Must be called from a Steely IRQ handler</TD></TR>
 * <TR><TD>secondary-only</TD>	<TD>Must be called from a Steely task in secondary mode or regular Linux task</TD></TR>
 * <TR><TD>rtdm-task</TD>	<TD>Must be called from a RTDM driver task</TD></TR>
 * <TR><TD>mode-unrestricted</TD>	<TD>May be called from a Steely task in either primary or secondary mode</TD></TR>
 * <TR><TD>task-unrestricted</TD>	<TD>May be called from a Steely or regular Linux task indifferently</TD></TR>
 * <TR><TD>unrestricted</TD>	<TD>May be called from any context previously described</TD></TR>
 * <TR><TD>atomic-entry</TD>	<TD>Caller must currently hold the big Steely kernel lock (nklock)</TD></TR>
 * </TABLE>
 *
 * @par
 * <b>Possible side-effects</b>
 * <TABLE>
 * <TR><TH>Tag</TH> <TH>Description</TH></TR>
 * <TR><TD>might-switch</TD>	<TD>The Steely kernel may switch context</TD></TR>
 * </TABLE>
 *
 * @}
 */
