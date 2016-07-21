/* -*- linux-c -*-
 * kernel/irq/pipeline.c
 *
 * Copyright (C) 2002-2016 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * IRQ pipeline.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/seq_buf.h>
#include <linux/kallsyms.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/dovetail.h>
#include "internals.h"

struct irq_stage root_irq_stage;
EXPORT_SYMBOL_GPL(root_irq_stage);

struct irq_stage *head_irq_stage = &root_irq_stage;
EXPORT_SYMBOL_GPL(head_irq_stage);

struct irq_domain *synthetic_irq_domain;

#ifdef CONFIG_SMP

static __initdata struct irq_stage_data bootup_context = {
	.stage = &root_irq_stage,
	.status = (1 << IPIPE_STALL_FLAG),
};

#define IPIPE_CRITICAL_TIMEOUT	1000000

static struct cpumask smp_sync_map;
static struct cpumask smp_lock_map;
static struct cpumask smp_pass_map;
static unsigned long smp_lock_wait;
static DEFINE_HARD_SPINLOCK(smp_barrier);
static atomic_t smp_lock_count = ATOMIC_INIT(0);
static void (*smp_sync)(void *arg);
static void *smp_sync_arg;

#else /* !CONFIG_SMP */

#define bootup_context irq_pipeline.root

#endif /* !CONFIG_SMP */

DEFINE_PER_CPU(struct irq_pipeline_data, irq_pipeline) = {
	.root = {
		.stage = &root_irq_stage,
		.status = (1 << IPIPE_STALL_FLAG),
	},
	.curr = &bootup_context,
};
EXPORT_PER_CPU_SYMBOL(irq_pipeline);

unsigned long __ipipe_hrclock_freq;
EXPORT_SYMBOL_GPL(__ipipe_hrclock_freq);

/* Up to 2k of pending work data per CPU. */
#define WORKBUF_SIZE 2048
static DEFINE_PER_CPU_ALIGNED(unsigned char[WORKBUF_SIZE], work_buf);
static DEFINE_PER_CPU(void *, work_tail);
static unsigned int root_work_sirq;

static irqreturn_t do_root_work(int sirq, void *dev_id);

void dovetail_mayday_hook(struct pt_regs *regs);

static inline int root_context_offset(void)
{
	void root_context_not_at_start_of_irq_pipeline(void);

	/* irq_pipeline.root must be found at offset #0. */

	if (offsetof(struct irq_pipeline_data, root))
		root_context_not_at_start_of_irq_pipeline();

	return 0;
}

#ifdef CONFIG_SMP

static inline void fixup_percpu_data(void)
{
	struct irq_pipeline_data *p;
	int cpu;

	/*
	 * irq_pipeline.curr cannot be assigned statically to
	 * &irq_pipeline.root, due to the dynamic nature of percpu
	 * data. So we make irq_pipeline.curr refer to a temporary
	 * boot up context in static memory, until we can fixup all
	 * context pointers in this routine, after per-cpu areas have
	 * been eventually set up. The temporary context data is
	 * copied to per_cpu(irq_pipeline, 0).root in the same move.
	 *
	 * Obviously, this code must run over the boot CPU, before SMP
	 * operations start.
	 */
	BUG_ON(smp_processor_id() || !irqs_disabled());

	per_cpu(irq_pipeline, 0).root = bootup_context;

	for_each_possible_cpu(cpu) {
		p = &per_cpu(irq_pipeline, cpu);
		p->curr = &p->root;
	}
}

static irqreturn_t pipeline_sync_handler(int irq, void *dev_id)
{
	int cpu = raw_smp_processor_id();

	cpumask_set_cpu(cpu, &smp_sync_map);

	/*
	 * Now we are in sync with the lock requestor running on
	 * another CPU. Enter a spinning wait until he releases the
	 * global lock.
	 */
	raw_spin_lock(&smp_barrier);

	/* Got it. Now get out. */

	/* Call the sync routine if any. */
	if (smp_sync)
		smp_sync(smp_sync_arg);

	cpumask_set_cpu(cpu, &smp_pass_map);

	raw_spin_unlock(&smp_barrier);

	cpumask_clear_cpu(cpu, &smp_sync_map);

	return IRQ_HANDLED;
}

static struct irqaction lock_ipi = {
	.handler = pipeline_sync_handler,
	.name = "Pipeline lock interrupt",
	.flags = IRQF_NO_THREAD | IRQF_PIPELINED | IRQF_STICKY,
};

#else /* !CONFIG_SMP */

static inline void fixup_percpu_data(void) { }

#endif /* CONFIG_SMP */

void __init irq_pipeline_init_early(void)
{
	struct irq_stage *stage = &root_irq_stage;

	/*
	 * This is called early from start_kernel(), even before the
	 * actual number of IRQs is known. Careful.
	 */
	fixup_percpu_data();

	/*
	 * A lightweight registration code for the root stage. We are
	 * running on the boot CPU, hw interrupts are off, and
	 * secondary CPUs are still lost in space.
	 */
	stage->name = "Linux";
	stage->context_offset = root_context_offset();
}

void __weak __init irq_pipeline_init_late(void)
{
}

static void sirq_noop(struct irq_data *data) { }

static unsigned int sirq_noop_ret(struct irq_data *data)
{
	return 0;
}

static struct irq_chip sirq_chip = {
	.name		= "SynthetIC",
	.irq_startup	= sirq_noop_ret,
	.irq_shutdown	= sirq_noop,
	.irq_enable	= sirq_noop,
	.irq_disable	= sirq_noop,
	.irq_ack	= sirq_noop,
	.irq_mask	= sirq_noop,
	.irq_unmask	= sirq_noop,
	.flags		= IRQCHIP_PIPELINE_SAFE | IRQCHIP_SKIP_SET_WAKE,
};

static int sirq_map(struct irq_domain *d, unsigned int irq,
		    irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &sirq_chip, handle_synthetic_irq);

	return 0;
}

static struct irq_domain_ops sirq_domain_ops = {
	.map	= sirq_map,
};

static struct irqaction root_work = {
	.handler = do_root_work,
	.name = "Root stage worker interrupt",
};

void __init irq_pipeline_init(void)
{
	int cpu;

	BUG_ON(!hard_irqs_disabled());

	synthetic_irq_domain = irq_domain_add_nomap(NULL, ~0,
						 &sirq_domain_ops,
						 NULL);
	root_work_sirq = irq_create_direct_mapping(synthetic_irq_domain);
	setup_irq(root_work_sirq, &root_work);

	for_each_possible_cpu(cpu)
		per_cpu(work_tail, cpu) = per_cpu(work_buf, cpu);

	/*
	 * We are running on the boot CPU, hw interrupts are off, and
	 * secondary CPUs are still lost in space. Now we may run
	 * arch-specific code for enabling the pipeline.
	 */
	arch_irq_pipeline_init();

#ifdef CONFIG_SMP
	setup_irq(IPIPE_CRITICAL_IPI, &lock_ipi);
#endif
	printk_pipeline_init();

	pr_info("IRQ pipeline (release #%d)\n", IPIPE_CORE_RELEASE);
}

static inline void init_head_stage(struct irq_stage *stage)
{
	struct irq_stage_data *p;
	int cpu;

	/* Must be set first, used in irq_stage_context(). */
	stage->context_offset = offsetof(struct irq_pipeline_data, head);

	for_each_possible_cpu(cpu) {
		p = irq_stage_context(stage, cpu);
		memset(p, 0, sizeof(*p));
		p->stage = stage;
	}
}

void root_irq_disable(void)
{
	unsigned long flags;

	ipipe_root_only();
	flags = hard_local_irq_save();
	__set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL(root_irq_disable);

unsigned long root_irq_save(void)
{
	unsigned long flags, x;

	ipipe_root_only();
	flags = hard_local_irq_save();
	x = __test_and_set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	hard_local_irq_restore(flags);

	return x;
}
EXPORT_SYMBOL(root_irq_save);

unsigned long root_irqs_disabled(void)
{
	unsigned long flags, x;

	flags = hard_local_irq_save();
	x = test_bit(IPIPE_STALL_FLAG, &irq_root_status);
	hard_local_irq_restore(flags);

	return x;
}
EXPORT_SYMBOL(root_irqs_disabled);

void root_irq_enable(void)
{
	struct irq_stage_data *p;

	hard_local_irq_disable();

	/* This helps catching bad usage from assembly call sites. */
	ipipe_root_only();

	p = irq_root_this_context();
	__clear_bit(IPIPE_STALL_FLAG, &p->status);
	if (unlikely(irq_staged_waiting(p)))
		irq_stage_sync_current();

	hard_local_irq_enable();
}
EXPORT_SYMBOL(root_irq_enable);

void __root_irq_restore_nosync(unsigned long x)
{
	struct irq_stage_data *p = irq_root_this_context();

	if (raw_irqs_disabled_flags(x)) {
		__set_bit(IPIPE_STALL_FLAG, &p->status);
		trace_hardirqs_off();
	} else {
		trace_hardirqs_on();
		__clear_bit(IPIPE_STALL_FLAG, &p->status);
	}
}
EXPORT_SYMBOL(__root_irq_restore_nosync);

void root_irq_restore_nosync(unsigned long x)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	__root_irq_restore_nosync(x);
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL(root_irq_restore_nosync);

void head_irq_enable(void)
{
	struct irq_stage_data *p = irq_head_this_context();

	hard_local_irq_disable();

	__clear_bit(IPIPE_STALL_FLAG, &p->status);

	if (unlikely(irq_staged_waiting(p)))
		irq_stage_sync(head_irq_stage);

	hard_local_irq_enable();
}
EXPORT_SYMBOL(head_irq_enable);

void __head_irq_restore(unsigned long x) /* hw interrupt off */
{
	struct irq_stage_data *p = irq_head_this_context();

	if (x) {
#ifdef CONFIG_DEBUG_KERNEL
		/*
		 * Already stalled albeit head_irq_restore() should
		 * have detected it? Send a warning once.
		 */
		if (WARN_ON_ONCE(__test_and_set_bit(IPIPE_STALL_FLAG, &p->status)))
			hard_local_irq_disable();
#endif
		__set_bit(IPIPE_STALL_FLAG, &p->status);
	} else {
		__clear_bit(IPIPE_STALL_FLAG, &p->status);
		if (unlikely(irq_staged_waiting(p)))
			irq_stage_sync(head_irq_stage);
		hard_local_irq_enable();
	}
}
EXPORT_SYMBOL(__head_irq_restore);

#if __IRQ_STAGE_MAP_LEVELS == 3

/* Must be called hw IRQs off. */
void irq_stage_post_event(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
	int l0b, l1b;

	WARN_ON_ONCE(irq_pipeline_debug() &&
		  (!hard_irqs_disabled() || irq >= IPIPE_NR_IRQS));

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	__set_bit(irq, p->irqpend_lomap);
	__set_bit(l1b, p->irqpend_mdmap);
	__set_bit(l0b, &p->irqpend_himap);
}
EXPORT_SYMBOL_GPL(irq_stage_post_event);

static void __clear_pending_irq(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
	int l0b, l1b;

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	__clear_bit(irq, p->irqpend_lomap);
	__clear_bit(l1b, p->irqpend_mdmap);
	__clear_bit(l0b, &p->irqpend_himap);
}

static inline int pull_next_irq(struct irq_stage_data *p)
{
	int l0b, l1b, l2b;
	unsigned long l0m, l1m, l2m;
	unsigned int irq;

	l0m = p->irqpend_himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = ffs(l0m) - 1;
	l1m = p->irqpend_mdmap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = ffs(l1m) - 1 + l0b * BITS_PER_LONG;
	l2m = p->irqpend_lomap[l1b];
	if (unlikely(l2m == 0))
		return -1;

	l2b = ffs(l2m) - 1;
	irq = l1b * BITS_PER_LONG + l2b;

	__clear_bit(irq, p->irqpend_lomap);
	if (p->irqpend_lomap[l1b] == 0) {
		__clear_bit(l1b, p->irqpend_mdmap);
		if (p->irqpend_mdmap[l0b] == 0)
			__clear_bit(l0b, &p->irqpend_himap);
	}

	return irq;
}

#else /* __IRQ_STAGE_MAP_LEVELS == 2 */

static void __clear_pending_irq(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
	int l0b = irq / BITS_PER_LONG;

	__clear_bit(irq, p->irqpend_lomap);
	__clear_bit(l0b, &p->irqpend_himap);
}

/* Must be called hw IRQs off. */
void irq_stage_post_event(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
	int l0b = irq / BITS_PER_LONG;

	WARN_ON_ONCE(irq_pipeline_debug() &&
		  (!hard_irqs_disabled() || irq >= IPIPE_NR_IRQS));

	__set_bit(irq, p->irqpend_lomap);
	__set_bit(l0b, &p->irqpend_himap);
}
EXPORT_SYMBOL_GPL(irq_stage_post_event);

static inline int pull_next_irq(struct irq_stage_data *p)
{
	unsigned long l0m, l1m;
	int l0b, l1b;

	l0m = p->irqpend_himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = ffs(l0m) - 1;
	l1m = p->irqpend_lomap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = ffs(l1m) - 1;
	__clear_bit(l1b, &p->irqpend_lomap[l0b]);
	if (p->irqpend_lomap[l0b] == 0)
		__clear_bit(l0b, &p->irqpend_himap);

	return l0b * BITS_PER_LONG + l1b;
}

#endif  /* __IRQ_STAGE_MAP_LEVELS == 2 */

void irq_pipeline_clear(unsigned int irq)
{
	unsigned long flags;
	
	flags = hard_local_irq_save();

	__clear_pending_irq(&root_irq_stage, irq);
	if (&root_irq_stage != head_irq_stage)
		__clear_pending_irq(head_irq_stage, irq);

	hard_local_irq_restore(flags);
}

void __irq_stage_sync(struct irq_stage *top)
{
	struct irq_stage_data *p;
	struct irq_stage *stage;

	/* We must enter over the root stage. */
	WARN_ON_ONCE(irq_pipeline_debug() &&
		     __current_irq_stage != &root_irq_stage);

	stage = top;

	for (;;) {
		p = irq_stage_this_context(stage);
		if (test_bit(IPIPE_STALL_FLAG, &p->status))
			break;

		if (irq_staged_waiting(p)) {
			if (stage == &root_irq_stage)
				irq_stage_sync_current();
			else {
				/* Switching to head. */
				dovetail_clear_callouts(p);
				irq_set_current_context(p);
				irq_stage_sync_current();
				__set_current_irq_stage(&root_irq_stage);
			}
		}

		if (stage == &root_irq_stage)
			break;
		
		stage = &root_irq_stage;
	}
}
EXPORT_SYMBOL_GPL(__irq_stage_sync);

unsigned long hard_preempt_disable(void)
{
	unsigned long flags = hard_local_irq_save();

	if (__on_root_stage())
		preempt_disable();

	return flags;
}
EXPORT_SYMBOL_GPL(hard_preempt_disable);

void hard_preempt_enable(unsigned long flags)
{
	if (__on_root_stage()) {
		preempt_enable_no_resched();
		hard_local_irq_restore(flags);
		preempt_check_resched();
	} else
		hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(hard_preempt_enable);

static inline
void call_action_handler(unsigned int irq, struct irq_desc *desc)
{
	struct irqaction *action = desc->action;
	void *dev_id = action->dev_id;

	if (irq_settings_is_per_cpu_devid(desc))
		dev_id = raw_cpu_ptr(action->percpu_dev_id);

	kstat_incr_irqs_this_cpu(desc);
	action->handler(irq, dev_id);
}

static inline
void call_head_handler(unsigned int irq, struct irq_desc *desc)
{
	call_action_handler(irq, desc);
	irq_finish_head(irq);
}

static void dispatch_irq_head(unsigned int irq, struct irq_desc *desc)
{				/* hw interrupts off */
	struct irq_stage_data *p = irq_head_this_context(), *old;
	struct irq_stage *head = p->stage;

	if (unlikely(test_bit(IPIPE_STALL_FLAG, &p->status))) {
		irq_stage_post_event(head, irq);
		return;
	}

	/* Switch to the head stage if not current. */
	old = irq_current_context;
	if (old != p)
		irq_set_current_context(p);

	__set_bit(IPIPE_STALL_FLAG, &p->status);
	call_head_handler(irq, desc);
	hard_local_irq_disable();
	p = irq_head_this_context();
	__clear_bit(IPIPE_STALL_FLAG, &p->status);

	/* Are we still running in the head stage? */
	if (likely(irq_current_context == p)) {
		/* Did we enter this code over the head stage? */
		if (old->stage == head) {
			/* Yes, do immediate synchronization. */
			if (irq_staged_waiting(p))
				irq_stage_sync_current();
			return;
		}
		irq_set_current_context(irq_root_this_context());
	}

	/*
	 * We must be running over the root stage, synchronize the
	 * pipeline for high priority IRQs (slow path).
	 */
	__irq_stage_sync(head);
}

static void __enter_pipeline(unsigned int irq, struct irq_desc *desc,
			     bool sync)
{
	struct irq_stage *stage;

	/*
	 * Survival kit when reading this code:
	 *
	 * - we have two main situations, leading to three cases for
	 *   handling interrupts:
	 *
	 *   a) the root stage is alone, no registered head stage
	 *      => all interrupts go through the interrupt log
	 *   b) a head stage is registered
	 *      => head stage IRQs go through the fast dispatcher
	 *      => root stage IRQs go through the interrupt log
	 *
	 * - when no head stage is registered, head_irq_stage ==
	 *   &root_irq_stage.
	 *
	 * - the caller tells us whether we may try to run the IRQ log
	 *   syncer. Typically, demuxed IRQs won't be synced
	 *   immediately.
	 */

	stage = __current_irq_stage;
	/*
	 * Sticky interrupts must be handled early and separately, so
	 * that we always process them on the current stage.
	 */
	if (irq_settings_is_sticky(desc))
		goto log;

	/*
	 * In case we have no registered head stage
	 * (i.e. head_irq_stage == &root_irq_stage), we always go
	 * through the interrupt log, and leave the dispatching work
	 * ultimately to irq_stage_sync().
	 */
	stage = head_irq_stage;
	if (stage == &root_irq_stage)
		goto log;

	if (irq_settings_is_pipelined(desc)) {
		if (likely(sync))
			dispatch_irq_head(irq, desc);
		else
			irq_stage_post_event(stage, irq);
		return;
	}

	stage = &root_irq_stage;
log:
	irq_stage_post_event(stage, irq);

	/*
	 * Optimize if we preempted a registered high priority head
	 * stage: we don't need to synchronize the pipeline unless
	 * there is a pending interrupt for it.
	 */
	if (sync &&
	    (__on_root_stage() ||
	     irq_staged_waiting(irq_head_this_context())))
		irq_stage_sync(head_irq_stage);
}

static inline
void copy_timer_regs(struct irq_desc *desc, struct pt_regs *regs)
{
	struct irq_pipeline_data *p;

	if (desc->action == NULL || !(desc->action->flags & __IRQF_TIMER))
		return;
	/*
	 * Given our deferred dispatching model for regular IRQs, we
	 * record the preempted context registers only for the latest
	 * timer interrupt, so that the regular tick handler charges
	 * CPU times properly. It is assumed that no other interrupt
	 * handler cares for such information.
	 */
	p = raw_cpu_ptr(&irq_pipeline);
	arch_save_timer_regs(&p->tick_regs, regs, __on_head_stage());
}

static void enter_pipeline(unsigned int irq, bool sync, struct pt_regs *regs)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (irq_pipeline_debug()) {
		if (!hard_irqs_disabled()) {
			hard_local_irq_disable();
			pr_err("IRQ pipeline: interrupts enabled on entry (IRQ%u)\n", irq);
		}
		if (unlikely(desc == NULL)) {
			pr_err("IRQ pipeline: received unhandled IRQ%u\n", irq);
			return;
		}
	}

	if (regs)
		copy_timer_regs(desc, regs);

	if (in_pipeline())   /* We may recurse (e.g. IRQ chaining). */
		generic_handle_irq_desc(desc);
	else {
		preempt_count_add(PIPELINE_OFFSET);
		generic_handle_irq_desc(desc);
		preempt_count_sub(PIPELINE_OFFSET);
	}

	if (irq_settings_is_chained(desc)) {
		if (sync) /* Run cascaded IRQ handlers. */
			irq_stage_sync(head_irq_stage);
		return;
	}

	__enter_pipeline(irq, desc, sync);
}

static inline void check_pending_mayday(struct pt_regs *regs)
{
#ifdef CONFIG_DOVETAIL
	/*
	 * Sending MAYDAY is in essence a rare case, so prefer test
	 * then maybe clear over test_and_clear.
	 */
	if (user_mode(regs) && test_thread_flag(TIF_MAYDAY)) {
		clear_thread_flag(TIF_MAYDAY);
		dovetail_mayday_hook(regs);
	}
#endif
}

void __irq_pipeline_enter(unsigned int irq, struct pt_regs *regs)
{				/* hw interrupts off */
	struct irq_desc *desc = irq_to_desc(irq);

	if (regs)
		copy_timer_regs(desc, regs);

	__enter_pipeline(irq, desc, true);

	if (regs)
		check_pending_mayday(regs);
}

void irq_pipeline_enter(unsigned int irq, struct pt_regs *regs)
{				/* hw interrupts off */
	enter_pipeline(irq, true, regs);
	check_pending_mayday(regs);
}

void irq_pipeline_enter_nosync(unsigned int irq)
{				/* hw interrupts off */
	enter_pipeline(irq, false, NULL);
}

/*
 * Over the root stage, IRQs with no registered action and non-sticky
 * IRQs must be dispatched by the arch-specific do_IRQ_pipelined()
 * routine. Sticky IRQs are immediately delivered to the registered
 * handler.
 */
static inline
void call_root_handler(unsigned int irq, struct irq_desc *desc)
{
	if (desc->action == NULL ||
	    !(desc->action->flags & IRQF_STICKY))
		do_IRQ_pipelined(irq, desc);
	else
		call_action_handler(irq, desc);

#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_disable();
#endif
}

/*
 * __irq_stage_sync_current() -- Flush the pending IRQs for the
 * current stage (and processor). This routine flushes the interrupt
 * log (see "Optimistic interrupt protection" from D. Stodolsky et
 * al. for more on the deferred interrupt scheme). Every interrupt
 * that occurred while the pipeline was stalled gets played.
 *
 * WARNING: CPU migration may occur over this routine.
 */
void __irq_stage_sync_current(void) /* hw IRQs off */
{
	struct irq_stage_data *p;
	struct irq_stage *stage;
	struct irq_desc *desc;
	int irq;

	p = irq_current_context;
respin:
	stage = p->stage;
	__set_bit(IPIPE_STALL_FLAG, &p->status);
	smp_wmb();

	if (stage == &root_irq_stage)
		trace_hardirqs_off();

	for (;;) {
		irq = pull_next_irq(p);
		if (irq < 0)
			break;
		/*
		 * Make sure the compiler does not reorder wrongly, so
		 * that all updates to maps are done before the
		 * handler gets called.
		 */
		barrier();

		if (stage != head_irq_stage)
			hard_local_irq_enable();

		desc = irq_to_desc(irq);
	
		if (stage == &root_irq_stage)
			call_root_handler(irq, desc);
		else
			call_head_handler(irq, desc);
	
		hard_local_irq_disable();

		/*
		 * We may have migrated to a different CPU (1) upon
		 * return from the handler, or downgraded from the
		 * head stage to the root one (2), the opposite way
		 * is NOT allowed though.
		 *
		 * (1) reload the current per-cpu context pointer, so
		 * that we further pull pending interrupts from the
		 * proper per-cpu log.
		 *
		 * (2) check the stall bit to know whether we may
		 * dispatch any interrupt pending for the root stage,
		 * and respin the entire dispatch loop if
		 * so. Otherwise, immediately return to the caller,
		 * _without_ affecting the stall state for the root
		 * stage, since we do not own it at this stage.  This
		 * case is basically reflecting what may happen in
		 * dispatch_irq_head() for the fast path.
		 */
		p = irq_current_context;
		if (p->stage != stage) {
			BUG_ON(irq_pipeline_debug() &&
			       stage == &root_irq_stage);
			if (test_bit(IPIPE_STALL_FLAG, &p->status))
				return;
			goto respin;
		}
	}

	if (stage == &root_irq_stage)
		trace_hardirqs_on();

	__clear_bit(IPIPE_STALL_FLAG, &p->status);
}

void __weak irq_stage_sync_current(void)
{
	__irq_stage_sync_current();
}

#ifdef CONFIG_DEBUG_IRQ_PIPELINE

notrace void ipipe_root_only(void)
{
	struct irq_stage *this_stage;
	unsigned long flags;

	flags = hard_smp_local_irq_save();

	this_stage = __current_irq_stage;
	if (likely(this_stage == &root_irq_stage &&
		   !test_bit(IPIPE_STALL_FLAG, &irq_head_status))) {
		hard_smp_local_irq_restore(flags);
		return;
	}

	if (in_nmi() || test_bit(IPIPE_OOPS_FLAG, &irq_root_status)) {
		hard_smp_local_irq_restore(flags);
		return;
	}

	hard_smp_local_irq_restore(flags);

	irq_pipeline_oops();

	if (this_stage != &root_irq_stage)
		pr_err("IRQ pipeline: Detected illicit call from head stage '%s'\n"
		       "              into a regular Linux service\n",
		       this_stage->name);
	else
		pr_err("IRQ pipeline: Detected stalled head stage, "
			"probably caused by a bug.\n"
			"             A critical section may have been "
			"left unterminated.\n");
	dump_stack();
}
EXPORT_SYMBOL(ipipe_root_only);

#endif /* CONFIG_DEBUG_IRQ_PIPELINE */

static irqreturn_t do_root_work(int sirq, void *dev_id)
{
	struct ipipe_work_header *work;
	unsigned long flags;
	void *curr, *tail;
	int cpu;

	/*
	 * Work is dispatched in enqueuing order. This interrupt
	 * context can't migrate to another CPU.
	 */
	cpu = smp_processor_id();
	curr = per_cpu(work_buf, cpu);

	for (;;) {
		flags = hard_local_irq_save();
		tail = per_cpu(work_tail, cpu);
		if (curr == tail) {
			per_cpu(work_tail, cpu) = per_cpu(work_buf, cpu);
			hard_local_irq_restore(flags);
			break;
		}
		work = curr;
		curr += work->size;
		hard_local_irq_restore(flags);
		work->handler(work);
	}

	return IRQ_HANDLED;
}

void __ipipe_post_work_root(struct ipipe_work_header *work)
{
	unsigned long flags;
	void *tail;
	int cpu;

	/*
	 * Subtle: we want to use the head stall/unstall operators,
	 * not the hard_* routines to protect against races. This way,
	 * we ensure that a root-based caller will trigger the sirq
	 * handling immediately when unstalling the head stage, as a
	 * result of calling irq_stage_sync() under the hood.
	 */
	flags = head_irq_save();
	cpu = raw_smp_processor_id();
	tail = per_cpu(work_tail, cpu);

	if (WARN_ON_ONCE((unsigned char *)tail + work->size >=
			 per_cpu(work_buf, cpu) + WORKBUF_SIZE))
		goto out;

	/* Work handling is deferred, so data has to be copied. */
	memcpy(tail, work, work->size);
	per_cpu(work_tail, cpu) = tail + work->size;
	irq_stage_post_root(root_work_sirq);
out:
	head_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(__ipipe_post_work_root);

void irq_push_stage(struct irq_stage *stage, const char *name,
		    struct irq_pipeline_clocking *clocking)
{
	BUG_ON(!on_root_stage() ||
	       stage == &root_irq_stage ||
	       head_irq_stage != &root_irq_stage);

	stage->name = name;
	init_head_stage(stage);
	arch_irq_push_stage(stage, clocking);
	barrier();
	head_irq_stage = stage;

	pr_info("IRQ pipeline: high-priority stage %s added.\n", name);
}
EXPORT_SYMBOL_GPL(irq_push_stage);

void irq_pop_stage(struct irq_stage *stage)
{
	BUG_ON(!on_root_stage() || stage != head_irq_stage);

	head_irq_stage = &root_irq_stage;
	smp_mb();

	pr_info("IRQ pipeline: stage %s removed.\n", stage->name);
}
EXPORT_SYMBOL_GPL(irq_pop_stage);

unsigned long irq_pipeline_lock_many(const struct cpumask *mask,
				     void (*syncfn)(void *arg), void *arg)
{
	unsigned long flags, loops __maybe_unused;
	struct cpumask allbutself __maybe_unused;
	int cpu __maybe_unused, n __maybe_unused;

	flags = hard_local_irq_save();

	if (num_online_cpus() == 1)
		return flags;

#ifdef CONFIG_SMP
	cpu = raw_smp_processor_id();
	if (!cpumask_test_and_set_cpu(cpu, &smp_lock_map)) {
		while (test_and_set_bit(0, &smp_lock_wait)) {
			n = 0;
			hard_local_irq_enable();

			do
				cpu_relax();
			while (++n < cpu);

			hard_local_irq_disable();
		}
restart:
		raw_spin_lock(&smp_barrier);

		smp_sync = syncfn;
		smp_sync_arg = arg;

		cpumask_clear(&smp_pass_map);
		cpumask_set_cpu(cpu, &smp_pass_map);

		/*
		 * Send the sync IPI to all processors but the current
		 * one.
		 */
		cpumask_andnot(&allbutself, mask, &smp_pass_map);
		irq_pipeline_send_remote(IPIPE_CRITICAL_IPI, &allbutself);
		loops = IPIPE_CRITICAL_TIMEOUT;

		while (!cpumask_equal(&smp_sync_map, &allbutself)) {
			if (--loops > 0) {
				cpu_relax();
				continue;
			}
			/*
			 * We ran into a deadlock due to a contended
			 * rwlock. Cancel this round and retry.
			 */
			smp_sync = NULL;

			raw_spin_unlock(&smp_barrier);
			/*
			 * Ensure all CPUs consumed the IPI to avoid
			 * running smp_sync prematurely. This
			 * usually resolves the deadlock reason too.
			 */
			while (!cpumask_equal(mask, &smp_pass_map))
				cpu_relax();

			goto restart;
		}
	}

	atomic_inc(&smp_lock_count);

#endif	/* CONFIG_SMP */

	return flags;
}
EXPORT_SYMBOL_GPL(irq_pipeline_lock_many);

void irq_pipeline_unlock(unsigned long flags)
{
	if (num_online_cpus() == 1) {
		hard_local_irq_restore(flags);
		return;
	}

#ifdef CONFIG_SMP
	if (atomic_dec_and_test(&smp_lock_count)) {
		raw_spin_unlock(&smp_barrier);
		while (!cpumask_empty(&smp_sync_map))
			cpu_relax();
		cpumask_clear_cpu(raw_smp_processor_id(), &smp_lock_map);
		clear_bit(0, &smp_lock_wait);
		smp_mb__after_atomic();
	}
#endif /* CONFIG_SMP */

	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(irq_pipeline_unlock);

void irq_pipeline_inject(unsigned int irq)
{
	struct irq_stage *stage = head_irq_stage;
	struct irq_desc *desc;
	unsigned long flags;

	flags = hard_local_irq_save();

	desc = irq_to_desc(irq);
	if (stage == &root_irq_stage ||
	    irq_desc_get_irq_data(desc)->domain != synthetic_irq_domain ||
	    !irq_settings_is_pipelined(desc))
		/* Slow path: emulate IRQ receipt. */
		__enter_pipeline(irq, desc, true);
	else
		/* Fast path: send to head stage immediately. */
		dispatch_irq_head(irq, desc);

	hard_local_irq_restore(flags);

}
EXPORT_SYMBOL_GPL(irq_pipeline_inject);

void irq_pipeline_oops(void)
{
	unsigned long flags;

	flags = hard_local_irq_save();	
	__set_bit(IPIPE_OOPS_FLAG, &irq_root_status);
	hard_local_irq_restore(flags);
}

bool irq_pipeline_idle(void)
{
	struct irq_stage_data *p;

	/*
	 * Emulate idle entry sequence over the root domain, which is
	 * stalled on entry.
	 */
	hard_local_irq_disable();

	trace_hardirqs_on();
	p = irq_root_this_context();
	__clear_bit(IPIPE_STALL_FLAG, &p->status);

	if (unlikely(irq_staged_waiting(p))) {
		irq_stage_sync_current();
		hard_local_irq_enable();
		return false;
	}

	return true;
}
EXPORT_SYMBOL_GPL(irq_pipeline_idle);

void irq_pipeline_nmi_enter(void)
{
	if (__test_and_set_bit(IPIPE_STALL_FLAG, &irq_root_status))
		__set_bit(IPIPE_STALL_NMI_FLAG, &irq_root_status);
	else
		__clear_bit(IPIPE_STALL_NMI_FLAG, &irq_root_status);
}
EXPORT_SYMBOL(irq_pipeline_nmi_enter);

void irq_pipeline_nmi_exit(void)
{
	if (test_bit(IPIPE_STALL_NMI_FLAG, &irq_root_status))
		__set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	else
		__clear_bit(IPIPE_STALL_FLAG, &irq_root_status);
}
EXPORT_SYMBOL(irq_pipeline_nmi_exit);

bool irq_pipeline_steal_tick(void) /* Preemption disabled. */
{
	struct irq_pipeline_data *p;

	p = raw_cpu_ptr(&irq_pipeline);

	return arch_steal_pipelined_tick(&p->tick_regs);
}

#ifndef CONFIG_SPARSE_IRQ
EXPORT_SYMBOL_GPL(irq_desc);
#endif
