/* -*- linux-c -*-
 * kernel/irq/irqptorture.c
 *
 * Copyright (C) 2017 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Torture test module of the IRQ pipeline.
 */
#include <linux/kernel.h>
#include <linux/torture.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/tick.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irq_pipeline.h>
#include <linux/stop_machine.h>
#include <linux/irq_work.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include "settings.h"

static struct irq_stage torture_stage;

/*
 * Configure and register the proxy device.
 */
static void torture_device_register(struct clock_event_device *proxy_ced,
				    struct clock_event_device *real_ced)
{
	u32 freq = (1000000000ULL * real_ced->mult) >> real_ced->shift;

	/*
	 * Ensure the proxy device has a better rating than the real
	 * one, so that it will be picked immediately as the system
	 * tick device when registered.
	 */
	proxy_ced->rating = real_ced->rating + 1;

	/*
	 * Configure the proxy as a transparent device, which passes
	 * on timing requests to the real device unmodified. This is
	 * basically the default configuration we received from
	 * tick_install_proxy().
	 */
	clockevents_config_and_register(proxy_ced, freq,
					real_ced->min_delta_ticks,
					real_ced->max_delta_ticks);

	pr_alert("irq_pipeline" TORTURE_FLAG
		 " CPU%d: proxy tick registered (%u.%02uMHz)\n",
		 smp_processor_id(), freq / 1000000, (freq / 10000) % 100);
}

static void torture_event_handler(struct clock_event_device *real_ced)
{
	/*
	 * We are running from the head stage, in NMI-like
	 * mode. Schedule a tick on the proxy device to satisfy the
	 * corresponding timing request asap.
	 */
	tick_notify_proxy();
}

static struct proxy_tick_ops proxy_ops = {
	.register_device = torture_device_register,
	.handle_event = torture_event_handler,
};

static int start_tick_takeover_test(void)
{
	return tick_install_proxy(&proxy_ops, cpu_online_mask);
}

static void stop_tick_takeover_test(void)
{
	tick_uninstall_proxy(&proxy_ops, cpu_online_mask);
}

struct stop_machine_p_data {
	int origin_cpu;
	cpumask_var_t disable_mask;
};

static int stop_machine_handler(void *arg)
{
	struct stop_machine_p_data *p = arg;
	int cpu = raw_smp_processor_id();

	/*
	 * The stop_machine_pipelined() handler must run with hard
	 * IRQs off, note the current state in the result mask.
	 */
	if (hard_irqs_disabled())
		cpumask_set_cpu(cpu, p->disable_mask);

	if (cpu != p->origin_cpu)
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d responds to stop_machine_pipelined()\n", cpu);
	return 0;
}

static int test_stop_machine_pipelined(void)
{
	struct stop_machine_p_data d;
	cpumask_var_t tmp_mask;
	int ret = -EINVAL, cpu;

	if (!zalloc_cpumask_var(&d.disable_mask, GFP_KERNEL)) {
		WARN_ON(1);
		return -EINVAL;
	}
	
	if (!alloc_cpumask_var(&tmp_mask, GFP_KERNEL)) {
		WARN_ON(1);
		goto fail;
	}

	d.origin_cpu = smp_processor_id();
	pr_alert("irq_pipeline" TORTURE_FLAG
		 " CPU%d initiates stop_machine_pipelined()\n",
		 d.origin_cpu);

	ret = stop_machine_pipelined(stop_machine_handler,
				     &d, cpu_online_mask);
	WARN_ON(ret);
	if (ret)
		goto fail;

	/*
	 * Check whether all handlers did run with hard IRQs off. If
	 * some of them did not, then we have a problem with the stop
	 * IRQ delivery.
	 */
	cpumask_xor(tmp_mask, cpu_online_mask, d.disable_mask);
	if (!cpumask_empty(tmp_mask)) {
		for_each_cpu(cpu, tmp_mask)
			pr_alert("irq_pipeline" TORTURE_FLAG
				 " CPU%d: hard IRQs ON in stop_machine_pipelined()"
				 " handler!\n", cpu);
	}
	
	free_cpumask_var(tmp_mask);
fail:
	free_cpumask_var(d.disable_mask);

	return ret;
}

static struct irq_work_tester {
	struct irq_work work;
	struct completion done;
} irq_work_tester;

static void irq_work_handler(struct irq_work *work)
{
	if (!on_root_stage()) {
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: irq_work handler not running on"
			 " root stage?!\n", smp_processor_id());
		return;
	}
	
	if (work != &irq_work_tester.work)
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: irq_work handler received broken"
			 " arg?!\n", smp_processor_id());
	else {
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: irq_work handled\n", smp_processor_id());
		complete(&irq_work_tester.done);
	}
}

static int trigger_head_work(void *arg)
{
	if (!on_head_stage()) {
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: escalated request not running on"
			 " head stage?!\n", smp_processor_id());
		return -EINVAL;
	}
	
	if ((struct irq_work_tester *)arg != &irq_work_tester) {
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: escalation handler received broken"
			 " arg?!\n", raw_smp_processor_id());
		return -EINVAL;
	}

	irq_work_queue(&irq_work_tester.work);
	pr_alert("irq_pipeline" TORTURE_FLAG
		 " CPU%d: stage escalation request works\n",
		 raw_smp_processor_id());

	return 0;
}

static int test_interstage_work_injection(void)
{
	struct irq_work_tester *p = &irq_work_tester;
	unsigned long rem;
	int ret;

	init_completion(&p->done);
	init_irq_work(&p->work, irq_work_handler);

	/* Trigger over the root stage. */
	irq_work_queue(&p->work);
	rem = wait_for_completion_timeout(&p->done, HZ / 10);
	if (!rem) {
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: irq_work trigger from root stage not handled!\n",
			 smp_processor_id());
		return -EINVAL;
	}

	pr_alert("irq_pipeline" TORTURE_FLAG
		 " CPU%d: root->root irq_work trigger works\n",
		 smp_processor_id());

	reinit_completion(&p->done);

	/* Now try over the head stage. */
	ret = irq_stage_escalate(trigger_head_work, p);
	if (ret)
		return ret;
		
	ret = wait_for_completion_timeout(&p->done, HZ / 10);
	if (!rem) {
		pr_alert("irq_pipeline" TORTURE_FLAG
			 " CPU%d: irq_work trigger from head"
			 " stage not handled!\n", smp_processor_id());
		return -EINVAL;
	}

	pr_alert("irq_pipeline" TORTURE_FLAG
		 " CPU%d: head->root irq_work trigger works\n",
		 smp_processor_id());

	return 0;
}

static int __init irqp_torture_init(void)
{
	int ret;

	pr_info("Starting IRQ pipeline tests...");

	ret = irq_stage_push(&torture_stage, "torture");
	if (ret) {
		if (ret == -EBUSY)
			pr_alert("irq_pipeline" TORTURE_FLAG
			 " won't run, head stage '%s' is already installed",
			 head_irq_stage->name);
		
		return ret;
	}

	ret = test_stop_machine_pipelined();
	if (ret)
		goto out;
	ret = start_tick_takeover_test();
	if (ret)
		goto out;
	ret = test_interstage_work_injection();
	if (!ret)
		msleep(1000);
	stop_tick_takeover_test();
out:
	irq_stage_pop(&torture_stage);
	pr_info("IRQ pipeline tests %s.", ret ? "FAILED" : "OK");

	return 0;
}
late_initcall(irqp_torture_init);
