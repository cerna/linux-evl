/* -*- linux-c -*-
 * kernel/irq/pipeline.c
 *
 * Copyright (C) 2002-2017 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * IRQ pipeline.
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kconfig.h>
#include <linux/sched.h>
#include <linux/printk.h>
#include <linux/seq_buf.h>
#include <linux/kallsyms.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/clockchips.h>
#include <linux/uaccess.h>
#include <linux/irqdomain.h>
#include <trace/events/irq.h>
#include "internals.h"

struct irq_stage root_irq_stage = {
	.name = "Linux",
};
EXPORT_SYMBOL_GPL(root_irq_stage);

struct irq_stage *head_irq_stage = &root_irq_stage;
EXPORT_SYMBOL_GPL(head_irq_stage);

struct irq_domain *synthetic_irq_domain;
EXPORT_SYMBOL_GPL(synthetic_irq_domain);

static bool irq_pipeline_oopsing;

#define IRQ_LOW_MAPSZ	DIV_ROUND_UP(IRQ_BITMAP_BITS, BITS_PER_LONG)

#if IRQ_LOW_MAPSZ > BITS_PER_LONG
/*
 * We need a 3-level mapping. This allows us to handle up to 32k IRQ
 * vectors on 32bit machines, 256k on 64bit ones.
 */
#define __IRQ_STAGE_MAP_LEVELS	3
#define IRQ_MID_MAPSZ	DIV_ROUND_UP(IRQ_LOW_MAPSZ, BITS_PER_LONG)
#else
/*
 * 2-level mapping is enough. This allows us to handle up to 1024 IRQ
 * vectors on 32bit machines, 4096 on 64bit ones.
 */
#define __IRQ_STAGE_MAP_LEVELS	2
#endif

struct irq_event_map {
#if __IRQ_STAGE_MAP_LEVELS == 3
	unsigned long mdmap[IRQ_MID_MAPSZ];
#endif
	unsigned long lomap[IRQ_LOW_MAPSZ];
};

#ifdef CONFIG_SMP

static struct irq_event_map bootup_irq_map __initdata;

static struct irq_stage_data bootup_irq_data __initdata = {
	.stage = &root_irq_stage,
	.status = (1 << STAGE_STALL_BIT),
	.log = {
		.map = &bootup_irq_map,
	},
};

static DEFINE_PER_CPU(struct irq_event_map, irq_map_array[2]); /* FIXME: __initdata?? */

DEFINE_PER_CPU(struct irq_pipeline_data, irq_pipeline) = {
	.curr = &bootup_irq_data,
};

static struct cpumask smp_sync_map;
static struct cpumask smp_lock_map;
static struct cpumask smp_pass_map;
static unsigned long smp_lock_wait;
static DEFINE_HARD_SPINLOCK(smp_barrier);
static atomic_t smp_lock_count = ATOMIC_INIT(0);
static cpu_stop_fn_t smp_sync_fn;
static void *smp_sync_data;

static irqreturn_t pipeline_sync_handler(int irq, void *dev_id)
{
	int cpu = raw_smp_processor_id(), ret;

	WARN_ON_ONCE(!hard_irqs_disabled());

	cpumask_set_cpu(cpu, &smp_sync_map);

	/*
	 * We are now in sync with the lock requestor running on a
	 * remote CPU. Enter a spinning wait until the global lock is
	 * released.
	 */
	raw_spin_lock(&smp_barrier);

	/*
	 * Passed the barrier, now call the synchronization routine on
	 * this remote CPU.  A sync routine better never fail, or
	 * something is really broken. We don't currently pass the
	 * status code back to the caller, but we complain loudly on
	 * failure.
	 */
	if (smp_sync_fn) {
		ret = smp_sync_fn(smp_sync_data);
		WARN_ON(ret);
	}

	cpumask_set_cpu(cpu, &smp_pass_map);

	raw_spin_unlock(&smp_barrier);

	cpumask_clear_cpu(cpu, &smp_sync_map);

	return IRQ_HANDLED;
}

static struct irqaction lock_ipi = {
	.handler = pipeline_sync_handler,
	.name = "Pipeline lock interrupt",
	.flags = IRQF_OOB | IRQF_PERCPU,
};

#else /* !CONFIG_SMP */

static struct irq_event_map root_irq_map;

static struct irq_event_map head_irq_map;

DEFINE_PER_CPU(struct irq_pipeline_data, irq_pipeline) = {
	.stages = {
		[0] = {
			.log = {
				.map = &root_irq_map,
			},
			.stage = &root_irq_stage,
			.status = (1 << STAGE_STALL_BIT),
		},
		[1] = {
			.log = {
				.map = &head_irq_map,
			},
		},
	},
	.curr = &irq_pipeline.stages[0],
};

#endif /* !CONFIG_SMP */

EXPORT_PER_CPU_SYMBOL(irq_pipeline);

static void sirq_noop(struct irq_data *data) { }

/* Virtual interrupt controller for synthetic IRQs. */
static struct irq_chip sirq_chip = {
	.name		= "SIRQC",
	.irq_enable	= sirq_noop,
	.irq_disable	= sirq_noop,
	.flags		= IRQCHIP_PIPELINE_SAFE | IRQCHIP_SKIP_SET_WAKE,
};

static int sirq_map(struct irq_domain *d, unsigned int irq,
		    irq_hw_number_t hwirq)
{
	irq_set_percpu_devid(irq);
	irq_set_chip_and_handler(irq, &sirq_chip, handle_synthetic_irq);

	return 0;
}

static struct irq_domain_ops sirq_domain_ops = {
	.map	= sirq_map,
};

/**
 *	handle_synthetic_irq -  synthetic irq handler
 *	@desc:	the interrupt description structure for this irq
 *
 *	Handles synthetic interrupts flowing down the IRQ pipeline
 *	with per-CPU semantics.
 *
 *      CAUTION: synthetic IRQs may be used to map hardware-generated
 *      events (e.g. IPIs or traps), we must start handling them as
 *      common interrupts.
 */
void handle_synthetic_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);
	struct irqaction *action;
	irqreturn_t ret;
	
	if (on_pipeline_entry()) {
		handle_oob_irq(desc);
		return;
	}

	action = desc->action;
	kstat_incr_irqs_this_cpu(desc);
	trace_irq_handler_entry(irq, action);
	ret = action->handler(irq, action->dev_id);
	trace_irq_handler_exit(irq, action, ret);
}

/**
 * irq_stage_context - IRQ stage data on specified CPU
 *
 * Return the address of @stage's data on @cpu. IRQs must be hard
 * disabled to prevent CPU migration.
 *
 * NOTE: this is the slowest accessor, use it carefully. Prefer
 * irq_stage_this_context() for requests targeted at the current
 * CPU. Additionally, if the target stage is known at build time,
 * consider irq_{root, head}_this_context().
 */
struct irq_stage_data *irq_stage_context(struct irq_stage *stage, int cpu)
{
	return &per_cpu(irq_pipeline.stages, cpu)[stage->index];
}

static inline
struct irq_stage_data *__irq_stage_this_context(struct irq_stage *stage)
{
	return &this_cpu_ptr(irq_pipeline.stages)[stage->index];
}

/**
 * irq_stage_this_context - IRQ stage data on the current CPU
 *
 * Return the address of @stage's data on the current CPU. IRQs must
 * be hard disabled to prevent CPU migration.
 */
struct irq_stage_data *irq_stage_this_context(struct irq_stage *stage)
{
	return __irq_stage_this_context(stage);
}

void irq_stage_sync(struct irq_stage *top)
{
	struct irq_stage_data *p;
	struct irq_stage *stage;

	/* We must enter over the root stage with hardirqs off. */
	if (irq_pipeline_debug()) {
		WARN_ON_ONCE(!hard_irqs_disabled());
		WARN_ON_ONCE(__current_irq_stage != &root_irq_stage);
	}

	stage = top;

	for (;;) {
		p = __irq_stage_this_context(stage);
		if (test_bit(STAGE_STALL_BIT, &p->status))
			break;

		if (irq_staged_waiting(p)) {
			if (stage == &root_irq_stage)
				irq_stage_sync_current();
			else {
				/* Switch to head before synchronizing. */
				irq_set_head_context(p);
				irq_stage_sync_current();
				/* Then back to the root stage. */
				irq_set_root_context(irq_root_this_context());
			}
		}

		if (stage == &root_irq_stage)
			break;
		
		stage = &root_irq_stage;
	}
}

static void synchronize_pipeline(struct irq_stage *top) /* hardirqs off */
{
	if (__current_irq_stage != top)
		irq_stage_sync(top);
	else if (!test_bit(STAGE_STALL_BIT,
			   &__irq_stage_this_context(top)->status))
		irq_stage_sync_current();
}

notrace void __root_irq_enable(void)
{
	struct irq_stage_data *p;
	unsigned long flags;

	/* This helps catching bad usage from assembly call sites. */
	check_root_stage();

	flags = hard_local_irq_save();

	p = irq_root_this_context();
	trace_hardirqs_on();
	__clear_bit(STAGE_STALL_BIT, &p->status);
	if (unlikely(irq_staged_waiting(p))) {
		irq_stage_sync_current();
		hard_local_irq_restore(flags);
		preempt_check_resched();
	} else
		hard_local_irq_restore(flags);
}
EXPORT_SYMBOL(__root_irq_enable);

/**
 *	root_irq_enable - (virtually) enable interrupts
 *
 *	Enable interrupts for the root stage, allowing interrupts to
 *	preempt the in-band code. If in-band IRQs are pending for the
 *	root stage in the per-CPU log at the time of this call, they
 *	are played back.
 */
notrace void root_irq_enable(void)
{
	/*
	 * We are NOT supposed to enter this code with hard IRQs off.
	 * If we do, then the caller might be wrongly assuming that
	 * invoking local_irq_enable() implies enabling hard
	 * interrupts like the legacy I-pipe did, which is not the
	 * case anymore.
	 */
	WARN_ON_ONCE(irq_pipeline_debug() && hard_irqs_disabled());
	__root_irq_enable();
}
EXPORT_SYMBOL(root_irq_enable);

/**
 *	root_irq_disable - (virtually) disable interrupts
 *
 *	Disable interrupts for the root stage, disabling in-band
 *	interrupts. Out-of-band interrupts can still be taken and
 *	delivered to their respective handlers though.
 */
notrace void root_irq_disable(void)
{
	unsigned long flags;

	check_root_stage();
	flags = hard_local_irq_save();
	__set_bit(STAGE_STALL_BIT, &irq_root_status);
	trace_hardirqs_off();
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL(root_irq_disable);

/**
 *	root_irqs_disabled - test the virtual interrupt state
 *
 *	Returns non-zero if interrupts are currently disabled for the
 *	root stage, zero otherwise.
 */
notrace unsigned long root_irqs_disabled(void)
{
	unsigned long flags, x;

	flags = hard_smp_local_irq_save();
	x = test_bit(STAGE_STALL_BIT, &irq_root_status);
	hard_smp_local_irq_restore(flags);

	return x;
}
EXPORT_SYMBOL(root_irqs_disabled);

/**
 *	root_irq_save - test and disable (virtual) interrupts
 *
 *	Save the virtual interrupt state then disables interrupts for
 *	the root stage.
 *
 *      Returns the original interrupt state.
 */
notrace unsigned long root_irq_save(void)
{
	unsigned long flags, x;

	check_root_stage();
	flags = hard_local_irq_save();
	x = __test_and_set_bit(STAGE_STALL_BIT, &irq_root_status);
	trace_hardirqs_off();
	hard_local_irq_restore(flags);

	return x;
}
EXPORT_SYMBOL(root_irq_save);

/**
 *	root_irq_restore - restore the (virtual) interrupt state
 *      @x:	Interrupt state to restore
 *
 *	Restore the virtual interrupt state from x. If the root stage
 *	is unstalled as a consequence of this operation, any interrupt
 *	pending for the root stage in the per-CPU log is played back.
 */
notrace void root_irq_restore(unsigned long x)
{
	if (x)
		root_irq_disable();
	else
		__root_irq_enable();
}
EXPORT_SYMBOL(root_irq_restore);

notrace void __root_irq_restore_nosync(unsigned long x)
{
	struct irq_stage_data *p = irq_root_this_context();

	if (raw_irqs_disabled_flags(x)) {
		__set_bit(STAGE_STALL_BIT, &p->status);
		trace_hardirqs_off();
	} else {
		trace_hardirqs_on();
		__clear_bit(STAGE_STALL_BIT, &p->status);
	}
}
EXPORT_SYMBOL(__root_irq_restore_nosync);

/**
 *	root_irq_restore_nosync - restore the (virtual) interrupt state
 *      @x:	Interrupt state to restore
 *
 *	Restore the virtual interrupt state from x. Unlike
 *	root_irq_restore(), pending interrupts are not played back.
 */
notrace void root_irq_restore_nosync(unsigned long x)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	__root_irq_restore_nosync(x);
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL(root_irq_restore_nosync);

/**
 *	head_irq_enable - enable interrupts in the CPU
 *
 *	Enable interrupts in the CPU, allowing out-of-band interrupts
 *	to preempt any code. If out-of-band IRQs are pending in the
 *	per-CPU log for the head stage at the time of this call, they
 *	are played back.
 */
notrace void head_irq_enable(void)
{
	struct irq_stage_data *p = irq_head_this_context();

	hard_local_irq_disable();

	__clear_bit(STAGE_STALL_BIT, &p->status);

	if (unlikely(irq_staged_waiting(p)))
		synchronize_pipeline(head_irq_stage);

	hard_local_irq_enable();
}
EXPORT_SYMBOL(head_irq_enable);

/**
 *	head_irq_restore - restore the hardware interrupt state
 *      @x:	Interrupt state to restore
 *
 *	Restore the harware interrupt state from x. If the head stage
 *	is unstalled as a consequence of this operation, any interrupt
 *	pending for the head stage in the per-CPU log is played back
 *	prior to turning IRQs on.
 */
notrace void __head_irq_restore(unsigned long x) /* hw interrupt off */
{
	struct irq_stage_data *p = irq_head_this_context();

	check_hard_irqs_disabled();

	if (!x) {
		__clear_bit(STAGE_STALL_BIT, &p->status);
		if (unlikely(irq_staged_waiting(p)))
			synchronize_pipeline(head_irq_stage);
		hard_local_irq_enable();
	}
}
EXPORT_SYMBOL(__head_irq_restore);

/**
 *	irq_stage_disabled - test the interrupt state of the current stage
 *
 *	Returns non-zero if interrupts are currently disabled for the
 *	current interrupt stage, zero otherwise.
 *      In other words, returns non-zero either if:
 *      - interrupts are disabled in the CPU,
 *      - the root stage is current and interrupts are virtually disabled.
 */
notrace bool irq_stage_disabled(void)
{
	unsigned long flags;
	bool ret = true;
	
	if (!hard_irqs_disabled()) {
		ret = false;
		flags = hard_smp_local_irq_save();
		if (on_root_stage())
			ret = test_bit(STAGE_STALL_BIT, &irq_root_status);
		hard_smp_local_irq_restore(flags);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(irq_stage_disabled);

/**
 *	irq_stage_test_and_disable - test and disable interrupts for
 *                                   the current stage
 *	@irqsoff:	Pointer to boolean denoting irq_stage_disabled()
 *                      on entry
 *
 *	Fully disables interrupts for the current stage. When the root
 *	stage is current, the stall bit is raised and hardware IRQs
 *	are masked as well. Only the latter operation is performed
 *	when the head stage is current.
 *
 *      Returns the combined interrupt state on entry including the
 *      real/hardware (in CPU) and virtual (root stage) states. For
 *      this reason, irq_stage_[test_and_]disable() must be paired
 *      with irq_stage_restore() exclusively. The flags returned by
 *      the former may NOT be used with the hard_irq_* API.
 */
notrace unsigned long irq_stage_test_and_disable(int *irqsoff)
{
	unsigned long flags;
	int stalled, dummy;

	if (irqsoff == NULL)
		irqsoff = &dummy;

	/*
	 * Forge flags combining the hardware and virtual IRQ
	 * states. We need to fill in the virtual state only if the
	 * root stage is current, otherwise it is not relevant.
	 */
	flags = hard_local_irq_save();
	*irqsoff = hard_irqs_disabled_flags(flags);
	if (on_root_stage()) {
		stalled = __test_and_set_bit(STAGE_STALL_BIT, &irq_root_status);
		flags = arch_irqs_merge_flags(flags, stalled);
		if (stalled)
			*irqsoff = 1;
	}

	/*
	 * CAUTION: don't ever pass this verbatim to
	 * hard_local_irq_restore(). Only irq_stage_restore() knows
	 * how to decode and use a combined flags variable.
	 */
	return flags;
}
EXPORT_SYMBOL_GPL(irq_stage_test_and_disable);

/**
 *	irq_stage_restore - restore interrupts for the current stage
 *	@flags: 	Combined interrupt state to restore as received from
 *              	irq_stage_test_and_disable()
 *
 *	Restore the virtual interrupt state if the root stage is
 *      current, and the hardware interrupt state unconditionally.
 *      The per-CPU log is not played for any stage.
 */
notrace void irq_stage_restore(unsigned long flags)
{
	int stalled;

	WARN_ON_ONCE(irq_pipeline_debug() && !hard_irqs_disabled());

	if (on_root_stage()) {
		flags = arch_irqs_split_flags(flags, &stalled);
		if (!stalled)
			__clear_bit(STAGE_STALL_BIT, &irq_root_status);
	}

	/*
	 * Only the interrupt bit is present in the combo state, all
	 * other status bits have been cleared by
	 * arch_irqs_merge_flags(), so don't ever try to restore the
	 * hardware status register with such flag word directly...
	 */
	if (!hard_irqs_disabled_flags(flags))
		hard_local_irq_enable();
}
EXPORT_SYMBOL_GPL(irq_stage_restore);

#if __IRQ_STAGE_MAP_LEVELS == 3

/* Must be called hw IRQs off. */
void irq_stage_post_event(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = __irq_stage_this_context(stage);
	int l0b, l1b;

	if (WARN_ON_ONCE(irq_pipeline_debug() &&
			 (!hard_irqs_disabled() || irq >= IRQ_BITMAP_BITS)))
		return;

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	__set_bit(irq, p->log.map->lomap);
	__set_bit(l1b, p->log.map->mdmap);
	__set_bit(l0b, &p->log.himap);
}
EXPORT_SYMBOL_GPL(irq_stage_post_event);

static void __clear_pending_irq(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = __irq_stage_this_context(stage);
	int l0b, l1b;

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	__clear_bit(irq, p->log.map->lomap);
	__clear_bit(l1b, p->log.map->mdmap);
	__clear_bit(l0b, &p->log.himap);
}

static inline int pull_next_irq(struct irq_stage_data *p)
{
	int l0b, l1b, l2b;
	unsigned long l0m, l1m, l2m;
	unsigned int irq;

	l0m = p->log.himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = ffs(l0m) - 1;
	l1m = p->log.map->mdmap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = ffs(l1m) - 1 + l0b * BITS_PER_LONG;
	l2m = p->log.map->lomap[l1b];
	if (unlikely(l2m == 0))
		return -1;

	l2b = ffs(l2m) - 1;
	irq = l1b * BITS_PER_LONG + l2b;

	__clear_bit(irq, p->log.map->lomap);
	if (p->log.map->lomap[l1b] == 0) {
		__clear_bit(l1b, p->log.map->mdmap);
		if (p->log.map->mdmap[l0b] == 0)
			__clear_bit(l0b, &p->log.himap);
	}

	return irq;
}

#else /* __IRQ_STAGE_MAP_LEVELS == 2 */

static void __clear_pending_irq(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = __irq_stage_this_context(stage);
	int l0b = irq / BITS_PER_LONG;

	__clear_bit(irq, p->log.map->lomap);
	__clear_bit(l0b, &p->log.himap);
}

/* Must be called hw IRQs off. */
void irq_stage_post_event(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = __irq_stage_this_context(stage);
	int l0b = irq / BITS_PER_LONG;

	if (WARN_ON_ONCE(irq_pipeline_debug() &&
			 (!hard_irqs_disabled() || irq >= IRQ_BITMAP_BITS)))
		return;

	__set_bit(irq, p->log.map->lomap);
	__set_bit(l0b, &p->log.himap);
}
EXPORT_SYMBOL_GPL(irq_stage_post_event);

static inline int pull_next_irq(struct irq_stage_data *p)
{
	unsigned long l0m, l1m;
	int l0b, l1b;

	l0m = p->log.himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = ffs(l0m) - 1;
	l1m = p->log.map->lomap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = ffs(l1m) - 1;
	__clear_bit(l1b, &p->log.map->lomap[l0b]);
	if (p->log.map->lomap[l0b] == 0)
		__clear_bit(l0b, &p->log.himap);

	return l0b * BITS_PER_LONG + l1b;
}

#endif  /* __IRQ_STAGE_MAP_LEVELS == 2 */

/**
 *	irq_pipeline_clear - clear IRQ event from per-CPU log
 *	@irq:	 IRQ to clear
 *
 *      Clear the given irq from the interrupt log for both the root
 *      and head stages on the current CPU.
 */
void irq_pipeline_clear(unsigned int irq)
{
	unsigned long flags;
	
	flags = hard_local_irq_save();

	__clear_pending_irq(&root_irq_stage, irq);
	if (head_stage_present())
		__clear_pending_irq(head_irq_stage, irq);

	hard_local_irq_restore(flags);
}

/**
 *	hard_preempt_disable - Disable preemption the hard way
 *
 *      Disable hardware interrupts in the CPU, and disable preemption
 *      if currently running in-band code on the root stage.
 *
 *      Return the hardware interrupt state.
 */
unsigned long hard_preempt_disable(void)
{
	unsigned long flags = hard_local_irq_save();

	if (on_root_stage())
		preempt_disable();

	return flags;
}
EXPORT_SYMBOL_GPL(hard_preempt_disable);

/**
 *	hard_preempt_enable - Enable preemption the hard way
 *
 *      Enable preemption if currently running in-band code on the
 *      root stage, restoring the hardware interrupt state in the CPU.
 *      The per-CPU log is not played for the head stage.
 */
void hard_preempt_enable(unsigned long flags)
{
	if (on_root_stage()) {
		preempt_enable_no_resched();
		hard_local_irq_restore(flags);
		preempt_check_resched();
	} else
		hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(hard_preempt_enable);

static inline
irqreturn_t __call_action_handler(struct irqaction *action,
				  struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);
	void *dev_id = action->dev_id;

	if (irq_settings_is_per_cpu_devid(desc))
		dev_id = raw_cpu_ptr(action->percpu_dev_id);

	return action->handler(irq, dev_id);
}

static void handle_unexpected_irq(struct irq_desc *desc, irqreturn_t ret)
{
	unsigned int irq = irq_desc_get_irq(desc);
	struct irqaction *action;

	raw_spin_lock(&desc->lock);

	/*
	 * Since IRQ_HANDLED was not received from any handler, we may
	 * have a problem dealing with an OOB interrupt. The error
	 * detection logic is as follows:
	 *
	 * - check and complain about any bogus return value from a
	 * out-of-band IRQ handler: we only allow IRQ_HANDLED and
	 * IRQ_NONE from those routines.
	 *
	 * - filter out spurious IRQs which may have been due to bus
	 * asynchronicity, those tend to happen infrequently and
	 * should not cause us to pull the break (see
	 * note_interrupt()).
	 *
	 * - otherwise, stop pipelining the IRQ line after a thousand
	 * consecutive unhandled events.
	 */

	if (ret != IRQ_NONE) {
		printk(KERN_ERR "out-of-band irq event %d: bogus return value %x\n",
				irq, ret);
		for_each_action_of_desc(desc, action)
			printk(KERN_ERR "[<%p>] %pf",
			       action->handler, action->handler);
		printk(KERN_CONT "\n");
		goto out;
	}
	
	if (time_after(jiffies, desc->last_unhandled + HZ/10))
		desc->irqs_unhandled = 0;
	else
		desc->irqs_unhandled++;

	desc->last_unhandled = jiffies;

	/*
	 * If more than a thousand unhandled events were received
	 * consecutively, we have to stop this IRQ from poking us at
	 * the head of the pipeline by disabling out-of-band mode for
	 * the interrupt.
	 */
	if (unlikely(desc->irqs_unhandled > 1000)) {
		printk(KERN_ERR "out-of-band irq %d: stuck or unexpected\n", irq);
		irq_stage_post_root(irq); /* only pending, not synced yet */
		irq_settings_clr_oob(desc);
		desc->istate |= IRQS_SPURIOUS_DISABLED;
		irq_disable(desc);
	}
out:
	raw_spin_unlock(&desc->lock);
}

void __weak irq_enter_head(void) { }

void __weak irq_exit_head(void) { }

/*
 * do_oob_irq() - Handles interrupts over the head stage. Hard irqs
 * off.
 */
static void do_oob_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);
	irqreturn_t ret = IRQ_NONE, res;
	struct irqaction *action;

	kstat_incr_irqs_this_cpu(desc);

	for_each_action_of_desc(desc, action) {
		trace_irq_handler_entry(irq, action);
		res = __call_action_handler(action, desc);
		trace_irq_handler_exit(irq, action, res);
		ret |= res;
	}

	if (likely(ret & IRQ_HANDLED)) {
		desc->irqs_unhandled = 0;
		return;
	}

	handle_unexpected_irq(desc, ret);
}

/*
 * Over the root stage, IRQs must be dispatched by the arch-specific
 * do_IRQ_pipelined() routine.
 *
 * Entered with hardirqs on, root stalled.
 */
static inline
void do_root_irq(struct irq_desc *desc)
{
	do_IRQ_pipelined(desc);
	WARN_ON_ONCE(irq_pipeline_debug() && !irqs_disabled());
}

static void dispatch_oob_irq(struct irq_desc *desc) /* hardirqs off */
{
	struct irq_stage_data *p = irq_head_this_context(), *old;
	struct irq_stage *head = p->stage;

	if (unlikely(test_bit(STAGE_STALL_BIT, &p->status))) {
		irq_stage_post_event(head, irq_desc_get_irq(desc));
		/* We may NOT have hardirqs on with a stalled head. */
		WARN_ON_ONCE(irq_pipeline_debug() && on_pipeline_entry());
		return;
	}

	/* Switch to the head stage if not current. */
	old = irq_current_context;
	if (old != p)
		irq_set_head_context(p);

	__set_bit(STAGE_STALL_BIT, &p->status);
	do_oob_irq(desc);
	__clear_bit(STAGE_STALL_BIT, &p->status);

	if (irq_pipeline_debug()) {
		/* No CPU migration allowed. */
		WARN_ON_ONCE(irq_head_this_context() != p);
		/* No stage migration allowed. */
		WARN_ON_ONCE(irq_current_context->stage != head);
	}

	if (old->stage != head)
		irq_set_root_context(old);
}

static bool inject_irq(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);
	struct irq_stage *stage;

	/*
	 * If there is no registered head stage, all interrupts go
	 * through the interrupt log.
	 *
	 * Otherwise, out-of-band IRQs are immediately delivered
	 * (dispatch_oob_irq()), while only in-band IRQs go through
	 * the interrupt log.
	 *
	 * This routine returns a boolean status telling the caller
	 * whether an out-of-band interrupt was delivered.
	 */
	stage = head_irq_stage;
	if (likely(stage != &root_irq_stage)) {
		if (irq_settings_is_oob(desc)) {
			dispatch_oob_irq(desc);
			return true;
		}
		stage = &root_irq_stage;
	}

	irq_stage_post_event(stage, irq);

	return false;
}

static void synchronize_pipeline_on_irq(void)
{
	/*
	 * Optimize if we preempted the high priority head stage: we
	 * don't need to synchronize the pipeline unless there is a
	 * pending interrupt for it.
	 */
	if (on_root_stage() ||
	    irq_staged_waiting(irq_head_this_context()))
		synchronize_pipeline(head_irq_stage);
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
	arch_save_timer_regs(&p->tick_regs, regs, on_head_stage());
}

/**
 *	generic_pipeline_irq - Pass an IRQ to the pipeline
 *	@irq:	IRQ to pass
 *	@regs:	Register file coming from the low-level handling code
 *
 *	Inject an IRQ into the pipeline from a CPU interrupt or trap
 *	context.  A flow handler runs for this IRQ.
 *
 *      Hard irqs must be off on entry.
 */
int generic_pipeline_irq(unsigned int irq, struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
	struct irq_desc *desc = irq_to_desc(irq);

	if (irq_pipeline_debug()) {
		if (!hard_irqs_disabled()) {
			hard_local_irq_disable();
			pr_err("IRQ pipeline: interrupts enabled on entry (IRQ%u)\n",
			       irq);
		}
		if (unlikely(desc == NULL)) {
			pr_err("IRQ pipeline: received unhandled IRQ%u\n",
			       irq);
			return -EINVAL;
		}
	}

	/*
	 * We should not re-enter here from a chained IRQ flow
	 * handler, deal with API abuse gracefully anyway.
	 */
	if (unlikely(on_pipeline_entry())) {
		WARN_ON_ONCE(irq_pipeline_debug());
		generic_handle_irq_desc(desc);
		goto out;
	}

	copy_timer_regs(desc, regs);
	irq_enter_head();
	preempt_count_add(PIPELINE_OFFSET);
	generic_handle_irq_desc(desc);
	preempt_count_sub(PIPELINE_OFFSET);
	/*
	 * We have to synchronize the logs because interrupts might
	 * have been logged while we were busy handling an OOB event
	 * coming from the hardware:
	 *
	 * - as a result of calling an OOB handler which in turned
	 * posted them.
	 *
	 * - because we posted them directly for scheduling the
	 * interrupt to happen from the root stage.
	 *
	 * This also means that hardware-originated OOB events have
	 * higher precedence when received than software-originated
	 * ones, which are synced once all IRQ flow handlers involved
	 * in the interrupt have run.
	 */
	irq_exit_head();
	synchronize_pipeline_on_irq();
out:
	set_irq_regs(old_regs);

	return 0;
}

bool handle_oob_irq(struct irq_desc *desc) /* hardirqs off */
{
	/*
	 * Flow handlers of chained interrupts have no business
	 * running here: they should decode the event, invoking
	 * generic_handle_irq() for each cascaded IRQ.
	 */
	if (WARN_ON_ONCE(irq_pipeline_debug() &&
			 irq_settings_is_chained(desc)))
		return false;
	
	return inject_irq(desc);
}

/**
 *	irq_pipeline_inject - Inject a software-generated IRQ into the pipeline
 *	@irq:	IRQ to inject
 *
 *	Inject an IRQ into the pipeline by software as if such
 *	hardware event had happened on the current CPU.
 */
int irq_pipeline_inject(unsigned int irq)
{
	struct irq_desc *desc;
	unsigned long flags;

	desc = irq_to_desc(irq);
	if (desc == NULL)
		return -EINVAL;

	flags = hard_local_irq_save();
	irq_enter_head();
	inject_irq(desc);
	irq_exit_head();
	synchronize_pipeline_on_irq();
	hard_local_irq_restore(flags);

	return 0;

}
EXPORT_SYMBOL_GPL(irq_pipeline_inject);

/*
 * irq_stage_sync_current() -- Flush the pending IRQs for the current
 * stage (and processor). This routine flushes the interrupt log (see
 * "Optimistic interrupt protection" from D. Stodolsky et al. for more
 * on the deferred interrupt scheme). Every interrupt that occurred
 * while the pipeline was stalled gets played.
 *
 * CAUTION: CPU migration may occur over this routine if running over
 * the root stage.
 */
void irq_stage_sync_current(void) /* hw IRQs off */
{
	struct irq_stage_data *p;
	struct irq_stage *stage;
	struct irq_desc *desc;
	int irq;

	p = irq_current_context;
respin:
	stage = p->stage;
	__set_bit(STAGE_STALL_BIT, &p->status);
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

		desc = irq_to_desc(irq);
	
		if (stage == &root_irq_stage) {
			hard_local_irq_enable();
			do_root_irq(desc);
			hard_local_irq_disable();
		} else
			do_oob_irq(desc);

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
		 * dispatch_oob_irq() for the fast path.
		 */
		p = irq_current_context;
		if (p->stage != stage) {
			WARN_ON_ONCE(irq_pipeline_debug() &&
				     stage == &root_irq_stage);
			if (test_bit(STAGE_STALL_BIT, &p->status))
				return;
			goto respin;
		}
	}

	if (stage == &root_irq_stage)
		trace_hardirqs_on();

	__clear_bit(STAGE_STALL_BIT, &p->status);
}

/**
 *      irq_stage_escalate - escalate function call to the head stage
 *      @fn:    address of routine
 *      @arg:   routine argument
 *
 *      Make the specified function run atomically on the head stage,
 *      switching the current stage accordingly.
 *
 *      This service accounts for the converse stage migration
 *      (i.e. head->root) that might occur during the call.
 *
 *      The root stage must be current on entry.
 */
int __irq_stage_escalate(int (*fn)(void *arg), void *arg)
{
	struct irq_stage_data *p = irq_head_this_context();
	int ret;

	irq_set_head_context(p);
	__set_bit(STAGE_STALL_BIT, &p->status);
	ret = fn(arg);
	/*
	 * Care for CPU migration by re-reading the stage data
	 * pointer. In case of stage migration from head->root, we do
	 * want the stall bit to be cleared for the head stage on the
	 * current CPU.
	 */
	p = irq_head_this_context();
	__clear_bit(STAGE_STALL_BIT, &p->status);
	if (likely(irq_current_context == p)) /* Ditto. */
		irq_set_root_context(irq_root_this_context());

	return ret;
}
EXPORT_SYMBOL_GPL(__irq_stage_escalate);

void irq_push_stage(struct irq_stage *stage, const char *name)
{
	struct irq_event_map *map;
	struct irq_stage_data *p;
	int cpu;

	if (WARN_ON(!on_root_stage() ||
		    stage == &root_irq_stage ||
		    head_stage_present()))
		return;

	stage->index = 1;
	stage->name = name;

	/* Initialize the head IRQ stage data on all CPUs. */

	for_each_possible_cpu(cpu) {
		p = &per_cpu(irq_pipeline.stages, cpu)[1];
		map = p->log.map; /* save/restore after memset(). */
		memset(p, 0, sizeof(*p));
		p->stage = stage;
		memset(map, 0, sizeof(struct irq_event_map));
		p->log.map = map;
	}

	arch_irq_push_stage(stage);
	barrier();
	head_irq_stage = stage;

	pr_info("IRQ pipeline: high-priority %s stage added.\n", name);
}
EXPORT_SYMBOL_GPL(irq_push_stage);

void irq_pop_stage(struct irq_stage *stage)
{
	WARN_ON(!on_root_stage() || stage != head_irq_stage);

	head_irq_stage = &root_irq_stage;
	smp_mb();

	pr_info("IRQ pipeline: %s stage removed.\n", stage->name);
}
EXPORT_SYMBOL_GPL(irq_pop_stage);

/**
 *	irq_pipeline_lock_many - Enter an inter-CPU critical section
 *	@mask:		The set of CPUs to be excluded from the section
 *	@fn:		A routine to invoke once the CPUs are stopped
 *	@data:		Argument to pass to fn
 *
 *      This routine forces the CPU(s) referred to by mask to stop
 *      executing in-band and out-of-band code, by keeping them
 *      spinning in a tight loop until irq_pipeline_unlock() is called
 *      for releasing them. Hardware interrupts are disabled in the
 *      current CPU.
 *
 *	Once the CPUs are stopped and before this routine returns,
 *	fn(data) is called if fn is different from %NULL.
 *
 *	Return the hardware interrupt state saved on entry.
 */
unsigned long irq_pipeline_lock_many(const struct cpumask *mask,
				     cpu_stop_fn_t fn, void *data)
{
	unsigned long flags, loops __maybe_unused;
	struct cpumask allbutself __maybe_unused;
	int cpu __maybe_unused, n __maybe_unused;

	flags = hard_local_irq_save();

	if (num_online_cpus() == 1)
		return flags;

#ifdef CONFIG_SMP
	cpu = raw_smp_processor_id();
	/* Lock recursion is valid, handle it. */
	if (!cpumask_test_and_set_cpu(cpu, &smp_lock_map)) {
		/*
		 * Wait for an ongoing locking sequence to end before
		 * starting a new one.
		 */
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

		smp_sync_fn = fn;
		smp_sync_data = data;

		cpumask_clear(&smp_pass_map);
		cpumask_set_cpu(cpu, &smp_pass_map);

		/*
		 * Send the sync IPI to all processors but the current
		 * one.
		 */
		cpumask_andnot(&allbutself, mask, &smp_pass_map);
		irq_pipeline_send_remote(STOP_OOB_IPI, &allbutself);
		loops = 1000000; /* Timeout loops */

		while (!cpumask_equal(&smp_sync_map, &allbutself)) {
			if (--loops > 0) {
				cpu_relax();
				continue;
			}
			/*
			 * We ran into a deadlock due to a contended
			 * rwlock. Cancel this round and retry.
			 */
			smp_sync_fn = NULL;

			raw_spin_unlock(&smp_barrier);
			/*
			 * Ensure all CPUs consumed the IPI to avoid
			 * running smp_sync_fn prematurely. This
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

/**
 *	irq_pipeline_unlock - Exit an inter-CPU critical section
 *	@flags:		Hardware interrupt state to restore
 *
 *      This routine exits a critical section started by a call to
 *	irq_pipeline_lock_many().  Hardware interrupts are restored in
 *	the current CPU.
 */
void irq_pipeline_unlock(unsigned long flags)
{
	/*
	 * CPUs cannot be unplugged until we release the pipeline
	 * lock, so checking num_online_cpus() is fine.
	 */
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

void irq_pipeline_oops(void)
{
	irq_pipeline_oopsing = true;
}

void irq_pipeline_nmi_enter(void)
{
	if (__test_and_set_bit(STAGE_STALL_BIT, &irq_root_status))
		__set_bit(STAGE_STALL_NMI_BIT, &irq_root_status);
	else
		__clear_bit(STAGE_STALL_NMI_BIT, &irq_root_status);
}
EXPORT_SYMBOL(irq_pipeline_nmi_enter);

void irq_pipeline_nmi_exit(void)
{
	if (test_bit(STAGE_STALL_NMI_BIT, &irq_root_status))
		__set_bit(STAGE_STALL_BIT, &irq_root_status);
	else
		__clear_bit(STAGE_STALL_BIT, &irq_root_status);
}
EXPORT_SYMBOL(irq_pipeline_nmi_exit);

bool irq_pipeline_steal_tick(void) /* Preemption disabled. */
{
	struct irq_pipeline_data *p;

	p = raw_cpu_ptr(&irq_pipeline);

	return arch_steal_pipelined_tick(&p->tick_regs);
}

bool __irq_cpuidle_enter(void)
{
	struct irq_stage_data *p;

	/*
	 * We may go idle if no interrupt is pending for delivery from
	 * the root stage.
	 */
	hard_local_irq_disable();
	p = irq_root_this_context();

	return !irq_staged_waiting(p);
}

bool __weak irq_cpuidle_control(struct cpuidle_device *dev,
				struct cpuidle_state *state)
{
	/*
	 * Allow entering the idle state by default, matching the
	 * original behavior when CPU_IDLE is turned
	 * on. irq_cpuidle_control() may be overriden by an
	 * out-of-band code for determining whether the CPU may
	 * actually enter the idle state.
	 */
	return true;
}

bool irq_cpuidle_enter(struct cpuidle_device *dev,
		       struct cpuidle_state *state)
{
	/*
	 * Pending IRQs or a co-kernel may deny the transition to
	 * idle.
	 */
	return __irq_cpuidle_enter() && irq_cpuidle_control(dev, state);
}

void irq_cpuidle_exit(void)
{
	/* unstall and re-enable hw IRQs too. */
	local_irq_enable_full();
}

#ifdef CONFIG_DEBUG_IRQ_PIPELINE

notrace void check_root_stage(void)
{
	struct irq_stage *this_stage;
	unsigned long flags;

	flags = hard_smp_local_irq_save();

	this_stage = __current_irq_stage;
	if (likely(this_stage == &root_irq_stage &&
		   !test_bit(STAGE_STALL_BIT, &irq_head_status))) {
		hard_smp_local_irq_restore(flags);
		return;
	}

	if (in_nmi() || irq_pipeline_oopsing) {
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
EXPORT_SYMBOL(check_root_stage);

#endif /* CONFIG_DEBUG_IRQ_PIPELINE */

static inline void fixup_percpu_data(void)
{
#ifdef CONFIG_SMP
	struct irq_pipeline_data *p;
	int cpu;

	/*
	 * irq_pipeline.curr cannot be assigned statically to
	 * &irq_pipeline.stages[0], due to the dynamic nature of
	 * percpu data. So we make irq_pipeline.curr refer to a
	 * temporary boot up context in static memory, until we can
	 * fixup all context pointers in this routine, after per-cpu
	 * areas have been eventually set up.
	 *
	 * Obviously, this code must run over the boot CPU, before SMP
	 * operations start, with hard IRQs off so that nothing can
	 * change under our feet.
	 */
	WARN_ON(smp_processor_id() || !hard_irqs_disabled());

	/*
	 * Initialize the final root stage data area with the current
	 * boot data placeholder.
	 */
	p = this_cpu_ptr(&irq_pipeline);
	p->stages[0] = bootup_irq_data;
	memcpy(p->stages[0].log.map, bootup_irq_data.log.map,
	       sizeof(struct irq_event_map));

	for_each_possible_cpu(cpu) {
		p = &per_cpu(irq_pipeline, cpu);
		p->curr = &per_cpu(irq_pipeline.stages, cpu)[0];
		p->stages[0].stage = &root_irq_stage;
		p->stages[0].log.map = &per_cpu(irq_map_array, cpu)[0];
		p->stages[1].log.map = &per_cpu(irq_map_array, cpu)[1];
	}
#endif
}

void __init irq_pipeline_init_early(void)
{
	/*
	 * This is called early from start_kernel(), even before the
	 * actual number of IRQs is known. We are running on the boot
	 * CPU, hw interrupts are off, and secondary CPUs are still
	 * lost in space. Careful.
	 */
	fixup_percpu_data();
}

/**
 *	irq_pipeline_init - Main pipeline core inits
 *
 *	This is step #2 of the 3-step pipeline initialization, which
 *	should happen right after init_IRQ() has run. The internal
 *	service interrupts are created along with the synthetic IRQ
 *	domain, and the arch-specific init chores are performed too.
 *
 *	Interrupt pipelining should be functional after this stage in
 *	most cases, unless the platform requires
 *	irq_pipeline_init_late() to have run for this.
 */
void __init irq_pipeline_init(void)
{
	WARN_ON(!hard_irqs_disabled());

	synthetic_irq_domain = irq_domain_add_nomap(NULL, ~0,
						    &sirq_domain_ops,
						    NULL);
	/*
	 * We are running on the boot CPU, hw interrupts are off, and
	 * secondary CPUs are still lost in space. Now we may run
	 * arch-specific code for enabling the pipeline.
	 */
	arch_irq_pipeline_init();

#ifdef CONFIG_SMP
	setup_percpu_irq(STOP_OOB_IPI, &lock_ipi);
#endif

	pr_info("IRQ pipeline enabled\n");
}

void __weak __init irq_pipeline_init_late(void)
{
}

#ifndef CONFIG_SPARSE_IRQ
EXPORT_SYMBOL_GPL(irq_desc);
#endif
