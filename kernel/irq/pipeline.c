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

#ifdef CONFIG_DEBUG_IRQ_PIPELINE
#define trace_on_debug
#else
#define trace_on_debug  notrace
#endif

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

static DEFINE_PER_CPU(struct irq_event_map, irq_map_array[2]);

DEFINE_PER_CPU(struct irq_pipeline_data, irq_pipeline) = {
	.stages = {
		[0] = {
			.log = {
				.map = &bootup_irq_map,
			},
			.stage = &root_irq_stage,
			.status = (1 << STAGE_STALL_BIT),
		},
	},
	.__curr = &irq_pipeline.stages[0],
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
	.__curr = &irq_pipeline.stages[0],
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

void irq_stage_sync(struct irq_stage *top)
{
	struct irq_stage_data *p;
	struct irq_stage *stage;

	/* We must enter over the root stage with hardirqs off. */
	if (irq_pipeline_debug()) {
		WARN_ON_ONCE(!hard_irqs_disabled());
		WARN_ON_ONCE(current_irq_stage != &root_irq_stage);
	}

	stage = top;

	for (;;) {
		p = irq_stage_this_context(stage);
		if (test_stage_bit(STAGE_STALL_BIT, p))
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
	if (current_irq_stage != top)
		irq_stage_sync(top);
	else if (!test_stage_bit(STAGE_STALL_BIT,
			   irq_stage_this_context(top)))
		irq_stage_sync_current();
}

trace_on_debug void __root_irq_enable(void)
{
	struct irq_stage_data *p;
	unsigned long flags;

	/* This helps catching bad usage from assembly call sites. */
	check_root_stage();

	flags = hard_local_irq_save();

	p = irq_root_this_context();
	trace_hardirqs_on();
	clear_stage_bit(STAGE_STALL_BIT, p);
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
trace_on_debug void root_irq_disable(void)
{
	unsigned long flags;

	check_root_stage();
	flags = hard_local_irq_save();
	set_stage_bit(STAGE_STALL_BIT, irq_root_this_context());
	trace_hardirqs_off();
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL(root_irq_disable);

/**
 *	root_irqs_disabled - test the virtual interrupt state
 *
 *	Returns non-zero if interrupts are currently disabled for the
 *	root stage, zero otherwise.
 *
 *	May be used from the head stage too (e.g. for tracing
 *	purpose).
 */
notrace unsigned long root_irqs_disabled(void)
{
	/*
	 * We don't have to guard against CPU migration here, because
	 * we are testing the root stage stall from that stage. Since
	 * may only migrate if our current stage is unstalled, such
	 * state won't have changed once resuming on the destination
	 * CPU.
	 *
	 * CAUTION: the assumption above only holds when testing the
	 * root stall bit from the root stage. Particularly, it does
	 * NOT hold when testing the head stall bit from the root
	 * stage. In that latter situation, hard irqs must be off in
	 * SMP.
	 */
	return __test_stage_bit(STAGE_STALL_BIT, irq_root_this_context());
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
trace_on_debug unsigned long root_irq_save(void)
{
	unsigned long flags, x;

	check_root_stage();
	flags = hard_local_irq_save();
	x = test_and_set_stage_bit(STAGE_STALL_BIT, irq_root_this_context());
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
trace_on_debug void root_irq_restore(unsigned long x)
{
	if (x)
		root_irq_disable();
	else
		__root_irq_enable();
}
EXPORT_SYMBOL(root_irq_restore);

/**
 *	root_irq_restore_nosync - restore the (virtual) interrupt state
 *      @x:	Interrupt state to restore
 *
 *	Restore the virtual interrupt state from x. Unlike
 *	root_irq_restore(), pending interrupts are not played back.
 *
 *	Hard irqs must be disabled on entry.
 */
trace_on_debug void root_irq_restore_nosync(unsigned long x)
{
	struct irq_stage_data *p = irq_root_this_context();

	check_hard_irqs_disabled();

	if (raw_irqs_disabled_flags(x)) {
		set_stage_bit(STAGE_STALL_BIT, p);
		trace_hardirqs_off();
	} else {
		trace_hardirqs_on();
		clear_stage_bit(STAGE_STALL_BIT, p);
	}
}

/**
 *	root_irq_enable_nosync - enable the (virtual) interrupt state
 *
 *	Enable the virtual interrupt state. Unlike root_irq_enable(),
 *	pending interrupts are not played back.
 *
 *	Hard irqs must be disabled on entry.
 */
trace_on_debug void root_irq_enable_nosync(void)
{
	struct irq_stage_data *p = irq_root_this_context();

	check_hard_irqs_disabled();
	trace_hardirqs_on();
	clear_stage_bit(STAGE_STALL_BIT, p);
}

/**
 *	head_irq_enable - enable interrupts in the CPU
 *
 *	Enable interrupts in the CPU, allowing out-of-band interrupts
 *	to preempt any code. If out-of-band IRQs are pending in the
 *	per-CPU log for the head stage at the time of this call, they
 *	are played back.
 */
trace_on_debug void head_irq_enable(void)
{
	struct irq_stage_data *p;

	hard_local_irq_disable();

	p = irq_head_this_context();
	clear_stage_bit(STAGE_STALL_BIT, p);

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
 *
 *      NOTE: Stalling the head stage must always be paired with
 *      disabling hard irqs and conversely when calling
 *      head_irq_restore(), otherwise the latter would badly misbehave
 *      in unbalanced conditions.
 */
trace_on_debug void __head_irq_restore(unsigned long x) /* hw interrupt off */
{
	struct irq_stage_data *p = irq_head_this_context();

	check_hard_irqs_disabled();

	if (!x) {
		clear_stage_bit(STAGE_STALL_BIT, p);
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
	bool ret = true;
	
	if (!hard_irqs_disabled()) {
		ret = false;
		/* See comment in root_irqs_disabled(). */
		if (on_root_stage())
			ret = __test_stage_bit(STAGE_STALL_BIT,
					       irq_root_this_context());
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
 *      with irq_stage_restore() exclusively. The combo state returned
 *      by the former may NOT be passed to hard_local_irq_restore().
 *
 *      The interrupt state of the current stage in the return value
 *      (i.e. stall bit for the root stage, hardware interrupt bit for
 *      the head stage) must be testable using arch_irqs_disabled_flags().
 */
trace_on_debug unsigned long irq_stage_test_and_disable(int *irqsoff)
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
		stalled = test_and_set_stage_bit(STAGE_STALL_BIT,
				 irq_root_this_context());
		flags = irqs_merge_flags(flags, stalled);
		if (stalled)
			*irqsoff = 1;
	}

	/*
	 * CAUTION: don't ever pass this verbatim to
	 * hard_local_irq_restore(). Only irq_stage_restore() knows
	 * how to decode and use a combo state word.
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
trace_on_debug void irq_stage_restore(unsigned long combo)
{
	unsigned long flags = combo;
	int stalled;

	WARN_ON_ONCE(irq_pipeline_debug() && !hard_irqs_disabled());

	if (on_root_stage()) {
		flags = irqs_split_flags(combo, &stalled);
		if (!stalled)
			clear_stage_bit(STAGE_STALL_BIT,
					irq_root_this_context());
	}

	/*
	 * The interrupt bit is the only hardware flag present in the
	 * combo state, all other status bits have been cleared by
	 * irqs_merge_flags(), so don't ever try to reload the
	 * hardware status register with such value directly!
	 */
	if (!hard_irqs_disabled_flags(flags))
		hard_local_irq_enable();
}
EXPORT_SYMBOL_GPL(irq_stage_restore);

#if __IRQ_STAGE_MAP_LEVELS == 3

/* Must be called hw IRQs off. */
void irq_stage_post_event(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
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

static void __clear_pending_irq(struct irq_stage_data *p, unsigned int irq)
{
	int l0b, l1b;

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	__clear_bit(irq, p->log.map->lomap);
	__clear_bit(l1b, p->log.map->mdmap);
	__clear_bit(l0b, &p->log.himap);
}

static void clear_pending_irq(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
	__clear_pending_irq(p, irq);
}

static inline int pull_next_irq(struct irq_stage_data *p)
{
	unsigned long l0m, l1m, l2m;
	int l0b, l1b, l2b, irq;

	l0m = p->log.himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = __ffs(l0m);
	l1m = p->log.map->mdmap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = __ffs(l1m) + l0b * BITS_PER_LONG;
	l2m = p->log.map->lomap[l1b];
	if (unlikely(l2m == 0))
		return -1;

	l2b = __ffs(l2m);
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

static void clear_pending_irq(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
	int l0b = irq / BITS_PER_LONG;

	__clear_bit(irq, p->log.map->lomap);
	__clear_bit(l0b, &p->log.himap);
}

/* Must be called hw IRQs off. */
void irq_stage_post_event(struct irq_stage *stage, unsigned int irq)
{
	struct irq_stage_data *p = irq_stage_this_context(stage);
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

	l0b = __ffs(l0m);
	l1m = p->log.map->lomap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = __ffs(l1m);
	__clear_bit(l1b, &p->log.map->lomap[l0b]);
	if (p->log.map->lomap[l0b] == 0)
		__clear_bit(l0b, &p->log.himap);

	return l0b * BITS_PER_LONG + l1b;
}

#endif  /* __IRQ_STAGE_MAP_LEVELS == 2 */

/**
 *	irq_pipeline_clear - clear IRQ event from all per-CPU logs
 *	@desc: IRQ descriptor
 *
 *      Clear any event of the specified IRQ pending from the relevant
 *      interrupt logs, for both the root and head stages.
 *
 *      All per-CPU logs are considered for device IRQs, per-CPU IRQ
 *      events are only looked up into the log of the current CPU.
 *
 *      Genirq should be the exclusive user of that code. The only
 *      safe context for running this code is when the corresponding
 *      IRQ line is masked, and the matching IRQ descriptor locked.
 *
 *      Hard irqs must be off on entry (which has to be the case since
 *      the IRQ descriptor lock is a mutable beast when pipelining).
 */
void irq_pipeline_clear(struct irq_desc *desc)
{
	unsigned int irq = irq_desc_get_irq(desc);
	struct irq_stage_data *p;
	int cpu;

	check_hard_irqs_disabled();

	if (irq_settings_is_per_cpu_devid(desc)) {
		clear_pending_irq(&root_irq_stage, irq);
		if (head_stage_present())
			clear_pending_irq(head_irq_stage, irq);
	} else {
		for_each_online_cpu(cpu) {
			p = irq_stage_context(&root_irq_stage, cpu);
			__clear_pending_irq(p, irq);
			if (head_stage_present()) {
				p = irq_stage_context(head_irq_stage, cpu);
				__clear_pending_irq(p, irq);
			}
		}
	}
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

void __weak irq_enter_head(void) { }

void __weak irq_exit_head(void) { }

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
	 *
	 * NOTE: we should already be holding desc->lock for non
	 * per-cpu IRQs, since we should only get there from the
	 * pipeline entry context.
	 */

	WARN_ON_ONCE(irq_pipeline_debug() &&
		     !irq_settings_is_per_cpu(desc) &&
		     !raw_spin_is_locked(&desc->lock));

	if (ret != IRQ_NONE) {
		printk(KERN_ERR "out-of-band irq event %d: bogus return value %x\n",
				irq, ret);
		for_each_action_of_desc(desc, action)
			printk(KERN_ERR "[<%p>] %pf",
			       action->handler, action->handler);
		printk(KERN_CONT "\n");
		return;
	}
	
	if (time_after(jiffies, desc->last_unhandled + HZ/10))
		desc->irqs_unhandled = 0;
	else
		desc->irqs_unhandled++;

	desc->last_unhandled = jiffies;

	/*
	 * If more than 1000 unhandled events were received
	 * consecutively, we have to stop this IRQ from poking us at
	 * the head of the pipeline by disabling out-of-band mode for
	 * the interrupt.
	 */
	if (unlikely(desc->irqs_unhandled > 1000)) {
		printk(KERN_ERR "out-of-band irq %d: stuck or unexpected\n", irq);
		irq_settings_clr_oob(desc);
		desc->istate |= IRQS_SPURIOUS_DISABLED;
		irq_disable(desc);
	}
}

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
 * arch_do_IRQ_pipelined() routine.
 *
 * Entered with hardirqs on, root stalled.
 */
static inline
void do_root_irq(struct irq_desc *desc)
{
	arch_do_IRQ_pipelined(desc);
	WARN_ON_ONCE(irq_pipeline_debug() && !irqs_disabled());
}

static void dispatch_oob_irq(struct irq_desc *desc) /* hardirqs off */
{
	struct irq_stage_data *p = irq_head_this_context(), *old;
	struct irq_stage *head = p->stage;

	if (unlikely(test_stage_bit(STAGE_STALL_BIT, p))) {
		irq_stage_post_event(head, irq_desc_get_irq(desc));
		/* We may NOT have hardirqs on with a stalled head. */
		WARN_ON_ONCE(irq_pipeline_debug() && on_pipeline_entry());
		return;
	}

	/* Switch to the head stage if not current. */
	old = irq_current_context;
	if (old != p)
		irq_set_head_context(p);

	set_stage_bit(STAGE_STALL_BIT, p);
	do_oob_irq(desc);
	clear_stage_bit(STAGE_STALL_BIT, p);

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

	/*
	 * If there is no registered head stage, all interrupts go to
	 * the root stage through the interrupt log.
	 *
	 * Otherwise, out-of-band IRQs are immediately delivered
	 * (dispatch_oob_irq()), while in-band IRQs go through the
	 * root stage log.
	 *
	 * This routine returns a boolean status telling the caller
	 * whether an out-of-band interrupt was delivered.
	 */
	if (likely(head_irq_stage != &root_irq_stage) &&
	    irq_settings_is_oob(desc)) {
		dispatch_oob_irq(desc);
		return true;
	}

	irq_stage_post_event(&root_irq_stage, irq);

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
	 * We may re-enter this routine either legitimately due to
	 * stacked IRQ domains, or because some chained IRQ handler is
	 * abusing the API, and should have called
	 * generic_handle_irq() instead of us. In any case, deal with
	 * re-entry gracefully.
	 */
	if (unlikely(on_pipeline_entry())) {
		if (WARN_ON_ONCE(irq_pipeline_debug() &&
				 irq_settings_is_chained(desc)))
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

	WARN_ON_ONCE(irq_pipeline_debug() && on_pipeline_entry());
	check_hard_irqs_disabled();

	p = irq_current_context;
respin:
	stage = p->stage;
	set_stage_bit(STAGE_STALL_BIT, p);
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
			if (test_stage_bit(STAGE_STALL_BIT, p))
				return;
			goto respin;
		}
	}

	if (stage == &root_irq_stage)
		trace_hardirqs_on();

	clear_stage_bit(STAGE_STALL_BIT, p);
}

/**
 *      irq_stage_escalate - escalate function call to the head stage
 *      @fn:    address of routine
 *      @arg:   routine argument
 *
 *      Make the specified function run on the head stage, switching
 *      the current stage accordingly if needed. The escalated call is
 *      allowed to perform a stage migration in the process.
 */
int irq_stage_escalate(int (*fn)(void *arg), void *arg)
{
	struct irq_stage_data *p, *old;
	struct irq_stage *head;
	unsigned long flags;
	int ret, s;

	flags = hard_local_irq_save();
	
	/* Switch to the head stage if not current. */
	p = irq_head_this_context();
	head = p->stage;
	old = irq_current_context;
	if (old != p)
		irq_set_head_context(p);

	s = test_and_set_stage_bit(STAGE_STALL_BIT, p);
	barrier();
	ret = fn(arg);
	hard_local_irq_disable();
	p = irq_head_this_context();
	if (!s)
		clear_stage_bit(STAGE_STALL_BIT, p);

	/*
	 * The exit logic is as follows:
	 *
	 *    ON-ENTRY  AFTER-CALL  EPILOGUE
	 *
	 *    head      head        sync current stage if !stalled
	 *    root      head        switch to root + sync all stages
	 *    head      root        sync all stages
	 *    root      root        sync all stages
	 *
	 * Each path which has stalled the head stage while running on
	 * the root stage at some point during the escalation process
	 * must synchronize all stages of the pipeline on
	 * exit. Otherwise, we may restrict the synchronization scope
	 * to the current stage when the whole process runs on the
	 * head stage.
	 */
	if (likely(irq_current_context == p)) {
		if (old->stage == head) {
			if (!s && irq_staged_waiting(p))
				irq_stage_sync_current();
			goto out;
		}
		irq_set_root_context(irq_root_this_context());
	}

	irq_stage_sync(head);
out:
	hard_local_irq_restore(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(irq_stage_escalate);

int irq_stage_push(struct irq_stage *stage, const char *name)
{
	struct irq_event_map *map;
	struct irq_stage_data *p;
	int cpu, ret;

	if (WARN_ON(irq_pipeline_debug() &&
		    (!on_root_stage() || stage == &root_irq_stage)))
		return -EINVAL;

	if (head_stage_present())
		return -EBUSY;

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
#ifdef CONFIG_DEBUG_IRQ_PIPELINE
		p->cpu = cpu;
#endif
	}

	ret = arch_irq_stage_push(stage);
	if (ret)
		return ret;

	head_irq_stage = stage;

	pr_info("IRQ pipeline: high-priority %s stage added.\n", name);

	return 0;
}
EXPORT_SYMBOL_GPL(irq_stage_push);

void irq_stage_pop(struct irq_stage *stage)
{
	WARN_ON(!on_root_stage() || stage != head_irq_stage);

	head_irq_stage = &root_irq_stage;
	smp_mb();

	pr_info("IRQ pipeline: %s stage removed.\n", stage->name);
}
EXPORT_SYMBOL_GPL(irq_stage_pop);

void irq_pipeline_oops(void)
{
	irq_pipeline_oopsing = true;
}

/*
 * Used to save/restore the status bits of the root stage across runs
 * of NMI-triggered code, so that we can restore the original pipeline
 * state before leaving NMI context.
 */
static DEFINE_PER_CPU(unsigned long, nmi_saved_status);

void irq_pipeline_nmi_enter(void)
{
	struct irq_stage_data *p = irq_root_this_context();
	raw_cpu_write(nmi_saved_status, p->status);
	
}
EXPORT_SYMBOL(irq_pipeline_nmi_enter);

void irq_pipeline_nmi_exit(void)
{
	struct irq_stage_data *p = irq_root_this_context();
	p->status = raw_cpu_read(nmi_saved_status);
}
EXPORT_SYMBOL(irq_pipeline_nmi_exit);

bool irq_pipeline_steal_tick(void) /* Preemption disabled. */
{
	struct irq_pipeline_data *p;

	p = raw_cpu_ptr(&irq_pipeline);

	return arch_steal_pipelined_tick(&p->tick_regs);
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
	struct irq_stage_data *p;

	WARN_ON_ONCE(irq_pipeline_debug() && hard_irqs_disabled());
	WARN_ON_ONCE(irq_pipeline_debug() && !irqs_disabled());
	
	hard_local_irq_disable();
	p = irq_root_this_context();

	/*
	 * Pending IRQ(s) waiting for delivery to the root stage, or
	 * the arbitrary decision of a co-kernel may deny the
	 * transition to a deeper C-state. Note that we return from
	 * this call with hard irqs off, so that we won't allow any
	 * interrupt to sneak into the IRQ log until we reach the
	 * processor idling code, or leave the CPU idle framework
	 * without sleeping.
	 */
	return !irq_staged_waiting(p) && irq_cpuidle_control(dev, state);
}

#ifdef CONFIG_DEBUG_IRQ_PIPELINE

notrace void check_root_stage(void)
{
	struct irq_stage *this_stage;
	unsigned long flags;

	flags = hard_smp_local_irq_save();

	this_stage = current_irq_stage;
	if (likely(this_stage == &root_irq_stage &&
		   !test_stage_bit(STAGE_STALL_BIT, irq_head_this_context()))) {
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

notrace bool __check_stage_bit_access(struct irq_stage_data *pd)
{
	check_hard_irqs_disabled_in_smp();

	return pd->cpu != raw_smp_processor_id();
}
EXPORT_SYMBOL(__check_stage_bit_access);

#endif /* CONFIG_DEBUG_IRQ_PIPELINE */

static inline void fixup_percpu_data(void)
{
#ifdef CONFIG_SMP
	struct irq_pipeline_data *p;
	int cpu;

	/*
	 * A temporary event log is used by the root stage during the
	 * early boot up (bootup_irq_map), until the per-cpu areas
	 * have been set up.
	 *
	 * Obviously, this code must run over the boot CPU, before SMP
	 * operations start, with hard IRQs off so that nothing can
	 * change under our feet.
	 */
	WARN_ON(smp_processor_id() || !hard_irqs_disabled());

	memcpy(&per_cpu(irq_map_array, 0)[0], &bootup_irq_map,
	       sizeof(struct irq_event_map));

	for_each_possible_cpu(cpu) {
		p = &per_cpu(irq_pipeline, cpu);
		p->__curr = &p->stages[0];
		p->stages[0].stage = &root_irq_stage;
		p->stages[0].log.map = &per_cpu(irq_map_array, cpu)[0];
		p->stages[1].log.map = &per_cpu(irq_map_array, cpu)[1];
#ifdef CONFIG_DEBUG_IRQ_PIPELINE
		p->stages[0].cpu = cpu;
		p->stages[1].cpu = cpu;
#endif
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
 *	Interrupt pipelining should be fully functional when this
 *	routine returns.
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

	pr_info("IRQ pipeline enabled\n");
}

#ifndef CONFIG_SPARSE_IRQ
EXPORT_SYMBOL_GPL(irq_desc);
#endif
