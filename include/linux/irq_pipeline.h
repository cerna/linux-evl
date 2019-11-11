/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2002 Philippe Gerum  <rpm@xenomai.org>.
 *               2006 Gilles Chanteperdrix.
 *               2007 Jan Kiszka.
 */
#ifndef _LINUX_IRQ_PIPELINE_H
#define _LINUX_IRQ_PIPELINE_H

struct cpuidle_device;
struct cpuidle_state;
struct irq_desc;

#ifdef CONFIG_IRQ_PIPELINE

#include <linux/compiler.h>
#include <linux/irqdomain.h>
#include <linux/percpu.h>
#include <linux/interrupt.h>
#include <linux/irqstage.h>
#include <linux/thread_info.h>
#include <asm/irqflags.h>

void irq_pipeline_init_early(void);

void irq_pipeline_init(void);

void arch_irq_pipeline_init(void);

int irq_inject_pipeline(unsigned int irq);

void synchronize_pipeline(void);

static __always_inline void synchronize_pipeline_on_irq(void)
{
	/*
	 * Optimize if we preempted the high priority oob stage: we
	 * don't need to synchronize the pipeline unless there is a
	 * pending interrupt for it.
	 */
	if (running_inband() ||
	    stage_irqs_pending(this_oob_staged()))
		synchronize_pipeline();
}

void dovetail_call_mayday(struct thread_info *ti,
			  struct pt_regs *regs);

bool handle_oob_irq(struct irq_desc *desc);

void arch_do_IRQ_pipelined(struct irq_desc *desc);

void irq_pipeline_clear(struct irq_desc *desc);

#ifdef CONFIG_SMP
void irq_pipeline_send_remote(unsigned int ipi,
			      const struct cpumask *cpumask);
#endif	/* CONFIG_SMP */

void irq_pipeline_oops(void);

bool irq_pipeline_steal_tick(void);

bool irq_cpuidle_enter(struct cpuidle_device *dev,
		       struct cpuidle_state *state);

int run_oob_call(int (*fn)(void *arg), void *arg);

extern bool irq_pipeline_active;

static inline bool inband_unsafe(void)
{
	return running_oob() ||
		(hard_irqs_disabled() && irq_pipeline_active);
}

static inline bool inband_irq_pending(void)
{
	check_hard_irqs_disabled();

	return stage_irqs_pending(this_inband_staged());
}

int handle_irq_pipelined(struct pt_regs *regs);

extern struct irq_domain *synthetic_irq_domain;

#else /* !CONFIG_IRQ_PIPELINE */

#include <linux/irqstage.h>
#include <asm/irq_pipeline.h>

static inline
void irq_pipeline_init_early(void) { }

static inline
void irq_pipeline_init(void) { }

static inline
void irq_pipeline_clear(struct irq_desc *desc) { }

static inline
void irq_pipeline_oops(void) { }

static inline bool handle_oob_irq(struct irq_desc *desc)
{
	return false;
}

static inline bool irq_cpuidle_enter(struct cpuidle_device *dev,
				     struct cpuidle_state *state)
{
	return true;
}

static inline bool inband_unsafe(void)
{
	return false;
}

static inline bool inband_irq_pending(void)
{
	return false;
}

#endif /* !CONFIG_IRQ_PIPELINE */

#if !defined(CONFIG_IRQ_PIPELINE) || !defined(CONFIG_SPARSE_IRQ)
static inline void uncache_irq_desc(unsigned int irq) { }
#else
void uncache_irq_desc(unsigned int irq);
#endif

#endif /* _LINUX_IRQ_PIPELINE_H */
