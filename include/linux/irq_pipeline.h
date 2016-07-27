/*
 * include/linux/irq_pipeline.h
 *
 * Copyright (C) 2002-2018 Philippe Gerum
 *               2006-2012 Gilles Chanteperdrix
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

int irq_pipeline_inject(unsigned int irq);

int generic_pipeline_irq(unsigned int irq,
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

int irq_stage_escalate(int (*fn)(void *arg), void *arg);

extern bool irq_pipeline_active;
	
static inline bool irq_critical_context(void)
{
	return on_head_stage() ||
		(hard_irqs_disabled() && irq_pipeline_active);
}

extern struct irq_domain *synthetic_irq_domain;

#else /* !CONFIG_IRQ_PIPELINE */

static inline
void irq_pipeline_init_early(void) { }

static inline
void irq_pipeline_init(void) { }

static inline
void irq_pipeline_clear(struct irq_desc *desc) { }

static inline
void irq_pipeline_oops(void) { }

static inline
int generic_pipeline_irq(unsigned int irq, struct pt_regs *regs)
{
	return 0;
}

static inline bool handle_oob_irq(struct irq_desc *desc)
{
	return false;
}

static inline bool irq_cpuidle_enter(struct cpuidle_device *dev,
				     struct cpuidle_state *state)
{
	return true;
}

static inline bool irq_critical_context(void)
{
	return false;
}

#endif /* !CONFIG_IRQ_PIPELINE */

#endif /* _LINUX_IRQ_PIPELINE_H */
