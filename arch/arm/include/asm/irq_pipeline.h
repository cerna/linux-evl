/*
 * arch/arm/include/asm/irq_pipeline.h
 *
 * Copyright (C) 2002-2018 Philippe Gerum.
 * Copyright (C) 2005 Stelian Pop.
 * Copyright (C) 2006-2008 Gilles Chanteperdrix.
 * Copyright (C) 2010 Philippe Gerum (SMP port).
 */
#ifndef _ASM_ARM_IRQ_PIPELINE_H
#define _ASM_ARM_IRQ_PIPELINE_H

#include <asm-generic/irq_pipeline.h>

#ifdef CONFIG_IRQ_PIPELINE

/*
 * Out-of-band IPIs are directly mapped to SGI1-3, instead of
 * multiplexed over SGI0 like regular in-band messages.
 */
#define OOB_IPI_BASE		2048
#define OOB_NR_IPI		3
#define STOP_OOB_IPI		(OOB_IPI_BASE + NR_IPI)
#define TIMER_OOB_IPI		(OOB_IPI_BASE + NR_IPI + 1)
#define RESCHEDULE_OOB_IPI	(OOB_IPI_BASE + NR_IPI + 2)

static inline notrace
unsigned long arch_irqs_virtual_to_native_flags(int stalled)
{
	return (!!stalled) << IRQMASK_I_POS;
}

static inline notrace
unsigned long arch_irqs_native_to_virtual_flags(unsigned long flags)
{
	return (!!hard_irqs_disabled_flags(flags)) << IRQMASK_i_POS;
}

static inline notrace unsigned long arch_local_irq_save(void)
{
	int stalled = root_irq_save();
	barrier();
	return arch_irqs_virtual_to_native_flags(stalled);
}

static inline notrace void arch_local_irq_enable(void)
{
	barrier();
	root_irq_enable();
}

static inline notrace void arch_local_irq_disable(void)
{
	root_irq_disable();
	barrier();
}

static inline notrace unsigned long arch_local_save_flags(void)
{
	int stalled = root_irqs_disabled();
	barrier();
	return arch_irqs_virtual_to_native_flags(stalled);
}

static inline int arch_irqs_disabled_flags(unsigned long flags)
{
	return native_irqs_disabled_flags(flags);
}

static inline notrace void arch_local_irq_restore(unsigned long flags)
{
	if (!arch_irqs_disabled_flags(flags))
		__root_irq_enable();
	barrier();
}

static inline
void arch_save_timer_regs(struct pt_regs *dst,
			  struct pt_regs *src, bool head_context)
{
	dst->ARM_cpsr = src->ARM_cpsr;
	dst->ARM_pc = src->ARM_pc;
	if (head_context)
		dst->ARM_cpsr |= IRQMASK_I_BIT;
}

static inline bool arch_steal_pipelined_tick(struct pt_regs *regs)
{
	return !!(regs->ARM_cpsr & IRQMASK_I_BIT);
}

struct irq_stage;
static inline void arch_irq_stage_push(struct irq_stage *stage) { }

#else /* !CONFIG_IRQ_PIPELINE */

static inline unsigned long arch_local_irq_save(void)
{
	return native_irq_save();
}

static inline void arch_local_irq_enable(void)
{
	native_irq_enable();
}

static inline void arch_local_irq_disable(void)
{
	native_irq_disable();
}

static inline unsigned long arch_local_save_flags(void)
{
	return native_save_flags();
}

static inline void arch_local_irq_restore(unsigned long flags)
{
	native_irq_restore(flags);
}

static inline int arch_irqs_disabled_flags(unsigned long flags)
{
	return native_irqs_disabled_flags(flags);
}

#endif /* !CONFIG_IRQ_PIPELINE */

#endif /* _ASM_ARM_IRQ_PIPELINE_H */
