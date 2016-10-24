/*
 * arch/arm/include/asm/irq_pipeline.h
 *
 * Copyright (C) 2002-2016 Philippe Gerum.
 * Copyright (C) 2005 Stelian Pop.
 * Copyright (C) 2006-2008 Gilles Chanteperdrix.
 * Copyright (C) 2010 Philippe Gerum (SMP port).
 */
#ifndef _ASM_ARM_IRQ_PIPELINE_H
#define _ASM_ARM_IRQ_PIPELINE_H

#define IPIPE_NR_XIRQS		3072

#include <asm-generic/irq_pipeline.h>

#ifdef CONFIG_IRQ_PIPELINE

#define IPIPE_CORE_RELEASE	1

#include <asm/irq.h>

#define IPIPE_IPI_BASE		2048
#define IPIPE_CRITICAL_IPI	(IPIPE_IPI_BASE + IPI_PIPELINE_CRITICAL)
#define IPIPE_HRTIMER_IPI	(IPIPE_IPI_BASE + IPI_PIPELINE_HRTIMER)
#define IPIPE_RESCHEDULE_IPI	(IPIPE_IPI_BASE + IPI_PIPELINE_RESCHEDULE)

#ifdef CONFIG_SMP_ON_UP
extern struct static_key __ipipe_smp_key;
#define ipipe_smp_p 	static_key_true(&__ipipe_smp_key)
#endif

static inline notrace unsigned long arch_local_irq_save(void)
{
	unsigned long flags = root_irq_save() << 7; /* PSR_I_BIT */
	barrier();
	return flags;
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
	unsigned long flags = root_irqs_disabled() << 7; /* PSR_I_BIT */
	barrier();
	return flags;
}

static inline int arch_irqs_disabled_flags(unsigned long flags)
{
	return native_irqs_disabled_flags(flags);
}

static inline notrace void arch_local_irq_restore(unsigned long flags)
{
	if (!arch_irqs_disabled_flags(flags))
		arch_local_irq_enable();
}

#endif /* CONFIG_IRQ_PIPELINE */

#endif /* _ASM_ARM_IRQ_PIPELINE_H */
