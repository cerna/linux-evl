/*
 * arch/x86/include/asm/irq_pipeline.h
 *
 * Copyright (C) 2002-2016 Philippe Gerum.
 *               2007 Jan Kiszka.
 */
#ifndef _ASM_X86_IRQ_PIPELINE_H
#define _ASM_X86_IRQ_PIPELINE_H

#include <asm-generic/irq_pipeline.h>

#ifdef CONFIG_IRQ_PIPELINE

#include <linux/types.h>
#include <asm/apicdef.h>
#include <asm/ptrace.h>
#include <asm/irq_vectors.h>

#define IPIPE_CORE_RELEASE	1

struct ipipe_arch_sysinfo {
};

#ifdef CONFIG_X86_LOCAL_APIC
/*
 * Special APIC interrupts are mapped above the last defined external
 * IRQ number.
 */
#define nr_apic_vectors	        (NR_VECTORS - FIRST_SYSTEM_VECTOR)
#define IPIPE_FIRST_APIC_IRQ	NR_IRQS
#define IPIPE_HRTIMER_IPI	apicm_vector_irq(IPIPE_HRTIMER_VECTOR)
#ifdef CONFIG_SMP
#define IPIPE_RESCHEDULE_IPI	apicm_vector_irq(IPIPE_RESCHEDULE_VECTOR)
#define IPIPE_CRITICAL_IPI	apicm_vector_irq(IPIPE_CRITICAL_VECTOR)
#endif /* CONFIG_SMP */
#define IPIPE_NR_XIRQS		(NR_IRQS + nr_apic_vectors)
#define apicm_irq_vector(irq)  ((irq) - IPIPE_FIRST_APIC_IRQ + FIRST_SYSTEM_VECTOR)
#define apicm_vector_irq(vec)  ((vec) - FIRST_SYSTEM_VECTOR + IPIPE_FIRST_APIC_IRQ)
#else /* !CONFIG_X86_LOCAL_APIC */
#define IPIPE_NR_XIRQS		NR_IRQS
#endif /* CONFIG_X86_LOCAL_APIC */

#define LAPIC_TIMER_IRQ		apicm_vector_irq(LOCAL_TIMER_VECTOR)

static inline bool is_apic_irqnr(unsigned int irq)
{
#ifdef CONFIG_X86_LOCAL_APIC
	return irq >= IPIPE_FIRST_APIC_IRQ && irq < IPIPE_NR_XIRQS;
#else
	return false;
#endif
}

/*
 * IF's left shift when combined with the IRQ pipeline's root stall
 * bit, which occupies the original IF position.
 */
#define X86_EFLAGS_IF_SHIFT  1

static inline notrace
unsigned long arch_irqs_virtual_to_native_flags(int stalled)
{
	return (!stalled) << X86_EFLAGS_IF_BIT;
}

static inline notrace
unsigned long arch_irqs_merge_flags(unsigned long flags, int stalled)
{
	flags <<= X86_EFLAGS_IF_SHIFT;
	flags &= X86_EFLAGS_IF << X86_EFLAGS_IF_SHIFT;
	return flags | arch_irqs_virtual_to_native_flags(stalled);
}

static inline notrace
unsigned long arch_irqs_split_flags(unsigned long flags, int *stalled)
{
	*stalled = !(flags & X86_EFLAGS_IF);
	flags &= X86_EFLAGS_IF << X86_EFLAGS_IF_SHIFT;
	return flags >> X86_EFLAGS_IF_SHIFT;
}

static inline notrace unsigned long arch_local_save_flags(void)
{
	int stalled = root_irqs_disabled();
	barrier();
	return arch_irqs_virtual_to_native_flags(stalled);
}

static inline notrace void arch_local_irq_restore(unsigned long flags)
{
	barrier();
	root_irq_restore(!(flags & X86_EFLAGS_IF));
}

static inline notrace void arch_local_irq_disable(void)
{
	root_irq_disable();
	barrier();
}

static inline notrace void arch_local_irq_enable(void)
{
	barrier();
	root_irq_enable();
}

static inline
void arch_save_timer_regs(struct pt_regs *dst,
			  struct pt_regs *src, bool head_context)
{
	dst->flags = src->flags;
	dst->cs = src->cs;
	dst->ip = src->ip;
	dst->bp = src->bp;
#ifdef CONFIG_X86_64
	dst->ss = src->ss;
	dst->sp = src->sp;
#endif
	if (head_context)
		dst->flags &= ~X86_EFLAGS_IF;
}

static inline bool arch_steal_pipelined_tick(struct pt_regs *regs)
{
	return !((regs)->flags & X86_EFLAGS_IF);
}

#ifdef CONFIG_X86_32

static inline u64 __ipipe_tsc_get(void)
{
	u64 t;
	__asm__ __volatile__("rdtsc" : "=A"(t));
	return t;
}

#define ipipe_tsc2ns(t)					\
({							\
	unsigned long long delta = (t) * 1000000ULL;	\
	unsigned long long freq = __ipipe_hrclock_freq;	\
	do_div(freq, 1000);				\
	do_div(delta, (unsigned)freq + 1);		\
	(unsigned long)delta;				\
})

#define ipipe_tsc2us(t)					\
({							\
	unsigned long long delta = (t) * 1000ULL;	\
	unsigned long long freq = __ipipe_hrclock_freq;	\
	do_div(freq, 1000);				\
	do_div(delta, (unsigned)freq + 1);		\
	(unsigned long)delta;				\
})

#else   /* CONFIG_X86_64 */

static inline u64 __ipipe_tsc_get(void)
{
	u32 ax, dx;
	__asm__ __volatile__("rdtsc" : "=a" (ax), "=d" (dx));
	return ((u64)a) | (((u64)d) << 32);
}

#define ipipe_tsc2ns(t)	(((t) * 1000UL) / (__ipipe_hrclock_freq / 1000000UL))
#define ipipe_tsc2us(t)	((t) / (__ipipe_hrclock_freq / 1000000UL))

#endif   /* CONFIG_X86_64 */

struct irq_stage;
static inline void arch_irq_push_stage(struct irq_stage *stage) { }

#else /* !CONFIG_IRQ_PIPELINE */

#define LAPIC_TIMER_IRQ		-1

#endif /* !CONFIG_IRQ_PIPELINE */

#endif /* _ASM_X86_IRQ_PIPELINE_H */
