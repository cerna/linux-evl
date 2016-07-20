/*
 * include/linux/irq_pipeline.h
 *
 * Copyright (C) 2002-2016 Philippe Gerum
 *               2006-2012 Gilles Chanteperdrix
 *               2007 Jan Kiszka.
 */
#ifndef _LINUX_IRQ_PIPELINE_H
#define _LINUX_IRQ_PIPELINE_H

#include <linux/compiler.h>
#include <linux/irqdomain.h>
#include <linux/percpu.h>
#include <linux/interrupt.h>
#include <linux/irqstage.h>
#include <linux/thread_info.h>
#include <linux/irqreturn.h>
#include <asm/irqflags.h>

#ifdef CONFIG_IRQ_PIPELINE

struct irq_pipeline_clocking {
	u64 sys_hrclock_freq;
	const char *hrclock_name;
	struct ipipe_arch_sysinfo arch;
};

struct ipipe_work_header {
	size_t size;
	void (*handler)(struct ipipe_work_header *work);
};

extern unsigned long __ipipe_hrclock_freq; /* FIXME */

void irq_pipeline_init_early(void);

void irq_pipeline_init(void);

void irq_pipeline_init_late(void);

void arch_irq_pipeline_init(void);

void __irq_pipeline_enter(unsigned int irq, struct pt_regs *regs);

void irq_pipeline_enter(unsigned int irq, struct pt_regs *regs);

void irq_pipeline_enter_nosync(unsigned int irq);

unsigned long irq_pipeline_lock_many(const struct cpumask *mask,
				     void (*syncfn)(void *arg),
				     void *arg);
static inline
unsigned long irq_pipeline_lock(void (*syncfn)(void *arg),
				void *arg)
{
	return irq_pipeline_lock_many(cpu_online_mask, syncfn, arg);
}

void irq_pipeline_unlock(unsigned long flags);

void irq_pipeline_inject(unsigned int irq);

void irq_pipeline_clear(unsigned int irq);

void do_IRQ_pipelined(unsigned int irq, struct irq_desc *desc);

#ifndef ipipe_smp_p
#define ipipe_smp_p	IS_ENABLED(CONFIG_SMP)
#endif

#ifndef irq_finish_head
#define irq_finish_head(irq) do { } while(0)
#endif

void irq_push_stage(struct irq_stage *stage,
		    const char *name,
		    struct irq_pipeline_clocking *clocking);

void irq_pop_stage(struct irq_stage *stage);

void arch_irq_push_stage(struct irq_stage *stage,
			 struct irq_pipeline_clocking *clocking);

void __ipipe_post_work_root(struct ipipe_work_header *work);

#define ipipe_post_work_root(p, header)			\
	do {						\
		void header_not_at_start(void);		\
		if (offsetof(typeof(*(p)), header)) {	\
			header_not_at_start();		\
		}					\
		__ipipe_post_work_root(&(p)->header);	\
	} while (0)

#ifdef CONFIG_SMP
void irq_pipeline_send_remote(unsigned int ipi,
			      const struct cpumask *cpumask);
#endif	/* CONFIG_SMP */

void irq_pipeline_oops(void);

bool irq_pipeline_steal_tick(void);

extern struct irq_domain *synthetic_irq_domain;

#else /* !CONFIG_IRQ_PIPELINE */

static inline void irq_pipeline_init_early(void) { }

static inline void irq_pipeline_init(void) { }

static inline void irq_pipeline_init_late(void) { }

static inline void irq_pipeline_enter_nosync(unsigned int irq) { }

static inline void irq_pipeline_clear(unsigned int irq) { }

static inline void irq_pipeline_oops(void) { }

#endif /* !CONFIG_IRQ_PIPELINE */

#endif /* _LINUX_IRQ_PIPELINE_H */
