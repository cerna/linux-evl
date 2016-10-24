/* -*- linux-c -*-
 * arch/arm/kernel/irq_pipeline.c
 *
 * Copyright (C) 2002-2005 Philippe Gerum.
 * Copyright (C) 2004 Wolfgang Grandegger (Adeos/arm port over 2.4).
 * Copyright (C) 2005 Heikki Lindholm (PowerPC 970 fixes).
 * Copyright (C) 2005 Stelian Pop.
 * Copyright (C) 2006-2008 Gilles Chanteperdrix.
 * Copyright (C) 2010 Philippe Gerum (SMP port).
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
 * Architecture-dependent I-PIPE support for ARM.
 */

#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/irq.h>
#include <linux/irqnr.h>
#include <linux/prefetch.h>
#include <linux/cpu.h>
#include <linux/irq_pipeline.h>
#include <asm/system_info.h>
#include <asm/atomic.h>
#include <asm/hardirq.h>
#include <asm/io.h>
#include <asm/unistd.h>
#include <asm/mach/irq.h>
#include <asm/exception.h>

#ifdef CONFIG_SMP

static struct irq_domain *sipic_domain;

static void sipic_irq_noop(struct irq_data *data) { }

static unsigned int sipic_irq_noop_ret(struct irq_data *data)
{
	return 0;
}

static struct irq_chip sipic_chip = {
	.name		= "SIPIC",
	.irq_startup	= sipic_irq_noop_ret,
	.irq_shutdown	= sipic_irq_noop,
	.irq_enable	= sipic_irq_noop,
	.irq_disable	= sipic_irq_noop,
	.irq_ack	= sipic_irq_noop,
	.irq_mask	= sipic_irq_noop,
	.irq_unmask	= sipic_irq_noop,
	.flags		= IRQCHIP_PIPELINE_SAFE | IRQCHIP_SKIP_SET_WAKE,
};

static int sipic_irq_map(struct irq_domain *d, unsigned int irq,
			irq_hw_number_t hwirq)
{
	irq_set_percpu_devid(irq);
	irq_set_chip_and_handler(irq, &sipic_chip, handle_synthetic_irq);

	return 0;
}

static struct irq_domain_ops sipic_domain_ops = {
	.map	= sipic_irq_map,
};

static void create_ipi_domain(void)
{
	/*
	 * Create an IRQ domain for mapping all IPIs, with fixed sirq
	 * numbers starting from IPIPE_IPI_BASE onward. The sirqs
	 * obtained can be injected into the pipeline upon IPI receipt
	 * like other interrupts.
	 */
	sipic_domain = irq_domain_add_simple(NULL, NR_IPI, IPIPE_IPI_BASE,
					     &sipic_domain_ops, NULL);
}

void irq_pipeline_send_remote(unsigned int ipi,
			      const struct cpumask *cpumask)
{
	enum ipi_msg_type msg = ipi - IPIPE_IPI_BASE;
	smp_cross_call(cpumask, msg);
}
EXPORT_SYMBOL_GPL(irq_pipeline_send_remote);

#endif	/* CONFIG_SMP */

void __init arch_irq_pipeline_init(void)
{
#ifdef CONFIG_CPU_ARM926T
	/*
	 * We do not want "wfi" to be called in arm926ejs based
	 * processor, as this causes Linux to disable the I-cache
	 * when idle.
	 */
	extern void cpu_arm926_proc_init(void);
	if (likely(cpu_proc_init == &cpu_arm926_proc_init)) {
		printk("I-pipe: ARM926EJ-S detected, disabling wfi instruction"
		       " in idle loop\n");
		cpu_idle_poll_ctrl(true);
	}
#endif
#ifdef CONFIG_SMP
	create_ipi_domain();
#endif
}

asmlinkage int __ipipe_check_root_interruptible(void)
{
	return __on_root_stage() && !irqs_disabled();
}

void do_IRQ_pipelined(unsigned int irq, struct irq_desc *desc)
{
	struct pt_regs *regs = raw_cpu_ptr(&irq_pipeline.tick_regs);

#ifdef CONFIG_SMP
	/*
	 * Check for IPIs, handing them over to the specific dispatch
	 * code.
	 */
	if (irq >= IPIPE_IPI_BASE && irq < IPIPE_IPI_BASE + NR_IPI) {
		__handle_IPI(irq - IPIPE_IPI_BASE, regs);
		return;
	}
#endif
		
	do_domain_irq(irq, regs);
}
