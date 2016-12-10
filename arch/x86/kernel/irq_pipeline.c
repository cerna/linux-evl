/*   -*- linux-c -*-
 *   arch/x86/kernel/irq_pipeline.c
 *
 *   Copyright (C) 2002-2016 Philippe Gerum.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/clockchips.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/irq_pipeline.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>
#include <asm/processor.h>
#include <asm/atomic.h>
#include <asm/hw_irq.h>
#include <asm/irq.h>
#include <asm/desc.h>
#include <asm/io.h>
#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/tlbflush.h>
#include <asm/fixmap.h>
#include <asm/bitops.h>
#include <asm/mpspec.h>
#ifdef CONFIG_X86_IO_APIC
#include <asm/io_apic.h>
#endif	/* CONFIG_X86_IO_APIC */
#include <asm/apic.h>
#endif	/* CONFIG_X86_LOCAL_APIC */
#include <asm/traps.h>
#include <asm/tsc.h>
#include <asm/mce.h>

DEFINE_PER_CPU(unsigned long, __ipipe_cr2);
EXPORT_PER_CPU_SYMBOL_GPL(__ipipe_cr2);

#ifdef CONFIG_X86_LOCAL_APIC

static struct irq_domain *apic_irq_domain;

static void apicm_irq_noop(struct irq_data *data) { }

static unsigned int apicm_irq_noop_ret(struct irq_data *data)
{
	return 0;
}

void handle_apic_irq(struct irq_desc *desc)
{
	if (apicm_irq_vector(irq_desc_get_irq(desc)) != SPURIOUS_APIC_VECTOR)
		__ack_APIC_irq();
}

static struct irq_chip apicm_chip = {
	.name		= "APIC mapper",
	.irq_startup	= apicm_irq_noop_ret,
	.irq_shutdown	= apicm_irq_noop,
	.irq_enable	= apicm_irq_noop,
	.irq_disable	= apicm_irq_noop,
	.irq_ack	= apicm_irq_noop,
	.irq_mask	= apicm_irq_noop,
	.irq_unmask	= apicm_irq_noop,
	.flags		= IRQCHIP_PIPELINE_SAFE | IRQCHIP_SKIP_SET_WAKE,
};

static int apicm_irq_map(struct irq_domain *d, unsigned int irq,
			 irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &apicm_chip, handle_apic_irq);

	return 0;
}

static struct irq_domain_ops apicm_domain_ops = {
	.map	= apicm_irq_map,
};

#endif	/* CONFIG_X86_LOCAL_APIC */

void do_root_irq(struct pt_regs *regs,
		 void (*handler)(struct pt_regs *regs));

static inline unsigned get_irq_vector(int irq)
{
#ifdef CONFIG_X86_IO_APIC
	struct irq_cfg *cfg;

	if (irq == IRQ_MOVE_CLEANUP_VECTOR)
		return irq;

	if (irq >= IPIPE_FIRST_APIC_IRQ && irq < IPIPE_NR_XIRQS)
		return apicm_irq_vector(irq);

	cfg = irq_get_chip_data(irq);

	return cfg->vector;
#elif defined(CONFIG_X86_LOCAL_APIC)
	return is_apic_irqnr(irq) ?
		apicm_irq_vector(irq) : irq + IRQ0_VECTOR;
#else
	return irq + IRQ0_VECTOR;
#endif
}

static inline void do_root_sirq(unsigned int irq, struct irq_desc *desc,
				struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	irq_enter();
	generic_handle_irq_desc(desc);
	irq_exit();
	set_irq_regs(old_regs);
#ifdef CONFIG_X86_64
	if (raw_cpu_read(irq_count) < 0)
#endif
		preempt_check_resched();
}

#define __P(__x)	((void (*)(struct pt_regs *))(__x))

asmlinkage void smp_apic_timer_interrupt(struct pt_regs *regs);
asmlinkage void smp_error_interrupt(struct pt_regs *regs);
asmlinkage void uv_bau_message_interrupt(struct pt_regs *regs);
asmlinkage void smp_irq_work_interrupt(struct pt_regs *regs);
asmlinkage void smp_x86_platform_ipi(struct pt_regs *regs);
asmlinkage void smp_reschedule_interrupt(struct pt_regs *regs);
asmlinkage void smp_call_function_interrupt(struct pt_regs *regs);
asmlinkage void smp_call_function_single_interrupt(struct pt_regs *regs);
asmlinkage void smp_irq_move_cleanup_interrupt(struct pt_regs *regs);
asmlinkage void smp_reboot_interrupt(struct pt_regs *regs);
void smp_kvm_posted_intr_ipi(struct pt_regs *regs);
void smp_kvm_posted_intr_wakeup_ipi(struct pt_regs *regs);
asmlinkage void smp_spurious_interrupt(struct pt_regs *regs);

void do_IRQ_pipelined(unsigned int irq, struct irq_desc *desc)
{
	void (*handler)(struct pt_regs *regs);
	struct pt_regs *regs;
	unsigned int vector;

	regs = raw_cpu_ptr(&irq_pipeline.tick_regs);

	if (desc->irq_data.domain == synthetic_irq_domain) {
		do_root_sirq(irq, desc, regs);
		return;
	}

	vector = get_irq_vector(irq);
	regs->orig_ax = ~vector;

	if (!is_apic_irqnr(irq)) {
		do_root_irq(regs, __P(do_IRQ));
		return;
	}

#ifdef CONFIG_X86_LOCAL_APIC
	switch (vector) {
	case LOCAL_TIMER_VECTOR:
		handler = __P(smp_apic_timer_interrupt);
		break;
	case ERROR_APIC_VECTOR:
		handler = __P(smp_error_interrupt);
		break;
#ifdef CONFIG_X86_THERMAL_VECTOR
	case THERMAL_APIC_VECTOR:
		handler = __P(smp_thermal_interrupt);
		break;
#endif
#ifdef CONFIG_X86_MCE_THRESHOLD
	case THRESHOLD_APIC_VECTOR:
		handler = __P(smp_threshold_interrupt);
		break;
#endif
#ifdef CONFIG_X86_UV
	case UV_BAU_MESSAGE:
		handler = __P(uv_bau_message_interrupt);
		break;
#endif
#ifdef CONFIG_IRQ_WORK
	case IRQ_WORK_VECTOR:
		handler = __P(smp_irq_work_interrupt);
		break;
#endif
	case X86_PLATFORM_IPI_VECTOR:
		handler = __P(smp_x86_platform_ipi);
#ifdef CONFIG_SMP
	case RESCHEDULE_VECTOR:
		handler = __P(smp_reschedule_interrupt);
		break;
	case CALL_FUNCTION_VECTOR:
		handler = __P(smp_call_function_interrupt);
		break;
	case CALL_FUNCTION_SINGLE_VECTOR:
		handler = __P(smp_call_function_single_interrupt);
		break;
	case IRQ_MOVE_CLEANUP_VECTOR:
		handler = __P(smp_irq_move_cleanup_interrupt);
		break;
	case REBOOT_VECTOR:
		handler = __P(smp_reboot_interrupt);
		break;
#ifdef CONFIG_X86_MCE_AMD
	case DEFERRED_ERROR_VECTOR:
		handler = __P(smp_deferred_error_interrupt);
		break;
#endif
#ifdef CONFIG_HAVE_KVM
	case POSTED_INTR_VECTOR:
		handler = __P(smp_kvm_posted_intr_ipi);
		break;
	case POSTED_INTR_WAKEUP_VECTOR:
		handler = __P(smp_kvm_posted_intr_wakeup_ipi);
		break;
#endif
#endif	/* CONFIG_SMP */
	case SPURIOUS_APIC_VECTOR:
	default:
		handler = __P(smp_spurious_interrupt);
	}

	do_root_irq(regs, handler);
#endif	/* CONFIG_X86_LOCAL_APIC */
}

#undef __P

#ifdef CONFIG_X86_LOCAL_APIC

void __init arch_irq_pipeline_init(void)
{
	apic_irq_domain = irq_domain_add_simple(NULL,
			NR_VECTORS - FIRST_SYSTEM_VECTOR,
			apicm_vector_irq(FIRST_SYSTEM_VECTOR),
			&apicm_domain_ops, NULL);
}

#else
void __init arch_irq_pipeline_init(void) { }
#endif

void __init irq_pipeline_init_late(void)
{
	__ipipe_hrclock_freq = 1000ULL * cpu_khz;
}

#ifdef CONFIG_SMP

void irq_pipeline_send_remote(unsigned int ipi,
			      const struct cpumask *cpumask)
{
	unsigned long flags;

	flags = hard_local_irq_save();

	if (likely(!cpumask_empty(cpumask)))
		apic->send_IPI_mask_allbutself(cpumask,
					       apicm_irq_vector(ipi));

	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(irq_pipeline_send_remote);

#endif	/* CONFIG_SMP */

int enter_irq_pipeline(struct pt_regs *regs)
{
	int irq, vector = ~regs->orig_ax;
	struct irq_desc *desc;

	if (vector >= FIRST_SYSTEM_VECTOR)
		irq = apicm_vector_irq(vector);
	else {
		desc = __this_cpu_read(vector_irq[vector]);
		BUG_ON(IS_ERR_OR_NULL(desc));
		irq = irq_desc_get_irq(desc);
	}

	irq_pipeline_enter(irq, regs);

	if (!__on_root_stage() ||
	    test_bit(IPIPE_STALL_FLAG, &irq_root_status))
		return 0;

	return 1;
}
