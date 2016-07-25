/*   -*- linux-c -*-
 *   arch/x86/kernel/dovetail.c
 *
 *   Copyright (C) 2002-2016 Philippe Gerum.
 */
#include <linux/memory.h>
#include <linux/dovetail.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <asm/traps.h>
#include <asm/i387.h>
#include <asm/fpu-internal.h>

void arch_dovetail_enable(int flags)
{
	struct task_struct *p = current;

	/*
	 * Setup a clean extended FPU state for kernel threads.  The
	 * kernel already took care of this issue for userland tasks
	 */
	if (p->mm == NULL && use_xsave())
		memcpy(p->thread.fpu.state, init_xstate_buf, xstate_size);
}

static inline void fixup_if(int s, struct pt_regs *regs)
{
	if (s)
		regs->flags &= ~X86_EFLAGS_IF;
	else
		regs->flags |= X86_EFLAGS_IF;
}

int do_trap_prologue(struct pt_regs *regs, int trapnr,
		     unsigned long *flags)
{
	bool root_entry = false;
	struct irq_stage *stage;
	unsigned long cr2;

	if (trapnr == X86_TRAP_PF)
		cr2 = native_read_cr2();

	/*
	 * If we fault over the root stage, we need to replicate the
	 * real interrupt state into the virtual mask before calling
	 * the dovetail trap handler. This is also required later
	 * before branching to the regular exception handler.
	 */
	if (on_root_stage()) {
		root_entry = true;
		local_save_flags(*flags);
		if (hard_irqs_disabled())
			local_irq_disable();
	}

	dovetail_handle_trap(trapnr, regs);

	/*
	 * If no head stage is installed, or in case we faulted in the
	 * iret path of x86-32, regs.flags does not match the root
	 * stage state. The fault handler or the low-level return code
	 * may evaluate it. So fix this up, either by the root state
	 * sampled on entry or, if we migrated to root, with the
	 * current state.
	 */
	if (likely(on_root_stage()))
		fixup_if(root_entry ? raw_irqs_disabled_flags(*flags) :
			 raw_irqs_disabled(), regs);
	else {
		/*
		 * Detect unhandled faults over the head stage,
		 * switching to root so that it can handle the fault
		 * cleanly.
		 */
		hard_local_irq_disable();
		stage = __current_irq_stage;
		__set_current_irq_stage(&root_irq_stage);

		/* Always warn about user land and unfixable faults. */
		if (user_mode(regs) ||
		    !search_exception_tables(instruction_pointer(regs)))
			WARN(1, "Unhandled exception over %s stage"
			     " at %#lx - switching to root stage\n",
			     stage->name, instruction_pointer(regs));
		else if (irq_pipeline_debug())
			/* Also report fixable ones when debugging is enabled. */
			WARN(1, "Fixable exception over stage %s "
			     "at %#lx - switching to root stage\n",
			     stage->name, instruction_pointer(regs));
	}

	if (trapnr == X86_TRAP_PF)
		write_cr2(cr2);

	return root_entry ? 0 : -1;
}

struct task_struct *__switch_to(struct task_struct *prev_p,
				struct task_struct *next_p);
EXPORT_SYMBOL_GPL(__switch_to);
EXPORT_SYMBOL_GPL(do_munmap);
EXPORT_PER_CPU_SYMBOL_GPL(fpu_owner_task);
EXPORT_SYMBOL_GPL(show_stack);
#if defined(CONFIG_CC_STACKPROTECTOR) && defined(CONFIG_X86_64)
EXPORT_PER_CPU_SYMBOL_GPL(irq_stack_union);
#endif
