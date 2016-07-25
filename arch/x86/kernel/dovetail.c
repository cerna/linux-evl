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

void arch_dovetail_get_hrclock(struct dovetail_hrclock_data *hrd)
{
	hrd->hrclock_freq = __ipipe_hrclock_freq;
	hrd->hrclock_name = "tsc";
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
