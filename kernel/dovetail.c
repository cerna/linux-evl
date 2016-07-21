/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016 Philippe Gerum  <rpm@xenomai.org>.
 */
#include <linux/timekeeper_internal.h>
#include <linux/sched/signal.h>
#include <linux/irq_pipeline.h>
#include <linux/dovetail.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

static bool dovetail_enabled;

void __weak arch_dovetail_init_task(struct task_struct *p)
{
}

void dovetail_init_task(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);

	clear_ti_local_flags(ti, _TLF_DOVETAIL|_TLF_HEAD|_TLF_OFFSTAGE);
	arch_dovetail_init_task(p);
}

void dovetail_init_altsched(struct dovetail_altsched_context *p)
{
	struct task_struct *tsk = current;

	check_root_stage();
	p->task = tsk;
	p->active_mm = tsk->mm;
}
EXPORT_SYMBOL_GPL(dovetail_init_altsched);

void dovetail_start_altsched(void)
{
	check_root_stage();
	set_thread_local_flags(_TLF_DOVETAIL);
}
EXPORT_SYMBOL_GPL(dovetail_start_altsched);

void dovetail_stop_altsched(void)
{
	clear_thread_local_flags(_TLF_DOVETAIL);
	clear_thread_flag(TIF_MAYDAY);
}
EXPORT_SYMBOL_GPL(dovetail_stop_altsched);

void __weak dovetail_fastcall_hook(struct pt_regs *regs)
{
}

int __weak dovetail_syscall_hook(struct irq_stage *stage,
				 struct pt_regs *regs)
{
	return 0;
}

void __weak dovetail_mayday_hook(struct pt_regs *regs)
{
}

static inline
void call_mayday(struct thread_info *ti, struct pt_regs *regs)
{
	clear_ti_thread_flag(ti, TIF_MAYDAY);
	dovetail_mayday_hook(regs);
}

void dovetail_call_mayday(struct thread_info *ti, struct pt_regs *regs)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	call_mayday(ti, regs);
	hard_local_irq_restore(flags);
}

int dovetail_pipeline_syscall(struct thread_info *ti, struct pt_regs *regs)
{
	struct irq_stage *caller_stage, *target_stage;
	struct irq_stage_data *p, *this_context;
	unsigned long flags;
	int ret = 0;

	/*
	 * We should definitely not pipeline a syscall through the
	 * slow path with IRQs off.
	 */
	WARN_ON_ONCE(dovetail_debug() && hard_irqs_disabled());

	if (!dovetail_enabled)
		return 0;

	flags = hard_local_irq_save();
	caller_stage = current_irq_stage;
	this_context = irq_get_current_context();
	target_stage = head_irq_stage;
next:
	p = irq_stage_this_context(target_stage);
	irq_set_current_context(p);
	hard_local_irq_restore(flags);
	ret = dovetail_syscall_hook(caller_stage, regs);
	flags = hard_local_irq_save();
	/*
	 * Be careful about any stage (root <-> head) _and_ CPU
	 * migration that might have happened as a result of handing
	 * over the syscall to the out-of-band handler.
	 *
	 * - if a stage migration is detected, fetch the new
	 * per-stage, per-CPU context pointer.
	 *
	 * - if no stage migration happened, switch back to the
	 * initial caller's stage, on a possibly different CPU though.
	 */
	if (current_irq_stage != target_stage)
		this_context = irq_get_current_context();
	else {
		p = irq_stage_this_context(this_context->stage);
		irq_set_current_context(p);
	}

	if (this_context->stage == &root_irq_stage) {
		if (target_stage != &root_irq_stage && ret == 0) {
			target_stage = &root_irq_stage;
			goto next;
		}
		p = irq_root_this_context();
		if (irq_staged_waiting(p))
			irq_stage_sync_current();
 	} else if (test_ti_thread_flag(ti, TIF_MAYDAY))
		call_mayday(ti, regs);

	hard_local_irq_restore(flags);

	return ret;
}

void dovetail_root_sync(void)
{
	struct irq_stage_data *p;
	unsigned long flags;

	flags = hard_local_irq_save();

	p = irq_root_this_context();
	if (irq_staged_waiting(p))
		irq_stage_sync_current();

	hard_local_irq_restore(flags);
}

int dovetail_handle_syscall(struct thread_info *ti,
			    unsigned long nr, struct pt_regs *regs)
{
	unsigned long local_flags = READ_ONCE(ti_local_flags(ti));
	int ret;

	/*
	 * If the syscall # is out of bounds and the current IRQ stage
	 * is not the root one, this has to be a non-native system
	 * call handled by some co-kernel on the head stage. Hand it
	 * over to the head stage via the fast syscall handler.
	 *
	 * Otherwise, if the system call is out of bounds or the
	 * current thread is shared with a co-kernel (aka
	 * "dovetailed"), hand the syscall over to the latter through
	 * the pipeline stages. This allows:
	 *
	 * - the co-kernel to receive the initial - foreign - syscall
	 * a thread should send for enabling dovetailing.
	 *
	 * - the co-kernel to manipulate the current execution stage
	 * for handling the request, which includes switching the
	 * current thread back to the root stage if the syscall is a
	 * native one, or promoting it to the head stage if handling
	 * the foreign syscall requires this.
	 *
	 * Native syscalls from regular (non-dovetailed) threads are
	 * ignored by this routine, and flow down to the regular
	 * system call handler.
	 */

	if (nr >= NR_syscalls && (local_flags & _TLF_HEAD)) {
		dovetail_fastcall_hook(regs);
		local_flags = READ_ONCE(ti_local_flags(ti));
		if (local_flags & _TLF_HEAD) {
			if (test_ti_thread_flag(ti, TIF_MAYDAY))
				dovetail_call_mayday(ti, regs);
			return 1; /* don't pass down, no tail work. */
		} else {
			dovetail_root_sync();
			return -1; /* don't pass down, do tail work. */
		}
	}

	if ((local_flags & _TLF_DOVETAIL) || nr >= NR_syscalls) {
		ret = dovetail_pipeline_syscall(ti, regs);
		local_flags = READ_ONCE(ti_local_flags(ti));
		if (local_flags & _TLF_HEAD)
			return 1; /* don't pass down, no tail work. */
		if (ret)
			return -1; /* don't pass down, do tail work. */
	}

	return 0; /* pass syscall down to the host. */
}

void __weak dovetail_trap_hook(unsigned int trapnr, struct pt_regs *regs)
{
}

void dovetail_handle_trap(unsigned int exception, struct pt_regs *regs)
{
	/*
	 * We send a notification about all traps raised over a
	 * registered head stage only.
	 */
	if (on_head_stage() && dovetail_enabled)
		dovetail_trap_hook(exception, regs);
}

void __weak dovetail_kevent_hook(int kevent, void *data)
{
}

void dovetail_handle_kevent(int kevent, void *data)
{
	check_root_stage();

	if (dovetail_enabled)
		dovetail_kevent_hook(kevent, data);
}

void __weak dovetail_migration_hook(struct task_struct *p)
{
}

static void finalize_oob_transition(void) /* hard IRQs off */
{
	struct irq_pipeline_data *pd;
	struct irq_stage_data *p;
	struct task_struct *t;

	check_root_stage();
	pd = raw_cpu_ptr(&irq_pipeline);
	t = pd->task_inflight;
	if (t == NULL)
		return;

	/*
	 * @t which is in flight to the head stage might have received
	 * a signal while waiting in off-stage state to be actually
	 * scheduled out. We can't act upon that signal safely from
	 * here, we simply let the task complete the migration process
	 * to the head stage. The pending signal will be handled when
	 * the task eventually exits the out-of-band context by the
	 * converse migration.
	 */
	pd->task_inflight = NULL;

	/*
	 * IRQs are hard disabled, but the stage transition handler
	 * may assume the head stage is stalled: fix this up.
	 */
	p = irq_head_this_context();
	set_stage_bit(STAGE_STALL_BIT, p);
	dovetail_migration_hook(t);
	clear_stage_bit(STAGE_STALL_BIT, p);
	if (irq_staged_waiting(p))
		/* Current stage (root) != p->stage (head). */
		irq_stage_sync(p->stage);
}

void dovetail_oob_trampoline(void)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	finalize_oob_transition();
	hard_local_irq_restore(flags);
}

int dovetail_inband_switch_tail(void)
{
	bool on_root;

	check_hard_irqs_disabled();

	/*
	 * We may run this code either over the inband or oob
	 * contexts. If inband, we may have a thread blocked in
	 * dovetail_leave_inband(), waiting for the co-kernel to
	 * schedule it back in over the oob context:
	 * finalize_oob_transition() should take care of it. If oob,
	 * the co-kernel just switched us back, and we may update the
	 * context markers.
	 *
	 * CAUTION: The preemption count may not reflect the active
	 * stage yet, so use the current stage pointer to determine
	 * which one we are on.
	 */
	on_root = current_irq_stage == &root_irq_stage;
	if (on_root)
		finalize_oob_transition();
	else {
		set_thread_local_flags(_TLF_HEAD);
		WARN_ON_ONCE(dovetail_debug() &&
			     (preempt_count() & STAGE_MASK));
		preempt_count_add(STAGE_OFFSET);
	}

	if (on_root)
		hard_local_irq_enable();

	return !on_root;
}

int dovetail_start(void)
{
	check_root_stage();

	if (!head_stage_present())
		return -ENODEV;
	else if (dovetail_enabled)
		return -EBUSY;

	dovetail_enabled = true;
	smp_wmb();

	return 0;
}
EXPORT_SYMBOL_GPL(dovetail_start);

void dovetail_stop(void)
{
	check_root_stage();

	dovetail_enabled = false;
	smp_wmb();
}
EXPORT_SYMBOL_GPL(dovetail_stop);
