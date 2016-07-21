/* -*- linux-c -*-
 * kernel/dovetail.c
 *
 * Copyright (C) 2002-2016 Philippe Gerum.
 *
 * Dual kernel interface.
 */
#include <linux/timekeeper_internal.h>
#include <linux/sched/signal.h>
#include <linux/dovetail.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

void __weak arch_dovetail_init_task(struct task_struct *p)
{
}

void dovetail_init_task(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);

	clear_ti_local_flags(ti, _TLF_DOVETAIL|_TLF_HEAD);
	arch_dovetail_init_task(p);
}

void __weak arch_dovetail_enable(int flags)
{
}

void dovetail_enable(int flags)	/* flags unused yet. */
{
	check_root_stage();
	arch_dovetail_enable(flags);
	set_thread_local_flags(_TLF_DOVETAIL);
}
EXPORT_SYMBOL_GPL(dovetail_enable);

void dovetail_disable(void)
{
	clear_thread_local_flags(_TLF_DOVETAIL);
	clear_thread_flag(TIF_MAYDAY);
}
EXPORT_SYMBOL_GPL(dovetail_disable);

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
	struct irq_stage *caller_stage, *this_stage, *stage;
	struct irq_stage_data *p;
	unsigned long flags;
	int ret = 0;

	/*
	 * We should definitely not pipeline a syscall through the
	 * slow path with IRQs off.
	 */
	WARN_ON_ONCE(dovetail_debug() && hard_irqs_disabled());

	flags = hard_local_irq_save();
	caller_stage = this_stage = __current_irq_stage;
	stage = head_irq_stage;
next:
	p = irq_stage_this_context(stage);
	if (likely(p->coflags & _DOVETAIL_SYSCALL_E)) {
		irq_set_current_context(p);
		p->coflags |= _DOVETAIL_SYSCALL_R;
		hard_local_irq_restore(flags);
		ret = dovetail_syscall_hook(caller_stage, regs);
		flags = hard_local_irq_save();
		p->coflags &= ~_DOVETAIL_SYSCALL_R;
		if (__current_irq_stage != stage)
			/* Account for stage migration. */
			this_stage = __current_irq_stage;
		else
			__set_current_irq_stage(this_stage);
	}

	if (this_stage == &root_irq_stage) {
		if (stage != &root_irq_stage && ret == 0) {
			stage = &root_irq_stage;
			goto next;
		}
		/*
		 * Careful: we may have migrated from head->root, so p
		 * would be irq_stage_this_context(head).
		 */
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
				call_mayday(ti, regs);
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

void __weak dovetail_trap_hook(struct dovetail_trap_data *data)
{
}

void dovetail_handle_trap(int exception, struct pt_regs *regs)
{
	struct dovetail_trap_data data;
	struct irq_stage_data *p;
	unsigned long flags;

	flags = hard_local_irq_save();

	/*
	 * We send a notification about all traps raised over a
	 * registered head stage only.
	 */
	if (__on_root_stage())
		goto out;

	p = irq_head_this_context();
	if (likely(p->coflags & _DOVETAIL_TRAP_E)) {
		p->coflags |= _DOVETAIL_TRAP_R;
		hard_local_irq_restore(flags);
		data.exception = exception;
		data.regs = regs;
		dovetail_trap_hook(&data);
		flags = hard_local_irq_save();
		p->coflags &= ~_DOVETAIL_TRAP_R;
	}
out:
	hard_local_irq_restore(flags);
}

void __weak dovetail_kevent_hook(int kevent, void *data)
{
}

void dovetail_handle_kevent(int kevent, void *data)
{
	struct irq_stage_data *p;
	unsigned long flags;

	check_root_stage();

	flags = hard_local_irq_save();

	p = irq_root_this_context();
	if (likely(p->coflags & _DOVETAIL_KEVENT_E)) {
		p->coflags |= _DOVETAIL_KEVENT_R;
		hard_local_irq_restore(flags);
		dovetail_kevent_hook(kevent, data);
		flags = hard_local_irq_save();
		p->coflags &= ~_DOVETAIL_KEVENT_R;
	}

	hard_local_irq_restore(flags);
}

bool __weak dovetail_enter_idle(void)
{
	return true;
}

void __weak dovetail_exit_idle(void) { }

void __weak dovetail_migration_hook(struct task_struct *p)
{
}

static void complete_domain_migration(void) /* hw IRQs off */
{
	struct irq_pipeline_data *pd;
	struct irq_stage_data *p;
	struct task_struct *t;

	check_root_stage();
	pd = raw_cpu_ptr(&irq_pipeline);
	t = pd->task_hijacked;
	if (t == NULL)
		return;

	pd->task_hijacked = NULL;
	if (signal_pending(t))	/* Migration aborted by signal. */
		return;

	/*
	 * IRQs are hard disabled, but the completion hook may assume
	 * the head stage is stalled: fix this up.
	 */
	p = irq_head_this_context();
	__set_bit(IPIPE_STALL_FLAG, &p->status);
	dovetail_migration_hook(t);
	__clear_bit(IPIPE_STALL_FLAG, &p->status);
	if (irq_staged_waiting(p))
		irq_pipeline_sync(p->stage);
}

void dovetail_complete_domain_migration(void)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	complete_domain_migration();
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(dovetail_complete_domain_migration);

int dovetail_context_switch_tail(void)
{
	int x;

	x = __on_root_stage();
	if (x)
		complete_domain_migration();
	else
		set_thread_local_flags(_TLF_HEAD);

	if (x)
		hard_local_irq_enable();

	return !x;
}

#ifdef CONFIG_DOVETAIL_TRACK_VM_GUEST
void dovetail_hypervisor_stall(void)
{
	struct hypervisor_stall *nfy;
	struct irq_pipeline_data *p;

	check_hard_irqs_disabled();
	p = raw_cpu_ptr(&irq_pipeline);
	nfy = p->vm_notifier;
	if (unlikely(nfy))
		nfy->handler(nfy);
}
EXPORT_SYMBOL_GPL(dovetail_hypervisor_stall);
#endif

void dovetail_host_events(struct irq_stage *stage, int event_mask)
{
	struct irq_stage_data *p;
	unsigned long flags;
	int cpu, wait;

	if (stage == &root_irq_stage) {
		WARN_ON(dovetail_debug() && (event_mask & _DOVETAIL_TRAP_E));
		event_mask &= ~_DOVETAIL_TRAP_E;
	} else {
		WARN_ON(dovetail_debug() && (event_mask & _DOVETAIL_KEVENT_E));
		event_mask &= ~_DOVETAIL_KEVENT_E;
	}

	flags = irq_pipeline_lock(NULL, NULL);

	for_each_online_cpu(cpu) {
		p = irq_stage_context(stage, cpu);
		p->coflags &= ~_DOVETAIL_ALL_E;
		p->coflags |= event_mask;
	}

	wait = (event_mask ^ _DOVETAIL_ALL_E) << _DOVETAIL_SHIFT_R;
	if (wait == 0 || !__on_root_stage()) {
		irq_pipeline_unlock(flags);
		return;
	}

	irq_stage_this_context(stage)->coflags &= ~wait;

	irq_pipeline_unlock(flags);

	/*
	 * In case we cleared some hooks over the root stage, we have
	 * to wait for any ongoing execution to finish, since our
	 * caller might subsequently unmap the target stage code.
	 *
	 * Synchronize with the notifiers, disabling all hooks before
	 * we start waiting for completion on all CPUs.
	 */
	for_each_online_cpu(cpu) {
		while (irq_stage_context(stage, cpu)->coflags & wait)
			schedule_timeout_interruptible(HZ / 50);
	}
}
EXPORT_SYMBOL_GPL(dovetail_host_events);

void __weak arch_dovetail_get_hrclock(struct dovetail_hrclock_data *hrd)
{
}

void dovetail_get_hrclock(struct dovetail_hrclock_data *hrd)
{
	arch_dovetail_get_hrclock(hrd);
}
EXPORT_SYMBOL_GPL(dovetail_get_hrclock);

#ifdef CONFIG_DOVETAIL_HAVE_HOSTRT
/*
 * NOTE: The architecture specific code must only call this function
 * when a clocksource suitable for CLOCK_HOST_REALTIME is enabled.
 * The event receiver is responsible for providing proper locking.
 */
void dovetail_update_hostrt(struct timekeeper *tk)
{
	struct tk_read_base *tkr = &tk->tkr_mono;
	struct clocksource *clock = tkr->clock;
	struct ipipe_hostrt_data data;
	struct timespec xt;

	xt.tv_sec = tk->xtime_sec;
	xt.tv_nsec = (long)(tkr->xtime_nsec >> tkr->shift);
	check_root_stage();
	data.live = 1;
	data.cycle_last = tkr->cycle_last;
	data.mask = clock->mask;
	data.mult = tkr->mult;
	data.shift = tkr->shift;
	data.wall_time_sec = xt.tv_sec;
	data.wall_time_nsec = xt.tv_nsec;
	data.wall_to_monotonic.tv_sec = tk->wall_to_monotonic.tv_sec;
	data.wall_to_monotonic.tv_nsec = tk->wall_to_monotonic.tv_nsec;
	dovetail_handle_kevent(KEVENT_HOSTRT, &data);
}

#endif /* CONFIG_DOVETAIL_HAVE_HOSTRT */
