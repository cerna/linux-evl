/*
 * Copyright (C) 2001-2013 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2006-2010 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 * Copyright (C) 2001-2013 The Xenomai project <http://www.xenomai.org>
 *
 * SMP support Copyright (C) 2004 The HYADES project <http://www.hyades-itea.org>
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/signal.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/irq_work.h>
#include <linux/sched/signal.h>
#include <linux/sched/types.h>
#include <steely/sched.h>
#include <steely/timer.h>
#include <steely/synch.h>
#include <steely/heap.h>
#include <steely/intr.h>
#include <steely/registry.h>
#include <steely/clock.h>
#include <steely/stat.h>
#include <steely/trace.h>
#include <steely/assert.h>
#include <steely/select.h>
#include <steely/lock.h>
#include <steely/thread.h>
#include <trace/events/steely-core.h>
#include <asm-generic/steely/mayday.h>
#include "debug.h"

static DECLARE_WAIT_QUEUE_HEAD(join_all);

static void timeout_handler(struct xntimer *timer)
{
	struct xnthread *thread = container_of(timer, struct xnthread, rtimer);

	xnthread_set_info(thread, XNTIMEO);	/* Interrupts are off. */
	xnthread_resume(thread, XNDELAY);
}

static inline void fixup_ptimer_affinity(struct xnthread *thread)
{
#ifdef CONFIG_SMP
	struct xntimer *timer = &thread->ptimer;
	int cpu;
	/*
	 * The thread a periodic timer is affine to might have been
	 * migrated to another CPU while passive. Fix this up.
	 */
	if (thread->sched != timer->sched) {
		cpu = xnclock_get_default_cpu(xntimer_clock(timer),
					      xnsched_cpu(thread->sched));
		xntimer_set_sched(timer, xnsched_struct(cpu));
	}
#endif
}

static void periodic_handler(struct xntimer *timer)
{
	struct xnthread *thread = container_of(timer, struct xnthread, ptimer);
	/*
	 * Prevent unwanted round-robin, and do not wake up threads
	 * blocked on a resource.
	 */
	if (xnthread_test_state(thread, XNDELAY|XNPEND) == XNDELAY)
		xnthread_resume(thread, XNDELAY);

	fixup_ptimer_affinity(thread);
}

static inline void enlist_new_thread(struct xnthread *thread)
{				/* nklock held, irqs off */
	list_add_tail(&thread->glink, &nkthreadq);
	steely_nrthreads++;
	xnvfile_touch_tag(&nkthreadlist_tag);
}

struct kthread_arg {
	struct xnthread *thread;
	struct completion *done;
};

static int kthread_trampoline(void *arg)
{
	struct kthread_arg *ka = arg;
	struct xnthread *thread = ka->thread;
	struct sched_param param;
	int ret, policy, prio;

	/*
	 * It only makes sense to create Steely kthreads with the
	 * SCHED_FIFO, SCHED_NORMAL or SCHED_WEAK policies. So
	 * anything that is not from Steely's RT class is assumed to
	 * belong to SCHED_NORMAL linux-wise.
	 */
	if (thread->sched_class != &xnsched_class_rt) {
		policy = SCHED_NORMAL;
		prio = 0;
	} else {
		policy = SCHED_FIFO;
		prio = normalize_priority(thread->cprio);
	}

	param.sched_priority = prio;
	sched_setscheduler(current, policy, &param);

	ret = xnthread_map(thread, ka->done);
	if (ret) {
		printk(STEELY_WARNING "failed to create kernel shadow %s\n",
		       thread->name);
		return ret;
	}

	trace_steely_shadow_entry(thread);

	thread->entry(thread->cookie);

	xnthread_cancel(thread);

	return 0;
}

static inline int spawn_kthread(struct xnthread *thread)
{
	DECLARE_COMPLETION_ONSTACK(done);
	struct kthread_arg ka = {
		.thread = thread,
		.done = &done
	};
	struct task_struct *p;

	p = kthread_run(kthread_trampoline, &ka, "%s", thread->name);
	if (IS_ERR(p))
		return PTR_ERR(p);

	wait_for_completion(&done);

	return 0;
}

int __xnthread_init(struct xnthread *thread,
		    const struct xnthread_init_attr *attr,
		    struct xnsched *sched,
		    struct xnsched_class *sched_class,
		    const union xnsched_policy_param *sched_param)
{
	int flags = attr->flags, ret, gravity;

	flags &= ~(XNSUSP|XNBOOST);
	if ((flags & XNROOT) == 0)
		flags |= XNDORMANT;

	if (attr->name)
		ksformat(thread->name,
			 sizeof(thread->name), "%s", attr->name);
	else
		ksformat(thread->name,
			 sizeof(thread->name), "@%p", thread);

	/*
	 * We mirror the global user debug state into the per-thread
	 * state, to speed up branch taking in lib/steely wherever
	 * this needs to be tested.
	 */
	if (IS_ENABLED(CONFIG_STEELY_DEBUG_MUTEX_SLEEP))
		flags |= XNDEBUG;

	thread->personality = attr->personality;
	cpumask_and(&thread->affinity, &attr->affinity, &steely_cpu_affinity);
	thread->sched = sched;
	thread->state = flags;
	thread->info = 0;
	thread->local_info = 0;
	thread->wprio = XNSCHED_IDLE_PRIO;
	thread->cprio = XNSCHED_IDLE_PRIO;
	thread->bprio = XNSCHED_IDLE_PRIO;
	thread->lock_count = 0;
	thread->rrperiod = XN_INFINITE;
	thread->wchan = NULL;
	thread->wwake = NULL;
	thread->wcontext = NULL;
	thread->res_count = 0;
	thread->handle = XN_NO_HANDLE;
	memset(&thread->stat, 0, sizeof(thread->stat));
	thread->selector = NULL;
	INIT_LIST_HEAD(&thread->glink);
	INIT_LIST_HEAD(&thread->boosters);
	/* These will be filled by xnthread_start() */
	thread->entry = NULL;
	thread->cookie = NULL;
	init_completion(&thread->exited);

	gravity = flags & XNUSER ? XNTIMER_UGRAVITY : XNTIMER_KGRAVITY;
	xntimer_init(&thread->rtimer, &nkclock, timeout_handler,
		     sched, gravity);
	xntimer_set_name(&thread->rtimer, thread->name);
	xntimer_set_priority(&thread->rtimer, XNTIMER_HIPRIO);
	xntimer_init(&thread->ptimer, &nkclock, periodic_handler,
		     sched, gravity);
	xntimer_set_name(&thread->ptimer, thread->name);
	xntimer_set_priority(&thread->ptimer, XNTIMER_HIPRIO);

	thread->base_class = NULL; /* xnsched_set_policy() will set it. */
	ret = xnsched_init_thread(thread);
	if (ret)
		goto err_out;

	ret = xnsched_set_policy(thread, sched_class, sched_param);
	if (ret)
		goto err_out;

	if ((flags & (XNUSER|XNROOT)) == 0) {
		ret = spawn_kthread(thread);
		if (ret)
			goto err_out;
	}

	return 0;

err_out:
	xntimer_destroy(&thread->rtimer);
	xntimer_destroy(&thread->ptimer);

	return ret;
}

void xnthread_init_shadow_tcb(struct xnthread *thread)
{
	struct xnarchtcb *tcb = xnthread_archtcb(thread);
	struct task_struct *p = current;

	memset(tcb, 0, sizeof(*tcb));
	tcb->core.host_task = p;
	tcb->core.tsp = &p->thread;
	tcb->core.mm = p->mm;
	tcb->core.active_mm = p->mm;
	tcb->core.tip = task_thread_info(p);
	xnarch_init_shadow_tcb(thread);
}

void xnthread_init_root_tcb(struct xnthread *thread)
{
	struct xnarchtcb *tcb = xnthread_archtcb(thread);
	struct task_struct *p = current;

	memset(tcb, 0, sizeof(*tcb));
	tcb->core.host_task = p;
	tcb->core.tsp = &tcb->core.ts;
	tcb->core.mm = p->mm;
	tcb->core.tip = NULL;
	xnarch_init_root_tcb(thread);
}

void xnthread_deregister(struct xnthread *thread)
{
	if (thread->handle != XN_NO_HANDLE)
		xnregistry_remove(thread->handle);

	thread->handle = XN_NO_HANDLE;
}

char *xnthread_format_status(unsigned long status, char *buf, int size)
{
	static const char labels[] = XNTHREAD_STATE_LABELS;
	int pos, c, mask;
	char *wp;

	for (mask = (int)status, pos = 0, wp = buf;
	     mask != 0 && wp - buf < size - 2;	/* 1-letter label + \0 */
	     mask >>= 1, pos++) {
		if ((mask & 1) == 0)
			continue;

		c = labels[pos];

		switch (1 << pos) {
		case XNROOT:
			c = 'R'; /* Always mark root as runnable. */
			break;
		case XNREADY:
			if (status & XNROOT)
				continue; /* Already reported on XNROOT. */
			break;
		case XNDELAY:
			/*
			 * Only report genuine delays here, not timed
			 * waits for resources.
			 */
			if (status & XNPEND)
				continue;
			break;
		case XNPEND:
			/* Report timed waits with lowercase symbol. */
			if (status & XNDELAY)
				c |= 0x20;
			break;
		default:
			if (c == '.')
				continue;
		}
		*wp++ = c;
	}

	*wp = '\0';

	return buf;
}

int xnthread_set_clock(struct xnthread *thread, struct xnclock *newclock)
{
	spl_t s;

	if (thread == NULL) {
		thread = xnthread_current();
		if (thread == NULL)
			return -EPERM;
	}
	
	/* Change the clock the thread's periodic timer is paced by. */
	xnlock_get_irqsave(&nklock, s);
	xntimer_set_clock(&thread->ptimer, newclock);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}
EXPORT_SYMBOL_GPL(xnthread_set_clock);

ktime_t xnthread_get_timeout(struct xnthread *thread, ktime_t base)
{
	struct xntimer *timer;
	ktime_t timeout;

	if (!xnthread_test_state(thread,XNDELAY))
		return 0LL;

	if (xntimer_running_p(&thread->rtimer))
		timer = &thread->rtimer;
	else if (xntimer_running_p(&thread->ptimer))
		timer = &thread->ptimer;
	else
		return 0;

	timeout = xntimer_get_date(timer);
	if (timeout <= base)
		return ktime_set(0, 1);

	return ktime_sub(timeout, base);
}
EXPORT_SYMBOL_GPL(xnthread_get_timeout);

ktime_t xnthread_get_period(struct xnthread *thread)
{
	ktime_t period = 0;
	/*
	 * The current thread period might be:
	 * - the value of the timer interval for periodic threads (ns/ticks)
	 * - or, the value of the alloted round-robin quantum (ticks)
	 * - or zero, meaning "no periodic activity".
	 */
	if (xntimer_running_p(&thread->ptimer))
		period = xntimer_interval(&thread->ptimer);
	else if (xnthread_test_state(thread,XNRRB))
		period = thread->rrperiod;

	return period;
}
EXPORT_SYMBOL_GPL(xnthread_get_period);

void xnthread_prepare_wait(struct xnthread_wait_context *wc)
{
	struct xnthread *curr = xnthread_current();

	wc->posted = 0;
	curr->wcontext = wc;
}
EXPORT_SYMBOL_GPL(xnthread_prepare_wait);

static inline void release_all_ownerships(struct xnthread *curr)
{
	struct xnsynch *synch, *tmp;

	/*
	 * Release all the ownerships obtained by a thread on
	 * synchronization objects. This routine must be entered
	 * interrupts off.
	 */
	xnthread_for_each_booster_safe(synch, tmp, curr) {
		xnsynch_release(synch, curr);
		if (synch->cleanup)
			synch->cleanup(synch);
	}
}

static inline void cleanup_tcb(struct xnthread *curr) /* nklock held, irqs off */
{
	list_del(&curr->glink);
	steely_nrthreads--;
	xnvfile_touch_tag(&nkthreadlist_tag);

	if (xnthread_test_state(curr, XNREADY)) {
		STEELY_BUG_ON(STEELY, xnthread_test_state(curr, XNTHREAD_BLOCK_BITS));
		xnsched_dequeue(curr);
		xnthread_clear_state(curr, XNREADY);
	}

	if (xnthread_test_state(curr, XNPEND))
		xnsynch_forget_sleeper(curr);

	xnthread_set_state(curr, XNZOMBIE);
	/*
	 * NOTE: we must be running over the root thread, or @curr
	 * is dormant, which means that we don't risk sched->curr to
	 * disappear due to voluntary rescheduling while holding the
	 * nklock, despite @curr bears the zombie bit.
	 */
	release_all_ownerships(curr);
	xnsched_forget(curr);
	xnthread_deregister(curr);
}

void __xnthread_cleanup(struct xnthread *curr)
{
	spl_t s;

	secondary_mode_only();

	xntimer_destroy(&curr->rtimer);
	xntimer_destroy(&curr->ptimer);

	if (curr->selector) {
		xnselector_destroy(curr->selector);
		curr->selector = NULL;
	}

	xnlock_get_irqsave(&nklock, s);
	cleanup_tcb(curr);
	xnlock_put_irqrestore(&nklock, s);

	/* Wake up the joiner if any (we can't have more than one). */
	complete(&curr->exited);

	/* Notify our exit to xnthread_killall() if need be. */
	if (waitqueue_active(&join_all))
		wake_up(&join_all);

	/* Finalize last since this incurs releasing the TCB. */
	xnthread_run_handler_stack(curr, finalize_thread);
}

/*
 * Unwinds xnthread_init() ops for an unmapped thread.  Since the
 * latter must be dormant, it can't be part of any runqueue.
 */
void __xnthread_discard(struct xnthread *thread)
{
	spl_t s;

	secondary_mode_only();

	xntimer_destroy(&thread->rtimer);
	xntimer_destroy(&thread->ptimer);

	xnlock_get_irqsave(&nklock, s);
	if (!list_empty(&thread->glink)) {
		list_del(&thread->glink);
		steely_nrthreads--;
		xnvfile_touch_tag(&nkthreadlist_tag);
	}
	xnthread_deregister(thread);
	xnlock_put_irqrestore(&nklock, s);
}

int xnthread_init(struct xnthread *thread,
		  const struct xnthread_init_attr *attr,
		  struct xnsched_class *sched_class,
		  const union xnsched_policy_param *sched_param)
{
	struct cpumask affinity;
	struct xnsched *sched;
	int ret;

	if (attr->flags & ~(XNUSER | XNSUSP))
		return -EINVAL;

	/*
	 * Pick an initial CPU for the new thread which is part of its
	 * affinity mask, and therefore also part of the supported
	 * CPUs. This CPU may change in pin_to_initial_cpu().
	 */
	cpumask_and(&affinity, &attr->affinity, &steely_cpu_affinity);
	if (cpumask_empty(&affinity))
		return -EINVAL;

	sched = xnsched_struct(cpumask_first(&affinity));

	ret = __xnthread_init(thread, attr, sched, sched_class, sched_param);
	if (ret)
		return ret;

	trace_steely_thread_init(thread, attr, sched_class);

	return 0;
}
EXPORT_SYMBOL_GPL(xnthread_init);

int xnthread_start(struct xnthread *thread,
		   const struct xnthread_start_attr *attr)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!xnthread_test_state(thread, XNDORMANT)) {
		xnlock_put_irqrestore(&nklock, s);
		return -EBUSY;
	}

	xnthread_set_state(thread, attr->mode & (XNTHREAD_MODE_BITS | XNSUSP));
	thread->entry = attr->entry;
	thread->cookie = attr->cookie;
	if (attr->mode & XNLOCK)
		thread->lock_count = 1;

	/*
	 * A user-space thread starts immediately Steely-wise since we
	 * already have an underlying Linux context for it, so we can
	 * enlist it now to make it visible from the /proc interface.
	 */
	if (xnthread_test_state(thread, XNUSER))
		enlist_new_thread(thread);

	trace_steely_thread_start(thread);

	xnthread_resume(thread, XNDORMANT);
	xnsched_run();

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}
EXPORT_SYMBOL_GPL(xnthread_start);

int xnthread_set_mode(int clrmask, int setmask)
{
	int oldmode, lock_count;
	struct xnthread *curr;
	spl_t s;

	primary_mode_only();

	xnlock_get_irqsave(&nklock, s);
	curr = xnsched_current_thread();
	oldmode = xnthread_get_state(curr) & XNTHREAD_MODE_BITS;
	lock_count = curr->lock_count;
	xnthread_clear_state(curr, clrmask & XNTHREAD_MODE_BITS);
	xnthread_set_state(curr, setmask & XNTHREAD_MODE_BITS);
	trace_steely_thread_set_mode(curr);

	if (setmask & XNLOCK) {
		if (lock_count == 0)
			xnsched_lock();
	} else if (clrmask & XNLOCK) {
		if (lock_count > 0) {
			curr->lock_count = 0;
			xnthread_clear_localinfo(curr, XNLBALERT);
			xnsched_run();
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	if (lock_count > 0)
		oldmode |= XNLOCK;

	return oldmode;
}
EXPORT_SYMBOL_GPL(xnthread_set_mode);

void xnthread_suspend(struct xnthread *thread, int mask,
		      ktime_t timeout, xntmode_t timeout_mode,
		      struct xnsynch *wchan)
{
	unsigned long oldstate;
	struct xnsched *sched;
	spl_t s;

	/* No, you certainly do not want to suspend the root thread. */
	STEELY_BUG_ON(STEELY, xnthread_test_state(thread, XNROOT));
	/* No built-in support for conjunctive wait. */
	STEELY_BUG_ON(STEELY, wchan && thread->wchan);

	xnlock_get_irqsave(&nklock, s);

	trace_steely_thread_suspend(thread, mask, timeout, timeout_mode, wchan);

	sched = thread->sched;
	oldstate = thread->state;

	/*
	 * If attempting to suspend a runnable thread which is pending
	 * a forced switch to secondary mode (XNKICKED), just raise
	 * the XNBREAK status and return immediately, except if we
	 * are precisely doing such switch by applying XNRELAX.
	 *
	 * In the latter case, we also make sure to clear XNKICKED,
	 * since we won't go through prepare_for_signal() once
	 * relaxed.
	 */
	if (likely((oldstate & XNTHREAD_BLOCK_BITS) == 0)) {
		if (likely((mask & XNRELAX) == 0)) {
			if (xnthread_test_info(thread, XNKICKED))
				goto abort;
			if (thread == sched->curr &&
			    thread->lock_count > 0 &&
			    (oldstate & XNTRAPLB) != 0)
				goto lock_break;
		}
		xnthread_clear_info(thread,
				    XNRMID|XNTIMEO|XNBREAK|XNWAKEN|XNROBBED|XNKICKED);
	}

	/*
	 * Don't start the timer for a thread delayed indefinitely.
	 */
	if (!timeout_infinite(timeout) || timeout_mode != XN_RELATIVE) {
		xntimer_set_sched(&thread->rtimer, thread->sched);
		if (xntimer_start(&thread->rtimer, timeout, XN_INFINITE,
				  timeout_mode)) {
			/* (absolute) timeout value in the past, bail out. */
			if (wchan) {
				thread->wchan = wchan;
				xnsynch_forget_sleeper(thread);
			}
			xnthread_set_info(thread, XNTIMEO);
			goto out;
		}
		xnthread_set_state(thread, XNDELAY);
	}

	if (oldstate & XNREADY) {
		xnsched_dequeue(thread);
		xnthread_clear_state(thread, XNREADY);
	}

	xnthread_set_state(thread, mask);

	/*
	 * We must make sure that we don't clear the wait channel if a
	 * thread is first blocked (wchan != NULL) then forcibly
	 * suspended (wchan == NULL), since these are conjunctive
	 * conditions.
	 */
	if (wchan)
		thread->wchan = wchan;

	/*
	 * If the current thread is being relaxed, we must have been
	 * called from xnthread_relax(), in which case we introduce an
	 * opportunity for interrupt delivery right before switching
	 * context, which shortens the uninterruptible code path.
	 *
	 * We have to shut irqs off before __xnsched_run() though: if
	 * an interrupt could preempt us in ___xnsched_run() right
	 * after the call to xnarch_escalate() but before we grab the
	 * nklock, we would enter the critical section in
	 * xnsched_run() while running in secondary mode, which would
	 * defeat the purpose of xnarch_escalate().
	 */
	if (likely(thread == sched->curr)) {
		xnsched_set_resched(sched);
		if (unlikely(mask & XNRELAX)) {
			xnlock_clear_irqon(&nklock);
			splmax();
			__xnsched_run(sched);
			return;
		}
		/*
		 * If the thread is runnning on another CPU,
		 * xnsched_run will trigger the IPI as required.
		 */
		__xnsched_run(sched);
		goto out;
	}

	/*
	 * Ok, this one is an interesting corner case, which requires
	 * a bit of background first. Here, we handle the case of
	 * suspending a _relaxed_ user shadow which is _not_ the
	 * current thread.
	 *
	 *  The net effect is that we are attempting to stop the
	 * shadow thread for Steely, whilst this thread is actually
	 * running some code under the control of the Linux scheduler
	 * (i.e. it's relaxed).
	 *
	 *  To make this possible, we force the target Linux task to
	 * migrate back to the Steely domain by sending it a
	 * SIGSHADOW signal the interface libraries trap for this
	 * specific internal purpose, whose handler is expected to
	 * call back Steely's migration service.
	 *
	 * By forcing this migration, we make sure that Steely
	 * controls, hence properly stops, the target thread according
	 * to the requested suspension condition. Otherwise, the
	 * shadow thread in secondary mode would just keep running
	 * into the Linux domain, thus breaking the most common
	 * assumptions regarding suspended threads.
	 *
	 * We only care for threads that are not current, and for
	 * XNSUSP, XNDELAY, XNDORMANT and XNHELD conditions, because:
	 *
	 * - There is no point in dealing with relaxed threads, since
	 * personalities have to ask for primary mode switch when
	 * processing any syscall which may block the caller
	 * (i.e. __xn_exec_primary).
	 *
	 * - among all blocking bits (XNTHREAD_BLOCK_BITS), only
	 * XNSUSP, XNDELAY and XNHELD may be applied by the current
	 * thread to a non-current thread. XNPEND is always added by
	 * the caller to its own state, XNRELAX has special semantics
	 * escaping this issue.
	 *
	 * We don't signal threads which are already in a dormant
	 * state, since they are suspended by definition.
	 */
	if (((oldstate & (XNTHREAD_BLOCK_BITS|XNUSER)) == (XNRELAX|XNUSER)) &&
	    (mask & (XNDELAY | XNSUSP | XNHELD)) != 0)
		xnthread_signal(thread, SIGSHADOW, SIGSHADOW_ACTION_HARDEN);
out:
	xnlock_put_irqrestore(&nklock, s);
	return;

lock_break:
	/* NOTE: thread is current */
	if (xnthread_test_state(thread, XNWARN) &&
	    !xnthread_test_localinfo(thread, XNLBALERT)) {
		xnthread_set_info(thread, XNKICKED);
		xnthread_set_localinfo(thread, XNLBALERT);
		xnthread_signal(thread, SIGDEBUG, SIGDEBUG_LOCK_BREAK);
	}
abort:
	if (wchan) {
		thread->wchan = wchan;
		xnsynch_forget_sleeper(thread);
	}
	xnthread_clear_info(thread, XNRMID | XNTIMEO);
	xnthread_set_info(thread, XNBREAK);
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnthread_suspend);

void xnthread_resume(struct xnthread *thread, int mask)
{
	unsigned long oldstate;
	struct xnsched *sched;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	trace_steely_thread_resume(thread, mask);

	xntrace_pid(xnthread_host_pid(thread), xnthread_current_priority(thread));

	sched = thread->sched;
	oldstate = thread->state;

	if ((oldstate & XNTHREAD_BLOCK_BITS) == 0) {
		if (oldstate & XNREADY)
			xnsched_dequeue(thread);
		goto enqueue;
	}

	/* Clear the specified block bit(s) */
	xnthread_clear_state(thread, mask);

	/*
	 * If XNDELAY was set in the clear mask, xnthread_unblock()
	 * was called for the thread, or a timeout has elapsed. In the
	 * latter case, stopping the timer is a no-op.
	 */
	if (mask & XNDELAY)
		xntimer_stop(&thread->rtimer);

	if (!xnthread_test_state(thread, XNTHREAD_BLOCK_BITS))
		goto clear_wchan;

	if (mask & XNDELAY) {
		mask = xnthread_test_state(thread, XNPEND);
		if (mask == 0)
			goto unlock_and_exit;
		if (thread->wchan)
			xnsynch_forget_sleeper(thread);
		goto recheck_state;
	}

	if (xnthread_test_state(thread, XNDELAY)) {
		if (mask & XNPEND) {
			/*
			 * A resource became available to the thread.
			 * Cancel the watchdog timer.
			 */
			xntimer_stop(&thread->rtimer);
			xnthread_clear_state(thread, XNDELAY);
		}
		goto recheck_state;
	}

	/*
	 * The thread is still suspended, but is no more pending on a
	 * resource.
	 */
	if ((mask & XNPEND) != 0 && thread->wchan)
		xnsynch_forget_sleeper(thread);

	goto unlock_and_exit;

recheck_state:
	if (xnthread_test_state(thread, XNTHREAD_BLOCK_BITS))
		goto unlock_and_exit;

clear_wchan:
	if ((mask & ~XNDELAY) != 0 && thread->wchan != NULL)
		/*
		 * If the thread was actually suspended, clear the
		 * wait channel.  -- this allows requests like
		 * xnthread_suspend(thread,XNDELAY,...)  not to run
		 * the following code when the suspended thread is
		 * woken up while undergoing a simple delay.
		 */
		xnsynch_forget_sleeper(thread);

	if (unlikely((oldstate & mask) & XNHELD)) {
		xnsched_requeue(thread);
		goto ready;
	}
enqueue:
	xnsched_enqueue(thread);
ready:
	xnthread_set_state(thread, XNREADY);
	xnsched_set_resched(sched);
unlock_and_exit:
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnthread_resume);

int xnthread_unblock(struct xnthread *thread)
{
	int ret = 1;
	spl_t s;

	/*
	 * Attempt to abort an undergoing wait for the given thread.
	 * If this state is due to an alarm that has been armed to
	 * limit the sleeping thread's waiting time while it pends for
	 * a resource, the corresponding XNPEND state will be cleared
	 * by xnthread_resume() in the same move. Otherwise, this call
	 * may abort an undergoing infinite wait for a resource (if
	 * any).
	 */
	xnlock_get_irqsave(&nklock, s);

	trace_steely_thread_unblock(thread);

	if (xnthread_test_state(thread, XNDELAY))
		xnthread_resume(thread, XNDELAY);
	else if (xnthread_test_state(thread, XNPEND))
		xnthread_resume(thread, XNPEND);
	else
		ret = 0;

	/*
	 * We should not clear a previous break state if this service
	 * is called more than once before the target thread actually
	 * resumes, so we only set the bit here and never clear
	 * it. However, we must not raise the XNBREAK bit if the
	 * target thread was already awake at the time of this call,
	 * so that downstream code does not get confused by some
	 * "successful but interrupted syscall" condition. IOW, a
	 * break state raised here must always trigger an error code
	 * downstream, and an already successful syscall cannot be
	 * marked as interrupted.
	 */
	if (ret)
		xnthread_set_info(thread, XNBREAK);

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_unblock);

int xnthread_set_periodic(struct xnthread *thread, ktime_t idate,
			  xntmode_t timeout_mode, ktime_t period)
{
	struct xnclock *clock;
	int ret = 0, cpu;
	spl_t s;

	if (thread == NULL) {
		thread = xnthread_current();
		if (thread == NULL)
			return -EPERM;
	}
		
	xnlock_get_irqsave(&nklock, s);

	if (period == XN_INFINITE) {
		if (xntimer_running_p(&thread->ptimer))
			xntimer_stop(&thread->ptimer);

		goto unlock_and_exit;
	}

	/*
	 * LART: detect periods which are shorter than the core clock
	 * gravity for kernel thread timers. This can't work, caller
	 * must have messed up arguments.
	 */
	if (period < xnclock_get_gravity(&nkclock, kernel)) {
		ret = -EINVAL;
		goto unlock_and_exit;
	}

	/*
	 * Pin the periodic timer to a proper CPU, by order of
	 * preference: the CPU the timed thread runs on if possible,
	 * or the first CPU by logical number which can receive events
	 * from the clock device backing the timer, among the dynamic
	 * set of real-time CPUs currently enabled.
	 */
	clock = xntimer_clock(&thread->ptimer);
	cpu = xnclock_get_default_cpu(clock, xnsched_cpu(thread->sched));
	xntimer_set_sched(&thread->ptimer, xnsched_struct(cpu));

	if (timeout_infinite(idate))
		xntimer_start(&thread->ptimer, period, period, XN_RELATIVE);
	else
		ret = xntimer_start(&thread->ptimer, idate, period,
				    XN_ABSOLUTE);
unlock_and_exit:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_set_periodic);

int xnthread_wait_period(unsigned long *overruns_r)
{
	unsigned long overruns = 0;
	struct xnthread *thread;
	struct xnclock *clock;
	ktime_t now;
	int ret = 0;
	spl_t s;

	thread = xnthread_current();

	xnlock_get_irqsave(&nklock, s);

	if (unlikely(!xntimer_running_p(&thread->ptimer))) {
		ret = -EWOULDBLOCK;
		goto out;
	}

	trace_steely_thread_wait_period(thread);

	clock = xntimer_clock(&thread->ptimer);
	now = xnclock_read_monotonic(clock);
	if (likely(now < xntimer_pexpect(&thread->ptimer))) {
		xnthread_suspend(thread, XNDELAY, XN_INFINITE, XN_RELATIVE, NULL);
		if (unlikely(xnthread_test_info(thread, XNBREAK))) {
			ret = -EINTR;
			goto out;
		}
		now = xnclock_read_monotonic(clock);
	}

	overruns = xntimer_get_overruns(&thread->ptimer, now);
	if (overruns) {
		ret = -ETIMEDOUT;
		trace_steely_thread_missed_period(thread);
	}

	if (likely(overruns_r != NULL))
		*overruns_r = overruns;
 out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_wait_period);

int xnthread_set_slice(struct xnthread *thread, ktime_t quantum)
{
	struct xnsched *sched;
	spl_t s;

	if (quantum <= xnclock_get_gravity(&nkclock, user))
		return -EINVAL;

	xnlock_get_irqsave(&nklock, s);

	sched = thread->sched;
	thread->rrperiod = quantum;

	if (!timeout_infinite(quantum)) {
		if (thread->base_class->sched_tick == NULL) {
			xnlock_put_irqrestore(&nklock, s);
			return -EINVAL;
		}
		xnthread_set_state(thread, XNRRB);
		if (sched->curr == thread)
			xntimer_start(&sched->rrbtimer,
				      quantum, XN_INFINITE, XN_RELATIVE);
	} else {
		xnthread_clear_state(thread, XNRRB);
		if (sched->curr == thread)
			xntimer_stop(&sched->rrbtimer);
	}

	xnlock_put_irqrestore(&nklock, s);

	return 0;
}
EXPORT_SYMBOL_GPL(xnthread_set_slice);

void xnthread_cancel(struct xnthread *thread)
{
	spl_t s;

	/* Right, so you want to kill the kernel?! */
	STEELY_BUG_ON(STEELY, xnthread_test_state(thread, XNROOT));

	xnlock_get_irqsave(&nklock, s);

	if (xnthread_test_info(thread, XNCANCELD))
		goto check_self_cancel;

	trace_steely_thread_cancel(thread);

	xnthread_set_info(thread, XNCANCELD);

	/*
	 * If @thread is not started yet, fake a start request,
	 * raising the kicked condition bit to make sure it will reach
	 * xnthread_test_cancel() on its wakeup path.
	 */
	if (xnthread_test_state(thread, XNDORMANT)) {
		xnthread_set_info(thread, XNKICKED);
		xnthread_resume(thread, XNDORMANT);
		goto out;
	}

check_self_cancel:
	if (xnthread_current() == thread) {
		xnlock_put_irqrestore(&nklock, s);
		xnthread_test_cancel();
		/*
		 * May return if on behalf of an IRQ handler which has
		 * preempted @thread.
		 */
		return;
	}

	/*
	 * Force the non-current thread to exit:
	 *
	 * - unblock a user thread, switch it to weak scheduling,
	 * then send it SIGTERM.
	 *
	 * - just unblock a kernel thread, it is expected to reach a
	 * cancellation point soon after
	 * (i.e. xnthread_test_cancel()).
	 */
	if (xnthread_test_state(thread, XNUSER)) {
		__xnthread_demote(thread);
		xnthread_signal(thread, SIGTERM, 0);
	} else
		__xnthread_kick(thread);
out:
	xnlock_put_irqrestore(&nklock, s);

	xnsched_run();
}
EXPORT_SYMBOL_GPL(xnthread_cancel);

struct wait_grace_struct {
	struct completion done;
	struct rcu_head rcu;
};

static void grace_elapsed(struct rcu_head *head)
{
	struct wait_grace_struct *wgs;

	wgs = container_of(head, struct wait_grace_struct, rcu);
	complete(&wgs->done);
}

static void wait_for_rcu_grace_period(struct pid *pid)
{
	struct wait_grace_struct wait = {
		.done = COMPLETION_INITIALIZER_ONSTACK(wait.done),
	};
	struct task_struct *p;

	init_rcu_head_on_stack(&wait.rcu);
	
	for (;;) {
		call_rcu(&wait.rcu, grace_elapsed);
		wait_for_completion(&wait.done);
		if (pid == NULL)
			break;
		rcu_read_lock();
		p = pid_task(pid, PIDTYPE_PID);
		rcu_read_unlock();
		if (p == NULL)
			break;
		reinit_completion(&wait.done);
	}
}

int xnthread_join(struct xnthread *thread, bool uninterruptible)
{
	struct xnthread *curr = xnthread_current();
	int ret = 0, switched = 0;
	struct pid *pid;
	pid_t tpid;
	spl_t s;

	STEELY_BUG_ON(STEELY, xnthread_test_state(thread, XNROOT));

	if (thread == curr)
		return -EDEADLK;

	xnlock_get_irqsave(&nklock, s);

	if (xnthread_test_state(thread, XNJOINED)) {
		ret = -EBUSY;
		goto out;
	}

	if (xnthread_test_info(thread, XNDORMANT))
		goto out;

	trace_steely_thread_join(thread);

	xnthread_set_state(thread, XNJOINED);
	tpid = xnthread_host_pid(thread);
	
	if (curr && !xnthread_test_state(curr, XNRELAX)) {
		xnlock_put_irqrestore(&nklock, s);
		xnthread_relax(0, 0);
		switched = 1;
	} else
		xnlock_put_irqrestore(&nklock, s);

	/*
	 * Since in theory, we might be sleeping there for a long
	 * time, we get a reference on the pid struct holding our
	 * target, then we check for its existence upon wake up.
	 */
	pid = find_get_pid(tpid);
	if (pid == NULL)
		goto done;

	/*
	 * We have a tricky issue to deal with, which involves code
	 * relying on the assumption that a destroyed thread will have
	 * scheduled away from do_exit() before xnthread_join()
	 * returns. A typical example is illustrated by the following
	 * sequence, with a RTDM kernel task implemented in a
	 * dynamically loaded module:
	 *
	 * CPU0:  rtdm_task_destroy(ktask)
	 *           xnthread_cancel(ktask)
	 *           xnthread_join(ktask)
	 *        ...<back to user>..
	 *        rmmod(module)
	 *
	 * CPU1:  in ktask()
	 *        ...
	 *        ...
	 *          __xnthread_test_cancel()
	 *             do_exit()
         *                schedule()
	 *
	 * In such a sequence, the code on CPU0 would expect the RTDM
	 * task to have scheduled away upon return from
	 * rtdm_task_destroy(), so that unmapping the destroyed task
	 * code and data memory when unloading the module is always
	 * safe.
	 *
	 * To address this, the joiner first waits for the joinee to
	 * signal completion from the Steely thread cleanup handler
	 * (__xnthread_cleanup), then waits for a full RCU grace
	 * period to have elapsed. Since the completion signal is sent
	 * on behalf of do_exit(), we may assume that the joinee has
	 * scheduled away before the RCU grace period ends.
	 */
	if (uninterruptible)
		wait_for_completion(&thread->exited);
	else {
		ret = wait_for_completion_interruptible(&thread->exited);
		if (ret < 0) {
			put_pid(pid);
			return -EINTR;
		}
	}

	/* Make sure the joinee has scheduled away ultimately. */
	wait_for_rcu_grace_period(pid);

	put_pid(pid);
done:
	ret = 0;
	if (switched)
		ret = xnthread_harden();

	return ret;
out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_join);

#ifdef CONFIG_SMP

int xnthread_migrate(int cpu)
{
	struct xnthread *curr;
	struct xnsched *sched;
	int ret = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	curr = xnthread_current();
	if (!xnsched_primary_p() || curr->lock_count > 0) {
		ret = -EPERM;
		goto unlock_and_exit;
	}

	if (!cpumask_test_cpu(cpu, &curr->affinity)) {
		ret = -EINVAL;
		goto unlock_and_exit;
	}

	sched = xnsched_struct(cpu);
	if (sched == curr->sched)
		goto unlock_and_exit;

	trace_steely_thread_migrate(curr, cpu);

	/* Move to remote scheduler. */
	xnsched_migrate(curr, sched);

	/*
	 * Migrate the thread's periodic timer. We don't have to care
	 * about the resource timer, since we can only deal with the
	 * current thread, which is, well, running, so it can't be
	 * sleeping on any timed wait at the moment.
	 */
	__xntimer_migrate(&curr->ptimer, sched);

	/*
	 * Reset execution time measurement period so that we don't
	 * mess up per-CPU statistics.
	 */
	xnstat_exectime_reset_stats(&curr->stat.lastperiod);

	/*
	 * So that xnthread_relax() will pin the linux mate on the
	 * same CPU next time the thread switches to secondary mode.
	 */
	xnthread_set_localinfo(curr, XNMOVED);

	xnsched_run();

 unlock_and_exit:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_migrate);

void xnthread_migrate_passive(struct xnthread *thread, struct xnsched *sched)
{				/* nklocked, IRQs off */
	if (thread->sched == sched)
		return;

	trace_steely_thread_migrate_passive(thread, xnsched_cpu(sched));
	/*
	 * Timer migration is postponed until the next timeout happens
	 * for the periodic and rrb timers. The resource timer will be
	 * moved to the right CPU next time it is armed in
	 * xnthread_suspend().
	 */
	xnsched_migrate_passive(thread, sched);

	xnstat_exectime_reset_stats(&thread->stat.lastperiod);
}

#endif	/* CONFIG_SMP */

int xnthread_set_schedparam(struct xnthread *thread,
			    struct xnsched_class *sched_class,
			    const union xnsched_policy_param *sched_param)
{
	spl_t s;
	int ret;

	xnlock_get_irqsave(&nklock, s);
	ret = __xnthread_set_schedparam(thread, sched_class, sched_param);
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_set_schedparam);

int __xnthread_set_schedparam(struct xnthread *thread,
			      struct xnsched_class *sched_class,
			      const union xnsched_policy_param *sched_param)
{
	int old_wprio, new_wprio, ret;

	old_wprio = thread->wprio;

	ret = xnsched_set_policy(thread, sched_class, sched_param);
	if (ret)
		return ret;

	new_wprio = thread->wprio;

	/*
	 * If the thread is waiting on a synchronization object,
	 * update its position in the corresponding wait queue, unless
	 * 1) reordering is explicitly disabled, or 2) the (weighted)
	 * priority has not changed (to prevent spurious round-robin
	 * effects).
	 */
	if (old_wprio != new_wprio && thread->wchan &&
	    (thread->wchan->status & (XNSYNCH_DREORD|XNSYNCH_PRIO))
	    == XNSYNCH_PRIO)
		xnsynch_requeue_sleeper(thread);
	/*
	 * We should not move the thread at the end of its priority
	 * group, if any of these conditions is true:
	 *
	 * - thread is not runnable;
	 * - thread bears the ready bit which means that xnsched_set_policy()
	 * already reordered the run queue;
	 * - thread currently holds the scheduler lock, so we don't want
	 * any round-robin effect to take place;
	 * - a priority boost is undergoing for this thread.
	 */
	if (!xnthread_test_state(thread, XNTHREAD_BLOCK_BITS|XNREADY|XNBOOST) &&
	    thread->lock_count == 0)
		xnsched_putback(thread);

	xnthread_set_info(thread, XNSCHEDP);
	/* Ask the target thread to call back if relaxed. */
	if (xnthread_test_state(thread, XNRELAX))
		xnthread_signal(thread, SIGSHADOW, SIGSHADOW_ACTION_HOME);
	
	return ret;
}

void __xnthread_test_cancel(struct xnthread *curr)
{
	/*
	 * Just in case xnthread_test_cancel() is called from an IRQ
	 * handler, in which case we may not take the exit path.
	 *
	 * NOTE: curr->sched is stable from our POV and can't change
	 * under our feet.
	 */
	if (curr->sched->lflags & XNINIRQ)
		return;

	if (!xnthread_test_state(curr, XNRELAX))
		xnthread_relax(0, 0);

	do_exit(0);
	/* ... won't return ... */
	STEELY_BUG(STEELY);
}
EXPORT_SYMBOL_GPL(__xnthread_test_cancel);

int xnthread_harden(void)
{
	struct task_struct *p = current;
	struct xnthread *thread;
	struct xnsched *sched;
	int ret;

	secondary_mode_only();

	thread = xnthread_current();
	if (thread == NULL)
		return -EPERM;

	if (signal_pending(p))
		return -ERESTARTSYS;

	trace_steely_shadow_gohard(thread);

	xnthread_clear_sync_window(thread, XNRELAX);

	ret = dovetail_enter_head();
	if (ret) {
		xnthread_set_sync_window(thread, XNRELAX);
		return ret;
	}

	/* "current" is now running into the Steely domain. */
	STEELY_BUG_ON(STEELY, !hard_irqs_disabled());
	sched = xnsched_current();

	xnlock_clear_irqon(&nklock);
	xnthread_test_cancel();

	trace_steely_shadow_hardened(thread);

	/*
	 * Recheck pending signals once again. As we block task
	 * wakeups during the migration and handle_sigwake_event()
	 * ignores signals until XNRELAX is cleared, any signal
	 * between setting __TASK_OFFSTAGE and starting the migration
	 * is just silently queued up to here.
	 */
	if (signal_pending(p)) {
		xnthread_relax(!xnthread_test_state(thread, XNSSTEP),
			       SIGDEBUG_MIGRATE_SIGNAL);
		return -ERESTARTSYS;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xnthread_harden);

struct lostage_wakeup {
	struct task_struct *task;
	struct irq_work work;
};

static void lostage_task_wakeup(struct irq_work *work)
{
	struct lostage_wakeup *rq;

	rq = container_of(work, struct lostage_wakeup, work);
	trace_steely_lostage_wakeup(rq->task);
	wake_up_process(rq->task);
	steely_free_irq_work(rq);
}

static void post_wakeup(struct task_struct *p)
{
	struct lostage_wakeup *rq;

	rq = steely_alloc_irq_work(sizeof(*rq));
	init_irq_work(&rq->work, lostage_task_wakeup);
	rq->task = p;
	trace_steely_lostage_request("wakeup", p);
	irq_work_queue(&rq->work);
}

void __xnthread_propagate_schedparam(struct xnthread *curr)
{
	int kpolicy = SCHED_FIFO, kprio = curr->bprio, ret;
	struct task_struct *p = current;
	struct sched_param param;
	spl_t s;

	/*
	 * Test-set race for XNSCHEDP is ok, the propagation is meant
	 * to be done asap but not guaranteed to be carried out
	 * immediately, and the request will remain pending until it
	 * is eventually handled. We just have to protect against a
	 * set-clear race.
	 */
	xnlock_get_irqsave(&nklock, s);
	xnthread_clear_info(curr, XNSCHEDP);
	xnlock_put_irqrestore(&nklock, s);

	/*
	 * Map our policies/priorities to the regular kernel's
	 * (approximated).
	 */
	if (xnthread_test_state(curr, XNWEAK) && kprio == 0)
		kpolicy = SCHED_NORMAL;
	else if (kprio >= MAX_USER_RT_PRIO)
		kprio = MAX_USER_RT_PRIO - 1;

	if (p->policy != kpolicy || (kprio > 0 && p->rt_priority != kprio)) {
		param.sched_priority = kprio;
		ret = sched_setscheduler_nocheck(p, kpolicy, &param);
		STEELY_WARN_ON(STEELY, ret != 0);
	}
}

void xnthread_relax(int notify, int reason)
{
	struct xnthread *thread = xnthread_current();
	struct task_struct *p = current;
	int cpu __maybe_unused;
	siginfo_t si;

	primary_mode_only();

	/*
	 * Enqueue the request to move the running shadow from the Steely
	 * domain to the Linux domain.  This will cause the Linux task
	 * to resume using the register state of the shadow thread.
	 */
	trace_steely_shadow_gorelax(thread, reason);

	/*
	 * If you intend to change the following interrupt-free
	 * sequence, /first/ make sure to check the special handling
	 * of XNRELAX in xnthread_suspend() when switching out the
	 * current thread, not to break basic assumptions we make
	 * there.
	 *
	 * We disable interrupts during the migration sequence, but
	 * xnthread_suspend() has an interrupts-on section built in.
	 */
	splmax();
	post_wakeup(p);
	/*
	 * Grab the nklock to synchronize the Linux task state
	 * manipulation with handle_sigwake_event. This lock will be
	 * dropped by xnthread_suspend().
	 */
	xnlock_get(&nklock);
	/*
	 * Logically speaking, we are back to the root stage now,
	 * about to wait for the host kernel to handle the wakeup
	 * call. Clear the off-stage flag and suspend Steely-wise,
	 * atomically.
	 */
	set_current_state(p->state & ~__TASK_OFFSTAGE);
	xnthread_run_handler_stack(thread, relax_thread);
	xnthread_suspend(thread, XNRELAX, XN_INFINITE, XN_RELATIVE, NULL);
	splnone();

	/*
	 * Basic sanity check after an expected transition to secondary
	 * mode.
	 */
	STEELY_WARN(STEELY, !on_root_stage(),
		  "xnthread_relax() failed for thread %s[%d]",
		  thread->name, xnthread_host_pid(thread));

	dovetail_leave_head();

	/* Account for secondary mode switch. */
	xnstat_counter_inc(&thread->stat.ssw);

	/*
	 * When relaxing, we check for propagating to the regular
	 * kernel new Steely schedparams that might have been set for
	 * us while we were running in primary mode.
	 *
	 * CAUTION: This obviously won't update the schedparams cached
	 * by the glibc for the caller in user-space, but this is the
	 * deal: we don't relax threads which issue
	 * pthread_setschedparam[_ex]() from primary mode, but then
	 * only the kernel side (Steely and the host kernel) will be
	 * aware of the change, and glibc might cache obsolete
	 * information.
	 */
	xnthread_propagate_schedparam(thread);
	
	if (xnthread_test_state(thread, XNUSER) && notify) {
		xndebug_notify_relax(thread, reason);
		if (xnthread_test_state(thread, XNWARN)) {
			/* Help debugging spurious relaxes. */
			memset(&si, 0, sizeof(si));
			si.si_signo = SIGDEBUG;
			si.si_code = SI_QUEUE;
			si.si_int = reason | sigdebug_marker;
			send_sig_info(SIGDEBUG, &si, p);
		}
		xnsynch_detect_boosted_relax(thread);
	}

	/*
	 * "current" is now running into the Linux domain on behalf of
	 * the root thread.
	 */
	xnthread_sync_window(thread);

#ifdef CONFIG_SMP
	if (xnthread_test_localinfo(thread, XNMOVED)) {
		xnthread_clear_localinfo(thread, XNMOVED);
		cpu = xnsched_cpu(thread->sched);
		set_cpus_allowed_ptr(p, cpumask_of(cpu));
	}
#endif

	trace_steely_shadow_relaxed(thread);
}
EXPORT_SYMBOL_GPL(xnthread_relax);

struct lostage_signal {
	struct task_struct *task;
	int signo, sigval;
	struct irq_work work;
};

static inline void do_kthread_signal(struct task_struct *p,
				     struct xnthread *thread,
				     struct lostage_signal *rq)
{
	printk(STEELY_WARNING
	       "kernel shadow %s received unhandled signal %d (action=0x%x)\n",
	       thread->name, rq->signo, rq->sigval);
}

static void lostage_task_signal(struct irq_work *work)
{
	struct lostage_signal *rq;
	struct xnthread *thread;
	struct task_struct *p;
	siginfo_t si;
	int signo;

	rq = container_of(work, struct lostage_signal, work);
	p = rq->task;
	thread = xnthread_from_task(p);
	if (thread && !xnthread_test_state(thread, XNUSER))
		do_kthread_signal(p, thread, rq);
	else {
		signo = rq->signo;
		trace_steely_lostage_signal(p, signo);
		if (signo == SIGSHADOW || signo == SIGDEBUG) {
			memset(&si, '\0', sizeof(si));
			si.si_signo = signo;
			si.si_code = SI_QUEUE;
			si.si_int = rq->sigval;
			send_sig_info(signo, &si, p);
		} else
			send_sig(signo, p, 1);
	}

	steely_free_irq_work(rq);
}

static int force_wakeup(struct xnthread *thread) /* nklock locked, irqs off */
{
	int ret = 0;

	if (xnthread_test_info(thread, XNKICKED))
		return 1;

	if (xnthread_unblock(thread)) {
		xnthread_set_info(thread, XNKICKED);
		ret = 1;
	}

	/*
	 * CAUTION: we must NOT raise XNBREAK when clearing a forcible
	 * block state, such as XNSUSP, XNHELD. The caller of
	 * xnthread_suspend() we unblock shall proceed as for a normal
	 * return, until it traverses a cancellation point if
	 * XNCANCELD was raised earlier, or calls xnthread_suspend()
	 * which will detect XNKICKED and act accordingly.
	 *
	 * Rationale: callers of xnthread_suspend() may assume that
	 * receiving XNBREAK means that the process that motivated the
	 * blocking did not go to completion. E.g. the wait context
	 * (see. xnthread_prepare_wait()) was NOT posted before
	 * xnsynch_sleep_on() returned, leaving no useful data there.
	 * Therefore, in case only XNSUSP remains set for the thread
	 * on entry to force_wakeup(), after XNPEND was lifted earlier
	 * when the wait went to successful completion (i.e. no
	 * timeout), then we want the kicked thread to know that it
	 * did receive the requested resource, not finding XNBREAK in
	 * its state word.
	 *
	 * Callers of xnthread_suspend() may inquire for XNKICKED to
	 * detect forcible unblocks from XNSUSP, XNHELD, if they
	 * should act upon this case specifically.
	 */
	if (xnthread_test_state(thread, XNSUSP|XNHELD)) {
		xnthread_resume(thread, XNSUSP|XNHELD);
		xnthread_set_info(thread, XNKICKED);
	}

	/*
	 * Tricky cases:
	 *
	 * - a thread which was ready on entry wasn't actually
	 * running, but nevertheless waits for the CPU in primary
	 * mode, so we have to make sure that it will be notified of
	 * the pending break condition as soon as it enters
	 * xnthread_suspend() from a blocking Steely syscall.
	 *
	 * - a ready/readied thread on exit may be prevented from
	 * running by the scheduling policy module it belongs
	 * to. Typically, policies enforcing a runtime budget do not
	 * block threads with no budget, but rather keep them out of
	 * their run queue, so that ->sched_pick() won't elect
	 * them. We tell the policy handler about the fact that we do
	 * want such thread to run until it relaxes, whatever this
	 * means internally for the implementation.
	 */
	if (xnthread_test_state(thread, XNREADY))
		xnsched_kick(thread);

	return ret;
}

void __xnthread_kick(struct xnthread *thread) /* nklock locked, irqs off */
{
	struct task_struct *p = xnthread_host_task(thread);

	/* Thread is already relaxed -- nop. */
	if (xnthread_test_state(thread, XNRELAX))
		return;

	/*
	 * First, try to kick the thread out of any blocking syscall
	 * Steely-wise. If that succeeds, then the thread will relax
	 * on its return path to user-space.
	 */
	if (force_wakeup(thread))
		return;

	/*
	 * If that did not work out because the thread was not blocked
	 * (i.e. XNPEND/XNDELAY) in a syscall, then force a mayday
	 * trap. Note that we don't want to send that thread any linux
	 * signal, we only want to force it to switch to secondary
	 * mode asap.
	 *
	 * It could happen that a thread is relaxed on a syscall
	 * return path after it was resumed from self-suspension
	 * (e.g. XNSUSP) then also forced to run a mayday trap right
	 * after: this is still correct, at worst we would get a
	 * useless mayday syscall leading to a no-op, no big deal.
	 */
	xnthread_set_info(thread, XNKICKED);

	/*
	 * We may send mayday signals to userland threads only.
	 * However, no need to run a mayday trap if the current thread
	 * kicks itself out of primary mode: it will relax on its way
	 * back to userland via the current syscall
	 * epilogue. Otherwise, we want that thread to enter the
	 * mayday trap asap, to call us back for relaxing.
	 */
	if (thread != xnsched_current_thread() &&
	    xnthread_test_state(thread, XNUSER))
		dovetail_send_mayday(p);
}

void xnthread_kick(struct xnthread *thread)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	__xnthread_kick(thread);
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnthread_kick);

void __xnthread_demote(struct xnthread *thread) /* nklock locked, irqs off */
{
	struct xnsched_class *sched_class;
	union xnsched_policy_param param;

	/*
	 * First we kick the thread out of primary mode, and have it
	 * resume execution immediately over the regular linux
	 * context.
	 */
	__xnthread_kick(thread);

	/*
	 * Then we demote it, turning that thread into a non real-time
	 * Steely shadow, which still has access to Steely
	 * resources, but won't compete for real-time scheduling
	 * anymore. In effect, moving the thread to a weak scheduling
	 * class/priority will prevent it from sticking back to
	 * primary mode.
	 */
#ifdef CONFIG_STEELY_SCHED_WEAK
	param.weak.prio = 0;
	sched_class = &xnsched_class_weak;
#else
	param.rt.prio = 0;
	sched_class = &xnsched_class_rt;
#endif
	__xnthread_set_schedparam(thread, sched_class, &param);
}

void xnthread_demote(struct xnthread *thread)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	__xnthread_demote(thread);
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnthread_demote);

void xnthread_signal(struct xnthread *thread, int sig, int arg)
{
	struct lostage_signal *rq;

	rq = steely_alloc_irq_work(sizeof(*rq));
	init_irq_work(&rq->work, lostage_task_signal);
	rq->task = xnthread_host_task(thread);
	rq->signo = sig;
	rq->sigval = sig == SIGDEBUG ? arg | sigdebug_marker : arg;
	trace_steely_lostage_request("signal", rq->task);
	irq_work_queue(&rq->work);
}
EXPORT_SYMBOL_GPL(xnthread_signal);

void xnthread_pin_initial(struct xnthread *thread)
{
	struct task_struct *p = current;
	struct xnsched *sched;
	int cpu;
	spl_t s;

	/*
	 * @thread is the Steely extension of the current kernel
	 * task. If the current CPU is part of the affinity mask of
	 * this thread, pin the latter on this CPU. Otherwise pin it
	 * to the first CPU of that mask.
	 */
	cpu = task_cpu(p);
	if (!cpumask_test_cpu(cpu, &thread->affinity))
		cpu = cpumask_first(&thread->affinity);

	set_cpus_allowed_ptr(p, cpumask_of(cpu));
	/*
	 * @thread is still unstarted Steely-wise, we are precisely
	 * in the process of mapping the current kernel task to
	 * it. Therefore xnthread_migrate_passive() is the right way
	 * to pin it on a real-time CPU.
	 */
	xnlock_get_irqsave(&nklock, s);
	sched = xnsched_struct(cpu);
	xnthread_migrate_passive(thread, sched);
	xnlock_put_irqrestore(&nklock, s);
}

struct parent_wakeup_request {
	struct completion *done;
	struct irq_work work;
};

static void do_parent_wakeup(struct irq_work *work)
{
	struct parent_wakeup_request *rq;

	rq = container_of(work, struct parent_wakeup_request, work);
	complete(rq->done);
	steely_free_irq_work(rq);
}

static inline void wakeup_parent(struct completion *done)
{
	struct parent_wakeup_request *rq;

	rq = steely_alloc_irq_work(sizeof(*rq));
	init_irq_work(&rq->work, do_parent_wakeup);
	rq->done = done;
	trace_steely_lostage_request("wakeup", current);
	irq_work_queue(&rq->work);
}

static inline void init_kthread_info(struct xnthread *thread)
{
	struct dovetail_state *p;

	p = dovetail_current_state();
	p->thread = thread;
	p->process = NULL;
}

int xnthread_map(struct xnthread *thread, struct completion *done)
{
	int ret;
	spl_t s;

	if (xnthread_test_state(thread, XNUSER))
		return -EINVAL;

	if (xnthread_current() || xnthread_test_state(thread, XNMAPPED))
		return -EBUSY;

	thread->u_window = NULL;
	xnthread_pin_initial(thread);

	trace_steely_shadow_map(thread);

	xnthread_init_shadow_tcb(thread);
	xnthread_suspend(thread, XNRELAX, XN_INFINITE, XN_RELATIVE, NULL);
	init_kthread_info(thread);
	xnthread_set_state(thread, XNMAPPED);
	xndebug_shadow_init(thread);
	xnthread_run_handler(thread, map_thread);
	/* Enable dovetailing in the host kernel. */
	dovetail_enable(0);

	/*
	 * CAUTION: Soon after xnthread_init() has returned,
	 * xnthread_start() is commonly invoked from the root domain,
	 * therefore the call site may expect the started kernel
	 * shadow to preempt immediately. As a result of such
	 * assumption, start attributes (struct xnthread_start_attr)
	 * are often laid on the caller's stack.
	 *
	 * For this reason, we raise the completion signal to wake up
	 * the xnthread_init() caller only once the emerging thread is
	 * hardened, and __never__ before that point. Since we run
	 * over the Steely domain upon return from xnthread_harden(),
	 * we schedule a synthetic interrupt handler in the root
	 * domain to signal the completion object.
	 */
	xnthread_resume(thread, XNDORMANT);
	ret = xnthread_harden();
	wakeup_parent(done);

	xnlock_get_irqsave(&nklock, s);

	enlist_new_thread(thread);
	/*
	 * Make sure xnthread_start() did not slip in from another CPU
	 * while we were back from wakeup_parent().
	 */
	if (thread->entry == NULL)
		xnthread_suspend(thread, XNDORMANT,
				 XN_INFINITE, XN_RELATIVE, NULL);

	xnlock_put_irqrestore(&nklock, s);

	xnthread_test_cancel();

	xntrace_pid(xnthread_host_pid(thread),
		    xnthread_current_priority(thread));

	return ret;
}
EXPORT_SYMBOL_GPL(xnthread_map);

/* nklock locked, irqs off */
void xnthread_call_mayday(struct xnthread *thread, int reason)
{
	struct task_struct *p = xnthread_host_task(thread);

	/* Mayday traps are available to userland threads only. */
	STEELY_BUG_ON(STEELY, !xnthread_test_state(thread, XNUSER));
	xnthread_set_info(thread, XNKICKED);
	xnthread_signal(thread, SIGDEBUG, reason);
	dovetail_send_mayday(p);
}
EXPORT_SYMBOL_GPL(xnthread_call_mayday);

int xnthread_killall(int grace, int mask)
{
	struct xnthread *t, *curr = xnthread_current();
	int nrkilled = 0, nrthreads, count;
	long ret;
	spl_t s;

	secondary_mode_only();

	/*
	 * We may hold the core lock across calls to xnthread_cancel()
	 * provided that we won't self-cancel.
	 */
	xnlock_get_irqsave(&nklock, s);

	nrthreads = steely_nrthreads;
	
	xnsched_for_each_thread(t) {
		if (xnthread_test_state(t, XNROOT) ||
		    xnthread_test_state(t, mask) != mask ||
		    t == curr)
			continue;

		if (STEELY_DEBUG(STEELY))
			printk(STEELY_INFO "terminating %s[%d]\n",
			       t->name, xnthread_host_pid(t));
		nrkilled++;
		xnthread_cancel(t);
	}

	xnlock_put_irqrestore(&nklock, s);

	/*
	 * Cancel then join all existing threads during the grace
	 * period. It is the caller's responsibility to prevent more
	 * threads to bind to the system if required, we won't make
	 * any provision for this here.
	 */
	count = nrthreads - nrkilled;
	if (STEELY_DEBUG(STEELY))
		printk(STEELY_INFO "waiting for %d threads to exit\n",
		       nrkilled);

	if (grace > 0) {
		ret = wait_event_interruptible_timeout(join_all,
						       steely_nrthreads == count,
						       grace * HZ);
		if (ret == 0)
			return -EAGAIN;
	} else
		ret = wait_event_interruptible(join_all,
					       steely_nrthreads == count);

	/* Wait for a full RCU grace period to expire. */
	wait_for_rcu_grace_period(NULL);

	if (STEELY_DEBUG(STEELY))
		printk(STEELY_INFO "joined %d threads\n",
		       count + nrkilled - steely_nrthreads);

	return ret < 0 ? EINTR : 0;
}
EXPORT_SYMBOL_GPL(xnthread_killall);
		     
/* Steely's generic personality. */
struct xnthread_personality steely_personality = {
	.name = "core",
	.magic = -1
};
EXPORT_SYMBOL_GPL(steely_personality);
