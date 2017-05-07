/*
 * Copyright (C) 2013 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/sched.h>
#include <steely/assert.h>
#include "internal.h"
#include "signal.h"
#include "thread.h"
#include "timer.h"
#include "clock.h"

static void *sigpending_mem;

static LIST_HEAD(sigpending_pool);

/*
 * How many signal notifications which may be pending at any given
 * time, except timers.  Steely signals are always thread directed,
 * and we assume that in practice, each signal number is processed by
 * a dedicated thread. We provide for up to three real-time signal
 * events to pile up, and a single notification pending for other
 * signals. Timers use a fast queuing logic maintaining a count of
 * overruns, and therefore do not consume any memory from this pool.
 */
#define __SIGPOOL_SIZE  (sizeof(struct steely_sigpending) *	\
			 (_NSIG + (SIGRTMAX - SIGRTMIN) * 2))

static int steely_signal_deliver(struct steely_thread *thread,
				 struct steely_sigpending *sigp,
				 int group)
{				/* nklocked, IRQs off */
	struct steely_sigwait_context *swc;
	struct steely_wait_context *wc;
	int sig, ret;

	sig = sigp->si.si_signo;
	STEELY_BUG_ON(STEELY, sig < 1 || sig > _NSIG);

	/*
	 * Attempt to deliver the signal immediately to the initial
	 * target that waits for it.
	 */
	if (xnsynch_pended_p(&thread->sigwait)) {
		wc = xnthread_get_wait_context(thread);
		swc = container_of(wc, struct steely_sigwait_context, wc);
		if (sigismember(swc->set, sig))
			goto deliver;
	}

	/*
	 * If that does not work out and we are sending to a thread
	 * group, try to deliver to any thread from the same process
	 * waiting for that signal.
	 */
	if (!group || list_empty(&thread->process->sigwaiters))
		return 0;

	list_for_each_entry(thread, &thread->process->sigwaiters, signext) {
		wc = xnthread_get_wait_context(thread);
		swc = container_of(wc, struct steely_sigwait_context, wc);
		if (sigismember(swc->set, sig))
			goto deliver;
	}

	return 0;
deliver:
	steely_copy_siginfo(sigp->si.si_code, swc->si, &sigp->si);
	steely_call_extension(signal_deliver, &thread->extref,
			      ret, swc->si, sigp);
	xnthread_complete_wait(&swc->wc);
	xnsynch_wakeup_one_sleeper(&thread->sigwait);
	list_del(&thread->signext);

	/*
	 * This is an immediate delivery bypassing any queuing, so we
	 * have to release the sigpending data right away before
	 * leaving.
	 */
	steely_signal_free(sigp);

	return 1;
}

int steely_signal_send(struct steely_thread *thread,
		       struct steely_sigpending *sigp,
		       int group)
{				/* nklocked, IRQs off */
	struct list_head *sigq;
	int sig, ret;

	/* Can we deliver this signal immediately? */
	ret = steely_signal_deliver(thread, sigp, group);
	if (ret)
		return ret;	/* Yep, done. */

	/*
	 * Nope, attempt to queue it. We start by calling any Steely
	 * extension for queuing the signal first.
	 */
	if (steely_call_extension(signal_queue, &thread->extref, ret, sigp)) {
		if (ret)
			/* Queuing done remotely or error. */
			return ret;
	}

	sig = sigp->si.si_signo;
	sigq = thread->sigqueues + sig - 1;
	if (!list_empty(sigq)) {
		/* Queue non-rt signals only once. */
		if (sig < SIGRTMIN)
			return 0;
		/* Queue rt signal source only once (SI_TIMER). */
		if (!list_empty(&sigp->next))
			return 0;
	}

	sigaddset(&thread->sigpending, sig);
	list_add_tail(&sigp->next, sigq);

	return 1;
}
EXPORT_SYMBOL_GPL(steely_signal_send);

int steely_signal_send_pid(pid_t pid, struct steely_sigpending *sigp)
{				/* nklocked, IRQs off */
	struct steely_thread *thread;

	thread = steely_thread_find(pid);
	if (thread)
		return steely_signal_send(thread, sigp, 0);

	return -ESRCH;
}
EXPORT_SYMBOL_GPL(steely_signal_send_pid);

struct steely_sigpending *steely_signal_alloc(void)
{				/* nklocked, IRQs off */
	struct steely_sigpending *sigp;

	if (list_empty(&sigpending_pool)) {
		if (printk_ratelimit())
			printk(STEELY_WARNING "signal bucket pool underflows\n");
		return NULL;
	}

	sigp = list_get_entry(&sigpending_pool, struct steely_sigpending, next);
	INIT_LIST_HEAD(&sigp->next);

	return sigp;
}
EXPORT_SYMBOL_GPL(steely_signal_alloc);

void steely_signal_free(struct steely_sigpending *sigp)
{				/* nklocked, IRQs off */
	if ((void *)sigp >= sigpending_mem &&
	    (void *)sigp < sigpending_mem + __SIGPOOL_SIZE)
		list_add_tail(&sigp->next, &sigpending_pool);
}
EXPORT_SYMBOL_GPL(steely_signal_free);

void steely_signal_flush(struct steely_thread *thread)
{
	struct steely_sigpending *sigp, *tmp;
	struct list_head *sigq;
	int n;

	/*
	 * TCB is not accessible from userland anymore, no locking
	 * required.
	 */
	if (sigisemptyset(&thread->sigpending))
		return;

	for (n = 0; n < _NSIG; n++) {
		sigq = thread->sigqueues + n;
		if (list_empty(sigq))
			continue;
		/*
		 * sigpending blocks must be unlinked so that we
		 * detect this fact when deleting their respective
		 * owners.
		 */
		list_for_each_entry_safe(sigp, tmp, sigq, next)
			list_del_init(&sigp->next);
	}

	sigemptyset(&thread->sigpending);
}

static int signal_wait(sigset_t *set, ktime_t timeout,
		       void __user *u_si,
		       int (*put_siginfo)(void __user *u_si,
					  const struct siginfo *si,
					  int overrun))
{
	struct steely_sigpending *sigp = NULL;
	struct steely_sigwait_context swc;
	struct steely_thread *curr;
	int ret, sig, n, overrun;
	unsigned long *p, *t, m;
	struct siginfo si, *sip;
	struct list_head *sigq;
	spl_t s;

	curr = steely_current_thread();
	STEELY_BUG_ON(STEELY, curr == NULL);

	if (u_si && !access_wok(u_si, sizeof(*u_si)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

check:
	if (sigisemptyset(&curr->sigpending))
		/* Most common/fast path. */
		goto wait;

	p = curr->sigpending.sig; /* pending */
	t = set->sig;		  /* tested */

	for (n = 0, sig = 0; n < _NSIG_WORDS; ++n) {
		m = *p++ & *t++;
		if (m == 0)
			continue;
		sig = ffz(~m) +  n *_NSIG_BPW + 1;
		break;
	}

	if (sig) {
		sigq = curr->sigqueues + sig - 1;
		if (list_empty(sigq)) {
			sigdelset(&curr->sigpending, sig);
			goto check;
		}
		sigp = list_get_entry(sigq, struct steely_sigpending, next);
		INIT_LIST_HEAD(&sigp->next); /* Mark sigp as unlinked. */
		if (list_empty(sigq))
			sigdelset(&curr->sigpending, sig);
		sip = &sigp->si;
		ret = 0;
		goto done;
	}

wait:
	if (timeout_nonblock(timeout)) {
		ret = -EAGAIN;
		goto fail;
	}
	swc.set = set;
	swc.si = &si;
	xnthread_prepare_wait(&swc.wc);
	list_add_tail(&curr->signext, &curr->process->sigwaiters);
	ret = xnsynch_sleep_on(&curr->sigwait, timeout, XN_RELATIVE);
	if (ret) {
		list_del(&curr->signext);
		ret = ret & XNBREAK ? -EINTR : -EAGAIN;
		goto fail;
	}
	sig = si.si_signo;
	sip = &si;
done:
	 /*
	  * si_overrun raises a nasty issue since we have to
	  * collect+clear it atomically before we drop the lock,
	  * although we don't know in advance if any extension would
	  * use it along with the additional si_codes it may provide,
	  * but we must drop the lock before running the
	  * signal_copyinfo handler.
	  *
	  * Observing that si_overrun is likely the only "unstable"
	  * data from the signal information which might change under
	  * our feet while we copy the bits to userland, we collect it
	  * here from the atomic section for all unknown si_codes,
	  * then pass its value to the signal_copyinfo handler.
	  */
	switch (sip->si_code) {
	case SI_TIMER:
		overrun = steely_timer_deliver(sip->si_tid);
		break;
	case SI_USER:
	case SI_MESGQ:
	case SI_QUEUE:
		overrun = 0;
		break;
	default:
		overrun = sip->si_overrun;
		if (overrun)
			sip->si_overrun = 0;
	}

	xnlock_put_irqrestore(&nklock, s);

	if (u_si == NULL)
		goto out;	/* Return signo only. */

	ret = put_siginfo(u_si, sip, overrun);
	if (ret)
		goto out;

	/* Allow an extended target to receive more data. */
	steely_call_extension(signal_copyinfo, &curr->extref,
			      ret, u_si, sip, overrun);
out:
	/*
	 * If we pulled the signal information from a sigpending
	 * block, release it to the free pool if applicable.
	 */
	if (sigp &&
	    (void *)sigp >= sigpending_mem &&
	    (void *)sigp < sigpending_mem + __SIGPOOL_SIZE) {
		xnlock_get_irqsave(&nklock, s);
		list_add_tail(&sigp->next, &sigpending_pool);
		xnlock_put_irqrestore(&nklock, s);
		/* no more ref. to sigp beyond this point. */
	}

	return ret ?: sig;
fail:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

static int signal_put_siginfo(void __user *u_si, const struct siginfo *si,
			      int overrun)
{
	struct siginfo __user *u_p = u_si;
	int code, ret;

	/* Translate kernel codes for userland. */
	code = si->si_code;
	if (code & __SI_MASK)
		code |= __SI_MASK;

	ret = __xn_put_user(si->si_signo, &u_p->si_signo);
	ret |= __xn_put_user(si->si_errno, &u_p->si_errno);
	ret |= __xn_put_user(code, &u_p->si_code);

	/*
	 * Copy the generic/standard siginfo bits to userland.
	 */
	switch (si->si_code) {
	case SI_TIMER:
		ret |= __xn_put_user(si->si_tid, &u_p->si_tid);
		ret |= __xn_put_user(si->si_ptr, &u_p->si_ptr);
		ret |= __xn_put_user(overrun, &u_p->si_overrun);
		break;
	case SI_QUEUE:
	case SI_MESGQ:
		ret |= __xn_put_user(si->si_ptr, &u_p->si_ptr);
		/* falldown wanted. */
	case SI_USER:
		ret |= __xn_put_user(si->si_pid, &u_p->si_pid);
		ret |= __xn_put_user(si->si_uid, &u_p->si_uid);
	}

	return ret;
}

int __steely_sigwait(sigset_t *set)
{
	return signal_wait(set, XN_INFINITE, NULL, NULL);
}

STEELY_SYSCALL(sigwait, primary,
	       (const sigset_t __user *u_set, int __user *u_sig))
{
	sigset_t set;
	int sig;

	if (steely_copy_from_user(&set, u_set, sizeof(set)))
		return -EFAULT;

	sig = signal_wait(&set, XN_INFINITE, NULL, NULL);
	if (sig < 0)
		return sig;

	return steely_copy_to_user(u_sig, &sig, sizeof(*u_sig));
}

int __steely_sigtimedwait(sigset_t *set,
			  const struct timespec *timeout,
			  void __user *u_si,
			  int (*put_siginfo)(void __user *u_si,
					     const struct siginfo *si,
					     int overrun))
{
	ktime_t ticks;

	if ((unsigned long)timeout->tv_nsec >= ONE_BILLION)
		return -EINVAL;

	ticks = timespec_to_ktime(*timeout);
	if (ktime_to_ns(ticks) == 0)
		ticks = XN_NONBLOCK;
	else
		ticks = ktime_add_ns(ticks, 1);

	return signal_wait(set, ticks, u_si, put_siginfo);
}

STEELY_SYSCALL(sigtimedwait, nonrestartable,
	       (const sigset_t __user *u_set,
		struct siginfo __user *u_si,
		const struct timespec __user *u_timeout))
{
	struct timespec timeout;
	sigset_t set;

	if (steely_copy_from_user(&set, u_set, sizeof(set)))
		return -EFAULT;

	if (steely_copy_from_user(&timeout, u_timeout, sizeof(timeout)))
		return -EFAULT;

	return __steely_sigtimedwait(&set, &timeout, u_si, signal_put_siginfo);
}

int __steely_sigwaitinfo(sigset_t *set,
			 void __user *u_si,
			 int (*put_siginfo)(void __user *u_si,
					    const struct siginfo *si,
					    int overrun))
{
	return signal_wait(set, XN_INFINITE, u_si, put_siginfo);
}

STEELY_SYSCALL(sigwaitinfo, nonrestartable,
	       (const sigset_t __user *u_set, struct siginfo __user *u_si))
{
	sigset_t set;

	if (steely_copy_from_user(&set, u_set, sizeof(set)))
		return -EFAULT;

	return __steely_sigwaitinfo(&set, u_si, signal_put_siginfo);
}

STEELY_SYSCALL(sigpending, primary, (old_sigset_t __user *u_set))
{
	struct steely_thread *curr = steely_current_thread();

	return steely_copy_to_user(u_set, &curr->sigpending, sizeof(*u_set));
}

int __steely_kill(struct steely_thread *thread, int sig, int group) /* nklocked, IRQs off */
{
	struct steely_sigpending *sigp;
	int ret = 0;

	/*
	 * We have undocumented pseudo-signals to suspend/resume/unblock
	 * threads, force them out of primary mode or even demote them
	 * to the weak scheduling class/priority. Process them early,
	 * before anyone can notice...
	 */
	switch(sig) {
	case 0:
		/* Check for existence only. */
		break;
	case SIGSUSP:
		/*
		 * All callers shall be tagged as conforming calls, so
		 * self-directed suspension can only happen from
		 * primary mode. Yummie.
		 */
		xnthread_suspend(thread, XNSUSP,
				 XN_INFINITE, XN_RELATIVE, NULL);
		if (thread == steely_current_thread() &&
		    xnthread_test_info(thread, XNBREAK))
			ret = -EINTR;
		break;
	case SIGRESM:
		xnthread_resume(thread, XNSUSP);
		goto resched;
	case SIGRELS:
		xnthread_unblock(thread);
		goto resched;
	case SIGKICK:
		xnthread_kick(thread);
		goto resched;
	case SIGDEMT:
		xnthread_demote(thread);
		goto resched;
	case 1 ... _NSIG:
		sigp = steely_signal_alloc();
		if (sigp) {
			sigp->si.si_signo = sig;
			sigp->si.si_errno = 0;
			sigp->si.si_code = SI_USER;
			sigp->si.si_pid = task_pid_nr(current);
			sigp->si.si_uid = get_current_uuid();
			if (steely_signal_send(thread, sigp, group) <= 0)
				steely_signal_free(sigp);
		}
	resched:
		xnsched_run();
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

STEELY_SYSCALL(kill, conforming, (pid_t pid, int sig))
{
	struct steely_thread *thread;
	int ret;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	thread = steely_thread_find(pid);
	if (thread == NULL)
		ret = -ESRCH;
	else
		ret = __steely_kill(thread, sig, 1);

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

int __steely_sigqueue(pid_t pid, int sig, const union sigval *value)
{
	struct steely_sigpending *sigp;
	struct steely_thread *thread;
	int ret = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	thread = steely_thread_find(pid);
	if (thread == NULL) {
		ret = -ESRCH;
		goto out;
	}

	switch(sig) {
	case 0:
		/* Check for existence only. */
		break;
	case 1 ... _NSIG:
		sigp = steely_signal_alloc();
		if (sigp) {
			sigp->si.si_signo = sig;
			sigp->si.si_errno = 0;
			sigp->si.si_code = SI_QUEUE;
			sigp->si.si_pid = task_pid_nr(current);
			sigp->si.si_uid = get_current_uuid();
			sigp->si.si_value = *value;
			if (steely_signal_send(thread, sigp, 1) <= 0)
				steely_signal_free(sigp);
			else
				xnsched_run();
		}
		break;
	default:
		/* Steely pseudo-signals are never process-directed. */
		ret = __steely_kill(thread, sig, 0);
	}
out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(__steely_sigqueue);

STEELY_SYSCALL(sigqueue, conforming,
	       (pid_t pid, int sig, const union sigval __user *u_value))
{
	union sigval val;
	int ret;

	ret = steely_copy_from_user(&val, u_value, sizeof(val));

	return ret ?: __steely_sigqueue(pid, sig, &val);
}

__init int steely_signal_init(void)
{
	struct steely_sigpending *sigp;

	sigpending_mem = xnheap_vmalloc(__SIGPOOL_SIZE);
	if (sigpending_mem == NULL)
		return -ENOMEM;

	for (sigp = sigpending_mem;
	     (void *)sigp < sigpending_mem + __SIGPOOL_SIZE; sigp++)
		list_add_tail(&sigp->next, &sigpending_pool);

	return 0;
}
