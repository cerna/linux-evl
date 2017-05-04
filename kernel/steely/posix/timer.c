/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#include <linux/module.h>
#include <linux/cred.h>
#include <linux/err.h>
#include "internal.h"
#include "thread.h"
#include "timer.h"
#include "clock.h"
#include "signal.h"

void steely_timer_handler(struct xntimer *xntimer)
{
	struct steely_timer *timer;
	/*
	 * Deliver the timer notification via a signal (unless
	 * SIGEV_NONE was given). If we can't do this because the
	 * target thread disappeared, then stop the timer. It will go
	 * away when timer_delete() is called, or the owner's process
	 * exits, whichever comes first.
	 */
	timer = container_of(xntimer, struct steely_timer, timerbase);
	if (timer->sigp.si.si_signo &&
	    steely_signal_send_pid(timer->target, &timer->sigp) == -ESRCH)
		xntimer_stop(&timer->timerbase);
}
EXPORT_SYMBOL_GPL(steely_timer_handler);

static inline struct steely_thread *
timer_init(struct steely_timer *timer,
	   const struct sigevent *__restrict__ evp) /* nklocked, IRQs off. */
{
	struct steely_thread *owner = steely_current_thread(), *target = NULL;
	struct xnclock *clock;

	/*
	 * First, try to offload this operation to the extended
	 * personality the current thread might originate from.
	 */
	if (steely_initcall_extension(timer_init, &timer->extref,
				      owner, target, evp) && target)
		return target;

	/*
	 * Ok, we have no extension available, or we do but it does
	 * not want to overload the standard behavior: handle this
	 * timer the pure Steely way then.
	 */
	if (evp == NULL || evp->sigev_notify == SIGEV_NONE) {
		target = owner;	/* Assume SIGEV_THREAD_ID. */
		goto init;
	}

	if (evp->sigev_notify != SIGEV_THREAD_ID)
		return ERR_PTR(-EINVAL);

	/*
	 * Recipient thread must be a Steely shadow in user-space,
	 * living in the same process than our caller.
	 */
	target = steely_thread_find_local(evp->sigev_notify_thread_id);
	if (target == NULL)
		return ERR_PTR(-EINVAL);
init:
	clock = steely_clock_find(timer->clockid);
	if (IS_ERR(clock))
		return ERR_PTR(PTR_ERR(clock));

	xntimer_init(&timer->timerbase, clock, steely_timer_handler,
		     target->threadbase.sched, XNTIMER_UGRAVITY);

	return target;
}

static inline int timer_alloc_id(struct steely_process *cc)
{
	int id;

	id = find_first_bit(cc->timers_map, CONFIG_STEELY_NRTIMERS);
	if (id == CONFIG_STEELY_NRTIMERS)
		return -EAGAIN;

	__clear_bit(id, cc->timers_map);

	return id;
}

static inline void timer_free_id(struct steely_process *cc, int id)
{
	__set_bit(id, cc->timers_map);
}

struct steely_timer *
steely_timer_by_id(struct steely_process *cc, timer_t timer_id)
{
	if (timer_id < 0 || timer_id >= CONFIG_STEELY_NRTIMERS)
		return NULL;

	if (test_bit(timer_id, cc->timers_map))
		return NULL;

	return cc->timers[timer_id];
}

static inline int timer_create(clockid_t clockid,
			       const struct sigevent *__restrict__ evp,
			       timer_t * __restrict__ timerid)
{
	struct steely_process *cc;
	struct steely_thread *target;
	struct steely_timer *timer;
	int signo, ret = -EINVAL;
	timer_t timer_id;
	spl_t s;

	cc = steely_current_process();
	if (cc == NULL)
		return -EPERM;

	timer = xnmalloc(sizeof(*timer));
	if (timer == NULL)
		return -ENOMEM;

	timer->sigp.si.si_errno = 0;
	timer->sigp.si.si_code = SI_TIMER;
	timer->sigp.si.si_overrun = 0;
	INIT_LIST_HEAD(&timer->sigp.next);
	timer->clockid = clockid;
	timer->overruns = 0;

	xnlock_get_irqsave(&nklock, s);

	ret = timer_alloc_id(cc);
	if (ret < 0)
		goto out;

	timer_id = ret;

	if (evp == NULL) {
		timer->sigp.si.si_int = timer_id;
		signo = SIGALRM;
	} else {
		if (evp->sigev_notify == SIGEV_NONE)
			signo = 0; /* Don't notify. */
		else {
			signo = evp->sigev_signo;
			if (signo < 1 || signo > _NSIG) {
				ret = -EINVAL;
				goto fail;
			}
			timer->sigp.si.si_value = evp->sigev_value;
		}
	}

	timer->sigp.si.si_signo = signo;
	timer->sigp.si.si_tid = timer_id;
	timer->id = timer_id;

	target = timer_init(timer, evp);
	if (target == NULL) {
		ret = -EPERM;
		goto fail;
	}

	if (IS_ERR(target)) {
		ret = PTR_ERR(target);
		goto fail;
	}

	timer->target = xnthread_host_pid(&target->threadbase);
	cc->timers[timer_id] = timer;

	xnlock_put_irqrestore(&nklock, s);

	*timerid = timer_id;

	return 0;
fail:
	timer_free_id(cc, timer_id);
out:
	xnlock_put_irqrestore(&nklock, s);

	xnfree(timer);

	return ret;
}

static void timer_cleanup(struct steely_process *p, struct steely_timer *timer)
{
	xntimer_destroy(&timer->timerbase);

	if (!list_empty(&timer->sigp.next))
		list_del(&timer->sigp.next);

	timer_free_id(p, steely_timer_id(timer));
	p->timers[steely_timer_id(timer)] = NULL;
}

static inline int
timer_delete(timer_t timerid)
{
	struct steely_process *cc;
	struct steely_timer *timer;
	int ret = 0;
	spl_t s;

	cc = steely_current_process();
	if (cc == NULL)
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	timer = steely_timer_by_id(cc, timerid);
	if (timer == NULL) {
		xnlock_put_irqrestore(&nklock, s);
		return -EINVAL;
	}
	/*
	 * If an extension runs and actually handles the deletion, we
	 * should not call the timer_cleanup extension handler for
	 * this timer, but we shall destroy the core timer. If the
	 * handler returns on error, the whole deletion process is
	 * aborted, leaving the timer untouched. In all other cases,
	 * we do the core timer cleanup work, firing the timer_cleanup
	 * extension handler if defined.
	 */
  	if (steely_call_extension(timer_delete, &timer->extref, ret) && ret < 0)
		goto out;

	if (ret == 0)
		steely_call_extension(timer_cleanup, &timer->extref, ret);
	else
		ret = 0;

	timer_cleanup(cc, timer);
	xnlock_put_irqrestore(&nklock, s);
	xnfree(timer);

	return ret;

out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

void __steely_timer_getval(struct xntimer *__restrict__ timer,
			   struct itimerspec *__restrict__ value)
{
	value->it_interval = ktime_to_timespec(xntimer_interval(timer));

	if (!xntimer_running_p(timer)) {
		value->it_value.tv_sec = 0;
		value->it_value.tv_nsec = 0;
	} else
		value->it_value =
			ktime_to_timespec(xntimer_get_timeout(timer));
}

static inline void
timer_gettimeout(struct steely_timer *__restrict__ timer,
		 struct itimerspec *__restrict__ value)
{
	int ret = 0;

	if (steely_call_extension(timer_gettime, &timer->extref,
				  ret, value) && ret != 0)
		return;

	__steely_timer_getval(&timer->timerbase, value);
}

int __steely_timer_setval(struct xntimer *__restrict__ timer, int clock_flag,
			  const struct itimerspec *__restrict__ value)
{
	ktime_t start, period;

	if (value->it_value.tv_nsec == 0 && value->it_value.tv_sec == 0) {
		xntimer_stop(timer);
		return 0;
	}

	if ((unsigned long)value->it_value.tv_nsec >= ONE_BILLION ||
	    ((unsigned long)value->it_interval.tv_nsec >= ONE_BILLION &&
	     (value->it_value.tv_sec != 0 || value->it_value.tv_nsec != 0)))
		return -EINVAL;

	start = ktime_add_ns(timespec_to_ktime(value->it_value), 1);
	period = timespec_to_ktime(value->it_interval);

	/*
	 * Now start the timer. If the timeout data has already
	 * passed, the caller will handle the case.
	 */
	return xntimer_start(timer, start, period, clock_flag);
}

static inline int timer_set(struct steely_timer *timer, int flags,
			    const struct itimerspec *__restrict__ value)
{				/* nklocked, IRQs off. */
	struct steely_thread *thread;
	int ret = 0;

	/* First, try offloading the work to an extension. */

	if (steely_call_extension(timer_settime, &timer->extref,
				  ret, value, flags) && ret != 0)
		return ret < 0 ? ret : 0;

	/*
	 * No extension, or operation not handled. Default to plain
	 * POSIX behavior.
	 */

	/*
	 * If the target thread vanished, simply don't start the
	 * timer.
	 */
	thread = steely_thread_find(timer->target);
	if (thread == NULL)
		return 0;

	/*
	 * Make the timer affine to the CPU running the thread to be
	 * signaled.
	 */
	xntimer_set_sched(&timer->timerbase, thread->threadbase.sched);

	return __steely_timer_setval(&timer->timerbase,
				     clock_flag(flags, timer->clockid), value);
}

static inline void
timer_deliver_late(struct steely_process *cc, timer_t timerid)
{
	struct steely_timer *timer;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	/*
	 * We dropped the lock shortly, revalidate the timer handle in
	 * case a deletion slipped in.
	 */
	timer = steely_timer_by_id(cc, timerid);
	if (timer)
		steely_timer_handler(&timer->timerbase);

	xnlock_put_irqrestore(&nklock, s);
}

int __steely_timer_settime(timer_t timerid, int flags,
			   const struct itimerspec *__restrict__ value,
			   struct itimerspec *__restrict__ ovalue)
{
	struct steely_timer *timer;
	struct steely_process *cc;
	int ret;
	spl_t s;

	cc = steely_current_process();
	STEELY_BUG_ON(STEELY, cc == NULL);

	xnlock_get_irqsave(&nklock, s);

	timer = steely_timer_by_id(cc, timerid);
	if (timer == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (ovalue)
		timer_gettimeout(timer, ovalue);

	ret = timer_set(timer, flags, value);
	if (ret == -ETIMEDOUT) {
		/*
		 * Time has already passed, deliver a notification
		 * immediately. Since we are about to dive into the
		 * signal machinery for this, let's drop the nklock to
		 * break the atomic section temporarily.
		 */
		xnlock_put_irqrestore(&nklock, s);
		timer_deliver_late(cc, timerid);
		return 0;
	}
out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

int __steely_timer_gettime(timer_t timerid, struct itimerspec *value)
{
	struct steely_timer *timer;
	struct steely_process *cc;
	spl_t s;

	cc = steely_current_process();
	if (cc == NULL)
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	timer = steely_timer_by_id(cc, timerid);
	if (timer == NULL)
		goto fail;

	timer_gettimeout(timer, value);

	xnlock_put_irqrestore(&nklock, s);

	return 0;
fail:
	xnlock_put_irqrestore(&nklock, s);

	return -EINVAL;
}

STEELY_SYSCALL(timer_delete, current, (timer_t timerid))
{
	return timer_delete(timerid);
}

int __steely_timer_create(clockid_t clock,
			  const struct sigevent *sev,
			  timer_t __user *u_tm)
{
	timer_t timerid = 0;
	int ret;

	ret = timer_create(clock, sev, &timerid);
	if (ret)
		return ret;

	if (steely_copy_to_user(u_tm, &timerid, sizeof(timerid))) {
		timer_delete(timerid);
		return -EFAULT;
	}

	return 0;
}

STEELY_SYSCALL(timer_create, current,
	       (clockid_t clock,
		const struct sigevent __user *u_sev,
		timer_t __user *u_tm))
{
	struct sigevent sev, *evp = NULL;

	if (u_sev) {
		evp = &sev;
		if (steely_copy_from_user(&sev, u_sev, sizeof(sev)))
			return -EFAULT;
	}

	return __steely_timer_create(clock, evp, u_tm);
}

STEELY_SYSCALL(timer_settime, primary,
	       (timer_t tm, int flags,
		const struct itimerspec __user *u_newval,
		struct itimerspec __user *u_oldval))
{
	struct itimerspec newv, oldv, *oldvp = &oldv;
	int ret;

	if (u_oldval == NULL)
		oldvp = NULL;

	if (steely_copy_from_user(&newv, u_newval, sizeof(newv)))
		return -EFAULT;

	ret = __steely_timer_settime(tm, flags, &newv, oldvp);
	if (ret)
		return ret;

	if (oldvp && steely_copy_to_user(u_oldval, oldvp, sizeof(oldv))) {
		__steely_timer_settime(tm, flags, oldvp, NULL);
		return -EFAULT;
	}

	return 0;
}

STEELY_SYSCALL(timer_gettime, current,
	       (timer_t tm, struct itimerspec __user *u_val))
{
	struct itimerspec val;
	int ret;

	ret = __steely_timer_gettime(tm, &val);
	if (ret)
		return ret;

	return steely_copy_to_user(u_val, &val, sizeof(val));
}

STEELY_SYSCALL(timer_getoverrun, current, (timer_t timerid))
{
	struct steely_timer *timer;
	struct steely_process *cc;
	int overruns;
	spl_t s;

	cc = steely_current_process();
	if (cc == NULL)
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	timer = steely_timer_by_id(cc, timerid);
	if (timer == NULL)
		goto fail;

	overruns = timer->overruns;

	xnlock_put_irqrestore(&nklock, s);

	return overruns;
fail:
	xnlock_put_irqrestore(&nklock, s);

	return -EINVAL;
}

int steely_timer_deliver(timer_t timerid) /* nklocked, IRQs off. */
{
	struct steely_timer *timer;
	ktime_t now;

	timer = steely_timer_by_id(steely_current_process(), timerid);
	if (timer == NULL)
		/* Killed before ultimate delivery, who cares then? */
		return 0;

	if (!xntimer_periodic_p(&timer->timerbase))
		timer->overruns = 0;
	else {
		now = xnclock_read_monotonic(xntimer_clock(&timer->timerbase));
		timer->overruns = xntimer_get_overruns(&timer->timerbase, now);
		if ((unsigned int)timer->overruns > STEELY_DELAYMAX)
			timer->overruns = STEELY_DELAYMAX;
	}

	return timer->overruns;
}

void steely_timer_reclaim(struct steely_process *p)
{
	struct steely_timer *timer;
	unsigned id;
	spl_t s;
	int ret;

	xnlock_get_irqsave(&nklock, s);

	if (find_first_zero_bit(p->timers_map, CONFIG_STEELY_NRTIMERS) ==
		CONFIG_STEELY_NRTIMERS)
		goto out;

	for (id = 0; id < ARRAY_SIZE(p->timers); id++) {
		timer = steely_timer_by_id(p, id);
		if (timer == NULL)
			continue;

		steely_call_extension(timer_cleanup, &timer->extref, ret);
		timer_cleanup(p, timer);
		xnlock_put_irqrestore(&nklock, s);
		xnfree(timer);
		xnlock_get_irqsave(&nklock, s);
	}
out:
	xnlock_put_irqrestore(&nklock, s);
}
