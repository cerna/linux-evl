/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

#include <linux/clocksource.h>
#include <linux/bitmap.h>
#include <linux/sched/signal.h>
#include <steely/vdso.h>
#include <steely/clock.h>
#include "internal.h"
#include "thread.h"
#include "clock.h"
#include <trace/events/steely.h>

static struct xnclock *external_clocks[STEELY_MAX_EXTCLOCKS];

DECLARE_BITMAP(steely_clock_extids, STEELY_MAX_EXTCLOCKS);

#define do_ext_clock(__clock_id, __handler, __ret, __args...)	\
({								\
	struct xnclock *__clock;				\
	int __val = 0, __nr;					\
	spl_t __s;						\
								\
	if (!__STEELY_CLOCK_EXT_P(__clock_id))			\
		__val = -EINVAL;				\
	else {							\
		__nr = __STEELY_CLOCK_EXT_INDEX(__clock_id);	\
		xnlock_get_irqsave(&nklock, __s);		\
		if (!test_bit(__nr, steely_clock_extids)) {	\
			xnlock_put_irqrestore(&nklock, __s);	\
			__val = -EINVAL;			\
		} else {					\
			__clock = external_clocks[__nr];	\
			(__ret) = xnclock_ ## __handler(__clock, ##__args); \
			xnlock_put_irqrestore(&nklock, __s);	\
		}						\
	}							\
	__val;							\
})

int __steely_clock_getres(clockid_t clock_id, struct timespec *ts)
{
	ktime_t res;
	int ret;

	switch (clock_id) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_MONOTONIC_RAW:
		*ts = ns_to_timespec(1);
		break;
	default:
		ret = do_ext_clock(clock_id, get_resolution, res);
		if (ret)
			return ret;
		*ts = ktime_to_timespec(res);
	}

	trace_steely_clock_getres(clock_id, ts);

	return 0;
}

STEELY_SYSCALL(clock_getres, current,
	       (clockid_t clock_id, struct timespec __user *u_ts))
{
	struct timespec ts;
	int ret;

	ret = __steely_clock_getres(clock_id, &ts);
	if (ret)
		return ret;

	if (u_ts && steely_copy_to_user(u_ts, &ts, sizeof(ts)))
		return -EFAULT;

	trace_steely_clock_getres(clock_id, &ts);

	return 0;
}

int __steely_clock_gettime(clockid_t clock_id, struct timespec *ts)
{
	ktime_t t;
	int ret;

	switch (clock_id) {
	case CLOCK_REALTIME:
		*ts = ktime_to_timespec(xnclock_read_realtime(&nkclock));
		break;
	case CLOCK_MONOTONIC:
		*ts = ktime_to_timespec(xnclock_read_monotonic(&nkclock));
		break;
	default:
		ret = do_ext_clock(clock_id, read_monotonic, t);
		if (ret)
			return ret;
		*ts = ktime_to_timespec(t);
	}

	trace_steely_clock_gettime(clock_id, ts);

	return 0;
}

STEELY_SYSCALL(clock_gettime, current,
	       (clockid_t clock_id, struct timespec __user *u_ts))
{
	struct timespec ts;
	int ret;

	ret = __steely_clock_gettime(clock_id, &ts);
	if (ret)
		return ret;

	if (steely_copy_to_user(u_ts, &ts, sizeof(*u_ts)))
		return -EFAULT;

	trace_steely_clock_gettime(clock_id, &ts);

	return 0;
}

int __steely_clock_settime(clockid_t clock_id, const struct timespec *ts)
{
	int _ret, ret = 0;
	ktime_t now;
	spl_t s;

	if ((unsigned long)ts->tv_nsec >= ONE_BILLION)
		return -EINVAL;

	switch (clock_id) {
	case CLOCK_REALTIME:
		xnlock_get_irqsave(&nklock, s);
		now = xnclock_read_realtime(&nkclock);
		xnclock_adjust(&nkclock, ktime_sub(timespec_to_ktime(*ts), now));
		xnlock_put_irqrestore(&nklock, s);
		break;
	default:
		_ret = do_ext_clock(clock_id, set_time, ret, ts);
		if (_ret || ret)
			return _ret ?: ret;
	}

	trace_steely_clock_settime(clock_id, ts);

	return 0;
}

STEELY_SYSCALL(clock_settime, current,
	       (clockid_t clock_id, const struct timespec __user *u_ts))
{
	struct timespec ts;

	if (steely_copy_from_user(&ts, u_ts, sizeof(ts)))
		return -EFAULT;

	return __steely_clock_settime(clock_id, &ts);
}

int __steely_clock_nanosleep(clockid_t clock_id, int flags,
			     const struct timespec *rqt,
			     struct timespec *rmt)
{
	struct restart_block *restart;
	struct xnthread *cur;
	ktime_t timeout, rem;
	int ret = 0;
	spl_t s;

	trace_steely_clock_nanosleep(clock_id, flags, rqt);

	if (clock_id != CLOCK_MONOTONIC &&
	    clock_id != CLOCK_REALTIME)
		return -EOPNOTSUPP;

	if (rqt->tv_sec < 0)
		return -EINVAL;

	if ((unsigned long)rqt->tv_nsec >= ONE_BILLION)
		return -EINVAL;

	if (flags & ~TIMER_ABSTIME)
		return -EINVAL;

	cur = xnthread_current();

	if (xnthread_test_localinfo(cur, XNSYSRST)) {
		xnthread_clear_localinfo(cur, XNSYSRST);
		restart = &current->restart_block;
		if (restart->fn != steely_restart_syscall_placeholder) {
			if (rmt) {
				xnlock_get_irqsave(&nklock, s);
				rem = xntimer_get_timeout_stopped(&cur->rtimer);
				xnlock_put_irqrestore(&nklock, s);
				*rmt = ktime_to_timespec(ktime_to_ns(rem) > 1 ? rem : 0);
			}
			return -EINTR;
		}
		timeout = restart->nanosleep.expires;
	} else
		timeout = timespec_to_ktime(*rqt);

	xnlock_get_irqsave(&nklock, s);

	xnthread_suspend(cur, XNDELAY, ktime_add_ns(timeout, 1),
			 clock_flag(flags, clock_id), NULL);

	if (xnthread_test_info(cur, XNBREAK)) {
		if (signal_pending(current)) {
			restart = &current->restart_block;
			restart->nanosleep.expires =
				(flags & TIMER_ABSTIME) ? timeout :
				    xntimer_get_timeout_stopped(&cur->rtimer);
			xnlock_put_irqrestore(&nklock, s);
			restart->fn = steely_restart_syscall_placeholder;

			xnthread_set_localinfo(cur, XNSYSRST);

			return -ERESTARTSYS;
		}

		if (flags == 0 && rmt) {
			rem = xntimer_get_timeout_stopped(&cur->rtimer);
			xnlock_put_irqrestore(&nklock, s);
			*rmt = ktime_to_timespec(ktime_to_ns(rem) > 1 ? rem : 0);
		} else
			xnlock_put_irqrestore(&nklock, s);

		return -EINTR;
	}

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

STEELY_SYSCALL(clock_nanosleep, primary,
	       (clockid_t clock_id, int flags,
		const struct timespec __user *u_rqt,
		struct timespec __user *u_rmt))
{
	struct timespec rqt, rmt, *rmtp = NULL;
	int ret;

	if (u_rmt)
		rmtp = &rmt;

	if (steely_copy_from_user(&rqt, u_rqt, sizeof(rqt)))
		return -EFAULT;

	ret = __steely_clock_nanosleep(clock_id, flags, &rqt, rmtp);
	if (ret == -EINTR && flags == 0 && rmtp) {
		if (steely_copy_to_user(u_rmt, rmtp, sizeof(*u_rmt)))
			return -EFAULT;
	}

	return ret;
}

int steely_clock_register(struct xnclock *clock,
			  const struct cpumask *affinity,
			  clockid_t *clk_id)
{
	int ret, nr;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	nr = find_first_zero_bit(steely_clock_extids, STEELY_MAX_EXTCLOCKS);
	if (nr >= STEELY_MAX_EXTCLOCKS) {
		xnlock_put_irqrestore(&nklock, s);
		return -EAGAIN;
	}

	/*
	 * CAUTION: a bit raised in steely_clock_extids means that the
	 * corresponding entry in external_clocks[] is valid. The
	 * converse assumption is NOT true.
	 */
	__set_bit(nr, steely_clock_extids);
	external_clocks[nr] = clock;

	xnlock_put_irqrestore(&nklock, s);

	ret = xnclock_register(clock, affinity);
	if (ret)
		return ret;

	clock->id = nr;
	*clk_id = __STEELY_CLOCK_EXT(clock->id);

	trace_steely_clock_register(clock->name, *clk_id);

	return 0;
}
EXPORT_SYMBOL_GPL(steely_clock_register);

void steely_clock_deregister(struct xnclock *clock)
{
	trace_steely_clock_deregister(clock->name, clock->id);
	clear_bit(clock->id, steely_clock_extids);
	smp_mb__after_atomic();
	external_clocks[clock->id] = NULL;
	xnclock_deregister(clock);
}
EXPORT_SYMBOL_GPL(steely_clock_deregister);

struct xnclock *steely_clock_find(clockid_t clock_id)
{
	struct xnclock *clock = ERR_PTR(-EINVAL);
	spl_t s;
	int nr;

	if (clock_id == CLOCK_MONOTONIC ||
	    clock_id == CLOCK_REALTIME)
		return &nkclock;
	
	if (__STEELY_CLOCK_EXT_P(clock_id)) {
		nr = __STEELY_CLOCK_EXT_INDEX(clock_id);
		xnlock_get_irqsave(&nklock, s);
		if (test_bit(nr, steely_clock_extids))
			clock = external_clocks[nr];
		xnlock_put_irqrestore(&nklock, s);
	}

	return clock;
}
EXPORT_SYMBOL_GPL(steely_clock_find);
