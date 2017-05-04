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
#ifndef _STEELY_POSIX_CLOCK_H
#define _STEELY_POSIX_CLOCK_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/cpumask.h>
#include <uapi/steely/time.h>
#include <steely/posix/syscall.h>

struct xnclock;

static inline ktime_t clock_get_ticks(clockid_t clock_id)
{
	return clock_id == CLOCK_REALTIME ?
		xnclock_read_realtime(&nkclock) :
		xnclock_read_monotonic(&nkclock);
}

static inline int clock_flag(int flag, clockid_t clock_id)
{
	if ((flag & TIMER_ABSTIME) == 0)
		return XN_RELATIVE;

	if (clock_id == CLOCK_REALTIME)
		return XN_REALTIME;

	return XN_ABSOLUTE;
}

int __steely_clock_getres(clockid_t clock_id,
			  struct timespec *ts);

int __steely_clock_gettime(clockid_t clock_id,
			   struct timespec *ts);

int __steely_clock_settime(clockid_t clock_id,
			   const struct timespec *ts);

int __steely_clock_nanosleep(clockid_t clock_id, int flags,
			     const struct timespec *rqt,
			     struct timespec *rmt);

STEELY_SYSCALL_DECL(clock_getres,
		    (clockid_t clock_id, struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(clock_gettime,
		    (clockid_t clock_id, struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(clock_settime,
		    (clockid_t clock_id, const struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(clock_nanosleep,
		    (clockid_t clock_id, int flags,
		     const struct timespec __user *u_rqt,
		     struct timespec __user *u_rmt));

int steely_clock_register(struct xnclock *clock,
			  const struct cpumask *affinity,
			  clockid_t *clk_id);

void steely_clock_deregister(struct xnclock *clock);

struct xnclock *steely_clock_find(clockid_t clock_id);

extern DECLARE_BITMAP(steely_clock_extids, STEELY_MAX_EXTCLOCKS);

#endif /* !_STEELY_POSIX_CLOCK_H */
