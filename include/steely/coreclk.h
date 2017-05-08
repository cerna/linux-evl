/*
 * Copyright (C) 2016 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_CORECLK_H
#define _STEELY_CORECLK_H

#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/dovetail.h>
#include <uapi/steely/kernel/types.h>

#define ONE_BILLION  1000000000

struct xnsched;

int xnclock_core_takeover(void);

void xnclock_core_release(void);

void xnclock_core_notify_root(struct xnsched *sched);

const char *xnclock_core_name(int cpu);

void xnclock_core_local_shot(struct xnsched *sched);

void xnclock_core_remote_shot(struct xnsched *sched);

static inline ktime_t xnclock_core_read_monotonic(void)
{
	return ktime_get_mono_fast_ns();
}

static inline ktime_t xnclock_core_read_realtime(void)
{
	return ktime_get_real_fast();
}

static inline ktime_t xnclock_core_read_cycles(void)
{
	return ktime_get_raw_fast_ns(); /* FIXME */
}

int xnclock_core_init(void);

void xnclock_core_cleanup(void);

extern struct xnclock nkclock;

extern unsigned int nkclock_lock;

#endif /* !_STEELY_CORECLK_H */
