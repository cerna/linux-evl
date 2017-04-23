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
#ifndef _STEELY_KERNEL_CORECLK_H
#define _STEELY_KERNEL_CORECLK_H

#include <linux/dovetail.h>
#include <uapi/steely/kernel/types.h>

struct xnsched;

int xnclock_core_takeover(void);

void xnclock_core_release(void);

void xnclock_core_notify_root(struct xnsched *sched);

const char *xnclock_core_name(int cpu);

void xnclock_core_local_shot(struct xnsched *sched);

void xnclock_core_remote_shot(struct xnsched *sched);

xnsticks_t xnclock_core_ns_to_ticks(xnsticks_t ns);

xnsticks_t xnclock_core_ticks_to_ns(xnsticks_t ticks);

xnsticks_t xnclock_core_ticks_to_ns_rounded(xnsticks_t ticks);

unsigned long long xnclock_divrem_billion(unsigned long long value,
					  unsigned long *rem);

xnticks_t xnclock_core_read_monotonic(void);

static inline xnticks_t xnclock_core_read_raw(void)
{
	return __ipipe_tsc_get();
}

int xnclock_core_init(unsigned long long freq);

void xnclock_core_cleanup(void);

extern struct xnclock nkclock;

extern unsigned int nkclock_lock;

#endif /* !_STEELY_KERNEL_CORECLK_H */
