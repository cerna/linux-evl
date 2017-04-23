/*
 * Copyright (C) 2006 Jan Kiszka <jan.kiszka@web.de>.
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
#ifndef _STEELY_KERNEL_TRACE_H
#define _STEELY_KERNEL_TRACE_H

#include <linux/types.h>
#include <uapi/steely/kernel/trace.h>

static inline int xntrace_max_begin(unsigned long v)
{
	return 0;
}

static inline int xntrace_max_end(unsigned long v)
{
	return 0;
}

static inline int xntrace_max_reset(void)
{
	return 0;
}

static inline int xntrace_user_start(void)
{
	return 0;
}

static inline int xntrace_user_stop(unsigned long v)
{
	return 0;
}

static inline int xntrace_user_freeze(unsigned long v, int once)
{
	return 0;
}

static inline int xntrace_special(unsigned char id, unsigned long v)
{
	return 0;
}

static inline int xntrace_special_u64(unsigned char id,
				      unsigned long long v)
{
	return 0;
}

static inline int xntrace_pid(pid_t pid, short prio)
{
	return 0;
}

static inline int xntrace_tick(unsigned long delay_ticks)
{
	return 0;
}

static inline int xntrace_panic_freeze(void)
{
	return 0;
}

static inline int xntrace_panic_dump(void)
{
	return 0;
}

#endif /* !_STEELY_KERNEL_TRACE_H */
