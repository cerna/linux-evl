/*
 * Copyright (C) 2012 Philippe Gerum <rpm@xenomai.org>
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

#ifndef _STEELY_POSIX_EVENT_H
#define _STEELY_POSIX_EVENT_H

#include <steely/synch.h>
#include <uapi/steely/event.h>
#include <steely/posix/syscall.h>
#include <steely/posix/process.h>

struct steely_resources;
struct steely_process;

struct steely_event {
	unsigned int magic;
	unsigned int value;
	int flags;
	struct xnsynch synch;
	struct steely_event_state *state;
	struct steely_resnode resnode;
};

int __steely_event_wait(struct steely_event_shadow __user *u_event,
			unsigned int bits,
			unsigned int __user *u_bits_r,
			int mode, const struct timespec *ts);

STEELY_SYSCALL_DECL(event_init,
		    (struct steely_event_shadow __user *u_evtsh,
		     unsigned int value,
		     int flags));

STEELY_SYSCALL_DECL(event_wait,
		    (struct steely_event_shadow __user *u_evtsh,
		     unsigned int bits,
		     unsigned int __user *u_bits_r,
		     int mode,
		     const struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(event_sync,
		    (struct steely_event_shadow __user *u_evtsh));

STEELY_SYSCALL_DECL(event_destroy,
		    (struct steely_event_shadow __user *u_evtsh));

STEELY_SYSCALL_DECL(event_inquire,
		    (struct steely_event_shadow __user *u_event,
		     struct steely_event_info __user *u_info,
		     pid_t __user *u_waitlist,
		     size_t waitsz));

void steely_event_reclaim(struct steely_resnode *node,
			  spl_t s);

#endif /* !_STEELY_POSIX_EVENT_H */
