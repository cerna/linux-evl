/*
 * Copyright (C) 2011 Philippe Gerum <rpm@xenomai.org>
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

#ifndef _STEELY_MONITOR_H
#define _STEELY_MONITOR_H

#include <steely/synch.h>
#include <uapi/steely/monitor.h>
#include <steely/syscall.h>
#include <steely/process.h>

struct steely_resources;
struct steely_process;

struct steely_monitor {
	unsigned int magic;
	struct xnsynch gate;
	struct xnsynch drain;
	struct steely_monitor_state *state;
	struct list_head waiters;
	int flags;
	xntmode_t tmode;
	struct steely_resnode resnode;
};

int __steely_monitor_wait(struct steely_monitor_shadow __user *u_mon,
			  int event, const struct timespec *ts,
			  int __user *u_ret);

STEELY_SYSCALL_DECL(monitor_init,
		    (struct steely_monitor_shadow __user *u_monsh,
		     clockid_t clk_id,
		     int flags));

STEELY_SYSCALL_DECL(monitor_enter,
		    (struct steely_monitor_shadow __user *u_monsh));

STEELY_SYSCALL_DECL(monitor_sync,
		    (struct steely_monitor_shadow __user *u_monsh));

STEELY_SYSCALL_DECL(monitor_exit,
		    (struct steely_monitor_shadow __user *u_monsh));

STEELY_SYSCALL_DECL(monitor_wait,
		    (struct steely_monitor_shadow __user *u_monsh,
		     int event, const struct timespec __user *u_ts,
		     int __user *u_ret));

STEELY_SYSCALL_DECL(monitor_destroy,
		    (struct steely_monitor_shadow __user *u_monsh));

void steely_monitor_reclaim(struct steely_resnode *node,
			    spl_t s);

#endif /* !_STEELY_MONITOR_H */
