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

#ifndef _STEELY_POSIX_MUTEX_H
#define _STEELY_POSIX_MUTEX_H

#include "thread.h"
#include <uapi/steely/mutex.h>
#include <steely/posix/syscall.h>
#include <steely/posix/process.h>

struct steely_process;

struct steely_mutex {
	unsigned int magic;
	struct xnsynch synchbase;
	/* steely_mutexq */
	struct list_head conds;
	struct steely_mutexattr attr;
	struct steely_resnode resnode;
};

int __steely_mutex_timedlock_break(struct steely_mutex_shadow __user *u_mx,
				   const void __user *u_ts,
				   int (*fetch_timeout)(struct timespec *ts,
							const void __user *u_ts));

int __steely_mutex_acquire_unchecked(struct xnthread *cur,
				     struct steely_mutex *mutex,
				     const struct timespec *ts);

STEELY_SYSCALL_DECL(mutex_check_init,
		    (struct steely_mutex_shadow __user *u_mx));

STEELY_SYSCALL_DECL(mutex_init,
		    (struct steely_mutex_shadow __user *u_mx,
		     const struct steely_mutexattr __user *u_attr));

STEELY_SYSCALL_DECL(mutex_destroy,
		    (struct steely_mutex_shadow __user *u_mx));

STEELY_SYSCALL_DECL(mutex_trylock,
		    (struct steely_mutex_shadow __user *u_mx));

STEELY_SYSCALL_DECL(mutex_lock,
		    (struct steely_mutex_shadow __user *u_mx));

STEELY_SYSCALL_DECL(mutex_timedlock,
		    (struct steely_mutex_shadow __user *u_mx,
		     const struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(mutex_unlock,
		    (struct steely_mutex_shadow __user *u_mx));

int steely_mutex_release(struct xnthread *cur,
			 struct steely_mutex *mutex);

void steely_mutex_reclaim(struct steely_resnode *node,
			  spl_t s);

#endif /* !_STEELY_POSIX_MUTEX_H */
