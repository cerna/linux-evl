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
#ifndef _STEELY_COND_H
#define _STEELY_COND_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/list.h>
#include <steely/synch.h>
#include <steely/thread.h>
#include <uapi/steely/thread.h>
#include <uapi/steely/cond.h>
#include <steely/syscall.h>
#include <steely/process.h>

struct steely_mutex;

struct steely_cond {
	unsigned int magic;
	struct xnsynch synchbase;
	struct list_head mutex_link;
	struct steely_cond_state *state;
	struct steely_condattr attr;
	struct steely_mutex *mutex;
	struct steely_resnode resnode;
};

int __steely_cond_wait_prologue(struct steely_cond_shadow __user *u_cnd,
				struct steely_mutex_shadow __user *u_mx,
				int *u_err,
				void __user *u_ts,
				int (*fetch_timeout)(struct timespec *ts,
						     const void __user *u_ts));
STEELY_SYSCALL_DECL(cond_init,
		    (struct steely_cond_shadow __user *u_cnd,
		     const struct steely_condattr __user *u_attr));

STEELY_SYSCALL_DECL(cond_destroy,
		    (struct steely_cond_shadow __user *u_cnd));

STEELY_SYSCALL_DECL(cond_wait_prologue,
		    (struct steely_cond_shadow __user *u_cnd,
		     struct steely_mutex_shadow __user *u_mx,
		     int *u_err,
		     unsigned int timed,
		     struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(cond_wait_epilogue,
		    (struct steely_cond_shadow __user *u_cnd,
		     struct steely_mutex_shadow __user *u_mx));

int steely_cond_deferred_signals(struct steely_cond *cond);

void steely_cond_reclaim(struct steely_resnode *node,
			 spl_t s);

#endif /* !_STEELY_COND_H */
