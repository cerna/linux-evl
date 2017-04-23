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
#ifndef _STEELY_POSIX_INTERNAL_H
#define _STEELY_POSIX_INTERNAL_H

#include <steely/sched.h>
#include <steely/heap.h>
#include <steely/ppd.h>
#include <steely/assert.h>
#include <steely/list.h>
#include <steely/arith.h>
#include <asm/steely/syscall.h>
#include "process.h"
#include "extension.h"
#include "syscall.h"
#include "memory.h"

#define STEELY_MAXNAME		64
#define STEELY_PERMS_MASK	(O_RDONLY | O_WRONLY | O_RDWR)

#define STEELY_MAGIC(n)		(0x8686##n##n)
#define STEELY_ANY_MAGIC	STEELY_MAGIC(00)
#define STEELY_THREAD_MAGIC	STEELY_MAGIC(01)
#define STEELY_MQ_MAGIC		STEELY_MAGIC(0A)
#define STEELY_MQD_MAGIC	STEELY_MAGIC(0B)
#define STEELY_EVENT_MAGIC	STEELY_MAGIC(0F)
#define STEELY_MONITOR_MAGIC	STEELY_MAGIC(10)
#define STEELY_TIMERFD_MAGIC	STEELY_MAGIC(11)

#define steely_obj_active(h,m,t)	\
	((h) && ((t *)(h))->magic == (m))

#define steely_mark_deleted(t) ((t)->magic = ~(t)->magic)

static inline xnhandle_t steely_get_handle_from_user(xnhandle_t *u_h)
{
	xnhandle_t handle;
	return __xn_get_user(handle, u_h) ? 0 : handle;
}

int steely_interface_init(void);

long steely_restart_syscall_placeholder(struct restart_block *param);

#endif /* !_STEELY_POSIX_INTERNAL_H */
