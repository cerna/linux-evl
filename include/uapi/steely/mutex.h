/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */
#ifndef _STEELY_UAPI_MUTEX_H
#define _STEELY_UAPI_MUTEX_H

#include <uapi/steely/kernel/types.h>

#define STEELY_MUTEX_MAGIC  0x86860303

struct steely_mutex_state {
	atomic_t owner;
	__u32 flags;
#define STEELY_MUTEX_COND_SIGNAL 0x00000001
#define STEELY_MUTEX_ERRORCHECK  0x00000002
	__u32 ceiling;
};

union steely_mutex_union {
	pthread_mutex_t native_mutex;
	struct steely_mutex_shadow {
		__u32 magic;
		__u32 lockcnt;
		__u32 state_offset;
		xnhandle_t handle;
		struct steely_mutexattr attr;
	} shadow_mutex;
};

#endif /* !_STEELY_UAPI_MUTEX_H */
