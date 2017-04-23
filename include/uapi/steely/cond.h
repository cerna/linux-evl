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
#ifndef _STEELY_UAPI_COND_H
#define _STEELY_UAPI_COND_H

#include <uapi/steely/mutex.h>

#define STEELY_COND_MAGIC 0x86860505

struct steely_cond_state {
	__u32 pending_signals;
	__u32 mutex_state_offset;
};

union steely_cond_union {
	pthread_cond_t native_cond;
	struct steely_cond_shadow {
		__u32 magic;
		__u32 state_offset;
		xnhandle_t handle;
	} shadow_cond;
};

#endif /* !_STEELY_UAPI_COND_H */
