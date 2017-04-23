/*
 * Copyright (C) 2013 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_UAPI_EVENT_H
#define _STEELY_UAPI_EVENT_H

#include <uapi/steely/kernel/types.h>

struct steely_event_state {
	__u32 value;
	__u32 flags;
#define STEELY_EVENT_PENDED  0x1
	__u32 nwaiters;
};

struct steely_event;

/* Creation flags. */
#define STEELY_EVENT_FIFO    0x0
#define STEELY_EVENT_PRIO    0x1
#define STEELY_EVENT_SHARED  0x2

/* Wait mode. */
#define STEELY_EVENT_ALL  0x0
#define STEELY_EVENT_ANY  0x1

struct steely_event_shadow {
	__u32 state_offset;
	__u32 flags;
	xnhandle_t handle;
};

struct steely_event_info {
	unsigned int value;
	int flags;
	int nrwait;
};

typedef struct steely_event_shadow steely_event_t;

#endif /* !_STEELY_UAPI_EVENT_H */
