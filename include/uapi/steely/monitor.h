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
#ifndef _STEELY_UAPI_MONITOR_H
#define _STEELY_UAPI_MONITOR_H

#include <uapi/steely/kernel/types.h>

struct steely_monitor_state {
	atomic_t owner;
	__u32 flags;
#define STEELY_MONITOR_GRANTED    0x01
#define STEELY_MONITOR_DRAINED    0x02
#define STEELY_MONITOR_SIGNALED   0x03 /* i.e. GRANTED or DRAINED */
#define STEELY_MONITOR_BROADCAST  0x04
#define STEELY_MONITOR_PENDED     0x08
};

struct steely_monitor;

struct steely_monitor_shadow {
	__u32 state_offset;
	__u32 flags;
	xnhandle_t handle;
#define STEELY_MONITOR_SHARED     0x1
#define STEELY_MONITOR_WAITGRANT  0x0
#define STEELY_MONITOR_WAITDRAIN  0x1
};

typedef struct steely_monitor_shadow steely_monitor_t;

#endif /* !_STEELY_UAPI_MONITOR_H */
