/*
 * This file is part of the Xenomai project.
 *
 * Copyright (C) 2009 Philippe Gerum <rpm@xenomai.org>
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

#ifndef _RTDM_UAPI_IPC_H
#define _RTDM_UAPI_IPC_H

#include <uapi/steely/kernel/types.h>
#include <uapi/steely/kernel/pipe.h>
#include <steely/rtdm.h>

/* Address family */
#define AF_RTIPC		111

/* Protocol family */
#define PF_RTIPC		AF_RTIPC

enum {
	IPCPROTO_IPC  = 0,
	IPCPROTO_XDDP = 1,
	IPCPROTO_IDDP = 2,
	IPCPROTO_BUFP = 3,
	IPCPROTO_MAX
};

/*
 * Port number type for the RTIPC address family.
 */
typedef int16_t rtipc_port_t;

/*
 * Port label information structure.
 */
struct rtipc_port_label {
	/* Port label string, null-terminated. */
	char label[XNOBJECT_NAME_LEN];
};

/*
 * Socket address structure for the RTIPC address family.
 */
struct sockaddr_ipc {
	/* RTIPC address family, must be @c AF_RTIPC */
	sa_family_t sipc_family;
	/* Port number. */
	rtipc_port_t sipc_port;
};

#define SOL_XDDP		311
#define XDDP_LABEL		1
#define XDDP_POOLSZ		2
#define XDDP_BUFSZ		3
#define XDDP_MONITOR		4
#define XDDP_EVTIN		1
#define XDDP_EVTOUT		2
#define XDDP_EVTDOWN		3
#define XDDP_EVTNOBUF		4

#define SOL_IDDP		312
#define IDDP_LABEL		1
#define IDDP_POOLSZ		2

#define SOL_BUFP		313
#define BUFP_LABEL		1
#define BUFP_BUFSZ		2

#endif /* !_RTDM_UAPI_IPC_H */
