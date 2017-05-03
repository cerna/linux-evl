/*
 * Real-Time Driver Model for Xenomai, user API header.
 *
 * @note Copyright (C) 2005, 2006 Jan Kiszka <jan.kiszka@web.de>
 * @note Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
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
 * @ingroup rtdm_user_api
 */
#ifndef _RTDM_UAPI_RTDM_H
#define _RTDM_UAPI_RTDM_H

/* Common user and driver API version */
#define RTDM_API_VER			9

/* Minimum API revision compatible with the current release */
#define RTDM_API_MIN_COMPAT_VER		9
/* @} API Versioning */

/* RTDM type for representing absolute dates. Its base type is a 64 bit
 *  unsigned integer. The unit is 1 nanosecond. */
typedef uint64_t nanosecs_abs_t;

/* RTDM type for representing relative intervals. Its base type is a 64 bit
 *  signed integer. The unit is 1 nanosecond. Relative intervals can also
 *  encode the special timeouts "infinite" and "non-blocking" */
typedef int64_t nanosecs_rel_t;

/* Block forever. */
#define RTDM_TIMEOUT_INFINITE		0

/* Any negative timeout means non-blocking. */
#define RTDM_TIMEOUT_NONE		(-1)

/* Device classes */
#define RTDM_CLASS_PARPORT		1
#define RTDM_CLASS_SERIAL		2
#define RTDM_CLASS_CAN			3
#define RTDM_CLASS_NETWORK		4
#define RTDM_CLASS_RTMAC		5
#define RTDM_CLASS_TESTING		6
#define RTDM_CLASS_RTIPC		7
#define RTDM_CLASS_STEELY		8
#define RTDM_CLASS_UDD			9
#define RTDM_CLASS_MEMORY		10
#define RTDM_CLASS_GPIO			11
#define RTDM_CLASS_SPI			12
#define RTDM_CLASS_PWM			13

#define RTDM_CLASS_MISC			223
#define RTDM_CLASS_EXPERIMENTAL		224
#define RTDM_CLASS_MAX			255

#define RTDM_SUBCLASS_GENERIC		(-1)

#define RTIOC_TYPE_COMMON		0

#define RTDM_MAX_DEVNAME_LEN		31

/*
 * Device information
 */
typedef struct rtdm_device_info {
	/* Device flags */
	int device_flags;

	/* Device class ID */
	int device_class;

  	/* Device sub-class */
	int device_sub_class;

	/* Supported device profile version */
	int profile_version;
} rtdm_device_info_t;

#define RTDM_PURGE_RX_BUFFER		0x0001
#define RTDM_PURGE_TX_BUFFER		0x0002

/*
 * Retrieve information about a device or socket.
 */
#define RTIOC_DEVICE_INFO \
	_IOR(RTIOC_TYPE_COMMON, 0x00, struct rtdm_device_info)

/*
 * Purge internal device or socket buffers.
 */
#define RTIOC_PURGE		_IOW(RTIOC_TYPE_COMMON, 0x10, int)

/* Internally used for mapping socket functions on IOCTLs */
struct _rtdm_getsockopt_args {
	int level;
	int optname;
	void *optval;
	socklen_t *optlen;
};

struct _rtdm_setsockopt_args {
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
};

struct _rtdm_getsockaddr_args {
	struct sockaddr *addr;
	socklen_t *addrlen;
};

struct _rtdm_setsockaddr_args {
	const struct sockaddr *addr;
	socklen_t addrlen;
};

#define _RTIOC_GETSOCKOPT	_IOW(RTIOC_TYPE_COMMON, 0x20,		\
				     struct _rtdm_getsockopt_args)
#define _RTIOC_SETSOCKOPT	_IOW(RTIOC_TYPE_COMMON, 0x21,		\
				     struct _rtdm_setsockopt_args)
#define _RTIOC_BIND		_IOW(RTIOC_TYPE_COMMON, 0x22,		\
				     struct _rtdm_setsockaddr_args)
#define _RTIOC_CONNECT		_IOW(RTIOC_TYPE_COMMON, 0x23,		\
				     struct _rtdm_setsockaddr_args)
#define _RTIOC_LISTEN		_IOW(RTIOC_TYPE_COMMON, 0x24,		\
				     int)
#define _RTIOC_ACCEPT		_IOW(RTIOC_TYPE_COMMON, 0x25,		\
				     struct _rtdm_getsockaddr_args)
#define _RTIOC_GETSOCKNAME	_IOW(RTIOC_TYPE_COMMON, 0x26,		\
				     struct _rtdm_getsockaddr_args)
#define _RTIOC_GETPEERNAME	_IOW(RTIOC_TYPE_COMMON, 0x27,		\
				     struct _rtdm_getsockaddr_args)
#define _RTIOC_SHUTDOWN		_IOW(RTIOC_TYPE_COMMON, 0x28,		\
				     int)

/* Internally used for mmap() */
struct _rtdm_mmap_request {
	__u64 offset;
	size_t length;
	int prot;
	int flags;
};

#endif /* !_RTDM_UAPI_RTDM_H */
