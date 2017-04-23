/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>.
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef _STEELY_POSIX_IO_H
#define _STEELY_POSIX_IO_H

#include <steely/rtdm.h>
#include <steely/posix/syscall.h>
#include <steely/select.h>

int __steely_first_fd_valid_p(fd_set *fds[XNSELECT_MAX_TYPES], int nfds);

int __steely_select_bind_all(struct xnselector *selector,
			     fd_set *fds[XNSELECT_MAX_TYPES], int nfds);

STEELY_SYSCALL_DECL(open,
		    (const char __user *u_path, int oflag));

STEELY_SYSCALL_DECL(socket,
		    (int protocol_family,
		     int socket_type, int protocol));

STEELY_SYSCALL_DECL(close, (int fd));

STEELY_SYSCALL_DECL(fcntl, (int fd, int cmd, int arg));

STEELY_SYSCALL_DECL(ioctl,
		    (int fd, unsigned int request, void __user *arg));

STEELY_SYSCALL_DECL(read,
		    (int fd, void __user *buf, size_t size));

STEELY_SYSCALL_DECL(write,
		    (int fd, const void __user *buf, size_t size));

STEELY_SYSCALL_DECL(recvmsg,
		    (int fd, struct user_msghdr __user *umsg, int flags));

STEELY_SYSCALL_DECL(sendmsg,
		    (int fd, struct user_msghdr __user *umsg, int flags));

STEELY_SYSCALL_DECL(mmap,
		    (int fd, struct _rtdm_mmap_request __user *u_rma,
		     void __user * __user *u_addrp));

STEELY_SYSCALL_DECL(select,
		    (int nfds,
		     fd_set __user *u_rfds,
		     fd_set __user *u_wfds,
		     fd_set __user *u_xfds,
		     struct timeval __user *u_tv));

#endif /* !_STEELY_POSIX_IO_H */
