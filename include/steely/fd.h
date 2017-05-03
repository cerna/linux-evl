/*
 * Copyright (C) 2005-2007 Jan Kiszka <jan.kiszka@web.de>
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
 * Copyright (C) 2008,2013,2014 Gilles Chanteperdrix <gch@xenomai.org>.
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
#ifndef _STEELY_KERNEL_FD_H
#define _STEELY_KERNEL_FD_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <steely/tree.h>
#include <asm-generic/steely/syscall.h>

struct vm_area_struct;
struct rtdm_fd;
struct _rtdm_mmap_request;
struct xnselector;
struct steely_ppd;

int rtdm_open_handler(struct rtdm_fd *fd, int oflags);

int rtdm_socket_handler(struct rtdm_fd *fd, int protocol);

void rtdm_close_handler(struct rtdm_fd *fd);

int rtdm_ioctl_handler(struct rtdm_fd *fd, unsigned int request, void __user *arg);

ssize_t rtdm_read_handler(struct rtdm_fd *fd, void __user *buf, size_t size);

ssize_t rtdm_write_handler(struct rtdm_fd *fd, const void __user *buf, size_t size);

ssize_t rtdm_recvmsg_handler(struct rtdm_fd *fd, struct user_msghdr *msg, int flags);

ssize_t rtdm_sendmsg_handler(struct rtdm_fd *fd, const struct user_msghdr *msg, int flags);

int rtdm_select_handler(struct rtdm_fd *fd, struct xnselector *selector,
			unsigned int type, unsigned int index);

int rtdm_mmap_handler(struct rtdm_fd *fd, struct vm_area_struct *vma);

unsigned long
rtdm_get_unmapped_area_handler(struct rtdm_fd *fd,
			       unsigned long len, unsigned long pgoff,
			       unsigned long flags);
struct rtdm_fd_ops {
	/* See rtdm_open_handler(). */
	int (*open)(struct rtdm_fd *fd, int oflags);
	/* See rtdm_socket_handler(). */
	int (*socket)(struct rtdm_fd *fd, int protocol);
	/* See rtdm_close_handler(). */
	void (*close)(struct rtdm_fd *fd);
	/* See rtdm_ioctl_handler(). */
	int (*ioctl_rt)(struct rtdm_fd *fd,
			unsigned int request, void __user *arg);
	/* See rtdm_ioctl_handler(). */
	int (*ioctl_nrt)(struct rtdm_fd *fd,
			 unsigned int request, void __user *arg);
	/* See rtdm_read_handler(). */
	ssize_t (*read_rt)(struct rtdm_fd *fd,
			   void __user *buf, size_t size);
	/* See rtdm_read_handler(). */
	ssize_t (*read_nrt)(struct rtdm_fd *fd,
			    void __user *buf, size_t size);
	/* See rtdm_write_handler(). */
	ssize_t (*write_rt)(struct rtdm_fd *fd,
			    const void __user *buf, size_t size);
	/* See rtdm_write_handler(). */
	ssize_t (*write_nrt)(struct rtdm_fd *fd,
			     const void __user *buf, size_t size);
	/* See rtdm_recvmsg_handler(). */
	ssize_t (*recvmsg_rt)(struct rtdm_fd *fd,
			      struct user_msghdr *msg, int flags);
	/* See rtdm_recvmsg_handler(). */
	ssize_t (*recvmsg_nrt)(struct rtdm_fd *fd,
			       struct user_msghdr *msg, int flags);
	/* See rtdm_sendmsg_handler(). */
	ssize_t (*sendmsg_rt)(struct rtdm_fd *fd,
			      const struct user_msghdr *msg, int flags);
	/* See rtdm_sendmsg_handler(). */
	ssize_t (*sendmsg_nrt)(struct rtdm_fd *fd,
			       const struct user_msghdr *msg, int flags);
	/* See rtdm_select_handler(). */
	int (*select)(struct rtdm_fd *fd,
		      struct xnselector *selector,
		      unsigned int type, unsigned int index);
	/* See rtdm_mmap_handler(). */
	int (*mmap)(struct rtdm_fd *fd,
		    struct vm_area_struct *vma);
	/* See rtdm_get_unmapped_area_handler(). */
	unsigned long (*get_unmapped_area)(struct rtdm_fd *fd,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags);
};

struct rtdm_fd {
	unsigned int magic;
	struct rtdm_fd_ops *ops;
	struct steely_ppd *owner;
	unsigned int refs;
	int minor;
	int oflags;
#ifdef CONFIG_STEELY_ARCH_SYS3264
	int compat;
#endif
	struct list_head cleanup;
};

#define RTDM_FD_MAGIC 0x52544446

#define RTDM_FD_COMPAT	__STEELY_COMPAT_BIT
#define RTDM_FD_COMPATX	__STEELY_COMPATX_BIT

int __rtdm_anon_getfd(const char *name, int flags);

void __rtdm_anon_putfd(int ufd);

static inline struct steely_ppd *rtdm_fd_owner(const struct rtdm_fd *fd)
{
	return fd->owner;
}

static inline int rtdm_fd_minor(const struct rtdm_fd *fd)
{
	return fd->minor;
}

static inline int rtdm_fd_flags(const struct rtdm_fd *fd)
{
	return fd->oflags;
}

#ifdef CONFIG_STEELY_ARCH_SYS3264
static inline int rtdm_fd_is_compat(const struct rtdm_fd *fd)
{
	return fd->compat;
}
#else
static inline int rtdm_fd_is_compat(const struct rtdm_fd *fd)
{
	return 0;
}
#endif

int rtdm_fd_enter(struct rtdm_fd *rtdm_fd, int ufd,
		  unsigned int magic, struct rtdm_fd_ops *ops);

struct rtdm_fd *rtdm_fd_get(int ufd, unsigned int magic);

int rtdm_fd_lock(struct rtdm_fd *fd);

void rtdm_fd_put(struct rtdm_fd *fd);

void rtdm_fd_unlock(struct rtdm_fd *fd);

int rtdm_fd_fcntl(int ufd, int cmd, ...);

int rtdm_fd_ioctl(int ufd, unsigned int request, ...);

ssize_t rtdm_fd_read(int ufd, void __user *buf, size_t size);

ssize_t rtdm_fd_write(int ufd, const void __user *buf, size_t size);

int rtdm_fd_close(int ufd, unsigned int magic);

ssize_t rtdm_fd_recvmsg(int ufd, struct user_msghdr *msg, int flags);

ssize_t rtdm_fd_sendmsg(int ufd, const struct user_msghdr *msg,
			int flags);

int rtdm_fd_mmap(int ufd, struct _rtdm_mmap_request *rma,
		 void **u_addrp);

int rtdm_fd_valid_p(int ufd);

int rtdm_fd_select(int ufd, struct xnselector *selector,
		   unsigned int type);

void rtdm_fd_cleanup(struct steely_ppd *p);

void rtdm_fd_init(void);

#endif /* _STEELY_KERNEL_FD_H */
