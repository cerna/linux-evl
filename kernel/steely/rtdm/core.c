/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
 * Copyright (C) 2014 Philippe Gerum <rpm@xenomai.org>
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
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/anon_inodes.h>
#include <steely/ppd.h>
#include <steely/heap.h>
#include "rtdm/internal.h"
#define CREATE_TRACE_POINTS
#include <trace/events/steely-rtdm.h>
#include "posix/process.h"

static void cleanup_instance(struct rtdm_device *dev,
			     struct rtdm_dev_context *context)
{
	if (context)
		kfree(context);

	__rtdm_put_device(dev);
}

void __rtdm_dev_close(struct rtdm_fd *fd)
{
	struct rtdm_dev_context *context = rtdm_fd_to_context(fd);
	struct rtdm_device *dev = context->device;
	struct rtdm_driver *drv = dev->driver;

	if (drv->ops.close)
		drv->ops.close(fd);

	cleanup_instance(dev, context);
}

int __rtdm_anon_getfd(const char *name, int flags)
{
	return anon_inode_getfd(name, &rtdm_dumb_fops, NULL, flags);
}

void __rtdm_anon_putfd(int ufd)
{
	__close_fd(current->files, ufd);
}

static int create_instance(int ufd, struct rtdm_device *dev,
			   struct rtdm_dev_context **context_ptr)
{
	struct rtdm_driver *drv = dev->driver;
	struct rtdm_dev_context *context;

	/*
	 * Reset to NULL so that we can always use cleanup_files/instance to
	 * revert also partially successful allocations.
	 */
	*context_ptr = NULL;

	if ((drv->device_flags & RTDM_EXCLUSIVE) != 0 &&
	    atomic_read(&dev->refcount) > 1)
		return -EBUSY;

	context = kzalloc(sizeof(struct rtdm_dev_context) +
			  drv->context_size, GFP_KERNEL);
	if (unlikely(context == NULL))
		return -ENOMEM;

	context->device = dev;
	*context_ptr = context;

	return rtdm_fd_enter(&context->fd, ufd, RTDM_FD_MAGIC, &dev->ops);
}

static inline struct file *
open_devnode(struct rtdm_device *dev, const char *path, int oflag)
{
	return filp_open(path, oflag, 0);
}

int __rtdm_dev_open(const char *path, int oflag)
{
	struct rtdm_dev_context *context;
	struct rtdm_device *dev;
	struct file *filp;
	int ufd, ret;

	secondary_mode_only();

	/*
	 * CAUTION: we do want a lookup into the registry to happen
	 * before any attempt is made to open the devnode, so that we
	 * don't inadvertently open a regular (i.e. non-RTDM) device.
	 * Reason is that opening, then closing a device - because we
	 * don't manage it - may incur side-effects we don't want,
	 * e.g. opening then closing one end of a pipe would cause the
	 * other side to read the EOF condition.  This is basically
	 * why we keep a RTDM registry for named devices, so that we
	 * can figure out whether an open() request is going to be
	 * valid, without having to open the devnode yet.
	 */
	dev = __rtdm_get_namedev(path);
	if (dev == NULL)
		return -ENODEV;

	ufd = get_unused_fd_flags(oflag);
	if (ufd < 0) {
		ret = ufd;
		goto fail_fd;
	}

	filp = open_devnode(dev, path, oflag);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		goto fail_fopen;
	}

	ret = create_instance(ufd, dev, &context);
	if (ret < 0)
		goto fail_create;

	context->fd.minor = dev->minor;
	context->fd.oflags = oflag;

	trace_steely_fd_open(current, &context->fd, ufd, oflag);

	if (dev->ops.open) {
		ret = dev->ops.open(&context->fd, oflag);
		if (!STEELY_ASSERT(STEELY, !spltest()))
			splnone();
		if (ret < 0)
			goto fail_open;
	}

	fd_install(ufd, filp);

	trace_steely_fd_created(&context->fd, ufd);

	return ufd;

fail_open:
	cleanup_instance(dev, context);
fail_create:
	filp_close(filp, current->files);
fail_fopen:
	put_unused_fd(ufd);
fail_fd:
	__rtdm_put_device(dev);

	return ret;
}
EXPORT_SYMBOL_GPL(__rtdm_dev_open);

int __rtdm_dev_socket(int protocol_family, int socket_type,
		      int protocol)
{
	struct rtdm_dev_context *context;
	struct rtdm_device *dev;
	int ufd, ret;

	secondary_mode_only();

	dev = __rtdm_get_protodev(protocol_family, socket_type);
	if (dev == NULL)
		return -EAFNOSUPPORT;

	ufd = __rtdm_anon_getfd("[rtdm-socket]", O_RDWR);
	if (ufd < 0) {
		ret = ufd;
		goto fail_getfd;
	}

	ret = create_instance(ufd, dev, &context);
	if (ret < 0)
		goto fail_create;

	trace_steely_fd_socket(current, &context->fd, ufd, protocol_family);

	if (dev->ops.socket) {
		ret = dev->ops.socket(&context->fd, protocol);
		if (!STEELY_ASSERT(STEELY, !spltest()))
			splnone();
		if (ret < 0)
			goto fail_socket;
	}

	trace_steely_fd_created(&context->fd, ufd);

	return ufd;

fail_socket:
	cleanup_instance(dev, context);
fail_create:
	__close_fd(current->files, ufd);
fail_getfd:
	__rtdm_put_device(dev);

	return ret;
}
EXPORT_SYMBOL_GPL(__rtdm_dev_socket);

int __rtdm_dev_ioctl_core(struct rtdm_fd *fd, unsigned int request,
			  void __user *arg)
{
	struct rtdm_device *dev = rtdm_fd_device(fd);
	struct rtdm_driver *drv = dev->driver;
	struct rtdm_device_info dev_info;

	if (fd->magic != RTDM_FD_MAGIC || request != RTIOC_DEVICE_INFO)
		return -ENOSYS;

	dev_info.device_flags = drv->device_flags;
	dev_info.device_class = drv->profile_info.class_id;
	dev_info.device_sub_class = drv->profile_info.subclass_id;
	dev_info.profile_version = drv->profile_info.version;

	return rtdm_safe_copy_to_user(fd, arg, &dev_info,  sizeof(dev_info));
}
