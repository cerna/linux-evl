/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
 * Copyright (C) 2013,2014 Gilles Chanteperdrix <gch@xenomai.org>.
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
#include <linux/list.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/kthread.h>
#include <linux/fdtable.h>
#include <linux/irq_work.h>
#include <steely/registry.h>
#include <steely/lock.h>
#include <trace/events/steely.h>
#include <steely/fd.h>
#include <steely/process.h>
#include <steely/syscall.h>
#include "internal.h"

#define RTDM_SETFL_MASK (O_NONBLOCK)

DEFINE_PRIVATE_XNLOCK(fdtree_lock);
static LIST_HEAD(rtdm_fd_cleanup_queue);
static struct semaphore rtdm_fd_cleanup_sem;
static DEFINE_PER_CPU(struct irq_work, trigger_close);

struct rtdm_fd_index {
	struct xnid id;
	struct rtdm_fd *fd;
};

static int enosys(void)
{
	return -ENOSYS;
}

static int enodev(void)
{
	return -ENODEV;
}

static void nop_close(struct rtdm_fd *fd)
{
}

static inline struct rtdm_fd_index *
fetch_fd_index(struct steely_ppd *p, int ufd)
{
	struct xnid *id = xnid_fetch(&p->fds, ufd);
	if (id == NULL)
		return NULL;

	return container_of(id, struct rtdm_fd_index, id);
}

static struct rtdm_fd *fetch_fd(struct steely_ppd *p, int ufd)
{
	struct rtdm_fd_index *idx = fetch_fd_index(p, ufd);
	if (idx == NULL)
		return NULL;

	return idx->fd;
}

#define assign_invalid_handler(__handler)				\
	do								\
		(__handler) = (typeof(__handler))enodev;		\
	while (0)

/* Calling this handler should beget ENODEV if not implemented. */
#define assign_invalid_default_handler(__handler)			\
	do								\
		if ((__handler) == NULL)				\
			(__handler) = (typeof(__handler))enodev;	\
	while (0)

#define __assign_default_handler(__handler, __placeholder)		\
	do								\
		if ((__handler) == NULL)				\
			(__handler) = (typeof(__handler))__placeholder;	\
	while (0)

/* Calling this handler should beget ENOSYS if not implemented. */
#define assign_default_handler(__handler)				\
	__assign_default_handler(__handler, enosys)

#define __rt(__handler)		__handler ## _rt
#define __nrt(__handler)	__handler ## _nrt

/*
 * Install a placeholder returning ENODEV if none of the dual handlers
 * are implemented, ENOSYS otherwise for NULL handlers to trigger the
 * adaptive switch.
 */
#define assign_default_dual_handlers(__handler)				\
	do								\
		if (__rt(__handler) || __nrt(__handler)) {		\
			assign_default_handler(__rt(__handler));	\
			assign_default_handler(__nrt(__handler));	\
		} else {						\
			assign_invalid_handler(__rt(__handler));	\
			assign_invalid_handler(__nrt(__handler));	\
		}							\
	while (0)

#ifdef CONFIG_STEELY_ARCH_SYS3264

static inline void set_compat_bit(struct rtdm_fd *fd)
{
	struct pt_regs *regs;

	if (steely_ppd_get(0) == &steely_kernel_ppd)
		fd->compat = 0;
	else {
		regs = task_pt_regs(current);
		STEELY_BUG_ON(STEELY, !__xn_syscall_p(regs));
		fd->compat = __STEELY_CALL_COMPAT(__xn_reg_sys(regs));
	}
}

#else	/* !CONFIG_STEELY_ARCH_SYS3264 */

static inline void set_compat_bit(struct rtdm_fd *fd)
{
}

#endif	/* !CONFIG_STEELY_ARCH_SYS3264 */

int rtdm_fd_enter(struct rtdm_fd *fd, int ufd, unsigned int magic,
		  struct rtdm_fd_ops *ops)
{
	struct rtdm_fd_index *idx;
	struct steely_ppd *ppd;
	spl_t s;
	int ret;

	secondary_mode_only();

	if (magic == 0)
		return -EINVAL;

	idx = kmalloc(sizeof(*idx), GFP_KERNEL);
	if (idx == NULL)
		return -ENOMEM;

	assign_default_dual_handlers(ops->ioctl);
	assign_default_dual_handlers(ops->read);
	assign_default_dual_handlers(ops->write);
	assign_default_dual_handlers(ops->recvmsg);
	assign_default_dual_handlers(ops->sendmsg);
	assign_invalid_default_handler(ops->select);
	assign_invalid_default_handler(ops->mmap);
	__assign_default_handler(ops->close, nop_close);

	ppd = steely_ppd_get(0);
	fd->magic = magic;
	fd->ops = ops;
	fd->owner = ppd;
	fd->refs = 1;
	set_compat_bit(fd);

	idx->fd = fd;

	xnlock_get_irqsave(&fdtree_lock, s);
	ret = xnid_enter(&ppd->fds, &idx->id, ufd);
	xnlock_put_irqrestore(&fdtree_lock, s);
	if (ret < 0) {
		kfree(idx);
		ret = -EBUSY;
	}

	return ret;
}

struct rtdm_fd *rtdm_fd_get(int ufd, unsigned int magic)
{
	struct steely_ppd *p = steely_ppd_get(0);
	struct rtdm_fd *fd;
	spl_t s;

	xnlock_get_irqsave(&fdtree_lock, s);
	fd = fetch_fd(p, ufd);
	if (fd == NULL || (magic != 0 && fd->magic != magic)) {
		fd = ERR_PTR(-EBADF);
		goto out;
	}

	++fd->refs;
out:
	xnlock_put_irqrestore(&fdtree_lock, s);

	return fd;
}
EXPORT_SYMBOL_GPL(rtdm_fd_get);

static int fd_cleanup_thread(void *data)
{
	struct rtdm_fd *fd;
	int err;
	spl_t s;

	for (;;) {
		set_cpus_allowed_ptr(current, cpu_online_mask);

		do {
			err = down_killable(&rtdm_fd_cleanup_sem);
		} while (err && !kthread_should_stop());

		if (kthread_should_stop())
			break;

		xnlock_get_irqsave(&fdtree_lock, s);
		fd = list_first_entry(&rtdm_fd_cleanup_queue,
				struct rtdm_fd, cleanup);
		list_del(&fd->cleanup);
		xnlock_put_irqrestore(&fdtree_lock, s);

		fd->ops->close(fd);
	}

	return 0;
}

static void lostage_trigger_close(struct irq_work *work)
{
	up(&rtdm_fd_cleanup_sem);
}

static void __put_fd(struct rtdm_fd *fd, spl_t s)
{
	int destroy;

	destroy = --fd->refs == 0;
	xnlock_put_irqrestore(&fdtree_lock, s);

	if (!destroy)
		return;

	if (on_root_stage())
		fd->ops->close(fd);
	else {
		xnlock_get_irqsave(&fdtree_lock, s);
		list_add_tail(&fd->cleanup, &rtdm_fd_cleanup_queue);
		xnlock_put_irqrestore(&fdtree_lock, s);
		irq_work_queue(raw_cpu_ptr(&trigger_close));
	}
}

void rtdm_fd_put(struct rtdm_fd *fd)
{
	spl_t s;

	xnlock_get_irqsave(&fdtree_lock, s);
	__put_fd(fd, s);
}
EXPORT_SYMBOL_GPL(rtdm_fd_put);

int rtdm_fd_lock(struct rtdm_fd *fd)
{
	spl_t s;

	xnlock_get_irqsave(&fdtree_lock, s);
	if (fd->refs == 0) {
		xnlock_put_irqrestore(&fdtree_lock, s);
		return -EIDRM;
	}
	++fd->refs;
	xnlock_put_irqrestore(&fdtree_lock, s);

	return 0;
}
EXPORT_SYMBOL_GPL(rtdm_fd_lock);

void rtdm_fd_unlock(struct rtdm_fd *fd)
{
	spl_t s;

	xnlock_get_irqsave(&fdtree_lock, s);
	/* Warn if fd was unreferenced. */
	STEELY_WARN_ON(STEELY, fd->refs <= 0);
	__put_fd(fd, s);
}
EXPORT_SYMBOL_GPL(rtdm_fd_unlock);

int rtdm_fd_fcntl(int ufd, int cmd, ...)
{
	struct rtdm_fd *fd;
	va_list ap;
	int arg;
	int ret;

	fd = rtdm_fd_get(ufd, 0);
	if (IS_ERR(fd))
		return PTR_ERR(fd);

	va_start(ap, cmd);
	arg = va_arg(ap, int);
	va_end(ap);

	switch (cmd) {
	case F_GETFL:
		ret = fd->oflags;
		break;
	case F_SETFL:
		fd->oflags = (fd->oflags & ~RTDM_SETFL_MASK) |
			(arg & RTDM_SETFL_MASK);
		ret = 0;
		break;
	default:
		ret = -EINVAL;
	}

	rtdm_fd_put(fd);

	return ret;
}
EXPORT_SYMBOL_GPL(rtdm_fd_fcntl);

static struct rtdm_fd *get_fd_fixup_mode(int ufd)
{
	struct steely_thread *thread;
	struct rtdm_fd *fd;
	
	fd = rtdm_fd_get(ufd, 0);
	if (IS_ERR(fd))
		return fd;

	/*
	 * Mode is selected according to the following convention:
	 *
	 * - Steely threads must try running the syscall from primary
	 * mode as a first attempt, regardless of their scheduling
	 * class. The driver handler may ask for demoting the caller
	 * to secondary mode by returning -ENOSYS.
	 *
	 * - Regular threads (i.e. not bound to Steely) may only run
	 * the syscall from secondary mode.
	 */
	thread = steely_current_thread();
	if (unlikely(on_root_stage())) {
		if (thread == NULL ||
		    xnthread_test_localinfo(thread, XNDESCENT))
			return fd;
	} else if (likely(thread))
		return fd;

	/*
	 * We need to switch to the converse mode. Since all callers
	 * bear the "adaptive" tag, we just pass -ENOSYS back to the
	 * syscall dispatcher to get switched to the next mode.
	 */
	rtdm_fd_put(fd);

	return ERR_PTR(-ENOSYS);
}

int rtdm_fd_ioctl(int ufd, unsigned int request, ...)
{
	struct rtdm_fd *fd;
	void __user *arg;
	va_list args;
	int err, ret;

	fd = get_fd_fixup_mode(ufd);
	if (IS_ERR(fd)) {
		err = PTR_ERR(fd);
		goto out;
	}

	va_start(args, request);
	arg = va_arg(args, void __user *);
	va_end(args);

	set_compat_bit(fd);

	trace_steely_fd_ioctl(current, fd, ufd, request);

	if (on_root_stage())
		err = fd->ops->ioctl_nrt(fd, request, arg);
	else
		err = fd->ops->ioctl_rt(fd, request, arg);

	if (!STEELY_ASSERT(STEELY, !spltest()))
		splnone();

	if (err < 0) {
		ret = __rtdm_dev_ioctl_core(fd, request, arg);
		if (ret != -ENOSYS)
			err = ret;
	}

	rtdm_fd_put(fd);
  out:
	if (err < 0)
		trace_steely_fd_ioctl_status(current, fd, ufd, err);

	return err;
}
EXPORT_SYMBOL_GPL(rtdm_fd_ioctl);

ssize_t
rtdm_fd_read(int ufd, void __user *buf, size_t size)
{
	struct rtdm_fd *fd;
	ssize_t ret;

	fd = get_fd_fixup_mode(ufd);
	if (IS_ERR(fd)) {
		ret = PTR_ERR(fd);
		goto out;
	}

	set_compat_bit(fd);

	trace_steely_fd_read(current, fd, ufd, size);

	if (on_root_stage())
		ret = fd->ops->read_nrt(fd, buf, size);
	else
		ret = fd->ops->read_rt(fd, buf, size);

	if (!STEELY_ASSERT(STEELY, !spltest()))
		    splnone();

	rtdm_fd_put(fd);

  out:
	if (ret < 0)
		trace_steely_fd_read_status(current, fd, ufd, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(rtdm_fd_read);

ssize_t rtdm_fd_write(int ufd, const void __user *buf, size_t size)
{
	struct rtdm_fd *fd;
	ssize_t ret;

	fd = get_fd_fixup_mode(ufd);
	if (IS_ERR(fd)) {
		ret = PTR_ERR(fd);
		goto out;
	}

	set_compat_bit(fd);

	trace_steely_fd_write(current, fd, ufd, size);

	if (on_root_stage())
		ret = fd->ops->write_nrt(fd, buf, size);
	else
		ret = fd->ops->write_rt(fd, buf, size);

	if (!STEELY_ASSERT(STEELY, !spltest()))
		splnone();

	rtdm_fd_put(fd);

  out:
	if (ret < 0)
		trace_steely_fd_write_status(current, fd, ufd, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(rtdm_fd_write);

ssize_t rtdm_fd_recvmsg(int ufd, struct user_msghdr *msg, int flags)
{
	struct rtdm_fd *fd;
	ssize_t ret;

	fd = get_fd_fixup_mode(ufd);
	if (IS_ERR(fd)) {
		ret = PTR_ERR(fd);
		goto out;
	}

	set_compat_bit(fd);

	trace_steely_fd_recvmsg(current, fd, ufd, flags);

	if (on_root_stage())
		ret = fd->ops->recvmsg_nrt(fd, msg, flags);
	else
		ret = fd->ops->recvmsg_rt(fd, msg, flags);

	if (!STEELY_ASSERT(STEELY, !spltest()))
		splnone();

	rtdm_fd_put(fd);
out:
	if (ret < 0)
		trace_steely_fd_recvmsg_status(current, fd, ufd, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(rtdm_fd_recvmsg);

ssize_t rtdm_fd_sendmsg(int ufd, const struct user_msghdr *msg, int flags)
{
	struct rtdm_fd *fd;
	ssize_t ret;

	fd = get_fd_fixup_mode(ufd);
	if (IS_ERR(fd)) {
		ret = PTR_ERR(fd);
		goto out;
	}

	set_compat_bit(fd);

	trace_steely_fd_sendmsg(current, fd, ufd, flags);

	if (on_root_stage())
		ret = fd->ops->sendmsg_nrt(fd, msg, flags);
	else
		ret = fd->ops->sendmsg_rt(fd, msg, flags);

	if (!STEELY_ASSERT(STEELY, !spltest()))
		splnone();

	rtdm_fd_put(fd);
out:
	if (ret < 0)
		trace_steely_fd_sendmsg_status(current, fd, ufd, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(rtdm_fd_sendmsg);

static void
__fd_close(struct steely_ppd *p, struct rtdm_fd_index *idx, spl_t s)
{
	xnid_remove(&p->fds, &idx->id);
	__put_fd(idx->fd, s);

	kfree(idx);
}

int rtdm_fd_close(int ufd, unsigned int magic)
{
	struct rtdm_fd_index *idx;
	struct steely_ppd *ppd;
	struct rtdm_fd *fd;
	spl_t s;

	secondary_mode_only();

	ppd = steely_ppd_get(0);

	xnlock_get_irqsave(&fdtree_lock, s);
	idx = fetch_fd_index(ppd, ufd);
	if (idx == NULL)
		goto ebadf;

	fd = idx->fd;
	if (magic != 0 && fd->magic != magic) {
ebadf:
		xnlock_put_irqrestore(&fdtree_lock, s);
		return -EBADF;
	}

	set_compat_bit(fd);

	trace_steely_fd_close(current, fd, ufd, fd->refs);

	/*
	 * In dual kernel mode, the linux-side fdtable and the RTDM
	 * ->close() handler are asynchronously managed, i.e.  the
	 * handler execution may be deferred after the regular file
	 * descriptor was removed from the fdtable if some refs on
	 * rtdm_fd are still pending.
	 */
	__fd_close(ppd, idx, s);
	__close_fd(current->files, ufd);

	return 0;
}
EXPORT_SYMBOL_GPL(rtdm_fd_close);

int rtdm_fd_mmap(int ufd, struct _rtdm_mmap_request *rma,
		 void **u_addrp)
{
	struct rtdm_fd *fd;
	int ret;

	secondary_mode_only();

	fd = rtdm_fd_get(ufd, 0);
	if (IS_ERR(fd)) {
		ret = PTR_ERR(fd);
		goto out;
	}

	set_compat_bit(fd);

	trace_steely_fd_mmap(current, fd, ufd, rma);

	if (rma->flags & (MAP_FIXED|MAP_ANONYMOUS)) {
		ret = -ENODEV;
		goto unlock;
	}

	ret = __rtdm_mmap_from_fdop(fd, rma->length, rma->offset,
				    rma->prot, rma->flags, u_addrp);
unlock:
	rtdm_fd_put(fd);
out:
	if (ret)
		trace_steely_fd_mmap_status(current, fd, ufd, ret);

	return ret;
}

int rtdm_fd_valid_p(int ufd)
{
	struct rtdm_fd *fd;
	spl_t s;

	xnlock_get_irqsave(&fdtree_lock, s);
	fd = fetch_fd(steely_ppd_get(0), ufd);
	xnlock_put_irqrestore(&fdtree_lock, s);

	return fd != NULL;
}

int rtdm_fd_select(int ufd, struct xnselector *selector,
		   unsigned int type)
{
	struct rtdm_fd *fd;
	int ret;

	fd = rtdm_fd_get(ufd, 0);
	if (IS_ERR(fd))
		return PTR_ERR(fd);

	set_compat_bit(fd);

	ret = fd->ops->select(fd, selector, type, ufd);

	if (!STEELY_ASSERT(STEELY, !spltest()))
		splnone();

	rtdm_fd_put(fd);

	return ret;
}

static void destroy_fd(void *cookie, struct xnid *id)
{
	struct steely_ppd *p = cookie;
	struct rtdm_fd_index *idx;
	spl_t s;

	idx = container_of(id, struct rtdm_fd_index, id);
	xnlock_get_irqsave(&fdtree_lock, s);
	__fd_close(p, idx, 0);
}

void rtdm_fd_cleanup(struct steely_ppd *p)
{
	/*
	 * This is called on behalf of a (userland) task exit handler,
	 * so we don't have to deal with the regular file descriptors,
	 * we only have to empty our own index.
	 */
	xntree_cleanup(&p->fds, p, destroy_fd);
}

void rtdm_fd_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		init_irq_work(&per_cpu(trigger_close, cpu),
			      lostage_trigger_close);

	sema_init(&rtdm_fd_cleanup_sem, 0);
	kthread_run(fd_cleanup_thread, NULL, "rtdm_fd");
}

static inline void warn_user(struct file *file, const char *call)
{
	struct dentry *dentry = file->f_path.dentry;
	
	printk(STEELY_WARNING
	       "%s[%d] called regular %s() on /dev/rtdm/%s\n",
	       current->comm, task_pid_nr(current), call + 5, dentry->d_name.name);
}

static ssize_t dumb_read(struct file *file, char  __user *buf,
			 size_t count, loff_t __user *ppos)
{
	warn_user(file, __func__);
	return -EINVAL;
}

static ssize_t dumb_write(struct file *file,  const char __user *buf,
			  size_t count, loff_t __user *ppos)
{
	warn_user(file, __func__);
	return -EINVAL;
}

static unsigned int dumb_poll(struct file *file, poll_table *pt)
{
	warn_user(file, __func__);
	return -EINVAL;
}

static long dumb_ioctl(struct file *file, unsigned int cmd,
		       unsigned long arg)
{
	warn_user(file, __func__);
	return -EINVAL;
}

const struct file_operations rtdm_dumb_fops = {
	.read		= dumb_read,
	.write		= dumb_write,
	.poll		= dumb_poll,
	.unlocked_ioctl	= dumb_ioctl,
};
