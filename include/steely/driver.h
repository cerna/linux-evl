/*
 * Real-Time Driver Model for Xenomai, driver API header
 *
 * Copyright (C) 2005-2007 Jan Kiszka <jan.kiszka@web.de>
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>
 * Copyright (C) 2008 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
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
 *
 * @ingroup driverapi
 */
#ifndef _STEELY_RTDM_DRIVER_H
#define _STEELY_RTDM_DRIVER_H

#include <asm/atomic.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/notifier.h>
#include <steely/version.h>
#include <steely/heap.h>
#include <steely/sched.h>
#include <steely/intr.h>
#include <steely/synch.h>
#include <steely/select.h>
#include <steely/clock.h>
#include <steely/init.h>
#include <steely/ancillaries.h>
#include <steely/tree.h>
#include <steely/fd.h>
#include <steely/rtdm.h>
#include <steely/process.h>

/* debug support */
#include <steely/assert.h>
#ifdef CONFIG_PCI
#include <asm-generic/steely/pci_ids.h>
#endif /* CONFIG_PCI */
#include <asm/steely/syscall.h>

struct class;
typedef struct xnselector rtdm_selector_t;
enum rtdm_selecttype;

/* If set, only a single instance of the device can be requested by an
 *  application. */
#define RTDM_EXCLUSIVE			0x0001

/*
 * Use fixed minor provided in the rtdm_device description for
 * registering. If this flag is absent, the RTDM core assigns minor
 * numbers to devices managed by a driver in order of registration.
 */
#define RTDM_FIXED_MINOR		0x0002

/* If set, the device is addressed via a clear-text name. */
#define RTDM_NAMED_DEVICE		0x0010

/* If set, the device is addressed via a combination of protocol ID and
 *  socket type. */
#define RTDM_PROTOCOL_DEVICE		0x0020

/* Mask selecting the device type. */
#define RTDM_DEVICE_TYPE_MASK		0x00F0

/* Flag indicating a secure variant of RTDM (not supported here) */
#define RTDM_SECURE_DEVICE		0x80000000

/* Maximum number of named devices per driver. */
#define RTDM_MAX_MINOR	1024

enum rtdm_selecttype {
	/* Select input data availability events */
	RTDM_SELECTTYPE_READ = XNSELECT_READ,

	/* Select ouput buffer availability events */
	RTDM_SELECTTYPE_WRITE = XNSELECT_WRITE,

	/* Select exceptional events */
	RTDM_SELECTTYPE_EXCEPT = XNSELECT_EXCEPT
};

struct rtdm_dev_context {
	struct rtdm_fd fd;

	/* Set of active device operation handlers */
	/* Reference to owning device */
	struct rtdm_device *device;

	/* Begin of driver defined context data structure */
	char dev_private[0];
};

static inline struct rtdm_dev_context *rtdm_fd_to_context(struct rtdm_fd *fd)
{
	return container_of(fd, struct rtdm_dev_context, fd);
}

static inline void *rtdm_fd_to_private(struct rtdm_fd *fd)
{
	return &rtdm_fd_to_context(fd)->dev_private[0];
}

static inline struct rtdm_fd *rtdm_private_to_fd(void *dev_private)
{
	struct rtdm_dev_context *ctx;
	ctx = container_of(dev_private, struct rtdm_dev_context, dev_private);
	return &ctx->fd;
}

static inline bool rtdm_fd_is_user(struct rtdm_fd *fd)
{
	return rtdm_fd_owner(fd) != &steely_kernel_ppd;
}

static inline struct rtdm_device *rtdm_fd_device(struct rtdm_fd *fd)
{
	return rtdm_fd_to_context(fd)->device;
}

struct rtdm_profile_info {
	/* Device class name */
	const char *name;
	/* Device class ID */
	int class_id;
  	/* Device sub-class */
	int subclass_id;
	/* Supported device profile version */
	int version;
	/* Reserved */
	unsigned int magic;
	struct module *owner;
	struct class *kdev_class;
};

struct rtdm_driver;

struct rtdm_sm_ops {
	/* Handler called upon transition to STEELY_STATE_WARMUP */ 
	int (*start)(struct rtdm_driver *drv);
	/* Handler called upon transition to STEELY_STATE_TEARDOWN */ 
	int (*stop)(struct rtdm_driver *drv);
};

struct rtdm_driver {
	/*
	 * Class profile information. The RTDM_PROFILE_INFO() macro @b
	 * must be used for filling up this field.
	 * @anchor rtdm_driver_profile
	 */
	struct rtdm_profile_info profile_info;
	/*
	 * Device flags
	 */
	int device_flags;
	/*
	 * Size of the private memory area the core should
	 * automatically allocate for each open file descriptor, which
	 * is usable for storing the context data associated to each
	 * connection. The allocated memory is zero-initialized. The
	 * start of this area can be retrieved by a call to
	 * rtdm_fd_to_private().
	 */
	size_t context_size;
	/* Protocol device identification: protocol family (PF_xxx) */
	int protocol_family;
	/* Protocol device identification: socket type (SOCK_xxx) */
	int socket_type;
	/* I/O operation handlers */
	struct rtdm_fd_ops ops;
	/* State management handlers */
	struct rtdm_sm_ops smops;
	/*
	 * Count of devices this driver manages. This value is used to
	 * allocate a chrdev region for named devices.
	 */
	int device_count;
	/* Base minor for named devices. */
	int base_minor;
	/* Reserved area */
	struct {
		union {
			struct {
				struct cdev cdev;
				int major;
			} named;
		};
		atomic_t refcount;
		struct notifier_block nb_statechange;
		DECLARE_BITMAP(minor_map, RTDM_MAX_MINOR);
	};
};

#define RTDM_CLASS_MAGIC	0x8284636c

#define RTDM_PROFILE_INFO(__name, __id, __subid, __version)	\
{								\
	.name = ( # __name ),					\
	.class_id = (__id),					\
	.subclass_id = (__subid),				\
	.version = (__version),					\
	.magic = ~RTDM_CLASS_MAGIC,				\
	.owner = THIS_MODULE,					\
	.kdev_class = NULL,					\
}

int rtdm_drv_set_sysclass(struct rtdm_driver *drv, struct class *cls);

struct rtdm_device {
	/* Device driver. */
	struct rtdm_driver *driver;
	/* Driver definable device data */
	void *device_data;
	/*
	 * Device label template for composing the device name. A
	 * limited printf-like format string is assumed, with a
	 * provision for replacing the first %d/%i placeholder found
	 * in the string by the device minor number.  It is up to the
	 * driver to actually mention this placeholder or not,
	 * depending on the naming convention for its devices.  For
	 * named devices, the corresponding device node will
	 * automatically appear in the /dev/rtdm hierachy with
	 * hotplug-enabled device filesystems (DEVTMPFS).
	 */
	const char *label;
	/*
	 * Minor number of the device. If RTDM_FIXED_MINOR is present
	 * in the driver flags, the value stored in this field is used
	 * verbatim by rtdm_dev_register(). Otherwise, the RTDM core
	 * automatically assigns minor numbers to all devices managed
	 * by the driver referred to by @a driver, in order of
	 * registration, storing the resulting values into this field.
	 *
	 * Device nodes created for named devices in the Linux /dev
	 * hierarchy are assigned this minor number.
	 *
	 * The minor number of the current device handling an I/O
	 * request can be retreived by a call to rtdm_fd_minor().
	 */
	int minor;
	/* Reserved area. */
	struct {
		unsigned int magic;
		char *name;
		union {
			struct {
				xnhandle_t handle;
			} named;
			struct {
				struct xnid id;
			} proto;
		};
		dev_t rdev;
		struct device *kdev;
		struct class *kdev_class;
		atomic_t refcount;
		struct rtdm_fd_ops ops;
		wait_queue_head_t putwq;
	};
};

int rtdm_dev_register(struct rtdm_device *device);

void rtdm_dev_unregister(struct rtdm_device *device);

static inline struct device *rtdm_dev_to_kdev(struct rtdm_device *device)
{
	return device->kdev;
}

/* --- clock services --- */
static inline nanosecs_abs_t rtdm_clock_read(void)
{
	return xnclock_read_realtime(&nkclock);
}

static inline nanosecs_abs_t rtdm_clock_read_monotonic(void)
{
	return xnclock_read_monotonic(&nkclock);
}

/* --- timeout sequences */

typedef nanosecs_abs_t rtdm_toseq_t;

void rtdm_toseq_init(rtdm_toseq_t *timeout_seq, nanosecs_rel_t timeout);

#define steely_atomic_enter(__context)				\
	do {							\
		xnlock_get_irqsave(&nklock, (__context));	\
		xnsched_lock();					\
	} while (0)

#define steely_atomic_leave(__context)				\
	do {							\
		xnsched_unlock();				\
		xnlock_put_irqrestore(&nklock, (__context));	\
	} while (0)


#define RTDM_LOCK_UNLOCKED(__name)	HARD_SPIN_LOCK_UNLOCKED

#define DEFINE_RTDM_LOCK(__name)		\
	rtdm_lock_t __name = RTDM_LOCK_UNLOCKED(__name)

/* Lock variable */
typedef hard_spinlock_t rtdm_lock_t;

/* Variable to save the context while holding a lock */
typedef unsigned long rtdm_lockctx_t;

static inline void rtdm_lock_init(rtdm_lock_t *lock)
{
	raw_spin_lock_init(lock);
}

static inline void rtdm_lock_get(rtdm_lock_t *lock)
{
	STEELY_BUG_ON(STEELY, !spltest());
	raw_spin_lock(lock);
	xnsched_lock();
}

static inline void rtdm_lock_put(rtdm_lock_t *lock)
{
	raw_spin_unlock(lock);
	xnsched_unlock();
}

#define rtdm_lock_get_irqsave(__lock, __context)	\
	((__context) = __rtdm_lock_get_irqsave(__lock))

static inline rtdm_lockctx_t __rtdm_lock_get_irqsave(rtdm_lock_t *lock)
{
	rtdm_lockctx_t context;

	context = head_irq_save();
	raw_spin_lock(lock);
	xnsched_lock();

	return context;
}

static inline
void rtdm_lock_put_irqrestore(rtdm_lock_t *lock, rtdm_lockctx_t context)
{
	raw_spin_unlock(lock);
	xnsched_unlock();
	head_irq_restore(context);
}

#define rtdm_lock_irqsave(__context)	\
	splhigh(__context)

#define rtdm_lock_irqrestore(__context)	\
	splexit(__context)

struct rtdm_waitqueue {
	struct xnsynch wait;
};
typedef struct rtdm_waitqueue rtdm_waitqueue_t;

#define RTDM_WAITQUEUE_INITIALIZER(__name) {		 \
	    .wait = XNSYNCH_WAITQUEUE_INITIALIZER((__name).wait), \
	}

#define DEFINE_RTDM_WAITQUEUE(__name)				\
	struct rtdm_waitqueue __name = RTDM_WAITQUEUE_INITIALIZER(__name)

#define DEFINE_RTDM_WAITQUEUE_ONSTACK(__name)	\
	DEFINE_RTDM_WAITQUEUE(__name)

static inline void rtdm_waitqueue_init(struct rtdm_waitqueue *wq)
{
	*wq = (struct rtdm_waitqueue)RTDM_WAITQUEUE_INITIALIZER(*wq);
}

static inline void rtdm_waitqueue_destroy(struct rtdm_waitqueue *wq)
{
	xnsynch_destroy(&wq->wait);
}

static inline int __rtdm_dowait(struct rtdm_waitqueue *wq,
				nanosecs_rel_t timeout, xntmode_t timeout_mode)
{
	int ret;
	
	ret = xnsynch_sleep_on(&wq->wait, timeout, timeout_mode);
	if (ret & XNBREAK)
		return -EINTR;
	if (ret & XNTIMEO)
		return -ETIMEDOUT;
	if (ret & XNRMID)
		return -EIDRM;
	return 0;
}

static inline int __rtdm_timedwait(struct rtdm_waitqueue *wq,
				   nanosecs_rel_t timeout, rtdm_toseq_t *toseq)
{
	if (toseq && timeout > 0)
		return __rtdm_dowait(wq, *toseq, XN_ABSOLUTE);

	return __rtdm_dowait(wq, timeout, XN_RELATIVE);
}

#define rtdm_timedwait_condition_locked(__wq, __cond, __timeout, __toseq) \
	({								\
		int __ret = 0;						\
		while (__ret == 0 && !(__cond))				\
			__ret = __rtdm_timedwait(__wq, __timeout, __toseq); \
		__ret;							\
	})

#define rtdm_wait_condition_locked(__wq, __cond)			\
	({								\
		int __ret = 0;						\
		while (__ret == 0 && !(__cond))				\
			__ret = __rtdm_dowait(__wq,			\
					      XN_INFINITE, XN_RELATIVE); \
		__ret;							\
	})

#define rtdm_timedwait_condition(__wq, __cond, __timeout, __toseq)	\
	({								\
		spl_t __s;						\
		int __ret;						\
		xnlock_get_irqsave(&nklock, __s);			\
		__ret = rtdm_timedwait_condition_locked(__wq, __cond,	\
					      __timeout, __toseq);	\
		xnlock_put_irqrestore(&nklock, __s);			\
		__ret;							\
	})

#define rtdm_timedwait(__wq, __timeout, __toseq)			\
	__rtdm_timedwait(__wq, __timeout, __toseq)

#define rtdm_timedwait_locked(__wq, __timeout, __toseq)			\
	rtdm_timedwait(__wq, __timeout, __toseq)

#define rtdm_wait_condition(__wq, __cond)				\
	({								\
		spl_t __s;						\
		int __ret;						\
		xnlock_get_irqsave(&nklock, __s);			\
		__ret = rtdm_wait_condition_locked(__wq, __cond);	\
		xnlock_put_irqrestore(&nklock, __s);			\
		__ret;							\
	})

#define rtdm_wait(__wq)							\
	__rtdm_dowait(__wq, XN_INFINITE, XN_RELATIVE)

#define rtdm_wait_locked(__wq)  rtdm_wait(__wq)

#define rtdm_waitqueue_lock(__wq, __context)  steely_atomic_enter(__context)

#define rtdm_waitqueue_unlock(__wq, __context)  steely_atomic_leave(__context)

#define rtdm_waitqueue_signal(__wq)					\
	({								\
		struct steely_thread *__waiter;				\
		__waiter = xnsynch_wakeup_one_sleeper(&(__wq)->wait);	\
		xnsched_run();						\
		__waiter != NULL;					\
	})

#define __rtdm_waitqueue_flush(__wq, __reason)				\
	({								\
		int __ret;						\
		__ret = xnsynch_flush(&(__wq)->wait, __reason);		\
		xnsched_run();						\
		__ret == XNSYNCH_RESCHED;				\
	})

#define rtdm_waitqueue_broadcast(__wq)	\
	__rtdm_waitqueue_flush(__wq, 0)

#define rtdm_waitqueue_flush(__wq)	\
	__rtdm_waitqueue_flush(__wq, XNBREAK)

#define rtdm_waitqueue_wakeup(__wq, __waiter)				\
	do {								\
		xnsynch_wakeup_this_sleeper(&(__wq)->wait, __waiter);	\
		xnsched_run();						\
	} while (0)

#define rtdm_for_each_waiter(__pos, __wq)		\
	xnsynch_for_each_sleeper(__pos, &(__wq)->wait)

#define rtdm_for_each_waiter_safe(__pos, __tmp, __wq)	\
	xnsynch_for_each_sleeper_safe(__pos, __tmp, &(__wq)->wait)

typedef struct xnintr rtdm_irq_t;

/* Enable IRQ-sharing with other real-time drivers */
#define RTDM_IRQTYPE_SHARED		XN_IRQTYPE_SHARED
/* Mark IRQ as edge-triggered, relevant for correct handling of shared
 *  edge-triggered IRQs */
#define RTDM_IRQTYPE_EDGE		XN_IRQTYPE_EDGE

typedef int (*rtdm_irq_handler_t)(rtdm_irq_t *irq_handle);

/* Unhandled interrupt */
#define RTDM_IRQ_NONE			XN_IRQ_NONE
/* Denote handled interrupt */
#define RTDM_IRQ_HANDLED		XN_IRQ_HANDLED
/* Request interrupt disabling on exit */
#define RTDM_IRQ_DISABLE		XN_IRQ_DISABLE

#define rtdm_irq_get_arg(irq_handle, type)	((type *)irq_handle->dev_id)

int rtdm_irq_request(rtdm_irq_t *irq_handle, unsigned int irq_no,
		     rtdm_irq_handler_t handler, unsigned long flags,
		     const char *device_name, void *arg);

static inline int rtdm_irq_free(rtdm_irq_t *irq_handle)
{
	if (!STEELY_ASSERT(STEELY, xnsched_root_p()))
		return -EPERM;
	xnintr_detach(irq_handle);
	return 0;
}

static inline int rtdm_irq_enable(rtdm_irq_t *irq_handle)
{
	xnintr_enable(irq_handle);
	return 0;
}

static inline int rtdm_irq_disable(rtdm_irq_t *irq_handle)
{
	xnintr_disable(irq_handle);
	return 0;
}

typedef struct rtdm_nrtsig rtdm_nrtsig_t;
typedef void (*rtdm_nrtsig_handler_t)(rtdm_nrtsig_t *nrt_sig, void *arg);

struct rtdm_nrtsig {
	rtdm_nrtsig_handler_t handler;
	void *arg;
};

void rtdm_schedule_nrt_work(struct work_struct *lostage_work);

static inline void rtdm_nrtsig_init(rtdm_nrtsig_t *nrt_sig,
				rtdm_nrtsig_handler_t handler, void *arg)
{
	nrt_sig->handler = handler;
	nrt_sig->arg = arg;
}

static inline void rtdm_nrtsig_destroy(rtdm_nrtsig_t *nrt_sig)
{
	nrt_sig->handler = NULL;
	nrt_sig->arg = NULL;
}

void rtdm_nrtsig_pend(rtdm_nrtsig_t *nrt_sig);

/* --- timer services --- */
typedef struct xntimer rtdm_timer_t;

typedef void (*rtdm_timer_handler_t)(rtdm_timer_t *timer);

enum rtdm_timer_mode {
	/* Monotonic timer with relative timeout */
	RTDM_TIMERMODE_RELATIVE = XN_RELATIVE,

	/* Monotonic timer with absolute timeout */
	RTDM_TIMERMODE_ABSOLUTE = XN_ABSOLUTE,

	/* Adjustable timer with absolute timeout */
	RTDM_TIMERMODE_REALTIME = XN_REALTIME
};

#define rtdm_timer_init(timer, handler, name)				\
({									\
	xntimer_init((timer), &nkclock, handler,			\
		     NULL, XNTIMER_IGRAVITY);				\
	xntimer_set_name((timer), (name));				\
	0;								\
})

void rtdm_timer_destroy(rtdm_timer_t *timer);

int rtdm_timer_start(rtdm_timer_t *timer, nanosecs_abs_t expiry,
		     nanosecs_rel_t interval, enum rtdm_timer_mode mode);

void rtdm_timer_stop(rtdm_timer_t *timer);

static inline int rtdm_timer_start_in_handler(rtdm_timer_t *timer,
					      nanosecs_abs_t expiry,
					      nanosecs_rel_t interval,
					      enum rtdm_timer_mode mode)
{
	return xntimer_start(timer, expiry, interval, (xntmode_t)mode);
}

static inline void rtdm_timer_stop_in_handler(rtdm_timer_t *timer)
{
	xntimer_stop(timer);
}

/* --- task services --- */

typedef struct steely_thread rtdm_task_t;

typedef void (*rtdm_task_proc_t)(void *arg);

#define RTDM_TASK_LOWEST_PRIORITY	0
#define RTDM_TASK_HIGHEST_PRIORITY	99

#define RTDM_TASK_RAISE_PRIORITY	(+1)
#define RTDM_TASK_LOWER_PRIORITY	(-1)

int rtdm_task_init(rtdm_task_t *task, const char *name,
		   rtdm_task_proc_t task_proc, void *arg,
		   int priority, nanosecs_rel_t period);
int __rtdm_task_sleep(ktime_t timeout, xntmode_t mode);
void rtdm_task_busy_sleep(nanosecs_rel_t delay);

static inline void rtdm_task_destroy(rtdm_task_t *task)
{
	xnthread_cancel(task);
	xnthread_join(task, true);
}

static inline int rtdm_task_should_stop(void)
{
	return xnthread_test_info(steely_current_thread(), XNCANCELD);
}

void rtdm_task_join(rtdm_task_t *task);

static inline void __deprecated rtdm_task_join_nrt(rtdm_task_t *task,
						   unsigned int poll_delay)
{
	rtdm_task_join(task);
}

static inline void rtdm_task_set_priority(rtdm_task_t *task, int priority)
{
	union xnsched_policy_param param = { .rt = { .prio = priority } };
	xnthread_set_schedparam(task, &xnsched_class_rt, &param);
	xnsched_run();
}

static inline int rtdm_task_set_period(rtdm_task_t *task,
				       nanosecs_abs_t start_date,
				       nanosecs_rel_t period)
{
	if (period < 0)
		period = 0;
	if (start_date == 0)
		start_date = XN_INFINITE;

	return xnthread_set_periodic(task, start_date, XN_ABSOLUTE, period);
}

static inline int rtdm_task_unblock(rtdm_task_t *task)
{
	int res = xnthread_unblock(task);

	xnsched_run();
	return res;
}

static inline rtdm_task_t *rtdm_task_current(void)
{
	return steely_current_thread();
}

static inline int rtdm_task_wait_period(unsigned long *overruns_r)
{
	if (!STEELY_ASSERT(STEELY, !xnsched_unblockable_p()))
		return -EPERM;
	return xnthread_wait_period(overruns_r);
}

static inline int rtdm_task_sleep(nanosecs_rel_t delay)
{
	return __rtdm_task_sleep(delay, XN_RELATIVE);
}

static inline int
rtdm_task_sleep_abs(nanosecs_abs_t wakeup_date, enum rtdm_timer_mode mode)
{
	/* For the sake of a consistent API usage... */
	if (mode != RTDM_TIMERMODE_ABSOLUTE && mode != RTDM_TIMERMODE_REALTIME)
		return -EINVAL;
	return __rtdm_task_sleep(wakeup_date, (xntmode_t)mode);
}

/* rtdm_task_sleep_abs shall be used instead */
static inline int __deprecated rtdm_task_sleep_until(nanosecs_abs_t wakeup_time)
{
	return __rtdm_task_sleep(wakeup_time, XN_REALTIME);
}

#define rtdm_task_busy_wait(__condition, __spin_ns, __sleep_ns)			\
	({									\
		__label__ done;							\
		nanosecs_abs_t __end;						\
		int __ret = 0;							\
		for (;;) {							\
			__end = rtdm_clock_read_monotonic() + __spin_ns;	\
			for (;;) {						\
				if (__condition)				\
					goto done;				\
				if (rtdm_clock_read_monotonic() >= __end)	\
					break;					\
			}							\
			__ret = rtdm_task_sleep(__sleep_ns);			\
			if (__ret)						\
				break;						\
		}								\
	done:									\
		__ret;								\
	})

#define rtdm_wait_context	steely_wait_context

static inline
void rtdm_wait_complete(struct rtdm_wait_context *wc)
{
	xnthread_complete_wait(wc);
}

static inline
int rtdm_wait_is_completed(struct rtdm_wait_context *wc)
{
	return xnthread_wait_complete_p(wc);
}

static inline void rtdm_wait_prepare(struct rtdm_wait_context *wc)
{
	xnthread_prepare_wait(wc);
}

static inline
struct rtdm_wait_context *rtdm_wait_get_context(rtdm_task_t *task)
{
	return xnthread_get_wait_context(task);
}

/* --- event services --- */

typedef struct rtdm_event {
	struct xnsynch synch_base;
	DECLARE_XNSELECT(select_block);
} rtdm_event_t;

#define RTDM_EVENT_PENDING		XNSYNCH_SPARE1

void rtdm_event_init(rtdm_event_t *event, unsigned long pending);
int rtdm_event_select(rtdm_event_t *event, rtdm_selector_t *selector,
		      enum rtdm_selecttype type, unsigned fd_index);
int rtdm_event_wait(rtdm_event_t *event);
int rtdm_event_timedwait(rtdm_event_t *event, nanosecs_rel_t timeout,
			 rtdm_toseq_t *timeout_seq);
void rtdm_event_signal(rtdm_event_t *event);

void rtdm_event_clear(rtdm_event_t *event);

void rtdm_event_pulse(rtdm_event_t *event);

void rtdm_event_destroy(rtdm_event_t *event);

/* --- semaphore services --- */

typedef struct rtdm_sem {
	unsigned long value;
	struct xnsynch synch_base;
	DECLARE_XNSELECT(select_block);
} rtdm_sem_t;

void rtdm_sem_init(rtdm_sem_t *sem, unsigned long value);
int rtdm_sem_select(rtdm_sem_t *sem, rtdm_selector_t *selector,
		    enum rtdm_selecttype type, unsigned fd_index);
int rtdm_sem_down(rtdm_sem_t *sem);
int rtdm_sem_timeddown(rtdm_sem_t *sem, nanosecs_rel_t timeout,
		       rtdm_toseq_t *timeout_seq);
void rtdm_sem_up(rtdm_sem_t *sem);

void rtdm_sem_destroy(rtdm_sem_t *sem);

/* --- mutex services --- */

typedef struct rtdm_mutex {
	struct xnsynch synch_base;
	atomic_t fastlock;
} rtdm_mutex_t;

void rtdm_mutex_init(rtdm_mutex_t *mutex);
int rtdm_mutex_lock(rtdm_mutex_t *mutex);
int rtdm_mutex_timedlock(rtdm_mutex_t *mutex, nanosecs_rel_t timeout,
			 rtdm_toseq_t *timeout_seq);
void rtdm_mutex_unlock(rtdm_mutex_t *mutex);
void rtdm_mutex_destroy(rtdm_mutex_t *mutex);

/* --- utility functions --- */

#define rtdm_printk(format, ...)	printk(format, ##__VA_ARGS__)

struct rtdm_ratelimit_state {
	rtdm_lock_t	lock;		/* protect the state */
	nanosecs_abs_t  interval;
	int		burst;
	int		printed;
	int		missed;
	nanosecs_abs_t	begin;
};

int rtdm_ratelimit(struct rtdm_ratelimit_state *rs, const char *func);

#define DEFINE_RTDM_RATELIMIT_STATE(name, interval_init, burst_init)	\
	struct rtdm_ratelimit_state name = {				\
		.lock		= RTDM_LOCK_UNLOCKED((name).lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

/* We use the Linux defaults */
#define DEF_RTDM_RATELIMIT_INTERVAL	5000000000LL
#define DEF_RTDM_RATELIMIT_BURST	10

#define rtdm_printk_ratelimited(fmt, ...)  ({				\
	static DEFINE_RTDM_RATELIMIT_STATE(_rs,				\
					   DEF_RTDM_RATELIMIT_INTERVAL,	\
					   DEF_RTDM_RATELIMIT_BURST);	\
									\
	if (rtdm_ratelimit(&_rs, __func__))				\
		printk(fmt, ##__VA_ARGS__);				\
})

static inline void *rtdm_malloc(size_t size)
{
	return xnmalloc(size);
}

static inline void rtdm_free(void *ptr)
{
	xnfree(ptr);
}

int rtdm_mmap_to_user(struct rtdm_fd *fd,
		      void *src_addr, size_t len,
		      int prot, void **pptr,
		      struct vm_operations_struct *vm_ops,
		      void *vm_private_data);

int rtdm_iomap_to_user(struct rtdm_fd *fd,
		       phys_addr_t src_addr, size_t len,
		       int prot, void **pptr,
		       struct vm_operations_struct *vm_ops,
		       void *vm_private_data);

int rtdm_mmap_kmem(struct vm_area_struct *vma, void *va);

int rtdm_mmap_vmem(struct vm_area_struct *vma, void *va);

int rtdm_mmap_iomem(struct vm_area_struct *vma, phys_addr_t pa);

int rtdm_munmap(void *ptr, size_t len);

static inline int rtdm_read_user_ok(struct rtdm_fd *fd,
				    const void __user *ptr, size_t size)
{
	return access_rok(ptr, size);
}

static inline int rtdm_rw_user_ok(struct rtdm_fd *fd,
				  const void __user *ptr, size_t size)
{
	return access_wok(ptr, size);
}

static inline int rtdm_copy_from_user(struct rtdm_fd *fd,
				      void *dst, const void __user *src,
				      size_t size)
{
	return __xn_copy_from_user(dst, src, size) ? -EFAULT : 0;
}

static inline int rtdm_safe_copy_from_user(struct rtdm_fd *fd,
					   void *dst, const void __user *src,
					   size_t size)
{
	return steely_copy_from_user(dst, src, size);
}

static inline int rtdm_copy_to_user(struct rtdm_fd *fd,
				    void __user *dst, const void *src,
				    size_t size)
{
	return __xn_copy_to_user(dst, src, size) ? -EFAULT : 0;
}

static inline int rtdm_safe_copy_to_user(struct rtdm_fd *fd,
					 void __user *dst, const void *src,
					 size_t size)
{
	return steely_copy_to_user(dst, src, size);
}

static inline int rtdm_strncpy_from_user(struct rtdm_fd *fd,
					 char *dst,
					 const char __user *src, size_t count)
{
	return steely_strncpy_from_user(dst, src, count);
}

static inline int rtdm_rt_capable(struct rtdm_fd *fd)
{
	if (!STEELY_ASSERT(STEELY, !xnsched_interrupt_p()))
		return 0;

	if (!rtdm_fd_is_user(fd))
		return !xnsched_root_p();

	return steely_current_thread() != NULL;
}

static inline int rtdm_in_rt_context(void)
{
	return current_irq_stage != &root_irq_stage;
}

#endif /* _STEELY_RTDM_DRIVER_H */
