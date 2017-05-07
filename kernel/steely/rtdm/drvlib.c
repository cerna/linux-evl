/*
 * Real-Time Driver Model for Xenomai, driver library
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
 */
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/mman.h>
#include <linux/irq_work.h>
#include <linux/highmem.h>
#include <linux/err.h>
#include <linux/anon_inodes.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <steely/driver.h>
#include "internal.h"
#include <trace/events/steely.h>

int rtdm_task_init(rtdm_task_t *task, const char *name,
		   rtdm_task_proc_t task_proc, void *arg,
		   int priority, nanosecs_rel_t period)
{
	union xnsched_policy_param param;
	struct xnthread_start_attr sattr;
	struct xnthread_init_attr iattr;
	int err;

	iattr.name = name;
	iattr.flags = 0;
	iattr.personality = &steely_personality;
	iattr.affinity = CPU_MASK_ALL;
	param.rt.prio = priority;

	err = xnthread_init(task, &iattr, &xnsched_class_rt, &param);
	if (err)
		return err;

	/* We need an anonymous registry entry to obtain a handle for fast
	   mutex locking. */
	err = xnthread_register(task, "");
	if (err)
		goto cleanup_out;

	if (period > 0) {
		err = xnthread_set_periodic(task, XN_INFINITE,
					    XN_RELATIVE, period);
		if (err)
			goto cleanup_out;
	}

	sattr.mode = 0;
	sattr.entry = task_proc;
	sattr.cookie = arg;
	err = xnthread_start(task, &sattr);
	if (err)
		goto cleanup_out;

	return 0;

      cleanup_out:
	xnthread_cancel(task);
	return err;
}

EXPORT_SYMBOL_GPL(rtdm_task_init);

int __rtdm_task_sleep(ktime_t timeout, xntmode_t mode)
{
	struct xnthread *thread;

	if (!STEELY_ASSERT(STEELY, !xnsched_unblockable_p()))
		return -EPERM;

	thread = xnthread_current();
	xnthread_suspend(thread, XNDELAY, timeout, mode, NULL);

	return xnthread_test_info(thread, XNBREAK) ? -EINTR : 0;
}

EXPORT_SYMBOL_GPL(__rtdm_task_sleep);

void rtdm_task_join(rtdm_task_t *task)
{
	trace_steely_driver_task_join(task);

	xnthread_join(task, true);
}

EXPORT_SYMBOL_GPL(rtdm_task_join);

void rtdm_task_busy_sleep(nanosecs_rel_t delay)
{
	ktime_t wakeup;

	wakeup = ktime_add_ns(xnclock_read_monotonic(&nkclock), delay);

	while (ktime_before(xnclock_read_monotonic(&nkclock), wakeup))
		cpu_relax();
}

EXPORT_SYMBOL_GPL(rtdm_task_busy_sleep);

void rtdm_timer_destroy(rtdm_timer_t *timer)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	xntimer_destroy(timer);
	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_timer_destroy);

int rtdm_timer_start(rtdm_timer_t *timer, nanosecs_abs_t expiry,
		     nanosecs_rel_t interval, enum rtdm_timer_mode mode)
{
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);
	err = xntimer_start(timer, expiry, interval, (xntmode_t)mode);
	xnlock_put_irqrestore(&nklock, s);

	return err;
}

EXPORT_SYMBOL_GPL(rtdm_timer_start);

void rtdm_timer_stop(rtdm_timer_t *timer)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	xntimer_stop(timer);
	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_timer_stop);

/* --- IPC cleanup helper --- */

#define RTDM_SYNCH_DELETED          XNSYNCH_SPARE0

void __rtdm_synch_flush(struct xnsynch *synch, unsigned long reason)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (reason == XNRMID)
		xnsynch_set_status(synch, RTDM_SYNCH_DELETED);

	if (likely(xnsynch_flush(synch, reason) == XNSYNCH_RESCHED))
		xnsched_run();

	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(__rtdm_synch_flush);

void rtdm_toseq_init(rtdm_toseq_t *timeout_seq, nanosecs_rel_t timeout)
{
	STEELY_WARN_ON(STEELY, xnsched_unblockable_p()); /* only warn here */

	*timeout_seq = xnclock_read_monotonic(&nkclock) + timeout;
}

EXPORT_SYMBOL_GPL(rtdm_toseq_init);

void rtdm_event_init(rtdm_event_t *event, unsigned long pending)
{
	spl_t s;

	trace_steely_driver_event_init(event, pending);

	/* Make atomic for re-initialisation support */
	xnlock_get_irqsave(&nklock, s);

	xnsynch_init(&event->synch_base, XNSYNCH_PRIO, NULL);
	if (pending)
		xnsynch_set_status(&event->synch_base, RTDM_EVENT_PENDING);
	xnselect_init(&event->select_block);

	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_event_init);

void rtdm_event_destroy(rtdm_event_t *event)
{
	trace_steely_driver_event_destroy(event);
	__rtdm_synch_flush(&event->synch_base, XNRMID);
	xnselect_destroy(&event->select_block);
}
EXPORT_SYMBOL_GPL(rtdm_event_destroy);

void rtdm_event_pulse(rtdm_event_t *event)
{
	trace_steely_driver_event_pulse(event);
	__rtdm_synch_flush(&event->synch_base, 0);
}
EXPORT_SYMBOL_GPL(rtdm_event_pulse);

void rtdm_event_signal(rtdm_event_t *event)
{
	int resched = 0;
	spl_t s;

	trace_steely_driver_event_signal(event);

	xnlock_get_irqsave(&nklock, s);

	xnsynch_set_status(&event->synch_base, RTDM_EVENT_PENDING);
	if (xnsynch_flush(&event->synch_base, 0))
		resched = 1;
	if (xnselect_signal(&event->select_block, 1))
		resched = 1;
	if (resched)
		xnsched_run();

	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_event_signal);

int rtdm_event_wait(rtdm_event_t *event)
{
	return rtdm_event_timedwait(event, 0, NULL);
}

EXPORT_SYMBOL_GPL(rtdm_event_wait);

int rtdm_event_timedwait(rtdm_event_t *event, nanosecs_rel_t timeout,
			 rtdm_toseq_t *timeout_seq)
{
	struct xnthread *thread;
	int err = 0, ret;
	spl_t s;

	if (!STEELY_ASSERT(STEELY, timeout < 0 || !xnsched_unblockable_p()))
		return -EPERM;

	trace_steely_driver_event_wait(event, xnthread_current());

	xnlock_get_irqsave(&nklock, s);

	if (unlikely(event->synch_base.status & RTDM_SYNCH_DELETED))
		err = -EIDRM;
	else if (likely(event->synch_base.status & RTDM_EVENT_PENDING)) {
		xnsynch_clear_status(&event->synch_base, RTDM_EVENT_PENDING);
		xnselect_signal(&event->select_block, 0);
	} else {
		/* non-blocking mode */
		if (timeout < 0) {
			err = -EWOULDBLOCK;
			goto unlock_out;
		}

		thread = xnthread_current();

		if (timeout_seq && (timeout > 0))
			/* timeout sequence */
			ret = xnsynch_sleep_on(&event->synch_base, *timeout_seq,
					       XN_ABSOLUTE);
		else
			/* infinite or relative timeout */
			ret = xnsynch_sleep_on(&event->synch_base, timeout, XN_RELATIVE);

		if (likely(ret == 0)) {
			xnsynch_clear_status(&event->synch_base,
					    RTDM_EVENT_PENDING);
			xnselect_signal(&event->select_block, 0);
		} else if (ret & XNTIMEO)
			err = -ETIMEDOUT;
		else if (ret & XNRMID)
			err = -EIDRM;
		else /* XNBREAK */
			err = -EINTR;
	}

unlock_out:
	xnlock_put_irqrestore(&nklock, s);

	return err;
}

EXPORT_SYMBOL_GPL(rtdm_event_timedwait);

void rtdm_event_clear(rtdm_event_t *event)
{
	spl_t s;

	trace_steely_driver_event_clear(event);

	xnlock_get_irqsave(&nklock, s);

	xnsynch_clear_status(&event->synch_base, RTDM_EVENT_PENDING);
	xnselect_signal(&event->select_block, 0);

	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_event_clear);

int rtdm_event_select(rtdm_event_t *event, rtdm_selector_t *selector,
		      enum rtdm_selecttype type, unsigned int fd_index)
{
	struct xnselect_binding *binding;
	int err;
	spl_t s;

	binding = xnmalloc(sizeof(*binding));
	if (!binding)
		return -ENOMEM;

	xnlock_get_irqsave(&nklock, s);
	err = xnselect_bind(&event->select_block,
			    binding, selector, type, fd_index,
			    event->synch_base.status & (RTDM_SYNCH_DELETED |
						       RTDM_EVENT_PENDING));
	xnlock_put_irqrestore(&nklock, s);

	if (err)
		xnfree(binding);

	return err;
}
EXPORT_SYMBOL_GPL(rtdm_event_select);

void rtdm_sem_init(rtdm_sem_t *sem, unsigned long value)
{
	spl_t s;

	trace_steely_driver_sem_init(sem, value);

	/* Make atomic for re-initialisation support */
	xnlock_get_irqsave(&nklock, s);

	sem->value = value;
	xnsynch_init(&sem->synch_base, XNSYNCH_PRIO, NULL);
	xnselect_init(&sem->select_block);

	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_sem_init);

void rtdm_sem_destroy(rtdm_sem_t *sem)
{
	trace_steely_driver_sem_destroy(sem);
	__rtdm_synch_flush(&sem->synch_base, XNRMID);
	xnselect_destroy(&sem->select_block);
}
EXPORT_SYMBOL_GPL(rtdm_sem_destroy);

int rtdm_sem_down(rtdm_sem_t *sem)
{
	return rtdm_sem_timeddown(sem, 0, NULL);
}

EXPORT_SYMBOL_GPL(rtdm_sem_down);

int rtdm_sem_timeddown(rtdm_sem_t *sem, nanosecs_rel_t timeout,
		       rtdm_toseq_t *timeout_seq)
{
	struct xnthread *thread;
	int err = 0, ret;
	spl_t s;

	if (!STEELY_ASSERT(STEELY, timeout < 0 || !xnsched_unblockable_p()))
		return -EPERM;

	trace_steely_driver_sem_wait(sem, xnthread_current());

	xnlock_get_irqsave(&nklock, s);

	if (unlikely(sem->synch_base.status & RTDM_SYNCH_DELETED))
		err = -EIDRM;
	else if (sem->value > 0) {
		if(!--sem->value)
			xnselect_signal(&sem->select_block, 0);
	} else if (timeout < 0) /* non-blocking mode */
		err = -EWOULDBLOCK;
	else {
		thread = xnthread_current();

		if (timeout_seq && timeout > 0)
			/* timeout sequence */
			ret = xnsynch_sleep_on(&sem->synch_base, *timeout_seq,
					       XN_ABSOLUTE);
		else
			/* infinite or relative timeout */
			ret = xnsynch_sleep_on(&sem->synch_base, timeout, XN_RELATIVE);

		if (ret) {
			if (ret & XNTIMEO)
				err = -ETIMEDOUT;
			else if (ret & XNRMID)
				err = -EIDRM;
			else /* XNBREAK */
				err = -EINTR;
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

EXPORT_SYMBOL_GPL(rtdm_sem_timeddown);

void rtdm_sem_up(rtdm_sem_t *sem)
{
	spl_t s;

	trace_steely_driver_sem_up(sem);

	xnlock_get_irqsave(&nklock, s);

	if (xnsynch_wakeup_one_sleeper(&sem->synch_base))
		xnsched_run();
	else
		if (sem->value++ == 0
		    && xnselect_signal(&sem->select_block, 1))
			xnsched_run();

	xnlock_put_irqrestore(&nklock, s);
}

EXPORT_SYMBOL_GPL(rtdm_sem_up);

int rtdm_sem_select(rtdm_sem_t *sem, rtdm_selector_t *selector,
		    enum rtdm_selecttype type, unsigned int fd_index)
{
	struct xnselect_binding *binding;
	int err;
	spl_t s;

	binding = xnmalloc(sizeof(*binding));
	if (!binding)
		return -ENOMEM;

	xnlock_get_irqsave(&nklock, s);
	err = xnselect_bind(&sem->select_block, binding, selector,
			    type, fd_index,
			    (sem->value > 0) ||
			    sem->synch_base.status & RTDM_SYNCH_DELETED);
	xnlock_put_irqrestore(&nklock, s);

	if (err)
		xnfree(binding);

	return err;
}
EXPORT_SYMBOL_GPL(rtdm_sem_select);

void rtdm_mutex_init(rtdm_mutex_t *mutex)
{
	spl_t s;

	/* Make atomic for re-initialisation support */
	xnlock_get_irqsave(&nklock, s);
	xnsynch_init(&mutex->synch_base, XNSYNCH_PI, &mutex->fastlock);
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(rtdm_mutex_init);

void rtdm_mutex_destroy(rtdm_mutex_t *mutex)
{
	trace_steely_driver_mutex_destroy(mutex);

	__rtdm_synch_flush(&mutex->synch_base, XNRMID);
}
EXPORT_SYMBOL_GPL(rtdm_mutex_destroy);

void rtdm_mutex_unlock(rtdm_mutex_t *mutex)
{
	if (!STEELY_ASSERT(STEELY, !xnsched_interrupt_p()))
		return;

	trace_steely_driver_mutex_release(mutex);

	if (unlikely(xnsynch_release(&mutex->synch_base,
				     xnsched_current_thread())))
		xnsched_run();
}
EXPORT_SYMBOL_GPL(rtdm_mutex_unlock);

int rtdm_mutex_lock(rtdm_mutex_t *mutex)
{
	return rtdm_mutex_timedlock(mutex, 0, NULL);
}

EXPORT_SYMBOL_GPL(rtdm_mutex_lock);

int rtdm_mutex_timedlock(rtdm_mutex_t *mutex, nanosecs_rel_t timeout,
			 rtdm_toseq_t *timeout_seq)
{
	struct xnthread *curr;
	int ret;
	spl_t s;

	if (!STEELY_ASSERT(STEELY, !xnsched_unblockable_p()))
		return -EPERM;

	curr = xnthread_current();
	trace_steely_driver_mutex_wait(mutex, curr);

	xnlock_get_irqsave(&nklock, s);

	if (unlikely(mutex->synch_base.status & RTDM_SYNCH_DELETED)) {
		ret = -EIDRM;
		goto out;
	}

	ret = xnsynch_try_acquire(&mutex->synch_base);
	if (ret != -EBUSY)
		goto out;

	if (timeout < 0) {
		ret = -EWOULDBLOCK;
		goto out;
	}

	for (;;) {
		if (timeout_seq && timeout > 0) /* timeout sequence */
			ret = xnsynch_acquire(&mutex->synch_base, *timeout_seq,
					      XN_ABSOLUTE);
		else		/* infinite or relative timeout */
			ret = xnsynch_acquire(&mutex->synch_base, timeout,
					      XN_RELATIVE);
		if (ret == 0)
			break;
		if (ret & XNBREAK)
			continue;
		ret = ret & XNTIMEO ? -ETIMEDOUT : -EIDRM;
		break;
	}
out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

EXPORT_SYMBOL_GPL(rtdm_mutex_timedlock);

int rtdm_irq_request(rtdm_irq_t *irq_handle, unsigned int irq_no,
		     rtdm_irq_handler_t handler, unsigned long flags,
		     const char *device_name, void *arg)
{
	int err;

	if (!STEELY_ASSERT(STEELY, xnsched_root_p()))
		return -EPERM;

	err = xnintr_init(irq_handle, device_name, irq_no, handler, flags);
	if (err)
		return err;

	err = xnintr_attach(irq_handle, arg);
	if (err) {
		xnintr_destroy(irq_handle);
		return err;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(rtdm_irq_request);

struct nrtsig_work {
	struct rtdm_nrtsig *nrtsig;
	struct irq_work work;
};

static void nrtsig_execute(struct irq_work *work)
{
	struct rtdm_nrtsig *nrtsig;
	struct nrtsig_work *rq;

	rq = container_of(work, typeof(*rq), work);
	nrtsig = rq->nrtsig;
	nrtsig->handler(nrtsig, nrtsig->arg);
	steely_free_irq_work(rq);
}

void rtdm_nrtsig_pend(rtdm_nrtsig_t *nrt_sig)
{
	struct nrtsig_work *rq;

	rq = steely_alloc_irq_work(sizeof(*rq));
	init_irq_work(&rq->work, nrtsig_execute);
	rq->nrtsig = nrt_sig;
	irq_work_queue(&rq->work);
}
EXPORT_SYMBOL_GPL(rtdm_nrtsig_pend);

struct lostage_schedule_work {
	struct work_struct *lostage_work;
	struct irq_work work;
};

static void lostage_schedule_work(struct irq_work *work)
{
	struct lostage_schedule_work *rq;

	rq = container_of(work, typeof(*rq), work);
	schedule_work(rq->lostage_work);
	steely_free_irq_work(rq);
}

void rtdm_schedule_nrt_work(struct work_struct *lostage_work)
{
	struct lostage_schedule_work *rq;

	if (on_root_stage())
		schedule_work(lostage_work);
	else {
		rq = steely_alloc_irq_work(sizeof(*rq));
		init_irq_work(&rq->work, lostage_schedule_work);
		rq->lostage_work = lostage_work;
		irq_work_queue(&rq->work);
	}
}
EXPORT_SYMBOL_GPL(rtdm_schedule_nrt_work);

struct mmap_tramp_data {
	struct rtdm_fd *fd;
	struct file_operations *fops;
	int (*mmap_handler)(struct rtdm_fd *fd,
			    struct vm_area_struct *vma);
};

struct mmap_helper_data {
	void *src_vaddr;
	phys_addr_t src_paddr;
	struct vm_operations_struct *vm_ops;
	void *vm_private_data;
	struct mmap_tramp_data tramp_data;
};

static int mmap_kmem_helper(struct vm_area_struct *vma, void *va)
{
	unsigned long addr, len, pfn, to;
	int ret = 0;

	to = (unsigned long)va;
	addr = vma->vm_start;
	len = vma->vm_end - vma->vm_start;

	if (to != PAGE_ALIGN(to) || (len & ~PAGE_MASK) != 0)
		return -EINVAL;

#ifndef CONFIG_MMU
	pfn = __pa(to) >> PAGE_SHIFT;
	ret = remap_pfn_range(vma, addr, pfn, len, PAGE_SHARED);
#else
	if (to < VMALLOC_START || to >= VMALLOC_END) {
		/* logical address. */
		pfn = __pa(to) >> PAGE_SHIFT;
		ret = remap_pfn_range(vma, addr, pfn, len, PAGE_SHARED);
		if (ret)
			return ret;
	} else {
		/* vmalloc memory. */
		while (len > 0) {
			struct page *page = vmalloc_to_page((void *)to);
			if (vm_insert_page(vma, addr, page))
				return -EAGAIN;
			addr += PAGE_SIZE;
			to += PAGE_SIZE;
			len -= PAGE_SIZE;
		}
	}

	if (steely_machine.prefault)
		steely_machine.prefault(vma);
#endif

	return ret;
}

static int mmap_iomem_helper(struct vm_area_struct *vma, phys_addr_t pa)
{
	pgprot_t prot = PAGE_SHARED;
	unsigned long len;

	len = vma->vm_end - vma->vm_start;
#ifndef CONFIG_MMU
	vma->vm_pgoff = pa >> PAGE_SHIFT;
#endif /* CONFIG_MMU */

#ifdef __HAVE_PHYS_MEM_ACCESS_PROT
	if (vma->vm_file)
		prot = phys_mem_access_prot(vma->vm_file, pa >> PAGE_SHIFT,
					    len, prot);
#endif
	vma->vm_page_prot = pgprot_noncached(prot);

	return remap_pfn_range(vma, vma->vm_start, pa >> PAGE_SHIFT,
			       len, vma->vm_page_prot);
}

static int mmap_buffer_helper(struct rtdm_fd *fd, struct vm_area_struct *vma)
{
	struct mmap_tramp_data *tramp_data = vma->vm_private_data;
	struct mmap_helper_data *helper_data;
	int ret;

	helper_data = container_of(tramp_data, struct mmap_helper_data, tramp_data);
	vma->vm_ops = helper_data->vm_ops;
	vma->vm_private_data = helper_data->vm_private_data;

	if (helper_data->src_paddr)
		ret = mmap_iomem_helper(vma, helper_data->src_paddr);
	else
		ret = mmap_kmem_helper(vma, helper_data->src_vaddr);

	return ret;
}

static int mmap_trampoline(struct file *filp, struct vm_area_struct *vma)
{
	struct mmap_tramp_data *tramp_data = filp->private_data;
	int ret;

	vma->vm_private_data = tramp_data;

	ret = tramp_data->mmap_handler(tramp_data->fd, vma);
	if (ret)
		return ret;

	return 0;
}

#ifndef CONFIG_MMU

static unsigned long
internal_get_unmapped_area(struct file *filp,
			   unsigned long addr, unsigned long len,
			   unsigned long pgoff, unsigned long flags)
{
	struct mmap_tramp_data *tramp_data = filp->private_data;
	struct mmap_helper_data *helper_data;
	unsigned long pa;

	helper_data = container_of(tramp_data, struct mmap_helper_data, tramp_data);
	pa = helper_data->src_paddr;
	if (pa)
		return (unsigned long)__va(pa);

	return (unsigned long)helper_data->src_vaddr;
}

static int do_rtdm_mmap(struct mmap_tramp_data *tramp_data,
			size_t len, off_t offset, int prot, int flags,
			void **pptr)
{
	const struct file_operations *old_fops;
	unsigned long u_addr;
	struct file *filp;

	filp = filp_open("/dev/mem", O_RDWR, 0);
	if (IS_ERR(filp))
		return PTR_ERR(filp);

	old_fops = filp->f_op;
	filp->f_op = tramp_data->fops;
	filp->private_data = tramp_data;
	u_addr = vm_mmap(filp, (unsigned long)*pptr, len, prot, flags, offset);
	filp_close(filp, current->files);
	filp->f_op = old_fops;

	if (IS_ERR_VALUE(u_addr))
		return (int)u_addr;

	*pptr = (void *)u_addr;

	return 0;
}

#else /* CONFIG_MMU */

static int do_rtdm_mmap(struct mmap_tramp_data *tramp_data,
			size_t len, off_t offset, int prot, int flags,
			void **pptr)
{
	unsigned long u_addr;
	struct file *filp;

	filp = anon_inode_getfile("[rtdm]", tramp_data->fops, tramp_data, O_RDWR);
	if (IS_ERR(filp))
		return PTR_ERR(filp);

	u_addr = vm_mmap(filp, (unsigned long)*pptr, len, prot, flags, offset);
	filp_close(filp, current->files);

	if (IS_ERR_VALUE(u_addr))
		return (int)u_addr;

	*pptr = (void *)u_addr;

	return 0;
}

#define internal_get_unmapped_area  NULL

#endif /* CONFIG_MMU */

static struct file_operations internal_mmap_fops = {
	.mmap = mmap_trampoline,
	.get_unmapped_area = internal_get_unmapped_area
};

static unsigned long
driver_get_unmapped_area(struct file *filp,
			 unsigned long addr, unsigned long len,
			 unsigned long pgoff, unsigned long flags)
{
	struct mmap_tramp_data *tramp_data = filp->private_data;
	struct rtdm_fd *fd = tramp_data->fd;

	if (fd->ops->get_unmapped_area)
		return fd->ops->get_unmapped_area(fd, len, pgoff, flags);

#ifdef CONFIG_MMU
	/* Run default handler. */
	return current->mm->get_unmapped_area(filp, addr, len, pgoff, flags);
#else
	return -ENODEV;
#endif
}

static struct file_operations driver_mmap_fops = {
	.mmap = mmap_trampoline,
	.get_unmapped_area = driver_get_unmapped_area
};

int __rtdm_mmap_from_fdop(struct rtdm_fd *fd, size_t len, off_t offset,
			  int prot, int flags, void **pptr)
{
	struct mmap_tramp_data tramp_data = {
		.fd = fd,
		.fops = &driver_mmap_fops,
		.mmap_handler = fd->ops->mmap,
	};

#ifndef CONFIG_MMU
	/*
	 * XXX: A .get_unmapped_area handler must be provided in the
	 * nommu case. We use this to force the memory management code
	 * not to share VM regions for distinct areas to map to, as it
	 * would otherwise do since all requests currently apply to
	 * the same file (i.e. from /dev/mem, see do_mmap_pgoff() in
	 * the nommu case).
	 */
	if (fd->ops->get_unmapped_area)
		offset = fd->ops->get_unmapped_area(fd, len, 0, flags);
#endif

	return do_rtdm_mmap(&tramp_data, len, offset, prot, flags, pptr);
}

int rtdm_mmap_to_user(struct rtdm_fd *fd,
		      void *src_addr, size_t len,
		      int prot, void **pptr,
		      struct vm_operations_struct *vm_ops,
		      void *vm_private_data)
{
	struct mmap_helper_data helper_data = {
		.tramp_data = {
			.fd = fd,
			.fops = &internal_mmap_fops,
			.mmap_handler = mmap_buffer_helper,
		},
		.src_vaddr = src_addr,
		.src_paddr = 0,
		.vm_ops = vm_ops,
		.vm_private_data = vm_private_data
	};

	if (!STEELY_ASSERT(STEELY, xnsched_root_p()))
		return -EPERM;

	return do_rtdm_mmap(&helper_data.tramp_data, len, 0, prot, MAP_SHARED, pptr);
}
EXPORT_SYMBOL_GPL(rtdm_mmap_to_user);

int rtdm_iomap_to_user(struct rtdm_fd *fd,
		       phys_addr_t src_addr, size_t len,
		       int prot, void **pptr,
		       struct vm_operations_struct *vm_ops,
		       void *vm_private_data)
{
	struct mmap_helper_data helper_data = {
		.tramp_data = {
			.fd = fd,
			.fops = &internal_mmap_fops,
			.mmap_handler = mmap_buffer_helper,
		},
		.src_vaddr = NULL,
		.src_paddr = src_addr,
		.vm_ops = vm_ops,
		.vm_private_data = vm_private_data
	};

	if (!STEELY_ASSERT(STEELY, xnsched_root_p()))
		return -EPERM;

	return do_rtdm_mmap(&helper_data.tramp_data, len, 0, prot, MAP_SHARED, pptr);
}
EXPORT_SYMBOL_GPL(rtdm_iomap_to_user);

int rtdm_mmap_kmem(struct vm_area_struct *vma, void *va)
{
	return mmap_kmem_helper(vma, va);
}
EXPORT_SYMBOL_GPL(rtdm_mmap_kmem);

int rtdm_mmap_vmem(struct vm_area_struct *vma, void *va)
{
	/*
	 * Our helper handles both of directly mapped to physical and
	 * purely virtual memory ranges.
	 */
	return mmap_kmem_helper(vma, va);
}
EXPORT_SYMBOL_GPL(rtdm_mmap_vmem);

int rtdm_mmap_iomem(struct vm_area_struct *vma, phys_addr_t pa)
{
	return mmap_iomem_helper(vma, pa);
}
EXPORT_SYMBOL_GPL(rtdm_mmap_iomem);

int rtdm_munmap(void *ptr, size_t len)
{
	if (!STEELY_ASSERT(STEELY, xnsched_root_p()))
		return -EPERM;

	return vm_munmap((unsigned long)ptr, len);
}
EXPORT_SYMBOL_GPL(rtdm_munmap);

int rtdm_ratelimit(struct rtdm_ratelimit_state *rs, const char *func)
{
	rtdm_lockctx_t lock_ctx;
	int ret;

	if (!rs->interval)
		return 1;

	rtdm_lock_get_irqsave(&rs->lock, lock_ctx);

	if (!rs->begin)
		rs->begin = rtdm_clock_read();
	if (rtdm_clock_read() >= rs->begin + rs->interval) {
		if (rs->missed)
			printk(KERN_WARNING "%s: %d callbacks suppressed\n",
			       func, rs->missed);
		rs->begin   = 0;
		rs->printed = 0;
		rs->missed  = 0;
	}
	if (rs->burst && rs->burst > rs->printed) {
		rs->printed++;
		ret = 1;
	} else {
		rs->missed++;
		ret = 0;
	}
	rtdm_lock_put_irqrestore(&rs->lock, lock_ctx);

	return ret;
}
EXPORT_SYMBOL_GPL(rtdm_ratelimit);
