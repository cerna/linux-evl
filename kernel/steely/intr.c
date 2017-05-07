/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2005,2006 Dmitry Adamushko <dmitry.adamushko@gmail.com>.
 * Copyright (C) 2007 Jan Kiszka <jan.kiszka@web.de>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
*/
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/irq_pipeline.h>
#include <linux/kernel_stat.h>
#include <linux/irq_work.h>
#include <steely/heap.h>
#include <steely/sched.h>
#include <steely/intr.h>
#include <steely/stat.h>
#include <steely/clock.h>
#include <steely/assert.h>
#include <trace/events/steely.h>

static irqreturn_t xnintr_irq_handler(int irq, void *dev_id);

#define XNINTR_MAX_UNHANDLED	1000

static DEFINE_MUTEX(intr_lock);

static LIST_HEAD(intr_list);

void xnintr_list_lock(void)
{
	mutex_lock(&intr_lock);
}

void xnintr_list_unlock(void)
{
	mutex_unlock(&intr_lock);
}

#ifdef CONFIG_STEELY_STATS
struct xnintr nktimer;	     /* Only for statistics */
static int xnintr_count = 1; /* Number of attached xnintr objects + nktimer */
static int xnintr_list_rev;  /* Modification counter of xnintr list */

/* Both functions update xnintr_list_rev at the very end.
 * This guarantees that module.c::stat_seq_open() won't get
 * an up-to-date xnintr_list_rev and old xnintr_count. */

static inline void stat_counter_inc(void)
{
	xnintr_count++;
	smp_mb();
	xnintr_list_rev++;
}

static inline void stat_counter_dec(void)
{
	xnintr_count--;
	smp_mb();
	xnintr_list_rev++;
}

static inline void sync_stat_references(struct xnintr *intr)
{
	struct xnirqstat *statp;
	struct xnsched *sched;
	int cpu;

	for_each_realtime_cpu(cpu) {
		sched = xnsched_struct(cpu);
		statp = per_cpu_ptr(intr->stats, cpu);
		/* Synchronize on all dangling references to go away. */
		while (sched->current_account == &statp->account)
			cpu_relax();
	}
}

static void clear_irqstats(struct xnintr *intr)
{
	struct xnirqstat *p;
	int cpu;

	for_each_realtime_cpu(cpu) {
		p = per_cpu_ptr(intr->stats, cpu);
		memset(p, 0, sizeof(*p));
	}
}

static inline void alloc_irqstats(struct xnintr *intr)
{
	intr->stats = alloc_percpu(struct xnirqstat);
	clear_irqstats(intr);
}

static inline void free_irqstats(struct xnintr *intr)
{
	free_percpu(intr->stats);
}

static inline void query_irqstats(struct xnintr *intr, int cpu,
				  struct xnintr_iterator *iterator)
{
	struct xnirqstat *statp;
	ktime_t last_switch;

	statp = per_cpu_ptr(intr->stats, cpu);
	iterator->hits = xnstat_counter_get(&statp->hits);
	last_switch = xnsched_struct(cpu)->last_account_switch;
	iterator->exectime_period = statp->account.total;
	iterator->account_period = ktime_sub(last_switch, statp->account.start);
	statp->sum.total = ktime_add(statp->sum.total, iterator->exectime_period);
	iterator->exectime_total = statp->sum.total;
	statp->account.total = 0;
	statp->account.start = last_switch;
}

static void inc_irqstats(struct xnintr *intr, struct xnsched *sched, ktime_t start)
{
	struct xnirqstat *statp;

	statp = raw_cpu_ptr(intr->stats);
	xnstat_counter_inc(&statp->hits);
	xnstat_exectime_lazy_switch(sched, &statp->account, start);
}

static inline void switch_irqstats(struct xnintr *intr, struct xnsched *sched)
{
	struct xnirqstat *statp;

	statp = raw_cpu_ptr(intr->stats);
	xnstat_exectime_switch(sched, &statp->account);
}

#else  /* !CONFIG_STEELY_STATS */

static inline void stat_counter_inc(void) {}

static inline void stat_counter_dec(void) {}

static inline void sync_stat_references(struct xnintr *intr) {}

static inline void alloc_irqstats(struct xnintr *intr) {}

static inline void free_irqstats(struct xnintr *intr) {}

static inline void clear_irqstats(struct xnintr *intr) {}

static inline
void query_irqstats(struct xnintr *intr, int cpu,
		    struct xnintr_iterator *iterator) {}

static inline
void inc_irqstats(struct xnintr *intr, struct xnsched *sched, ktime_t start) {}

static inline
void switch_irqstats(struct xnintr *intr, struct xnsched *sched) {}

#endif /* !CONFIG_STEELY_STATS */

/*
 * FIXME: we should have a dedicated heap for all irq_works, to avoid
 * serialization with operations on the system heap. In addition, we
 * should deal with transient lack of storage in this pool, on a
 * real-time event signaling availability of memory in the pool
 * (i.e. cleared when depleted). Per-cpu irq_work storage would be
 * nice too (i.e. per-cpu heaps).
 */

void *steely_alloc_irq_work(size_t size)
{
	return xnmalloc(size);
}

void steely_free_irq_work(void *p)
{
	xnfree(p);
}

struct irqdisable_work {
	unsigned int irq;
	struct irq_work	work;
};

static void lostage_irqdisable_line(struct irq_work *work)
{
	struct irqdisable_work *rq;

	rq = container_of(work, struct irqdisable_work, work);
	disable_irq(rq->irq);
	steely_free_irq_work(rq);
}

static void disable_irq_line(int irq)
{
	struct irqdisable_work *rq;

	rq = steely_alloc_irq_work(sizeof(*rq));
	init_irq_work(&rq->work, lostage_irqdisable_line);
	rq->irq = irq;
	irq_work_queue(&rq->work);
}

/* Optional support for shared interrupts. */

#ifdef CONFIG_STEELY_SHIRQ

struct xnintr_vector {
	DECLARE_XNLOCK(lock);
	struct xnintr *handlers;
	int unhandled;
} ____cacheline_aligned_in_smp;

static struct xnintr_vector vectors[IPIPE_NR_IRQS];

static inline struct xnintr *xnintr_vec_first(unsigned int irq)
{
	return vectors[irq].handlers;
}

static inline struct xnintr *xnintr_vec_next(struct xnintr *prev)
{
	return prev->next_handler;
}

static void disable_shared_irq_line(struct xnintr_vector *vec)
{
	int irq = vec - vectors;
	struct xnintr *intr;

	xnlock_get(&vec->lock);
	intr = vec->handlers;
	while (intr) {
		set_bit(XN_IRQSTAT_DISABLED, &intr->status);
		intr = intr->next_handler;
	}
	xnlock_put(&vec->lock);
	disable_irq_line(irq);
}

/*
 * Low-level interrupt handler dispatching the user-defined ISRs for
 * shared interrupts -- Called with interrupts off.
 */
static irqreturn_t xnintr_vec_handler(int irq, void *dev_id)
{
	struct xnsched *sched = xnsched_current();
	struct xnintr_vector *vec = vectors + irq;
	xnstat_exectime_t *prev;
	struct xnintr *intr;
	int s = 0, ret;
	ktime_t start;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();
	trace_steely_irq_entry(irq);

	++sched->inesting;
	sched->lflags |= XNINIRQ;

	xnlock_get(&vec->lock);
	intr = vec->handlers;
	if (unlikely(test_bit(XN_IRQSTAT_DISABLED, &intr->status))) {
		/* irqdisable_work is on its way, ignore. */
		xnlock_put(&vec->lock);
		goto out;
	}

	while (intr) {
		/*
		 * NOTE: We assume that no CPU migration can occur
		 * while running the interrupt service routine.
		 */
		ret = intr->isr(intr);
		STEELY_WARN_ON_ONCE(USER, (ret & XN_IRQ_STATMASK) == 0);
		s |= ret;
		if (ret & XN_IRQ_HANDLED) {
			inc_irqstats(intr, sched, start);
			start = xnstat_exectime_now();
		}
		intr = intr->next_handler;
	}

	xnlock_put(&vec->lock);

	if (unlikely(!(s & XN_IRQ_HANDLED))) {
		if (++vec->unhandled == XNINTR_MAX_UNHANDLED) {
			printk(STEELY_ERR "%s: IRQ%d not handled. Disabling IRQ line\n",
			       __FUNCTION__, irq);
			s |= XN_IRQ_DISABLE;
		}
	} else
		vec->unhandled = 0;

	if (s & XN_IRQ_PROPAGATE)
		irq_stage_post_root(irq);
	else if (s & XN_IRQ_DISABLE)
		disable_shared_irq_line(vec);
	else
		release_irq(irq);
out:
	xnstat_exectime_switch(sched, prev);

	if (--sched->inesting == 0) {
		sched->lflags &= ~XNINIRQ;
		xnsched_run();
	}

	trace_steely_irq_exit(irq);

	return IRQ_HANDLED;
}

/*
 * Low-level interrupt handler dispatching the user-defined ISRs for
 * shared edge-triggered interrupts -- Called with interrupts off.
 */
static irqreturn_t xnintr_edge_vec_handler(int irq, void *dev_id)
{
	const int MAX_EDGEIRQ_COUNTER = 128;
	struct xnsched *sched = xnsched_current();
	struct xnintr_vector *vec = vectors + irq;
	struct xnintr *intr, *end = NULL;
	int s = 0, counter = 0, ret;
	xnstat_exectime_t *prev;
	ktime_t start;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();
	trace_steely_irq_entry(irq);

	++sched->inesting;
	sched->lflags |= XNINIRQ;

	xnlock_get(&vec->lock);
	intr = vec->handlers;
	if (unlikely(test_bit(XN_IRQSTAT_DISABLED, &intr->status))) {
		/* irqdisable_work is on its way, ignore. */
		xnlock_put(&vec->lock);
		goto out;
	}

	while (intr != end) {
		switch_irqstats(intr, sched);
		/*
		 * NOTE: We assume that no CPU migration will occur
		 * while running the interrupt service routine.
		 */
		ret = intr->isr(intr);
		STEELY_WARN_ON_ONCE(USER, (ret & XN_IRQ_STATMASK) == 0);
		s |= ret;

		if (ret & XN_IRQ_HANDLED) {
			end = NULL;
			inc_irqstats(intr, sched, start);
			start = xnstat_exectime_now();
		} else if (end == NULL)
			end = intr;

		if (counter++ > MAX_EDGEIRQ_COUNTER)
			break;

		intr = intr->next_handler;
		if (intr  == NULL)
			intr = vec->handlers;
	}

	xnlock_put(&vec->lock);

	if (counter > MAX_EDGEIRQ_COUNTER)
		printk(STEELY_ERR "%s: failed to get the IRQ%d line free\n",
		       __FUNCTION__, irq);

	if (unlikely(!(s & XN_IRQ_HANDLED))) {
		if (++vec->unhandled == XNINTR_MAX_UNHANDLED) {
			printk(STEELY_ERR "%s: IRQ%d not handled. Disabling IRQ line\n",
			       __FUNCTION__, irq);
			s |= XN_IRQ_DISABLE;
		}
	} else
		vec->unhandled = 0;

	if (s & XN_IRQ_PROPAGATE)
		irq_stage_post_root(irq);
	else if (s & XN_IRQ_DISABLE)
		disable_shared_irq_line(vec);
	else
		release_irq(irq);
out:
	xnstat_exectime_switch(sched, prev);

	if (--sched->inesting == 0) {
		sched->lflags &= ~XNINIRQ;
		xnsched_run();
	}

	trace_steely_irq_exit(irq);

	return IRQ_HANDLED;
}

static inline int xnintr_irq_attach(struct xnintr *intr)
{
	struct xnintr_vector *vec = vectors + intr->irq;
	struct xnintr *prev, **p = &vec->handlers;
	int ret;

	prev = *p;
	if (prev) {
		/* Check on whether the shared mode is allowed. */
		if ((prev->flags & intr->flags & XN_IRQTYPE_SHARED) == 0 ||
		    ((prev->flags & XN_IRQTYPE_EDGE) !=
		     (intr->flags & XN_IRQTYPE_EDGE)))
			return -EBUSY;

		/*
		 * Get a position at the end of the list to insert the
		 * new element.
		 */
		while (prev) {
			p = &prev->next_handler;
			prev = *p;
		}
	} else {
		/* Initialize the corresponding interrupt channel */
		irq_handler_t handler = xnintr_irq_handler;

		if (intr->flags & XN_IRQTYPE_SHARED) {
			if (intr->flags & XN_IRQTYPE_EDGE)
				handler = xnintr_edge_vec_handler;
			else
				handler = xnintr_vec_handler;

		}
		vec->unhandled = 0;

		ret = request_irq(intr->irq, handler, IRQF_PIPELINED,
				  intr->name, intr);
		if (ret)
			return ret;
	}

	intr->next_handler = NULL;
	/*
	 * Add the given interrupt object. No need to synchronise with
	 * the IRQ handler, we are only extending the chain.
	 */
	*p = intr;

	return 0;
}

static inline void xnintr_irq_detach(struct xnintr *intr)
{
	struct xnintr_vector *vec = vectors + intr->irq;
	struct xnintr *e, **p = &vec->handlers;

	while ((e = *p) != NULL) {
		if (e == intr) {
			/* Remove the given interrupt object from the list. */
			xnlock_get(&vec->lock);
			*p = e->next_handler;
			xnlock_put(&vec->lock);

			sync_stat_references(intr);

			/* Release the IRQ line if this was the last user */
			if (vec->handlers == NULL)
				free_irq(intr->irq, intr);

			return;
		}
		p = &e->next_handler;
	}

	printk(STEELY_ERR "attempted to detach an unregistered interrupt descriptor\n");
}

#else /* !CONFIG_STEELY_SHIRQ */

struct xnintr_vector {
#if defined(CONFIG_SMP) || STEELY_DEBUG(LOCKING)
	DECLARE_XNLOCK(lock);
#endif /* CONFIG_SMP || STEELY_DEBUG(LOCKING) */
} ____cacheline_aligned_in_smp;

static struct xnintr_vector vectors[IPIPE_NR_IRQS];

static inline struct xnintr *xnintr_vec_first(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	
	return desc->action ? desc->action->dev_id : NULL;
}

static inline struct xnintr *xnintr_vec_next(struct xnintr *prev)
{
	return NULL;
}

static inline int xnintr_irq_attach(struct xnintr *intr)
{
	return request_irq(intr->irq, xnintr_irq_handler,
			   IRQF_PIPELINED, intr->name, intr);
}

static inline void xnintr_irq_detach(struct xnintr *intr)
{
	free_irq(intr->irq, intr);
	sync_stat_references(intr);
}

#endif /* !CONFIG_STEELY_SHIRQ */

/*
 * Low-level interrupt handler dispatching non-shared ISRs -- Called
 * with interrupts off.
 */
static irqreturn_t xnintr_irq_handler(int irq, void *dev_id)
{
	struct xnintr_vector __maybe_unused *vec = vectors + irq;
	struct xnsched *sched = xnsched_current();
	xnstat_exectime_t *prev;
	struct xnintr *intr;
	ktime_t start;
	int s = 0;

	/*
	 * CAUTION: we assume that no race is possible with
	 * xnintr_detach() in the current implementation, such as we
	 * might receive an interrupt on the local CPU while the
	 * remote one is releasing the xnintr descriptor. The pipeline
	 * is expected to provide such guarantee under the hood.
	 */
	intr = dev_id;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();
	trace_steely_irq_entry(irq);

	++sched->inesting;
	sched->lflags |= XNINIRQ;

	xnlock_get(&vec->lock);

	if (unlikely(test_bit(XN_IRQSTAT_DISABLED, &intr->status))) {
		/* irqdisable_work is on its way, ignore. */
		xnlock_put(&vec->lock);
		goto out;
	}

	s = intr->isr(intr);
	STEELY_WARN_ON_ONCE(USER, (s & XN_IRQ_STATMASK) == 0);
	if (unlikely(!(s & XN_IRQ_HANDLED))) {
		if (++intr->unhandled == XNINTR_MAX_UNHANDLED) {
			printk(STEELY_ERR "%s: IRQ%d not handled. Disabling IRQ line\n",
			       __FUNCTION__, irq);
			s |= XN_IRQ_DISABLE;
		}
	} else {
		inc_irqstats(intr, sched, start);
		intr->unhandled = 0;
	}

	if (s & XN_IRQ_DISABLE)
		set_bit(XN_IRQSTAT_DISABLED, &intr->status);

	xnlock_put(&vec->lock);

	if (s & XN_IRQ_DISABLE)
		disable_irq_line(irq);
	else if (s & XN_IRQ_PROPAGATE)
		irq_stage_post_root(irq);
	else
		release_irq(irq);
out:
	xnstat_exectime_switch(sched, prev);

	if (--sched->inesting == 0) {
		sched->lflags &= ~XNINIRQ;
		xnsched_run();
	}

	trace_steely_irq_exit(irq);

	return IRQ_HANDLED;
}

int __init xnintr_mount(void)
{
#if defined(CONFIG_SMP) || STEELY_DEBUG(LOCKING) || defined(CONFIG_STEELY_SHIRQ)
	int i;
	for (i = 0; i < ARRAY_SIZE(vectors); ++i)
		xnlock_init(&vectors[i].lock);
#endif
	return 0;
}

static void register_intr(struct xnintr *intr, void *dev_id)
{
	intr->dev_id = dev_id;
	clear_irqstats(intr);
	xnintr_list_lock();
	stat_counter_inc();
	list_add_tail(&intr->next, &intr_list);
	xnintr_list_unlock();
}

int xnintr_init(struct xnintr *intr, const char *name,
		int irq, xnisr_t isr, int flags)
{
	secondary_mode_only();

	/*
	 * A descriptor with a negative IRQ number is a placeholder
	 * and won't be attached, register it on the fly. Otherwise,
	 * this number must be valid.
	 */
	if (irq >= 0 && irq_to_desc(irq) == NULL)
		return -EINVAL;

	intr->irq = irq;
	intr->isr = isr;
	intr->dev_id = NULL;
	intr->name = name ? : "<unknown>";
	intr->flags = flags;
	intr->status = _XN_IRQSTAT_DISABLED;
	intr->unhandled = 0;
	raw_spin_lock_init(&intr->lock);
#ifdef CONFIG_STEELY_SHIRQ
	intr->next_handler = NULL;
#endif
	alloc_irqstats(intr);
	INIT_LIST_HEAD(&intr->next);

	if (irq < 0)
		register_intr(intr, NULL);

	return 0;
}
EXPORT_SYMBOL_GPL(xnintr_init);

void xnintr_destroy(struct xnintr *intr)
{
	secondary_mode_only();
	xnintr_detach(intr);
	free_irqstats(intr);
}
EXPORT_SYMBOL_GPL(xnintr_destroy);

int xnintr_attach(struct xnintr *intr, void *dev_id)
{
	int ret;

	secondary_mode_only();
	trace_steely_irq_attach(intr->irq);
	register_intr(intr, dev_id);

#ifdef CONFIG_SMP
	irq_set_affinity(intr->irq, &steely_cpu_affinity);
#endif /* CONFIG_SMP */

	raw_spin_lock(&intr->lock);

	if (test_and_set_bit(XN_IRQSTAT_ATTACHED, &intr->status)) {
		ret = -EBUSY;
		goto out;
	}

	ret = xnintr_irq_attach(intr);
	if (ret)
		clear_bit(XN_IRQSTAT_ATTACHED, &intr->status);
out:
	raw_spin_unlock(&intr->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(xnintr_attach);

void xnintr_detach(struct xnintr *intr)
{
	secondary_mode_only();
	trace_steely_irq_detach(intr->irq);

	xnintr_list_lock();

	raw_spin_lock(&intr->lock);

	if (test_and_clear_bit(XN_IRQSTAT_ATTACHED, &intr->status)) {
		xnintr_irq_detach(intr);
		stat_counter_dec();
	}

	raw_spin_unlock(&intr->lock);

	if (!list_empty(&intr->next))
		list_del(&intr->next);

	xnintr_list_unlock();
}
EXPORT_SYMBOL_GPL(xnintr_detach);

void xnintr_enable(struct xnintr *intr)
{
	unsigned long flags;

	secondary_mode_only();
	trace_steely_irq_enable(intr->irq);

	raw_spin_lock_irqsave(&intr->lock, flags);

	/*
	 * If disabled on entry, there is no way we could race with
	 * disable_irq_line().
	 */
	if (test_and_clear_bit(XN_IRQSTAT_DISABLED, &intr->status))
		enable_irq(intr->irq);

	raw_spin_unlock_irqrestore(&intr->lock, flags);
}
EXPORT_SYMBOL_GPL(xnintr_enable);

void xnintr_disable(struct xnintr *intr)
{
	unsigned long flags;

	secondary_mode_only();
	trace_steely_irq_disable(intr->irq);

	/* We only need a virtual masking. */
	raw_spin_lock_irqsave(&intr->lock, flags);

	/* Racing with disable_irq_line() is innocuous. */
	if (!test_and_set_bit(XN_IRQSTAT_DISABLED, &intr->status))
		disable_irq(intr->irq);

	raw_spin_unlock_irqrestore(&intr->lock, flags);
}
EXPORT_SYMBOL_GPL(xnintr_disable);

void xnintr_affinity(struct xnintr *intr, struct cpumask cpumask)
{
	secondary_mode_only();
#ifdef CONFIG_SMP
	irq_set_affinity(intr->irq, &cpumask);
#endif
}
EXPORT_SYMBOL_GPL(xnintr_affinity);

#ifdef CONFIG_STEELY_STATS

int xnintr_query_init(struct xnintr_iterator *iterator)
{
	iterator->cpus = *cpu_online_mask;
	iterator->prev = NULL;

	if (list_empty(&intr_list)) {
		iterator->curr = NULL;
		return 0;
	}

	iterator->curr = list_first_entry(&intr_list,
					  struct xnintr, next);

	/* The order is important here: first xnintr_list_rev then
	 * xnintr_count.  On the other hand, xnintr_attach/detach()
	 * update xnintr_count first and then xnintr_list_rev.  This
	 * should guarantee that we can't get an up-to-date
	 * xnintr_list_rev and old xnintr_count here. The other way
	 * around is not a problem as xnintr_query() will notice this
	 * fact later.  Should xnintr_list_rev change later,
	 * xnintr_query() will trigger an appropriate error below.
	 */
	iterator->list_rev = xnintr_list_rev;
	smp_mb();

	return xnintr_count;
}

int xnintr_query_next(struct xnintr_iterator *iterator,
		      char *name_buf)
{
	struct xnintr *intr;

	if (iterator->list_rev != xnintr_list_rev)
		return -EAGAIN;
redo:
	if (iterator->curr == NULL)
		return -ENODEV;

	if (cpumask_empty(&iterator->cpus)) {
		iterator->cpus = *cpu_online_mask;
		intr = NULL;
		if (iterator->prev != &nktimer)
			intr = xnintr_vec_next(iterator->prev);
		if (intr == NULL) {
			intr = iterator->curr;
			iterator->curr = NULL;
			iterator->prev = NULL;
			if (!list_is_last(&intr->next, &intr_list))
				iterator->curr = list_next_entry(intr, next);
			goto redo;
		}
	} else {
		intr = iterator->prev;
		if (intr == NULL) {
			if (iterator->curr == &nktimer)
				intr = &nktimer;
			else
				intr = xnintr_vec_first(iterator->curr->irq);
		}
	}

	iterator->cpu = cpumask_first(&iterator->cpus);
	cpumask_clear_cpu(iterator->cpu, &iterator->cpus);
	iterator->prev = intr;

	if (intr->irq < 0)
		ksformat(name_buf, XNOBJECT_NAME_LEN, "%s",
			 intr->name);
	else
		ksformat(name_buf, XNOBJECT_NAME_LEN, "IRQ%d: %s",
			 intr->irq, intr->name);

	query_irqstats(intr, iterator->cpu, iterator);

	return 0;
}

#endif /* CONFIG_STEELY_STATS */

#ifdef CONFIG_STEELY_VFILE

#include <steely/vfile.h>

static inline void format_irq_proc(struct xnintr *intr,
				   struct xnvfile_regular_iterator *it)
{
	xnvfile_puts(it, "        ");

	do {
		xnvfile_putc(it, ' ');
		xnvfile_puts(it, intr->name);
		intr = xnintr_vec_next(intr);
	} while (intr);
}

static int irq_vfile_show(struct xnvfile_regular_iterator *it,
			  void *data)
{
	struct xnintr *intr;
	int irq, cpu;

	xnintr_list_lock();

	if (list_empty(&intr_list))
		goto done;

	/* FIXME: We assume the entire output fits in a single page. */

	xnvfile_puts(it, "  IRQ ");

	for_each_realtime_cpu(cpu)
		xnvfile_printf(it, "        CPU%d", cpu);

	list_for_each_entry(intr, &intr_list, next) {
		irq = intr->irq;
		if (irq < 0)
			continue;
		xnvfile_printf(it, "\n%5d:", irq);
		for_each_realtime_cpu(cpu)
			xnvfile_printf(it, "%12u",
				       kstat_irqs_cpu(irq, cpu));
		format_irq_proc(intr, it);
	}

	xnvfile_putc(it, '\n');
done:
	xnintr_list_unlock();

	return 0;
}

static struct xnvfile_regular_ops irq_vfile_ops = {
	.show = irq_vfile_show,
};

static struct xnvfile_regular irq_vfile = {
	.ops = &irq_vfile_ops,
};

void xnintr_init_proc(void)
{
	xnvfile_init_regular("irq", &irq_vfile, &steely_vfroot);
}

void xnintr_cleanup_proc(void)
{
	xnvfile_destroy_regular(&irq_vfile);
}

#endif /* CONFIG_STEELY_VFILE */
