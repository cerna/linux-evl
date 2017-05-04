/*
 * Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 * Copyright (C) 2008 Efixo
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
#include <linux/types.h>
#include <linux/bitops.h>	/* For hweight_long */
#include <linux/irq_work.h>
#include <steely/heap.h>
#include <steely/sched.h>
#include <steely/synch.h>
#include <steely/select.h>

static LIST_HEAD(selector_list);

static DEFINE_PER_CPU(struct irq_work, deletion_irq_work);

void xnselect_init(struct xnselect *select_block)
{
	INIT_LIST_HEAD(&select_block->bindings);
}
EXPORT_SYMBOL_GPL(xnselect_init);

static inline int xnselect_wakeup(struct xnselector *selector)
{
	return xnsynch_flush(&selector->synchbase, 0) == XNSYNCH_RESCHED;
}

int xnselect_bind(struct xnselect *select_block,
		  struct xnselect_binding *binding,
		  struct xnselector *selector,
		  unsigned type,
		  unsigned index,
		  unsigned state)
{
	atomic_only();

	if (type >= XNSELECT_MAX_TYPES || index > __FD_SETSIZE)
		return -EINVAL;

	binding->selector = selector;
	binding->fd = select_block;
	binding->type = type;
	binding->bit_index = index;

	list_add_tail(&binding->slink, &selector->bindings);
	list_add_tail(&binding->link, &select_block->bindings);
	__FD_SET__(index, &selector->fds[type].expected);
	if (state) {
		__FD_SET__(index, &selector->fds[type].pending);
		if (xnselect_wakeup(selector))
			xnsched_run();
	} else
		__FD_CLR__(index, &selector->fds[type].pending);

	return 0;
}
EXPORT_SYMBOL_GPL(xnselect_bind);

/* Must be called with nklock locked irqs off */
int __xnselect_signal(struct xnselect *select_block, unsigned state)
{
	struct xnselect_binding *binding;
	struct xnselector *selector;
	int resched = 0;

	list_for_each_entry(binding, &select_block->bindings, link) {
		selector = binding->selector;
		if (state) {
			if (!__FD_ISSET__(binding->bit_index,
					&selector->fds[binding->type].pending)) {
				__FD_SET__(binding->bit_index,
					 &selector->fds[binding->type].pending);
				if (xnselect_wakeup(selector))
					resched = 1;
			}
		} else
			__FD_CLR__(binding->bit_index,
				 &selector->fds[binding->type].pending);
	}

	return resched;
}
EXPORT_SYMBOL_GPL(__xnselect_signal);

void xnselect_destroy(struct xnselect *select_block)
{
	struct xnselect_binding *binding, *tmp;
	struct xnselector *selector;
	int resched = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (list_empty(&select_block->bindings))
		goto out;

	list_for_each_entry_safe(binding, tmp, &select_block->bindings, link) {
		list_del(&binding->link);
		selector = binding->selector;
		__FD_CLR__(binding->bit_index,
			 &selector->fds[binding->type].expected);
		if (!__FD_ISSET__(binding->bit_index,
				&selector->fds[binding->type].pending)) {
			__FD_SET__(binding->bit_index,
				 &selector->fds[binding->type].pending);
			if (xnselect_wakeup(selector))
				resched = 1;
		}
		list_del(&binding->slink);
		xnlock_put_irqrestore(&nklock, s);
		xnfree(binding);
		xnlock_get_irqsave(&nklock, s);
	}
	if (resched)
		xnsched_run();
out:
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnselect_destroy);

static unsigned
fd_set_andnot(fd_set *result, fd_set *first, fd_set *second, unsigned n)
{
	unsigned i, not_empty = 0;

	for (i = 0; i < __FDELT__(n); i++)
		if((result->fds_bits[i] =
		    first->fds_bits[i] & ~(second->fds_bits[i])))
			not_empty = 1;

	if (i < __FDSET_LONGS__
	    && (result->fds_bits[i] =
		first->fds_bits[i] & ~(second->fds_bits[i]) & (__FDMASK__(n) - 1)))
		not_empty = 1;

	return not_empty;
}

static unsigned
fd_set_and(fd_set *result, fd_set *first, fd_set *second, unsigned n)
{
	unsigned i, not_empty = 0;

	for (i = 0; i < __FDELT__(n); i++)
		if((result->fds_bits[i] =
		    first->fds_bits[i] & second->fds_bits[i]))
			not_empty = 1;

	if (i < __FDSET_LONGS__
	    && (result->fds_bits[i] =
		first->fds_bits[i] & second->fds_bits[i] & (__FDMASK__(n) - 1)))
		not_empty = 1;

	return not_empty;
}

static void fd_set_zeropad(fd_set *set, unsigned n)
{
	unsigned i;

	i = __FDELT__(n);

	if (i < __FDSET_LONGS__)
		set->fds_bits[i] &= (__FDMASK__(n) - 1);

	for(i++; i < __FDSET_LONGS__; i++)
		set->fds_bits[i] = 0;
}

static unsigned fd_set_popcount(fd_set *set, unsigned n)
{
	unsigned count = 0, i;

	for (i = 0; i < __FDELT__(n); i++)
		if (set->fds_bits[i])
			count += hweight_long(set->fds_bits[i]);

	if (i < __FDSET_LONGS__ && (set->fds_bits[i] & (__FDMASK__(n) - 1)))
		count += hweight_long(set->fds_bits[i] & (__FDMASK__(n) - 1));

	return count;
}

int xnselector_init(struct xnselector *selector)
{
	unsigned int i;

	xnsynch_init(&selector->synchbase, XNSYNCH_FIFO, NULL);
	for (i = 0; i < XNSELECT_MAX_TYPES; i++) {
		__FD_ZERO__(&selector->fds[i].expected);
		__FD_ZERO__(&selector->fds[i].pending);
	}
	INIT_LIST_HEAD(&selector->bindings);

	return 0;
}
EXPORT_SYMBOL_GPL(xnselector_init);

int xnselect(struct xnselector *selector,
	     fd_set *out_fds[XNSELECT_MAX_TYPES],
	     fd_set *in_fds[XNSELECT_MAX_TYPES],
	     int nfds,
	     ktime_t timeout, xntmode_t timeout_mode)
{
	unsigned int i, not_empty = 0, count;
	int info = 0;
	spl_t s;

	if ((unsigned) nfds > __FD_SETSIZE)
		return -EINVAL;

	for (i = 0; i < XNSELECT_MAX_TYPES; i++)
		if (out_fds[i])
			fd_set_zeropad(out_fds[i], nfds);

	xnlock_get_irqsave(&nklock, s);
	for (i = 0; i < XNSELECT_MAX_TYPES; i++)
		if (out_fds[i]
		    && fd_set_andnot(out_fds[i], in_fds[i],
				     &selector->fds[i].expected, nfds))
			not_empty = 1;
	xnlock_put_irqrestore(&nklock, s);

	if (not_empty)
		return -ECHRNG;

	xnlock_get_irqsave(&nklock, s);
	for (i = 0; i < XNSELECT_MAX_TYPES; i++)
		if (out_fds[i]
		    && fd_set_and(out_fds[i], in_fds[i],
				  &selector->fds[i].pending, nfds))
			not_empty = 1;

	while (!not_empty) {
		info = xnsynch_sleep_on(&selector->synchbase,
					timeout, timeout_mode);

		for (i = 0; i < XNSELECT_MAX_TYPES; i++)
			if (out_fds[i]
			    && fd_set_and(out_fds[i], in_fds[i],
					  &selector->fds[i].pending, nfds))
				not_empty = 1;

		if (info & (XNBREAK | XNTIMEO))
			break;
	}
	xnlock_put_irqrestore(&nklock, s);

	if (not_empty) {
		for (count = 0, i = 0; i < XNSELECT_MAX_TYPES; i++)
			if (out_fds[i])
				count += fd_set_popcount(out_fds[i], nfds);

		return count;
	}

	if (info & XNBREAK)
		return -EINTR;

	return 0; /* Timeout */
}
EXPORT_SYMBOL_GPL(xnselect);

void xnselector_destroy(struct xnselector *selector)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	list_add_tail(&selector->destroy_link, &selector_list);
	irq_work_queue(&deletion_irq_work);
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnselector_destroy);

static void xnselector_destroy_loop(struct irq_work *work)
{
	struct xnselect_binding *binding, *tmpb;
	struct xnselector *selector, *tmps;
	struct xnselect *fd;
	int resched;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (list_empty(&selector_list))
		goto out;

	list_for_each_entry_safe(selector, tmps, &selector_list, destroy_link) {
		list_del(&selector->destroy_link);
		if (list_empty(&selector->bindings))
			goto release;
		list_for_each_entry_safe(binding, tmpb, &selector->bindings, slink) {
			list_del(&binding->slink);
			fd = binding->fd;
			list_del(&binding->link);
			xnlock_put_irqrestore(&nklock, s);
			xnfree(binding);
			xnlock_get_irqsave(&nklock, s);
		}
	release:
		resched = xnsynch_destroy(&selector->synchbase) == XNSYNCH_RESCHED;
		xnlock_put_irqrestore(&nklock, s);

		xnfree(selector);
		if (resched)
			xnsched_run();

		xnlock_get_irqsave(&nklock, s);
	}
out:
	xnlock_put_irqrestore(&nklock, s);
}

int xnselect_mount(void)
{
	int cpu;

	for_each_possible_cpu(cpu)
		init_irq_work(&per_cpu(deletion_irq_work, cpu),
			      xnselector_destroy_loop);

	return 0;
}

int xnselect_umount(void)
{
	return 0;
}
