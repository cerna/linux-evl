/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_INTR_H
#define _STEELY_INTR_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/cpumask.h>
#include <steely/stat.h>

/* Possible return values of a handler. */
#define XN_IRQ_NONE	 0x1
#define XN_IRQ_HANDLED	 0x2
#define XN_IRQ_STATMASK	 (XN_IRQ_NONE|XN_IRQ_HANDLED)
#define XN_IRQ_PROPAGATE 0x100
#define XN_IRQ_DISABLE   0x200

/* Init flags. */
#define XN_IRQTYPE_SHARED  0x1
#define XN_IRQTYPE_EDGE    0x2

/* Status bits. */
#define XN_IRQSTAT_ATTACHED   0
#define _XN_IRQSTAT_ATTACHED  (1 << XN_IRQSTAT_ATTACHED)
#define XN_IRQSTAT_DISABLED   1
#define _XN_IRQSTAT_DISABLED  (1 << XN_IRQSTAT_DISABLED)

struct xnintr;
struct xnsched;

typedef int (*xnisr_t)(struct xnintr *intr);

struct xnirqstat {
	/* Number of handled receipts since attachment. */
	xnstat_counter_t hits;
	/* Runtime accounting entity */
	xnstat_exectime_t account;
	/* Accumulated accounting entity */
	xnstat_exectime_t sum;
};

struct xnintr {
#ifdef CONFIG_STEELY_SHIRQ
	/* Next object in the IRQ-sharing chain. */
	struct xnintr *next_handler;
#endif
	/* Number of consequent unhandled interrupts */
	unsigned int unhandled;
	/* Interrupt service routine. */
	xnisr_t isr;
	/* Opaque device id. */
	void *dev_id;
	/* runtime status */
	unsigned long status;
	/* Creation flags. */
	int flags;
	/* IRQ number. */
	unsigned int irq;
	/* Symbolic name. */
	const char *name;
	/* Descriptor maintenance lock. */
	raw_spinlock_t lock;
#ifdef CONFIG_STEELY_STATS
	/* Statistics. */
	struct xnirqstat *stats;
#endif
	struct list_head next;
};

struct xnintr_iterator {
	/* Current CPU. */
	int cpu;
	/* Remaining CPUs to iterate over. */
	struct cpumask cpus;
	/* Current hit counter. */
	unsigned long hits;
	/* Used CPU time in current accounting period. */
	ktime_t exectime_period;
	/* Length of accounting period. */
	ktime_t account_period;
	/* Overall CPU time consumed. */
	ktime_t exectime_total;
	/* System-wide xnintr list revision (internal use). */
	int list_rev;
	/* Currently visited xnintr object (internal use). */
	struct xnintr *curr;
	/* Previously visited xnintr object (internal use). */
	struct xnintr *prev;
};

extern struct xnintr nktimer;

int xnintr_mount(void);

irqreturn_t xnintr_core_clock_handler(int irq,
				      void *dev_id);

void xnintr_init_proc(void);

void xnintr_cleanup_proc(void);

    /* Public interface. */

int xnintr_init(struct xnintr *intr,
		const char *name,
		int irq,
		xnisr_t isr,
		int flags);

void xnintr_destroy(struct xnintr *intr);

int xnintr_attach(struct xnintr *intr,
		  void *dev_id);

void xnintr_detach(struct xnintr *intr);

void xnintr_enable(struct xnintr *intr);

void xnintr_disable(struct xnintr *intr);

void xnintr_affinity(struct xnintr *intr,
		     struct cpumask cpumask);

int xnintr_query_init(struct xnintr_iterator *iterator);

int xnintr_query_next(struct xnintr_iterator *iterator,
		      char *name_buf);

void xnintr_list_lock(void);

void xnintr_list_unlock(void);

void *steely_alloc_irq_work(size_t size);

void steely_free_irq_work(void *p);

#endif /* !_STEELY_INTR_H */
