/*
 * Copyright (C) 2001-2008,2012 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004,2005 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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
#ifndef _STEELY_KERNEL_LOCK_H
#define _STEELY_KERNEL_LOCK_H

#include <linux/irq_pipeline.h>
#include <linux/percpu.h>
#include <linux/ktime.h>
#include <steely/assert.h>

typedef unsigned long spl_t;

#define splhigh(x)  ((x) = head_irq_save() & 1)
#ifdef CONFIG_SMP
#define splexit(x)  head_irq_restore(x & 1)
#else /* !CONFIG_SMP */
#define splexit(x)  head_irq_restore(x)
#endif /* !CONFIG_SMP */
#define splmax()    head_irq_disable()
#define splnone()   head_irq_enable()
#define spltest()   head_irqs_disabled()

#if STEELY_DEBUG(LOCKING)

struct xnlock {
	unsigned owner;
	arch_spinlock_t alock;
	const char *file;
	const char *function;
	unsigned int line;
	int cpu;
	ktime_t spin_time;
	ktime_t lock_date;
};

struct xnlockinfo {
	ktime_t spin_time;
	ktime_t lock_time;
	const char *file;
	const char *function;
	unsigned int line;
};

#define XNARCH_LOCK_UNLOCKED (struct xnlock) {	\
	~0,					\
	__ARCH_SPIN_LOCK_UNLOCKED,		\
	NULL,					\
	NULL,					\
	0,					\
	-1,					\
	0LL,					\
	0LL,					\
}

#define XNLOCK_DBG_CONTEXT		, __FILE__, __LINE__, __FUNCTION__
#define XNLOCK_DBG_CONTEXT_ARGS					\
	, const char *file, int line, const char *function
#define XNLOCK_DBG_PASS_CONTEXT		, file, line, function

void xnlock_dbg_prepare_acquire(ktime_t *start);
void xnlock_dbg_prepare_spin(unsigned int *spin_limit);
void xnlock_dbg_acquired(struct xnlock *lock, int cpu,
			 ktime_t *start,
			 const char *file, int line,
			 const char *function);
int xnlock_dbg_release(struct xnlock *lock,
			 const char *file, int line,
			 const char *function);

DECLARE_PER_CPU(struct xnlockinfo, xnlock_stats);

#else /* !STEELY_DEBUG(LOCKING) */

struct xnlock {
	unsigned owner;
	arch_spinlock_t alock;
};

#define XNARCH_LOCK_UNLOCKED			\
	(struct xnlock) {			\
		~0,				\
		__ARCH_SPIN_LOCK_UNLOCKED,	\
	}

#define XNLOCK_DBG_CONTEXT
#define XNLOCK_DBG_CONTEXT_ARGS
#define XNLOCK_DBG_PASS_CONTEXT

static inline
void xnlock_dbg_prepare_acquire(ktime_t *start)
{
}

static inline
void xnlock_dbg_prepare_spin(unsigned int *spin_limit)
{
}

static inline void
xnlock_dbg_acquired(struct xnlock *lock, int cpu,
		    ktime_t *start)
{
}

static inline int xnlock_dbg_release(struct xnlock *lock)
{
	return 0;
}

#endif /* !STEELY_DEBUG(LOCKING) */

#if defined(CONFIG_SMP) || STEELY_DEBUG(LOCKING)

#define xnlock_get(lock)		__xnlock_get(lock  XNLOCK_DBG_CONTEXT)
#define xnlock_put(lock)		__xnlock_put(lock  XNLOCK_DBG_CONTEXT)
#define xnlock_get_irqsave(lock,x) \
	((x) = __xnlock_get_irqsave(lock  XNLOCK_DBG_CONTEXT))
#define xnlock_put_irqrestore(lock,x) \
	__xnlock_put_irqrestore(lock,x  XNLOCK_DBG_CONTEXT)
#define xnlock_clear_irqoff(lock)	xnlock_put_irqrestore(lock, 1)
#define xnlock_clear_irqon(lock)	xnlock_put_irqrestore(lock, 0)

static inline void xnlock_init (struct xnlock *lock)
{
	*lock = XNARCH_LOCK_UNLOCKED;
}

#define DECLARE_XNLOCK(lock)		struct xnlock lock
#define DECLARE_EXTERN_XNLOCK(lock)	extern struct xnlock lock
#define DEFINE_XNLOCK(lock)		struct xnlock lock = XNARCH_LOCK_UNLOCKED
#define DEFINE_PRIVATE_XNLOCK(lock)	static DEFINE_XNLOCK(lock)

static inline int ____xnlock_get(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS)
{
	int cpu = raw_smp_processor_id();
	ktime_t start;

	if (lock->owner == cpu)
		return 2;

	xnlock_dbg_prepare_acquire(&start);

	arch_spin_lock(&lock->alock);
	lock->owner = cpu;

	xnlock_dbg_acquired(lock, cpu, &start /*, */ XNLOCK_DBG_PASS_CONTEXT);

	return 0;
}

static inline void ____xnlock_put(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS)
{
	if (xnlock_dbg_release(lock /*, */ XNLOCK_DBG_PASS_CONTEXT))
		return;

	lock->owner = ~0U;
	arch_spin_unlock(&lock->alock);
}

#ifndef CONFIG_STEELY_ARCH_OUTOFLINE_XNLOCK
#define ___xnlock_get ____xnlock_get
#define ___xnlock_put ____xnlock_put
#else /* out of line xnlock */
int ___xnlock_get(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS);

void ___xnlock_put(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS);
#endif /* out of line xnlock */

static inline spl_t
__xnlock_get_irqsave(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS)
{
	unsigned long flags;

	splhigh(flags);

	flags |= ___xnlock_get(lock /*, */ XNLOCK_DBG_PASS_CONTEXT);

	return flags;
}

static inline void __xnlock_put_irqrestore(struct xnlock *lock, spl_t flags
					   /*, */ XNLOCK_DBG_CONTEXT_ARGS)
{
	/* Only release the lock if we didn't take it recursively. */
	if (!(flags & 2))
		___xnlock_put(lock /*, */ XNLOCK_DBG_PASS_CONTEXT);

	splexit(flags & 1);
}

static inline int xnlock_is_owner(struct xnlock *lock)
{
	return lock->owner == raw_smp_processor_id();
}

static inline int __xnlock_get(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS)
{
	return ___xnlock_get(lock /* , */ XNLOCK_DBG_PASS_CONTEXT);
}

static inline void __xnlock_put(struct xnlock *lock /*, */ XNLOCK_DBG_CONTEXT_ARGS)
{
	___xnlock_put(lock /*, */ XNLOCK_DBG_PASS_CONTEXT);
}

#else /* !(CONFIG_SMP || STEELY_DEBUG(LOCKING) */

#define xnlock_init(lock)		do { } while(0)
#define xnlock_get(lock)		do { } while(0)
#define xnlock_put(lock)		do { } while(0)
#define xnlock_get_irqsave(lock,x)	splhigh(x)
#define xnlock_put_irqrestore(lock,x)	splexit(x)
#define xnlock_clear_irqoff(lock)	splmax()
#define xnlock_clear_irqon(lock)	splnone()
#define xnlock_is_owner(lock)		1

#define DECLARE_XNLOCK(lock)
#define DECLARE_EXTERN_XNLOCK(lock)
#define DEFINE_XNLOCK(lock)
#define DEFINE_PRIVATE_XNLOCK(lock)

#endif /* !(CONFIG_SMP || STEELY_DEBUG(LOCKING)) */

DECLARE_EXTERN_XNLOCK(nklock);

#endif /* !_STEELY_KERNEL_LOCK_H */
