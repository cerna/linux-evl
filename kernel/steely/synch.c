/*
 * Copyright (C) 2001-2008 Philippe Gerum <rpm@xenomai.org>.
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
#include <stdarg.h>
#include <linux/signal.h>
#include <steely/sched.h>
#include <steely/synch.h>
#include <steely/thread.h>
#include <steely/clock.h>
#include <uapi/steely/signal.h>
#include <trace/events/steely-core.h>

#define PP_CEILING_MASK 0xff

static inline int get_ceiling_value(struct xnsynch *synch)
{
	/*
	 * The ceiling priority value is stored in user-writable
	 * memory, make sure to constrain it within valid bounds for
	 * xnsched_class_rt before using it.
	 */
	return *synch->ceiling_ref & PP_CEILING_MASK ?: 1;
}

struct xnsynch *lookup_lazy_pp(xnhandle_t handle);

void xnsynch_init(struct xnsynch *synch, int flags, atomic_t *fastlock)
{
	if (flags & (XNSYNCH_PI|XNSYNCH_PP))
		flags |= XNSYNCH_PRIO | XNSYNCH_OWNER;	/* Obviously... */

	synch->status = flags & ~XNSYNCH_CLAIMED;
	synch->owner = NULL;
	synch->cleanup = NULL;	/* for PI/PP only. */
	synch->wprio = -1;
	synch->ceiling_ref = NULL;
	INIT_LIST_HEAD(&synch->pendq);

	if (flags & XNSYNCH_OWNER) {
		BUG_ON(fastlock == NULL);
		synch->fastlock = fastlock;
		atomic_set(fastlock, XN_NO_HANDLE);
	} else
		synch->fastlock = NULL;
}
EXPORT_SYMBOL_GPL(xnsynch_init);

void xnsynch_init_protect(struct xnsynch *synch, int flags,
			  atomic_t *fastlock, u32 *ceiling_ref)
{
	xnsynch_init(synch, (flags & ~XNSYNCH_PI) | XNSYNCH_PP, fastlock);
	synch->ceiling_ref = ceiling_ref;
}

int xnsynch_destroy(struct xnsynch *synch)
{
	int ret;
	
	ret = xnsynch_flush(synch, XNRMID);
	STEELY_BUG_ON(STEELY, synch->status & XNSYNCH_CLAIMED);

	return ret;
}
EXPORT_SYMBOL_GPL(xnsynch_destroy);

int xnsynch_sleep_on(struct xnsynch *synch, ktime_t timeout,
		     xntmode_t timeout_mode)
{
	struct xnthread *thread;
	spl_t s;

	primary_mode_only();

	STEELY_BUG_ON(STEELY, synch->status & XNSYNCH_OWNER);

	thread = xnthread_current();

	if (IS_ENABLED(CONFIG_STEELY_DEBUG_MUTEX_SLEEP) &&
	    thread->res_count > 0 &&
	    xnthread_test_state(thread, XNWARN))
		xnthread_signal(thread, SIGDEBUG, SIGDEBUG_MUTEX_SLEEP);
	
	xnlock_get_irqsave(&nklock, s);

	trace_steely_synch_sleepon(synch, thread);

	if ((synch->status & XNSYNCH_PRIO) == 0) /* i.e. FIFO */
		list_add_tail(&thread->plink, &synch->pendq);
	else /* i.e. priority-sorted */
		list_add_priff(thread, &synch->pendq, wprio, plink);

	xnthread_suspend(thread, XNPEND, timeout, timeout_mode, synch);

	xnlock_put_irqrestore(&nklock, s);

	return xnthread_test_info(thread, XNRMID|XNTIMEO|XNBREAK);
}
EXPORT_SYMBOL_GPL(xnsynch_sleep_on);

struct xnthread *xnsynch_wakeup_one_sleeper(struct xnsynch *synch)
{
	struct xnthread *thread;
	spl_t s;

	STEELY_BUG_ON(STEELY, synch->status & XNSYNCH_OWNER);

	xnlock_get_irqsave(&nklock, s);

	if (list_empty(&synch->pendq)) {
		thread = NULL;
		goto out;
	}

	trace_steely_synch_wakeup(synch);
	thread = list_first_entry(&synch->pendq, struct xnthread, plink);
	list_del(&thread->plink);
	thread->wchan = NULL;
	xnthread_resume(thread, XNPEND);
out:
	xnlock_put_irqrestore(&nklock, s);

	return thread;
}
EXPORT_SYMBOL_GPL(xnsynch_wakeup_one_sleeper);

int xnsynch_wakeup_many_sleepers(struct xnsynch *synch, int nr)
{
	struct xnthread *thread, *tmp;
	int nwakeups = 0;
	spl_t s;

	STEELY_BUG_ON(STEELY, synch->status & XNSYNCH_OWNER);

	xnlock_get_irqsave(&nklock, s);

	if (list_empty(&synch->pendq))
		goto out;

	trace_steely_synch_wakeup_many(synch);

	list_for_each_entry_safe(thread, tmp, &synch->pendq, plink) {
		if (nwakeups++ >= nr)
			break;
		list_del(&thread->plink);
		thread->wchan = NULL;
		xnthread_resume(thread, XNPEND);
	}
out:
	xnlock_put_irqrestore(&nklock, s);

	return nwakeups;
}
EXPORT_SYMBOL_GPL(xnsynch_wakeup_many_sleepers);

void xnsynch_wakeup_this_sleeper(struct xnsynch *synch, struct xnthread *sleeper)
{
	spl_t s;

	STEELY_BUG_ON(STEELY, synch->status & XNSYNCH_OWNER);

	xnlock_get_irqsave(&nklock, s);

	trace_steely_synch_wakeup(synch);
	list_del(&sleeper->plink);
	sleeper->wchan = NULL;
	xnthread_resume(sleeper, XNPEND);

	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xnsynch_wakeup_this_sleeper);

static inline void raise_boost_flag(struct xnthread *owner)
{
	/* Backup the base priority at first boost only. */
	if (!xnthread_test_state(owner, XNBOOST)) {
		owner->bprio = owner->cprio;
		xnthread_set_state(owner, XNBOOST);
	}
}

static void inherit_thread_priority(struct xnthread *owner,
				    struct xnthread *target)
{
	if (xnthread_test_state(owner, XNZOMBIE))
		return;
	
	/* Apply the scheduling policy of "target" to "thread" */
	xnsched_track_policy(owner, target);

	/*
	 * Owner may be sleeping, propagate priority update through
	 * the PI chain if needed.
	 */
	if (owner->wchan)
		xnsynch_requeue_sleeper(owner);
}

static void __ceil_owner_priority(struct xnthread *owner, int prio)
{
	if (xnthread_test_state(owner, XNZOMBIE))
		return;
	/*
	 * Raise owner priority to the ceiling value, this implicitly
	 * selects SCHED_FIFO for the owner.
	 */
	xnsched_protect_priority(owner, prio);

	if (owner->wchan)
		xnsynch_requeue_sleeper(owner);
}

static void adjust_boost(struct xnthread *owner, struct xnthread *target)
{
	struct xnsynch *synch;

	/*
	 * CAUTION: we may have PI and PP-enabled objects among the
	 * boosters, considering the leader of synch->pendq is
	 * therefore NOT enough for determining the next boost
	 * priority, since PP is tracked on acquisition, not on
	 * contention. Check the head of the booster list instead.
	 */
	synch = list_first_entry(&owner->boosters, struct xnsynch, next);
	if (synch->wprio == owner->wprio)
		return;
	
	if (synch->status & XNSYNCH_PP)
		__ceil_owner_priority(owner, get_ceiling_value(synch));
	else {
		STEELY_BUG_ON(STEELY, list_empty(&synch->pendq));
		if (target == NULL)
			target = list_first_entry(&synch->pendq,
						  struct xnthread, plink);
		inherit_thread_priority(owner, target);
	}
}

static void ceil_owner_priority(struct xnsynch *synch)
{
	struct xnthread *owner = synch->owner;
	int wprio;

	/* PP ceiling values are implicitly based on the RT class. */
	wprio = xnsched_calc_wprio(&xnsched_class_rt,
				   get_ceiling_value(synch));
	synch->wprio = wprio;
	list_add_priff(synch, &owner->boosters, wprio, next);
	raise_boost_flag(owner);
	synch->status |= XNSYNCH_CEILING;

	/*
	 * If the ceiling value is lower than the current effective
	 * priority, we must not adjust the latter.  BEWARE: not only
	 * this restriction is required to keep the PP logic right,
	 * but this is also a basic assumption made by all
	 * xnthread_commit_ceiling() callers which won't check for any
	 * rescheduling opportunity upon return.
	 *
	 * However we do want the object to be linked to the booster
	 * list, and XNBOOST must appear in the current thread status.
	 *
	 * This way, setparam() won't be allowed to decrease the
	 * current weighted priority below the ceiling value, until we
	 * eventually release this object.
	 */
	if (wprio > owner->wprio)
		adjust_boost(owner, NULL);
}

static inline
void track_owner(struct xnsynch *synch, struct xnthread *owner)
{
	synch->owner = owner;
}

static inline  /* nklock held, irqs off */
void set_current_owner_locked(struct xnsynch *synch, struct xnthread *owner)
{
	/*
	 * Update the owner information, and apply priority protection
	 * for PP objects. We may only get there if owner is current,
	 * or blocked.
	 */
	track_owner(synch, owner);
	if (synch->status & XNSYNCH_PP)
		ceil_owner_priority(synch);
}

static inline
void set_current_owner(struct xnsynch *synch, struct xnthread *owner)
{
	spl_t s;

	track_owner(synch, owner);
	if (synch->status & XNSYNCH_PP) {
		xnlock_get_irqsave(&nklock, s);
		ceil_owner_priority(synch);
		xnlock_put_irqrestore(&nklock, s);
	}
}

static inline
xnhandle_t get_owner_handle(xnhandle_t ownerh, struct xnsynch *synch)
{
	/*
	 * On acquisition from kernel space, the fast lock handle
	 * should bear the FLCEIL bit for PP objects, so that userland
	 * takes the slow path on release, jumping to the kernel for
	 * dropping the ceiling priority boost.
	 */
	if (synch->status & XNSYNCH_PP)
		ownerh = xnsynch_fast_ceiling(ownerh);

	return ownerh;
}

static void commit_ceiling(struct xnsynch *synch, struct xnthread *curr)
{
	xnhandle_t oldh, h;
	atomic_t *lockp;

	track_owner(synch, curr);
	ceil_owner_priority(synch);
	/*
	 * Raise FLCEIL, which indicates a kernel entry will be
	 * required for releasing this resource.
	 */
	lockp = xnsynch_fastlock(synch);
	do {
		h = atomic_read(lockp);
		oldh = atomic_cmpxchg(lockp, h, xnsynch_fast_ceiling(h));
	} while (oldh != h);
}

void xnsynch_commit_ceiling(struct xnthread *curr)  /* nklock held, irqs off */
{
	struct xnsynch *synch;
	atomic_t *lockp;

	/* curr->u_window has to be valid, curr bears XNUSER. */
	synch = lookup_lazy_pp(curr->u_window->pp_pending);
	if (synch == NULL) {
		/*
		 * If pp_pending is a bad handle, don't panic but
		 * rather ignore: we don't want a misbehaving userland
		 * to crash the kernel.
		 */
		STEELY_WARN_ON_ONCE(USER, 1);
		goto out;
	}

	/*
	 * For PP locks, userland does, in that order:
	 *
	 * -- LOCK
	 * 1. curr->u_window->pp_pending = lock_handle
	 *    barrier();
	 * 2. atomic_cmpxchg(lockp, XN_NO_HANDLE, curr->handle);
	 *
	 * -- UNLOCK
	 * 1. atomic_cmpxchg(lockp, curr->handle, XN_NO_HANDLE); [unclaimed]
	 *    barrier();
	 * 2. curr->u_window->pp_pending = XN_NO_HANDLE
	 *
	 * Make sure we have not been caught in a rescheduling in
	 * between those steps. If we did, then we won't be holding
	 * the lock as we schedule away, therefore no priority update
	 * must take place.
	 */
	lockp = xnsynch_fastlock(synch);
	if (xnsynch_fast_owner_check(lockp, curr->handle))
		return;

	/*
	 * In rare cases, we could be called multiple times for
	 * committing a lazy ceiling for the same object, e.g. if
	 * userland is preempted in the middle of a recursive locking
	 * sequence.
	 *
	 * This stems from the fact that userland has to update
	 * ->pp_pending prior to trying to grab the lock atomically,
	 * at which point it can figure out whether a recursive
	 * locking happened. We get out of this trap by testing the
	 * XNSYNCH_CEILING flag.
	 */
	if ((synch->status & XNSYNCH_CEILING) == 0)
		commit_ceiling(synch, curr);
out:
	curr->u_window->pp_pending = XN_NO_HANDLE;
}

int xnsynch_try_acquire(struct xnsynch *synch)
{
	struct xnthread *curr;
	atomic_t *lockp;
	xnhandle_t h;

	primary_mode_only();

	STEELY_BUG_ON(STEELY, (synch->status & XNSYNCH_OWNER) == 0);

	curr = xnthread_current();
	lockp = xnsynch_fastlock(synch);
	trace_steely_synch_try_acquire(synch, curr);

	h = atomic_cmpxchg(lockp, XN_NO_HANDLE,
			   get_owner_handle(curr->handle, synch));
	if (h != XN_NO_HANDLE)
		return xnhandle_get_id(h) == curr->handle ?
			-EDEADLK : -EBUSY;

	set_current_owner(synch, curr);
	xnthread_get_resource(curr);

	return 0;
}
EXPORT_SYMBOL_GPL(xnsynch_try_acquire);

int xnsynch_acquire(struct xnsynch *synch, ktime_t timeout,
		    xntmode_t timeout_mode)
{
	struct xnthread *curr, *owner;
	xnhandle_t currh, h, oldh;
	atomic_t *lockp;
	spl_t s;

	primary_mode_only();

	STEELY_BUG_ON(STEELY, (synch->status & XNSYNCH_OWNER) == 0);

	curr = xnthread_current();
	currh = curr->handle;
	lockp = xnsynch_fastlock(synch);
	trace_steely_synch_acquire(synch, curr);
redo:
	/* Basic form of xnsynch_try_acquire(). */
	h = atomic_cmpxchg(lockp, XN_NO_HANDLE,
			   get_owner_handle(currh, synch));
	if (likely(h == XN_NO_HANDLE)) {
		set_current_owner(synch, curr);
		xnthread_get_resource(curr);
		return 0;
	}

	xnlock_get_irqsave(&nklock, s);

	/*
	 * Set claimed bit.  In case it appears to be set already,
	 * re-read its state under nklock so that we don't miss any
	 * change between the lock-less read and here. But also try to
	 * avoid cmpxchg where possible. Only if it appears not to be
	 * set, start with cmpxchg directly.
	 */
	if (xnsynch_fast_is_claimed(h)) {
		oldh = atomic_read(lockp);
		goto test_no_owner;
	}

	do {
		oldh = atomic_cmpxchg(lockp, h, xnsynch_fast_claimed(h));
		if (likely(oldh == h))
			break;
	test_no_owner:
		if (oldh == XN_NO_HANDLE) {
			/* Mutex released from another cpu. */
			xnlock_put_irqrestore(&nklock, s);
			goto redo;
		}
		h = oldh;
	} while (!xnsynch_fast_is_claimed(h));

	owner = xnthread_lookup(h);
	if (owner == NULL) {
		/*
		 * The handle is broken, therefore pretend that the
		 * synch object was deleted to signal an error.
		 */
		xnthread_set_info(curr, XNRMID);
		goto out;
	}

	/*
	 * This is the contended path. We just detected an earlier
	 * syscall-less fast locking from userland, fix up the
	 * in-kernel state information accordingly.
	 *
	 * The consistency of the state information is guaranteed,
	 * because we just raised the claim bit atomically for this
	 * contended lock, therefore userland will have to jump to the
	 * kernel when releasing it, instead of doing a fast
	 * unlock. Since we currently own the superlock, consistency
	 * wrt transfer_ownership() is guaranteed through
	 * serialization.
	 *
	 * CAUTION: in this particular case, the only assumptions we
	 * can safely make is that *owner is valid but not current on
	 * this CPU.
	 */
	track_owner(synch, owner);
	xnsynch_detect_relaxed_owner(synch, curr);

	if ((synch->status & XNSYNCH_PRIO) == 0) { /* i.e. FIFO */
		list_add_tail(&curr->plink, &synch->pendq);
		goto block;
	}

	if (curr->wprio > owner->wprio) {
		if (xnthread_test_info(owner, XNWAKEN) && owner->wwake == synch) {
			/* Ownership is still pending, steal the resource. */
			set_current_owner_locked(synch, curr);
			xnthread_clear_info(curr, XNRMID | XNTIMEO | XNBREAK);
			xnthread_set_info(owner, XNROBBED);
			goto grab;
		}

		list_add_priff(curr, &synch->pendq, wprio, plink);

		if (synch->status & XNSYNCH_PI) {
			raise_boost_flag(owner);

			if (synch->status & XNSYNCH_CLAIMED)
				list_del(&synch->next); /* owner->boosters */
			else
				synch->status |= XNSYNCH_CLAIMED;

			synch->wprio = curr->wprio;
			list_add_priff(synch, &owner->boosters, wprio, next);
			/*
			 * curr->wprio > owner->wprio implies that
			 * synch must be leading the booster list
			 * after insertion, so we may call
			 * inherit_thread_priority() for tracking
			 * current's priority directly without going
			 * through adjust_boost().
			 */
			inherit_thread_priority(owner, curr);
		}
	} else
		list_add_priff(curr, &synch->pendq, wprio, plink);
block:
	xnthread_suspend(curr, XNPEND, timeout, timeout_mode, synch);
	curr->wwake = NULL;
	xnthread_clear_info(curr, XNWAKEN);

	if (xnthread_test_info(curr, XNRMID | XNTIMEO | XNBREAK))
		goto out;

	if (xnthread_test_info(curr, XNROBBED)) {
		/*
		 * Somebody stole us the ownership while we were ready
		 * to run, waiting for the CPU: we need to wait again
		 * for the resource.
		 */
		if (timeout_mode != XN_RELATIVE || timeout_infinite(timeout)) {
			xnlock_put_irqrestore(&nklock, s);
			goto redo;
		}
		timeout = xntimer_get_timeout_stopped(&curr->rtimer);
		if (ktime_to_ns(timeout) > 1) { /* Otherwise, it's too late. */
			xnlock_put_irqrestore(&nklock, s);
			goto redo;
		}
		xnthread_set_info(curr, XNTIMEO);
		goto out;
	}
grab:
	xnthread_get_resource(curr);

	if (xnsynch_pended_p(synch))
		currh = xnsynch_fast_claimed(currh);

	/* Set new ownership for this object. */
	atomic_set(lockp, get_owner_handle(currh, synch));
out:
	xnlock_put_irqrestore(&nklock, s);

	return xnthread_test_info(curr, XNRMID|XNTIMEO|XNBREAK);
}
EXPORT_SYMBOL_GPL(xnsynch_acquire);

static void drop_booster(struct xnsynch *synch, struct xnthread *owner)
{
	list_del(&synch->next);	/* owner->boosters */

	if (list_empty(&owner->boosters)) {
		xnthread_clear_state(owner, XNBOOST);
		inherit_thread_priority(owner, owner);
	} else
		adjust_boost(owner, NULL);
}

static inline void clear_pi_boost(struct xnsynch *synch,
				  struct xnthread *owner)
{	/* nklock held, irqs off */
	synch->status &= ~XNSYNCH_CLAIMED;
	drop_booster(synch, owner);
}

static inline void clear_pp_boost(struct xnsynch *synch,
				  struct xnthread *owner)
{	/* nklock held, irqs off */
	synch->status &= ~XNSYNCH_CEILING;
	drop_booster(synch, owner);
}

static bool transfer_ownership(struct xnsynch *synch,
			       struct xnthread *lastowner)
{				/* nklock held, irqs off */
	struct xnthread *nextowner;
	xnhandle_t nextownerh;
	atomic_t *lockp;

	lockp = xnsynch_fastlock(synch);

	/*
	 * Our caller checked for contention locklessly, so we do have
	 * to check again under lock in a different way.
	 */
	if (list_empty(&synch->pendq)) {
		synch->owner = NULL;
		atomic_set(lockp, XN_NO_HANDLE);
		return false;
	}

	nextowner = list_first_entry(&synch->pendq, struct xnthread, plink);
	list_del(&nextowner->plink);
	nextowner->wchan = NULL;
	nextowner->wwake = synch;
	set_current_owner_locked(synch, nextowner);
	xnthread_set_info(nextowner, XNWAKEN);
	xnthread_resume(nextowner, XNPEND);

	if (synch->status & XNSYNCH_CLAIMED)
		clear_pi_boost(synch, lastowner);

	nextownerh = get_owner_handle(nextowner->handle, synch);
	if (xnsynch_pended_p(synch))
		nextownerh = xnsynch_fast_claimed(nextownerh);

	atomic_set(lockp, nextownerh);

	return true;
}

bool xnsynch_release(struct xnsynch *synch, struct xnthread *curr)
{
	bool need_resched = false;
	xnhandle_t currh, h;
	atomic_t *lockp;
	spl_t s;

	STEELY_BUG_ON(STEELY, (synch->status & XNSYNCH_OWNER) == 0);

	trace_steely_synch_release(synch);

	if (xnthread_put_resource(curr))
		return false;

	lockp = xnsynch_fastlock(synch);
	currh = curr->handle;
	/*
	 * FLCEIL may only be raised by the owner, or when the owner
	 * is blocked waiting for the synch (ownership transfer). In
	 * addition, only the current owner of a synch may release it,
	 * therefore we can't race while testing FLCEIL locklessly.
	 * All updates to FLCLAIM are covered by the superlock.
	 *
	 * Therefore, clearing the fastlock racelessly in this routine
	 * without leaking FLCEIL/FLCLAIM updates can be achieved by
	 * holding the superlock.
	 */
	xnlock_get_irqsave(&nklock, s);

	h = atomic_cmpxchg(lockp, currh, XN_NO_HANDLE);
	if ((h & ~XNSYNCH_FLCEIL) != currh)
		/* FLCLAIM set, synch is contended. */
		need_resched = transfer_ownership(synch, curr);
	else if (h != currh)	/* FLCEIL set, FLCLAIM clear. */
		atomic_set(lockp, XN_NO_HANDLE);

	if (synch->status & XNSYNCH_PP) {
		clear_pp_boost(synch, curr);
		need_resched = true;
	}

	xnlock_put_irqrestore(&nklock, s);

	return need_resched;
}
EXPORT_SYMBOL_GPL(xnsynch_release);

void xnsynch_requeue_sleeper(struct xnthread *thread)
{				/* nklock held, irqs off */
	struct xnsynch *synch = thread->wchan;
	struct xnthread *owner;

	STEELY_BUG_ON(STEELY, !(synch->status & XNSYNCH_PRIO));

	/*
	 * Update the position in the pend queue of a thread waiting
	 * for a lock. This routine propagates the change throughout
	 * the PI chain if required.
	 */
	list_del(&thread->plink);
	list_add_priff(thread, &synch->pendq, wprio, plink);
	owner = synch->owner;

	/* Only PI-enabled objects are of interest here. */
	if ((synch->status & XNSYNCH_PI) == 0)
		return;

	synch->wprio = thread->wprio;
	if (synch->status & XNSYNCH_CLAIMED)
		list_del(&synch->next);
	else {
		synch->status |= XNSYNCH_CLAIMED;
		raise_boost_flag(owner);
	}

	list_add_priff(synch, &owner->boosters, wprio, next);
	adjust_boost(owner, thread);
}
EXPORT_SYMBOL_GPL(xnsynch_requeue_sleeper);

struct xnthread *xnsynch_peek_pendq(struct xnsynch *synch)
{
	struct xnthread *thread = NULL;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!list_empty(&synch->pendq))
		thread = list_first_entry(&synch->pendq,
					  struct xnthread, plink);

	xnlock_put_irqrestore(&nklock, s);

	return thread;
}
EXPORT_SYMBOL_GPL(xnsynch_peek_pendq);

int xnsynch_flush(struct xnsynch *synch, int reason)
{
	struct xnthread *sleeper, *tmp;
	int ret;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	trace_steely_synch_flush(synch);

	if (list_empty(&synch->pendq)) {
		STEELY_BUG_ON(STEELY, synch->status & XNSYNCH_CLAIMED);
		ret = XNSYNCH_DONE;
	} else {
		ret = XNSYNCH_RESCHED;
		list_for_each_entry_safe(sleeper, tmp, &synch->pendq, plink) {
			list_del(&sleeper->plink);
			xnthread_set_info(sleeper, reason);
			sleeper->wchan = NULL;
			xnthread_resume(sleeper, XNPEND);
		}
		if (synch->status & XNSYNCH_CLAIMED)
			clear_pi_boost(synch, synch->owner);
	}

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}
EXPORT_SYMBOL_GPL(xnsynch_flush);

void xnsynch_forget_sleeper(struct xnthread *thread)
{				/* nklock held, irqs off */
	struct xnsynch *synch = thread->wchan;
	struct xnthread *owner, *target;

	/*
	 * Do all the necessary housekeeping chores to stop a thread
	 * from waiting on a given synchronization object. Doing so
	 * may require to update a PI chain.
	 */
	trace_steely_synch_forget(synch);

	xnthread_clear_state(thread, XNPEND);
	thread->wchan = NULL;
	list_del(&thread->plink); /* synch->pendq */

	/*
	 * Only a sleeper leaving a PI chain triggers an update.
	 * NOTE: PP objects never bear the CLAIMED bit.
	 */
	if ((synch->status & XNSYNCH_CLAIMED) == 0)
		return;

	owner = synch->owner;

	if (list_empty(&synch->pendq)) {
		/* No more sleepers: clear the PI boost. */
		clear_pi_boost(synch, owner);
		return;
	}

	/*
	 * Reorder the booster queue of the current owner after we
	 * left the wait list, then set its priority to the new
	 * required minimum required to prevent priority inversion.
	 */
	target = list_first_entry(&synch->pendq, struct xnthread, plink);
	synch->wprio = target->wprio;
	list_del(&synch->next);	/* owner->boosters */
	list_add_priff(synch, &owner->boosters, wprio, next);
	adjust_boost(owner, target);
}
EXPORT_SYMBOL_GPL(xnsynch_forget_sleeper);

#if STEELY_DEBUG(MUTEX_RELAXED)

/*
 * Detect when a thread is about to sleep on a synchronization
 * object currently owned by someone running in secondary mode.
 */
void xnsynch_detect_relaxed_owner(struct xnsynch *synch,
				  struct xnthread *sleeper)
{
	if (xnthread_test_state(sleeper, XNWARN) &&
	    !xnthread_test_info(sleeper, XNPIALERT) &&
	    xnthread_test_state(synch->owner, XNRELAX)) {
		xnthread_set_info(sleeper, XNPIALERT);
		xnthread_signal(sleeper, SIGDEBUG,
				  SIGDEBUG_MIGRATE_PRIOINV);
	} else
		xnthread_clear_info(sleeper,  XNPIALERT);
}

/*
 * Detect when a thread is about to relax while holding booster(s)
 * (claimed PI or active PP object), which denotes a potential for
 * priority inversion. In such an event, any sleeper bearing the
 * XNWARN bit will receive a SIGDEBUG notification.
 */
void xnsynch_detect_boosted_relax(struct xnthread *owner)
{
	struct xnthread *sleeper;
	struct xnsynch *synch;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	xnthread_for_each_booster(synch, owner) {
		xnsynch_for_each_sleeper(sleeper, synch) {
			if (xnthread_test_state(sleeper, XNWARN)) {
				xnthread_set_info(sleeper, XNPIALERT);
				xnthread_signal(sleeper, SIGDEBUG,
						  SIGDEBUG_MIGRATE_PRIOINV);
			}
		}
	}

	xnlock_put_irqrestore(&nklock, s);
}

#endif /* STEELY_DEBUG(MUTEX_RELAXED) */
