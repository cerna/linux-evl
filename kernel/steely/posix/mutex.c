/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

#include "internal.h"
#include "thread.h"
#include "mutex.h"
#include "cond.h"
#include "clock.h"

static int steely_mutex_init_inner(struct steely_mutex_shadow *shadow,
				   struct steely_mutex *mutex,
				   struct steely_mutex_state *state,
				   const struct steely_mutexattr *attr)
{
	int synch_flags = XNSYNCH_PRIO | XNSYNCH_OWNER;
	struct steely_umm *umm;
	spl_t s;
	int ret;

	ret = xnregistry_enter_anon(mutex, &mutex->resnode.handle);
	if (ret < 0)
		return ret;

	umm = &steely_ppd_get(attr->pshared)->umm;
	shadow->handle = mutex->resnode.handle;
	shadow->magic = STEELY_MUTEX_MAGIC;
	shadow->lockcnt = 0;
	shadow->attr = *attr;
	shadow->state_offset = steely_umm_offset(umm, state);

	mutex->magic = STEELY_MUTEX_MAGIC;

	if (attr->protocol == PTHREAD_PRIO_PROTECT) {
		state->ceiling = attr->ceiling + 1;
		xnsynch_init_protect(&mutex->synchbase, synch_flags,
				     &state->owner, &state->ceiling);
	} else {
		state->ceiling = 0;
		if (attr->protocol == PTHREAD_PRIO_INHERIT)
			synch_flags |= XNSYNCH_PI;
		xnsynch_init(&mutex->synchbase, synch_flags, &state->owner);
	}

	state->flags = (attr->type == PTHREAD_MUTEX_ERRORCHECK
			? STEELY_MUTEX_ERRORCHECK : 0);
	mutex->attr = *attr;
	INIT_LIST_HEAD(&mutex->conds);

	xnlock_get_irqsave(&nklock, s);
	steely_add_resource(&mutex->resnode, mutex, attr->pshared);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/* must be called with nklock locked, interrupts off. */
int __steely_mutex_acquire_unchecked(struct steely_thread *cur,
				     struct steely_mutex *mutex,
				     const struct timespec *ts)
{
	int ret;

	if (ts) {
		if (ts->tv_nsec >= ONE_BILLION)
			return -EINVAL;
		ret = xnsynch_acquire(&mutex->synchbase,
				      ktime_add_ns(timespec_to_ktime(*ts), 1),
				      XN_REALTIME);
	} else
		ret = xnsynch_acquire(&mutex->synchbase,
				      XN_INFINITE, XN_RELATIVE);

	if (ret) {
		if (ret & XNBREAK)
			return -EINTR;
		if (ret & XNTIMEO)
			return -ETIMEDOUT;
		return -EINVAL;
	}

	return 0;
}

int steely_mutex_release(struct steely_thread *curr,
			 struct steely_mutex *mutex)
{	/* nklock held, irqs off */
	struct steely_mutex_state *state;
	struct steely_cond *cond;
	unsigned long flags;
	int need_resched;

	if (!steely_obj_active(mutex, STEELY_MUTEX_MAGIC, struct steely_mutex))
		 return -EINVAL;

	if (IS_ENABLED(CONFIG_STEELY_DEBUG_POSIX_SYNCHRO) &&
	    mutex->resnode.scope !=
	    steely_current_resources(mutex->attr.pshared))
		return -EPERM;

	/*
	 * We are about to release a mutex which is still pending PP
	 * (i.e. we never got scheduled out while holding it). Clear
	 * the lazy handle.
	 */
	if (mutex->resnode.handle == curr->u_window->pp_pending)
		curr->u_window->pp_pending = XN_NO_HANDLE;

	state = container_of(mutex->synchbase.fastlock, struct steely_mutex_state, owner);
	flags = state->flags;
	need_resched = 0;
	if ((flags & STEELY_MUTEX_COND_SIGNAL)) {
		state->flags = flags & ~STEELY_MUTEX_COND_SIGNAL;
		if (!list_empty(&mutex->conds)) {
			list_for_each_entry(cond, &mutex->conds, mutex_link)
				need_resched |=
				steely_cond_deferred_signals(cond);
		}
	}
	need_resched |= xnsynch_release(&mutex->synchbase, curr);

	return need_resched;
}

int __steely_mutex_timedlock_break(struct steely_mutex_shadow __user *u_mx,
				   const void __user *u_ts,
				   int (*fetch_timeout)(struct timespec *ts,
							const void __user *u_ts))
{
	struct steely_thread *curr = steely_current_thread();
	struct timespec ts, *tsp = NULL;
	struct steely_mutex *mutex;
	xnhandle_t handle;
	spl_t s;
	int ret;

	/* We need a valid thread handle for the fast lock. */
	if (curr->handle == XN_NO_HANDLE)
		return -EPERM;

	handle = steely_get_handle_from_user(&u_mx->handle);
redo:
	xnlock_get_irqsave(&nklock, s);

	mutex = xnregistry_lookup(handle, NULL);
	if (!steely_obj_active(mutex, STEELY_MUTEX_MAGIC, struct steely_mutex)) {
		ret = -EINVAL;
		goto out;
	}

	if (IS_ENABLED(CONFIG_STEELY_DEBUG_POSIX_SYNCHRO) &&
	    mutex->resnode.scope !=
	    steely_current_resources(mutex->attr.pshared)) {
		ret = -EPERM;
		goto out;
	}

	xnthread_commit_ceiling(curr);

	if (xnsynch_owner_check(&mutex->synchbase, curr)) {
		if (fetch_timeout) {
			xnlock_put_irqrestore(&nklock, s);
			ret = fetch_timeout(&ts, u_ts);
			if (ret)
				return ret;

			fetch_timeout = NULL;
			tsp = &ts;
			goto redo; /* Revalidate handle. */
		}
		ret = __steely_mutex_acquire_unchecked(curr, mutex, tsp);
		xnlock_put_irqrestore(&nklock, s);
		return ret;
	}

	/* We already own the mutex, something looks wrong. */

	ret = -EBUSY;
	switch(mutex->attr.type) {
	case PTHREAD_MUTEX_NORMAL:
		/* Attempting to relock a normal mutex, deadlock. */
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_POSIX_SYNCHRO))
			printk(STEELY_WARNING
			       "thread %s deadlocks on non-recursive mutex\n",
			       curr->name);
		/* Make the caller hang. */
		__steely_mutex_acquire_unchecked(curr, mutex, NULL);
		break;

	case PTHREAD_MUTEX_ERRORCHECK:
	case PTHREAD_MUTEX_RECURSIVE:
		/*
		 * Recursive mutexes are handled in user-space, so
		 * these cases should never happen.
		 */
		ret = -EINVAL;
		break;
	}
out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

STEELY_SYSCALL(mutex_check_init, current,
	       (struct steely_mutex_shadow __user *u_mx))
{
	struct steely_mutex *mutex;
	xnhandle_t handle;
	int err;
	spl_t s;

	handle = steely_get_handle_from_user(&u_mx->handle);

	xnlock_get_irqsave(&nklock, s);
	mutex = xnregistry_lookup(handle, NULL);
	if (steely_obj_active(mutex, STEELY_MUTEX_MAGIC, typeof(*mutex)))
		/* mutex is already in a queue. */
		err = -EBUSY;
	else
		err = 0;

	xnlock_put_irqrestore(&nklock, s);
	return err;
}

STEELY_SYSCALL(mutex_init, current,
	       (struct steely_mutex_shadow __user *u_mx,
		const struct steely_mutexattr __user *u_attr))
{
	struct steely_mutex_state *state;
	struct steely_mutex_shadow mx;
	struct steely_mutexattr attr;
	struct steely_mutex *mutex;
	int ret;

	if (steely_copy_from_user(&mx, u_mx, sizeof(mx)))
		return -EFAULT;

	if (steely_copy_from_user(&attr, u_attr, sizeof(attr)))
		return -EFAULT;

	mutex = xnmalloc(sizeof(*mutex));
	if (mutex == NULL)
		return -ENOMEM;

	state = steely_umm_alloc(&steely_ppd_get(attr.pshared)->umm,
				 sizeof(*state));
	if (state == NULL) {
		xnfree(mutex);
		return -EAGAIN;
	}

	ret = steely_mutex_init_inner(&mx, mutex, state, &attr);
	if (ret) {
		xnfree(mutex);
		steely_umm_free(&steely_ppd_get(attr.pshared)->umm, state);
		return ret;
	}

	return steely_copy_to_user(u_mx, &mx, sizeof(*u_mx));
}

STEELY_SYSCALL(mutex_destroy, current,
	       (struct steely_mutex_shadow __user *u_mx))
{
	struct steely_mutex_shadow mx;
	struct steely_mutex *mutex;
	spl_t s;
	int ret;

	if (steely_copy_from_user(&mx, u_mx, sizeof(mx)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	mutex = xnregistry_lookup(mx.handle, NULL);
	if (!steely_obj_active(mutex, STEELY_MUTEX_MAGIC, typeof(*mutex))) {
		ret = -EINVAL;
		goto fail;
	}
	if (steely_current_resources(mutex->attr.pshared) !=
	    mutex->resnode.scope) {
		ret = -EPERM;
		goto fail;
	}
	if (xnsynch_fast_owner_check(mutex->synchbase.fastlock,
					XN_NO_HANDLE) != 0 ||
	    !list_empty(&mutex->conds)) {
		ret = -EBUSY;
		goto fail;
	}

	steely_mutex_reclaim(&mutex->resnode, s); /* drops lock */

	steely_mark_deleted(&mx);

	return steely_copy_to_user(u_mx, &mx, sizeof(*u_mx));
fail:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

STEELY_SYSCALL(mutex_trylock, primary,
	       (struct steely_mutex_shadow __user *u_mx))
{
	struct steely_thread *curr = steely_current_thread();
	struct steely_mutex *mutex;
	xnhandle_t handle;
	spl_t s;
	int ret;

	handle = steely_get_handle_from_user(&u_mx->handle);

	xnlock_get_irqsave(&nklock, s);

	mutex = xnregistry_lookup(handle, NULL);
	if (!steely_obj_active(mutex, STEELY_MUTEX_MAGIC, typeof(*mutex))) {
		ret = -EINVAL;
		goto out;
	}

	xnthread_commit_ceiling(curr);

	ret = xnsynch_fast_acquire(mutex->synchbase.fastlock, curr->handle);
	switch(ret) {
	case 0:
		xnthread_get_resource(curr);
		break;

/* This should not happen, as recursive mutexes are handled in
   user-space */
	case -EBUSY:
		ret = -EINVAL;
		break;

	case -EAGAIN:
		ret = -EBUSY;
		break;
	}
out:
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

STEELY_SYSCALL(mutex_lock, primary,
	       (struct steely_mutex_shadow __user *u_mx))
{
	return __steely_mutex_timedlock_break(u_mx, NULL, NULL);
}

static inline int mutex_fetch_timeout(struct timespec *ts,
				      const void __user *u_ts)
{
	return u_ts == NULL ? -EFAULT :
		steely_copy_from_user(ts, u_ts, sizeof(*ts));
}

STEELY_SYSCALL(mutex_timedlock, primary,
	       (struct steely_mutex_shadow __user *u_mx,
		const struct timespec __user *u_ts))
{
	return __steely_mutex_timedlock_break(u_mx, u_ts, mutex_fetch_timeout);
}

STEELY_SYSCALL(mutex_unlock, nonrestartable,
	       (struct steely_mutex_shadow __user *u_mx))
{
	struct steely_mutex *mutex;
	struct steely_thread *curr;
	xnhandle_t handle;
	int ret;
	spl_t s;

	handle = steely_get_handle_from_user(&u_mx->handle);
	curr = steely_current_thread();

	xnlock_get_irqsave(&nklock, s);

	mutex = xnregistry_lookup(handle, NULL);
	ret = steely_mutex_release(curr, mutex);
	if (ret > 0) {
		xnsched_run();
		ret = 0;
	}

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

void steely_mutex_reclaim(struct steely_resnode *node, spl_t s)
{
	struct steely_mutex_state *state;
	struct steely_mutex *mutex;
	int pshared;

	mutex = container_of(node, struct steely_mutex, resnode);
	state = container_of(mutex->synchbase.fastlock, struct steely_mutex_state, owner);
	pshared = mutex->attr.pshared;
	xnregistry_remove(node->handle);
	steely_del_resource(node);
	xnsynch_destroy(&mutex->synchbase);
	steely_mark_deleted(mutex);
	xnlock_put_irqrestore(&nklock, s);

	steely_umm_free(&steely_ppd_get(pshared)->umm, state);
	xnfree(mutex);
}

struct xnsynch *lookup_lazy_pp(xnhandle_t handle)
{				/* nklock held, irqs off */
	struct steely_mutex *mutex;

	/* Only mutexes may be PP-enabled. */
	
	mutex = xnregistry_lookup(handle, NULL);
	if (mutex == NULL ||
	    !steely_obj_active(mutex, STEELY_MUTEX_MAGIC, struct steely_mutex) ||
	    mutex->attr.protocol != PTHREAD_PRIO_PROTECT)
		return NULL;

	return &mutex->synchbase;
}
