/* -*- linux-c -*-
 * kernel/locking/pipeline.c
 *
 * Copyright (C) 2016 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 */
#include <linux/linkage.h>
#include <linux/preempt.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/irq_pipeline.h>
#include <linux/kconfig.h>

#define DEBUG_MUTABLE_ON(__c)	\
	WARN_ON_ONCE(IS_ENABLED(CONFIG_DEBUG_SPINLOCK) && (__c))

/*
 * If entering the pipeline, IRQs are hard disabled.
 */

void mutable_spin_lock(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	/*
	 * A mutable spinlock combines real and virtual IRQ disabling
	 * when protecting a critical section over the root stage,
	 * disabling preemption like regular spinlocks. It behaves
	 * like a hard spinlock assuming that hard IRQ disabling is
	 * already in effect when used from the pipeline entry
	 * context, which may preempt any stage.
	 */
	spin_acquire(&rlock->dep_map, 0, 0, _RET_IP_);
	if (in_pipeline()) {
		LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
		return;
	}

	rflags = hard_local_irq_save();
	DEBUG_MUTABLE_ON(!__on_root_stage());
	preempt_disable();
	LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
	lock = container_of(rlock, struct mutable_spinlock, rlock);
	lock->hwflags = rflags;
}
EXPORT_SYMBOL(mutable_spin_lock);

void mutable_spin_unlock(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	spin_release(&rlock->dep_map, 1, _RET_IP_);
	if (in_pipeline()) {
		do_raw_spin_unlock(rlock);
		return;
	}

	lock = container_of(rlock, struct mutable_spinlock, rlock);
	rflags = lock->hwflags;
	do_raw_spin_unlock(rlock);
	hard_local_irq_restore(rflags);
	preempt_enable();
}
EXPORT_SYMBOL(mutable_spin_unlock);

void mutable_spin_lock_irq(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	spin_acquire(&rlock->dep_map, 0, 0, _RET_IP_);
	if (in_pipeline()) {
		LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
		return;
	}

	rflags = hard_local_irq_save();
	DEBUG_MUTABLE_ON(!__on_root_stage());
	__set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	preempt_disable();
	LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
	lock = container_of(rlock, struct mutable_spinlock, rlock);
	lock->hwflags = rflags;
}
EXPORT_SYMBOL(mutable_spin_lock_irq);

void mutable_spin_unlock_irq(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	spin_release(&rlock->dep_map, 1, _RET_IP_);
	if (in_pipeline()) {
		do_raw_spin_unlock(rlock);
		return;
	}

	lock = container_of(rlock, struct mutable_spinlock, rlock);
	rflags = lock->hwflags;
	do_raw_spin_unlock(rlock);
	__clear_bit(IPIPE_STALL_FLAG, &irq_root_status);
	hard_local_irq_restore(rflags);
	preempt_enable();
}
EXPORT_SYMBOL(mutable_spin_unlock_irq);

unsigned long __mutable_spin_lock_irqsave(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags, vflags;

	spin_acquire(&rlock->dep_map, 0, 0, _RET_IP_);
	if (in_pipeline()) {
		LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
		return test_bit(IPIPE_STALL_FLAG, &irq_root_status);
	}

	rflags = hard_local_irq_save();
	DEBUG_MUTABLE_ON(!__on_root_stage());
	vflags = __test_and_set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	preempt_disable();
	LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
	lock = container_of(rlock, struct mutable_spinlock, rlock);
	lock->hwflags = rflags;

	return vflags;
}
EXPORT_SYMBOL(__mutable_spin_lock_irqsave);

void mutable_spin_unlock_irqrestore(struct raw_spinlock *rlock,
				    unsigned long vflags)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	spin_release(&rlock->dep_map, 1, _RET_IP_);
	if (in_pipeline()) {
		do_raw_spin_unlock(rlock);
		return;
	}

	lock = container_of(rlock, struct mutable_spinlock, rlock);
	rflags = lock->hwflags;
	do_raw_spin_unlock(rlock);
	if (!vflags)
		__clear_bit(IPIPE_STALL_FLAG, &irq_root_status);
	hard_local_irq_restore(rflags);
	preempt_enable();
}
EXPORT_SYMBOL(mutable_spin_unlock_irqrestore);

int mutable_spin_trylock(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	if (in_pipeline()) {
		if (do_raw_spin_trylock(rlock)) {
			spin_acquire(&rlock->dep_map, 0, 1, _RET_IP_);
			return 1;
		}
		return 0;
	}
	
	lock = container_of(rlock, struct mutable_spinlock, rlock);
	rflags = hard_local_irq_save();
	DEBUG_MUTABLE_ON(!__on_root_stage());
	preempt_disable();
	
	if (do_raw_spin_trylock(rlock)) {
		lock->hwflags = rflags;
		spin_acquire(&rlock->dep_map, 0, 1, _RET_IP_);
		return 1;
	}

	hard_local_irq_restore(rflags);
	preempt_enable();

	return 0;
}
EXPORT_SYMBOL(mutable_spin_trylock);

int __mutable_spin_trylock_irqsave(struct raw_spinlock *rlock,
				   unsigned long *vflags)
{
	struct mutable_spinlock *lock;
	unsigned long rflags;

	if (in_pipeline()) {
		if (do_raw_spin_trylock(rlock)) {
			spin_acquire(&rlock->dep_map, 0, 1, _RET_IP_);
			*vflags = test_bit(IPIPE_STALL_FLAG, &irq_root_status);
			return 1;
		}
		return 0;
	}
	
	rflags = hard_local_irq_save();
	lock = container_of(rlock, struct mutable_spinlock, rlock);
	DEBUG_MUTABLE_ON(!__on_root_stage());
	*vflags = __test_and_set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	preempt_disable();
	
	if (do_raw_spin_trylock(rlock)) {
		spin_acquire(&rlock->dep_map, 0, 1, _RET_IP_);
		lock->hwflags = rflags;
		return 1;
	}

	if (!*vflags)
		__clear_bit(IPIPE_STALL_FLAG, &irq_root_status);
	
	hard_local_irq_restore(rflags);
	preempt_enable();

	return 0;
}
EXPORT_SYMBOL(__mutable_spin_trylock_irqsave);

int mutable_spin_trylock_irq(struct raw_spinlock *rlock)
{
	struct mutable_spinlock *lock;
	unsigned long rflags, vflags;

	if (in_pipeline()) {
		if (do_raw_spin_trylock(rlock)) {
			spin_acquire(&rlock->dep_map, 0, 1, _RET_IP_);
			return 1;
		}
		return 0;
	}
	
	lock = container_of(rlock, struct mutable_spinlock, rlock);
	rflags = hard_local_irq_save();
	DEBUG_MUTABLE_ON(!__on_root_stage());
	vflags = __test_and_set_bit(IPIPE_STALL_FLAG, &irq_root_status);
	preempt_disable();
	
	if (do_raw_spin_trylock(rlock)) {
		lock->hwflags = rflags;
		spin_acquire(&rlock->dep_map, 0, 1, _RET_IP_);
		return 1;
	}

	if (!vflags)
		__clear_bit(IPIPE_STALL_FLAG, &irq_root_status);

	hard_local_irq_restore(rflags);
	preempt_enable();

	return 0;
}
EXPORT_SYMBOL(mutable_spin_trylock_irq);
