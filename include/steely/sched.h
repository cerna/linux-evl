/*
 * Copyright (C) 2008 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_SCHED_H
#define _STEELY_SCHED_H

#include <linux/percpu.h>
#include <linux/list.h>
#include <steely/lock.h>
#include <steely/thread.h>
#include <steely/schedqueue.h>
#include <steely/sched-tp.h>
#include <steely/sched-weak.h>
#include <steely/sched-sporadic.h>
#include <steely/sched-quota.h>
#include <steely/vfile.h>
#include <steely/assert.h>
#include <steely/syscall.h>
#include <asm/steely/machine.h>

/** Shared scheduler status flags **/

/*
 * A rescheduling call is pending.
 */
#define XNRESCHED	0x10000000
/*
 * Currently running in tick handler context.
 */
#define XNINTCK		0x20000000

/** Private scheduler flags **/

/*
 * A proxy tick is being processed, i.e. matching an earlier timing
 * request from the regular kernel.
 */
#define XNHTICK		0x00008000
/*
 * Currently running in IRQ handling context.
 */
#define XNINIRQ		0x00004000
/*
 * Proxy tick is deferred, because we have more urgent real-time
 * duties to carry out first.
 */
#define XNHDEFER	0x00002000
/*
 * Idle state: there is no outstanding timer, or the leading one is
 * the proxy tick. We check this flag to know whether we may allow the
 * regular kernel to enter the idle state.
 */
#define XNIDLE		0x00001000

struct xnsched_rt {
	xnsched_queue_t runnable;	/* Runnable thread queue. */
};

struct xnsched {
	/* Shared status bitmask. */
	unsigned long status;
	/* Private status bitmask. */
	unsigned long lflags;
	/* Current thread. */
	struct steely_thread *curr;
#ifdef CONFIG_SMP
	/* Owner CPU id. */
	int cpu;
	/* Mask of CPUs needing rescheduling. */
	struct cpumask resched;
#endif
	/* Context of built-in real-time class. */
	struct xnsched_rt rt;
#ifdef CONFIG_STEELY_SCHED_WEAK
	/* Context of weak scheduling class. */
	struct xnsched_weak weak;
#endif
#ifdef CONFIG_STEELY_SCHED_TP
	/* Context of TP class. */
	struct xnsched_tp tp;
#endif
#ifdef CONFIG_STEELY_SCHED_SPORADIC
	/* Context of sporadic scheduling class. */
	struct xnsched_sporadic pss;
#endif
#ifdef CONFIG_STEELY_SCHED_QUOTA
	/* Context of runtime quota scheduling. */
	struct xnsched_quota quota;
#endif
	/* Interrupt nesting level. */
	volatile unsigned inesting;
	/* Host timer. */
	struct xntimer htimer;
	/* Round-robin timer. */
	struct xntimer rrbtimer;
	/* Root thread control block. */
	struct steely_thread rootcb;
#ifdef CONFIG_STEELY_WATCHDOG
	/* Watchdog timer object. */
	struct xntimer wdtimer;
	/* Watchdog tick count. */
	int wdcount;
#endif
#ifdef CONFIG_STEELY_STATS
	/* Last account switch date (ticks). */
	ktime_t last_account_switch;
	/* Currently active account */
	xnstat_exectime_t *current_account;
#endif
};

DECLARE_PER_CPU(struct xnsched, nksched);

extern struct cpumask steely_cpu_affinity;

extern struct list_head nkthreadq;

extern int steely_nrthreads;

#ifdef CONFIG_STEELY_VFILE
extern struct xnvfile_rev_tag nkthreadlist_tag;
#endif

union xnsched_policy_param;

struct xnsched_class {
	void (*sched_init)(struct xnsched *sched);
	void (*sched_enqueue)(struct steely_thread *thread);
	void (*sched_dequeue)(struct steely_thread *thread);
	void (*sched_requeue)(struct steely_thread *thread);
	struct steely_thread *(*sched_pick)(struct xnsched *sched);
	void (*sched_tick)(struct xnsched *sched);
	void (*sched_rotate)(struct xnsched *sched,
			     const union xnsched_policy_param *p);
	void (*sched_migrate)(struct steely_thread *thread,
			      struct xnsched *sched);
	/*
	 * Set base scheduling parameters. This routine is indirectly
	 * called upon a change of base scheduling settings through
	 * __xnthread_set_schedparam() -> xnsched_set_policy(),
	 * exclusively.
	 *
	 * The scheduling class implementation should do the necessary
	 * housekeeping to comply with the new settings.
	 * thread->base_class is up to date before the call is made,
	 * and should be considered for the new weighted priority
	 * calculation. On the contrary, thread->sched_class should
	 * NOT be referred to by this handler.
	 *
	 * sched_setparam() is NEVER involved in PI or PP
	 * management. However it must deny a priority update if it
	 * contradicts an ongoing boost for @a thread. This is
	 * typically what the xnsched_set_effective_priority() helper
	 * does for such handler.
	 *
	 * Returns true if the effective priority was updated
	 * (thread->cprio).
	 */
	bool (*sched_setparam)(struct steely_thread *thread,
			       const union xnsched_policy_param *p);
	void (*sched_getparam)(struct steely_thread *thread,
			       union xnsched_policy_param *p);
	void (*sched_trackprio)(struct steely_thread *thread,
				const union xnsched_policy_param *p);
	void (*sched_protectprio)(struct steely_thread *thread, int prio);
	int (*sched_declare)(struct steely_thread *thread,
			     const union xnsched_policy_param *p);
	void (*sched_forget)(struct steely_thread *thread);
	void (*sched_kick)(struct steely_thread *thread);
#ifdef CONFIG_STEELY_VFILE
	int (*sched_init_vfile)(struct xnsched_class *schedclass,
				struct xnvfile_directory *vfroot);
	void (*sched_cleanup_vfile)(struct xnsched_class *schedclass);
#endif
	int nthreads;
	struct xnsched_class *next;
	int weight;
	int policy;
	const char *name;
};

#define XNSCHED_CLASS_WEIGHT(n)		(n * XNSCHED_CLASS_WEIGHT_FACTOR)

/* Placeholder for current thread priority */
#define XNSCHED_RUNPRIO   0x80000000

#define xnsched_for_each_thread(__thread)	\
	list_for_each_entry(__thread, &nkthreadq, glink)

#ifdef CONFIG_SMP
static inline int xnsched_cpu(struct xnsched *sched)
{
	return sched->cpu;
}
#else /* !CONFIG_SMP */
static inline int xnsched_cpu(struct xnsched *sched)
{
	return 0;
}
#endif /* CONFIG_SMP */

static inline struct xnsched *xnsched_struct(int cpu)
{
	return &per_cpu(nksched, cpu);
}

static inline struct xnsched *xnsched_current(void)
{
	/* IRQs off */
	return raw_cpu_ptr(&nksched);
}

static inline struct steely_thread *xnsched_current_thread(void)
{
	return xnsched_current()->curr;
}

/* Test resched flag of given sched. */
static inline int xnsched_resched_p(struct xnsched *sched)
{
	return sched->status & XNRESCHED;
}

/* Set self resched flag for the current scheduler. */
static inline void xnsched_set_self_resched(struct xnsched *sched)
{
	sched->status |= XNRESCHED;
}

/* Set resched flag for the given scheduler. */
#ifdef CONFIG_SMP

static inline void xnsched_set_resched(struct xnsched *sched)
{
	struct xnsched *current_sched = xnsched_current();

	if (current_sched == sched)
		current_sched->status |= XNRESCHED;
	else if (!xnsched_resched_p(sched)) {
		cpumask_set_cpu(xnsched_cpu(sched), &current_sched->resched);
		sched->status |= XNRESCHED;
		current_sched->status |= XNRESCHED;
	}
}

#define xnsched_realtime_cpus    steely_pipeline.supported_cpus

static inline int xnsched_supported_cpu(int cpu)
{
	return cpumask_test_cpu(cpu, &xnsched_realtime_cpus);
}

#else /* !CONFIG_SMP */

static inline void xnsched_set_resched(struct xnsched *sched)
{
	xnsched_set_self_resched(sched);
}

#define xnsched_realtime_cpus CPU_MASK_ALL

static inline int xnsched_supported_cpu(int cpu)
{
	return 1;
}

#endif /* !CONFIG_SMP */

#define for_each_realtime_cpu(cpu)		\
	for_each_online_cpu(cpu)		\
		if (xnsched_supported_cpu(cpu))	\

int ___xnsched_run(struct xnsched *sched);

irqreturn_t __xnsched_run_handler(int irq, void *dev_id);

static inline int __xnsched_run(struct xnsched *sched)
{
	/*
	 * NOTE: Since ___xnsched_run() won't run immediately if an
	 * escalation to primary domain is needed, we won't use
	 * critical scheduler information before we actually run in
	 * primary mode; therefore we can first test the scheduler
	 * status then escalate.
	 *
	 * Running in the primary domain means that no Linux-triggered
	 * CPU migration may occur from that point either. Finally,
	 * since migration is always a self-directed operation for
	 * Steely threads, we can safely read the scheduler state bits
	 * without holding the nklock.
	 *
	 * Said differently, if we race here because of a CPU
	 * migration, it must have been Linux-triggered because we run
	 * in secondary mode; in which case we will escalate to the
	 * primary domain, then unwind the current call frame without
	 * running the rescheduling procedure in
	 * ___xnsched_run(). Therefore, the scheduler slot
	 * (i.e. "sched") will be either valid, or unused.
	 */
	if (((sched->status|sched->lflags) & (XNINIRQ|XNRESCHED)) != XNRESCHED)
		return 0;

	return ___xnsched_run(sched);
}

static inline int xnsched_run(void)
{
	struct xnsched *sched = xnsched_current();
	/*
	 * No rescheduling is possible, either if:
	 *
	 * - the current thread holds the scheduler lock
	 * - an ISR context is active
	 * - we are caught in the middle of an unlocked context switch.
	 */
	smp_rmb();
	if (unlikely(sched->curr->lock_count > 0))
		return 0;

	return __xnsched_run(sched);
}

void xnsched_lock(void);

void xnsched_unlock(void);

static inline int xnsched_interrupt_p(void)
{
	return xnsched_current()->lflags & XNINIRQ;
}

static inline int xnsched_root_p(void)
{
	return xnthread_test_state(xnsched_current_thread(), XNROOT);
}

static inline int xnsched_unblockable_p(void)
{
	return xnsched_interrupt_p() || xnsched_root_p();
}

static inline int xnsched_primary_p(void)
{
	return !xnsched_unblockable_p();
}

#ifdef CONFIG_STEELY_WATCHDOG
static inline void xnsched_reset_watchdog(struct xnsched *sched)
{
	sched->wdcount = 0;
}
#else /* !CONFIG_STEELY_WATCHDOG */
static inline void xnsched_reset_watchdog(struct xnsched *sched)
{
}
#endif /* CONFIG_STEELY_WATCHDOG */

bool xnsched_set_effective_priority(struct steely_thread *thread,
				    int prio);

#include <steely/sched-idle.h>
#include <steely/sched-rt.h>

int xnsched_init_proc(void);

void xnsched_cleanup_proc(void);

void xnsched_register_classes(void);

void xnsched_init(struct xnsched *sched, int cpu);

void xnsched_destroy(struct xnsched *sched);

struct steely_thread *xnsched_pick_next(struct xnsched *sched);

void xnsched_putback(struct steely_thread *thread);

int xnsched_set_policy(struct steely_thread *thread,
		       struct xnsched_class *sched_class,
		       const union xnsched_policy_param *p);

void xnsched_track_policy(struct steely_thread *thread,
			  struct steely_thread *target);

void xnsched_protect_priority(struct steely_thread *thread,
			      int prio);

void xnsched_migrate(struct steely_thread *thread,
		     struct xnsched *sched);

void xnsched_migrate_passive(struct steely_thread *thread,
			     struct xnsched *sched);

static inline void xnsched_rotate(struct xnsched *sched,
				  struct xnsched_class *sched_class,
				  const union xnsched_policy_param *sched_param)
{
	sched_class->sched_rotate(sched, sched_param);
}

static inline int xnsched_init_thread(struct steely_thread *thread)
{
	int ret = 0;

	xnsched_idle_init_thread(thread);
	xnsched_rt_init_thread(thread);

#ifdef CONFIG_STEELY_SCHED_TP
	ret = xnsched_tp_init_thread(thread);
	if (ret)
		return ret;
#endif /* CONFIG_STEELY_SCHED_TP */
#ifdef CONFIG_STEELY_SCHED_SPORADIC
	ret = xnsched_sporadic_init_thread(thread);
	if (ret)
		return ret;
#endif /* CONFIG_STEELY_SCHED_SPORADIC */
#ifdef CONFIG_STEELY_SCHED_QUOTA
	ret = xnsched_quota_init_thread(thread);
	if (ret)
		return ret;
#endif /* CONFIG_STEELY_SCHED_QUOTA */

	return ret;
}

static inline int xnsched_root_priority(struct xnsched *sched)
{
	return sched->rootcb.cprio;
}

static inline struct xnsched_class *xnsched_root_class(struct xnsched *sched)
{
	return sched->rootcb.sched_class;
}

static inline void xnsched_tick(struct xnsched *sched)
{
	struct steely_thread *curr = sched->curr;
	struct xnsched_class *sched_class = curr->sched_class;
	/*
	 * A thread that undergoes round-robin scheduling only
	 * consumes its time slice when it runs within its own
	 * scheduling class, which excludes temporary PI boosts, and
	 * does not hold the scheduler lock.
	 */
	if (sched_class == curr->base_class &&
	    sched_class->sched_tick &&
	    xnthread_test_state(curr, XNTHREAD_BLOCK_BITS|XNRRB) == XNRRB &&
		curr->lock_count == 0)
		sched_class->sched_tick(sched);
}

static inline int xnsched_declare(struct xnsched_class *sched_class,
				  struct steely_thread *thread,
				  const union xnsched_policy_param *p)
{
	int ret;

	if (sched_class->sched_declare) {
		ret = sched_class->sched_declare(thread, p);
		if (ret)
			return ret;
	}
	if (sched_class != thread->base_class)
		sched_class->nthreads++;

	return 0;
}

static inline int xnsched_calc_wprio(struct xnsched_class *sched_class,
				     int prio)
{
	return prio + sched_class->weight;
}

#ifdef CONFIG_STEELY_SCHED_CLASSES

static inline void xnsched_enqueue(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class != &xnsched_class_idle)
		sched_class->sched_enqueue(thread);
}

static inline void xnsched_dequeue(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class != &xnsched_class_idle)
		sched_class->sched_dequeue(thread);
}

static inline void xnsched_requeue(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class != &xnsched_class_idle)
		sched_class->sched_requeue(thread);
}

static inline
bool xnsched_setparam(struct steely_thread *thread,
		      const union xnsched_policy_param *p)
{
	return thread->base_class->sched_setparam(thread, p);
}

static inline void xnsched_getparam(struct steely_thread *thread,
				    union xnsched_policy_param *p)
{
	thread->sched_class->sched_getparam(thread, p);
}

static inline void xnsched_trackprio(struct steely_thread *thread,
				     const union xnsched_policy_param *p)
{
	thread->sched_class->sched_trackprio(thread, p);
	thread->wprio = xnsched_calc_wprio(thread->sched_class, thread->cprio);
}

static inline void xnsched_protectprio(struct steely_thread *thread, int prio)
{
	thread->sched_class->sched_protectprio(thread, prio);
	thread->wprio = xnsched_calc_wprio(thread->sched_class, thread->cprio);
}

static inline void xnsched_forget(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->base_class;

	--sched_class->nthreads;

	if (sched_class->sched_forget)
		sched_class->sched_forget(thread);
}

static inline void xnsched_kick(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->base_class;

	xnthread_set_info(thread, XNKICKED);

	if (sched_class->sched_kick)
		sched_class->sched_kick(thread);

	xnsched_set_resched(thread->sched);
}

#else /* !CONFIG_STEELY_SCHED_CLASSES */

/*
 * If only the RT and IDLE scheduling classes are compiled in, we can
 * fully inline common helpers for dealing with those.
 */

static inline void xnsched_enqueue(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class != &xnsched_class_idle)
		__xnsched_rt_enqueue(thread);
}

static inline void xnsched_dequeue(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class != &xnsched_class_idle)
		__xnsched_rt_dequeue(thread);
}

static inline void xnsched_requeue(struct steely_thread *thread)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class != &xnsched_class_idle)
		__xnsched_rt_requeue(thread);
}

static inline bool xnsched_setparam(struct steely_thread *thread,
				    const union xnsched_policy_param *p)
{
	struct xnsched_class *sched_class = thread->base_class;

	if (sched_class == &xnsched_class_idle)
		return __xnsched_idle_setparam(thread, p);

	return __xnsched_rt_setparam(thread, p);
}

static inline void xnsched_getparam(struct steely_thread *thread,
				    union xnsched_policy_param *p)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class == &xnsched_class_idle)
		__xnsched_idle_getparam(thread, p);
	else
		__xnsched_rt_getparam(thread, p);
}

static inline void xnsched_trackprio(struct steely_thread *thread,
				     const union xnsched_policy_param *p)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class == &xnsched_class_idle)
		__xnsched_idle_trackprio(thread, p);
	else
		__xnsched_rt_trackprio(thread, p);

	thread->wprio = xnsched_calc_wprio(sched_class, thread->cprio);
}

static inline void xnsched_protectprio(struct steely_thread *thread, int prio)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (sched_class == &xnsched_class_idle)
		__xnsched_idle_protectprio(thread, prio);
	else
		__xnsched_rt_protectprio(thread, prio);

	thread->wprio = xnsched_calc_wprio(sched_class, thread->cprio);
}

static inline void xnsched_forget(struct steely_thread *thread)
{
	--thread->base_class->nthreads;
	__xnsched_rt_forget(thread);
}

static inline void xnsched_kick(struct steely_thread *thread)
{
	xnthread_set_info(thread, XNKICKED);
	xnsched_set_resched(thread->sched);
}

#endif /* !CONFIG_STEELY_SCHED_CLASSES */

struct steely_resources;
struct steely_process;

struct steely_sched_group {
#ifdef CONFIG_STEELY_SCHED_QUOTA
	struct xnsched_quota_group quota;
#endif
	struct steely_resources *scope;
	int pshared;
	struct list_head next;
};

int __steely_sched_weightprio(int policy,
			      const struct sched_param_ex *param_ex);

int __steely_sched_setconfig_np(int cpu, int policy,
				void __user *u_config,
				size_t len,
				union sched_config *(*fetch_config)
				(int policy, const void __user *u_config,
				 size_t *len),
				int (*ack_config)(int policy,
						  const union sched_config *config,
						  void __user *u_config));

ssize_t __steely_sched_getconfig_np(int cpu, int policy,
				    void __user *u_config,
				    size_t len,
				    union sched_config *(*fetch_config)
				    (int policy, const void __user *u_config,
				     size_t *len),
				    ssize_t (*put_config)(int policy,
							  void __user *u_config, size_t u_len,
							  const union sched_config *config,
							  size_t len));
int steely_sched_setscheduler_ex(pid_t pid,
				 int policy,
				 const struct sched_param_ex *param_ex,
				 __u32 __user *u_winoff,
				 int __user *u_promoted);

int steely_sched_getscheduler_ex(pid_t pid,
				 int *policy_r,
				 struct sched_param_ex *param_ex);

struct xnsched_class *
steely_sched_policy_param(union xnsched_policy_param *param,
			  int u_policy, const struct sched_param_ex *param_ex,
			  ktime_t *tslice_r);

STEELY_SYSCALL_DECL(sched_yield, (void));

STEELY_SYSCALL_DECL(sched_weightprio,
		    (int policy, const struct sched_param_ex __user *u_param));

STEELY_SYSCALL_DECL(sched_minprio, (int policy));

STEELY_SYSCALL_DECL(sched_maxprio, (int policy));

STEELY_SYSCALL_DECL(sched_setconfig_np,
		    (int cpu,
		     int policy,
		     union sched_config __user *u_config,
		     size_t len));

STEELY_SYSCALL_DECL(sched_getconfig_np,
		    (int cpu, int policy,
		     union sched_config __user *u_config,
		     size_t len));

STEELY_SYSCALL_DECL(sched_setscheduler_ex,
		    (pid_t pid,
		     int policy,
		     const struct sched_param_ex __user *u_param,
		     __u32 __user *u_winoff,
		     int __user *u_promoted));

STEELY_SYSCALL_DECL(sched_getscheduler_ex,
		    (pid_t pid,
		     int __user *u_policy,
		     struct sched_param_ex __user *u_param));

void steely_sched_reclaim(struct steely_process *process);

#endif /* !_STEELY_SCHED_H */
