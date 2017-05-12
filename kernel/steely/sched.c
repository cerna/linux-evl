/*
 * Copyright (C) 2001-2013 Philippe Gerum <rpm@xenomai.org>.
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
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <asm/div64.h>
#include <steely/sched.h>
#include <steely/thread.h>
#include <steely/timer.h>
#include <steely/heap.h>
#include <steely/clock.h>
#include <uapi/steely/signal.h>
#include <trace/events/steely.h>

DEFINE_PER_CPU(struct xnsched, nksched);
EXPORT_PER_CPU_SYMBOL_GPL(nksched);

struct cpumask steely_cpu_affinity = CPU_MASK_ALL;
EXPORT_SYMBOL_GPL(steely_cpu_affinity);

LIST_HEAD(nkthreadq);

int steely_nrthreads;

#ifdef CONFIG_STEELY_VFILE
struct xnvfile_rev_tag nkthreadlist_tag;
#endif

static struct xnsched_class *xnsched_class_highest;

#define for_each_xnsched_class(p) \
   for (p = xnsched_class_highest; p; p = p->next)

static void xnsched_register_class(struct xnsched_class *sched_class)
{
	sched_class->next = xnsched_class_highest;
	xnsched_class_highest = sched_class;

	/*
	 * Classes shall be registered by increasing priority order,
	 * idle first and up.
	 */
	STEELY_BUG_ON(STEELY, sched_class->next &&
		   sched_class->next->weight > sched_class->weight);

	printk(STEELY_INFO "scheduling class %s registered.\n", sched_class->name);
}

void xnsched_register_classes(void)
{
	xnsched_register_class(&xnsched_class_idle);
#ifdef CONFIG_STEELY_SCHED_WEAK
	xnsched_register_class(&xnsched_class_weak);
#endif
#ifdef CONFIG_STEELY_SCHED_TP
	xnsched_register_class(&xnsched_class_tp);
#endif
#ifdef CONFIG_STEELY_SCHED_SPORADIC
	xnsched_register_class(&xnsched_class_sporadic);
#endif
#ifdef CONFIG_STEELY_SCHED_QUOTA
	xnsched_register_class(&xnsched_class_quota);
#endif
	xnsched_register_class(&xnsched_class_rt);
}

#ifdef CONFIG_STEELY_WATCHDOG

static unsigned long wd_timeout_arg = CONFIG_STEELY_WATCHDOG_TIMEOUT;
module_param_named(watchdog_timeout, wd_timeout_arg, ulong, 0644);

static void watchdog_handler(struct xntimer *timer)
{
	struct xnsched *sched = xnsched_current();
	struct steely_thread *curr = sched->curr;

	if (likely(xnthread_test_state(curr, XNROOT))) {
		xnsched_reset_watchdog(sched);
		return;
	}

	if (likely(++sched->wdcount < wd_timeout_arg))
		return;

	trace_steely_watchdog_signal(curr);

	if (xnthread_test_state(curr, XNUSER)) {
		printk(STEELY_WARNING "watchdog triggered on CPU #%d -- runaway thread "
		       "'%s' signaled\n", xnsched_cpu(sched), curr->name);
		xnthread_call_mayday(curr, SIGDEBUG_WATCHDOG);
	} else {
		printk(STEELY_WARNING "watchdog triggered on CPU #%d -- runaway thread "
		       "'%s' canceled\n", xnsched_cpu(sched), curr->name);
		/*
		 * On behalf on an IRQ handler, xnthread_cancel()
		 * would go half way cancelling the preempted
		 * thread. Therefore we manually raise XNKICKED to
		 * cause the next call to xnthread_suspend() to return
		 * early in XNBREAK condition, and XNCANCELD so that
		 * @thread exits next time it invokes
		 * xnthread_test_cancel().
		 */
		xnthread_set_info(curr, XNKICKED|XNCANCELD);
	}

	xnsched_reset_watchdog(sched);
}

#endif /* CONFIG_STEELY_WATCHDOG */

static void roundrobin_handler(struct xntimer *timer)
{
	struct xnsched *sched = container_of(timer, struct xnsched, rrbtimer);
	xnsched_tick(sched);
}

void xnsched_init(struct xnsched *sched, int cpu)
{
	char rrbtimer_name[XNOBJECT_NAME_LEN];
	char htimer_name[XNOBJECT_NAME_LEN];
	char root_name[XNOBJECT_NAME_LEN];
	union xnsched_policy_param param;
	struct steely_thread_init_attr attr;
	struct xnsched_class *p;

#ifdef CONFIG_SMP
	sched->cpu = cpu;
	ksformat(htimer_name, sizeof(htimer_name), "[host-timer/%u]", cpu);
	ksformat(rrbtimer_name, sizeof(rrbtimer_name), "[rrb-timer/%u]", cpu);
	ksformat(root_name, sizeof(root_name), "ROOT/%u", cpu);
	cpumask_clear(&sched->resched);
#else
	strcpy(htimer_name, "[host-timer]");
	strcpy(rrbtimer_name, "[rrb-timer]");
	strcpy(root_name, "ROOT");
#endif
	for_each_xnsched_class(p) {
		if (p->sched_init)
			p->sched_init(sched);
	}

	sched->status = 0;
	sched->lflags = XNIDLE;
	sched->inesting = 0;
	sched->curr = &sched->rootcb;

	attr.flags = XNROOT;
	attr.name = root_name;
	attr.personality = &steely_personality;
	attr.affinity = *cpumask_of(cpu);
	param.idle.prio = XNSCHED_IDLE_PRIO;

	__xnthread_init(&sched->rootcb, &attr,
			sched, &xnsched_class_idle, &param);

	/*
	 * No direct handler here since proxy timer events are handled
	 * specifically by the generic timer code.
	 */
	xntimer_init(&sched->htimer, &nkclock, NULL,
		     sched, XNTIMER_IGRAVITY);
	xntimer_set_priority(&sched->htimer, XNTIMER_LOPRIO);
	xntimer_set_name(&sched->htimer, htimer_name);
	xntimer_init(&sched->rrbtimer, &nkclock, roundrobin_handler,
		     sched, XNTIMER_IGRAVITY);
	xntimer_set_name(&sched->rrbtimer, rrbtimer_name);
	xntimer_set_priority(&sched->rrbtimer, XNTIMER_LOPRIO);

	xnstat_exectime_set_current(sched, &sched->rootcb.stat.account);

	xnthread_init_root_tcb(&sched->rootcb);
	list_add_tail(&sched->rootcb.glink, &nkthreadq);
	steely_nrthreads++;

#ifdef CONFIG_STEELY_WATCHDOG
	xntimer_init(&sched->wdtimer, &nkclock, watchdog_handler,
		     sched, XNTIMER_NOBLCK|XNTIMER_IGRAVITY);
	xntimer_set_name(&sched->wdtimer, "[watchdog]");
	xntimer_set_priority(&sched->wdtimer, XNTIMER_LOPRIO);
#endif /* CONFIG_STEELY_WATCHDOG */
}

void xnsched_destroy(struct xnsched *sched)
{
	xntimer_destroy(&sched->htimer);
	xntimer_destroy(&sched->rrbtimer);
	xntimer_destroy(&sched->rootcb.ptimer);
	xntimer_destroy(&sched->rootcb.rtimer);
#ifdef CONFIG_STEELY_WATCHDOG
	xntimer_destroy(&sched->wdtimer);
#endif /* CONFIG_STEELY_WATCHDOG */
}

static inline void set_thread_running(struct xnsched *sched,
				      struct steely_thread *thread)
{
	xnthread_clear_state(thread, XNREADY);
	if (xnthread_test_state(thread, XNRRB))
		xntimer_start(&sched->rrbtimer,
			      thread->rrperiod, XN_INFINITE, XN_RELATIVE);
	else
		xntimer_stop(&sched->rrbtimer);
}

/* Must be called with nklock locked, interrupts off. */
struct steely_thread *xnsched_pick_next(struct xnsched *sched)
{
	struct xnsched_class *p __maybe_unused;
	struct steely_thread *curr = sched->curr;
	struct steely_thread *thread;

	if (!xnthread_test_state(curr, XNTHREAD_BLOCK_BITS | XNZOMBIE)) {
		/*
		 * Do not preempt the current thread if it holds the
		 * scheduler lock.
		 */
		if (curr->lock_count > 0) {
			xnsched_set_self_resched(sched);
			return curr;
		}
		/*
		 * Push the current thread back to the run queue of
		 * the scheduling class it belongs to, if not yet
		 * linked to it (XNREADY tells us if it is).
		 */
		if (!xnthread_test_state(curr, XNREADY)) {
			xnsched_requeue(curr);
			xnthread_set_state(curr, XNREADY);
		}
	}

	/*
	 * Find the runnable thread having the highest priority among
	 * all scheduling classes, scanned by decreasing priority.
	 */
#ifdef CONFIG_STEELY_SCHED_CLASSES
	for_each_xnsched_class(p) {
		thread = p->sched_pick(sched);
		if (thread) {
			set_thread_running(sched, thread);
			return thread;
		}
	}

	return NULL; /* Never executed because of the idle class. */
#else /* !CONFIG_STEELY_SCHED_CLASSES */
	thread = xnsched_rt_pick(sched);
	if (unlikely(thread == NULL))
		thread = &sched->rootcb;

	set_thread_running(sched, thread);

	return thread;
#endif /* CONFIG_STEELY_SCHED_CLASSES */
}

void xnsched_lock(void)
{
	struct xnsched *sched = xnsched_current();
	struct steely_thread *curr = sched->curr;

	/*
	 * CAUTION: The fast steely_current_thread() accessor carries the
	 * relevant lock nesting count only if current runs in primary
	 * mode. Otherwise, if the caller is unknown or relaxed
	 * Steely-wise, then we fall back to the root thread on the
	 * current scheduler, which must be done with IRQs off.
	 * Either way, we don't need to grab the super lock.
	 */
	if (unlikely(curr == NULL || xnthread_test_state(curr, XNRELAX))) {
		/*
		 * In IRQ: scheduler already locked, and we may have
		 * interrupted xnthread_relax() where the BUG_ON condition is
		 * temporarily false.
		 */
		if (sched->lflags & XNINIRQ)
			return;

		irqoff_only();
		curr = &sched->rootcb;
		STEELY_BUG_ON(STEELY, xnsched_current()->curr != curr);
	}

	curr->lock_count++;
}
EXPORT_SYMBOL_GPL(xnsched_lock);

void xnsched_unlock(void)
{
	struct xnsched *sched = xnsched_current();
	struct steely_thread *curr = sched->curr;

	if (unlikely(curr == NULL || xnthread_test_state(curr, XNRELAX))) {
		/*
		 * In IRQ
		 */
		if (sched->lflags & XNINIRQ)
			return;

		irqoff_only();
		curr = &xnsched_current()->rootcb;
	}

	if (!STEELY_ASSERT(STEELY, curr->lock_count > 0))
		return;
	
	if (--curr->lock_count == 0) {
		xnthread_clear_localinfo(curr, XNLBALERT);
		xnsched_run();
	}
}
EXPORT_SYMBOL_GPL(xnsched_unlock);

/* nklock locked, interrupts off. */
void xnsched_putback(struct steely_thread *thread)
{
	if (xnthread_test_state(thread, XNREADY))
		xnsched_dequeue(thread);
	else
		xnthread_set_state(thread, XNREADY);

	xnsched_enqueue(thread);
	xnsched_set_resched(thread->sched);
}

/* nklock locked, interrupts off. */
int xnsched_set_policy(struct steely_thread *thread,
		       struct xnsched_class *sched_class,
		       const union xnsched_policy_param *p)
{
	struct xnsched_class *orig_effective_class __maybe_unused;
	bool effective;
	int ret;

	/*
	 * Declaring a thread to a new scheduling class may fail, so
	 * we do that early, while the thread is still a member of the
	 * previous class. However, this also means that the
	 * declaration callback shall not do anything that might
	 * affect the previous class (such as touching thread->rlink
	 * for instance).
	 */
	if (sched_class != thread->base_class) {
		ret = xnsched_declare(sched_class, thread, p);
		if (ret)
			return ret;
	}

	/*
	 * As a special case, we may be called from __xnthread_init()
	 * with no previous scheduling class at all.
	 */
	if (likely(thread->base_class != NULL)) {
		if (xnthread_test_state(thread, XNREADY))
			xnsched_dequeue(thread);

		if (sched_class != thread->base_class)
			xnsched_forget(thread);
	}

	/*
	 * Set the base and effective scheduling parameters. However,
	 * xnsched_setparam() will deny lowering the effective
	 * priority if a boost is undergoing, only recording the
	 * change into the base priority field in such situation.
	 */
	thread->base_class = sched_class;
	/*
	 * Referring to the effective class from a setparam() handler
	 * is wrong: make sure to break if so.
	 */
	if (STEELY_DEBUG(STEELY)) {
		orig_effective_class = thread->sched_class;
		thread->sched_class = NULL;
	}

	/*
	 * This is the ONLY place where calling xnsched_setparam() is
	 * legit, sane and safe.
	 */
	effective = xnsched_setparam(thread, p);
	if (effective) {
		thread->sched_class = sched_class;
		thread->wprio = xnsched_calc_wprio(sched_class, thread->cprio);
	} else if (STEELY_DEBUG(STEELY))
		thread->sched_class = orig_effective_class;

	if (xnthread_test_state(thread, XNREADY))
		xnsched_enqueue(thread);

	if (!xnthread_test_state(thread, XNDORMANT))
		xnsched_set_resched(thread->sched);

	return 0;
}
EXPORT_SYMBOL_GPL(xnsched_set_policy);

/* nklock locked, interrupts off. */
bool xnsched_set_effective_priority(struct steely_thread *thread, int prio)
{
	int wprio = xnsched_calc_wprio(thread->base_class, prio);

	thread->bprio = prio;
	if (wprio == thread->wprio)
		return true;

	/*
	 * We may not lower the effective/current priority of a
	 * boosted thread when changing the base scheduling
	 * parameters. Only xnsched_track_policy() and
	 * xnsched_protect_priority() may do so when dealing with PI
	 * and PP synchs resp.
	 */
	if (wprio < thread->wprio && xnthread_test_state(thread, XNBOOST))
		return false;

	thread->cprio = prio;

	return true;
}

/* nklock locked, interrupts off. */
void xnsched_track_policy(struct steely_thread *thread,
			  struct steely_thread *target)
{
	union xnsched_policy_param param;

	/*
	 * Inherit (or reset) the effective scheduling class and
	 * priority of a thread. Unlike xnsched_set_policy(), this
	 * routine is allowed to lower the weighted priority with no
	 * restriction, even if a boost is undergoing.
	 */
	if (xnthread_test_state(thread, XNREADY))
		xnsched_dequeue(thread);
	/*
	 * Self-targeting means to reset the scheduling policy and
	 * parameters to the base settings. Otherwise, make thread
	 * inherit the scheduling parameters from target.
	 */
	if (target == thread) {
		thread->sched_class = thread->base_class;
		xnsched_trackprio(thread, NULL);
		/*
		 * Per SuSv2, resetting the base scheduling parameters
		 * should not move the thread to the tail of its
		 * priority group.
		 */
		if (xnthread_test_state(thread, XNREADY))
			xnsched_requeue(thread);

	} else {
		xnsched_getparam(target, &param);
		thread->sched_class = target->sched_class;
		xnsched_trackprio(thread, &param);
		if (xnthread_test_state(thread, XNREADY))
			xnsched_enqueue(thread);
	}

	xnsched_set_resched(thread->sched);
}

/* nklock locked, interrupts off. */
void xnsched_protect_priority(struct steely_thread *thread, int prio)
{
	/*
	 * Apply a PP boost by changing the effective priority of a
	 * thread, forcing it to the RT class. Like
	 * xnsched_track_policy(), this routine is allowed to lower
	 * the weighted priority with no restriction, even if a boost
	 * is undergoing.
	 *
	 * This routine only deals with active boosts, resetting the
	 * base priority when leaving a PP boost is obtained by a call
	 * to xnsched_track_policy().
	 */
	if (xnthread_test_state(thread, XNREADY))
		xnsched_dequeue(thread);

	thread->sched_class = &xnsched_class_rt;
	xnsched_protectprio(thread, prio);

	if (xnthread_test_state(thread, XNREADY))
		xnsched_enqueue(thread);

	xnsched_set_resched(thread->sched);
}

static void migrate_thread(struct steely_thread *thread, struct xnsched *sched)
{
	struct xnsched_class *sched_class = thread->sched_class;

	if (xnthread_test_state(thread, XNREADY)) {
		xnsched_dequeue(thread);
		xnthread_clear_state(thread, XNREADY);
	}

	if (sched_class->sched_migrate)
		sched_class->sched_migrate(thread, sched);
	/*
	 * WARNING: the scheduling class may have just changed as a
	 * result of calling the per-class migration hook.
	 */
	thread->sched = sched;
}

/*
 * nklock locked, interrupts off. thread must be runnable.
 */
void xnsched_migrate(struct steely_thread *thread, struct xnsched *sched)
{
	xnsched_set_resched(thread->sched);
	migrate_thread(thread, sched);
	/* Move thread to the remote run queue. */
	xnsched_putback(thread);
}

/*
 * nklock locked, interrupts off. Thread may be blocked.
 */
void xnsched_migrate_passive(struct steely_thread *thread, struct xnsched *sched)
{
	struct xnsched *last_sched = thread->sched;

	migrate_thread(thread, sched);

	if (!xnthread_test_state(thread, XNTHREAD_BLOCK_BITS)) {
		xnsched_requeue(thread);
		xnthread_set_state(thread, XNREADY);
		xnsched_set_resched(last_sched);
	}
}

#ifdef CONFIG_STEELY_SCALABLE_SCHED

void xnsched_initq(struct xnsched_mlq *q)
{
	int prio;

	q->elems = 0;
	bitmap_zero(q->prio_map, XNSCHED_MLQ_LEVELS);

	for (prio = 0; prio < XNSCHED_MLQ_LEVELS; prio++)
		INIT_LIST_HEAD(q->heads + prio);
}

static inline int get_qindex(struct xnsched_mlq *q, int prio)
{
	STEELY_BUG_ON(STEELY, prio < 0 || prio >= XNSCHED_MLQ_LEVELS);
	/*
	 * BIG FAT WARNING: We need to rescale the priority level to a
	 * 0-based range. We use find_first_bit() to scan the bitmap
	 * which is a bit scan forward operation. Therefore, the lower
	 * the index value, the higher the priority (since least
	 * significant bits will be found first when scanning the
	 * bitmap).
	 */
	return XNSCHED_MLQ_LEVELS - prio - 1;
}

static struct list_head *add_q(struct xnsched_mlq *q, int prio)
{
	struct list_head *head;
	int idx;

	idx = get_qindex(q, prio);
	head = q->heads + idx;
	q->elems++;

	/* New item is not linked yet. */
	if (list_empty(head))
		__set_bit(idx, q->prio_map);

	return head;
}

void xnsched_addq(struct xnsched_mlq *q, struct steely_thread *thread)
{
	struct list_head *head = add_q(q, thread->cprio);
	list_add(&thread->rlink, head);
}

void xnsched_addq_tail(struct xnsched_mlq *q, struct steely_thread *thread)
{
	struct list_head *head = add_q(q, thread->cprio);
	list_add_tail(&thread->rlink, head);
}

static void del_q(struct xnsched_mlq *q,
		  struct list_head *entry, int idx)
{
	struct list_head *head = q->heads + idx;

	list_del(entry);
	q->elems--;

	if (list_empty(head))
		__clear_bit(idx, q->prio_map);
}

void xnsched_delq(struct xnsched_mlq *q, struct steely_thread *thread)
{
	del_q(q, &thread->rlink, get_qindex(q, thread->cprio));
}

struct steely_thread *xnsched_getq(struct xnsched_mlq *q)
{
	struct steely_thread *thread;
	struct list_head *head;
	int idx;

	if (q->elems == 0)
		return NULL;

	idx = xnsched_weightq(q);
	head = q->heads + idx;
	STEELY_BUG_ON(STEELY, list_empty(head));
	thread = list_first_entry(head, struct steely_thread, rlink);
	del_q(q, &thread->rlink, idx);

	return thread;
}

struct steely_thread *xnsched_findq(struct xnsched_mlq *q, int prio)
{
	struct list_head *head;
	int idx;

	idx = get_qindex(q, prio);
	head = q->heads + idx;
	if (list_empty(head))
		return NULL;

	return list_first_entry(head, struct steely_thread, rlink);
}

#ifdef CONFIG_STEELY_SCHED_CLASSES

struct steely_thread *xnsched_rt_pick(struct xnsched *sched)
{
	struct xnsched_mlq *q = &sched->rt.runnable;
	struct steely_thread *thread;
	struct list_head *head;
	int idx;

	if (q->elems == 0)
		return NULL;

	/*
	 * Some scheduling policies may be implemented as variants of
	 * the core SCHED_FIFO class, sharing its runqueue
	 * (e.g. SCHED_SPORADIC, SCHED_QUOTA). This means that we have
	 * to do some cascading to call the right pick handler
	 * eventually.
	 */
	idx = xnsched_weightq(q);
	head = q->heads + idx;
	STEELY_BUG_ON(STEELY, list_empty(head));

	/*
	 * The active class (i.e. ->sched_class) is the one currently
	 * queuing the thread, reflecting any priority boost due to
	 * PI.
	 */
	thread = list_first_entry(head, struct steely_thread, rlink);
	if (unlikely(thread->sched_class != &xnsched_class_rt))
		return thread->sched_class->sched_pick(sched);

	del_q(q, &thread->rlink, idx);

	return thread;
}

#endif /* CONFIG_STEELY_SCHED_CLASSES */

#else /* !CONFIG_STEELY_SCALABLE_SCHED */

struct steely_thread *xnsched_findq(struct list_head *q, int prio)
{
	struct steely_thread *thread;

	if (list_empty(q))
		return NULL;

	/* Find thread leading a priority group. */
	list_for_each_entry(thread, q, rlink) {
		if (prio == thread->cprio)
			return thread;
	}

	return NULL;
}

#ifdef CONFIG_STEELY_SCHED_CLASSES

struct steely_thread *xnsched_rt_pick(struct xnsched *sched)
{
	struct list_head *q = &sched->rt.runnable;
	struct steely_thread *thread;

	if (list_empty(q))
		return NULL;

	thread = list_first_entry(q, struct steely_thread, rlink);
	if (unlikely(thread->sched_class != &xnsched_class_rt))
		return thread->sched_class->sched_pick(sched);

	list_del(&thread->rlink);

	return thread;
}

#endif /* CONFIG_STEELY_SCHED_CLASSES */

#endif /* !CONFIG_STEELY_SCALABLE_SCHED */

static inline int test_resched(struct xnsched *sched)
{
	int resched = xnsched_resched_p(sched);
#ifdef CONFIG_SMP
	/* Send resched IPI to remote CPU(s). */
	if (unlikely(!cpumask_empty(&sched->resched))) {
		smp_mb();
		irq_pipeline_send_remote(IPIPE_RESCHEDULE_IPI, &sched->resched);
		cpumask_clear(&sched->resched);
	}
#endif
	sched->status &= ~XNRESCHED;

	return resched;
}

static inline void leave_root(struct steely_thread *root)
{
	struct xnarchtcb *rootcb = xnthread_archtcb(root);
	struct task_struct *p = current;

	dovetail_leave_root();
	/* Remember the preempted Linux task pointer. */
	rootcb->core.host_task = p;
	rootcb->core.tsp = &p->thread;
	rootcb->core.mm = rootcb->core.active_mm = current->active_mm;
	rootcb->core.tip = task_thread_info(p);
	xnarch_leave_root(root);
}

irqreturn_t __xnsched_run_handler(int irq, void *dev_id)
{
	/* hw interrupts are off. */
	trace_steely_schedule_remote(xnsched_current());
	xnsched_run();

	return IRQ_HANDLED;
}

static inline void do_lazy_user_work(struct steely_thread *curr)
{
	xnthread_commit_ceiling(curr);
}

int ___xnsched_run(struct xnsched *sched)
{
	struct steely_thread *prev, *next, *curr;
	int switched, shadow;
	spl_t s;

	if (xnarch_escalate())
		return 0;

	trace_steely_schedule(sched);

	xnlock_get_irqsave(&nklock, s);

	curr = sched->curr;
	/*
	 * CAUTION: xnthread_host_task(curr) may be unsynced and even
	 * stale if curr = &rootcb, since the task logged by
	 * leave_root() may not still be the current one. Use
	 * "current" for disambiguating.
	 */
	if (xnthread_test_state(curr, XNUSER))
		do_lazy_user_work(curr);

	switched = 0;
	if (!test_resched(sched))
		goto out;

	next = xnsched_pick_next(sched);
	if (next == curr) {
		if (unlikely(xnthread_test_state(next, XNROOT))) {
			if (sched->lflags & XNHTICK)
				xnclock_core_notify_root(sched);
			if (sched->lflags & XNHDEFER)
				xnclock_program_shot(&nkclock, sched);
		}
		goto out;
	}

	prev = curr;

	trace_steely_switch_context(prev, next);

	if (xnthread_test_state(next, XNROOT))
		xnsched_reset_watchdog(sched);

	sched->curr = next;
	shadow = 1;

	if (xnthread_test_state(prev, XNROOT)) {
		leave_root(prev);
		shadow = 0;
	} else if (xnthread_test_state(next, XNROOT)) {
		if (sched->lflags & XNHTICK)
			xnclock_core_notify_root(sched);
		if (sched->lflags & XNHDEFER)
			xnclock_program_shot(&nkclock, sched);
	}

	xnstat_exectime_switch(sched, &next->stat.account);
	xnstat_counter_inc(&next->stat.csw);
	xnarch_switch_to(prev, next);

	/*
	 * Test whether we transitioned from primary mode to secondary
	 * over a shadow thread, caused by a call to xnthread_relax().
	 * In such a case, we are running over the regular schedule()
	 * tail code, so we have to skip our tail code.
	 *
	 * CAUTION: TLF_HEAD is still present in the local flags
	 * although we have switched to the root domain, until
	 * dovetail_leave_head() clears it. Always use on_root_stage()
	 * for determining the current domain in context switch code.
	 */
	if (shadow && __on_root_stage()) {
		curr = steely_current_thread();
		STEELY_WARN_ON(STEELY, xnthread_test_state(curr,
				 XNTHREAD_BLOCK_BITS & ~XNRELAX));
		goto shadow_epilogue;
	}

	STEELY_BUG_ON(STEELY, !hard_irqs_disabled());
	switched = 1;
	sched = xnsched_current();
	/*
	 * Re-read the currently running thread, this is needed
	 * because of relaxed/hardened transitions.
	 */
	curr = sched->curr;
out:
	xnlock_put_irqrestore(&nklock, s);

	return switched;

shadow_epilogue:

	dovetail_complete_domain_migration();

	/*
	 * Interrupts must be disabled here (has to be done on entry
	 * of the Linux [__]switch_to function), but it is what
	 * callers expect, specifically the reschedule of an IRQ
	 * handler that hit before we call xnsched_run in
	 * xnthread_suspend() when relaxing a thread.
	 */
	STEELY_BUG_ON(STEELY, !hard_irqs_disabled());

	return 1;
}
EXPORT_SYMBOL_GPL(___xnsched_run);

#ifdef CONFIG_STEELY_VFILE

static struct xnvfile_directory sched_vfroot;

struct vfile_schedlist_priv {
	struct steely_thread *curr;
	ktime_t start_time;
};

struct vfile_schedlist_data {
	int cpu;
	pid_t pid;
	char name[XNOBJECT_NAME_LEN];
	char sched_class[XNOBJECT_NAME_LEN];
	char personality[XNOBJECT_NAME_LEN];
	int cprio;
	ktime_t timeout;
	int state;
};

static struct xnvfile_snapshot_ops vfile_schedlist_ops;

static struct xnvfile_snapshot schedlist_vfile = {
	.privsz = sizeof(struct vfile_schedlist_priv),
	.datasz = sizeof(struct vfile_schedlist_data),
	.tag = &nkthreadlist_tag,
	.ops = &vfile_schedlist_ops,
};

static int vfile_schedlist_rewind(struct xnvfile_snapshot_iterator *it)
{
	struct vfile_schedlist_priv *priv = xnvfile_iterator_priv(it);

	/* &nkthreadq cannot be empty (root thread(s)). */
	priv->curr = list_first_entry(&nkthreadq, struct steely_thread, glink);
	priv->start_time = xnclock_read_monotonic(&nkclock);

	return steely_nrthreads;
}

static int vfile_schedlist_next(struct xnvfile_snapshot_iterator *it,
				void *data)
{
	struct vfile_schedlist_priv *priv = xnvfile_iterator_priv(it);
	struct vfile_schedlist_data *p = data;
	ktime_t timeout, period;
	struct steely_thread *thread;
	ktime_t base_time;

	if (priv->curr == NULL)
		return 0;	/* All done. */

	thread = priv->curr;
	if (list_is_last(&thread->glink, &nkthreadq))
		priv->curr = NULL;
	else
		priv->curr = list_next_entry(thread, glink);

	p->cpu = xnsched_cpu(thread->sched);
	p->pid = xnthread_host_pid(thread);
	memcpy(p->name, thread->name, sizeof(p->name));
	p->cprio = thread->cprio;
	p->state = xnthread_get_state(thread);
	if (thread->lock_count > 0)
		p->state |= XNLOCK;
	knamecpy(p->sched_class, thread->sched_class->name);
	knamecpy(p->personality, thread->personality->name);
	period = xnthread_get_period(thread);
	base_time = priv->start_time;
	if (xntimer_clock(&thread->ptimer) != &nkclock)
		base_time = xnclock_read_monotonic(xntimer_clock(&thread->ptimer));
	timeout = xnthread_get_timeout(thread, base_time);
	/*
	 * Here we cheat: thread is periodic and the sampling rate may
	 * be high, so it is indeed possible that the next tick date
	 * from the ptimer progresses fast enough while we are busy
	 * collecting output data in this loop, so that next_date -
	 * start_time > period. In such a case, we simply ceil the
	 * value to period to keep the result meaningful, even if not
	 * necessarily accurate. But what does accuracy mean when the
	 * sampling frequency is high, and the way to read it has to
	 * go through the vfile interface anyway?
	 */
	if (period > 0 && period < timeout &&
	    !xntimer_running_p(&thread->rtimer))
		timeout = period;

	p->timeout = timeout;

	return 1;
}

static int vfile_schedlist_show(struct xnvfile_snapshot_iterator *it,
				void *data)
{
	struct vfile_schedlist_data *p = data;
	char sbuf[64], pbuf[16], tbuf[16];

	if (p == NULL)
		xnvfile_printf(it,
			       "%-3s  %-6s %-5s  %-8s  %-5s %-12s  %-10s %s\n",
			       "CPU", "PID", "CLASS", "TYPE", "PRI", "TIMEOUT",
			       "STAT", "NAME");
	else {
		ksformat(pbuf, sizeof(pbuf), "%3d", p->cprio);
		xntimer_format_time(p->timeout, tbuf, sizeof(tbuf));
		xnthread_format_status(p->state, sbuf, sizeof(sbuf));

		xnvfile_printf(it,
			       "%3u  %-6d %-5s  %-8s  %-5s %-12s  %-10s %s%s%s\n",
			       p->cpu,
			       p->pid,
			       p->sched_class,
			       p->personality,
			       pbuf,
			       tbuf,
			       sbuf,
			       (p->state & XNUSER) ? "" : "[",
			       p->name,
			       (p->state & XNUSER) ? "" : "]");
	}

	return 0;
}

static struct xnvfile_snapshot_ops vfile_schedlist_ops = {
	.rewind = vfile_schedlist_rewind,
	.next = vfile_schedlist_next,
	.show = vfile_schedlist_show,
};

#ifdef CONFIG_STEELY_STATS

static spl_t vfile_schedstat_lock_s;

static int vfile_schedstat_get_lock(struct xnvfile *vfile)
{
	xnlock_get_irqsave(&nklock, vfile_schedstat_lock_s);

	return 0;
}

static void vfile_schedstat_put_lock(struct xnvfile *vfile)
{
	xnlock_put_irqrestore(&nklock, vfile_schedstat_lock_s);
}

static struct xnvfile_lock_ops vfile_schedstat_lockops = {
	.get = vfile_schedstat_get_lock,
	.put = vfile_schedstat_put_lock,
};

struct vfile_schedstat_priv {
	struct steely_thread *curr;
};

struct vfile_schedstat_data {
	int cpu;
	pid_t pid;
	int state;
	char name[XNOBJECT_NAME_LEN];
	unsigned long ssw;
	unsigned long csw;
	unsigned long xsc;
	unsigned long pf;
	ktime_t exectime_period;
	ktime_t account_period;
	ktime_t exectime_total;
	struct xnsched_class *sched_class;
	ktime_t period;
	int cprio;
};

static struct xnvfile_snapshot_ops vfile_schedstat_ops;

static struct xnvfile_snapshot schedstat_vfile = {
	.privsz = sizeof(struct vfile_schedstat_priv),
	.datasz = sizeof(struct vfile_schedstat_data),
	.tag = &nkthreadlist_tag,
	.ops = &vfile_schedstat_ops,
	.entry = { .lockops = &vfile_schedstat_lockops },
};

static int vfile_schedstat_rewind(struct xnvfile_snapshot_iterator *it)
{
	struct vfile_schedstat_priv *priv = xnvfile_iterator_priv(it);

	priv->curr = list_first_entry(&nkthreadq, struct steely_thread, glink);

	return steely_nrthreads;
}

static int vfile_schedstat_next(struct xnvfile_snapshot_iterator *it,
				void *data)
{
	struct vfile_schedstat_priv *priv = xnvfile_iterator_priv(it);
	struct vfile_schedstat_data *p = data;
	struct steely_thread *thread;
	struct xnsched *sched;
	ktime_t period;

	thread = priv->curr;
	if (thread == NULL)
		return 0;

	if (list_is_last(&thread->glink, &nkthreadq))
		priv->curr = NULL;
	else
		priv->curr = list_next_entry(thread, glink);

	sched = thread->sched;
	p->cpu = xnsched_cpu(sched);
	p->pid = xnthread_host_pid(thread);
	memcpy(p->name, thread->name, sizeof(p->name));
	p->state = xnthread_get_state(thread);
	if (thread->lock_count > 0)
		p->state |= XNLOCK;
	p->ssw = xnstat_counter_get(&thread->stat.ssw);
	p->csw = xnstat_counter_get(&thread->stat.csw);
	p->xsc = xnstat_counter_get(&thread->stat.xsc);
	p->pf = xnstat_counter_get(&thread->stat.pf);
	p->sched_class = thread->sched_class;
	p->cprio = thread->cprio;
	p->period = xnthread_get_period(thread);

	period = ktime_sub(sched->last_account_switch,
			   thread->stat.lastperiod.start);
	if (ktime_to_ns(period) == 0 && thread == sched->curr) {
		p->exectime_period = ktime_set(0, 1);
		p->account_period = ktime_set(0, 1);
	} else {
		p->exectime_period =
			ktime_sub(thread->stat.account.total,
				  thread->stat.lastperiod.total);
		p->account_period = period;
	}
	p->exectime_total = thread->stat.account.total;
	thread->stat.lastperiod.total = thread->stat.account.total;
	thread->stat.lastperiod.start = sched->last_account_switch;

	return 1;
}

static int vfile_schedstat_show(struct xnvfile_snapshot_iterator *it,
				void *data)
{
	struct vfile_schedstat_data *p = data;
	u64 usage = 0;

	if (p == NULL)
		xnvfile_printf(it,
			       "%-3s  %-6s %-10s %-10s %-10s %-4s  %-8s  %5s"
			       "  %s\n",
			       "CPU", "PID", "MSW", "CSW", "XSC", "PF", "STAT", "%CPU",
			       "NAME");
	else {
		if (p->account_period) {
			while (p->account_period > 0xffffffffUL) {
				p->exectime_period >>= 16;
				p->account_period >>= 16;
			}
			usage = p->exectime_period * 1000LL +
				(p->account_period >> 1);
			do_div(usage, ktime_to_ns(p->account_period));
		}
		xnvfile_printf(it,
			       "%3u  %-6d %-10lu %-10lu %-10lu %-4lu  %.8x  %3u.%u"
			       "  %s%s%s\n",
			       p->cpu, p->pid, p->ssw, p->csw, p->xsc, p->pf, p->state,
			       (u32)usage / 10, (u32)usage % 10,
			       (p->state & XNUSER) ? "" : "[",
			       p->name,
			       (p->state & XNUSER) ? "" : "]");
	}

	return 0;
}

static int vfile_schedacct_show(struct xnvfile_snapshot_iterator *it,
				void *data)
{
	struct vfile_schedstat_data *p = data;

	if (p == NULL)
		return 0;

	xnvfile_printf(it, "%u %d %lu %lu %lu %lu %.8x %Lu %Lu %Lu %s %s %d %Lu\n",
		       p->cpu, p->pid, p->ssw, p->csw, p->xsc, p->pf, p->state,
		       ktime_to_ns(p->account_period),
		       ktime_to_ns(p->exectime_period),
		       ktime_to_ns(p->exectime_total),
		       p->name,
		       p->sched_class->name,
		       p->cprio,
		       p->period);

	return 0;
}

static struct xnvfile_snapshot_ops vfile_schedstat_ops = {
	.rewind = vfile_schedstat_rewind,
	.next = vfile_schedstat_next,
	.show = vfile_schedstat_show,
};

/*
 * An accounting vfile is a thread statistics vfile in disguise with a
 * different output format, which is parser-friendly.
 */
static struct xnvfile_snapshot_ops vfile_schedacct_ops;

static struct xnvfile_snapshot schedacct_vfile = {
	.privsz = sizeof(struct vfile_schedstat_priv),
	.datasz = sizeof(struct vfile_schedstat_data),
	.tag = &nkthreadlist_tag,
	.ops = &vfile_schedacct_ops,
};

static struct xnvfile_snapshot_ops vfile_schedacct_ops = {
	.rewind = vfile_schedstat_rewind,
	.next = vfile_schedstat_next,
	.show = vfile_schedacct_show,
};

#endif /* CONFIG_STEELY_STATS */

#ifdef CONFIG_SMP

static int affinity_vfile_show(struct xnvfile_regular_iterator *it,
			       void *data)
{
	unsigned long val = 0;
	int cpu;

	for (cpu = 0; cpu < BITS_PER_LONG; cpu++)
		if (cpumask_test_cpu(cpu, &steely_cpu_affinity))
			val |= (1UL << cpu);

	xnvfile_printf(it, "%08lx\n", val);

	return 0;
}

static ssize_t affinity_vfile_store(struct xnvfile_input *input)
{
	struct cpumask affinity, set;
	ssize_t ret;
	long val;
	int cpu;
	spl_t s;

	ret = xnvfile_get_integer(input, &val);
	if (ret < 0)
		return ret;

	if (val == 0)
		affinity = xnsched_realtime_cpus; /* Reset to default. */
	else {
		cpumask_clear(&affinity);
		for (cpu = 0; cpu < BITS_PER_LONG; cpu++, val >>= 1) {
			if (val & 1)
				cpumask_set_cpu(cpu, &affinity);
		}
	}

	cpumask_and(&set, &affinity, cpu_online_mask);
	if (cpumask_empty(&set))
		return -EINVAL;

	/*
	 * The new dynamic affinity must be a strict subset of the
	 * static set of supported CPUs.
	 */
	cpumask_or(&set, &affinity, &xnsched_realtime_cpus);
	if (!cpumask_equal(&set, &xnsched_realtime_cpus))
		return -EINVAL;

	xnlock_get_irqsave(&nklock, s);
	steely_cpu_affinity = affinity;
	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

static struct xnvfile_regular_ops affinity_vfile_ops = {
	.show = affinity_vfile_show,
	.store = affinity_vfile_store,
};

static struct xnvfile_regular affinity_vfile = {
	.ops = &affinity_vfile_ops,
};

#endif /* CONFIG_SMP */

int xnsched_init_proc(void)
{
	struct xnsched_class *p;
	int ret;

	ret = xnvfile_init_dir("sched", &sched_vfroot, &steely_vfroot);
	if (ret)
		return ret;

	ret = xnvfile_init_snapshot("threads", &schedlist_vfile, &sched_vfroot);
	if (ret)
		return ret;

	for_each_xnsched_class(p) {
		if (p->sched_init_vfile) {
			ret = p->sched_init_vfile(p, &sched_vfroot);
			if (ret)
				return ret;
		}
	}

#ifdef CONFIG_STEELY_STATS
	ret = xnvfile_init_snapshot("stat", &schedstat_vfile, &sched_vfroot);
	if (ret)
		return ret;
	ret = xnvfile_init_snapshot("acct", &schedacct_vfile, &sched_vfroot);
	if (ret)
		return ret;
#endif /* CONFIG_STEELY_STATS */

#ifdef CONFIG_SMP
	xnvfile_init_regular("affinity", &affinity_vfile, &steely_vfroot);
#endif /* CONFIG_SMP */

	return 0;
}

void xnsched_cleanup_proc(void)
{
	struct xnsched_class *p;

	for_each_xnsched_class(p) {
		if (p->sched_cleanup_vfile)
			p->sched_cleanup_vfile(p);
	}

#ifdef CONFIG_SMP
	xnvfile_destroy_regular(&affinity_vfile);
#endif /* CONFIG_SMP */
#ifdef CONFIG_STEELY_STATS
	xnvfile_destroy_snapshot(&schedacct_vfile);
	xnvfile_destroy_snapshot(&schedstat_vfile);
#endif /* CONFIG_STEELY_STATS */
	xnvfile_destroy_snapshot(&schedlist_vfile);
	xnvfile_destroy_dir(&sched_vfroot);
}

#endif /* CONFIG_STEELY_VFILE */

struct xnsched_class *
steely_sched_policy_param(union xnsched_policy_param *param,
			  int u_policy, const struct sched_param_ex *param_ex,
			  ktime_t *tslice_r)
{
	struct xnsched_class *sched_class;
	int prio, policy;
	ktime_t tslice;

	prio = param_ex->sched_priority;
	tslice = XN_INFINITE;
	policy = u_policy;

	/*
	 * NOTE: The user-defined policy may be different than ours,
	 * e.g. SCHED_FIFO,prio=-7 from userland would be interpreted
	 * as SCHED_WEAK,prio=7 in kernel space.
	 */
	if (prio < 0) {
		prio = -prio;
		policy = SCHED_WEAK;
	}
	sched_class = &xnsched_class_rt;
	param->rt.prio = prio;

	switch (policy) {
	case SCHED_NORMAL:
		if (prio)
			return NULL;
		/*
		 * When the weak scheduling class is compiled in,
		 * SCHED_WEAK and SCHED_NORMAL threads are scheduled
		 * by xnsched_class_weak, at their respective priority
		 * levels. Otherwise, SCHED_NORMAL is scheduled by
		 * xnsched_class_rt at priority level #0.
		 */
	case SCHED_WEAK:
#ifdef CONFIG_STEELY_SCHED_WEAK
		if (prio < XNSCHED_WEAK_MIN_PRIO ||
		    prio > XNSCHED_WEAK_MAX_PRIO)
			return NULL;
		param->weak.prio = prio;
		sched_class = &xnsched_class_weak;
#else
		if (prio)
			return NULL;
#endif
		break;
	case SCHED_RR:
		/* if unspecified, use current one. */
		tslice = timespec_to_ktime(param_ex->sched_rr_quantum);
		if (timeout_infinite(tslice) && tslice_r)
			tslice = *tslice_r;
		/* falldown wanted */
	case SCHED_FIFO:
		if (prio < XNSCHED_FIFO_MIN_PRIO ||
		    prio > XNSCHED_FIFO_MAX_PRIO)
			return NULL;
		break;
	case SCHED_STEELY:
		if (prio < XNSCHED_CORE_MIN_PRIO ||
		    prio > XNSCHED_CORE_MAX_PRIO)
			return NULL;
		break;
#ifdef CONFIG_STEELY_SCHED_SPORADIC
	case SCHED_SPORADIC:
		param->pss.normal_prio = param_ex->sched_priority;
		param->pss.low_prio = param_ex->sched_ss_low_priority;
		param->pss.current_prio = param->pss.normal_prio;
		param->pss.init_budget = timespec_to_ktime(param_ex->sched_ss_init_budget);
		param->pss.repl_period = timespec_to_ktime(param_ex->sched_ss_repl_period);
		param->pss.max_repl = param_ex->sched_ss_max_repl;
		sched_class = &xnsched_class_sporadic;
		break;
#endif
#ifdef CONFIG_STEELY_SCHED_TP
	case SCHED_TP:
		param->tp.prio = param_ex->sched_priority;
		param->tp.ptid = param_ex->sched_tp_partition;
		sched_class = &xnsched_class_tp;
		break;
#endif
#ifdef CONFIG_STEELY_SCHED_QUOTA
	case SCHED_QUOTA:
		param->quota.prio = param_ex->sched_priority;
		param->quota.tgid = param_ex->sched_quota_group;
		sched_class = &xnsched_class_quota;
		break;
#endif
	default:
		return NULL;
	}

	if (tslice_r)
		*tslice_r = tslice;

	return sched_class;
}

STEELY_SYSCALL(sched_minprio, current, (int policy))
{
	int ret;

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
	case SCHED_SPORADIC:
	case SCHED_TP:
	case SCHED_QUOTA:
		ret = XNSCHED_FIFO_MIN_PRIO;
		break;
	case SCHED_STEELY:
		ret = XNSCHED_CORE_MIN_PRIO;
		break;
	case SCHED_NORMAL:
	case SCHED_WEAK:
		ret = 0;
		break;
	default:
		ret = -EINVAL;
	}

	trace_steely_sched_min_prio(policy, ret);

	return ret;
}

STEELY_SYSCALL(sched_maxprio, current, (int policy))
{
	int ret;

	switch (policy) {
	case SCHED_FIFO:
	case SCHED_RR:
	case SCHED_SPORADIC:
	case SCHED_TP:
	case SCHED_QUOTA:
		ret = XNSCHED_FIFO_MAX_PRIO;
		break;
	case SCHED_STEELY:
		ret = XNSCHED_CORE_MAX_PRIO;
		break;
	case SCHED_NORMAL:
		ret = 0;
		break;
	case SCHED_WEAK:
#ifdef CONFIG_STEELY_SCHED_WEAK
		ret = XNSCHED_FIFO_MAX_PRIO;
#else
		ret = 0;
#endif
		break;
	default:
		ret = -EINVAL;
	}

	trace_steely_sched_max_prio(policy, ret);

	return ret;
}

STEELY_SYSCALL(sched_yield, primary, (void))
{
	struct steely_thread *curr = steely_current_thread();
	int ret = 0;

	trace_steely_pthread_yield(0);

	/* Maybe some extension wants to handle this. */
  	if (steely_call_extension(sched_yield, &curr->extref, ret) && ret)
		return ret > 0 ? 0 : ret;

	xnthread_resume(curr, 0);
	if (xnsched_run())
		return 0;

	/*
	 * If the round-robin move did not beget any context switch to
	 * a thread running in primary mode, then wait for the next
	 * linux context switch to happen.
	 *
	 * Rationale: it is most probably unexpected that
	 * sched_yield() does not cause any context switch, since this
	 * service is commonly used for implementing a poor man's
	 * cooperative scheduling. By waiting for a context switch to
	 * happen in the regular kernel, we guarantee that the CPU has
	 * been relinquished for a while.
	 *
	 * Typically, this behavior allows a thread running in primary
	 * mode to effectively yield the CPU to a thread of
	 * same/higher priority stuck in secondary mode.
	 *
	 * NOTE: calling steely_yield() with no timeout
	 * (i.e. XN_INFINITE) is probably never a good idea. This
	 * means that a SCHED_FIFO non-rt thread stuck in a tight loop
	 * would prevent the caller from waking up, since no
	 * linux-originated schedule event would happen for unblocking
	 * it on the current CPU. For this reason, we pass the
	 * arbitrary TICK_NSEC value to limit the wait time to a
	 * reasonable amount.
	 */
	return steely_yield(TICK_NSEC, TICK_NSEC);
}

#ifdef CONFIG_STEELY_SCHED_TP

static inline
int set_tp_config(int cpu, union sched_config *config, size_t len)
{
	ktime_t offset, duration, next_offset;
	struct xnsched_tp_schedule *gps, *ogps;
	struct xnsched_tp_window *w;
	struct sched_tp_window *p;
	struct xnsched *sched;
	spl_t s;
	int n;

	if (len < sizeof(config->tp))
		return -EINVAL;

	sched = xnsched_struct(cpu);

	switch (config->tp.op) {
	case sched_tp_install:
		if (config->tp.nr_windows > 0)
			break;
		/* Fallback wanted. */
	case sched_tp_uninstall:
		gps = NULL;
		goto set_schedule;
	case sched_tp_start:
		xnlock_get_irqsave(&nklock, s);
		xnsched_tp_start_schedule(sched);
		xnlock_put_irqrestore(&nklock, s);
		return 0;
	case sched_tp_stop:
		xnlock_get_irqsave(&nklock, s);
		xnsched_tp_stop_schedule(sched);
		xnlock_put_irqrestore(&nklock, s);
		return 0;
	default:
		return -EINVAL;
	}

	/* Install a new TP schedule on CPU. */

	gps = xnmalloc(sizeof(*gps) + config->tp.nr_windows * sizeof(*w));
	if (gps == NULL)
		return -ENOMEM;

	for (n = 0, p = config->tp.windows, w = gps->pwins, next_offset = 0;
	     n < config->tp.nr_windows; n++, p++, w++) {
		/*
		 * Time windows must be strictly contiguous. Holes may
		 * be defined using windows assigned to the pseudo
		 * partition #-1.
		 */
		offset = timespec_to_ktime(p->offset);
		if (offset != next_offset)
			goto cleanup_and_fail;

		duration = timespec_to_ktime(p->duration);
		if (ktime_to_ns(duration) <= 0)
			goto cleanup_and_fail;

		if (p->ptid < -1 ||
		    p->ptid >= CONFIG_STEELY_SCHED_TP_NRPART)
			goto cleanup_and_fail;

		w->w_offset = next_offset;
		w->w_part = p->ptid;
		next_offset = ktime_add(next_offset, duration);
	}

	atomic_set(&gps->refcount, 1);
	gps->pwin_nr = n;
	gps->tf_duration = next_offset;
set_schedule:
	xnlock_get_irqsave(&nklock, s);
	ogps = xnsched_tp_set_schedule(sched, gps);
	xnlock_put_irqrestore(&nklock, s);

	if (ogps)
		xnsched_tp_put_schedule(ogps);

	return 0;

cleanup_and_fail:
	xnfree(gps);

	return -EINVAL;
}

static inline
ssize_t get_tp_config(int cpu, void __user *u_config, size_t len,
		      union sched_config *(*fetch_config)
		      (int policy, const void __user *u_config,
		       size_t *len),
		      ssize_t (*put_config)(int policy, void __user *u_config,
					    size_t u_len,
					    const union sched_config *config,
					    size_t len))
{
	struct xnsched_tp_window *pw, *w;
	struct xnsched_tp_schedule *gps;
	struct sched_tp_window *pp, *p;
	union sched_config *config;
	struct xnsched *sched;
	ssize_t ret, elen;
	spl_t s;
	int n;

	xnlock_get_irqsave(&nklock, s);

	sched = xnsched_struct(cpu);
	gps = xnsched_tp_get_schedule(sched);
	if (gps == NULL) {
		xnlock_put_irqrestore(&nklock, s);
		return 0;
	}

	xnlock_put_irqrestore(&nklock, s);

	elen = sched_tp_confsz(gps->pwin_nr);
	config = xnmalloc(elen);
	if (config == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	config->tp.op = sched_tp_install;
	config->tp.nr_windows = gps->pwin_nr;
	for (n = 0, pp = p = config->tp.windows, pw = w = gps->pwins;
	     n < gps->pwin_nr; pp = p, p++, pw = w, w++, n++) {
		p->offset = ktime_to_timespec(w->w_offset);
		pp->duration = ktime_to_timespec(ktime_sub(w->w_offset,
				   pw->w_offset));
		p->ptid = w->w_part;
	}
	pp->duration = ktime_to_timespec(ktime_sub(gps->tf_duration,
				   pw->w_offset));
	ret = put_config(SCHED_TP, u_config, len, config, elen);
	xnfree(config);
out:
	xnsched_tp_put_schedule(gps);

	return ret;
}

#else /* !CONFIG_STEELY_SCHED_TP */

static inline int
set_tp_config(int cpu, union sched_config *config, size_t len)
{
	return -EINVAL;
}

static inline ssize_t
get_tp_config(int cpu, union sched_config __user *u_config, size_t len,
	      union sched_config *(*fetch_config)
	      (int policy, const void __user *u_config,
	       size_t *len),
	      ssize_t (*put_config)(int policy, void __user *u_config,
				    size_t u_len,
				    const union sched_config *config,
				    size_t len))
{
	return -EINVAL;
}

#endif /* !CONFIG_STEELY_SCHED_TP */

#ifdef CONFIG_STEELY_SCHED_QUOTA

static inline
int set_quota_config(int cpu, union sched_config *config, size_t len)
{
	struct __sched_config_quota *p = &config->quota;
	struct __sched_quota_info *iq = &p->info;
	struct steely_sched_group *group;
	struct xnsched_quota_group *tg;
	struct xnsched *sched;
	int ret, quota_sum;
	spl_t s;

	if (len < sizeof(*p))
		return -EINVAL;

	switch (p->op) {
	case sched_quota_add:
		group = xnmalloc(sizeof(*group));
		if (group == NULL)
			return -ENOMEM;
		tg = &group->quota;
		group->pshared = p->add.pshared != 0;
		group->scope = steely_current_resources(group->pshared);
		xnlock_get_irqsave(&nklock, s);
		sched = xnsched_struct(cpu);
		ret = xnsched_quota_create_group(tg, sched, &quota_sum);
		if (ret) {
			xnlock_put_irqrestore(&nklock, s);
			xnfree(group);
			return ret;
		}
		list_add(&group->next, &group->scope->schedq);
		xnlock_put_irqrestore(&nklock, s);
		break;
	case sched_quota_remove:
	case sched_quota_force_remove:
		xnlock_get_irqsave(&nklock, s);
		sched = xnsched_struct(cpu);
		tg = xnsched_quota_find_group(sched, p->remove.tgid);
		if (tg == NULL)
			goto bad_tgid;
		group = container_of(tg, struct steely_sched_group, quota);
		if (group->scope != steely_current_resources(group->pshared))
			goto bad_tgid;
		ret = xnsched_quota_destroy_group(tg,
						  p->op == sched_quota_force_remove,
						  &quota_sum);
		if (ret) {
			xnlock_put_irqrestore(&nklock, s);
			return ret;
		}
		list_del(&group->next);
		xnlock_put_irqrestore(&nklock, s);
		xnfree(group);
		break;
	case sched_quota_set:
		xnlock_get_irqsave(&nklock, s);
		sched = xnsched_struct(cpu);
		tg = xnsched_quota_find_group(sched, p->set.tgid);
		if (tg == NULL)
			goto bad_tgid;
		group = container_of(tg, struct steely_sched_group, quota);
		if (group->scope != steely_current_resources(group->pshared))
			goto bad_tgid;
		xnsched_quota_set_limit(tg, p->set.quota, p->set.quota_peak,
					&quota_sum);
		xnlock_put_irqrestore(&nklock, s);
		break;
	default:
		return -EINVAL;
	}

	iq->tgid = tg->tgid;
	iq->quota = tg->quota_percent;
	iq->quota_peak = tg->quota_peak_percent;
	iq->quota_sum = quota_sum;

	return 0;
bad_tgid:
	xnlock_put_irqrestore(&nklock, s);

	return -ESRCH;
}

static inline
ssize_t get_quota_config(int cpu, void __user *u_config, size_t len,
			 union sched_config *(*fetch_config)
			 (int policy, const void __user *u_config,
			  size_t *len),
			 ssize_t (*put_config)(int policy, void __user *u_config,
					       size_t u_len,
					       const union sched_config *config,
					       size_t len))
{
	struct steely_sched_group *group;
	struct xnsched_quota_group *tg;
	union sched_config *config;
	struct xnsched *sched;
	ssize_t ret;
	spl_t s;

	config = fetch_config(SCHED_QUOTA, u_config, &len);
	if (IS_ERR(config))
		return PTR_ERR(config);

	xnlock_get_irqsave(&nklock, s);
	sched = xnsched_struct(cpu);
	tg = xnsched_quota_find_group(sched, config->quota.get.tgid);
	if (tg == NULL)
		goto bad_tgid;

	group = container_of(tg, struct steely_sched_group, quota);
	if (group->scope != steely_current_resources(group->pshared))
		goto bad_tgid;

	config->quota.info.tgid = tg->tgid;
	config->quota.info.quota = tg->quota_percent;
	config->quota.info.quota_peak = tg->quota_peak_percent;
	config->quota.info.quota_sum = xnsched_quota_sum_all(sched);
	xnlock_put_irqrestore(&nklock, s);

	ret = put_config(SCHED_QUOTA, u_config, len, config, sizeof(*config));
	xnfree(config);

	return ret;
bad_tgid:
	xnlock_put_irqrestore(&nklock, s);
	xnfree(config);

	return -ESRCH;
}

#else /* !CONFIG_STEELY_SCHED_QUOTA */

static inline
int set_quota_config(int cpu, union sched_config *config, size_t len)
{
	return -EINVAL;
}

static inline
ssize_t get_quota_config(int cpu, void __user *u_config,
			 size_t len,
			 union sched_config *(*fetch_config)
			 (int policy, const void __user *u_config,
			  size_t *len),
			 ssize_t (*put_config)(int policy, void __user *u_config,
					       size_t u_len,
					       const union sched_config *config,
					       size_t len))
{
	return -EINVAL;
}

#endif /* !CONFIG_STEELY_SCHED_QUOTA */

static union sched_config *
sched_fetch_config(int policy, const void __user *u_config, size_t *len)
{
	union sched_config *buf;
	int ret;

	if (u_config == NULL)
		return ERR_PTR(-EFAULT);

	if (policy == SCHED_QUOTA && *len < sizeof(buf->quota))
		return ERR_PTR(-EINVAL);

	buf = xnmalloc(*len);
	if (buf == NULL)
		return ERR_PTR(-ENOMEM);

	ret = steely_copy_from_user(buf, u_config, *len);
	if (ret) {
		xnfree(buf);
		return ERR_PTR(ret);
	}

	return buf;
}

static int sched_ack_config(int policy, const union sched_config *config,
			    void __user *u_config)
{
	union sched_config __user *u_p = u_config;

	if (policy != SCHED_QUOTA)
		return 0;

	return u_p == NULL ? -EFAULT :
		steely_copy_to_user(&u_p->quota.info, &config->quota.info,
				       sizeof(u_p->quota.info));
}

static ssize_t sched_put_config(int policy,
				void __user *u_config, size_t u_len,
				const union sched_config *config, size_t len)
{
	union sched_config *u_p = u_config;

	if (u_config == NULL)
		return -EFAULT;

	if (policy == SCHED_QUOTA) {
		if (u_len < sizeof(config->quota))
			return -EINVAL;
		return steely_copy_to_user(&u_p->quota.info, &config->quota.info,
					      sizeof(u_p->quota.info)) ?:
			sizeof(u_p->quota.info);
	}

	return steely_copy_to_user(u_config, config, len) ?: len;
}

int __steely_sched_setconfig_np(int cpu, int policy,
				void __user *u_config,
				size_t len,
				union sched_config *(*fetch_config)
				(int policy, const void __user *u_config,
				 size_t *len),
				int (*ack_config)(int policy,
						  const union sched_config *config,
						  void __user *u_config))
{
	union sched_config *buf;
	int ret;

	trace_steely_sched_setconfig(cpu, policy, len);

	if (cpu < 0 || cpu >= NR_CPUS || !cpu_online(cpu))
		return -EINVAL;

	if (len == 0)
		return -EINVAL;

	buf = fetch_config(policy, u_config, &len);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	switch (policy)	{
	case SCHED_TP:
		ret = set_tp_config(cpu, buf, len);
		break;
	case SCHED_QUOTA:
		ret = set_quota_config(cpu, buf, len);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret == 0)
		ret = ack_config(policy, buf, u_config);

	xnfree(buf);

	return ret;
}

STEELY_SYSCALL(sched_setconfig_np, conforming,
	       (int cpu, int policy,
		union sched_config __user *u_config,
		size_t len))
{
	return __steely_sched_setconfig_np(cpu, policy, u_config, len,
					   sched_fetch_config, sched_ack_config);
}

ssize_t __steely_sched_getconfig_np(int cpu, int policy,
				    void __user *u_config,
				    size_t len,
				    union sched_config *(*fetch_config)
				    (int policy, const void __user *u_config,
				     size_t *len),
				    ssize_t (*put_config)(int policy,
							  void __user *u_config,
							  size_t u_len,
							  const union sched_config *config,
							  size_t len))
{
	ssize_t ret;

	switch (policy)	{
	case SCHED_TP:
		ret = get_tp_config(cpu, u_config, len,
				    fetch_config, put_config);
		break;
	case SCHED_QUOTA:
		ret = get_quota_config(cpu, u_config, len,
				       fetch_config, put_config);
		break;
	default:
		ret = -EINVAL;
	}

	trace_steely_sched_get_config(cpu, policy, ret);

	return ret;
}

STEELY_SYSCALL(sched_getconfig_np, conforming,
	       (int cpu, int policy,
		union sched_config __user *u_config,
		size_t len))
{
	return __steely_sched_getconfig_np(cpu, policy, u_config, len,
					   sched_fetch_config, sched_put_config);
}

int __steely_sched_weightprio(int policy,
			      const struct sched_param_ex *param_ex)
{
	struct xnsched_class *sched_class;
	union xnsched_policy_param param;
	int prio;

	sched_class = steely_sched_policy_param(&param, policy,
						param_ex, NULL);
	if (sched_class == NULL)
		return -EINVAL;

	prio = param_ex->sched_priority;
	if (prio < 0)
		prio = -prio;

	return prio + sched_class->weight;
}

STEELY_SYSCALL(sched_weightprio, current,
	       (int policy, const struct sched_param_ex __user *u_param))
{
	struct sched_param_ex param_ex;

	if (steely_copy_from_user(&param_ex, u_param, sizeof(param_ex)))
		return -EFAULT;

	return __steely_sched_weightprio(policy, &param_ex);
}

int steely_sched_setscheduler_ex(pid_t pid,
				 int policy,
				 const struct sched_param_ex *param_ex,
				 __u32 __user *u_winoff,
				 int __user *u_promoted)
{
	struct steely_local_hkey hkey;
	struct steely_thread *thread;
	int ret, promoted = 0;
	spl_t s;

	trace_steely_sched_setscheduler(pid, policy, param_ex);

	if (pid) {
		xnlock_get_irqsave(&nklock, s);
		thread = steely_thread_find(pid);
		xnlock_put_irqrestore(&nklock, s);
	} else
		thread = steely_current_thread();

	if (thread == NULL) {
		if (u_winoff == NULL)
			return -ESRCH;
			
		thread = steely_thread_shadow(current, &hkey, u_winoff);
		if (IS_ERR(thread))
			return PTR_ERR(thread);

		promoted = 1;
	}

	ret = __steely_thread_setschedparam_ex(thread, policy, param_ex);
	if (ret)
		return ret;

	return steely_copy_to_user(u_promoted, &promoted, sizeof(promoted));
}

STEELY_SYSCALL(sched_setscheduler_ex, conforming,
	       (pid_t pid,
		int policy,
		const struct sched_param_ex __user *u_param,
		__u32 __user *u_winoff,
		int __user *u_promoted))
{
	struct sched_param_ex param_ex;

	if (steely_copy_from_user(&param_ex, u_param, sizeof(param_ex)))
		return -EFAULT;

	return steely_sched_setscheduler_ex(pid, policy, &param_ex,
					    u_winoff, u_promoted);
}

int steely_sched_getscheduler_ex(pid_t pid,
				 int *policy_r,
				 struct sched_param_ex *param_ex)
{
	struct steely_thread *thread;
	spl_t s;

	trace_steely_sched_getscheduler(pid);

	if (pid) {
		xnlock_get_irqsave(&nklock, s);
		thread = steely_thread_find(pid);
		xnlock_put_irqrestore(&nklock, s);
	} else
		thread = steely_current_thread();

	if (thread == NULL)
		return -ESRCH;

	return __steely_thread_getschedparam_ex(thread, policy_r, param_ex);
}

STEELY_SYSCALL(sched_getscheduler_ex, current,
	       (pid_t pid,
		int __user *u_policy,
		struct sched_param_ex __user *u_param))
{
	struct sched_param_ex param_ex;
	int ret, policy;

	ret = steely_sched_getscheduler_ex(pid, &policy, &param_ex);
	if (ret)
		return ret;

	if (steely_copy_to_user(u_param, &param_ex, sizeof(param_ex)) ||
	    steely_copy_to_user(u_policy, &policy, sizeof(policy)))
		return -EFAULT;

	return 0;
}

void steely_sched_reclaim(struct steely_process *process)
{
	struct steely_resources *p = &process->resources;
	struct steely_sched_group *group;
#ifdef CONFIG_STEELY_SCHED_QUOTA
	int quota_sum;
#endif
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while (!list_empty(&p->schedq)) {
		group = list_get_entry(&p->schedq, struct steely_sched_group, next);
#ifdef CONFIG_STEELY_SCHED_QUOTA
		xnsched_quota_destroy_group(&group->quota, 1, &quota_sum);
#endif
		xnlock_put_irqrestore(&nklock, s);
		xnfree(group);
		xnlock_get_irqsave(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);
}
