/*
 * Copyright (C) 2006-2011 Philippe Gerum <rpm@xenomai.org>.
 * Copyright Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/errno.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/tick.h>
#include <linux/kconfig.h>
#include <linux/clocksource.h>
#include <linux/bitmap.h>
#include <linux/sched/signal.h>
#include <steely/sched.h>
#include <steely/timer.h>
#include <steely/clock.h>
#include <steely/coreclk.h>
#include <steely/vdso.h>
#include <steely/thread.h>
#include <uapi/steely/time.h>
#include <trace/events/steely.h>
#include "internal.h"

static struct xnclock *external_clocks[STEELY_MAX_EXTCLOCKS];

DECLARE_BITMAP(steely_clock_extids, STEELY_MAX_EXTCLOCKS);

static void adjust_timer(struct xntimer *timer, xntimerq_t *q,
			 ktime_t delta)
{
	struct xnclock *clock = xntimer_clock(timer);
	ktime_t period, diff;
	s64 div;

	xntimer_backward(timer, delta);

	if (xntimer_periodic_p(timer) == 0)
		goto enqueue;

	timer->start_date = ktime_sub(timer->start_date, delta);
	period = xntimer_interval(timer);
	diff = ktime_sub(xnclock_read_monotonic(clock), xntimer_expiry(timer));

	if (diff >= period) {
		/*
		 * Timer should tick several times before now, instead
		 * of calling timer->handler several times, we change
		 * the timer date without changing its pexpect, so
		 * that timer will tick only once and the lost ticks
		 * will be counted as overruns.
		 */
		div = ktime_divns(diff, ktime_to_ns(period));
		timer->periodic_ticks += div;
		xntimer_update_date(timer);
	} else if (ktime_to_ns(delta) < 0
		   && (timer->status & XNTIMER_FIRED)
		   && ktime_to_ns(ktime_add(diff, period)) <= 0) {
		/*
		 * Timer is periodic and NOT waiting for its first
		 * shot, so we make it tick sooner than its original
		 * date in order to avoid the case where by adjusting
		 * time to a sooner date, real-time periodic timers do
		 * not tick until the original date has passed.
		 */
		div = ktime_divns(-diff, ktime_to_ns(period));
		timer->periodic_ticks -= div;
		timer->pexpect_ticks -= div;
		xntimer_update_date(timer);
	}

enqueue:
	xntimer_enqueue(timer, q);
}

void xnclock_adjust(struct xnclock *clock, ktime_t delta)
{
	struct xntimer *timer, *tmp;
	struct list_head adjq;
	struct xnsched *sched;
	xntimerq_it_t it;
	unsigned int cpu;
	xntimerh_t *h;
	xntimerq_t *q;

	INIT_LIST_HEAD(&adjq);

	for_each_online_cpu(cpu) {
		sched = xnsched_struct(cpu);
		q = &xnclock_percpu_timerdata(clock, cpu)->q;

		for (h = xntimerq_it_begin(q, &it); h;
		     h = xntimerq_it_next(q, &it, h)) {
			timer = container_of(h, struct xntimer, aplink);
			if (timer->status & XNTIMER_REALTIME)
				list_add_tail(&timer->adjlink, &adjq);
		}

		if (list_empty(&adjq))
			continue;

		list_for_each_entry_safe(timer, tmp, &adjq, adjlink) {
			list_del(&timer->adjlink);
			xntimer_dequeue(timer, q);
			adjust_timer(timer, q, delta);
		}

		if (sched != xnsched_current())
			xnclock_remote_shot(clock, sched);
		else
			xnclock_program_shot(clock, sched);
	}
}
EXPORT_SYMBOL_GPL(xnclock_adjust);

#ifdef CONFIG_SMP

int xnclock_get_default_cpu(struct xnclock *clock, int cpu)
{
	struct cpumask set;
	/*
	 * Check a CPU number against the possible set of CPUs
	 * receiving events from the underlying clock device. If the
	 * suggested CPU does not receive events from this device,
	 * return the first one which does.  We also account for the
	 * dynamic set of real-time CPUs.
	 *
	 * A clock device with no percpu semantics causes this routine
	 * to return CPU0 unconditionally.
	 */
	if (cpumask_empty(&clock->affinity))
		return 0;
	
	cpumask_and(&set, &clock->affinity, &steely_cpu_affinity);
	if (!cpumask_empty(&set) && !cpumask_test_cpu(cpu, &set))
		cpu = cpumask_first(&set);

	return cpu;
}
EXPORT_SYMBOL_GPL(xnclock_get_default_cpu);

#endif /* !CONFIG_SMP */

#ifdef CONFIG_STEELY_STATS

static struct xnvfile_directory timerlist_vfroot;

static struct xnvfile_snapshot_ops timerlist_ops;

struct vfile_clock_priv {
	struct xntimer *curr;
};

struct vfile_clock_data {
	int cpu;
	unsigned int scheduled;
	unsigned int fired;
	ktime_t timeout;
	ktime_t interval;
	unsigned long status;
	char name[XNOBJECT_NAME_LEN];
};

static int timerlist_rewind(struct xnvfile_snapshot_iterator *it)
{
	struct vfile_clock_priv *priv = xnvfile_iterator_priv(it);
	struct xnclock *clock = xnvfile_priv(it->vfile);

	if (list_empty(&clock->timerq))
		return -ESRCH;

	priv->curr = list_first_entry(&clock->timerq, struct xntimer, next_stat);

	return clock->nrtimers;
}

static int timerlist_next(struct xnvfile_snapshot_iterator *it, void *data)
{
	struct vfile_clock_priv *priv = xnvfile_iterator_priv(it);
	struct xnclock *clock = xnvfile_priv(it->vfile);
	struct vfile_clock_data *p = data;
	struct xntimer *timer;

	if (priv->curr == NULL)
		return 0;

	timer = priv->curr;
	if (list_is_last(&timer->next_stat, &clock->timerq))
		priv->curr = NULL;
	else
		priv->curr = list_entry(timer->next_stat.next,
					struct xntimer, next_stat);

	if (clock == &nkclock && xnstat_counter_get(&timer->scheduled) == 0)
		return VFILE_SEQ_SKIP;

	p->cpu = xnsched_cpu(xntimer_sched(timer));
	p->scheduled = xnstat_counter_get(&timer->scheduled);
	p->fired = xnstat_counter_get(&timer->fired);
	p->timeout = xntimer_get_timeout(timer);
	p->interval = xntimer_interval(timer);
	p->status = timer->status;
	knamecpy(p->name, timer->name);

	return 1;
}

static int timerlist_show(struct xnvfile_snapshot_iterator *it, void *data)
{
	struct vfile_clock_data *p = data;
	char timeout_buf[]  = "-         ";
	char interval_buf[] = "-         ";
	char hit_buf[32];

	if (p == NULL)
		xnvfile_printf(it,
			       "%-3s  %-20s  %-10s  %-10s  %s\n",
			       "CPU", "SCHED/SHOT", "TIMEOUT",
			       "INTERVAL", "NAME");
	else {
		if (p->status & XNTIMER_RUNNING)
			xntimer_format_time(p->timeout, timeout_buf,
					    sizeof(timeout_buf));
		if (p->status & XNTIMER_PERIODIC)
			xntimer_format_time(p->interval, interval_buf,
					    sizeof(interval_buf));
		ksformat(hit_buf, sizeof(hit_buf), "%u/%u",
			 p->scheduled, p->fired);
		xnvfile_printf(it,
			       "%-3u  %-20s  %-10s  %-10s  %s\n",
			       p->cpu, hit_buf, timeout_buf,
			       interval_buf, p->name);
	}

	return 0;
}

static struct xnvfile_snapshot_ops timerlist_ops = {
	.rewind = timerlist_rewind,
	.next = timerlist_next,
	.show = timerlist_show,
};

static void init_timerlist_proc(struct xnclock *clock)
{
	memset(&clock->timer_vfile, 0, sizeof(clock->timer_vfile));
	clock->timer_vfile.privsz = sizeof(struct vfile_clock_priv);
	clock->timer_vfile.datasz = sizeof(struct vfile_clock_data);
	clock->timer_vfile.tag = &clock->timer_revtag;
	clock->timer_vfile.ops = &timerlist_ops;

	xnvfile_init_snapshot(clock->name, &clock->timer_vfile, &timerlist_vfroot);
	xnvfile_priv(&clock->timer_vfile) = clock;
}

static void cleanup_timerlist_proc(struct xnclock *clock)
{
	xnvfile_destroy_snapshot(&clock->timer_vfile);
}

void init_timerlist_root(void)
{
	xnvfile_init_dir("timer", &timerlist_vfroot, &steely_vfroot);
}

void cleanup_timerlist_root(void)
{
	xnvfile_destroy_dir(&timerlist_vfroot);
}

#else  /* !CONFIG_STEELY_STATS */

static inline void init_timerlist_root(void) { }

static inline void cleanup_timerlist_root(void) { }

static inline void init_timerlist_proc(struct xnclock *clock) { }

static inline void cleanup_timerlist_proc(struct xnclock *clock) { }

#endif	/* !CONFIG_STEELY_STATS */

#ifdef CONFIG_STEELY_VFILE

static struct xnvfile_directory clock_vfroot;

static int clock_show(struct xnvfile_regular_iterator *it, void *data)
{
	struct xnclock *clock = xnvfile_priv(it->vfile);
	u64 cycles = xnclock_read_cycles(clock);

	if (clock->id >= 0)	/* External clock, print id. */
		xnvfile_printf(it, "%7s: %d\n", "id", __STEELY_CLOCK_EXT(clock->id));
		
	xnvfile_printf(it, "%7s: irq=%Ld kernel=%Ld user=%Ld\n", "gravity",
		       ktime_to_ns(xnclock_get_gravity(clock, irq)),
		       ktime_to_ns(xnclock_get_gravity(clock, kernel)),
		       ktime_to_ns(xnclock_get_gravity(clock, user)));

	xnclock_print_status(clock, it);

	xnvfile_printf(it, "%7s: %Lu (%.8x %.8x)\n", "cycles",
		       cycles, (u32)(cycles >> 32), (u32)(cycles & -1U));

	return 0;
}

static ssize_t clock_store(struct xnvfile_input *input)
{
	char buf[128], *args = buf, *p;
	struct xnclock_gravity gravity;
	struct xnvfile_regular *vfile;
	struct xnclock *clock;
	unsigned long ns;
	ssize_t nbytes;
	int ret;

	nbytes = xnvfile_get_string(input, buf, sizeof(buf));
	if (nbytes < 0)
		return nbytes;

	vfile = container_of(input->vfile, struct xnvfile_regular, entry);
	clock = xnvfile_priv(vfile);
	gravity = clock->gravity;

	while ((p = strsep(&args, " \t:/,")) != NULL) {
		if (*p == '\0')
			continue;
		ns = simple_strtol(p, &p, 10);
		switch (*p) {
		case 'i':
			gravity.irq = ns;
			break;
		case 'k':
			gravity.kernel = ns;
			break;
		case 'u':
		case '\0':
			gravity.user = ns;
			break;
		default:
			return -EINVAL;
		}
		ret = xnclock_set_gravity(clock, &gravity);
		if (ret)
			return ret;
	}

	return nbytes;
}

static struct xnvfile_regular_ops clock_ops = {
	.show = clock_show,
	.store = clock_store,
};

static void init_clock_proc(struct xnclock *clock)
{
	memset(&clock->vfile, 0, sizeof(clock->vfile));
	clock->vfile.ops = &clock_ops;
	xnvfile_init_regular(clock->name, &clock->vfile, &clock_vfroot);
	xnvfile_priv(&clock->vfile) = clock;
	init_timerlist_proc(clock);
}

static void cleanup_clock_proc(struct xnclock *clock)
{
	cleanup_timerlist_proc(clock);
	xnvfile_destroy_regular(&clock->vfile);
}

void xnclock_init_proc(void)
{
	xnvfile_init_dir("clock", &clock_vfroot, &steely_vfroot);
	init_timerlist_root();
}

void xnclock_cleanup_proc(void)
{
	xnvfile_destroy_dir(&clock_vfroot);
	cleanup_timerlist_root();
}

#else /* !CONFIG_STEELY_VFILE */

static inline void init_clock_proc(struct xnclock *clock) { }

static inline void cleanup_clock_proc(struct xnclock *clock) { }

#endif	/* !CONFIG_STEELY_VFILE */

int xnclock_register(struct xnclock *clock, const struct cpumask *affinity)
{
	struct xntimerdata *tmd;
	int cpu;

	secondary_mode_only();

#ifdef CONFIG_SMP
	/*
	 * A CPU affinity set may be defined for each clock,
	 * enumerating the CPUs which can receive ticks from the
	 * backing clock device.  When given, this set must be a
	 * subset of the real-time CPU set.
	 */
	if (affinity) {
		cpumask_and(&clock->affinity, affinity, &xnsched_realtime_cpus);
		if (cpumask_empty(&clock->affinity))
			return -EINVAL;
	} else	/* No percpu semantics. */
		cpumask_clear(&clock->affinity);
#endif

	/* Allocate the percpu timer queue slot. */
	clock->timerdata = alloc_percpu(struct xntimerdata);
	if (clock->timerdata == NULL)
		return -ENOMEM;

	/*
	 * POLA: init all timer slots for the new clock, although some
	 * of them might remain unused depending on the CPU affinity
	 * of the event source(s). If the clock device has no percpu
	 * semantics, all timers will be queued to slot #0.
	 */
	for_each_online_cpu(cpu) {
		tmd = xnclock_percpu_timerdata(clock, cpu);
		xntimerq_init(&tmd->q);
	}

#ifdef CONFIG_STEELY_STATS
	INIT_LIST_HEAD(&clock->timerq);
#endif /* CONFIG_STEELY_STATS */

	init_clock_proc(clock);

	return 0;
}
EXPORT_SYMBOL_GPL(xnclock_register);

void xnclock_deregister(struct xnclock *clock)
{
	struct xntimerdata *tmd;
	int cpu;

	secondary_mode_only();

	cleanup_clock_proc(clock);

	for_each_online_cpu(cpu) {
		tmd = xnclock_percpu_timerdata(clock, cpu);
		STEELY_BUG_ON(STEELY, !xntimerq_empty(&tmd->q));
		xntimerq_destroy(&tmd->q);
	}

	free_percpu(clock->timerdata);
}
EXPORT_SYMBOL_GPL(xnclock_deregister);

void xnclock_tick(struct xnclock *clock)
{
	struct xnsched *sched = xnsched_current();
	struct xntimer *timer;
	xntimerq_t *timerq;
	xntimerh_t *h;
	ktime_t now;

	atomic_only();

#ifdef CONFIG_SMP
	/*
	 * Some external clock devices may have no percpu semantics,
	 * in which case all timers are queued to slot #0.
	 */
	if (IS_ENABLED(CONFIG_STEELY_EXTCLOCK) &&
	    clock != &nkclock &&
	    !cpumask_test_cpu(xnsched_cpu(sched), &clock->affinity))
		timerq = &xnclock_percpu_timerdata(clock, 0)->q;
	else
#endif
		timerq = &xnclock_this_timerdata(clock)->q;
	
	/*
	 * Optimisation: any local timer reprogramming triggered by
	 * invoked timer handlers can wait until we leave the tick
	 * handler. Use this status flag as hint to xntimer_start().
	 */
	sched->status |= XNINTCK;

	now = xnclock_read_monotonic(clock);
	while ((h = xntimerq_head(timerq)) != NULL) {
		timer = container_of(h, struct xntimer, aplink);
		if (now < xntimerh_date(&timer->aplink))
			break;

		trace_steely_timer_expire(timer);

		xntimer_dequeue(timer, timerq);
		xntimer_account_fired(timer);

		/*
		 * By postponing the propagation of the low-priority
		 * host tick to the interrupt epilogue (see
		 * xnintr_irq_handler()), we save some I-cache, which
		 * translates into precious microsecs on low-end hw.
		 */
		if (unlikely(timer == &sched->htimer)) {
			sched->lflags |= XNHTICK;
			sched->lflags &= ~XNHDEFER;
			/* Proxy tick is always oneshot. */
			continue;
		}

		/* Check for a locked clock state (i.e. ptracing). */
		if (unlikely(nkclock_lock > 0)) {
			if (timer->status & XNTIMER_NOBLCK)
				goto fire;
			if (timer->status & XNTIMER_PERIODIC)
				goto advance;
			/*
			 * We have no period for this blocked timer,
			 * so have it tick again at a reasonably close
			 * date in the future, waiting for the clock
			 * to be unlocked at some point. Since clocks
			 * are blocked when single-stepping into an
			 * application using a debugger, it is fine to
			 * wait for 250 ms for the user to continue
			 * program execution.
			 */
			xntimer_forward(timer, ms_to_ktime(250));
			goto requeue;
		}
	fire:
		timer->handler(timer);
		now = xnclock_read_monotonic(clock);
		timer->status |= XNTIMER_FIRED;
		/*
		 * Only requeue periodic timers which have not been
		 * requeued, stopped or killed.
		 */
		if ((timer->status &
		     (XNTIMER_PERIODIC|XNTIMER_DEQUEUED|XNTIMER_KILLED|XNTIMER_RUNNING)) !=
		    (XNTIMER_PERIODIC|XNTIMER_DEQUEUED|XNTIMER_RUNNING))
			continue;
	advance:
		do {
			timer->periodic_ticks++;
			xntimer_update_date(timer);
		} while (xntimerh_date(&timer->aplink) < now);
	requeue:
#ifdef CONFIG_SMP
		/*
		 * Make sure to pick the right percpu queue, in case
		 * the timer was migrated over its timeout
		 * handler. Since this timer was dequeued,
		 * xntimer_migrate() did not kick the remote CPU, so
		 * we have to do this now if required.
		 */
		if (unlikely(timer->sched != sched)) {
			timerq = xntimer_percpu_queue(timer);
			xntimer_enqueue(timer, timerq);
			if (xntimer_is_heading(timer))
				xnclock_remote_shot(clock, timer->sched);
			continue;
		}
#endif
		xntimer_enqueue(timer, timerq);
	}

	sched->status &= ~XNINTCK;

	xnclock_program_shot(clock, sched);
}
EXPORT_SYMBOL_GPL(xnclock_tick);

void xnclock_stop_timers(struct xnclock *clock)
{
	struct xnsched *sched;
	struct xntimer *timer;
	xntimerq_t *q;
	xntimerh_t *h;
	spl_t s;
	int cpu;

	/* Deactivate all outstanding timers on the clock. */

	xnlock_get_irqsave(&nklock, s);

	for_each_realtime_cpu(cpu) {
		sched = xnsched_struct(cpu);
		q = &xnclock_percpu_timerdata(clock, cpu)->q;
		while (!xntimerq_empty(q)) {
			h = xntimerq_head(q);
			timer = container_of(h, struct xntimer, aplink);
			if (STEELY_WARN_ON(STEELY, timer->status & XNTIMER_DEQUEUED))
				continue;
			__xntimer_deactivate(timer);
		}
	}

	xnlock_put_irqrestore(&nklock, s);
}

#define do_ext_clock(__clock_id, __handler, __ret, __args...)	\
({								\
	struct xnclock *__clock;				\
	int __val = 0, __nr;					\
	spl_t __s;						\
								\
	if (!__STEELY_CLOCK_EXT_P(__clock_id))			\
		__val = -EINVAL;				\
	else {							\
		__nr = __STEELY_CLOCK_EXT_INDEX(__clock_id);	\
		xnlock_get_irqsave(&nklock, __s);		\
		if (!test_bit(__nr, steely_clock_extids)) {	\
			xnlock_put_irqrestore(&nklock, __s);	\
			__val = -EINVAL;			\
		} else {					\
			__clock = external_clocks[__nr];	\
			(__ret) = xnclock_ ## __handler(__clock, ##__args); \
			xnlock_put_irqrestore(&nklock, __s);	\
		}						\
	}							\
	__val;							\
})

int __steely_clock_getres(clockid_t clock_id, struct timespec *ts)
{
	ktime_t res;
	int ret;

	switch (clock_id) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
	case CLOCK_MONOTONIC_RAW:
		*ts = ns_to_timespec(1);
		break;
	default:
		ret = do_ext_clock(clock_id, get_resolution, res);
		if (ret)
			return ret;
		*ts = ktime_to_timespec(res);
	}

	trace_steely_clock_getres(clock_id, ts);

	return 0;
}

STEELY_SYSCALL(clock_getres, current,
	       (clockid_t clock_id, struct timespec __user *u_ts))
{
	struct timespec ts;
	int ret;

	ret = __steely_clock_getres(clock_id, &ts);
	if (ret)
		return ret;

	if (u_ts && steely_copy_to_user(u_ts, &ts, sizeof(ts)))
		return -EFAULT;

	trace_steely_clock_getres(clock_id, &ts);

	return 0;
}

int __steely_clock_gettime(clockid_t clock_id, struct timespec *ts)
{
	ktime_t t;
	int ret;

	switch (clock_id) {
	case CLOCK_REALTIME:
		*ts = ktime_to_timespec(xnclock_read_realtime(&nkclock));
		break;
	case CLOCK_MONOTONIC:
		*ts = ktime_to_timespec(xnclock_read_monotonic(&nkclock));
		break;
	default:
		ret = do_ext_clock(clock_id, read_monotonic, t);
		if (ret)
			return ret;
		*ts = ktime_to_timespec(t);
	}

	trace_steely_clock_gettime(clock_id, ts);

	return 0;
}

STEELY_SYSCALL(clock_gettime, current,
	       (clockid_t clock_id, struct timespec __user *u_ts))
{
	struct timespec ts;
	int ret;

	ret = __steely_clock_gettime(clock_id, &ts);
	if (ret)
		return ret;

	if (steely_copy_to_user(u_ts, &ts, sizeof(*u_ts)))
		return -EFAULT;

	trace_steely_clock_gettime(clock_id, &ts);

	return 0;
}

int __steely_clock_settime(clockid_t clock_id, const struct timespec *ts)
{
	int _ret, ret = 0;
	ktime_t now;
	spl_t s;

	if ((unsigned long)ts->tv_nsec >= ONE_BILLION)
		return -EINVAL;

	switch (clock_id) {
	case CLOCK_REALTIME:
		xnlock_get_irqsave(&nklock, s);
		now = xnclock_read_realtime(&nkclock);
		xnclock_adjust(&nkclock, ktime_sub(timespec_to_ktime(*ts), now));
		xnlock_put_irqrestore(&nklock, s);
		break;
	default:
		_ret = do_ext_clock(clock_id, set_time, ret, ts);
		if (_ret || ret)
			return _ret ?: ret;
	}

	trace_steely_clock_settime(clock_id, ts);

	return 0;
}

STEELY_SYSCALL(clock_settime, current,
	       (clockid_t clock_id, const struct timespec __user *u_ts))
{
	struct timespec ts;

	if (steely_copy_from_user(&ts, u_ts, sizeof(ts)))
		return -EFAULT;

	return __steely_clock_settime(clock_id, &ts);
}

int __steely_clock_nanosleep(clockid_t clock_id, int flags,
			     const struct timespec *rqt,
			     struct timespec *rmt)
{
	struct restart_block *restart;
	struct steely_thread *cur;
	ktime_t timeout, rem;
	int ret = 0;
	spl_t s;

	trace_steely_clock_nanosleep(clock_id, flags, rqt);

	if (clock_id != CLOCK_MONOTONIC &&
	    clock_id != CLOCK_REALTIME)
		return -EOPNOTSUPP;

	if (rqt->tv_sec < 0)
		return -EINVAL;

	if ((unsigned long)rqt->tv_nsec >= ONE_BILLION)
		return -EINVAL;

	if (flags & ~TIMER_ABSTIME)
		return -EINVAL;

	cur = steely_current_thread();

	if (xnthread_test_localinfo(cur, XNSYSRST)) {
		xnthread_clear_localinfo(cur, XNSYSRST);
		restart = &current->restart_block;
		if (restart->fn != steely_restart_syscall_placeholder) {
			if (rmt) {
				xnlock_get_irqsave(&nklock, s);
				rem = xntimer_get_timeout_stopped(&cur->rtimer);
				xnlock_put_irqrestore(&nklock, s);
				*rmt = ktime_to_timespec(ktime_to_ns(rem) > 1 ? rem : 0);
			}
			return -EINTR;
		}
		timeout = restart->nanosleep.expires;
	} else
		timeout = timespec_to_ktime(*rqt);

	xnlock_get_irqsave(&nklock, s);

	xnthread_suspend(cur, XNDELAY, ktime_add_ns(timeout, 1),
			 clock_flag(flags, clock_id), NULL);

	if (xnthread_test_info(cur, XNBREAK)) {
		if (signal_pending(current)) {
			restart = &current->restart_block;
			restart->nanosleep.expires =
				(flags & TIMER_ABSTIME) ? timeout :
				    xntimer_get_timeout_stopped(&cur->rtimer);
			xnlock_put_irqrestore(&nklock, s);
			restart->fn = steely_restart_syscall_placeholder;

			xnthread_set_localinfo(cur, XNSYSRST);

			return -ERESTARTSYS;
		}

		if (flags == 0 && rmt) {
			rem = xntimer_get_timeout_stopped(&cur->rtimer);
			xnlock_put_irqrestore(&nklock, s);
			*rmt = ktime_to_timespec(ktime_to_ns(rem) > 1 ? rem : 0);
		} else
			xnlock_put_irqrestore(&nklock, s);

		return -EINTR;
	}

	xnlock_put_irqrestore(&nklock, s);

	return ret;
}

STEELY_SYSCALL(clock_nanosleep, primary,
	       (clockid_t clock_id, int flags,
		const struct timespec __user *u_rqt,
		struct timespec __user *u_rmt))
{
	struct timespec rqt, rmt, *rmtp = NULL;
	int ret;

	if (u_rmt)
		rmtp = &rmt;

	if (steely_copy_from_user(&rqt, u_rqt, sizeof(rqt)))
		return -EFAULT;

	ret = __steely_clock_nanosleep(clock_id, flags, &rqt, rmtp);
	if (ret == -EINTR && flags == 0 && rmtp) {
		if (steely_copy_to_user(u_rmt, rmtp, sizeof(*u_rmt)))
			return -EFAULT;
	}

	return ret;
}

int steely_clock_register(struct xnclock *clock,
			  const struct cpumask *affinity,
			  clockid_t *clk_id)
{
	int ret, nr;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	nr = find_first_zero_bit(steely_clock_extids, STEELY_MAX_EXTCLOCKS);
	if (nr >= STEELY_MAX_EXTCLOCKS) {
		xnlock_put_irqrestore(&nklock, s);
		return -EAGAIN;
	}

	/*
	 * CAUTION: a bit raised in steely_clock_extids means that the
	 * corresponding entry in external_clocks[] is valid. The
	 * converse assumption is NOT true.
	 */
	__set_bit(nr, steely_clock_extids);
	external_clocks[nr] = clock;

	xnlock_put_irqrestore(&nklock, s);

	ret = xnclock_register(clock, affinity);
	if (ret)
		return ret;

	clock->id = nr;
	*clk_id = __STEELY_CLOCK_EXT(clock->id);

	trace_steely_clock_register(clock->name, *clk_id);

	return 0;
}
EXPORT_SYMBOL_GPL(steely_clock_register);

void steely_clock_deregister(struct xnclock *clock)
{
	trace_steely_clock_deregister(clock->name, clock->id);
	clear_bit(clock->id, steely_clock_extids);
	smp_mb__after_atomic();
	external_clocks[clock->id] = NULL;
	xnclock_deregister(clock);
}
EXPORT_SYMBOL_GPL(steely_clock_deregister);

struct xnclock *steely_clock_find(clockid_t clock_id)
{
	struct xnclock *clock = ERR_PTR(-EINVAL);
	spl_t s;
	int nr;

	if (clock_id == CLOCK_MONOTONIC ||
	    clock_id == CLOCK_REALTIME)
		return &nkclock;
	
	if (__STEELY_CLOCK_EXT_P(clock_id)) {
		nr = __STEELY_CLOCK_EXT_INDEX(clock_id);
		xnlock_get_irqsave(&nklock, s);
		if (test_bit(nr, steely_clock_extids))
			clock = external_clocks[nr];
		xnlock_put_irqrestore(&nklock, s);
	}

	return clock;
}
EXPORT_SYMBOL_GPL(steely_clock_find);

int __init xnclock_init(void)
{
	xnclock_core_init();

	return 0;
}

void __init xnclock_cleanup(void)
{
	xnclock_core_cleanup();
}
