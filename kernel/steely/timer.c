/*
 * Copyright (C) 2001,2002,2003,2007,2012 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
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
#include <linux/sched.h>
#include <steely/sched.h>
#include <steely/thread.h>
#include <steely/timer.h>
#include <steely/intr.h>
#include <steely/clock.h>
#include <steely/trace.h>
#include <steely/arith.h>
#include <asm/div64.h>
#include <trace/events/steely-core.h>

bool xntimer_is_heading(struct xntimer *timer)
{
	struct xnsched *sched = timer->sched;
	xntimerq_t *q;
	xntimerh_t *h;

	q = xntimer_percpu_queue(timer);
	h = xntimerq_head(q);
	if (h == &timer->aplink)
		return true;

	if (sched->lflags & XNHDEFER) {
		h = xntimerq_second(q, h);
		if (h == &timer->aplink)
			return true;
	}

	return false;
}

static void program_timer(struct xntimer *timer, xntimerq_t *q)
{
	xntimer_enqueue(timer, q);
	if (xntimer_is_heading(timer)) {
		struct xnsched *sched = xntimer_sched(timer);
		struct xnclock *clock = xntimer_clock(timer);
		if (sched != xnsched_current())
			xnclock_remote_shot(clock, sched);
		else
			xnclock_program_shot(clock, sched);
	}
}

int xntimer_start(struct xntimer *timer,
		  ktime_t value, ktime_t interval,
		  xntmode_t mode)
{
	struct xnclock *clock = xntimer_clock(timer);
	xntimerq_t *q = xntimer_percpu_queue(timer);
	ktime_t date, now, lateness, gravity;
	int ret = 0;

	trace_steely_timer_start(timer, value, interval, mode);

	if ((timer->status & XNTIMER_DEQUEUED) == 0)
		xntimer_dequeue(timer, q);

	now = xnclock_read_monotonic(clock);

	timer->status &= ~(XNTIMER_REALTIME | XNTIMER_FIRED | XNTIMER_PERIODIC);
	switch (mode) {
	case XN_RELATIVE:
		if (ktime_to_ns(value) < 0)
			return -ETIMEDOUT;
		date = ktime_add(value,  now);
		break;
	case XN_REALTIME:
		timer->status |= XNTIMER_REALTIME;
		value = ktime_sub(value, xnclock_get_offset(clock));
		/* fall through */
	default: /* XN_ABSOLUTE || XN_REALTIME */
		date = value;
		if (date <= now) {
			if (timeout_infinite(interval))
				return -ETIMEDOUT;
			/*
			 * We are late on arrival for the first
			 * delivery, wait for the next shot on the
			 * periodic time line.
			 */
			lateness = ktime_sub(now, date);
			date = ktime_add_ns(date,
				    ktime_to_ns(interval) *
				    (ktime_divns(lateness, ktime_to_ns(interval)) + 1));
		}
		break;
	}

	/*
	 * To cope with the basic system latency, we apply a clock
	 * gravity value, which is the amount of time expressed in
	 * clock ticks by which we should anticipate the shot for any
	 * outstanding timer. The gravity value varies with the type
	 * of context the timer wakes up, i.e. irq handler, kernel or
	 * user thread.
	 */
	gravity = xntimer_gravity(timer);
	xntimerh_date(&timer->aplink) = ktime_sub(date, gravity);
	if (now >= xntimerh_date(&timer->aplink))
		xntimer_forward(timer, gravity / 2);

	timer->interval = XN_INFINITE;
	if (!timeout_infinite(interval)) {
		timer->interval = interval;
		timer->start_date = date;
		timer->pexpect_ticks = 0;
		timer->periodic_ticks = 0;
		timer->status |= XNTIMER_PERIODIC;
	}

	timer->status |= XNTIMER_RUNNING;
	program_timer(timer, q);

	return ret;
}
EXPORT_SYMBOL_GPL(xntimer_start);

bool __xntimer_deactivate(struct xntimer *timer)
{
	xntimerq_t *q = xntimer_percpu_queue(timer);
	bool heading = true;

	if (!(timer->status & XNTIMER_DEQUEUED)) {
		heading = xntimer_is_heading(timer);
		xntimer_dequeue(timer, q);
	}

	timer->status &= ~(XNTIMER_FIRED|XNTIMER_RUNNING);

	return heading;
}

void __xntimer_stop(struct xntimer *timer)
{
	struct xnclock *clock = xntimer_clock(timer);
	struct xnsched *sched;
	bool heading;

	trace_steely_timer_stop(timer);
	heading = __xntimer_deactivate(timer);
	sched = xntimer_sched(timer);
	/*
	 * If we removed the heading timer, reprogram the next shot if
	 * any. If the timer was running on another CPU, let it tick.
	 */
	if (heading && sched == xnsched_current())
		xnclock_program_shot(clock, sched);
}
EXPORT_SYMBOL_GPL(__xntimer_stop);

ktime_t xntimer_get_date(struct xntimer *timer)
{
	if (!xntimer_running_p(timer))
		return XN_INFINITE;

	return xntimer_expiry(timer);
}
EXPORT_SYMBOL_GPL(xntimer_get_date);

ktime_t __xntimer_get_timeout(struct xntimer *timer)
{
	struct xnclock *clock;
	ktime_t expiry, now;

	clock = xntimer_clock(timer);
	now = xnclock_read_monotonic(clock);
	expiry = xntimer_expiry(timer);
	if (expiry <= now)
		return ktime_set(0, 1);  /* Will elapse shortly. */

	return ktime_sub(expiry, now);
}
EXPORT_SYMBOL_GPL(__xntimer_get_timeout);

void __xntimer_init(struct xntimer *timer,
		    struct xnclock *clock,
		    void (*handler)(struct xntimer *timer),
		    struct xnsched *sched,
		    int flags)
{
	spl_t s __maybe_unused;
	int cpu;

#ifdef CONFIG_STEELY_EXTCLOCK
	timer->clock = clock;
#endif
	xntimerh_init(&timer->aplink);
	xntimerh_date(&timer->aplink) = XN_INFINITE;
	xntimer_set_priority(timer, XNTIMER_STDPRIO);
	timer->status = (XNTIMER_DEQUEUED|(flags & XNTIMER_INIT_MASK));
	timer->handler = handler;
	timer->interval = XN_INFINITE;
	/*
	 * If the CPU the caller is affine to does not receive timer
	 * events, or no affinity was specified (i.e. sched == NULL),
	 * assign the timer to the first possible CPU which can
	 * receive interrupt events from the clock device backing this
	 * timer.
	 *
	 * If the clock device has no percpu semantics,
	 * xnclock_get_default_cpu() makes the timer always affine to
	 * CPU0 unconditionally.
	 */
	cpu = xnclock_get_default_cpu(clock, sched ? xnsched_cpu(sched) : 0);
	timer->sched = xnsched_struct(cpu);

#ifdef CONFIG_STEELY_STATS
#ifdef CONFIG_STEELY_EXTCLOCK
	timer->tracker = clock;
#endif
	ksformat(timer->name, XNOBJECT_NAME_LEN, "%d/%s",
		 task_pid_nr(current), current->comm);
	xntimer_reset_stats(timer);
	xnlock_get_irqsave(&nklock, s);
	list_add_tail(&timer->next_stat, &clock->timerq);
	clock->nrtimers++;
	xnvfile_touch(&clock->timer_vfile);
	xnlock_put_irqrestore(&nklock, s);
#endif /* CONFIG_STEELY_STATS */
}
EXPORT_SYMBOL_GPL(__xntimer_init);

void xntimer_set_gravity(struct xntimer *timer, int gravity)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	timer->status &= ~XNTIMER_GRAVITY_MASK;
	timer->status |= gravity;
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xntimer_set_gravity);

#ifdef CONFIG_STEELY_EXTCLOCK

#ifdef CONFIG_STEELY_STATS

static void switch_clock_tracking(struct xntimer *timer,
				  struct xnclock *newclock)
{
	struct xnclock *oldclock = timer->tracker;

	list_del(&timer->next_stat);
	oldclock->nrtimers--;
	xnvfile_touch(&oldclock->timer_vfile);
	list_add_tail(&timer->next_stat, &newclock->timerq);
	newclock->nrtimers++;
	xnvfile_touch(&newclock->timer_vfile);
	timer->tracker = newclock;
}

void xntimer_switch_tracking(struct xntimer *timer,
			     struct xnclock *newclock)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	switch_clock_tracking(timer, newclock);
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xntimer_switch_tracking);

#else

static inline
void switch_clock_tracking(struct xntimer *timer,
			   struct xnclock *newclock)
{ }

#endif /* CONFIG_STEELY_STATS */

static inline void __xntimer_set_clock(struct xntimer *timer,
				       struct xnclock *newclock)
{
#ifdef CONFIG_SMP
	int cpu;
	/*
	 * Make sure the timer lives on a CPU the backing clock device
	 * ticks on.
	 */
	cpu = xnclock_get_default_cpu(newclock, xnsched_cpu(timer->sched));
	xntimer_migrate(timer, xnsched_struct(cpu));
#endif
	switch_clock_tracking(timer, newclock);
}

void xntimer_set_clock(struct xntimer *timer,
		       struct xnclock *newclock)
{
	xntimer_stop(timer);
	timer->clock = newclock;
	__xntimer_set_clock(timer, newclock);
}

#endif /* CONFIG_STEELY_EXTCLOCK */

void xntimer_destroy(struct xntimer *timer)
{
	struct xnclock *clock __maybe_unused = xntimer_clock(timer);
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	xntimer_stop(timer);
	timer->status |= XNTIMER_KILLED;
	timer->sched = NULL;
#ifdef CONFIG_STEELY_STATS
	list_del(&timer->next_stat);
	clock->nrtimers--;
	xnvfile_touch(&clock->timer_vfile);
#endif /* CONFIG_STEELY_STATS */
	xnlock_put_irqrestore(&nklock, s);
}
EXPORT_SYMBOL_GPL(xntimer_destroy);

#ifdef CONFIG_SMP

void __xntimer_migrate(struct xntimer *timer, struct xnsched *sched)
{				/* nklocked, IRQs off */
	struct xnclock *clock;
	xntimerq_t *q;

	if (sched == timer->sched)
		return;

	trace_steely_timer_migrate(timer, xnsched_cpu(sched));

	/*
	 * This assertion triggers when the timer is migrated to a CPU
	 * for which we do not expect any clock events/IRQs from the
	 * associated clock device. If so, the timer would never fire
	 * since clock ticks would never happen on that CPU.
	 *
	 * A clock device with an empty affinity mask has no percpu
	 * semantics, which disables the check.
	 */
	STEELY_WARN_ON_SMP(STEELY,
			 !cpumask_empty(&xntimer_clock(timer)->affinity) &&
			 !cpumask_test_cpu(xnsched_cpu(sched),
					   &xntimer_clock(timer)->affinity));

	if (timer->status & XNTIMER_RUNNING) {
		xntimer_stop(timer);
		timer->sched = sched;
		clock = xntimer_clock(timer);
		q = xntimer_percpu_queue(timer);
		xntimer_enqueue(timer, q);
		if (xntimer_is_heading(timer))
			xnclock_remote_shot(clock, sched);
	} else
		timer->sched = sched;
}
EXPORT_SYMBOL_GPL(__xntimer_migrate);

bool xntimer_set_sched(struct xntimer *timer,
		       struct xnsched *sched)
{
	/*
	 * We may deny the request if the target CPU does not receive
	 * any event from the clock device backing the timer, or the
	 * clock device has no percpu semantics.
	 */
	if (cpumask_test_cpu(xnsched_cpu(sched),
			     &xntimer_clock(timer)->affinity)) {
		xntimer_migrate(timer, sched);
		return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(xntimer_set_sched);

#endif /* CONFIG_SMP */

unsigned long xntimer_get_overruns(struct xntimer *timer, ktime_t now)
{
	unsigned long overruns = 0;
	ktime_t delta;
	xntimerq_t *q;

	delta = ktime_sub(now, xntimer_pexpect(timer));
	if (unlikely(delta >= timer->interval)) {
		overruns = ktime_divns(delta, ktime_to_ns(timer->interval));
		timer->pexpect_ticks += overruns;
		if (xntimer_running_p(timer)) {
			STEELY_BUG_ON(STEELY, (timer->status &
				    (XNTIMER_DEQUEUED|XNTIMER_PERIODIC))
				    != XNTIMER_PERIODIC);
				q = xntimer_percpu_queue(timer);
			xntimer_dequeue(timer, q);
			while (xntimerh_date(&timer->aplink) < now) {
				timer->periodic_ticks++;
				xntimer_update_date(timer);
			}
			program_timer(timer, q);
		}
	}

	timer->pexpect_ticks++;

	return overruns;
}
EXPORT_SYMBOL_GPL(xntimer_get_overruns);

char *xntimer_format_time(ktime_t t, char *buf, size_t bufsz)
{
	int len = (int)bufsz;
	unsigned int ms, us;
	unsigned long sec;
	char *p = buf;
	uint32_t rem;
	uint64_t ns;

	ns = ktime_to_ns(t);
	if (ns == 0 && bufsz > 1) {
		strcpy(buf, "-");
		return buf;
	}

	rem = do_div(ns, ONE_BILLION);
	sec = (unsigned long)ns;
	us = rem / 1000;
	ms = us / 1000;
	us %= 1000;

	if (sec) {
		p += ksformat(p, bufsz, "%lus", sec);
		len = bufsz - (p - buf);
	}

	if (len > 0 && (ms || (sec && us))) {
		p += ksformat(p, bufsz - (p - buf), "%ums", ms);
		len = bufsz - (p - buf);
	}

	if (len > 0 && us)
		p += ksformat(p, bufsz - (p - buf), "%uus", us);

	return buf;
}
EXPORT_SYMBOL_GPL(xntimer_format_time);

#ifdef CONFIG_STEELY_TIMER_RBTREE

static inline bool xntimerh_is_lt(xntimerh_t *left, xntimerh_t *right)
{
	return left->date < right->date
		|| (left->date == right->date && left->prio > right->prio);
}

void xntimerq_insert(xntimerq_t *q, xntimerh_t *holder)
{
	struct rb_node **new = &q->root.rb_node, *parent = NULL;

	if (!q->head)
		q->head = holder;
	else if (xntimerh_is_lt(holder, q->head)) {
		parent = &q->head->link;
		new = &parent->rb_left;
		q->head = holder;
	} else while (*new) {
		xntimerh_t *i = container_of(*new, xntimerh_t, link);

		parent = *new;
		if (xntimerh_is_lt(holder, i))
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&holder->link, parent, new);
	rb_insert_color(&holder->link, &q->root);
}

#endif
