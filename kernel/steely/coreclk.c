/*
 * Copyright (C) 2016 Philippe Gerum <rpm@xenomai.org>.
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
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/clockchips.h>
#include <linux/tick.h>
#include <linux/irqdomain.h>
#include <linux/ktime.h>
#include <linux/irq_pipeline.h>
#include <linux/slab.h>
#include <steely/sched.h>
#include <steely/timer.h>
#include <steely/intr.h>
#include <steely/clock.h>
#include <steely/coreclk.h>
#include <steely/arith.h>
#include <asm/steely/calibration.h>
#include <trace/events/steely-core.h>

unsigned int nkclock_lock;

/* Core clock source frequency. */
static unsigned long long core_clock_freq;

static inline xnstat_exectime_t *switch_stats(struct xnsched *sched);

/*
 * This is our high-precision clock tick device, which operates the
 * best rated clock event device taken over from the kernel. A head
 * stage handler forwards tick events to our clock management core.
 */
struct core_tick_device {
	u32 mult;
	u32 shift;
	struct clock_event_device *real_device;
};

static DEFINE_PER_CPU(struct core_tick_device, clock_cpu_device);

static int proxy_set_next_ktime(ktime_t expires,
				struct clock_event_device *proxy_ced)
{
	struct xnsched *sched;
	int64_t delta;
	int ret;
	spl_t s;

	delta = ktime_to_ns(ktime_sub(expires, ktime_get()));
	if (delta <= 0)
		delta = 1;

	xnlock_get_irqsave(&nklock, s);
	sched = xnsched_current();
	ret = xntimer_start(&sched->htimer, delta, XN_INFINITE, XN_RELATIVE);
	xnlock_put_irqrestore(&nklock, s);

	return ret ? -ETIME : 0;
}

static inline void calc_mult_shift(struct core_tick_device *ctd,
				   struct clock_event_device *real_ced)
{
	u32 timer_freq;
	u64 sec;
	
	timer_freq = (1000000000ULL * real_ced->mult) >> real_ced->shift;

	/* Same logic as clockevents_config(). */

	sec = real_ced->max_delta_ticks;
	do_div(sec, timer_freq);
	if (!sec)
		sec = 1;
	else if (sec > 600 && real_ced->max_delta_ticks > UINT_MAX)
		sec = 600;

	clocks_calc_mult_shift(&ctd->mult, &ctd->shift,
			       core_clock_freq, timer_freq, sec);
}

static void proxy_device_register(struct clock_event_device *proxy_ced,
				  struct clock_event_device *real_ced)
{
	struct core_tick_device *ctd = this_cpu_ptr(&clock_cpu_device);

	ctd->real_device = real_ced;

	/*
	 * Calculate the scaling values for converting clock source
	 * ticks we receive in xnclock_core_set_next_event() to timer
	 * ticks we should pass to the real device's set_next_event()
	 * handler.
	 *
	 * Hopefully, at some point we will get rid of this conversion
	 * by having the Steely timers express timeouts in nanoseconds
	 * internally.
	 */
	if ((real_ced->features & CLOCK_EVT_FEAT_KTIME) == 0)
		calc_mult_shift(ctd, real_ced);
	
	proxy_ced->features |= CLOCK_EVT_FEAT_KTIME;
	proxy_ced->set_next_ktime = proxy_set_next_ktime;
	proxy_ced->set_next_event = NULL;
	proxy_ced->rating = real_ced->rating + 1;
	proxy_ced->min_delta_ns = 1;
	proxy_ced->max_delta_ns = KTIME_MAX;
	proxy_ced->min_delta_ticks = 1;
	proxy_ced->max_delta_ticks = ULONG_MAX;
	clockevents_register_device(proxy_ced);
}

static void proxy_device_unregister(struct clock_event_device *proxy_ced,
				    struct clock_event_device *real_ced)
{
	struct core_tick_device *ctd = this_cpu_ptr(&clock_cpu_device);

	ctd->real_device = NULL;
}

/*
 * This is our high-precision clock tick handler. We only have two
 * possible callers, each of them may only run over a CPU which is a
 * member of the real-time set:
 *
 * - our HRTIMER_IPI handler, such IPI is directed to members of our
 * real-time CPU set exclusively.
 *
 * - our core_clock_event_handler() routine. The IRQ pipeline
 * guarantees that such handler always runs over a CPU which is a
 * member of the CPU set passed to enable_clock_devices() (i.e. our
 * real-time CPU set).
 */
static void core_clock_tick_handler(unsigned int irq)
{
	struct xnsched *sched = xnsched_current();
	xnstat_exectime_t *prev;

	STEELY_BUG_ON(STEELY, !xnsched_supported_cpu(xnsched_cpu(sched)));

	prev = switch_stats(sched);

	trace_steely_clock_entry(irq);

	++sched->inesting;
	sched->lflags |= XNINIRQ;

	xnlock_get(&nklock);
	xnclock_tick(&nkclock);
	xnlock_put(&nklock);

	/* Make sure to release the clock IRQ before rescheduling. */
	release_irq(irq);

	trace_steely_clock_exit(irq);
	xnstat_exectime_switch(sched, prev);

	if (--sched->inesting == 0) {
		sched->lflags &= ~XNINIRQ;
		xnsched_run();
		sched = xnsched_current();
	}
	/*
	 * If the core clock interrupt preempted a real-time thread,
	 * any transition to the root thread has already triggered a
	 * host tick propagation from xnsched_run(), so at this point,
	 * we only need to propagate the host tick in case the
	 * interrupt preempted the root thread.
	 */
	if ((sched->lflags & XNHTICK) &&
	    xnthread_test_state(sched->curr, XNROOT))
		xnclock_core_notify_root(sched);
}

static void core_clock_event_handler(struct clock_event_device *real_ced)
{
	core_clock_tick_handler(real_ced->irq);
}

static void xnclock_core_set_next_event(unsigned long cdelay) /* in clock ticks, hw IRQs off */
{
	struct core_tick_device *ctd = raw_cpu_ptr(&clock_cpu_device);
	struct clock_event_device *real_ced = ctd->real_device;
	unsigned long long tdelay;
	ktime_t nsdelay;

	if (real_ced->features & CLOCK_EVT_FEAT_KTIME) {
		nsdelay = ns_to_ktime(xnclock_core_ticks_to_ns(cdelay));
		real_ced->set_next_ktime(nsdelay, real_ced);
		return;
	}

	/*
	 * Caution: depending on the underlying device, the original
	 * set_next_event() handler may want to track the in-flight
	 * requests, so don't bypass it via manual IRQ injection
	 * directly into the pipeline, ever.
	 */
	tdelay = ((unsigned long long)cdelay * ctd->mult) >> ctd->shift;
	tdelay = min((unsigned long)tdelay, real_ced->max_delta_ticks);
	tdelay = max((unsigned long)tdelay, real_ced->min_delta_ticks);
	if (real_ced->set_next_event((unsigned long)tdelay, real_ced))
		real_ced->set_next_event(real_ced->min_delta_ticks, real_ced);
}

#ifdef CONFIG_STEELY_STATS
static inline xnstat_exectime_t *switch_stats(struct xnsched *sched)
{
	struct xnirqstat *statp;
	xnstat_exectime_t *prev;

	statp = xnstat_percpu_data;
	prev = xnstat_exectime_switch(sched, &statp->account);
	xnstat_counter_inc(&statp->hits);

	return prev;
}

#else	/* !CONFIG_STEELY_STATS */
static inline xnstat_exectime_t *switch_stats(struct xnsched *sched)
{
	return NULL;
}
#endif	/* CONFIG_STEELY_STATS */

void xnclock_core_notify_root(struct xnsched *sched) /* hw IRQs off. */
{
	/*
	 * A proxy clock event device is active on this CPU, make it
	 * tick asap when the host kernel resumes; this will honour a
	 * previous set_next_ktime() request received from the kernel
	 * we have carried out using our core timing services.
	 */
	sched->lflags &= ~XNHTICK;
	tick_notify_proxy();
}

#ifdef CONFIG_SMP

static irqreturn_t core_clock_ipi_handler(int irq, void *dev_id)
{
	core_clock_tick_handler(irq);

	return IRQ_HANDLED;
}

#endif

static struct proxy_tick_ops proxy_ops = {
	.register_device = proxy_device_register,
	.unregister_device = proxy_device_unregister,
	.handle_event = core_clock_event_handler,
};

int xnclock_core_takeover(void)
{
	struct timeval tv;
	xnticks_t now;
#ifdef CONFIG_STEELY_WATCHDOG
	struct xnsched *sched;
	int cpu;
	spl_t s;
#endif
	int ret;

	if (core_clock_freq == 0) {
		WARN(1, "high-resolution clock not configured");
		return -ENODEV;
	}

	do_gettimeofday(&tv);
	now = tv.tv_sec * 1000000000ULL + tv.tv_usec * 1000;
	nkclock.wallclock_offset = now - xnclock_read_monotonic(&nkclock);

#ifdef CONFIG_SMP
	ret = request_percpu_irq_flags(IPIPE_HRTIMER_IPI,
				       core_clock_ipi_handler,
				       "Steely timer IPI", IRQF_PIPELINED,
				       &steely_machine_cpudata);
	if (ret)
		return ret;
#endif

#ifdef CONFIG_STEELY_STATS
	xnintr_init(&nktimer, "Core timer", -1, NULL, 0);
#endif /* CONFIG_STEELY_STATS */

	/*
	 * CAUTION:
	 *
	 * - Steely timers may be started only _after_ the proxy clock
	 * device has been set up for the target CPU.
	 *
	 * - do not hold any lock across calls to
	 * xnclock_core_takeover().
	 *
	 * - tick_install_proxy() guarantees that the real clock
	 * device supports oneshot mode, or fails.
	 */
	ret = tick_install_proxy(&proxy_ops, &xnsched_realtime_cpus);
	if (ret) {
#ifdef CONFIG_SMP
		free_percpu_irq(IPIPE_HRTIMER_IPI,
				&steely_machine_cpudata);
#endif
		return ret;
	}

#ifdef CONFIG_STEELY_WATCHDOG
	xnlock_get_irqsave(&nklock, s);
	for_each_realtime_cpu(cpu) {
		sched = xnsched_struct(cpu);
		xntimer_start(&sched->wdtimer, 1000000000UL,
			      1000000000UL, XN_RELATIVE);
		xnsched_reset_watchdog(sched);
	}
	xnlock_put_irqrestore(&nklock, s);
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(xnclock_core_takeover);

void xnclock_core_release(void)
{
	tick_uninstall_proxy(&proxy_ops, &xnsched_realtime_cpus);
#ifdef CONFIG_SMP
	free_percpu_irq(IPIPE_HRTIMER_IPI, &steely_machine_cpudata);
#endif
#ifdef CONFIG_STEELY_STATS
	xnintr_destroy(&nktimer);
#endif /* CONFIG_STEELY_STATS */
	/*
	 * When the kernel is swapping clock event devices on behalf
	 * of enable_clock_devices(), it may end up calling
	 * program_timer() via the synthetic device's
	 * ->set_next_event() handler for resuming the host timer.
	 * Therefore, no timer should remain queued before
	 * enable_clock_devices() is called, or unpleasant hangs may
	 * happen if the host timer is not at front of the queue. You
	 * have been warned.
	 */
	xnclock_stop_timers(&nkclock);
}
EXPORT_SYMBOL_GPL(xnclock_core_release);

#ifdef XNARCH_HAVE_LLMULSHFT

static unsigned int tsc_scale, tsc_shift;

#ifdef XNARCH_HAVE_NODIV_LLIMD

static struct xnarch_u32frac tsc_frac;

long long xnclock_core_ns_to_ticks(long long ns)
{
	return xnarch_nodiv_llimd(ns, tsc_frac.frac, tsc_frac.integ);
}

#else /* !XNARCH_HAVE_NODIV_LLIMD */

long long xnclock_core_ns_to_ticks(long long ns)
{
	return xnarch_llimd(ns, 1 << tsc_shift, tsc_scale);
}

#endif /* !XNARCH_HAVE_NODIV_LLIMD */

xnsticks_t xnclock_core_ticks_to_ns(xnsticks_t ticks)
{
	return xnarch_llmulshft(ticks, tsc_scale, tsc_shift);
}

xnsticks_t xnclock_core_ticks_to_ns_rounded(xnsticks_t ticks)
{
	unsigned int shift = tsc_shift - 1;
	return (xnarch_llmulshft(ticks, tsc_scale, shift) + 1) / 2;
}

#else  /* !XNARCH_HAVE_LLMULSHFT */

xnsticks_t xnclock_core_ticks_to_ns(xnsticks_t ticks)
{
	return xnarch_llimd(ticks, 1000000000, core_clock_freq);
}

xnsticks_t xnclock_core_ticks_to_ns_rounded(xnsticks_t ticks)
{
	return (xnarch_llimd(ticks, 1000000000, core_clock_freq/2) + 1) / 2;
}

xnsticks_t xnclock_core_ns_to_ticks(xnsticks_t ns)
{
	return xnarch_llimd(ns, core_clock_freq, 1000000000);
}

#endif /* !XNARCH_HAVE_LLMULSHFT */

EXPORT_SYMBOL_GPL(xnclock_core_ticks_to_ns);
EXPORT_SYMBOL_GPL(xnclock_core_ticks_to_ns_rounded);
EXPORT_SYMBOL_GPL(xnclock_core_ns_to_ticks);

void xnclock_core_local_shot(struct xnsched *sched)
{
	struct xntimerdata *tmd;
	struct xntimer *timer;
	xnsticks_t delay;
	xntimerh_t *h;

	/*
	 * Do not reprogram locally when inside the tick handler -
	 * will be done on exit anyway. Also exit if there is no
	 * pending timer.
	 */
	if (sched->status & XNINTCK)
		return;

	tmd = xnclock_this_timerdata(&nkclock);
	h = xntimerq_head(&tmd->q);
	if (h == NULL)
		return;

	/*
	 * Here we try to defer the host tick heading the timer queue,
	 * so that it does not preempt a real-time activity uselessly,
	 * in two cases:
	 *
	 * 1) a rescheduling is pending for the current CPU. We may
	 * assume that a real-time thread is about to resume, so we
	 * want to move the host tick out of the way until the host
	 * kernel resumes, unless there is no other outstanding
	 * timers.
	 *
	 * 2) the current thread is running in primary mode, in which
	 * case we may also defer the host tick until the host kernel
	 * resumes.
	 *
	 * The host tick deferral is cleared whenever Steely is about
	 * to yield control to the host kernel (see ___xnsched_run()),
	 * or a timer with an earlier timeout date is scheduled,
	 * whichever comes first.
	 */
	sched->lflags &= ~XNHDEFER;
	timer = container_of(h, struct xntimer, aplink);
	if (unlikely(timer == &sched->htimer)) {
		if (xnsched_resched_p(sched) ||
		    !xnthread_test_state(sched->curr, XNROOT)) {
			h = xntimerq_second(&tmd->q, h);
			if (h) {
				sched->lflags |= XNHDEFER;
				timer = container_of(h, struct xntimer, aplink);
			}
		}
	}

	delay = xntimerh_date(&timer->aplink) - xnclock_core_read_raw();
	if (delay < 0)
		delay = 0;
	else if (delay > UINT_MAX)
		delay = UINT_MAX;

	trace_steely_clock_shot(delay);

	xnclock_core_set_next_event(delay);
}

bool dovetail_enter_idle(void)	/* root stage, hard_irqs_disabled() */
{
	struct xnsched *sched = xnsched_current();

	/*
	 * Should we allow CPUIDLE to enter the idle state on the
	 * current CPU? We can figure this out easily by checking the
	 * host tick deferral flag (XNHDEFER): if set, then we have
	 * more urgent tasks to deliver than processing host ticks, so
	 * we don't want to enter the idle state.
	 */
	
	return !!(sched->lflags & XNHDEFER);
}

#ifdef CONFIG_SMP
void xnclock_core_remote_shot(struct xnsched *sched)
{
	irq_pipeline_send_remote(IPIPE_HRTIMER_IPI,
				 cpumask_of(xnsched_cpu(sched)));
}
#endif

xnticks_t xnclock_core_read_monotonic(void)
{
	return xnclock_core_ticks_to_ns(xnclock_core_read_raw());
}
EXPORT_SYMBOL_GPL(xnclock_core_read_monotonic);

static int set_core_clock_gravity(struct xnclock *clock,
				  const struct xnclock_gravity *p)
{
	nkclock.gravity = *p;

	return 0;
}

static void reset_core_clock_gravity(struct xnclock *clock)
{
	struct xnclock_gravity gravity;

	xnarch_get_latencies(&gravity);
	if (gravity.kernel == 0)
		gravity.kernel = gravity.user;
	set_core_clock_gravity(clock, &gravity);
}

#ifdef CONFIG_STEELY_VFILE

void print_core_clock_status(struct xnclock *clock,
			     struct xnvfile_regular_iterator *it)
{
	struct core_tick_device *ctd = this_cpu_ptr(&clock_cpu_device);
	const char *tm_status, *wd_status = "";

	tm_status = nkclock_lock > 0 ? "locked" : "on";
#ifdef CONFIG_STEELY_WATCHDOG
	wd_status = "+watchdog";
#endif /* CONFIG_STEELY_WATCHDOG */

	xnvfile_printf(it, "timer device: %s\n",
		       ctd->real_device ?
		       ctd->real_device->name : "(inactive)");
	xnvfile_printf(it, "%7s: %s%s\n", "status", tm_status, wd_status);
}

#endif

struct xnclock nkclock = {
	.name = "coreclk",
	.resolution = 1,	/* nanosecond. */
	.ops = {
		.set_gravity = set_core_clock_gravity,
		.reset_gravity = reset_core_clock_gravity,
#ifdef CONFIG_STEELY_VFILE
		.print_status = print_core_clock_status,
#endif
	},
	.id = -1,
};
EXPORT_SYMBOL_GPL(nkclock);

int __init xnclock_core_init(unsigned long long freq)
{
	core_clock_freq = freq;
#ifdef XNARCH_HAVE_LLMULSHFT
	xnarch_init_llmulshft(1000000000, freq, &tsc_scale, &tsc_shift);
#ifdef XNARCH_HAVE_NODIV_LLIMD
	xnarch_init_u32frac(&tsc_frac, 1 << tsc_shift, tsc_scale);
#endif
#endif
	xnclock_reset_gravity(&nkclock);
	xnclock_register(&nkclock, &xnsched_realtime_cpus);

	return 0;
}

void __init xnclock_core_cleanup(void)
{
	xnclock_deregister(&nkclock);
}
