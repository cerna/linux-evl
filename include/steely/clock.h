/*
 * Copyright (C) 2006,2007 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_KERNEL_CLOCK_H
#define _STEELY_KERNEL_CLOCK_H

#include <steely/list.h>
#include <steely/vfile.h>
#include <steely/coreclk.h>

struct xnsched;
struct xntimerdata;

struct xnclock_gravity {
	unsigned long irq;
	unsigned long kernel;
	unsigned long user;
};

struct xnclock {
	/* (ns) */
	xnticks_t wallclock_offset;
	/* (ns) */
	xnticks_t resolution;
	/* (raw clock ticks). */
	struct xnclock_gravity gravity;
	/* Clock name. */
	const char *name;
	struct {
#ifdef CONFIG_STEELY_EXTCLOCK
		xnticks_t (*read_raw)(struct xnclock *clock);
		xnticks_t (*read_monotonic)(struct xnclock *clock);
		int (*set_time)(struct xnclock *clock,
				const struct timespec *ts);
		xnsticks_t (*ns_to_ticks)(struct xnclock *clock,
					  xnsticks_t ns);
		xnsticks_t (*ticks_to_ns)(struct xnclock *clock,
					  xnsticks_t ticks);
		xnsticks_t (*ticks_to_ns_rounded)(struct xnclock *clock,
						  xnsticks_t ticks);
		void (*program_local_shot)(struct xnclock *clock,
					   struct xnsched *sched);
		void (*program_remote_shot)(struct xnclock *clock,
					    struct xnsched *sched);
#endif
		int (*set_gravity)(struct xnclock *clock,
				   const struct xnclock_gravity *p);
		void (*reset_gravity)(struct xnclock *clock);
#ifdef CONFIG_STEELY_VFILE
		void (*print_status)(struct xnclock *clock,
				     struct xnvfile_regular_iterator *it);
#endif
	} ops;
	/* Private section. */
	struct xntimerdata *timerdata;
	int id;
#ifdef CONFIG_SMP
	/* Possible CPU affinity of clock beat. */
	struct cpumask affinity;
#endif
#ifdef CONFIG_STEELY_STATS
	struct xnvfile_snapshot timer_vfile;
	struct xnvfile_rev_tag timer_revtag;
	struct list_head timerq;
	int nrtimers;
#endif /* CONFIG_STEELY_STATS */
#ifdef CONFIG_STEELY_VFILE
	struct xnvfile_regular vfile;
#endif
};

int xnclock_register(struct xnclock *clock,
		     const struct cpumask *affinity);

void xnclock_deregister(struct xnclock *clock);

void xnclock_tick(struct xnclock *clock);

void xnclock_adjust(struct xnclock *clock,
		    xnsticks_t delta);

void xnclock_stop_timers(struct xnclock *clock);

#ifdef CONFIG_STEELY_EXTCLOCK

/*
 * Most calls targeting the core clock should allow the compiler to
 * optimize out the alternate branch to non-core clock handlers.
 */

static inline void xnclock_program_shot(struct xnclock *clock,
					struct xnsched *sched)
{
	if (likely(clock == &nkclock))
		xnclock_core_local_shot(sched);
	else if (clock->ops.program_local_shot)
		clock->ops.program_local_shot(clock, sched);
}

static inline void xnclock_remote_shot(struct xnclock *clock,
				       struct xnsched *sched)
{
#ifdef CONFIG_SMP
	if (likely(clock == &nkclock))
		xnclock_core_remote_shot(sched);
	else if (clock->ops.program_remote_shot)
		clock->ops.program_remote_shot(clock, sched);
#endif
}

static inline xnticks_t xnclock_read_raw(struct xnclock *clock)
{
	if (likely(clock == &nkclock))
		return xnclock_core_read_raw();

	return clock->ops.read_raw(clock);
}

static inline xnsticks_t xnclock_ns_to_ticks(struct xnclock *clock,
					     xnsticks_t ns)
{
	if (likely(clock == &nkclock))
		return xnclock_core_ns_to_ticks(ns);

	return clock->ops.ns_to_ticks(clock, ns);
}

static inline xnsticks_t xnclock_ticks_to_ns(struct xnclock *clock,
					     xnsticks_t ticks)
{
	if (likely(clock == &nkclock))
		return xnclock_core_ticks_to_ns(ticks);

	return clock->ops.ticks_to_ns(clock, ticks);
}

static inline xnsticks_t xnclock_ticks_to_ns_rounded(struct xnclock *clock,
						     xnsticks_t ticks)
{
	if (likely(clock == &nkclock))
		return xnclock_core_ticks_to_ns_rounded(ticks);

	return clock->ops.ticks_to_ns_rounded(clock, ticks);
}

static inline xnticks_t xnclock_read_monotonic(struct xnclock *clock)
{
	if (likely(clock == &nkclock))
		return xnclock_core_read_monotonic();

	return clock->ops.read_monotonic(clock);
}

static inline int xnclock_set_time(struct xnclock *clock,
				   const struct timespec *ts)
{
	if (likely(clock == &nkclock))
		return -EINVAL;

	return clock->ops.set_time(clock, ts);
}

#else /* !CONFIG_STEELY_EXTCLOCK */

static inline void xnclock_program_shot(struct xnclock *clock,
					struct xnsched *sched)
{
	xnclock_core_local_shot(sched);
}

static inline void xnclock_remote_shot(struct xnclock *clock,
				       struct xnsched *sched)
{
#ifdef CONFIG_SMP
	xnclock_core_remote_shot(sched);
#endif
}

static inline xnticks_t xnclock_read_raw(struct xnclock *clock)
{
	return xnclock_core_read_raw();
}

static inline xnsticks_t xnclock_ns_to_ticks(struct xnclock *clock,
					     xnsticks_t ns)
{
	return xnclock_core_ns_to_ticks(ns);
}

static inline xnsticks_t xnclock_ticks_to_ns(struct xnclock *clock,
					     xnsticks_t ticks)
{
	return xnclock_core_ticks_to_ns(ticks);
}

static inline xnsticks_t xnclock_ticks_to_ns_rounded(struct xnclock *clock,
						     xnsticks_t ticks)
{
	return xnclock_core_ticks_to_ns_rounded(ticks);
}

static inline xnticks_t xnclock_read_monotonic(struct xnclock *clock)
{
	return xnclock_core_read_monotonic();
}

static inline int xnclock_set_time(struct xnclock *clock,
				   const struct timespec *ts)
{
	/*
	 * There is no way to change the core clock's idea of time.
	 */
	return -EINVAL;
}

#endif /* !CONFIG_STEELY_EXTCLOCK */

#ifdef CONFIG_SMP
int xnclock_get_default_cpu(struct xnclock *clock, int cpu);
#else
static inline int xnclock_get_default_cpu(struct xnclock *clock, int cpu)
{
	return cpu;
}
#endif

static inline xnticks_t xnclock_get_offset(struct xnclock *clock)
{
	return clock->wallclock_offset;
}

static inline xnticks_t xnclock_get_resolution(struct xnclock *clock)
{
	return clock->resolution; /* ns */
}

static inline void xnclock_set_resolution(struct xnclock *clock,
					  xnticks_t resolution)
{
	clock->resolution = resolution; /* ns */
}

static inline int xnclock_set_gravity(struct xnclock *clock,
				      const struct xnclock_gravity *gravity)
{
	if (clock->ops.set_gravity)
		return clock->ops.set_gravity(clock, gravity);

	return -EINVAL;
}

static inline void xnclock_reset_gravity(struct xnclock *clock)
{
	if (clock->ops.reset_gravity)
		clock->ops.reset_gravity(clock);
}

#define xnclock_get_gravity(__clock, __type)  ((__clock)->gravity.__type)

static inline xnticks_t xnclock_read_realtime(struct xnclock *clock)
{
	/*
	 * Return an adjusted value of the monotonic time with the
	 * translated system wallclock offset.
	 */
	return xnclock_read_monotonic(clock) + xnclock_get_offset(clock);
}

xnticks_t xnclock_get_host_time(void);

#ifdef CONFIG_STEELY_VFILE

void xnclock_init_proc(void);

void xnclock_cleanup_proc(void);

static inline void xnclock_print_status(struct xnclock *clock,
					struct xnvfile_regular_iterator *it)
{
	if (clock->ops.print_status)
		clock->ops.print_status(clock, it);
}

#else
static inline void xnclock_init_proc(void) { }
static inline void xnclock_cleanup_proc(void) { }
#endif

void xnclock_update_freq(unsigned long long freq);

int xnclock_init(unsigned long long freq);

void xnclock_cleanup(void);

#endif /* !_STEELY_KERNEL_CLOCK_H */
