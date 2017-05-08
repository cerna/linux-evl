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
#ifndef _STEELY_CLOCK_H
#define _STEELY_CLOCK_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/cpumask.h>
#include <steely/list.h>
#include <steely/vfile.h>
#include <steely/coreclk.h>
#include <steely/syscall.h>
#include <uapi/steely/time.h>

struct xnsched;
struct xntimerdata;

struct xnclock_gravity {
	ktime_t irq;
	ktime_t kernel;
	ktime_t user;
};

struct xnclock {
	/* (ns) */
	ktime_t resolution;
	/* Anticipation values for timer shots. */
	struct xnclock_gravity gravity;
	/* Clock name. */
	const char *name;
	struct {
#ifdef CONFIG_STEELY_EXTCLOCK
		u64 (*read_cycles)(struct xnclock *clock);
		ktime_t (*read_monotonic)(struct xnclock *clock);
		ktime_t (*read_realtime)(struct xnclock *clock);
		int (*set_time)(struct xnclock *clock,
				const struct timespec *ts);
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
		    ktime_t delta);

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

static inline u64 xnclock_read_cycles(struct xnclock *clock)
{
	if (likely(clock == &nkclock))
		return xnclock_core_read_cycles();

	return clock->ops.read_cycles(clock);
}

static inline ktime_t xnclock_read_monotonic(struct xnclock *clock)
{
	if (likely(clock == &nkclock))
		return xnclock_core_read_monotonic();

	return clock->ops.read_monotonic(clock);
}

static inline ktime_t xnclock_read_realtime(struct xnclock *clock)
{
	if (likely(clock == &nkclock))
		return xnclock_core_read_realtime();

	return clock->ops.read_realtime(clock);
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

static inline ktime_t xnclock_read_cycles(struct xnclock *clock)
{
	return xnclock_core_read_cycles();
}

static inline ktime_t xnclock_read_monotonic(struct xnclock *clock)
{
	return xnclock_core_read_monotonic();
}

static inline ktime_t xnclock_read_realtime(struct xnclock *clock)
{
	return xnclock_core_read_realtime();
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

static inline ktime_t xnclock_get_resolution(struct xnclock *clock)
{
	return clock->resolution;
}

static inline void xnclock_set_resolution(struct xnclock *clock,
					  ktime_t resolution)
{
	clock->resolution = resolution;
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

int xnclock_init(void);

void xnclock_cleanup(void);

int __steely_clock_getres(clockid_t clock_id,
			  struct timespec *ts);

int __steely_clock_gettime(clockid_t clock_id,
			   struct timespec *ts);

int __steely_clock_settime(clockid_t clock_id,
			   const struct timespec *ts);

int __steely_clock_nanosleep(clockid_t clock_id, int flags,
			     const struct timespec *rqt,
			     struct timespec *rmt);

STEELY_SYSCALL_DECL(clock_getres,
		    (clockid_t clock_id, struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(clock_gettime,
		    (clockid_t clock_id, struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(clock_settime,
		    (clockid_t clock_id, const struct timespec __user *u_ts));

STEELY_SYSCALL_DECL(clock_nanosleep,
		    (clockid_t clock_id, int flags,
		     const struct timespec __user *u_rqt,
		     struct timespec __user *u_rmt));

int steely_clock_register(struct xnclock *clock,
			  const struct cpumask *affinity,
			  clockid_t *clk_id);

void steely_clock_deregister(struct xnclock *clock);

struct xnclock *steely_clock_find(clockid_t clock_id);

extern DECLARE_BITMAP(steely_clock_extids, STEELY_MAX_EXTCLOCKS);

#endif /* !_STEELY_CLOCK_H */
