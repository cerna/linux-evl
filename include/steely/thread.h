/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 * Copyright Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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
#ifndef _STEELY_THREAD_H
#define _STEELY_THREAD_H

#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/sched/rt.h>
#include <steely/list.h>
#include <steely/stat.h>
#include <steely/timer.h>
#include <steely/registry.h>
#include <steely/schedparam.h>
#include <steely/synch.h>
#include <steely/extension.h>
#include <steely/syscall.h>
#include <uapi/steely/kernel/thread.h>
#include <uapi/steely/signal.h>
#include <uapi/steely/sched.h>
#include <asm/steely/machine.h>
#include <asm/steely/thread.h>

#define XNTHREAD_BLOCK_BITS   (XNSUSP|XNPEND|XNDELAY|XNDORMANT|XNRELAX|XNHELD)
#define XNTHREAD_MODE_BITS    (XNRRB|XNWARN|XNTRAPLB)

struct steely_thread;
struct xnsched;
struct xnselector;
struct xnsched_class;
struct xnsched_tpslot;
struct steely_thread_personality;
struct steely_threadstat;
struct completion;

struct steely_thread_init_attr {
	struct steely_thread_personality *personality;
	struct cpumask affinity;
	int flags;
	const char *name;
};

struct steely_thread_start_attr {
	int mode;
	void (*entry)(void *cookie);
	void *cookie;
};

struct steely_wait_context {
	int posted;
};

struct steely_thread_personality {
	const char *name;
	unsigned int magic;
	int xid;
	atomic_t refcnt;
	struct {
		void *(*attach_process)(void);
		void (*detach_process)(void *arg);
		void (*map_thread)(struct steely_thread *thread);
		struct steely_thread_personality *(*relax_thread)(struct steely_thread *thread);
		struct steely_thread_personality *(*harden_thread)(struct steely_thread *thread);
		struct steely_thread_personality *(*move_thread)(struct steely_thread *thread,
							    int dest_cpu);
		struct steely_thread_personality *(*exit_thread)(struct steely_thread *thread);
		struct steely_thread_personality *(*finalize_thread)(struct steely_thread *thread);
	} ops;
	struct module *module;
};

struct steely_local_hkey {
	/* pthread_t from userland. */
	unsigned long u_pth;
	/* kernel mm context. */
	struct mm_struct *mm;
};

struct steely_sigwait_context {
	struct steely_wait_context wc;
	sigset_t *set;
	struct siginfo *si;
};

struct steely_thread {
	unsigned int magic;

	struct xnarchtcb tcb;	/* Architecture-dependent block */

	__u32 state;		/* Thread state flags */
	__u32 info;		/* Thread information flags */
	__u32 local_info;	/* Local thread information flags */

	struct xnsched *sched;		/* Thread scheduler */
	struct xnsched_class *sched_class; /* Current scheduling class */
	struct xnsched_class *base_class; /* Base scheduling class */

#ifdef CONFIG_STEELY_SCHED_TP
	struct xnsched_tpslot *tps;	/* Current partition slot for TP scheduling */
	struct list_head tp_link;	/* Link in per-sched TP thread queue */
#endif
#ifdef CONFIG_STEELY_SCHED_SPORADIC
	struct xnsched_sporadic_data *pss; /* Sporadic scheduling data. */
#endif
#ifdef CONFIG_STEELY_SCHED_QUOTA
	struct xnsched_quota_group *quota; /* Quota scheduling group. */
	struct list_head quota_expired;
	struct list_head quota_next;
#endif
	struct cpumask affinity;	/* Processor affinity. */

	/* Base priority (before PI/PP boost) */
	int bprio;

	/* Current (effective) priority */
	int cprio;

	/*
	 * Weighted priority (cprio + scheduling class weight).
	 */
	int wprio;

	int lock_count;	/* Scheduler lock count. */

	/*
	 * Thread holder in xnsched run queue. Ordered by
	 * thread->cprio.
	 */
	struct list_head rlink;

	/*
	 * Thread holder in xnsynch pendq. Prioritized by
	 * thread->cprio + scheduling class weight.
	 */
	struct list_head plink;

	/* Thread holder in global queue. */
	struct list_head glink;

	/*
	 * List of xnsynch owned by this thread which cause a priority
	 * boost due to one of the following reasons:
	 *
	 * - they are currently claimed by other thread(s) when
	 * enforcing the priority inheritance protocol (XNSYNCH_PI).
	 *
	 * - they require immediate priority ceiling (XNSYNCH_PP).
	 *
	 * This list is ordered by decreasing (weighted) thread
	 * priorities.
	 */
	struct list_head boosters;

	struct xnsynch *wchan;		/* Resource the thread pends on */

	struct xnsynch *wwake;		/* Wait channel the thread was resumed from */

	int res_count;			/* Held resources count */

	struct xntimer rtimer;		/* Resource timer */

	struct xntimer ptimer;		/* Periodic timer */

	ktime_t rrperiod;		/* Allotted round-robin period (ns) */

  	struct steely_wait_context *wcontext;	/* Active wait context. */

	struct {
		xnstat_counter_t ssw;	/* Primary -> secondary mode switch count */
		xnstat_counter_t csw;	/* Context switches (includes secondary -> primary switches) */
		xnstat_counter_t xsc;	/* Xenomai syscalls */
		xnstat_counter_t pf;	/* Number of page faults */
		xnstat_exectime_t account; /* Execution time accounting entity */
		xnstat_exectime_t lastperiod; /* Interval marker for execution time reports */
	} stat;

	struct xnselector *selector;    /* For select. */

	xnhandle_t handle;	/* Handle in registry */

	char name[XNOBJECT_NAME_LEN]; /* Symbolic name of thread */

	void (*entry)(void *cookie); /* Thread entry routine */
	void *cookie;		/* Cookie to pass to the entry routine */

	/*
	 * Thread data visible from userland through a window on the
	 * global heap.
	 */
	struct steely_user_window *u_window;

	struct steely_thread_personality *personality;

	struct completion exited;

#ifdef CONFIG_STEELY_DEBUG
	const char *exe_path;	/* Executable path */
	u32 proghash;		/* Hash value for exe_path */
#endif

	struct steely_extref extref;
	struct steely_process *process;
	struct list_head next;	/* in steely_thread_list */

	/* Signal management. */
	sigset_t sigpending;
	struct list_head sigqueues[_NSIG]; /* in steely_sigpending */
	struct xnsynch sigwait;
	struct list_head signext;

	/* Monitor wait object and link holder. */
	struct xnsynch monitor_synch;
	struct list_head monitor_link;

	struct steely_local_hkey hkey;
};

static inline int xnthread_get_state(const struct steely_thread *thread)
{
	return thread->state;
}

static inline int xnthread_test_state(struct steely_thread *thread, int bits)
{
	return thread->state & bits;
}

static inline void xnthread_set_state(struct steely_thread *thread, int bits)
{
	thread->state |= bits;
}

static inline void xnthread_clear_state(struct steely_thread *thread, int bits)
{
	thread->state &= ~bits;
}

static inline int xnthread_test_info(struct steely_thread *thread, int bits)
{
	return thread->info & bits;
}

static inline void xnthread_set_info(struct steely_thread *thread, int bits)
{
	thread->info |= bits;
}

static inline void xnthread_clear_info(struct steely_thread *thread, int bits)
{
	thread->info &= ~bits;
}

static inline int xnthread_test_localinfo(struct steely_thread *curr, int bits)
{
	return curr->local_info & bits;
}

static inline void xnthread_set_localinfo(struct steely_thread *curr, int bits)
{
	curr->local_info |= bits;
}

static inline void xnthread_clear_localinfo(struct steely_thread *curr, int bits)
{
	curr->local_info &= ~bits;
}

static inline struct xnarchtcb *xnthread_archtcb(struct steely_thread *thread)
{
	return &thread->tcb;
}

static inline int xnthread_base_priority(const struct steely_thread *thread)
{
	return thread->bprio;
}

static inline int xnthread_current_priority(const struct steely_thread *thread)
{
	return thread->cprio;
}

static inline struct task_struct *xnthread_host_task(struct steely_thread *thread)
{
	return xnthread_archtcb(thread)->core.host_task;
}

static inline pid_t xnthread_host_pid(struct steely_thread *thread)
{
	if (xnthread_test_state(thread, XNROOT))
		return 0;

	return task_pid_nr(xnthread_host_task(thread));
}

#define xnthread_for_each_booster(__pos, __thread)		\
	list_for_each_entry(__pos, &(__thread)->boosters, next)

#define xnthread_for_each_booster_safe(__pos, __tmp, __thread)	\
	list_for_each_entry_safe(__pos, __tmp, &(__thread)->boosters, next)

#define xnthread_run_handler(__t, __h, __a...)				\
	do {								\
		struct steely_thread_personality *__p__ = (__t)->personality;	\
		if ((__p__)->ops.__h)					\
			(__p__)->ops.__h(__t, ##__a);			\
	} while (0)
	
#define xnthread_run_handler_stack(__t, __h, __a...)			\
	do {								\
		struct steely_thread_personality *__p__ = (__t)->personality;	\
		do {							\
			if ((__p__)->ops.__h == NULL)			\
				break;					\
			__p__ = (__p__)->ops.__h(__t, ##__a);		\
		} while (__p__);					\
	} while (0)
	
static inline
struct steely_wait_context *xnthread_get_wait_context(struct steely_thread *thread)
{
	return thread->wcontext;
}

static inline
int xnthread_register(struct steely_thread *thread, const char *name)
{
	return xnregistry_enter(name, thread, &thread->handle, NULL);
}

static inline
struct steely_thread *xnthread_lookup(xnhandle_t threadh)
{
	struct steely_thread *thread = xnregistry_lookup(threadh, NULL);
	return thread && thread->handle == xnhandle_get_index(threadh) ? thread : NULL;
}

static inline void xnthread_sync_window(struct steely_thread *thread)
{
	if (thread->u_window) {
		thread->u_window->state = thread->state;
		thread->u_window->info = thread->info;
	}
}

static inline
void xnthread_clear_sync_window(struct steely_thread *thread, int state_bits)
{
	if (thread->u_window) {
		thread->u_window->state = thread->state & ~state_bits;
		thread->u_window->info = thread->info;
	}
}

static inline
void xnthread_set_sync_window(struct steely_thread *thread, int state_bits)
{
	if (thread->u_window) {
		thread->u_window->state = thread->state | state_bits;
		thread->u_window->info = thread->info;
	}
}

static inline int normalize_priority(int prio)
{
	return prio < MAX_RT_PRIO ? prio : MAX_RT_PRIO - 1;
}

int __xnthread_init(struct steely_thread *thread,
		    const struct steely_thread_init_attr *attr,
		    struct xnsched *sched,
		    struct xnsched_class *sched_class,
		    const union xnsched_policy_param *sched_param);

void __xnthread_test_cancel(struct steely_thread *curr);

void __xnthread_cleanup(struct steely_thread *curr);

void __xnthread_discard(struct steely_thread *thread);

static inline struct steely_thread *steely_current_thread(void)
{
	return dovetail_current_state()->thread;
}

static inline struct steely_thread *xnthread_from_task(struct task_struct *p)
{
	return dovetail_task_state(p)->thread;
}

static inline void xnthread_test_cancel(void)
{
	struct steely_thread *curr = steely_current_thread();

	if (curr && xnthread_test_info(curr, XNCANCELD))
		__xnthread_test_cancel(curr);
}

static inline
void xnthread_complete_wait(struct steely_wait_context *wc)
{
	wc->posted = 1;
}

static inline
int xnthread_wait_complete_p(struct steely_wait_context *wc)
{
	return wc->posted;
}

void xnthread_init_shadow_tcb(struct steely_thread *thread);

void xnthread_init_root_tcb(struct steely_thread *thread);

void xnthread_deregister(struct steely_thread *thread);

char *xnthread_format_status(unsigned long status,
			     char *buf, int size);

int xnthread_set_clock(struct steely_thread *thread,
		       struct xnclock *newclock);

ktime_t xnthread_get_timeout(struct steely_thread *thread,
			     ktime_t base);

ktime_t xnthread_get_period(struct steely_thread *thread);

void xnthread_prepare_wait(struct steely_wait_context *wc);

int xnthread_init(struct steely_thread *thread,
		  const struct steely_thread_init_attr *attr,
		  struct xnsched_class *sched_class,
		  const union xnsched_policy_param *sched_param);

int xnthread_start(struct steely_thread *thread,
		   const struct steely_thread_start_attr *attr);

int xnthread_set_mode(int clrmask,
		      int setmask);

void xnthread_suspend(struct steely_thread *thread,
		      int mask,
		      ktime_t timeout,
		      xntmode_t timeout_mode,
		      struct xnsynch *wchan);

void xnthread_resume(struct steely_thread *thread,
		     int mask);

int xnthread_unblock(struct steely_thread *thread);

int xnthread_set_periodic(struct steely_thread *thread,
			  ktime_t idate,
			  xntmode_t timeout_mode,
			  ktime_t period);

int xnthread_wait_period(unsigned long *overruns_r);

int xnthread_set_slice(struct steely_thread *thread,
		       ktime_t quantum);

void xnthread_cancel(struct steely_thread *thread);

int xnthread_join(struct steely_thread *thread, bool uninterruptible);

int xnthread_harden(void);

void xnthread_relax(int notify, int reason);

void __xnthread_kick(struct steely_thread *thread);

void xnthread_kick(struct steely_thread *thread);

void __xnthread_demote(struct steely_thread *thread);

void xnthread_demote(struct steely_thread *thread);

void xnthread_signal(struct steely_thread *thread,
		     int sig, int arg);

void xnthread_pin_initial(struct steely_thread *thread);

void xnthread_call_mayday(struct steely_thread *thread, int reason);

static inline void xnthread_get_resource(struct steely_thread *curr)
{
	if (xnthread_test_state(curr, XNWEAK|XNDEBUG))
		curr->res_count++;
}

static inline int xnthread_put_resource(struct steely_thread *curr)
{
	if (xnthread_test_state(curr, XNWEAK) ||
	    IS_ENABLED(CONFIG_STEELY_DEBUG_MUTEX_SLEEP)) {
		if (unlikely(curr->res_count == 0)) {
			if (xnthread_test_state(curr, XNWARN))
				xnthread_signal(curr, SIGDEBUG,
						SIGDEBUG_RESCNT_IMBALANCE);
			return -EPERM;
		}
		curr->res_count--;
	}

	return 0;
}

static inline void xnthread_commit_ceiling(struct steely_thread *curr)
{
	if (curr->u_window->pp_pending)
		xnsynch_commit_ceiling(curr);
}

#ifdef CONFIG_SMP
int xnthread_migrate(int cpu);

void xnthread_migrate_passive(struct steely_thread *thread,
			      struct xnsched *sched);
#else

static inline int xnthread_migrate(int cpu)
{
	return cpu ? -EINVAL : 0;
}

static inline void xnthread_migrate_passive(struct steely_thread *thread,
					    struct xnsched *sched)
{ }

#endif

int __xnthread_set_schedparam(struct steely_thread *thread,
			      struct xnsched_class *sched_class,
			      const union xnsched_policy_param *sched_param);

int xnthread_set_schedparam(struct steely_thread *thread,
			    struct xnsched_class *sched_class,
			    const union xnsched_policy_param *sched_param);

int xnthread_killall(int grace, int mask);

void __xnthread_propagate_schedparam(struct steely_thread *curr);

static inline void xnthread_propagate_schedparam(struct steely_thread *curr)
{
	if (xnthread_test_info(curr, XNSCHEDP))
		__xnthread_propagate_schedparam(curr);
}

extern struct steely_thread_personality steely_personality;

#ifdef CONFIG_STEELY_EXTENSION

int steely_thread_extend(struct steely_extension *ext,
			 void *priv);

void steely_thread_restrict(void);

static inline
int steely_thread_extended_p(const struct steely_thread *thread,
			     const struct steely_extension *ext)
{
	return thread->extref.extension == ext;
}

#else /* !CONFIG_STEELY_EXTENSION */

static inline
int steely_thread_extended_p(const struct steely_thread *thread,
			     const struct steely_extension *ext)
{
	return 0;
}

#endif /* !CONFIG_STEELY_EXTENSION */

int __steely_thread_create(unsigned long pth, int policy,
			   struct sched_param_ex __user *u_param,
			   int xid, __u32 __user *u_winoff);

int __steely_thread_setschedparam_ex(struct steely_thread *thread, int policy,
				     const struct sched_param_ex *param_ex);

int steely_thread_setschedparam_ex(unsigned long pth,
				   int policy,
				   const struct sched_param_ex *param_ex,
				   __u32 __user *u_winoff,
				   int __user *u_promoted);

int steely_thread_getschedparam_ex(unsigned long pth,
				   int *policy_r,
				   struct sched_param_ex *param_ex);

int __steely_thread_getschedparam_ex(struct steely_thread *thread,
				     int *policy_r,
				     struct sched_param_ex *param_ex);

struct steely_thread *steely_thread_find(pid_t pid);

struct steely_thread *steely_thread_find_local(pid_t pid);

struct steely_thread *steely_thread_lookup(unsigned long pth);

STEELY_SYSCALL_DECL(thread_create,
		    (unsigned long pth, int policy,
		     struct sched_param_ex __user *u_param,
		     int xid, __u32 __user *u_winoff));

struct steely_thread *
steely_thread_shadow(struct task_struct *p,
		     struct steely_local_hkey *lhkey,
		     __u32 __user *u_winoff);

STEELY_SYSCALL_DECL(thread_setmode,
		    (int clrmask, int setmask, int __user *u_mode_r));

STEELY_SYSCALL_DECL(thread_setname,
		    (unsigned long pth, const char __user *u_name));

STEELY_SYSCALL_DECL(thread_kill, (unsigned long pth, int sig));

STEELY_SYSCALL_DECL(thread_join, (unsigned long pth));

STEELY_SYSCALL_DECL(thread_getpid, (unsigned long pth));

STEELY_SYSCALL_DECL(thread_getstat,
		    (pid_t pid, struct steely_threadstat __user *u_stat));

STEELY_SYSCALL_DECL(thread_setschedparam_ex,
		    (unsigned long pth,
		     int policy,
		     const struct sched_param_ex __user *u_param,
		     __u32 __user *u_winoff,
		     int __user *u_promoted));

STEELY_SYSCALL_DECL(thread_getschedparam_ex,
		    (unsigned long pth,
		     int __user *u_policy,
		     struct sched_param_ex __user *u_param));

#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED  1

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

#define PTHREAD_INHERIT_SCHED  0
#define PTHREAD_EXPLICIT_SCHED 1

#define PTHREAD_MUTEX_NORMAL     0
#define PTHREAD_MUTEX_RECURSIVE  1
#define PTHREAD_MUTEX_ERRORCHECK 2
#define PTHREAD_MUTEX_DEFAULT    0

/*
 * pthread_mutexattr_t and pthread_condattr_t fit on 32 bits, for
 * compatibility with libc.
 */

/* The following definitions are copied from linuxthread pthreadtypes.h. */
struct _pthread_fastlock {
	long int __status;
	int __spinlock;
};

typedef struct {
	struct _pthread_fastlock __c_lock;
	long __c_waiting;
	char __padding[48 - sizeof (struct _pthread_fastlock)
		       - sizeof (long) - sizeof (long long)];
	long long __align;
} pthread_cond_t;

enum {
	PTHREAD_PRIO_NONE,
	PTHREAD_PRIO_INHERIT,
	PTHREAD_PRIO_PROTECT
};

typedef struct {
	int __m_reserved;
	int __m_count;
	long __m_owner;
	int __m_kind;
	struct _pthread_fastlock __m_lock;
} pthread_mutex_t;

#endif /* !_STEELY_THREAD_H */
