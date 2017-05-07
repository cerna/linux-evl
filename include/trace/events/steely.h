/*
 * Copyright (C) 2014 Jan Kiszka <jan.kiszka@siemens.com>.
 * Copyright (C) 2014 Philippe Gerum <rpm@xenomai.org>.
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
#if !defined(_TRACE_STEELY_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_STEELY_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM steely

#include <linux/mman.h>
#include <linux/sched.h>
#include <steely/posix/mutex.h>
#include <steely/posix/cond.h>
#include <steely/posix/mqueue.h>
#include <steely/posix/event.h>
#include <steely/posix/sem.h>
#include <linux/tracepoint.h>

struct rtdm_fd;
struct rtdm_event;
struct rtdm_sem;
struct rtdm_mutex;
struct xnthread;
struct rtdm_device;
struct rtdm_dev_context;
struct _rtdm_mmap_request;

DECLARE_EVENT_CLASS(thread_event,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(name, thread->name)
		__field(pid_t, pid)
		__field(unsigned long, state)
		__field(unsigned long, info)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__assign_str(name, thread->name);
		__entry->state = thread->state;
		__entry->info = thread->info;
		__entry->pid = xnthread_host_pid(thread);
	),

	TP_printk("thread=%p(%s) pid=%d state=0x%lx info=0x%lx",
		  __entry->thread, __get_str(name), __entry->pid,
		  __entry->state, __entry->info)
);

DECLARE_EVENT_CLASS(synch_wait_event,
	TP_PROTO(struct xnsynch *synch, struct xnthread *thread),
	TP_ARGS(synch, thread),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(name, thread->name)
		__field(struct xnsynch *, synch)
	),

	TP_fast_assign(
		__entry->thread	= thread;
		__assign_str(name, thread->name);
		__entry->synch = synch;
	),

	TP_printk("synch=%p thread=%p(%s)",
		  __entry->synch, __entry->thread, __get_str(name))
);

DECLARE_EVENT_CLASS(synch_post_event,
	TP_PROTO(struct xnsynch *synch),
	TP_ARGS(synch),

	TP_STRUCT__entry(
		__field(struct xnsynch *, synch)
	),

	TP_fast_assign(
		__entry->synch = synch;
	),

	TP_printk("synch=%p", __entry->synch)
);

DECLARE_EVENT_CLASS(irq_event,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq),

	TP_STRUCT__entry(
		__field(unsigned int, irq)
	),

	TP_fast_assign(
		__entry->irq = irq;
	),

	TP_printk("irq=%u", __entry->irq)
);

DECLARE_EVENT_CLASS(clock_event,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq),

	TP_STRUCT__entry(
		__field(unsigned int, irq)
	),

	TP_fast_assign(
		__entry->irq = irq;
	),

	TP_printk("clock_irq=%u", __entry->irq)
);

DECLARE_EVENT_CLASS(thread_migrate,
	TP_PROTO(struct xnthread *thread, unsigned int cpu),
	TP_ARGS(thread, cpu),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(name, thread->name)
		__field(unsigned int, cpu)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__assign_str(name, thread->name);
		__entry->cpu = cpu;
	),

	TP_printk("thread=%p(%s) cpu=%u",
		  __entry->thread, __get_str(name), __entry->cpu)
);

DECLARE_EVENT_CLASS(timer_event,
	TP_PROTO(struct xntimer *timer),
	TP_ARGS(timer),

	TP_STRUCT__entry(
		__field(struct xntimer *, timer)
	),

	TP_fast_assign(
		__entry->timer = timer;
	),

	TP_printk("timer=%p", __entry->timer)
);

TRACE_EVENT(steely_schedule,
	TP_PROTO(struct xnsched *sched),
	TP_ARGS(sched),

	TP_STRUCT__entry(
		__field(unsigned long, status)
	),

	TP_fast_assign(
		__entry->status = sched->status;
	),

	TP_printk("status=0x%lx", __entry->status)
);

TRACE_EVENT(steely_schedule_remote,
	TP_PROTO(struct xnsched *sched),
	TP_ARGS(sched),

	TP_STRUCT__entry(
		__field(unsigned long, status)
	),

	TP_fast_assign(
		__entry->status = sched->status;
	),

	TP_printk("status=0x%lx", __entry->status)
);

TRACE_EVENT(steely_switch_context,
	TP_PROTO(struct xnthread *prev, struct xnthread *next),
	TP_ARGS(prev, next),

	TP_STRUCT__entry(
		__field(struct xnthread *, prev)
		__field(struct xnthread *, next)
		__string(prev_name, prev->name)
		__string(next_name, next->name)
	),

	TP_fast_assign(
		__entry->prev = prev;
		__entry->next = next;
		__assign_str(prev_name, prev->name);
		__assign_str(next_name, next->name);
	),

	TP_printk("prev=%p(%s) next=%p(%s)",
		  __entry->prev, __get_str(prev_name),
		  __entry->next, __get_str(next_name))
);

TRACE_EVENT(steely_thread_init,
	TP_PROTO(struct xnthread *thread,
		 const struct xnthread_init_attr *attr,
		 struct xnsched_class *sched_class),
	TP_ARGS(thread, attr, sched_class),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(thread_name, thread->name)
		__string(class_name, sched_class->name)
		__field(unsigned long, flags)
		__field(int, cprio)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__assign_str(thread_name, thread->name);
		__entry->flags = attr->flags;
		__assign_str(class_name, sched_class->name);
		__entry->cprio = thread->cprio;
	),

	TP_printk("thread=%p(%s) flags=0x%lx class=%s prio=%d",
		   __entry->thread, __get_str(thread_name), __entry->flags,
		   __get_str(class_name), __entry->cprio)
);

TRACE_EVENT(steely_thread_suspend,
	TP_PROTO(struct xnthread *thread, unsigned long mask, ktime_t timeout,
		 xntmode_t timeout_mode, struct xnsynch *wchan),
	TP_ARGS(thread, mask, timeout, timeout_mode, wchan),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__field(unsigned long, mask)
		__field(ktime_t, timeout)
		__field(xntmode_t, timeout_mode)
		__field(struct xnsynch *, wchan)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__entry->mask = mask;
		__entry->timeout = timeout;
		__entry->timeout_mode = timeout_mode;
		__entry->wchan = wchan;
	),

	TP_printk("thread=%p mask=0x%lx timeout=%Lu timeout_mode=%d wchan=%p",
		  __entry->thread, __entry->mask,
		  ktime_to_ns(__entry->timeout), __entry->timeout_mode,
		  __entry->wchan)
);

TRACE_EVENT(steely_thread_resume,
	TP_PROTO(struct xnthread *thread, unsigned long mask),
	TP_ARGS(thread, mask),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__field(unsigned long, mask)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__entry->mask = mask;
	),

	TP_printk("thread=%p mask=0x%lx",
		  __entry->thread, __entry->mask)
);

TRACE_EVENT(steely_thread_fault,
	TP_PROTO(struct xnthread *thread, struct dovetail_trap_data *td),
	TP_ARGS(thread, td),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(name, thread->name)
		__field(void *,	ip)
		__field(unsigned int, type)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__assign_str(name, thread->name);
		__entry->ip = (void *)xnarch_fault_pc(td);
		__entry->type = xnarch_fault_trap(td);
	),

	TP_printk("thread=%p(%s) ip=%p type=%x",
		  __entry->thread, __get_str(name), __entry->ip,
		  __entry->type)
);

DEFINE_EVENT(thread_event, steely_thread_start,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_thread_cancel,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_thread_join,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_thread_unblock,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_thread_wait_period,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_thread_missed_period,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_thread_set_mode,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_migrate, steely_thread_migrate,
	TP_PROTO(struct xnthread *thread, unsigned int cpu),
	TP_ARGS(thread, cpu)
);

DEFINE_EVENT(thread_migrate, steely_thread_migrate_passive,
	TP_PROTO(struct xnthread *thread, unsigned int cpu),
	TP_ARGS(thread, cpu)
);

DEFINE_EVENT(thread_event, steely_shadow_gohard,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_watchdog_signal,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_shadow_hardened,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

#define steely_print_relax_reason(reason)				\
	__print_symbolic(reason,					\
			 { SIGDEBUG_UNDEFINED,		"undefined" },	\
			 { SIGDEBUG_MIGRATE_SIGNAL,	"signal" },	\
			 { SIGDEBUG_MIGRATE_SYSCALL,	"syscall" },	\
			 { SIGDEBUG_MIGRATE_FAULT,	"fault" })

TRACE_EVENT(steely_shadow_gorelax,
	TP_PROTO(struct xnthread *thread, int reason),
	TP_ARGS(thread, reason),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__field(int, reason)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__entry->reason = reason;
	),

	TP_printk("thread=%p reason=%s",
		  __entry->thread, steely_print_relax_reason(__entry->reason))
);

DEFINE_EVENT(thread_event, steely_shadow_relaxed,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

DEFINE_EVENT(thread_event, steely_shadow_entry,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

TRACE_EVENT(steely_shadow_map,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(name, thread->name)
		__field(int, prio)
	),

	TP_fast_assign(
		__entry->thread	= thread;
		__assign_str(name, thread->name);
		__entry->prio = xnthread_base_priority(thread);
	),

	TP_printk("thread=%p(%s) prio=%d",
		  __entry->thread, __get_str(name), __entry->prio)
);

DEFINE_EVENT(thread_event, steely_shadow_unmap,
	TP_PROTO(struct xnthread *thread),
	TP_ARGS(thread)
);

TRACE_EVENT(steely_lostage_request,
        TP_PROTO(const char *type, struct task_struct *task),
	TP_ARGS(type, task),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__array(char, comm, TASK_COMM_LEN)
		__field(const char *, type)
	),

	TP_fast_assign(
		__entry->type = type;
		__entry->pid = task_pid_nr(task);
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
	),

	TP_printk("request=%s pid=%d comm=%s",
		  __entry->type, __entry->pid, __entry->comm)
);

TRACE_EVENT(steely_lostage_wakeup,
	TP_PROTO(struct task_struct *task),
	TP_ARGS(task),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__array(char, comm, TASK_COMM_LEN)
	),

	TP_fast_assign(
		__entry->pid = task_pid_nr(task);
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
	),

	TP_printk("pid=%d comm=%s",
		  __entry->pid, __entry->comm)
);

TRACE_EVENT(steely_lostage_signal,
	TP_PROTO(struct task_struct *task, int sig),
	TP_ARGS(task, sig),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__array(char, comm, TASK_COMM_LEN)
		__field(int, sig)
	),

	TP_fast_assign(
		__entry->pid = task_pid_nr(task);
		__entry->sig = sig;
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
	),

	TP_printk("pid=%d comm=%s sig=%d",
		  __entry->pid, __entry->comm, __entry->sig)
);

DEFINE_EVENT(irq_event, steely_irq_entry,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(irq_event, steely_irq_exit,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(irq_event, steely_irq_attach,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(irq_event, steely_irq_detach,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(irq_event, steely_irq_enable,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(irq_event, steely_irq_disable,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(clock_event, steely_clock_entry,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(clock_event, steely_clock_exit,
	TP_PROTO(unsigned int irq),
	TP_ARGS(irq)
);

DEFINE_EVENT(timer_event, steely_timer_stop,
	TP_PROTO(struct xntimer *timer),
	TP_ARGS(timer)
);

DEFINE_EVENT(timer_event, steely_timer_expire,
	TP_PROTO(struct xntimer *timer),
	TP_ARGS(timer)
);

#define steely_print_timer_mode(mode)			\
	__print_symbolic(mode,				\
			 { XN_RELATIVE, "rel" },	\
			 { XN_ABSOLUTE, "abs" },	\
			 { XN_REALTIME, "rt" })

TRACE_EVENT(steely_timer_start,
	TP_PROTO(struct xntimer *timer, ktime_t value, ktime_t interval,
		 xntmode_t mode),
	TP_ARGS(timer, value, interval, mode),

	TP_STRUCT__entry(
		__field(struct xntimer *, timer)
#ifdef CONFIG_STEELY_STATS
		__string(name, timer->name)
#endif
		__field(ktime_t, value)
		__field(ktime_t, interval)
		__field(xntmode_t, mode)
	),

	TP_fast_assign(
		__entry->timer = timer;
#ifdef CONFIG_STEELY_STATS
		__assign_str(name, timer->name);
#endif
		__entry->value = value;
		__entry->interval = interval;
		__entry->mode = mode;
	),

	TP_printk("timer=%p(%s) value=%Lu interval=%Lu mode=%s",
		  __entry->timer,
#ifdef CONFIG_STEELY_STATS
		  __get_str(name),
#else
		  "(anon)",
#endif
		  ktime_to_ns(__entry->value),
		  ktime_to_ns(__entry->interval),
		  steely_print_timer_mode(__entry->mode))
);

#ifdef CONFIG_SMP

TRACE_EVENT(steely_timer_migrate,
	TP_PROTO(struct xntimer *timer, unsigned int cpu),
	TP_ARGS(timer, cpu),

	TP_STRUCT__entry(
		__field(struct xntimer *, timer)
		__field(unsigned int, cpu)
	),

	TP_fast_assign(
		__entry->timer = timer;
		__entry->cpu = cpu;
	),

	TP_printk("timer=%p cpu=%u",
		  __entry->timer, __entry->cpu)
);

#endif /* CONFIG_SMP */

DEFINE_EVENT(synch_wait_event, steely_synch_sleepon,
	TP_PROTO(struct xnsynch *synch, struct xnthread *thread),
	TP_ARGS(synch, thread)
);

DEFINE_EVENT(synch_wait_event, steely_synch_try_acquire,
	TP_PROTO(struct xnsynch *synch, struct xnthread *thread),
	TP_ARGS(synch, thread)
);

DEFINE_EVENT(synch_wait_event, steely_synch_acquire,
	TP_PROTO(struct xnsynch *synch, struct xnthread *thread),
	TP_ARGS(synch, thread)
);

DEFINE_EVENT(synch_post_event, steely_synch_release,
	TP_PROTO(struct xnsynch *synch),
	TP_ARGS(synch)
);

DEFINE_EVENT(synch_post_event, steely_synch_wakeup,
	TP_PROTO(struct xnsynch *synch),
	TP_ARGS(synch)
);

DEFINE_EVENT(synch_post_event, steely_synch_wakeup_many,
	TP_PROTO(struct xnsynch *synch),
	TP_ARGS(synch)
);

DEFINE_EVENT(synch_post_event, steely_synch_flush,
	TP_PROTO(struct xnsynch *synch),
	TP_ARGS(synch)
);

DEFINE_EVENT(synch_post_event, steely_synch_forget,
	TP_PROTO(struct xnsynch *synch),
	TP_ARGS(synch)
);

#define __timespec_fields(__name)				\
	__field(__kernel_time_t, tv_sec_##__name)		\
	__field(long, tv_nsec_##__name)

#define __assign_timespec(__to, __from)				\
	do {							\
		__entry->tv_sec_##__to = (__from)->tv_sec;	\
		__entry->tv_nsec_##__to = (__from)->tv_nsec;	\
	} while (0)

#define __timespec_args(__name)					\
	__entry->tv_sec_##__name, __entry->tv_nsec_##__name

DECLARE_EVENT_CLASS(syscall_entry,
	TP_PROTO(struct xnthread *thread, unsigned int nr),
	TP_ARGS(thread, nr),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__string(name, thread ? thread->name : "(anon)")
		__field(unsigned int, nr)
	),

	TP_fast_assign(
		__entry->thread	= thread;
		__assign_str(name, thread ? thread->name : "(anon)");
		__entry->nr = nr;
	),

	TP_printk("thread=%p(%s) syscall=%u",
		  __entry->thread, __get_str(name), __entry->nr)
);

DECLARE_EVENT_CLASS(syscall_exit,
	TP_PROTO(struct xnthread *thread, long result),
	TP_ARGS(thread, result),

	TP_STRUCT__entry(
		__field(struct xnthread *, thread)
		__field(long, result)
	),

	TP_fast_assign(
		__entry->thread = thread;
		__entry->result = result;
	),

	TP_printk("thread=%p result=%ld",
		  __entry->thread, __entry->result)
);

#define steely_print_sched_policy(__policy)			\
	__print_symbolic(__policy,				\
			 {SCHED_NORMAL, "normal"},		\
			 {SCHED_FIFO, "fifo"},			\
			 {SCHED_RR, "rr"},			\
			 {SCHED_TP, "tp"},			\
			 {SCHED_QUOTA, "quota"},		\
			 {SCHED_SPORADIC, "sporadic"},		\
			 {SCHED_STEELY, "steely"},		\
			 {SCHED_WEAK, "weak"},			\
			 {__SCHED_CURRENT, "<current>"})

#define steely_print_sched_params(__policy, __p_ex)			\
({									\
	const unsigned char *__ret = trace_seq_buffer_ptr(p);		\
	switch (__policy) {						\
	case SCHED_QUOTA:						\
		trace_seq_printf(p, "priority=%d, group=%d",		\
				 (__p_ex)->sched_priority,		\
				 (__p_ex)->sched_quota_group);		\
		break;							\
	case SCHED_TP:							\
		trace_seq_printf(p, "priority=%d, partition=%d",	\
				 (__p_ex)->sched_priority,		\
				 (__p_ex)->sched_tp_partition);		\
		break;							\
	case SCHED_NORMAL:						\
		break;							\
	case SCHED_SPORADIC:						\
		trace_seq_printf(p, "priority=%d, low_priority=%d, "	\
				 "budget=(%ld.%09ld), period=(%ld.%09ld), "\
				 "maxrepl=%d",				\
				 (__p_ex)->sched_priority,		\
				 (__p_ex)->sched_ss_low_priority,	\
				 (__p_ex)->sched_ss_init_budget.tv_sec,	\
				 (__p_ex)->sched_ss_init_budget.tv_nsec, \
				 (__p_ex)->sched_ss_repl_period.tv_sec,	\
				 (__p_ex)->sched_ss_repl_period.tv_nsec, \
				 (__p_ex)->sched_ss_max_repl);		\
		break;							\
	case SCHED_RR:							\
	case SCHED_FIFO:						\
	case SCHED_STEELY:						\
	case SCHED_WEAK:						\
	default:							\
		trace_seq_printf(p, "priority=%d",			\
				 (__p_ex)->sched_priority);		\
		break;							\
	}								\
	trace_seq_putc(p, '\0');					\
	__ret;								\
})

DECLARE_EVENT_CLASS(steely_posix_schedparam,
	TP_PROTO(unsigned long pth, int policy,
		 const struct sched_param_ex *param_ex),
	TP_ARGS(pth, policy, param_ex),

	TP_STRUCT__entry(
		__field(unsigned long, pth)
		__field(int, policy)
		__dynamic_array(char, param_ex, sizeof(struct sched_param_ex))
	),

	TP_fast_assign(
		__entry->pth = pth;
		__entry->policy = policy;
		memcpy(__get_dynamic_array(param_ex), param_ex, sizeof(*param_ex));
	),

	TP_printk("pth=%p policy=%d(%s) param={ %s }",
		  (void *)__entry->pth, __entry->policy,
		  steely_print_sched_policy(__entry->policy),
		  steely_print_sched_params(__entry->policy,
					    (struct sched_param_ex *)
					    __get_dynamic_array(param_ex))
	)
);

DECLARE_EVENT_CLASS(steely_posix_scheduler,
	TP_PROTO(pid_t pid, int policy,
		 const struct sched_param_ex *param_ex),
	TP_ARGS(pid, policy, param_ex),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__field(int, policy)
		__dynamic_array(char, param_ex, sizeof(struct sched_param_ex))
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->policy = policy;
		memcpy(__get_dynamic_array(param_ex), param_ex, sizeof(*param_ex));
	),

	TP_printk("pid=%d policy=%d(%s) param={ %s }",
		  __entry->pid, __entry->policy,
		  steely_print_sched_policy(__entry->policy),
		  steely_print_sched_params(__entry->policy,
					    (struct sched_param_ex *)
					    __get_dynamic_array(param_ex))
	)
);

DECLARE_EVENT_CLASS(steely_void,
	TP_PROTO(int dummy),
	TP_ARGS(dummy),
	TP_STRUCT__entry(
		__array(char, dummy, 0)
	),
	TP_fast_assign(
		(void)dummy;
	),
	TP_printk("%s", "")
);

DEFINE_EVENT(syscall_entry, steely_head_sysentry,
	TP_PROTO(struct xnthread *thread, unsigned int nr),
	TP_ARGS(thread, nr)
);

DEFINE_EVENT(syscall_exit, steely_head_sysexit,
	TP_PROTO(struct xnthread *thread, long result),
	TP_ARGS(thread, result)
);

DEFINE_EVENT(syscall_entry, steely_root_sysentry,
	TP_PROTO(struct xnthread *thread, unsigned int nr),
	TP_ARGS(thread, nr)
);

DEFINE_EVENT(syscall_exit, steely_root_sysexit,
	TP_PROTO(struct xnthread *thread, long result),
	TP_ARGS(thread, result)
);

DEFINE_EVENT(steely_posix_schedparam, steely_pthread_create,
	TP_PROTO(unsigned long pth, int policy,
		 const struct sched_param_ex *param_ex),
	TP_ARGS(pth, policy, param_ex)
);

DEFINE_EVENT(steely_posix_schedparam, steely_pthread_setschedparam,
	TP_PROTO(unsigned long pth, int policy,
		 const struct sched_param_ex *param_ex),
	TP_ARGS(pth, policy, param_ex)
);

DEFINE_EVENT(steely_posix_schedparam, steely_pthread_getschedparam,
	TP_PROTO(unsigned long pth, int policy,
		 const struct sched_param_ex *param_ex),
	TP_ARGS(pth, policy, param_ex)
);

#define steely_print_thread_mode(__mode)			\
	__print_flags(__mode, "|",				\
		      {PTHREAD_WARNSW, "warnsw"},		\
		      {PTHREAD_LOCK_SCHED, "lock"},		\
		      {PTHREAD_DISABLE_LOCKBREAK, "nolockbreak"})

TRACE_EVENT(steely_pthread_setmode,
	TP_PROTO(int clrmask, int setmask),
	TP_ARGS(clrmask, setmask),
	TP_STRUCT__entry(
		__field(int, clrmask)
		__field(int, setmask)
	),
	TP_fast_assign(
		__entry->clrmask = clrmask;
		__entry->setmask = setmask;
	),
	TP_printk("clrmask=%#x(%s) setmask=%#x(%s)",
		  __entry->clrmask, steely_print_thread_mode(__entry->clrmask),
		  __entry->setmask, steely_print_thread_mode(__entry->setmask))
);

TRACE_EVENT(steely_pthread_setname,
	TP_PROTO(unsigned long pth, const char *name),
	TP_ARGS(pth, name),
	TP_STRUCT__entry(
		__field(unsigned long, pth)
		__string(name, name)
	),
	TP_fast_assign(
		__entry->pth = pth;
		__assign_str(name, name);
	),
	TP_printk("pth=%p name=%s", (void *)__entry->pth, __get_str(name))
);

DECLARE_EVENT_CLASS(steely_posix_pid,
	TP_PROTO(pid_t pid),
	TP_ARGS(pid),
	TP_STRUCT__entry(
		__field(pid_t, pid)
	),
	TP_fast_assign(
		__entry->pid = pid;
	),
	TP_printk("pid=%d", __entry->pid)
);

DEFINE_EVENT(steely_posix_pid, steely_pthread_stat,
	TP_PROTO(pid_t pid),
	TP_ARGS(pid)
);

TRACE_EVENT(steely_pthread_kill,
	TP_PROTO(unsigned long pth, int sig),
	TP_ARGS(pth, sig),
	TP_STRUCT__entry(
		__field(unsigned long, pth)
		__field(int, sig)
	),
	TP_fast_assign(
		__entry->pth = pth;
		__entry->sig = sig;
	),
	TP_printk("pth=%p sig=%d", (void *)__entry->pth, __entry->sig)
);

TRACE_EVENT(steely_pthread_join,
	TP_PROTO(unsigned long pth),
	TP_ARGS(pth),
	TP_STRUCT__entry(
		__field(unsigned long, pth)
	),
	TP_fast_assign(
		__entry->pth = pth;
	),
	TP_printk("pth=%p", (void *)__entry->pth)
);

TRACE_EVENT(steely_pthread_pid,
	TP_PROTO(unsigned long pth),
	TP_ARGS(pth),
	TP_STRUCT__entry(
		__field(unsigned long, pth)
	),
	TP_fast_assign(
		__entry->pth = pth;
	),
	TP_printk("pth=%p", (void *)__entry->pth)
);

TRACE_EVENT(steely_pthread_extend,
	TP_PROTO(unsigned long pth, const char *name),
	TP_ARGS(pth, name),
	TP_STRUCT__entry(
		__field(unsigned long, pth)
		__string(name, name)
	),
	TP_fast_assign(
		__entry->pth = pth;
		__assign_str(name, name);
	),
	TP_printk("pth=%p +personality=%s", (void *)__entry->pth, __get_str(name))
);

TRACE_EVENT(steely_pthread_restrict,
	TP_PROTO(unsigned long pth, const char *name),
	TP_ARGS(pth, name),
	TP_STRUCT__entry(
		__field(unsigned long, pth)
		__string(name, name)
	),
	TP_fast_assign(
		__entry->pth = pth;
		__assign_str(name, name);
	),
	TP_printk("pth=%p -personality=%s", (void *)__entry->pth, __get_str(name))
);

DEFINE_EVENT(steely_void, steely_pthread_yield,
	TP_PROTO(int dummy),
	TP_ARGS(dummy)
);

TRACE_EVENT(steely_sched_setconfig,
	TP_PROTO(int cpu, int policy, size_t len),
	TP_ARGS(cpu, policy, len),
	TP_STRUCT__entry(
		__field(int, cpu)
		__field(int, policy)
		__field(size_t, len)
	),
	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->policy = policy;
		__entry->len = len;
	),
	TP_printk("cpu=%d policy=%d(%s) len=%Zu",
		  __entry->cpu, __entry->policy,
		  steely_print_sched_policy(__entry->policy),
		  __entry->len)
);

TRACE_EVENT(steely_sched_get_config,
	TP_PROTO(int cpu, int policy, size_t rlen),
	TP_ARGS(cpu, policy, rlen),
	TP_STRUCT__entry(
		__field(int, cpu)
		__field(int, policy)
		__field(ssize_t, rlen)
	),
	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->policy = policy;
		__entry->rlen = rlen;
	),
	TP_printk("cpu=%d policy=%d(%s) rlen=%Zd",
		  __entry->cpu, __entry->policy,
		  steely_print_sched_policy(__entry->policy),
		  __entry->rlen)
);

DEFINE_EVENT(steely_posix_scheduler, steely_sched_setscheduler,
	TP_PROTO(pid_t pid, int policy,
		 const struct sched_param_ex *param_ex),
	TP_ARGS(pid, policy, param_ex)
);

DEFINE_EVENT(steely_posix_pid, steely_sched_getscheduler,
	TP_PROTO(pid_t pid),
	TP_ARGS(pid)
);

DECLARE_EVENT_CLASS(steely_posix_prio_bound,
	TP_PROTO(int policy, int prio),
	TP_ARGS(policy, prio),
	TP_STRUCT__entry(
		__field(int, policy)
		__field(int, prio)
	),
	TP_fast_assign(
		__entry->policy = policy;
		__entry->prio = prio;
	),
	TP_printk("policy=%d(%s) prio=%d",
		  __entry->policy,
		  steely_print_sched_policy(__entry->policy),
		  __entry->prio)
);

DEFINE_EVENT(steely_posix_prio_bound, steely_sched_min_prio,
	TP_PROTO(int policy, int prio),
	TP_ARGS(policy, prio)
);

DEFINE_EVENT(steely_posix_prio_bound, steely_sched_max_prio,
	TP_PROTO(int policy, int prio),
	TP_ARGS(policy, prio)
);

DECLARE_EVENT_CLASS(steely_posix_sem,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle),
	TP_STRUCT__entry(
		__field(xnhandle_t, handle)
	),
	TP_fast_assign(
		__entry->handle = handle;
	),
	TP_printk("sem=%#x", __entry->handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_wait,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_trywait,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_timedwait,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_post,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_destroy,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_broadcast,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_inquire,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

TRACE_EVENT(steely_psem_getvalue,
	TP_PROTO(xnhandle_t handle, int value),
	TP_ARGS(handle, value),
	TP_STRUCT__entry(
		__field(xnhandle_t, handle)
		__field(int, value)
	),
	TP_fast_assign(
		__entry->handle = handle;
		__entry->value = value;
	),
	TP_printk("sem=%#x value=%d", __entry->handle, __entry->value)
);

#define steely_print_sem_flags(__flags)				\
  	__print_flags(__flags, "|",				\
			 {SEM_FIFO, "fifo"},			\
			 {SEM_PULSE, "pulse"},			\
			 {SEM_PSHARED, "pshared"},		\
			 {SEM_REPORT, "report"},		\
			 {SEM_WARNDEL, "warndel"},		\
			 {SEM_RAWCLOCK, "rawclock"},		\
			 {SEM_NOBUSYDEL, "nobusydel"})

TRACE_EVENT(steely_psem_init,
	TP_PROTO(const char *name, xnhandle_t handle,
		 int flags, unsigned int value),
	TP_ARGS(name, handle, flags, value),
	TP_STRUCT__entry(
		__string(name, name)
		__field(xnhandle_t, handle)
		__field(int, flags)
		__field(unsigned int, value)
	),
	TP_fast_assign(
		__assign_str(name, name);
		__entry->handle = handle;
		__entry->flags = flags;
		__entry->value = value;
	),
	TP_printk("sem=%#x(%s) flags=%#x(%s) value=%u",
		  __entry->handle,
		  __get_str(name),
		  __entry->flags,
		  steely_print_sem_flags(__entry->flags),
		  __entry->value)
);

TRACE_EVENT(steely_psem_init_failed,
	TP_PROTO(const char *name, int flags, unsigned int value, int status),
	TP_ARGS(name, flags, value, status),
	TP_STRUCT__entry(
		__string(name, name)
		__field(int, flags)
		__field(unsigned int, value)
		__field(int, status)
	),
	TP_fast_assign(
		__assign_str(name, name);
		__entry->flags = flags;
		__entry->value = value;
		__entry->status = status;
	),
	TP_printk("name=%s flags=%#x(%s) value=%u error=%d",
		  __get_str(name),
		  __entry->flags,
		  steely_print_sem_flags(__entry->flags),
		  __entry->value, __entry->status)
);

#define steely_print_oflags(__flags)		\
	__print_flags(__flags,  "|", 		\
		      {O_RDONLY, "rdonly"},	\
		      {O_WRONLY, "wronly"},	\
		      {O_RDWR, "rdwr"},		\
		      {O_CREAT, "creat"},	\
		      {O_EXCL, "excl"},		\
		      {O_DIRECT, "direct"},	\
		      {O_NONBLOCK, "nonblock"},	\
		      {O_TRUNC, "trunc"})

TRACE_EVENT(steely_psem_open,
	TP_PROTO(const char *name, xnhandle_t handle,
		 int oflags, mode_t mode, unsigned int value),
	TP_ARGS(name, handle, oflags, mode, value),
	TP_STRUCT__entry(
		__string(name, name)
		__field(xnhandle_t, handle)
		__field(int, oflags)
		__field(mode_t, mode)
		__field(unsigned int, value)
	),
	TP_fast_assign(
		__assign_str(name, name);
		__entry->handle = handle;
		__entry->oflags = oflags;
		if (oflags & O_CREAT) {
			__entry->mode = mode;
			__entry->value = value;
		} else {
			__entry->mode = 0;
			__entry->value = 0;
		}
	),
	TP_printk("named_sem=%#x=(%s) oflags=%#x(%s) mode=%o value=%u",
		  __entry->handle, __get_str(name),
		  __entry->oflags, steely_print_oflags(__entry->oflags),
		  __entry->mode, __entry->value)
);

TRACE_EVENT(steely_psem_open_failed,
	TP_PROTO(const char *name, int oflags, mode_t mode,
		 unsigned int value, int status),
	TP_ARGS(name, oflags, mode, value, status),
	TP_STRUCT__entry(
		__string(name, name)
		__field(int, oflags)
		__field(mode_t, mode)
		__field(unsigned int, value)
		__field(int, status)
	),
	TP_fast_assign(
		__assign_str(name, name);
		__entry->oflags = oflags;
		__entry->status = status;
		if (oflags & O_CREAT) {
			__entry->mode = mode;
			__entry->value = value;
		} else {
			__entry->mode = 0;
			__entry->value = 0;
		}
	),
	TP_printk("named_sem=%s oflags=%#x(%s) mode=%o value=%u error=%d",
		  __get_str(name),
		  __entry->oflags, steely_print_oflags(__entry->oflags),
		  __entry->mode, __entry->value, __entry->status)
);

DEFINE_EVENT(steely_posix_sem, steely_psem_close,
	TP_PROTO(xnhandle_t handle),
	TP_ARGS(handle)
);

TRACE_EVENT(steely_psem_unlink,
	TP_PROTO(const char *name),
	TP_ARGS(name),
	TP_STRUCT__entry(
		__string(name, name)
	),
	TP_fast_assign(
		__assign_str(name, name);
	),
	TP_printk("name=%s", __get_str(name))
);

DECLARE_EVENT_CLASS(steely_clock_timespec,
	TP_PROTO(clockid_t clk_id, const struct timespec *val),
	TP_ARGS(clk_id, val),

	TP_STRUCT__entry(
		__field(clockid_t, clk_id)
		__timespec_fields(val)
	),

	TP_fast_assign(
		__entry->clk_id = clk_id;
		__assign_timespec(val, val);
	),

	TP_printk("clock_id=%d timeval=(%ld.%09ld)",
		  __entry->clk_id,
		  __timespec_args(val)
	)
);

DEFINE_EVENT(steely_clock_timespec, steely_clock_getres,
	TP_PROTO(clockid_t clk_id, const struct timespec *res),
	TP_ARGS(clk_id, res)
);

DEFINE_EVENT(steely_clock_timespec, steely_clock_gettime,
	TP_PROTO(clockid_t clk_id, const struct timespec *time),
	TP_ARGS(clk_id, time)
);

DEFINE_EVENT(steely_clock_timespec, steely_clock_settime,
	TP_PROTO(clockid_t clk_id, const struct timespec *time),
	TP_ARGS(clk_id, time)
);

#define steely_print_timer_flags(__flags)			\
	__print_flags(__flags, "|",				\
		      {TIMER_ABSTIME, "TIMER_ABSTIME"})

TRACE_EVENT(steely_clock_nanosleep,
	TP_PROTO(clockid_t clk_id, int flags, const struct timespec *time),
	TP_ARGS(clk_id, flags, time),

	TP_STRUCT__entry(
		__field(clockid_t, clk_id)
		__field(int, flags)
		__timespec_fields(time)
	),

	TP_fast_assign(
		__entry->clk_id = clk_id;
		__entry->flags = flags;
		__assign_timespec(time, time);
	),

	TP_printk("clock_id=%d flags=%#x(%s) rqt=(%ld.%09ld)",
		  __entry->clk_id,
		  __entry->flags, steely_print_timer_flags(__entry->flags),
		  __timespec_args(time)
	)
);

DECLARE_EVENT_CLASS(steely_clock_ident,
	TP_PROTO(const char *name, clockid_t clk_id),
	TP_ARGS(name, clk_id),
	TP_STRUCT__entry(
		__string(name, name)
		__field(clockid_t, clk_id)
	),
	TP_fast_assign(
		__assign_str(name, name);
		__entry->clk_id = clk_id;
	),
	TP_printk("name=%s, id=%#x", __get_str(name), __entry->clk_id)
);

DEFINE_EVENT(steely_clock_ident, steely_clock_register,
	TP_PROTO(const char *name, clockid_t clk_id),
	TP_ARGS(name, clk_id)
);

DEFINE_EVENT(steely_clock_ident, steely_clock_deregister,
	TP_PROTO(const char *name, clockid_t clk_id),
	TP_ARGS(name, clk_id)
);

#define steely_print_clock(__clk_id)					\
	__print_symbolic(__clk_id,					\
			 {CLOCK_MONOTONIC, "CLOCK_MONOTONIC"},		\
			 {CLOCK_REALTIME, "CLOCK_REALTIME"})

TRACE_EVENT(steely_cond_init,
	TP_PROTO(const struct steely_cond_shadow __user *u_cnd,
		 const struct steely_condattr *attr),
	TP_ARGS(u_cnd, attr),
	TP_STRUCT__entry(
		__field(const struct steely_cond_shadow __user *, u_cnd)
		__field(clockid_t, clk_id)
		__field(int, pshared)
	),
	TP_fast_assign(
		__entry->u_cnd = u_cnd;
		__entry->clk_id = attr->clock;
		__entry->pshared = attr->pshared;
	),
	TP_printk("cond=%p attr={ .clock=%s, .pshared=%d }",
		  __entry->u_cnd,
		  steely_print_clock(__entry->clk_id),
		  __entry->pshared)
);

TRACE_EVENT(steely_cond_destroy,
	TP_PROTO(const struct steely_cond_shadow __user *u_cnd),
	TP_ARGS(u_cnd),
	TP_STRUCT__entry(
		__field(const struct steely_cond_shadow __user *, u_cnd)
	),
	TP_fast_assign(
		__entry->u_cnd = u_cnd;
	),
	TP_printk("cond=%p", __entry->u_cnd)
);

TRACE_EVENT(steely_cond_timedwait,
	TP_PROTO(const struct steely_cond_shadow __user *u_cnd,
		 const struct steely_mutex_shadow __user *u_mx,
		 const struct timespec *timeout),
	TP_ARGS(u_cnd, u_mx, timeout),
	TP_STRUCT__entry(
		__field(const struct steely_cond_shadow __user *, u_cnd)
		__field(const struct steely_mutex_shadow __user *, u_mx)
		__timespec_fields(timeout)
	),
	TP_fast_assign(
		__entry->u_cnd = u_cnd;
		__entry->u_mx = u_mx;
		__assign_timespec(timeout, timeout);
	),
	TP_printk("cond=%p, mutex=%p, timeout=(%ld.%09ld)",
		  __entry->u_cnd, __entry->u_mx, __timespec_args(timeout))
);

TRACE_EVENT(steely_cond_wait,
	TP_PROTO(const struct steely_cond_shadow __user *u_cnd,
		 const struct steely_mutex_shadow __user *u_mx),
	TP_ARGS(u_cnd, u_mx),
	TP_STRUCT__entry(
		__field(const struct steely_cond_shadow __user *, u_cnd)
		__field(const struct steely_mutex_shadow __user *, u_mx)
	),
	TP_fast_assign(
		__entry->u_cnd = u_cnd;
		__entry->u_mx = u_mx;
	),
	TP_printk("cond=%p, mutex=%p",
		  __entry->u_cnd, __entry->u_mx)
);

TRACE_EVENT(steely_mq_open,
	TP_PROTO(const char *name, int oflags, mode_t mode),
	TP_ARGS(name, oflags, mode),

	TP_STRUCT__entry(
		__string(name, name)
		__field(int, oflags)
		__field(mode_t, mode)
	),

	TP_fast_assign(
		__assign_str(name, name);
		__entry->oflags = oflags;
		__entry->mode = (oflags & O_CREAT) ? mode : 0;
	),

	TP_printk("name=%s oflags=%#x(%s) mode=%o",
		  __get_str(name),
		  __entry->oflags, steely_print_oflags(__entry->oflags),
		  __entry->mode)
);

TRACE_EVENT(steely_mq_notify,
	TP_PROTO(mqd_t mqd, const struct sigevent *sev),
	TP_ARGS(mqd, sev),

	TP_STRUCT__entry(
		__field(mqd_t, mqd)
		__field(int, signo)
	),

	TP_fast_assign(
		__entry->mqd = mqd;
		__entry->signo = sev && sev->sigev_notify != SIGEV_NONE ?
			sev->sigev_signo : 0;
	),

	TP_printk("mqd=%d signo=%d",
		  __entry->mqd, __entry->signo)
);

TRACE_EVENT(steely_mq_close,
	TP_PROTO(mqd_t mqd),
	TP_ARGS(mqd),

	TP_STRUCT__entry(
		__field(mqd_t, mqd)
	),

	TP_fast_assign(
		__entry->mqd = mqd;
	),

	TP_printk("mqd=%d", __entry->mqd)
);

TRACE_EVENT(steely_mq_unlink,
	TP_PROTO(const char *name),
	TP_ARGS(name),

	TP_STRUCT__entry(
		__string(name, name)
	),

	TP_fast_assign(
		__assign_str(name, name);
	),

	TP_printk("name=%s", __get_str(name))
);

TRACE_EVENT(steely_mq_send,
	TP_PROTO(mqd_t mqd, const void __user *u_buf, size_t len,
		 unsigned int prio),
	TP_ARGS(mqd, u_buf, len, prio),
	TP_STRUCT__entry(
		__field(mqd_t, mqd)
		__field(const void __user *, u_buf)
		__field(size_t, len)
		__field(unsigned int, prio)
	),
	TP_fast_assign(
		__entry->mqd = mqd;
		__entry->u_buf = u_buf;
		__entry->len = len;
		__entry->prio = prio;
	),
	TP_printk("mqd=%d buf=%p len=%Zu prio=%u",
		  __entry->mqd, __entry->u_buf, __entry->len,
		  __entry->prio)
);

TRACE_EVENT(steely_mq_timedreceive,
	TP_PROTO(mqd_t mqd, const void __user *u_buf, size_t len,
		 const struct timespec *timeout),
	TP_ARGS(mqd, u_buf, len, timeout),
	TP_STRUCT__entry(
		__field(mqd_t, mqd)
		__field(const void __user *, u_buf)
		__field(size_t, len)
		__timespec_fields(timeout)
	),
	TP_fast_assign(
		__entry->mqd = mqd;
		__entry->u_buf = u_buf;
		__entry->len = len;
		__assign_timespec(timeout, timeout);
	),
	TP_printk("mqd=%d buf=%p len=%Zu timeout=(%ld.%09ld)",
		  __entry->mqd, __entry->u_buf, __entry->len,
		  __timespec_args(timeout))
);

TRACE_EVENT(steely_mq_receive,
	TP_PROTO(mqd_t mqd, const void __user *u_buf, size_t len),
	TP_ARGS(mqd, u_buf, len),
	TP_STRUCT__entry(
		__field(mqd_t, mqd)
		__field(const void __user *, u_buf)
		__field(size_t, len)
	),
	TP_fast_assign(
		__entry->mqd = mqd;
		__entry->u_buf = u_buf;
		__entry->len = len;
	),
	TP_printk("mqd=%d buf=%p len=%Zu",
		  __entry->mqd, __entry->u_buf, __entry->len)
);

DECLARE_EVENT_CLASS(steely_posix_mqattr,
	TP_PROTO(mqd_t mqd, const struct mq_attr *attr),
	TP_ARGS(mqd, attr),
	TP_STRUCT__entry(
		__field(mqd_t, mqd)
		__field(long, flags)
		__field(long, curmsgs)
		__field(long, msgsize)
		__field(long, maxmsg)
	),
	TP_fast_assign(
		__entry->mqd = mqd;
		__entry->flags = attr->mq_flags;
		__entry->curmsgs = attr->mq_curmsgs;
		__entry->msgsize = attr->mq_msgsize;
		__entry->maxmsg = attr->mq_maxmsg;
	),
	TP_printk("mqd=%d flags=%#lx(%s) curmsgs=%ld msgsize=%ld maxmsg=%ld",
		  __entry->mqd,
		  __entry->flags, steely_print_oflags(__entry->flags),
		  __entry->curmsgs,
		  __entry->msgsize,
		  __entry->maxmsg
	)
);

DEFINE_EVENT(steely_posix_mqattr, steely_mq_getattr,
	TP_PROTO(mqd_t mqd, const struct mq_attr *attr),
	TP_ARGS(mqd, attr)
);

DEFINE_EVENT(steely_posix_mqattr, steely_mq_setattr,
	TP_PROTO(mqd_t mqd, const struct mq_attr *attr),
	TP_ARGS(mqd, attr)
);

#define steely_print_evflags(__flags)			\
	__print_flags(__flags,  "|",			\
		      {STEELY_EVENT_SHARED, "shared"},	\
		      {STEELY_EVENT_PRIO, "prio"})

TRACE_EVENT(steely_event_init,
	TP_PROTO(const struct steely_event_shadow __user *u_event,
		 unsigned long value, int flags),
	TP_ARGS(u_event, value, flags),
	TP_STRUCT__entry(
		__field(const struct steely_event_shadow __user *, u_event)
		__field(unsigned long, value)
		__field(int, flags)
	),
	TP_fast_assign(
		__entry->u_event = u_event;
		__entry->value = value;
		__entry->flags = flags;
	),
	TP_printk("event=%p value=%lu flags=%#x(%s)",
		  __entry->u_event, __entry->value,
		  __entry->flags, steely_print_evflags(__entry->flags))
);

#define steely_print_evmode(__mode)			\
	__print_symbolic(__mode,			\
			 {STEELY_EVENT_ANY, "any"},	\
			 {STEELY_EVENT_ALL, "all"})

TRACE_EVENT(steely_event_timedwait,
	TP_PROTO(const struct steely_event_shadow __user *u_event,
		 unsigned long bits, int mode,
		 const struct timespec *timeout),
	TP_ARGS(u_event, bits, mode, timeout),
	TP_STRUCT__entry(
		__field(const struct steely_event_shadow __user *, u_event)
		__field(unsigned long, bits)
		__field(int, mode)
		__timespec_fields(timeout)
	),
	TP_fast_assign(
		__entry->u_event = u_event;
		__entry->bits = bits;
		__entry->mode = mode;
		__assign_timespec(timeout, timeout);
	),
	TP_printk("event=%p bits=%#lx mode=%#x(%s) timeout=(%ld.%09ld)",
		  __entry->u_event, __entry->bits, __entry->mode,
		  steely_print_evmode(__entry->mode),
		  __timespec_args(timeout))
);

TRACE_EVENT(steely_event_wait,
	TP_PROTO(const struct steely_event_shadow __user *u_event,
		 unsigned long bits, int mode),
	TP_ARGS(u_event, bits, mode),
	TP_STRUCT__entry(
		__field(const struct steely_event_shadow __user *, u_event)
		__field(unsigned long, bits)
		__field(int, mode)
	),
	TP_fast_assign(
		__entry->u_event = u_event;
		__entry->bits = bits;
		__entry->mode = mode;
	),
	TP_printk("event=%p bits=%#lx mode=%#x(%s)",
		  __entry->u_event, __entry->bits, __entry->mode,
		  steely_print_evmode(__entry->mode))
);

DECLARE_EVENT_CLASS(steely_event_ident,
	TP_PROTO(const struct steely_event_shadow __user *u_event),
	TP_ARGS(u_event),
	TP_STRUCT__entry(
		__field(const struct steely_event_shadow __user *, u_event)
	),
	TP_fast_assign(
		__entry->u_event = u_event;
	),
	TP_printk("event=%p", __entry->u_event)
);

DEFINE_EVENT(steely_event_ident, steely_event_destroy,
	TP_PROTO(const struct steely_event_shadow __user *u_event),
	TP_ARGS(u_event)
);

DEFINE_EVENT(steely_event_ident, steely_event_sync,
	TP_PROTO(const struct steely_event_shadow __user *u_event),
	TP_ARGS(u_event)
);

DEFINE_EVENT(steely_event_ident, steely_event_inquire,
	TP_PROTO(const struct steely_event_shadow __user *u_event),
	TP_ARGS(u_event)
);

DECLARE_EVENT_CLASS(fd_event,
	TP_PROTO(struct rtdm_fd *fd, int ufd),
	TP_ARGS(fd, ufd),

	TP_STRUCT__entry(
		__field(struct rtdm_device *, dev)
		__field(int, ufd)
	),

	TP_fast_assign(
		__entry->dev = rtdm_fd_to_context(fd)->device;
		__entry->ufd = ufd;
	),

	TP_printk("device=%p fd=%d",
		  __entry->dev, __entry->ufd)
);

DECLARE_EVENT_CLASS(fd_request,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd, unsigned long arg),
	TP_ARGS(task, fd, ufd, arg),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(pid_t, pid)
		__field(struct rtdm_device *, dev)
		__field(int, ufd)
		__field(unsigned long, arg)
	),

	TP_fast_assign(
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->pid = task_pid_nr(task);
		__entry->dev = rtdm_fd_to_context(fd)->device;
		__entry->ufd = ufd;
		__entry->arg = arg;
	),

	TP_printk("device=%p fd=%d arg=%#lx pid=%d comm=%s",
		  __entry->dev, __entry->ufd, __entry->arg,
		  __entry->pid, __entry->comm)
);

DECLARE_EVENT_CLASS(fd_request_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd, int status),
	TP_ARGS(task, fd, ufd, status),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(pid_t, pid)
		__field(struct rtdm_device *, dev)
		__field(int, ufd)
	),

	TP_fast_assign(
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->pid = task_pid_nr(task);
		__entry->dev =
			!IS_ERR(fd) ? rtdm_fd_to_context(fd)->device : NULL;
		__entry->ufd = ufd;
	),

	TP_printk("device=%p fd=%d pid=%d comm=%s",
		  __entry->dev, __entry->ufd, __entry->pid, __entry->comm)
);

DECLARE_EVENT_CLASS(task_op,
	TP_PROTO(struct xnthread *task),
	TP_ARGS(task),

	TP_STRUCT__entry(
		__field(struct xnthread *, task)
		__string(task_name, task->name)
	),

	TP_fast_assign(
		__entry->task = task;
		__assign_str(task_name, task->name);
	),

	TP_printk("task %p(%s)", __entry->task, __get_str(task_name))
);

DECLARE_EVENT_CLASS(event_op,
	TP_PROTO(struct rtdm_event *ev),
	TP_ARGS(ev),

	TP_STRUCT__entry(
		__field(struct rtdm_event *, ev)
	),

	TP_fast_assign(
		__entry->ev = ev;
	),

	TP_printk("event=%p", __entry->ev)
);

DECLARE_EVENT_CLASS(sem_op,
	TP_PROTO(struct rtdm_sem *sem),
	TP_ARGS(sem),

	TP_STRUCT__entry(
		__field(struct rtdm_sem *, sem)
	),

	TP_fast_assign(
		__entry->sem = sem;
	),

	TP_printk("sem=%p", __entry->sem)
);

DECLARE_EVENT_CLASS(mutex_op,
	TP_PROTO(struct rtdm_mutex *mutex),
	TP_ARGS(mutex),

	TP_STRUCT__entry(
		__field(struct rtdm_mutex *, mutex)
	),

	TP_fast_assign(
		__entry->mutex = mutex;
	),

	TP_printk("mutex=%p", __entry->mutex)
);

TRACE_EVENT(steely_device_register,
	TP_PROTO(struct rtdm_device *dev),
	TP_ARGS(dev),

	TP_STRUCT__entry(
		__field(struct rtdm_device *, dev)
		__string(device_name, dev->name)
		__field(int, flags)
		__field(int, class_id)
		__field(int, subclass_id)
		__field(int, profile_version)
	),

	TP_fast_assign(
		__entry->dev	= dev;
		__assign_str(device_name, dev->name);
		__entry->flags = dev->driver->device_flags;
		__entry->class_id = dev->driver->profile_info.class_id;
		__entry->subclass_id = dev->driver->profile_info.subclass_id;
		__entry->profile_version = dev->driver->profile_info.version;
	),

	TP_printk("%s device %s=%p flags=0x%x, class=%d.%d profile=%d",
		  (__entry->flags & RTDM_DEVICE_TYPE_MASK)
		  == RTDM_NAMED_DEVICE ? "named" : "protocol",
		  __get_str(device_name), __entry->dev,
		  __entry->flags, __entry->class_id, __entry->subclass_id,
		  __entry->profile_version)
);

TRACE_EVENT(steely_device_unregister,
	TP_PROTO(struct rtdm_device *dev),
	TP_ARGS(dev),

	TP_STRUCT__entry(
		__field(struct rtdm_device *, dev)
		__string(device_name, dev->name)
	),

	TP_fast_assign(
		__entry->dev	= dev;
		__assign_str(device_name, dev->name);
	),

	TP_printk("device %s=%p",
		  __get_str(device_name), __entry->dev)
);

DEFINE_EVENT(fd_event, steely_fd_created,
	TP_PROTO(struct rtdm_fd *fd, int ufd),
	TP_ARGS(fd, ufd)
);

DEFINE_EVENT(fd_request, steely_fd_open,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long oflags),
	TP_ARGS(task, fd, ufd, oflags)
);

DEFINE_EVENT(fd_request, steely_fd_close,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long lock_count),
	TP_ARGS(task, fd, ufd, lock_count)
);

DEFINE_EVENT(fd_request, steely_fd_socket,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long protocol_family),
	TP_ARGS(task, fd, ufd, protocol_family)
);

DEFINE_EVENT(fd_request, steely_fd_read,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long len),
	TP_ARGS(task, fd, ufd, len)
);

DEFINE_EVENT(fd_request, steely_fd_write,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long len),
	TP_ARGS(task, fd, ufd, len)
);

DEFINE_EVENT(fd_request, steely_fd_ioctl,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long request),
	TP_ARGS(task, fd, ufd, request)
);

DEFINE_EVENT(fd_request, steely_fd_sendmsg,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long flags),
	TP_ARGS(task, fd, ufd, flags)
);

DEFINE_EVENT(fd_request, steely_fd_recvmsg,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 unsigned long flags),
	TP_ARGS(task, fd, ufd, flags)
);

#define steely_print_protbits(__prot)		\
	__print_flags(__prot,  "|", 		\
		      {PROT_EXEC, "exec"},	\
		      {PROT_READ, "read"},	\
		      {PROT_WRITE, "write"})

#define steely_print_mapbits(__flags)		\
	__print_flags(__flags,  "|", 		\
		      {MAP_SHARED, "shared"},	\
		      {MAP_PRIVATE, "private"},	\
		      {MAP_ANONYMOUS, "anon"},	\
		      {MAP_FIXED, "fixed"},	\
		      {MAP_HUGETLB, "huge"},	\
		      {MAP_NONBLOCK, "nonblock"},	\
		      {MAP_NORESERVE, "noreserve"},	\
		      {MAP_POPULATE, "populate"},	\
		      {MAP_UNINITIALIZED, "uninit"})

TRACE_EVENT(steely_fd_mmap,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd, struct _rtdm_mmap_request *rma),
        TP_ARGS(task, fd, ufd, rma),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(pid_t, pid)
		__field(struct rtdm_device *, dev)
		__field(int, ufd)
		__field(size_t, length)
		__field(off_t, offset)
		__field(int, prot)
		__field(int, flags)
	),

	TP_fast_assign(
		memcpy(__entry->comm, task->comm, TASK_COMM_LEN);
		__entry->pid = task_pid_nr(task);
		__entry->dev = rtdm_fd_to_context(fd)->device;
		__entry->ufd = ufd;
		__entry->length = rma->length;
		__entry->offset = rma->offset;
		__entry->prot = rma->prot;
		__entry->flags = rma->flags;
	),

	TP_printk("device=%p fd=%d area={ len:%Zu, off:%Lu }"
		  " prot=%#x(%s) flags=%#x(%s) pid=%d comm=%s",
		  __entry->dev, __entry->ufd, __entry->length,
		  (unsigned long long)__entry->offset,
		  __entry->prot, steely_print_protbits(__entry->prot),
		  __entry->flags, steely_print_mapbits(__entry->flags),
		  __entry->pid, __entry->comm)
);

DEFINE_EVENT(fd_request_status, steely_fd_ioctl_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 int status),
	TP_ARGS(task, fd, ufd, status)
);

DEFINE_EVENT(fd_request_status, steely_fd_read_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 int status),
	TP_ARGS(task, fd, ufd, status)
);

DEFINE_EVENT(fd_request_status, steely_fd_write_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 int status),
	TP_ARGS(task, fd, ufd, status)
);

DEFINE_EVENT(fd_request_status, steely_fd_recvmsg_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 int status),
	TP_ARGS(task, fd, ufd, status)
);

DEFINE_EVENT(fd_request_status, steely_fd_sendmsg_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 int status),
	TP_ARGS(task, fd, ufd, status)
);

DEFINE_EVENT(fd_request_status, steely_fd_mmap_status,
	TP_PROTO(struct task_struct *task,
		 struct rtdm_fd *fd, int ufd,
		 int status),
	TP_ARGS(task, fd, ufd, status)
);

DEFINE_EVENT(task_op, steely_driver_task_join,
	TP_PROTO(struct xnthread *task),
	TP_ARGS(task)
);

TRACE_EVENT(steely_driver_event_init,
	TP_PROTO(struct rtdm_event *ev, unsigned long pending),
	TP_ARGS(ev, pending),

	TP_STRUCT__entry(
		__field(struct rtdm_event *, ev)
		__field(unsigned long,	pending)
	),

	TP_fast_assign(
		__entry->ev = ev;
		__entry->pending = pending;
	),

	TP_printk("event=%p pending=%#lx",
		  __entry->ev, __entry->pending)
);

TRACE_EVENT(steely_driver_event_wait,
	TP_PROTO(struct rtdm_event *ev, struct xnthread *task),
	TP_ARGS(ev, task),

	TP_STRUCT__entry(
		__field(struct xnthread *, task)
		__string(task_name, task->name)
		__field(struct rtdm_event *, ev)
	),

	TP_fast_assign(
		__entry->task = task;
		__assign_str(task_name, task->name);
		__entry->ev = ev;
	),

	TP_printk("event=%p task=%p(%s)",
		  __entry->ev, __entry->task, __get_str(task_name))
);

DEFINE_EVENT(event_op, steely_driver_event_signal,
	TP_PROTO(struct rtdm_event *ev),
	TP_ARGS(ev)
);

DEFINE_EVENT(event_op, steely_driver_event_clear,
	TP_PROTO(struct rtdm_event *ev),
	TP_ARGS(ev)
);

DEFINE_EVENT(event_op, steely_driver_event_pulse,
	TP_PROTO(struct rtdm_event *ev),
	TP_ARGS(ev)
);

DEFINE_EVENT(event_op, steely_driver_event_destroy,
	TP_PROTO(struct rtdm_event *ev),
	TP_ARGS(ev)
);

TRACE_EVENT(steely_driver_sem_init,
	TP_PROTO(struct rtdm_sem *sem, unsigned long value),
	TP_ARGS(sem, value),

	TP_STRUCT__entry(
		__field(struct rtdm_sem *, sem)
		__field(unsigned long, value)
	),

	TP_fast_assign(
		__entry->sem = sem;
		__entry->value = value;
	),

	TP_printk("sem=%p value=%lu",
		  __entry->sem, __entry->value)
);

TRACE_EVENT(steely_driver_sem_wait,
	TP_PROTO(struct rtdm_sem *sem, struct xnthread *task),
	TP_ARGS(sem, task),

	TP_STRUCT__entry(
		__field(struct xnthread *, task)
		__string(task_name, task->name)
		__field(struct rtdm_sem *, sem)
	),

	TP_fast_assign(
		__entry->task = task;
		__assign_str(task_name, task->name);
		__entry->sem = sem;
	),

	TP_printk("sem=%p task=%p(%s)",
		  __entry->sem, __entry->task, __get_str(task_name))
);

DEFINE_EVENT(sem_op, steely_driver_sem_up,
	TP_PROTO(struct rtdm_sem *sem),
	TP_ARGS(sem)
);

DEFINE_EVENT(sem_op, steely_driver_sem_destroy,
	TP_PROTO(struct rtdm_sem *sem),
	TP_ARGS(sem)
);

DEFINE_EVENT(mutex_op, steely_driver_mutex_init,
	TP_PROTO(struct rtdm_mutex *mutex),
	TP_ARGS(mutex)
);

DEFINE_EVENT(mutex_op, steely_driver_mutex_release,
	TP_PROTO(struct rtdm_mutex *mutex),
	TP_ARGS(mutex)
);

DEFINE_EVENT(mutex_op, steely_driver_mutex_destroy,
	TP_PROTO(struct rtdm_mutex *mutex),
	TP_ARGS(mutex)
);

TRACE_EVENT(steely_driver_mutex_wait,
	TP_PROTO(struct rtdm_mutex *mutex, struct xnthread *task),
	TP_ARGS(mutex, task),

	TP_STRUCT__entry(
		__field(struct xnthread *, task)
		__string(task_name, task->name)
		__field(struct rtdm_mutex *, mutex)
	),

	TP_fast_assign(
		__entry->task = task;
		__assign_str(task_name, task->name);
		__entry->mutex = mutex;
	),

	TP_printk("mutex=%p task=%p(%s)",
		  __entry->mutex, __entry->task, __get_str(task_name))
);

#endif /* _TRACE_STEELY_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
