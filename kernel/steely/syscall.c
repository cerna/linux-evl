/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>
 * Copyright (C) 2005 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/types.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/dovetail.h>
#include <linux/kconfig.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/signal.h>
#include <uapi/steely/corectl.h>
#include <steely/tree.h>
#include <steely/vdso.h>
#include <steely/init.h>
#include <steely/thread.h>
#include <steely/mutex.h>
#include <steely/cond.h>
#include <steely/mqueue.h>
#include <steely/sem.h>
#include <steely/signal.h>
#include <steely/timer.h>
#include <steely/monitor.h>
#include <steely/clock.h>
#include <steely/sched.h>
#include <steely/event.h>
#include <steely/timerfd.h>
#include <steely/io.h>
#include <steely/corectl.h>
#include <asm-generic/steely/mayday.h>
#include <trace/events/steely.h>
#include "debug.h"
#include "internal.h"

/* Syscall must run into the Linux domain. */
#define __xn_exec_lostage    0x1
/* Syscall must run into the Steely domain. */
#define __xn_exec_histage    0x2
/* Shadow syscall: caller must be mapped. */
#define __xn_exec_shadow     0x4
/* Switch back toggle; caller must return to its original mode. */
#define __xn_exec_switchback 0x8
/* Exec in current domain. */
#define __xn_exec_current    0x10
/* Exec in conforming domain, Steely or Linux. */
#define __xn_exec_conforming 0x20
/* Attempt syscall restart in the opposite domain upon -ENOSYS. */
#define __xn_exec_adaptive   0x40
/* Do not restart syscall upon signal receipt. */
#define __xn_exec_norestart  0x80
/* Shorthand for shadow init syscall. */
#define __xn_exec_init       __xn_exec_lostage
/* Shorthand for shadow syscall in Steely domain. */
#define __xn_exec_primary   (__xn_exec_shadow|__xn_exec_histage)
/* Shorthand for shadow syscall in Linux space. */
#define __xn_exec_secondary (__xn_exec_shadow|__xn_exec_lostage)
/* Shorthand for syscall in Linux space with switchback if shadow. */
#define __xn_exec_downup    (__xn_exec_lostage|__xn_exec_switchback)
/* Shorthand for non-restartable primary syscall. */
#define __xn_exec_nonrestartable (__xn_exec_primary|__xn_exec_norestart)
/* Domain probing syscall starting in conforming mode. */
#define __xn_exec_probing   (__xn_exec_conforming|__xn_exec_adaptive)
/* Hand over mode selection to syscall.  */
#define __xn_exec_handover  (__xn_exec_current|__xn_exec_adaptive)

#define SYSCALL_PROPAGATE   0
#define SYSCALL_STOP        1

typedef long (*steely_syshand)(unsigned long arg1, unsigned long arg2,
			       unsigned long arg3, unsigned long arg4,
			       unsigned long arg5);

static void prepare_for_signal(struct task_struct *p,
			       struct steely_thread *thread,
			       struct pt_regs *regs,
			       int sysflags)
{
	int notify = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (xnthread_test_info(thread, XNKICKED)) {
		if (signal_pending(p)) {
			__xn_error_return(regs,
					  (sysflags & __xn_exec_norestart) ?
					  -EINTR : -ERESTARTSYS);
			notify = !xnthread_test_state(thread, XNSSTEP);
			xnthread_clear_info(thread, XNBREAK);
		}
		xnthread_clear_info(thread, XNKICKED);
	}

	xnlock_put_irqrestore(&nklock, s);

	xnthread_test_cancel();

	xnthread_relax(notify, SIGDEBUG_MIGRATE_SIGNAL);
}

static STEELY_SYSCALL(migrate, current, (int domain))
{
	struct steely_thread *thread = steely_current_thread();

	if (on_root_stage()) {
		if (domain == STEELY_PRIMARY) {
			if (thread == NULL)
				return -EPERM;
			/*
			 * Paranoid: a corner case where userland
			 * fiddles with SIGSHADOW while the target
			 * thread is still waiting to be started.
			 */
			if (xnthread_test_state(thread, XNDORMANT))
				return 0;

			return xnthread_harden() ? : 1;
		}
		return 0;
	}

	/* current_irq_stage != &root_irq_stage */
	if (domain == STEELY_SECONDARY) {
		xnthread_relax(0, 0);
		return 1;
	}

	return 0;
}

static STEELY_SYSCALL(trace, current,
		      (int op, unsigned long a1,
		       unsigned long a2, unsigned long a3))
{
	return -EINVAL;
}

static STEELY_SYSCALL(archcall, current,
		      (unsigned long a1, unsigned long a2,
		       unsigned long a3, unsigned long a4,
		       unsigned long a5))
{
	return xnarch_local_syscall(a1, a2, a3, a4, a5);
}

static STEELY_SYSCALL(get_current, current,
		      (xnhandle_t __user *u_handle))
{
	struct steely_thread *cur = steely_current_thread();

	if (cur == NULL)
		return -EPERM;

	return steely_copy_to_user(u_handle, &cur->handle,
				      sizeof(*u_handle));
}

static STEELY_SYSCALL(backtrace, lostage,
		      (int nr, unsigned long __user *u_backtrace, int reason))
{
	unsigned long backtrace[SIGSHADOW_BACKTRACE_DEPTH];
	int ret;

	/*
	 * In case backtrace() in userland is broken or fails. We may
	 * want to know about this in kernel space however, for future
	 * use.
	 */
	if (nr <= 0)
		return 0;
	/*
	 * We may omit the older frames if we can't store the full
	 * backtrace.
	 */
	if (nr > SIGSHADOW_BACKTRACE_DEPTH)
		nr = SIGSHADOW_BACKTRACE_DEPTH;
	/*
	 * Fetch the backtrace array, filled with PC values as seen
	 * from the relaxing thread in user-space. This can't fail
	 */
	ret = steely_copy_from_user(backtrace, u_backtrace, nr * sizeof(long));
	if (ret)
		return ret;

	xndebug_trace_relax(nr, backtrace, reason);

	return 0;
}

static STEELY_SYSCALL(serialdbg, current,
		      (const char __user *u_msg, int len))
{
	char buf[128];
	int n;

	while (len > 0) {
		n = len;
		if (n > sizeof(buf))
			n = sizeof(buf);
		if (steely_copy_from_user(buf, u_msg, n))
			return -EFAULT;
		raw_printk("%.*s", n, buf);
		u_msg += n;
		len -= n;
	}

	return 0;
}

static STEELY_SYSCALL(mayday, current, (void))
{
	struct pt_regs *regs = task_pt_regs(current);
	struct steely_thread *cur;

	cur = steely_current_thread();
	if (cur == NULL) {
		printk(STEELY_WARNING
		       "MAYDAY received from invalid context %s[%d]\n",
		       current->comm, task_pid_nr(current));
		return -EPERM;
	}

	/*
	 * If the thread was kicked by the watchdog, this syscall we
	 * have just forced on it via the mayday escape will cause it
	 * to relax. See handle_head_syscall().
	 */
	xnarch_fixup_mayday(xnthread_archtcb(cur), regs);

	/*
	 * Return whatever value xnarch_fixup_mayday set for this
	 * register, in order not to undo what xnarch_fixup_mayday
	 * did.
	 */
	return __xn_reg_rval(regs);
}

static void stringify_feature_set(unsigned long fset, char *buf, int size)
{
	unsigned long feature;
	int nc, nfeat;

	*buf = '\0';

	for (feature = 1, nc = nfeat = 0; fset != 0 && size > 0; feature <<= 1) {
		if (fset & feature) {
			nc = ksformat(buf, size, "%s%s",
				      nfeat > 0 ? " " : "",
				      get_feature_label(feature));
			nfeat++;
			size -= nc;
			buf += nc;
			fset &= ~feature;
		}
	}
}

static STEELY_SYSCALL(bind, lostage,
		      (struct steely_bindreq __user *u_breq))
{
	unsigned long featreq, featmis;
	struct steely_bindreq breq;
	struct steely_featinfo *f;
	int abirev;

	if (steely_copy_from_user(&breq, u_breq, sizeof(breq)))
		return -EFAULT;

	f = &breq.feat_ret;
	featreq = breq.feat_req;
	if (!realtime_core_running() && (featreq & __xn_feat_control) == 0)
		return -EPERM;

	/*
	 * Calculate the missing feature set:
	 * kernel_unavailable_set & user_mandatory_set.
	 */
	featmis = (~STEELY_FEAT_DEP & (featreq & STEELY_FEAT_MAN));
	abirev = breq.abi_rev;

	/*
	 * Pass back the supported feature set and the ABI revision
	 * level to user-space.
	 */
	f->feat_all = STEELY_FEAT_DEP;
	stringify_feature_set(STEELY_FEAT_DEP, f->feat_all_s,
			      sizeof(f->feat_all_s));
	f->feat_man = featreq & STEELY_FEAT_MAN;
	stringify_feature_set(f->feat_man, f->feat_man_s,
			      sizeof(f->feat_man_s));
	f->feat_mis = featmis;
	stringify_feature_set(featmis, f->feat_mis_s,
			      sizeof(f->feat_mis_s));
	f->feat_req = featreq;
	stringify_feature_set(featreq, f->feat_req_s,
			      sizeof(f->feat_req_s));
	f->feat_abirev = STEELY_ABI_REV;
	collect_arch_features(f);

	f->vdso_offset = steely_umm_offset(&steely_ppd_get(1)->umm, nkvdso);

	if (steely_copy_to_user(u_breq, &breq, sizeof(breq)))
		return -EFAULT;

	/*
	 * If some mandatory features the user-space code relies on
	 * are missing at kernel level, we cannot go further.
	 */
	if (featmis)
		return -EINVAL;

	if (!check_abi_revision(abirev))
		return -ENOEXEC;

	return steely_bind_core(featreq);
}

static STEELY_SYSCALL(extend, lostage, (unsigned int magic))
{
	return steely_bind_personality(magic);
}

static int StEeLy_ni(void)
{
	return -ENOSYS;
}

/*
 * We have a single syscall table for all ABI models, i.e. 64bit
 * native + 32bit) or plain 32bit. In the former case, we may want to
 * support several models with a single build (e.g. ia32 and x32 for
 * x86_64).
 *
 * The syscall table is set up in a single step, based on three
 * subsequent sources of initializers:
 *
 * - first, all syscall entries are defaulted to a placeholder
 * returning -ENOSYS, as the table may be sparse.
 *
 * - then __STEELY_CALL_ENTRY() produces a native call entry
 * (e.g. pure 64bit call handler for a 64bit architecture), optionally
 * followed by a set of 32bit syscall entries offset by an
 * arch-specific base index, which default to the native calls. These
 * nitty-gritty details are defined by
 * <asm/steely/syscall32.h>. 32bit architectures - or 64bit ones for
 * which we don't support any 32bit ABI model - will simply define
 * __STEELY_CALL32_ENTRY() as an empty macro.
 *
 * - finally, 32bit thunk entries are generated per-architecture, by
 * including <asm/steely/syscall32-table.h>, overriding the default
 * handlers installed during the previous step.
 *
 * For instance, with CONFIG_X86_X32 support enabled in an x86_64
 * kernel, sc_steely_mq_timedreceive would appear twice in the table,
 * as:
 *
 * [sc_steely_mq_timedreceive] = steely_mq_timedreceive,
 * ...
 * [sc_steely_mq_timedreceive + __STEELY_X32_BASE] = steely32x_mq_timedreceive,
 *
 * steely32x_mq_timedreceive() would do the required thunking for
 * dealing with the 32<->64bit conversion of arguments. On the other
 * hand, sc_steely_sched_yield - which do not require any thunk -
 * would also appear twice, but both entries would point at the native
 * syscall implementation:
 *
 * [sc_steely_sched_yield] = steely_sched_yield,
 * ...
 * [sc_steely_sched_yield + __STEELY_X32_BASE] = steely_sched_yield,
 *
 * Accordingly, applications targeting the x32 model (-mx32) issue
 * syscalls in the range [__STEELY_X32_BASE..__STEELY_X32_BASE +
 * __NR_STEELY_SYSCALLS-1], whilst native (32/64bit) ones issue
 * syscalls in the range [0..__NR_STEELY_SYSCALLS-1].
 *
 * In short, this is an incremental process where the arch-specific
 * code can override the 32bit syscall entries, pointing at the thunk
 * routines it may need for handing 32bit calls over their respective
 * 64bit implementation.
 *
 * By convention, there is NO pure 32bit syscall, which means that
 * each 32bit syscall defined by a compat ABI interface MUST match a
 * native (64bit) syscall. This is important as we share the call
 * modes (i.e. __xn_exec_ bits) between all ABI models.
 *
 * --rpm
 */
#define __syshand__(__name)	((steely_syshand)(StEeLy_ ## __name))

#define __STEELY_NI	__syshand__(ni)

#define __STEELY_CALL_NI				\
	[0 ... __NR_STEELY_SYSCALLS-1] = __STEELY_NI,	\
	__STEELY_CALL32_INITHAND(__STEELY_NI)

#define __STEELY_CALL_NFLAGS				\
	[0 ... __NR_STEELY_SYSCALLS-1] = 0,		\
	__STEELY_CALL32_INITMODE(0)

#define __STEELY_CALL_ENTRY(__name)				\
	[sc_steely_ ## __name] = __syshand__(__name),		\
	__STEELY_CALL32_ENTRY(__name, __syshand__(__name))

#define __STEELY_MODE(__name, __mode)	\
	[sc_steely_ ## __name] = __xn_exec_##__mode,

#ifdef CONFIG_STEELY_ARCH_SYS3264
#include <steely/syscall32.h>
#endif

#include "syscall_entries.h"

static const steely_syshand steely_syscalls[] = {
	__STEELY_CALL_NI
	__STEELY_CALL_ENTRIES
#ifdef CONFIG_STEELY_ARCH_SYS3264
#include <asm/steely/syscall32-table.h>
#endif
};

static const int steely_sysmodes[] = {
	__STEELY_CALL_NFLAGS
	__STEELY_CALL_MODES
};

static inline int allowed_syscall(struct steely_process *process,
				  struct steely_thread *thread,
				  int sysflags, int nr)
{
	if (nr == sc_steely_bind)
		return 1;
	
	if (process == NULL)
		return 0;

	if (thread == NULL && (sysflags & __xn_exec_shadow))
		return 0;

	return cap_raised(current_cap(), CAP_SYS_NICE);
}

static int handle_head_syscall(struct irq_stage *stage, struct pt_regs *regs)
{
	struct steely_process *process;
	int switched, sigs, sysflags;
	struct steely_thread *thread;
	steely_syshand handler;
	struct task_struct *p;
	unsigned int nr, code;
	long ret;

	if (!__xn_syscall_p(regs))
		goto linux_syscall;

	thread = steely_current_thread();
	code = __xn_syscall(regs);
	if (code >= ARRAY_SIZE(steely_syscalls))
		goto bad_syscall;

	nr = code & (__NR_STEELY_SYSCALLS - 1);

	trace_steely_head_sysentry(thread, code);

	process = steely_current_process();
	if (process == NULL) {
		process = steely_search_process(current->mm);
		steely_set_process(process);
	}

	handler = steely_syscalls[code];
	sysflags = steely_sysmodes[nr];

	/*
	 * Executing Steely services requires CAP_SYS_NICE, except for
	 * sc_steely_bind which does its own checks.
	 */
	if (unlikely(!allowed_syscall(process, thread, sysflags, nr))) {
		/*
		 * Exclude get_current from reporting, it is used to probe the
		 * execution context.
		 */
		if (STEELY_DEBUG(STEELY) && nr != sc_steely_get_current)
			printk(STEELY_WARNING
			       "syscall <%d> denied to %s[%d]\n",
			       nr, current->comm, task_pid_nr(current));
		__xn_error_return(regs, -EPERM);
		goto ret_handled;
	}

	if (sysflags & __xn_exec_conforming)
		/*
		 * If the conforming exec bit is set, turn the exec
		 * bitmask for the syscall into the most appropriate
		 * setup for the caller, i.e. Steely domain for
		 * shadow threads, Linux otherwise.
		 */
		sysflags |= (thread ? __xn_exec_histage : __xn_exec_lostage);

	/*
	 * Here we have to dispatch the syscall execution properly,
	 * depending on:
	 *
	 * o Whether the syscall must be run into the Linux or Steely
	 * domain, or indifferently in the current Steely domain.
	 *
	 * o Whether the caller currently runs in the Linux or Steely
	 * domain.
	 */
restart:
	/*
	 * Process adaptive syscalls by restarting them in the
	 * opposite domain upon receiving -ENOSYS from the syscall
	 * handler.
	 */
	switched = 0;
	if (sysflags & __xn_exec_lostage) {
		/*
		 * The syscall must run from the Linux domain.
		 */
		if (stage == &steely_pipeline.stage) {
			/*
			 * Request originates from the Steely domain:
			 * relax the caller then invoke the syscall
			 * handler right after.
			 */
			xnthread_relax(1, SIGDEBUG_MIGRATE_SYSCALL);
			switched = 1;
		} else
			/*
			 * Request originates from the Linux domain:
			 * propagate the event to our Linux-based
			 * handler, so that the syscall is executed
			 * from there.
			 */
			return SYSCALL_PROPAGATE;
	} else if (sysflags & (__xn_exec_histage | __xn_exec_current)) {
		/*
		 * Syscall must run either from the Steely domain, or
		 * from the calling domain.
		 *
		 * If the request originates from the Linux domain,
		 * hand it over to our secondary-mode dispatcher.
		 * Otherwise, invoke the syscall handler immediately.
		 */
		if (stage != &steely_pipeline.stage)
			return SYSCALL_PROPAGATE;
	}

	/*
	 * 'thread' has to be valid from that point: all syscalls
	 * regular threads may call have been pipelined to the root
	 * handler (lostage ones), or rejected by allowed_syscall().
	 */

	ret = handler(__xn_reg_arglist(regs));
	if (ret == -ENOSYS && (sysflags & __xn_exec_adaptive)) {
		if (switched) {
			ret = xnthread_harden();
			if (ret) {
				switched = 0;
				goto done;
			}
		} else /* Mark the primary -> secondary transition. */
			xnthread_set_localinfo(thread, XNDESCENT);
		sysflags ^=
		    (__xn_exec_lostage | __xn_exec_histage |
		     __xn_exec_adaptive);
		goto restart;
	}
done:
	__xn_status_return(regs, ret);
	sigs = 0;
	if (!xnsched_root_p()) {
		p = current;
		if (signal_pending(p) ||
		    xnthread_test_info(thread, XNKICKED)) {
			sigs = 1;
			prepare_for_signal(p, thread, regs, sysflags);
		} else if (xnthread_test_state(thread, XNWEAK) &&
			   thread->res_count == 0) {
			if (switched)
				switched = 0;
			else
				xnthread_relax(0, 0);
		}
	}
	if (!sigs && (sysflags & __xn_exec_switchback) && switched)
		/* -EPERM will be trapped later if needed. */
		xnthread_harden();

ret_handled:
	/* Update the stats and userland-visible state. */
	if (thread) {
		xnthread_clear_localinfo(thread, XNDESCENT);
		xnstat_counter_inc(&thread->stat.xsc);
		xnthread_sync_window(thread);
	}

	trace_steely_head_sysexit(thread, __xn_reg_rval(regs));

	return SYSCALL_STOP;

linux_syscall:
	if (xnsched_root_p())
		/*
		 * The call originates from the Linux domain, either
		 * from a relaxed shadow or from a regular Linux task;
		 * just propagate the event so that we will fall back
		 * to handle_root_syscall().
		 */
		return SYSCALL_PROPAGATE;

	/*
	 * From now on, we know that we have a valid shadow thread
	 * pointer.
	 *
	 * The current syscall will eventually fall back to the Linux
	 * syscall handler if our Linux domain handler does not
	 * intercept it. Before we let it go, ensure that the current
	 * thread has properly entered the Linux domain.
	 */
	xnthread_relax(1, SIGDEBUG_MIGRATE_SYSCALL);

	return SYSCALL_PROPAGATE;

bad_syscall:
	printk(STEELY_WARNING "bad syscall <%#lx>\n", __xn_syscall(regs));

	__xn_error_return(regs, -ENOSYS);

	return SYSCALL_STOP;
}

static int handle_root_syscall(struct irq_stage *stage, struct pt_regs *regs)
{
	int sysflags, switched, sigs;
	struct steely_thread *thread;
	steely_syshand handler;
	struct task_struct *p;
	unsigned int nr, code;
	long ret;

	/*
	 * Catch cancellation requests pending for user shadows
	 * running mostly in secondary mode, i.e. XNWEAK. In that
	 * case, we won't run prepare_for_signal() that frequently, so
	 * check for cancellation here.
	 */
	xnthread_test_cancel();

	if (!__xn_syscall_p(regs))
		/* Fall back to Linux syscall handling. */
		return SYSCALL_PROPAGATE;

	thread = steely_current_thread();
	/* code has already been checked in the head domain handler. */
	code = __xn_syscall(regs);
	nr = code & (__NR_STEELY_SYSCALLS - 1);

	trace_steely_root_sysentry(thread, code);

	/* Processing a Steely syscall. */

	handler = steely_syscalls[code];
	sysflags = steely_sysmodes[nr];

	if (thread && (sysflags & __xn_exec_conforming))
		sysflags |= __xn_exec_histage;
restart:
	/*
	 * Process adaptive syscalls by restarting them in the
	 * opposite domain upon receiving -ENOSYS from the syscall
	 * handler.
	 */
	switched = 0;
	if (sysflags & __xn_exec_histage) {
		/*
		 * This request originates from the Linux domain but
		 * should run into the Steely domain: harden the
		 * caller before invoking the syscall handler.
		 */
		ret = xnthread_harden();
		if (ret) {
			__xn_error_return(regs, ret);
			goto ret_handled;
		}
		switched = 1;
	} else {
		/*
		 * We want to run the syscall in the current Linux
		 * domain. This is a slow path, so proceed with any
		 * pending schedparam update on the fly.
		 */
		if (thread)
			xnthread_propagate_schedparam(thread);
	}

	ret = handler(__xn_reg_arglist(regs));
	if (ret == -ENOSYS && (sysflags & __xn_exec_adaptive)) {
		sysflags ^= __xn_exec_histage;
		if (switched) {
			xnthread_relax(1, SIGDEBUG_MIGRATE_SYSCALL);
			sysflags &= ~__xn_exec_adaptive;
			 /* Mark the primary -> secondary transition. */
			xnthread_set_localinfo(thread, XNDESCENT);
		}
		goto restart;
	}

	__xn_status_return(regs, ret);

	sigs = 0;
	if (!xnsched_root_p()) {
		/*
		 * We may have gained a shadow TCB from the syscall we
		 * just invoked, so make sure to fetch it.
		 */
		thread = steely_current_thread();
		p = current;
		if (signal_pending(p)) {
			sigs = 1;
			prepare_for_signal(p, thread, regs, sysflags);
		} else if (xnthread_test_state(thread, XNWEAK) &&
			   thread->res_count == 0)
			sysflags |= __xn_exec_switchback;
	}
	if (!sigs && (sysflags & __xn_exec_switchback)
	    && (switched || xnsched_primary_p()))
		xnthread_relax(0, 0);

ret_handled:
	/* Update the stats and userland-visible state. */
	if (thread) {
		xnthread_clear_localinfo(thread, XNDESCENT);
		xnstat_counter_inc(&thread->stat.xsc);
		xnthread_sync_window(thread);
	}

	trace_steely_root_sysexit(thread, __xn_reg_rval(regs));

	return SYSCALL_STOP;
}

int dovetail_syscall_hook(struct irq_stage *stage, struct pt_regs *regs)
{
	if (unlikely(on_root_stage()))
		return handle_root_syscall(stage, regs);

	return handle_head_syscall(stage, regs);
}

int dovetail_fastcall_hook(struct pt_regs *regs)
{
	int ret;

	ret = handle_head_syscall(&steely_pipeline.stage, regs);
	STEELY_BUG_ON(STEELY, ret == SYSCALL_PROPAGATE);

	return ret;
}

long steely_restart_syscall_placeholder(struct restart_block *param)
{
	return -EINVAL;
}
