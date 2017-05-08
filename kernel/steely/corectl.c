/*
 * Copyright (C) 2016 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/irq_pipeline.h>
#include <linux/kconfig.h>
#include <linux/atomic.h>
#include <linux/printk.h>
#include <steely/init.h>
#include <steely/thread.h>
#include <steely/coreclk.h>
#include <steely/version.h>
#include <steely/corectl.h>
#include <asm/steely/syscall.h>

static BLOCKING_NOTIFIER_HEAD(config_notifier_list);

static int do_conf_option(int option, void __user *u_buf, size_t u_bufsz)
{
	struct steely_config_vector vec;
	int ret, val = 0;

	if (option <= _CC_STEELY_GET_CORE_STATUS && u_bufsz < sizeof(val))
		return -EINVAL;

	switch (option) {
	case _CC_STEELY_GET_VERSION:
		val = STEELY_VERSION_CODE;
		break;
	case _CC_STEELY_GET_NR_PIPES:
#ifdef CONFIG_STEELY_PIPE
		val = CONFIG_STEELY_PIPE_NRDEV;
#endif
		break;
	case _CC_STEELY_GET_NR_TIMERS:
		val = CONFIG_STEELY_NRTIMERS;
		break;
	case _CC_STEELY_GET_POLICIES:
		val = _CC_STEELY_SCHED_FIFO|_CC_STEELY_SCHED_RR;
		if (IS_ENABLED(CONFIG_STEELY_SCHED_WEAK))
			val |= _CC_STEELY_SCHED_WEAK;
		if (IS_ENABLED(CONFIG_STEELY_SCHED_SPORADIC))
			val |= _CC_STEELY_SCHED_SPORADIC;
		if (IS_ENABLED(CONFIG_STEELY_SCHED_QUOTA))
			val |= _CC_STEELY_SCHED_QUOTA;
		if (IS_ENABLED(CONFIG_STEELY_SCHED_TP))
			val |= _CC_STEELY_SCHED_TP;
		break;
	case _CC_STEELY_GET_DEBUG:
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_STEELY))
			val |= _CC_STEELY_DEBUG_ASSERT;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_CONTEXT))
			val |= _CC_STEELY_DEBUG_CONTEXT;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_LOCKING))
			val |= _CC_STEELY_DEBUG_LOCKING;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_USER))
			val |= _CC_STEELY_DEBUG_USER;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_MUTEX_RELAXED))
			val |= _CC_STEELY_DEBUG_MUTEX_RELAXED;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_MUTEX_SLEEP))
			val |= _CC_STEELY_DEBUG_MUTEX_SLEEP;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_POSIX_SYNCHRO))
			val |= _CC_STEELY_DEBUG_POSIX_SYNCHRO;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_LEGACY))
			val |= _CC_STEELY_DEBUG_LEGACY;
		if (IS_ENABLED(CONFIG_STEELY_DEBUG_TRACE_RELAX))
			val |= _CC_STEELY_DEBUG_TRACE_RELAX;
		if (IS_ENABLED(CONFIG_STEELY_RTNET_CHECKED))
			val |= _CC_STEELY_DEBUG_NET;
		break;
	case _CC_STEELY_GET_WATCHDOG:
#ifdef CONFIG_STEELY_WATCHDOG
		val = CONFIG_STEELY_WATCHDOG_TIMEOUT;
#endif
		break;
	case _CC_STEELY_GET_CORE_STATUS:
		val = realtime_core_state();
		break;
	default:
		if (!on_root_stage())
			/* Switch to secondary mode first. */
			return -ENOSYS;
		vec.u_buf = u_buf;
		vec.u_bufsz = u_bufsz;
		ret = blocking_notifier_call_chain(&config_notifier_list,
						   option, &vec);
		if (ret == NOTIFY_DONE)
			return -EINVAL; /* Nobody cared. */
		return notifier_to_errno(ret);
	}

	ret = steely_copy_to_user(u_buf, &val, sizeof(val));

	return ret ? -EFAULT : 0;
}

static int stop_services(const void __user *u_buf, size_t u_bufsz)
{
	const u32 final_grace_period = 3; /* seconds */
	enum steely_run_states state;
	__u32 grace_period;
	int ret;

	/*
	 * XXX: we don't have any syscall for unbinding a thread from
	 * the Steely core, so we deny real-time threads from stopping
	 * Steely services. i.e. _CC_STEELY_STOP_CORE must be issued
	 * from a plain regular linux thread.
	 */
	if (steely_current_thread())
		return -EPERM;

	if (u_bufsz != sizeof(__u32))
		return -EINVAL;

	ret = steely_copy_from_user(&grace_period,
				    u_buf, sizeof(grace_period));
	if (ret)
		return ret;

	state = atomic_cmpxchg(&steely_runstate,
			       STEELY_STATE_RUNNING,
			       STEELY_STATE_TEARDOWN);
	switch (state) {
	case STEELY_STATE_STOPPED:
		break;
	case STEELY_STATE_RUNNING:
		/* Kill user threads. */
		ret = xnthread_killall(grace_period, XNUSER);
		if (ret) {
			set_realtime_core_state(state);
			return ret;
		}
		steely_call_state_chain(STEELY_STATE_TEARDOWN);
		/* Kill lingering RTDM tasks. */
		ret = xnthread_killall(final_grace_period, 0);
		if (ret == -EAGAIN)
			printk(STEELY_WARNING "some RTDM tasks won't stop");
		xnclock_core_release();
		set_realtime_core_state(STEELY_STATE_STOPPED);
		printk(STEELY_INFO "services stopped\n");
		break;
	default:
		ret = -EINPROGRESS;
	}

	return ret;
}

static int start_services(void)
{
	enum steely_run_states state;
	int ret = 0;

	state = atomic_cmpxchg(&steely_runstate,
			       STEELY_STATE_STOPPED,
			       STEELY_STATE_WARMUP);
	switch (state) {
	case STEELY_STATE_RUNNING:
		break;
	case STEELY_STATE_STOPPED:
		ret = xnclock_core_takeover();
		if (ret) {
			atomic_set(&steely_runstate, STEELY_STATE_STOPPED);
			return ret;
		}
		steely_call_state_chain(STEELY_STATE_WARMUP);
		set_realtime_core_state(STEELY_STATE_RUNNING);
		printk(STEELY_INFO "services started\n");
		break;
	default:
		ret = -EINPROGRESS;
	}

	return ret;
}

STEELY_SYSCALL(corectl, probing,
	       (int request, void __user *u_buf, size_t u_bufsz))
{
	int ret;
	
	switch (request) {
	case _CC_STEELY_STOP_CORE:
		ret = stop_services(u_buf, u_bufsz);
		break;
	case _CC_STEELY_START_CORE:
		ret = start_services();
		break;
	default:
		ret = do_conf_option(request, u_buf, u_bufsz);
	}
	
	return ret;
}

void steely_add_config_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_register(&config_notifier_list, nb);
}
EXPORT_SYMBOL_GPL(steely_add_config_chain);

void steely_remove_config_chain(struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&config_notifier_list, nb);
}
EXPORT_SYMBOL_GPL(steely_remove_config_chain);
