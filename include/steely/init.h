/*
 * Copyright (C) 2013 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_KERNEL_INIT_H
#define _STEELY_KERNEL_INIT_H

#include <linux/atomic.h>
#include <linux/notifier.h>
#include <uapi/steely/corectl.h>

extern atomic_t steely_runstate;

static inline enum steely_run_states realtime_core_state(void)
{
	return atomic_read(&steely_runstate);
}

static inline int realtime_core_enabled(void)
{
	return atomic_read(&steely_runstate) != STEELY_STATE_DISABLED;
}

static inline int realtime_core_running(void)
{
	return atomic_read(&steely_runstate) == STEELY_STATE_RUNNING;
}

static inline void set_realtime_core_state(enum steely_run_states state)
{
	atomic_set(&steely_runstate, state);
}

void steely_add_state_chain(struct notifier_block *nb);

void steely_remove_state_chain(struct notifier_block *nb);

void steely_call_state_chain(enum steely_run_states newstate);

#endif /* !_STEELY_KERNEL_INIT_H_ */
