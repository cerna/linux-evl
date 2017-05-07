/*
 * Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org>.
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
#ifndef _STEELY_KERNEL_ASSERT_H
#define _STEELY_KERNEL_ASSERT_H

#include <linux/kconfig.h>
#include <steely/ancillaries.h>

#define STEELY_INFO	KERN_INFO    "[Steely] "
#define STEELY_WARNING	KERN_WARNING "[Steely] "
#define STEELY_ERR	KERN_ERR     "[Steely] "

#define STEELY_DEBUG(__subsys)				\
	IS_ENABLED(CONFIG_STEELY_DEBUG_##__subsys)
#define STEELY_ASSERT(__subsys, __cond)			\
	(!WARN_ON(STEELY_DEBUG(__subsys) && !(__cond)))
#define STEELY_BUG(__subsys)				\
	BUG_ON(STEELY_DEBUG(__subsys))
#define STEELY_BUG_ON(__subsys, __cond)			\
	BUG_ON(STEELY_DEBUG(__subsys) && (__cond))
#define STEELY_WARN(__subsys, __cond, __fmt...)		\
	WARN(STEELY_DEBUG(__subsys) && (__cond), __fmt)
#define STEELY_WARN_ON(__subsys, __cond)			\
	WARN_ON(STEELY_DEBUG(__subsys) && (__cond))
#define STEELY_WARN_ON_ONCE(__subsys, __cond)		\
	WARN_ON_ONCE(STEELY_DEBUG(__subsys) && (__cond))
#ifdef CONFIG_SMP
#define STEELY_BUG_ON_SMP(__subsys, __cond)		\
	STEELY_BUG_ON(__subsys, __cond)
#define STEELY_WARN_ON_SMP(__subsys, __cond)		\
	STEELY_WARN_ON(__subsys, __cond)
#define STEELY_WARN_ON_ONCE_SMP(__subsys, __cond)		\
	STEELY_WARN_ON_ONCE(__subsys, __cond)
#else
#define STEELY_BUG_ON_SMP(__subsys, __cond)		\
	do { } while (0)
#define STEELY_WARN_ON_SMP(__subsys, __cond)		\
	do { } while (0)
#define STEELY_WARN_ON_ONCE_SMP(__subsys, __cond)		\
	do { } while (0)
#endif

#define primary_mode_only()	STEELY_BUG_ON(CONTEXT, on_root_stage())
#define secondary_mode_only()	STEELY_BUG_ON(CONTEXT, !on_root_stage())
#define interrupt_only()	STEELY_BUG_ON(CONTEXT, !xnsched_interrupt_p())
#define realtime_cpu_only()	STEELY_BUG_ON(CONTEXT, !xnsched_supported_cpu(raw_smp_processor_id()))
#define thread_only()		STEELY_BUG_ON(CONTEXT, xnsched_interrupt_p())
#define irqoff_only()		STEELY_BUG_ON(CONTEXT, hard_irqs_disabled() == 0)
#if STEELY_DEBUG(LOCKING)
#define atomic_only()		STEELY_BUG_ON(CONTEXT, (xnlock_is_owner(&nklock) && hard_irqs_disabled()) == 0)
#define preemptible_only()	STEELY_BUG_ON(CONTEXT, xnlock_is_owner(&nklock) || hard_irqs_disabled())
#else
#define atomic_only()		STEELY_BUG_ON(CONTEXT, hard_irqs_disabled() == 0)
#define preemptible_only()	STEELY_BUG_ON(CONTEXT, hard_irqs_disabled() != 0)
#endif

#endif /* !_STEELY_KERNEL_ASSERT_H */
