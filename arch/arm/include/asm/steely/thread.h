/*
 * Copyright (C) 2005 Stelian Pop
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
#ifndef _STEELY_ARM_ASM_THREAD_H
#define _STEELY_ARM_ASM_THREAD_H

#include <asm-generic/steely/thread.h>

struct xnarchtcb {
	struct xntcb core;
	struct {
		unsigned long pc;
		unsigned long r0;
#ifdef __ARM_EABI__
		unsigned long r7;
#endif
#ifdef CONFIG_ARM_THUMB
		unsigned long psr;
#endif
	} mayday;
};

#define xnarch_fault_regs(d)	((d)->regs)
#define xnarch_fault_trap(d)	((d)->exception)
#define xnarch_fault_code(d)	(0)
#define xnarch_fault_pc(d)	((d)->regs->ARM_pc - (thumb_mode((d)->regs) ? 2 : 4)) /* XXX ? */

#define xnarch_fault_pf_p(d)	((d)->exception == IPIPE_TRAP_ACCESS)
#define xnarch_fault_bp_p(d)	((current->ptrace & PT_PTRACED) &&	\
				 ((d)->exception == IPIPE_TRAP_BREAK ||	\
				  (d)->exception == IPIPE_TRAP_UNDEFINSTR))

#define xnarch_fault_notify(d) (!xnarch_fault_bp_p(d))

void xnarch_switch_to(struct xnthread *out, struct xnthread *in);

static inline int xnarch_escalate(void)
{
	if (on_root_stage()) {
		irq_pipeline_inject(steely_pipeline.escalate_virq);
		return 1;
	}

	return 0;
}

static inline void xnarch_init_root_tcb(struct xnthread *thread) { }
static inline void xnarch_init_shadow_tcb(struct xnthread *thread) { }
static inline void xnarch_enter_root(struct xnthread *root) { }
static inline void xnarch_leave_root(struct xnthread *root) { }

#endif /* !_STEELY_ARM_ASM_THREAD_H */
