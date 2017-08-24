/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_IRQFLAGS_H
#define __ASM_IRQFLAGS_H

#ifdef __KERNEL__

#include <asm/ptrace.h>

#define IRQMASK_I_BIT	PSR_I_BIT
#define IRQMASK_I_POS	7
/*
 * I-bit's left shift when combined with the IRQ pipeline's root stall
 * bit, which occupies the original I-bit position.
 */
#define IRQMASK_I_SHIFT	1

/*
 * CPU interrupt mask handling.
 */
static inline unsigned long native_irq_save(void)
{
	unsigned long flags;
	asm volatile(
		"mrs	%0, daif		// native_irq_save\n"
		"msr	daifset, #2"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

static inline void native_irq_enable(void)
{
	asm volatile(
		"msr	daifclr, #2		// native_irq_enable"
		:
		:
		: "memory");
}

static inline void native_irq_disable(void)
{
	asm volatile(
		"msr	daifset, #2		// native_irq_disable"
		:
		:
		: "memory");
}

#define local_fiq_enable()	asm("msr	daifclr, #1" : : : "memory")
#define local_fiq_disable()	asm("msr	daifset, #1" : : : "memory")

#define local_async_enable()	asm("msr	daifclr, #4" : : : "memory")
#define local_async_disable()	asm("msr	daifset, #4" : : : "memory")

/*
 * Save the current interrupt enable state.
 */
static inline unsigned long native_save_flags(void)
{
	unsigned long flags;
	asm volatile(
		"mrs	%0, daif		// native_save_flags"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

/*
 * restore saved IRQ state
 */
static inline void native_irq_restore(unsigned long flags)
{
	asm volatile(
		"msr	daif, %0		// native_irq_restore"
	:
	: "r" (flags)
	: "memory");
}

static inline int native_irqs_disabled_flags(unsigned long flags)
{
	return flags & PSR_I_BIT;
}

static inline bool native_irqs_disabled(void)
{
	unsigned long flags = native_save_flags();
	return native_irqs_disabled_flags(flags);
}

#include <asm/irq_pipeline.h>

/*
 * save and restore debug state
 */
#define local_dbg_save(flags)						\
	do {								\
		typecheck(unsigned long, flags);			\
		asm volatile(						\
		"mrs    %0, daif		// local_dbg_save\n"	\
		"msr    daifset, #8"					\
		: "=r" (flags) : : "memory");				\
	} while (0)

#define local_dbg_restore(flags)					\
	do {								\
		typecheck(unsigned long, flags);			\
		asm volatile(						\
		"msr    daif, %0		// local_dbg_restore\n"	\
		: : "r" (flags) : "memory");				\
	} while (0)

#endif
#endif
