/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * ARM port
 *   Copyright (C) 2005 Stelian Pop
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */
#ifndef _STEELY_ARM_ASM_UAPI_SYSCALL_H
#define _STEELY_ARM_ASM_UAPI_SYSCALL_H

#define __xn_syscode(__nr)	(__STEELY_SYSCALL_BIT | (__nr))

#define STEELY_SYSARCH_TSCINFO      4

#ifndef __KERNEL__
#if defined(__thumb__) || defined(__ARM_EABI__)
#define __NR_SYSCALL_BASE	0
#define __ARM_NR_BASE		(__NR_SYSCALL_BASE+0x0f0000)
#else
#define __NR_SYSCALL_BASE	0x900000
#define __ARM_NR_BASE		(__NR_SYSCALL_BASE+0x0f0000)
#endif
#define __ARM_NR_dovetail	(__ARM_NR_BASE+66)
#endif

#endif /* !_STEELY_ARM_ASM_UAPI_SYSCALL_H */
