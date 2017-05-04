/*
 * Copyright (C) 2009 Wolfgang Mauerer <wolfgang.mauerer@siemens.com>.
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
#ifndef _STEELY_KERNEL_VDSO_H
#define _STEELY_KERNEL_VDSO_H

#include <linux/time.h>
#include <asm/barrier.h>
#include <asm/atomic.h>
#include <asm/processor.h>
#include <uapi/steely/kernel/vdso.h>

/*
 * Define the available feature set here. We have no feature defined
 * for now.
 */
#define XNVDSO_FEATURES 0

extern struct xnvdso *nkvdso;

#endif /* _STEELY_KERNEL_VDSO_H */
