/*
 * Copyright (C) 2005 Stelian Pop
 * Copyright (C) 2010 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
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
#include <asm/steely/machine.h>
#include <asm/steely/syscall.h>
#include <uapi/asm/steely/tsc.h>

int xnarch_local_syscall(unsigned long a1, unsigned long a2,
			 unsigned long a3, unsigned long a4,
			 unsigned long a5)
{
	struct __ipipe_tscinfo *p;
	struct __xn_tscinfo info;

	if (a1 != STEELY_SYSARCH_TSCINFO)
		return -EINVAL;
	
	p = &steely_pipeline.clock_data.arch.tsc;
	
	switch (p->type) {
	case IPIPE_TSC_TYPE_DECREMENTER:
		info.counter = p->u.dec.counter;
		break;
	case IPIPE_TSC_TYPE_NONE:
		return -ENOSYS;
	default:
		info.counter = p->u.fr.counter;
		break;
	}

	return steely_copy_to_user((void *)a2, &info, sizeof(info));
}
