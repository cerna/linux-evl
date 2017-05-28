/*
 *   Copyright (C) 2005 Stelian Pop
 *
 *   Xenomai is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge MA 02139, USA; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   Xenomai is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#include <linux/mm.h>
#include <asm/cacheflush.h>
#include <asm/steely/machine.h>

#define CALIBRATION_LOOPS 10

static void mach_arm_prefault(struct vm_area_struct *vma)
{
	unsigned long addr;
	unsigned int flags;

	if ((vma->vm_flags & VM_MAYREAD)) {
		flags = (vma->vm_flags & VM_MAYWRITE) ? FAULT_FLAG_WRITE : 0;
		for (addr = vma->vm_start;
		     addr != vma->vm_end; addr += PAGE_SIZE)
			handle_mm_fault(vma, addr, flags);
	}
}

struct steely_machine steely_machine = {
	.name = "arm",
	.init = NULL,
	.late_init = NULL,
	.cleanup = NULL,
	.prefault = mach_arm_prefault,
};
