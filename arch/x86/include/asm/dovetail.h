/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 Philippe Gerum.
 */
#ifndef _ASM_X86_DOVETAIL_H
#define _ASM_X86_DOVETAIL_H

#ifndef __ASSEMBLY__

void fpu__suspend_inband(void);
void fpu__resume_inband(void);

static inline
void arch_dovetail_switch_prepare(bool leave_inband)
{
	if (leave_inband)
		fpu__suspend_inband();
}

static inline
void arch_dovetail_switch_finish(bool enter_inband)
{
	if (enter_inband)
		fpu__resume_inband();
}

#endif

#endif /* _ASM_X86_DOVETAIL_H */
