/*   -*- linux-c -*-
 *   arch/arm/kernel/dovetail.c
 *
 *   Copyright (C) 2017 Philippe Gerum.
 */
#include <linux/dovetail.h>

void arch_dovetail_get_hrclock(struct dovetail_hrclock_data *hrd)
{
	hrd->hrclock_freq = __ipipe_hrclock_freq;
	hrd->hrclock_name = "ipipe_tsc";
	__ipipe_mach_get_tscinfo(&hrd->arch.tsc);
}
