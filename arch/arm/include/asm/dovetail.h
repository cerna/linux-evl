/*
 * arch/arm/include/asm/dovetail.h
 *
 * Copyright (C) 2016 Philippe Gerum.
 */
#ifndef _ASM_ARM_DOVETAIL_H
#define _ASM_ARM_DOVETAIL_H

/* ARM traps */
#define IPIPE_TRAP_ACCESS	 0	/* Data or instruction access exception */
#define IPIPE_TRAP_SECTION	 1	/* Section fault */
#define IPIPE_TRAP_DABT		 2	/* Generic data abort */
#define IPIPE_TRAP_UNKNOWN	 3	/* Unknown exception */
#define IPIPE_TRAP_BREAK	 4	/* Instruction breakpoint */
#define IPIPE_TRAP_FPU		 5	/* Floating point exception */
#define IPIPE_TRAP_VFP		 6	/* VFP floating point exception */
#define IPIPE_TRAP_UNDEFINSTR	 7	/* Undefined instruction */
#define IPIPE_TRAP_ALIGNMENT	 8	/* Unaligned access exception */
#define IPIPE_TRAP_MAYDAY        9	/* Internal recovery trap */
#define IPIPE_NR_FAULTS         10

#define dovetail_get_active_mm()	__this_cpu_read(irq_pipeline.active_mm)

#define IPIPE_TSC_TYPE_NONE	   		0
#define IPIPE_TSC_TYPE_FREERUNNING 		1
#define IPIPE_TSC_TYPE_DECREMENTER 		2
#define IPIPE_TSC_TYPE_FREERUNNING_COUNTDOWN	3
#define IPIPE_TSC_TYPE_FREERUNNING_TWICE	4
#define IPIPE_TSC_TYPE_FREERUNNING_ARCH		5

/* tscinfo, exported to user-space */
struct __ipipe_tscinfo {
	unsigned type;
	unsigned freq;
	unsigned long counter_vaddr;
	union {
		struct {
			unsigned long counter_paddr;
			unsigned long long mask;
		};
		struct {
			unsigned *counter; /* Hw counter physical address */
			unsigned long long mask; /* Significant bits in the hw counter. */
			unsigned long long *tsc; /* 64 bits tsc value. */
		} fr;
		struct {
			unsigned *counter; /* Hw counter physical address */
			unsigned long long mask; /* Significant bits in the hw counter. */
			unsigned *last_cnt; /* Counter value when updating
						tsc value. */
			unsigned long long *tsc; /* 64 bits tsc value. */
		} dec;
	} u;
};

struct ipipe_arch_sysinfo {
	struct __ipipe_tscinfo tsc;
};

extern char __ipipe_tsc_area[];
void __ipipe_mach_get_tscinfo(struct __ipipe_tscinfo *info);
unsigned long long __ipipe_tsc_get(void) __attribute__((long_call));
void __ipipe_tsc_register(struct __ipipe_tscinfo *info);
void __ipipe_tsc_update(void);

#endif /* _ASM_ARM_DOVETAIL_H */
