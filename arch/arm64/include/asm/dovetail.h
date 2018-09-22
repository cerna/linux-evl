/*
 * arch/arm/include/asm64/dovetail.h
 *
 * Copyright (C) 2018 Philippe Gerum.
 */
#ifndef _ASM_ARM64_DOVETAIL_H
#define _ASM_ARM64_DOVETAIL_H

/* ARM64 traps */
#define ARM64_TRAP_ACCESS	0	/* Data or instruction access exception */
#define ARM64_TRAP_ABRT		1	/* Memory/alignment abort */
#define ARM64_TRAP_SEA		2	/* Synchronous external abort */
#define ARM64_TRAP_DEBUG	3	/* Debug trap */
#define ARM64_TRAP_UNDI		4	/* Undefined instruction */
#define ARM64_TRAP_UNDSE	5	/* Undefined synchronous exception */
#define ARM64_TRAP_FPE		6	/* FPSIMD exception */
#define ARM64_TRAP_SVE		7	/* SVE access trap */

#endif /* _ASM_ARM64_DOVETAIL_H */
