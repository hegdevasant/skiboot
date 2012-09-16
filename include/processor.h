#ifndef __PROCESSOR_H
#define __PROCESSOR_H

#include <compiler.h>

/* P7 MSR bits */
#define MSR_SF		0x8000000000000000UL	/*  0 : 64-bit mode */
#define MSR_HV		0x1000000000000000UL	/*  3 : Hypervisor mode */
#define MSR_VEC		0x0000000002000000UL	/* 38 : VMX enable */
#define MSR_VSX		0x0000000000800000UL	/* 40 : VSX enable */
#define MSR_EE		0x0000000000008000UL	/* 48 : External Int. Enable */
#define MSR_PR		0x0000000000004000UL	/* 49 : Problem state */
#define MSR_FP		0x0000000000002000UL	/* 50 : Floating Point Enable */
#define MSR_ME		0x0000000000001000UL	/* 51 : Machine Check Enable */
#define MSR_FE0		0x0000000000000800UL	/* 52 : FP Exception 0 */
#define MSR_SE		0x0000000000000400UL	/* 53 : Step enable */
#define MSR_BE		0x0000000000000200UL	/* 54 : Branch trace enable */
#define MSR_FE1		0x0000000000000100UL	/* 55 : FP Exception 1 */
#define MSR_IR		0x0000000000000020UL	/* 58 : Instructions reloc */
#define MSR_DR		0x0000000000000010UL	/* 59 : Data reloc */
#define MSR_PMM		0x0000000000000004UL	/* 61 : Perf Monitor */
#define MSR_RI		0x0000000000000002UL	/* 62 : Recoverable Interrupt */
#define MSR_LE		0x0000000000000001UL	/* 63 : Little Endian */

/* SPR register definitions */
#define SPRN_PIR		1023

/* Thread priority control opcodes */
#define smt_low		or 1,1,1
#define smt_medium	or 2,2,2
#define smt_high	or 3,3,3
#define smt_medium_high	or 5,5,5
#define smt_medium_low	or 6,6,6
#define smt_extra_high	or 7,7,7
#define smt_very_low	or 31,31,31

#ifndef __ASSEMBLY__

/* SPR access functions */
static inline unsigned long mfmsr(void)
{
	unsigned long val;
	
	asm volatile("mfmsr %0" : "=r"(val) : : "memory");
	return val;
}

static inline void mtmsr(unsigned long val)
{
	asm volatile("mtmsr %0" : : "r"(val) : "memory");
}

static inline void mtmsrd(unsigned long val, int l)
{
	asm volatile("mtmsrd %0,%1" : : "r"(val), "i"(l) : "memory");
}

static inline unsigned long mfspr(unsigned int spr)
{
	unsigned long val;

	asm volatile("mfspr %0,%1" : "=r"(val) : "i"(spr) : "memory");
	return val;
}

static inline void mtspr(unsigned int spr, unsigned long val)
{
	asm volatile("mtspr %0,%1" : : "i"(l), "r"(val) : "memory");
}


#endif /* __ASSEMBLY__ */

#endif /* __PROCESSOR_H */
