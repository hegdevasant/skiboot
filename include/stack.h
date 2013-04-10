/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __STACKFRAME_H
#define __STACKFRAME_H

#define STACK_ENTRY_OPAL_API	0	/* OPAL call */
#define STACK_ENTRY_MCHECK	0x0200	/* Machine check */
#define STACK_ENTRY_HMI		0x0e60	/* Hypervisor maintainance */
#define STACK_ENTRY_RESET	0x0100	/* System reset */
#define STACK_ENTRY_SOFTPATCH	0x1500	/* Soft patch (denorm emulation) */

/* Portion of the stack reserved for machine checks */
#define MC_STACK_SIZE		0x1000

/* Safety/ABI gap at top of stack */
#define STACK_TOP_GAP		0x100

/* Remaining stack space (gap included) */
#define NORMAL_STACK_SIZE	(STACK_SIZE - MC_STACK_SIZE)

/* Offset to get to normal CPU stacks */
#define CPU_STACKS_OFFSET	(CPU_STACKS_BASE + \
				 NORMAL_STACK_SIZE - STACK_TOP_GAP)

/* Offset to get to machine check CPU stacks */
#define CPU_MC_STACKS_OFFSET	(CPU_STACKS_BASE + STACK_SIZE - STACK_TOP_GAP)

#ifndef __ASSEMBLY__

#include <stdint.h>

/* This is the struct used to save GPRs etc.. on OPAL entry
 * and from some exceptions. It is not always entirely populated
 * depending on the entry type
 */
struct stack_frame {
	/* Standard 112-byte stack frame header (the minimum size required,
	 * using an 8-doubleword param save area). The callee (in C) may use
	 * lrsave; we declare these here so we don't get our own save area
	 * overwritten */
	uint64_t	backchain;
	uint64_t	crsave;
	uint64_t	lrsave;
	uint64_t	compiler_dw;
	uint64_t	linker_dw;
	uint64_t	tocsave;
	uint64_t	paramsave[8];

	/* Space for stack-local vars used by asm. At present we only use
	 * one doubleword. */
	uint64_t	locals[1];

	/* Entry type */
	uint64_t	type;

	/* GPR save area
	 *
	 * We don't necessarily save everything in here
	 */
	uint64_t	gpr[32];

	/* Other SPR saved
	 *
	 * Only for some exceptions.
	 */
	uint32_t	cr;
	uint32_t	xer;
	uint64_t	ctr;
	uint64_t	lr;
	uint64_t	pc;
	uint64_t	cfar;
	uint64_t	srr0;
	uint64_t	srr1;
};

#endif /* __ASSEMBLY__ */
#endif /* __STACKFRAME_H */

