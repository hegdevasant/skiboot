/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>
#include <opal.h>
#include <stack.h>

#define EPAPR_MAGIC	0x65504150

#define EXCEPTION(nr)	\
	.= nr;		\
	b .;


/**
 * patch_exception() makes assumptions about this macro, in order to extract
 * the correct stack during MC. If you update this, also check the offset and
 * the patch code in that function.
 */
#define GET_STACK(stack_reg,pir_reg)				\
	sldi	stack_reg,pir_reg,STACK_SHIFT;			\
	addis	stack_reg,stack_reg,CPU_STACKS_OFFSET@ha;	\
	addi	stack_reg,stack_reg,CPU_STACKS_OFFSET@l;

#define GET_CPU()						\
	clrrdi	%r13,%r1,STACK_SHIFT

	.section ".head","ax"

	. = 0
.global __head
__head:
	/* When booted as an OPAL LID, this is a pointer to the OPAL
	 * variant of the NACA
	 */
	.llong	opal_naca

	/* This entry point is used when booting with a flat device-tree
	 * pointer in r3
	 */
	. = 0x10
.global fdt_entry
fdt_entry:
	mr	%r27,%r3
	li	%r25,0
	b	boot_entry

	/* This is our boot semaphore used for CPUs to sync, it has to be
	 * at an easy to locate address (without relocation) since we
	 * need to get at it very early, before we apply our relocs
	 */
	. = 0xf0
boot_sem:
	.long	0

	/* And this is a boot flag used to kick secondaries into the
	 * main code.
	 */
boot_flag:
	.long	0

	/* Exception stubs */
	EXCEPTION(0x100)

	/* Entry point set by the FSP */
	.= 0x180
	li	%r27,0
	li	%r25,0
	b	boot_entry

	/* More exception stubs */
	EXCEPTION(0x200)
	EXCEPTION(0x300)
	EXCEPTION(0x380)
	EXCEPTION(0x400)
	EXCEPTION(0x480)
	EXCEPTION(0x500)
	EXCEPTION(0x600)
	EXCEPTION(0x700)
	EXCEPTION(0x800)
	EXCEPTION(0x900)
	EXCEPTION(0x980)
	EXCEPTION(0xa00)
	EXCEPTION(0xb00)
	EXCEPTION(0xc00)
	EXCEPTION(0xd00)
	EXCEPTION(0xe00)
	EXCEPTION(0xe20)
	EXCEPTION(0xe40)
	EXCEPTION(0xe50)
	EXCEPTION(0xe60)
	EXCEPTION(0xf00)
	EXCEPTION(0xf20)
	EXCEPTION(0xf40)
	EXCEPTION(0x1000)
	EXCEPTION(0x1100)
	EXCEPTION(0x1200)
	EXCEPTION(0x1300)
	EXCEPTION(0x1400)
	EXCEPTION(0x1500)
	EXCEPTION(0x1600)
	EXCEPTION(0x1700)
	EXCEPTION(0x1800)
	EXCEPTION(0x1900)
	EXCEPTION(0x1a00)
	EXCEPTION(0x1b00)
	EXCEPTION(0x1c00)
	EXCEPTION(0x1d00)
	EXCEPTION(0x1e00)
	EXCEPTION(0x1f00)

	.= 0x2000
	/* This is the OPAL branch table. It's populated at boot time
	 * with function pointers to the various OPAL functions from
	 * the content of the .opal_table section, indexed by Token.
	 */
.global opal_branch_table
opal_branch_table:
	.space	8 * (OPAL_LAST + 1)

/*
 *
 * Boot time entry point from FSP
 *
 * All CPUs come here
 *
 * Boot code NV register usage:
 *
 *   r31 :  Boot PIR
 *   r30 :  Current running offset
 *   r29 :  Target address
 *   r28 :  PVR
 *   r27 :  DTB pointer (or NULL)
 *   r26 :  PIR thread mask
 *   r25 :  Selected master CPU (OPAL boot)
 */
.global boot_entry
boot_entry:
	/* Check PVR and set some CR bits */
	mfspr	%r28,SPR_PVR
	li	%r26,3	/* Default to SMT4 */
	srdi	%r3,%r28,16
	cmpwi	cr0,%r3,PVR_TYPE_P7
	beq	1f
	cmpwi	cr0,%r3,PVR_TYPE_P7P
	beq	1f
	cmpwi	cr0,%r3,PVR_TYPE_P8
	bne	.	/* Unsupported CPU type... what do we do ? */
	li	%r26,7	/* SMT 8 */

	/* Get our reloc offset into r30 */
1:	bcl	20,31,$+4
1:	mflr	%r30
	subi	%r30,%r30,(1b - __head)

	/* Get ourselves a TOC & relocate it to our target address */
	LOAD_IMM32(%r2,__toc_start - __head)
	LOAD_IMM64(%r29, SKIBOOT_BASE)
	add	%r2,%r2,%r29

	/* Fixup our MSR (remove TA) */
	LOAD_IMM64(%r3, (MSR_HV | MSR_SF))
	mtmsrd	%r3,0

	/* Check our PIR, avoid threads */
	mfspr	%r31,SPR_PIR
	and.	%r0,%r31,%r26
	bne	secondary_wait

	/* Initialize per-core SPRs */
	bl init_shared_sprs

	/* Pick a boot CPU, cpu index in r31 */
	LOAD_IMM32(%r3, boot_sem - __head)
	add	%r3,%r3,%r30
1:	lwarx	%r4,0,%r3
	addi	%r0,%r4,1
	stwcx.	%r0,0,%r3
	bne	1b
	isync
	cmpwi	cr0,%r4,0
	bne	secondary_wait

	/* Make sure we are in SMT medium */
	smt_medium

	/* Initialize thread SPRs */
	bl init_replicated_sprs

	/* Check if we need to copy ourselves up and update %r30 to
	 * be our new offset
	 */
	cmpd	%r29,%r30
	beq	2f
	LOAD_IMM32(%r3, _sbss - __head)
	srdi	%r3,%r3,3
	mtctr	%r3
	mr	%r4,%r30
	mr	%r15,%r30
	mr	%r30,%r29
1:	ld	%r0,0(%r4)
	std	%r0,0(%r29)
	addi	%r29,%r29,8
	addi	%r4,%r4,8
	bdnz	1b
	sync
	icbi	0,%r29
	sync
	isync
	LOAD_IMM32(%r3, 2f - __head)
	add	%r3,%r3,%r30
	mtctr	%r3
	bctr

	/* Get ready for C code: get a stack */
2:	GET_STACK(%r1,%r31)

	/* Clear up initial frame */
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)

	/* Relocate ourselves */
	bl	call_relocate

	/* Tell secondaries to move to second stage (relocated) spin loop */
	LOAD_IMM32(%r3, boot_flag - __head)
	add	%r3,%r3,%r15
	li	%r0,1
	stw	%r0,0(%r3)

	/* Clear BSS */
	li	%r0,0
	LOAD_ADDR_FROM_TOC(%r3, _sbss)
	LOAD_ADDR_FROM_TOC(%r4, _ebss)
	subf	%r4,%r3,%r4
	srdi	%r4,%r4,3
	mtctr	%r4
1:	std	%r0,0(%r3)
	addi	%r3,%r3,8
	bdnz	1b

	/* Jump to C */
	GET_CPU()
	mr	%r3,%r27
	mr	%r4,%r25
	bl	main_cpu_entry
	b	.

	/* Secondary CPUs wait here r31 is PIR */
secondary_wait:	
	/* The primary might be in the middle of relocating us,
	 * so first we spin on the boot_flag
	 */
	LOAD_IMM32(%r3, boot_flag - __head)
	add	%r3,%r3,%r30
1:	smt_very_low
	lwz	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

	/* Init some registers */
	bl init_replicated_sprs

	/* Switch to new runtime address */
	mr	%r30,%r29
	LOAD_IMM32(%r3, 1f - __head)
	add	%r3,%r3,%r30
	mtctr	%r3
	isync
	bctr	
1:
	/* Now wait for cpu_secondary_start to be set */
	LOAD_ADDR_FROM_TOC(%r3, cpu_secondary_start)
1:	smt_very_low	
	ld	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

	smt_medium

	/* Check our PIR is in bound */
	LOAD_ADDR_FROM_TOC(%r5, cpu_max_pir)
	lwz	%r5,0(%r5)
	cmpw	%r31,%r5
	bgt-	secondary_not_found

	/* Get our stack, cpu thread, and jump to C */
	GET_STACK(%r1,%r31)
	li	%r0,0
	std	%r0,0(%r1)
	std	%r0,16(%r1)
	GET_CPU()

	bl	secondary_cpu_entry
	b	.

	/* Not found... what to do ? set some global error ? */
secondary_not_found:
	smt_very_low
	b	.

call_relocate:
	mflr	%r14
	LOAD_IMM32(%r4,__dynamic_start - __head)
	LOAD_IMM32(%r5,__rela_dyn_start - __head)
	add	%r4,%r4,%r30
	add	%r5,%r5,%r30
	mr	%r3,%r30
	bl	relocate
	cmpwi	%r3,0
	beq	1f
	mtlr	%r14
	blr
1:	/* Fatal relocate failure */
	b	.

/* This is a little piece of code that is copied down to
 * 0x100 when doing a "fast reset"
 */
.global fast_reset_patch_start
fast_reset_patch_start:	
	smt_medium
	LOAD_IMM64(%r30, SKIBOOT_BASE)
	LOAD_IMM32(%r3, fast_reset_entry - __head)
	add	%r3,%r30,%r3
	mtctr	%r3
	bctr
.global fast_reset_patch_end
fast_reset_patch_end:

/* Fast reset code. We clean up the TLB and a few SPRs and
 * return to C code. All CPUs do that, the CPU triggering the
 * reset does it to itself last. The C code will sort out who
 * the master is. We come from the trampoline above with
 * r30 containing SKIBOOT_BASE
 */
fast_reset_entry:
	/* Clear out SLB */
	li	%r6,0
	slbmte	%r6,%r6
	slbia
	ptesync

	/* Get PIR */
	mfspr	%r31,SPR_PIR

	/* Get a stack and restore r13 */
	GET_STACK(%r1,%r31)
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)
	GET_CPU()

	/* Get our TOC */
	addis	%r2,%r30,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	/* Go to C ! */
	bl	fast_reboot
	b	.

.global cleanup_tlb
cleanup_tlb:
	/* Clean the TLB */
	li	%r3,128
	mtctr	%r3
	li	%r4,0x800		/* IS field = 0b10 */
	ptesync
1:	tlbiel	%r4
	addi	%r4,%r4,0x1000
	bdnz	1b
	ptesync

/* Functions to initialize replicated and shared SPRs to sane
 * values. This is called at boot and on soft-reset
 */
.global init_shared_sprs
init_shared_sprs:
	li	%r0,0
	mtspr	SPR_SDR1, %r0
	mtspr	SPR_AMOR, %r0

	/* TSCR: doc recommended value */
	LOAD_IMM32(%r3,0x88CC6880)
	mtspr	SPR_TSCR, %r3

	/* LPCR: sane value */
	LOAD_IMM64(%r3,0x0070000000000004)
	mtspr	SPR_LPCR, %r3

	/* XXX TODO: Add more */
	blr

.global init_replicated_sprs
init_replicated_sprs:
	/* XXX TODO: Add more */
	blr

/*
 *
 * NACA structure, accessed by the FPS to find the SPIRA
 *
 */
	. = 0x4000
.global naca
naca:
	.llong	0			/* 0x0000 : Reserved */
	.llong	0			/* 0x0008 : Reserved */
	.llong	0			/* 0x0010 : Reserved */
	.llong	hv_release_data		/* 0x0018 : HV release data */
	.llong	0			/* 0x0020 : Reserved */
	.llong	0			/* 0x0028 : Reserved */
	.llong	spira			/* 0x0030 : SP Interface Root */
	.llong	hv_lid_load_table	/* 0x0038 : LID load table */
	.llong	0			/* 0x0040 : Reserved */
	.space	68
	.long	0			/* 0x008c : Reserved */
	.space	16
	.long	SPIRA_ACTUAL_SIZE	/* 0x00a0 : Actual size of SPIRA */
	.space	28
	.llong	0			/* 0x00c0 : resident module loadmap */
	.space	136
	.llong	0			/* 0x0150 : reserved */
	.space	40
	.llong	0			/* 0x0180 : reserved */
	.space	36
	.long	0			/* 0x01ac : control flags */
	.byte	0			/* 0x01b0 : reserved */
	.space	4
	.byte	0			/* 0x01b5 : default state for SW attn */
	.space	1
	.byte	0x00			/* 0x01b7 : PCIA format */
	.space	0xe48

	.balign	0x10
hv_release_data:
	.space	58
	.llong	0x666			/* VRM ? */

	.balign	0x10
hv_lid_load_table:
	.long	0x10
	.long	0x10
	.long	0
	.long	0

/*
 *
 * OPAL variant of NACA
 *
 */
.global opal_naca
opal_naca:
	.llong	opal_boot_trampoline	/* Primary entry (used ?) */
	.llong	opal_boot_trampoline	/* Secondary entry (used ?) */
	.llong	spira			/* Spira pointer */
	.llong	0			/* Load address */
	.llong	opal_boot_trampoline	/* 0x180 trampoline */
	.llong	0			/* More stuff as seen in objdump ...*/
	.llong	0
	.llong	0
	.llong	0

	/* The FSP seems to ignore our primary/secondary entry
	 * points and instead copy that bit down to 0x180 and
	 * patch the first instruction to get our expected
	 * boot CPU number. We ignore that patching for now and
	 * got to the same entry we use for pHyp and FDT HB.
	 */
opal_boot_trampoline:
	li	%r25,0
	li	%r27,-1
	ba	boot_entry - __head

/*
 *
 * OPAL entry point from operating system
 *
 * Register usage:
 *
 *       r0: Token
 *       r2: OPAL Base
 *  r3..r11: Args
 *      r12: Scratch
 * r13..r31: Preserved
 *
 */
	.balign	0x10
.global opal_entry
opal_entry:
	/* Get our per CPU stack */
	mfspr	%r12,SPR_PIR
	GET_STACK(%r12,%r12)
	stdu	%r12,-STACK_FRAMESIZE(%r12)

	/* Save caller r1, establish new r1 */
	std	%r1,STACK_GPR1(%r12)
	mr	%r1,%r12

	/* May save arguments for tracing */
#ifdef OPAL_TRACE_ENTRY
	std	%r3,STACK_GPR3(%r1)
	std	%r4,STACK_GPR4(%r1)
	std	%r5,STACK_GPR5(%r1)
	std	%r6,STACK_GPR6(%r1)
	std	%r7,STACK_GPR7(%r1)
	std	%r8,STACK_GPR8(%r1)
	std	%r9,STACK_GPR9(%r1)
	std	%r10,STACK_GPR10(%r1)
	std	%r11,STACK_GPR11(%r1)
#endif
	/* Save Token (r0), LR and r13 */
	mflr	%r12
	std	%r0,STACK_GPR0(%r1)
	std	%r13,STACK_GPR13(%r1)
	std	%r12,STACK_LR(%r1)

	/* Get the CPU thread */
	GET_CPU()

	/* Mark the stack frame */
	li	%r12,STACK_ENTRY_OPAL_API	
	std	%r12,STACK_TYPE(%r1)

	/* Get our TOC */
	addis	%r2,%r2,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	/* Check for a reboot in progress */
	LOAD_ADDR_FROM_TOC(%r12, reboot_in_progress)
	lbz	%r12,0(%r12)
	cmpwi	%r12,0
	bne	3f

#ifdef OPAL_TRACE_ENTRY
	mr	%r3,%r1
	bl	opal_trace_entry
	ld	%r0,STACK_GPR0(%r1)
	ld	%r3,STACK_GPR3(%r1)
	ld	%r4,STACK_GPR4(%r1)
	ld	%r5,STACK_GPR5(%r1)
	ld	%r6,STACK_GPR6(%r1)
	ld	%r7,STACK_GPR7(%r1)
	ld	%r8,STACK_GPR8(%r1)
	ld	%r9,STACK_GPR9(%r1)
	ld	%r10,STACK_GPR10(%r1)
	ld	%r11,STACK_GPR11(%r1)
#endif /* OPAL_TRACE_ENTRY */

	/* Convert our token into a table entry and get the
	 * function pointer. Also check the token.
	 */
	cmpldi	%r0,OPAL_LAST
	bgt-	2f
	sldi	%r0,%r0,3
	LOAD_ADDR_FROM_TOC(%r12, opal_branch_table)
	ldx	%r0,%r12,%r0
	cmpldi	%r0,0
	beq-	2f
	mtctr	%r0

	/* Jump ! */
	bctrl

1:	ld	%r12,STACK_LR(%r1)
	mtlr	%r12
	ld	%r13,STACK_GPR13(%r1)
	ld	%r1,STACK_GPR1(%r1)
	blr

2:	/* Bad token */
	ld	%r3,STACK_GPR0(%r1)
	bl	opal_bad_token
	b	1b

3:	/* Reboot in progress, reject all calls */
	li	%r3,OPAL_BUSY
	b	1b

.global start_kernel
start_kernel:
	sync
	icbi	0,%r3
	sync
	isync
	mtctr	%r3
	mr	%r3,%r4
	LOAD_IMM64(%r8,SKIBOOT_BASE);
	LOAD_IMM32(%r10, opal_entry - __head)
	add	%r9,%r8,%r10
	LOAD_IMM32(%r6, EPAPR_MAGIC)
	addi	%r7,%r5,1
	li	%r4,0
	li	%r5,0
	bctr

.global start_kernel_secondary
start_kernel_secondary:
	sync
	isync
	mtctr	%r3
	mfspr	%r3,SPR_PIR
	bctr

	.global exc_primary_start
exc_primary_start:
	mtspr	SPR_HSPRG1,%r1
	mfspr	%r1,SPR_CFAR
0:	b	.
	.global exc_primary_end
exc_primary_end:

	.global exc_primary_patch_branch
exc_primary_patch_branch:
	.long	0b - exc_primary_start

	.global exc_secondary_start
exc_secondary_start:
	mtspr	SPR_CFAR,%r1
	mfspr	%r1,SPR_PIR
0:	GET_STACK(%r1,%r1)
	stdu	%r1,-STACK_FRAMESIZE(%r1)
	std	%r3,STACK_GPR3(%r1)
	mfspr	%r3,SPR_HSPRG1
	std	%r3,STACK_GPR1(%r1)
	mfspr	%r3,SPR_CFAR
	std	%r3,STACK_CFAR(%r1)
1:	mfspr	%r3,SPR_SRR0
	std	%r3,STACK_SRR0(%r1)
2:	mfspr	%r3,SPR_SRR1
	std	%r3,STACK_SRR1(%r1)
	mflr	%r3
	std	%r3,STACK_LR(%r1)
	LOAD_IMM32(%r3,SKIBOOT_BASE + exception_entry_common - __head);
	mtlr	%r3
3:	li	%r3,0
	blrl	/* XXX Use a BH=01 variant to avoid link stack problems */
	ld	%r3,STACK_LR(%r1)
	mtlr	%r3
	ld	%r3,STACK_SRR0(%r1)
4:	mtspr	SPR_SRR0,%r3
	ld	%r3,STACK_SRR1(%r1)
5:	mtspr	SPR_SRR1,%r3
	ld	%r3,STACK_GPR3(%r1)
	ld	%r1,STACK_GPR1(%r1)
6:	rfid
	.global exc_secondary_end
exc_secondary_end:

	.global exc_secondary_patch_stack
exc_secondary_patch_stack:
	.long	0b - exc_secondary_start
	.global exc_secondary_patch_mfsrr0
exc_secondary_patch_mfsrr0:
	.long	1b - exc_secondary_start
	.global exc_secondary_patch_mfsrr1
exc_secondary_patch_mfsrr1:
	.long	2b - exc_secondary_start
	.global exc_secondary_patch_type
exc_secondary_patch_type:
	.long	3b - exc_secondary_start
	.global exc_secondary_patch_mtsrr0
exc_secondary_patch_mtsrr0:
	.long	4b - exc_secondary_start
	.global exc_secondary_patch_mtsrr1
exc_secondary_patch_mtsrr1:
	.long	5b - exc_secondary_start
	.global exc_secondary_patch_rfid
exc_secondary_patch_rfid:
	.long	6b - exc_secondary_start

	/* The rest of the exception entry code */
exception_entry_common:
	std	%r3,STACK_TYPE(%r1)

	/* We save the exception return LR in the stack-locals area */
	mflr	%r3
	std	%r3,STACK_LOCALS(%r1)

	/* Save more stuff */
	std	%r0,STACK_GPR0(%r1)
	std	%r2,STACK_GPR2(%r1)
	std	%r4,STACK_GPR4(%r1)
	std	%r5,STACK_GPR5(%r1)
	std	%r6,STACK_GPR6(%r1)
	std	%r7,STACK_GPR7(%r1)
	std	%r8,STACK_GPR8(%r1)
	std	%r9,STACK_GPR9(%r1)
	std	%r10,STACK_GPR10(%r1)
	std	%r11,STACK_GPR11(%r1)
	std	%r12,STACK_GPR12(%r1)
	std	%r13,STACK_GPR13(%r1)
	mfcr	%r3
	stw	%r3,STACK_CR(%r1)
	mfctr	%r3
	std	%r3,STACK_CTR(%r1)

	GET_CPU()

	LOAD_IMM64(%r2, SKIBOOT_BASE)
	addis	%r2,%r2,(__toc_start - __head)@ha
	addi	%r2,%r2,(__toc_start - __head)@l

	mr	%r3,%r1
	bl	exception_entry

	ld	%r3,STACK_CTR(%r1)
	lwz	%r4,STACK_CR(%r1)
	mtctr	%r3
	mtcr	%r4

	ld	%r0,STACK_GPR0(%r1)
	ld	%r2,STACK_GPR2(%r1)
	ld	%r4,STACK_GPR4(%r1)
	ld	%r5,STACK_GPR5(%r1)
	ld	%r6,STACK_GPR6(%r1)
	ld	%r7,STACK_GPR7(%r1)
	ld	%r8,STACK_GPR8(%r1)
	ld	%r9,STACK_GPR9(%r1)
	ld	%r10,STACK_GPR10(%r1)
	ld	%r11,STACK_GPR11(%r1)
	ld	%r12,STACK_GPR12(%r1)
	ld	%r13,STACK_GPR13(%r1)

	ld	%r3,STACK_LOCALS(%r1)
	mtlr	%r3
	blr
