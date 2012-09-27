#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>

#define EXCEPTION(nr)	\
	.= nr;		\
	b .;

	.section ".head","ax"
	/* Keep that gap empty */
	. = 0
.global __head
__head:
	/* This entry point will be used when starting a runtime OPAL */
	b	.

	/* This is our boot semaphore used for CPUs to sync, it has to be
	 * at an easy to locate address (without relocation) since we
	 * need to get at it very early, before we apply our relocs
	 */
	. = 0xf0
__boot_sem:
	.llong	0

	/* And this is a boot flag used to kick secondaries into the
	 * main code.
	 */
__boot_flag:
	.llong	0

	/* Here will sit the reset handler */
	EXCEPTION(0x100)

	/* Main entry point (to move elsewhere) */
	.= 0x180
.global __entry
__entry:
	b	__entry2

	/* Exception stubs */
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

__entry2:
	/* Get our reloc offset into r30 */
	bcl	20,31,$+4
1:	mflr	%r30
	subi	%r30,%r30,(1b - __head)

	/* Get ourselves a TOC */
	LOAD_IMM32(%r2,__toc_start - __head)
	add	%r2,%r2,%r30

	/* We might need relocation, update the TOC */
	LOAD_IMM64(%r29, SKIBOOT_BASE)
	add	%r2,%r2,%r29

	/* Check our PIR, avoid threads */
	mfspr	%r31,SPR_PIR
	andi.	%r0,%r31,3
	bne	secondary_wait

	/* Pick a boot CPU, cpu index in r31 */
	LOAD_IMM32(%r3, __boot_sem - __head)
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

	/* Check if we need to copy ourselves up and update %r30 to
	 * be our new offset
	 */
	cmpd	%r29,%r30
	beq	2f
	LOAD_IMM32(%r3, _sbss - __head)
	subf	%r3,%r30,%r3
	srdi	%r3,%r3,3
	mtctr	%r3
	mr	%r4,%r30
	mr	%r28,%r30
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
2:	LOAD_IMM32(%r1,boot_stack - __head)
	LOAD_IMM32(%r3,STACK_SIZE - 256)
	add	%r1,%r1,%r30
	add	%r1,%r1,%r3

	/* Clear up initial frame */
	li	%r3,0
	std	%r3,0(%r1)
	std	%r3,8(%r1)
	std	%r3,16(%r1)

	/* Relocate ourselves */
	bl	call_relocate

	/* Tell secondaries to move to second stage (relocated) spin loop */
	LOAD_IMM32(%r3, __boot_flag - __head)
	add	%r3,%r3,%r28
	li	%r0,1
	std	%r0,0(%r3)

	/* Clear BSS before we try to use that stack */
	li	%r0,0
	LOAD_ADDR_FROM_TOC(%r3, _sbss)
	LOAD_ADDR_FROM_TOC(%r4, _ebss)
	subf	%r4,%r3,%r4
	srdi	%r4,%r4,3
	mtctr	%r4
1:	std	%r0,0(%r3)
	addi	%r3,%r3,8
	bdnz	1b
	bl	main_cpu_entry
	b	.

	/* Secondary CPUs wait here r31 is PIR */
secondary_wait:	
	/* The primary might be in the middle of relocating us,
	 * so first we spin on the __boot_flag
	 */
	LOAD_IMM32(%r3, __boot_flag - __head)
	add	%r3,%r3,%r30
1:	smt_very_low
	ld	%r0,0(%r3)
	cmpdi	%r0,0
	beq	1b

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

	/* Lookup our PIR in the cpu_threads array */
	smt_medium
	LOAD_ADDR_FROM_TOC(%r3, cpu_threads)
	LOAD_ADDR_FROM_TOC(%r5, cpu_max_pir)
	mulli	%r4,%r31,CPUTHREAD_SIZE
	ld	%r3,0(%r3)
	lwz	%r5,0(%r5)
	cmpw	%r31,%r5
	bgt	secondary_not_found
	add	%r3,%r3,%r4

	/* Got our cpu_thread, stick a copy of it in HSPRG0 */
	mtspr	SPR_HSPRG0,%r3

	/* Get our stack and jump to C */
	ld	%r1,CPUTHREAD_STACK(%r3)
	li	%r0,0
	std	%r0,0(%r1)
	std	%r0,16(%r1)
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

	/* NACA */
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
	.byte	0x01			/* 0x01b7 : PCIA format */
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
