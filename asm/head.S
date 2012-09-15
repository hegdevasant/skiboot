#include <asm-utils.h>
#include <asm-offsets.h>

	.section ".head","ax"
	/* Keep that gap empty */
	. = 0
.global __head
__head:
	/* Various entry points used mostly for debugging */
	b	__entry
	. = 0x100
	b	__entry

	/* Main entry point */
	.= 0x180
.global __entry
__entry:
	/* Get ourselves a TOC */
	LOAD_IMM32(%r2,__toc_start + 0x8000)

	/* XXX Check our PIR, avoid threads ! */

	/* Pick a boot CPU, cpu index in r31 */
	LOAD_ADDR_FROM_TOC(%r3, boot_cpu_count)
1:	lwarx	%r31,0,%r3
	addi	%r0,%r31,1
	stwcx.	%r0,0,%r3
	bne	1b
	isync
	cmpwi	cr0,%r31,0
	bne	secondary_wait

	/* We got a primary, get ready for C code: get a stack */
	LOAD_ADDR_FROM_TOC(%r1, stack_top)
	ld	%r1,0(%r1)

	/* Clear BSS before we try to use that stack */
	LOAD_IMM32(%r3, _sbss)
	LOAD_IMM32(%r4, _ebss)
	subf	%r4,%r3,%r4
	srdi	%r4,%r4,3
	mtctr	%r4
1:	std	%r5,0(%r3)
	addi	%r3,%r3,8
	bdnz	1b
	bl	main_cpu_entry
	b	.

	/* Secondary CPUs wait here */
secondary_wait:	
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
	.llong	0			/* 0x0038 : LID load table */
	.llong	0			/* 0x0040 : Reserved */
	
hv_release_data:
	.space	58
	.llong	0x666			/* VRM ? */

