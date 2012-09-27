#include <asm-utils.h>
#include <asm-offsets.h>
#include <processor.h>

	.section ".head","ax"
	.balign	0x10

	/* bool try_lock(struct lock *lock) */
.global try_lock
try_lock:
	ld	%r0,0(%r3)
	andi.	%r10,%r0,1
	bne	2f
	lwz	%r9,CPUTHREAD_PIR(%r13)
1:	ldarx	%r0,0,%r3
	andi.	%r10,%r0,1
	bne-	2f
	ori	%r0,%r0,1
	rldimi	%r0,%r9,32,0
	stdcx.	%r0,0,%r3
	bne	1b
	sync
	li	%r3,-1
	blr
2:	li	%r3,0
	blr

