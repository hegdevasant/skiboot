/*
 * Memory management
 */

#include <skiboot.h>
#include <processor.h>
#include <cpu.h>

static uint64_t brk = HEAP_BASE;

void *sbrk(int incr)
{
	void *prev = (void *)brk;

	if ((brk + incr) > (HEAP_BASE + HEAP_SIZE)) {
		errno = ENOMEM;
		return (void *)-1;
	}
	brk += incr;

	return prev;
}

void backtrace(void)
{
	unsigned int pir = mfspr(SPR_PIR);
	unsigned long *sp;
	unsigned long *bottom, *top;

	/* Check if there's a __builtin_something instead */
	asm("mr %0,1" : "=r" (sp));

	bottom = cpu_stack_bottom(pir);
	top = cpu_stack_top(pir);

	/* XXX Handle SMP */
	fprintf(stderr, "CPU %08x Backtrace:\n", pir);
	while(sp > bottom && sp < top) {
		fprintf(stderr, " S: %016lx R: %016lx\n",
			(unsigned long)sp, sp[2]);
		sp = (unsigned long *)sp[0];
	}
}
