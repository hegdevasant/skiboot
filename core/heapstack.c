/*
 * Memory management
 */

#include <skiboot.h>
#include <processor.h>

/* Small heap used for libc'c sbrk/malloc */
static char heap[HEAP_SIZE] __attribute__ ((aligned(16)));
static char *brk = heap;

void *sbrk(int incr)
{
	void *prev = brk;

	if (brk + incr > &heap[HEAP_SIZE]) {
		errno = ENOMEM;
		return (void *)-1;
	}
	brk += incr;
	return prev;
}

/* Initial stack */
static char stack[STACK_SIZE] __attribute__ ((aligned(16)));
void *stack_top = &stack[STACK_SIZE - 256];

void backtrace(void)
{
	unsigned long *sp;

	/* Check if there's a __builtin_something instead */
	asm("mr %0,1" : "=r" (sp));

	/* XXX Handle SMP */
	fprintf(stderr, "CPU %08lx Backtrace:\n", mfspr(SPR_PIR));
	while((void *)sp > (void *)stack && (void *)sp < stack_top) {
		fprintf(stderr, " S: %016lx R: %016lx\n",
			(unsigned long)sp, sp[2]);
		sp = (unsigned long *)sp[0];
	}
}
