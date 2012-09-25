/*
 * Memory management
 */

#include <skiboot.h>
#include <processor.h>

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

/* Initial stack */
char boot_stack[STACK_SIZE] __attribute__ ((aligned(16)));
void *boot_stack_top = &boot_stack[STACK_SIZE - 256];

void backtrace(void)
{
	unsigned long *sp;

	/* Check if there's a __builtin_something instead */
	asm("mr %0,1" : "=r" (sp));

	/* XXX Handle SMP */
	fprintf(stderr, "CPU %08lx Backtrace:\n", mfspr(SPR_PIR));
	while((void *)sp > (void *)boot_stack && (void *)sp < boot_stack_top) {
		fprintf(stderr, " S: %016lx R: %016lx\n",
			(unsigned long)sp, sp[2]);
		sp = (unsigned long *)sp[0];
	}
}
