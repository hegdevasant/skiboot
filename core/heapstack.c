/*
 * Memory management
 */

#include <skiboot.h>
#include <unistd.h>
#include <errno.h>

/* Small heap used for libc'c sbrk/malloc */
static char heap[HEAP_SIZE] __attribute__ ((aligned(16)));
static char *brk = heap;

void *sbrk(int incr)
{
	void *prev = brk;

	if (brk + incr > &heap[HEAP_SIZE]) {
		errno = ENOMEM;
		return NULL;
	}
	brk += incr;
	return prev;
}

/* Initial stack */
static char stack[STACK_SIZE] __attribute__ ((aligned(16)));
void *stack_top = &stack[STACK_SIZE - 256];

