/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <config.h>

#define BITS_PER_LONG (sizeof(long) * 8)
/* Don't include this, it's PPC-specific */
#define __CPU_H
static unsigned int cpu_max_pir = 1;

#include <stdlib.h>

/* Use these before we undefine them below. */
static inline void *real_malloc(size_t size)
{
	return malloc(size);
}

static inline void real_free(void *p)
{
	return free(p);
}

/* We want *mem_region* to use the skiboot malloc, but not us. */
#undef malloc
#undef free
#undef realloc
#define malloc skiboot_malloc
#define free skiboot_free
#define realloc skiboot_realloc

#include "../malloc.c"
#include "../mem_region.c"

#undef malloc
#undef free
#undef realloc

#include <assert.h>
#include <stdio.h>

struct dt_node *dt_root;

void lock(struct lock *l)
{
	assert(!l->lock_val);
	l->lock_val = 1;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val = 0;
}

#define TEST_HEAP_ORDER 27
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

#define NUM_ALLOCS 4096

int main(void)
{
	uint64_t i, len;
	void *p[NUM_ALLOCS];

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)real_malloc(skiboot_heap.len);

	len = skiboot_heap.len / NUM_ALLOCS - sizeof(struct alloc_hdr);
	for (i = 0; i < NUM_ALLOCS; i++) {
		p[i] = skiboot_malloc(len);
		assert(p[i] > region_start(&skiboot_heap));
		assert(p[i] + len <= region_start(&skiboot_heap)
		       + skiboot_heap.len);
	}
	assert(mem_check(&skiboot_heap));
	assert(mem_region_lock.lock_val == 0);
	free(region_start(&skiboot_heap));
	return 0;
}
