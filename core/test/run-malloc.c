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

#include "../mem_region.c"
#include "../malloc.c"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_HEAP_ORDER 12
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

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

static bool heap_empty(void)
{
	const struct alloc_hdr *h = skiboot_heap.start;
	return h->num_longs == skiboot_heap.len / sizeof(long);
}

int main(void)
{
	char test_heap[TEST_HEAP_SIZE], *p, *p2;
	size_t i;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	/* Allocations of various sizes. */
	for (i = 0; i < TEST_HEAP_ORDER; i++) {
		p = malloc(1ULL << i);
		assert(p);
		assert(p > (char *)test_heap);
		assert(p + (1ULL << i) <= (char *)test_heap + TEST_HEAP_SIZE);
		assert(!mem_region_lock.lock_val);
		free(p);
		assert(!mem_region_lock.lock_val);
		assert(heap_empty());
	}

	/* Realloc as malloc. */
	mem_region_lock.lock_val = 0;
	p = realloc(NULL, 100);
	assert(p);
	assert(!mem_region_lock.lock_val);

	/* Realloc as free. */
	p = realloc(p, 0);
	assert(!p);
	assert(!mem_region_lock.lock_val);
	assert(heap_empty());

	/* Realloc longer. */
	p = realloc(NULL, 100);
	assert(p);
	assert(!mem_region_lock.lock_val);
	p2 = realloc(p, 200);
	assert(p2 == p);
	assert(!mem_region_lock.lock_val);
	free(p);
	assert(!mem_region_lock.lock_val);
	assert(heap_empty());

	/* Realloc shorter. */
	mem_region_lock.lock_val = 0;
	p = realloc(NULL, 100);
	assert(!mem_region_lock.lock_val);
	assert(p);
	p2 = realloc(p, 1);
	assert(!mem_region_lock.lock_val);
	assert(p2 == p);
	free(p);
	assert(!mem_region_lock.lock_val);
	assert(heap_empty());

	/* Realloc with move. */
	p2 = malloc(TEST_HEAP_SIZE - 64 - sizeof(struct alloc_hdr)*2);
	assert(p2);
	p = malloc(64);
	assert(p);
	free(p2);

	p2 = realloc(p, 128);
	assert(p2 != p);
	free(p2);
	assert(heap_empty());
	assert(!mem_region_lock.lock_val);
	return 0;
}
