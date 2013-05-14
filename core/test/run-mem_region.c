/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <config.h>

#define BITS_PER_LONG (sizeof(long) * 8)

#include "../mem_region.c"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define TEST_HEAP_ORDER 12
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

static bool heap_empty(void)
{
	const struct alloc_hdr *h = skiboot_heap.start;
	return h->num_longs == skiboot_heap.len / sizeof(long);
}

int main(void)
{
	char *test_heap;
	void *p, *ptrs[100];
	size_t i;

	/* Use malloc for the heap, so valgrind can find issues. */
	test_heap = malloc(TEST_HEAP_SIZE);
	skiboot_heap.start = test_heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	/* Allocations of various sizes. */
	for (i = 0; i < TEST_HEAP_ORDER; i++) {
		p = mem_alloc(&skiboot_heap, 1ULL << i, 1);
		assert(p);
		assert(mem_check(&skiboot_heap));
		assert(p > (void *)test_heap);
		assert(p + (1ULL << i) <= (void *)test_heap + TEST_HEAP_SIZE);
		assert(mem_size(&skiboot_heap, p) >= 1ULL << i);
		mem_free(&skiboot_heap, p);
		assert(heap_empty());
		assert(mem_check(&skiboot_heap));
	}
	p = mem_alloc(&skiboot_heap, 1ULL << i, 1);
	assert(!p);
	mem_free(&skiboot_heap, p);
	assert(heap_empty());
	assert(mem_check(&skiboot_heap));

	/* Allocations of various alignments: use small alloc first. */
	ptrs[0] = mem_alloc(&skiboot_heap, 1, 1);
	for (i = 0; ; i++) {
		p = mem_alloc(&skiboot_heap, 1, 1ULL << i);
		assert(mem_check(&skiboot_heap));
		/* We will eventually fail... */
		if (!p) {
			assert(i >= TEST_HEAP_ORDER);
			break;
		}
		assert(p);
		assert((long)p % (1ULL << i) == 0);
		assert(p > (void *)test_heap);
		assert(p + 1 <= (void *)test_heap + TEST_HEAP_SIZE);
		mem_free(&skiboot_heap, p);
		assert(mem_check(&skiboot_heap));
	}
	mem_free(&skiboot_heap, ptrs[0]);
	assert(heap_empty());
	assert(mem_check(&skiboot_heap));

	/* Many little allocations, freed in reverse order. */
	for (i = 0; i < 100; i++) {
		ptrs[i] = mem_alloc(&skiboot_heap, sizeof(long), 1);
		assert(ptrs[i]);
		assert(ptrs[i] > (void *)test_heap);
		assert(ptrs[i] + sizeof(long)
		       <= (void *)test_heap + TEST_HEAP_SIZE);
		assert(mem_check(&skiboot_heap));
	}
	for (i = 0; i < 100; i++)
		mem_free(&skiboot_heap, ptrs[100 - 1 - i]);

	assert(heap_empty());
	assert(mem_check(&skiboot_heap));

	/* Check the prev_free gets updated properly. */
	ptrs[0] = mem_alloc(&skiboot_heap, sizeof(long), 1);
	ptrs[1] = mem_alloc(&skiboot_heap, sizeof(long), 1);
	assert(ptrs[1] > ptrs[0]);
	mem_free(&skiboot_heap, ptrs[0]);
	assert(mem_check(&skiboot_heap));
	ptrs[0] = mem_alloc(&skiboot_heap, sizeof(long), 1);
	assert(mem_check(&skiboot_heap));
	mem_free(&skiboot_heap, ptrs[1]);
	mem_free(&skiboot_heap, ptrs[0]);
	assert(mem_check(&skiboot_heap));
	assert(heap_empty());

#if 0
	printf("Heap map:\n");
	for (i = 0; i < TEST_HEAP_SIZE / sizeof(long); i++) {
		printf("%u", test_bit(skiboot_heap.bitmap, i));
		if (i % 64 == 63)
			printf("\n");
		else if (i % 8 == 7)
			printf(" ");
	}
#endif

	/* Simple enlargement, then free */
	p = mem_alloc(&skiboot_heap, 1, 1);
	assert(p);
	assert(mem_resize(&skiboot_heap, p, 100));
	assert(mem_size(&skiboot_heap, p) >= 100);
	assert(mem_check(&skiboot_heap));
	mem_free(&skiboot_heap, p);

	/* Simple shrink, then free */
	p = mem_alloc(&skiboot_heap, 100, 1);
	assert(p);
	assert(mem_resize(&skiboot_heap, p, 1));
	assert(mem_size(&skiboot_heap, p) < 100);
	assert(mem_check(&skiboot_heap));
	mem_free(&skiboot_heap, p);

	/* Lots of resizing (enlarge). */
	p = mem_alloc(&skiboot_heap, 1, 1);
	assert(p);
	for (i = 1; i <= TEST_HEAP_SIZE - sizeof(struct alloc_hdr); i++) {
		assert(mem_resize(&skiboot_heap, p, i));
		assert(mem_size(&skiboot_heap, p) >= i);
		assert(mem_check(&skiboot_heap));
	}

	/* Can't make it larger though. */
	assert(!mem_resize(&skiboot_heap, p, i));

	for (i = TEST_HEAP_SIZE - sizeof(struct alloc_hdr); i > 0; i--) {
		assert(mem_resize(&skiboot_heap, p, i));
		assert(mem_check(&skiboot_heap));
	}

	mem_free(&skiboot_heap, p);
	assert(mem_check(&skiboot_heap));
	free(test_heap);
	return 0;
}
