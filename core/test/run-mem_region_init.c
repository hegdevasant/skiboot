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
char __rodata_start[1], __rodata_end[1];

static inline char *skiboot_strdup(const char *str)
{
	char *ret = skiboot_malloc(strlen(str) + 1);
	return memcpy(ret, str, strlen(str) + 1);
}
#undef strdup
#define strdup skiboot_strdup

#include "../device.c"

#undef malloc
#undef free
#undef realloc

#include <skiboot.h>

#include <assert.h>
#include <stdio.h>

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

/* We actually need a lot of room for the bitmaps! */
#define TEST_HEAP_ORDER 27
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

static void add_mem_node(uint64_t start, uint64_t len)
{
	struct dt_node *mem;
	u64 reg[2];
	char name[sizeof("memory@") + STR_MAX_CHARS(reg[0])];

	/* reg contains start and length */
	reg[0] = cpu_to_be64(start);
	reg[1] = cpu_to_be64(len);

	sprintf(name, "memory@%llx", (unsigned long long)start);

	mem = dt_new(dt_root, name);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property(mem, "reg", reg, sizeof(reg));
}

int main(void)
{
	uint64_t end;
	int builtins;
	struct mem_region *r;
	char *heap = real_malloc(TEST_HEAP_SIZE);

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)heap;
	skiboot_heap.len = TEST_HEAP_SIZE;

	dt_root = dt_new_root("");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	/* Make sure we overlap the heap, at least. */
	add_mem_node(0, 0x100000000ULL);
	add_mem_node(0x100000000ULL, 0x100000000ULL);
	end = 0x200000000ULL;

	/* Now convert. */
	mem_region_init();
	assert(mem_check(&skiboot_heap));

	builtins = 0;
	list_for_each(&regions, r, list) {
		/* Regions must not overlap. */
		struct mem_region *r2, *pre = NULL, *post = NULL;
		list_for_each(&regions, r2, list) {
			if (r == r2)
				continue;
			assert(!overlaps(r, r2));
		}

		/* But should have exact neighbours. */
		list_for_each(&regions, r2, list) {
			if (r == r2)
				continue;
			if (r2->start == r->start + r->len)
				post = r2;
			if (r2->start + r2->len == r->start)
				pre = r2;
		}
		assert(r->start == 0 || pre);
		assert(r->start + r->len == end || post);

		if (r == &skiboot_code_and_text ||
		    r == &skiboot_heap ||
		    r == &skiboot_after_heap ||
		    r == &skiboot_cpu_stacks)
			builtins++;
		else
			assert(r->allocatable);
		assert(mem_check(r));
	}
	assert(builtins == 4);

	dt_free(dt_root);

	while ((r = list_pop(&regions, struct mem_region, list)) != NULL) {
		list_del(&r->list);
		if (r != &skiboot_code_and_text &&
		    r != &skiboot_heap &&
		    r != &skiboot_after_heap &&
		    r != &skiboot_cpu_stacks) {
			skiboot_free(r);
		}
		assert(mem_check(&skiboot_heap));
	}
	assert(mem_region_lock.lock_val == 0);
	real_free(heap);
	return 0;
}
