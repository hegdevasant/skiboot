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

/* Under valgrind, even a shrinking realloc moves, so override */
#include <stdlib.h>
#define realloc(p, size) (p)

#define zalloc(size) calloc((size), 1)

#include <skiboot.h>

char __rodata_start[16];
#define __rodata_end (__rodata_start + sizeof(__rodata_start))

#include "../mem_region.c"
#include "../device.c"
#include <assert.h>
#include <stdio.h>

void lock(struct lock *l)
{
	l->lock_val++;
}

void unlock(struct lock *l)
{
	l->lock_val--;
}

#define TEST_HEAP_ORDER 12
#define TEST_HEAP_SIZE (1ULL << TEST_HEAP_ORDER)

static void add_mem_node(uint64_t start, uint64_t len)
{
	struct dt_node *mem;
	u64 reg[2];
	char name[sizeof("memory@") + STR_MAX_CHARS(reg[0])];

	/* reg contains start and length */
	reg[0] = cpu_to_be64(start);
	reg[1] = cpu_to_be64(len);

	sprintf(name, "memory@%llx", start);

	mem = dt_new(dt_root, name);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property(mem, "reg", reg, sizeof(reg));
}

int main(void)
{
	uint64_t i;
	struct mem_region *r, *other = NULL;
	void *other_mem;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)malloc(TEST_HEAP_SIZE);
	skiboot_heap.len = TEST_HEAP_SIZE;

	dt_root = dt_new_root("");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	other_mem = malloc(1024*1024);
	add_mem_node((unsigned long)other_mem, 1024*1024);

	/* Now convert. */
	mem_region_init();

	/* Find our node to allocate from */
	list_for_each(&regions, r, list) {
		if (region_start(r) == other_mem)
			other = r;
	}
	/* This could happen if skiboot addresses clashed with our alloc. */
	assert(other);

	/* Allocate 1k from other region. */
	mem_alloc(other, 1024, 1);
	mem_region_release_unused();

	/* Now we expect it to be split. */
	i = 0;
	list_for_each(&regions, r, list) {
		i++;
		if (r == &skiboot_code_and_text)
			continue;
		if (r == &skiboot_heap)
			continue;
		if (r == &skiboot_after_heap)
			continue;
		if (r == &skiboot_cpu_stacks)
			continue;
		if (r == other) {
			assert(r->for_skiboot);
			assert(r->allocatable);
			assert(r->len < 1024 * 1024);
		} else {
			assert(!r->for_skiboot);
			assert(!r->allocatable);
			assert(r->start == other->start + other->len);
			assert(r->start + r->len == other->start + 1024*1024);
		}
	}
	assert(i == 6);

	dt_free(dt_root);
	free((void *)(long)skiboot_heap.start);
	free(other_mem);
	return 0;
}
