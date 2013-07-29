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

static void *__malloc(size_t size, const char *location __attribute__((unused)))
{
	return malloc(size);
}

static void *__zalloc(size_t size, const char *location __attribute__((unused)))
{
	return calloc(size, 1);
}

static inline void __free(void *p, const char *location __attribute__((unused)))
{
	return free(p);
}

#include <skiboot.h>

/* We need mem_region to accept __location__ */
#define is_rodata(p) true
#include "../mem_region.c"

/* But we need device tree to make copies of names. */
#undef is_rodata
#define is_rodata(p) false

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

	sprintf(name, "memory@%llx", (long long)start);

	mem = dt_new(dt_root, name);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property(mem, "reg", reg, sizeof(reg));
}

int main(void)
{
	uint64_t i;
	struct mem_region *r;

	/* Use malloc for the heap, so valgrind can find issues. */
	skiboot_heap.start = (unsigned long)malloc(TEST_HEAP_SIZE);
	skiboot_heap.len = TEST_HEAP_SIZE;
	skiboot_os_reserve.len = skiboot_heap.start;

	dt_root = dt_new_root("");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	add_mem_node(0, 0x100000000ULL);
	add_mem_node(0x100000000ULL, 0x100000000ULL);

	mem_region_init();

	mem_region_release_unused();

	assert(mem_check(&skiboot_heap));

	/* Now we expect it to be split. */
	i = 0;
	list_for_each(&regions, r, list) {
		assert(mem_check(r));
		i++;
		if (r == &skiboot_os_reserve)
			continue;
		if (r == &skiboot_code_and_text)
			continue;
		if (r == &skiboot_heap)
			continue;
		if (r == &skiboot_after_heap)
			continue;
		if (r == &skiboot_cpu_stacks)
			continue;

		/* the memory nodes should all be available to the OS now */
		assert(r->type == REGION_OS);
	}
	assert(i == 9);

	dt_free(dt_root);
	free((void *)(long)skiboot_heap.start);
	return 0;
}
