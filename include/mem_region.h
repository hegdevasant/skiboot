/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __MEMORY_REGION
#define __MEMORY_REGION
#include <ccan/list/list.h>
#include <stdint.h>

/* An area of physical memory. */
struct mem_region {
	const char *name;
	void *start;
	uint64_t len;
	/* Can we allocate within this region? */
	bool allocatable;
	struct list_head free_list;
};

extern struct lock mem_region_lock;
void *mem_alloc(struct mem_region *region, size_t size, size_t align);
void mem_free(struct mem_region *region, void *mem);
bool mem_resize(struct mem_region *region, void *mem, size_t len);
size_t mem_size(const struct mem_region *region, const void *ptr);
bool mem_check(const struct mem_region *region);

/* Specifically for working on the heap. */
extern struct mem_region skiboot_heap;

#endif /* __MEMORY_REGION */
