/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <mem_region.h>
#include <mem_region-malloc.h>
#include <libfdt_env.h>
#include <lock.h>
#include <device.h>
#include <cpu.h>

struct lock mem_region_lock = LOCK_UNLOCKED;

static struct list_head regions = LIST_HEAD_INIT(regions);

static struct mem_region skiboot_os_reserve = {
	.name		= "ibm,os-reserve",
	.start		= 0,
	.len		= SKIBOOT_BASE,
	.type		= REGION_OS,
};

struct mem_region skiboot_heap = {
	.name		= "ibm,firmware-heap",
	.start		= HEAP_BASE,
	.len		= HEAP_SIZE,
	.type		= REGION_SKIBOOT_HEAP,
};

static struct mem_region skiboot_code_and_text = {
	.name		= "ibm,firmware-code",
	.start		= SKIBOOT_BASE,
	.len		= HEAP_BASE - SKIBOOT_BASE,
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_after_heap = {
	.name		= "ibm,firmware-data",
	.start		= HEAP_BASE + HEAP_SIZE,
	.len		= SKIBOOT_BASE + SKIBOOT_SIZE - (HEAP_BASE + HEAP_SIZE),
	.type		= REGION_SKIBOOT_FIRMWARE,
};

static struct mem_region skiboot_cpu_stacks = {
	.name		= "ibm,firmware-stacks",
	.start		= CPU_STACKS_BASE,
	.len		= 0, /* TBA */
	.type		= REGION_SKIBOOT_FIRMWARE,
};

struct alloc_hdr {
	bool free : 1;
	bool prev_free : 1;
	unsigned long num_longs : BITS_PER_LONG-2; /* Including header. */
	const char *location;
};

struct free_hdr {
	struct alloc_hdr hdr;
	struct list_node list;
	/* ... unsigned long tailer; */
};

#define ALLOC_HDR_LONGS (sizeof(struct alloc_hdr) / sizeof(long))
#define ALLOC_MIN_LONGS (sizeof(struct free_hdr) / sizeof(long) + 1)

/* Avoid ugly casts. */
static void *region_start(const struct mem_region *region)
{
	return (void *)(unsigned long)region->start;
}

/* Each free block has a tailer, so we can walk backwards. */
static unsigned long *tailer(struct free_hdr *f)
{
	return (unsigned long *)f + f->hdr.num_longs - 1;
}

/* This walks forward to the next hdr (or NULL if at the end). */
static struct alloc_hdr *next_hdr(const struct mem_region *region,
				  const struct alloc_hdr *hdr)
{
	void *next;

	next = ((unsigned long *)hdr + hdr->num_longs);
	if (next >= region_start(region) + region->len)
		next = NULL;
	return next;
}

/* Creates free block covering entire region. */
static void init_allocatable_region(struct mem_region *region)
{
	struct free_hdr *f = region_start(region);
	assert(region->type == REGION_SKIBOOT_HEAP);
	f->hdr.num_longs = region->len / sizeof(long);
	f->hdr.free = true;
	f->hdr.prev_free = false;
	*tailer(f) = f->hdr.num_longs;
	list_head_init(&region->free_list);
	list_add(&region->free_list, &f->list);
}

static void make_free(struct mem_region *region, struct free_hdr *f,
		      const char *location)
{
	struct alloc_hdr *next;

	if (f->hdr.prev_free) {
		struct free_hdr *prev;
		unsigned long *prev_tailer = (unsigned long *)f - 1;

		prev = (void *)((unsigned long *)f - *prev_tailer);
		assert(prev->hdr.free);
		assert(!prev->hdr.prev_free);

		/* Expand to cover the one we just freed. */
		prev->hdr.num_longs += f->hdr.num_longs;
		f = prev;
	} else {
		f->hdr.free = true;
		f->hdr.location = location;
		list_add(&region->free_list, &f->list);
	}

	/* Fix up tailer. */
	*tailer(f) = f->hdr.num_longs;

	/* If next is free, coalesce it */
	next = next_hdr(region, &f->hdr);
	if (next) {
		next->prev_free = true;
		if (next->free) {
			struct free_hdr *next_free = (void *)next;
			list_del_from(&region->free_list, &next_free->list);
			/* Maximum of one level of recursion */
			make_free(region, next_free, location);
		}
	}
}

/* Can we fit this many longs with this alignment in this free block? */
static bool fits(struct free_hdr *f, size_t longs, size_t align, size_t *offset)
{
	*offset = 0;

	while (f->hdr.num_longs >= *offset + longs) {
		size_t addr;

		addr = (unsigned long)f
			+ (*offset + ALLOC_HDR_LONGS) * sizeof(long);
		if ((addr & (align - 1)) == 0)
			return true;

		/* Don't make tiny chunks! */
		if (*offset == 0)
			*offset = ALLOC_MIN_LONGS;
		else
			(*offset)++;
	}
	return false;
}

static void discard_excess(struct mem_region *region,
			   struct alloc_hdr *hdr, size_t alloc_longs,
			   const char *location)
{
	/* Do we have excess? */
	if (hdr->num_longs > alloc_longs + ALLOC_MIN_LONGS) {
		struct free_hdr *post;

		/* Set up post block. */
		post = (void *)hdr + alloc_longs * sizeof(long);
		post->hdr.num_longs = hdr->num_longs - alloc_longs;
		post->hdr.prev_free = false;

		/* Trim our block. */
		hdr->num_longs = alloc_longs;

		/* This coalesces as required. */
		make_free(region, post, location);
	}
}

static const char *hdr_location(const struct alloc_hdr *hdr)
{
	/* Corrupt: step carefully! */
	if (is_rodata(hdr->location))
		return hdr->location;
	return "*CORRUPT*";
}

static void bad_header(const struct mem_region *region,
		       const struct alloc_hdr *hdr,
		       const char *during,
		       const char *location)
{
	/* Corrupt: step carefully! */
	if (is_rodata(hdr->location))
		prerror("%p (in %s) %s at %s, previously %s\n",
			hdr-1, region->name, during, location, hdr->location);
	else
		prerror("%p (in %s) %s at %s, previously %p\n",
			hdr-1, region->name, during, location, hdr->location);
	abort();
}

void *mem_alloc(struct mem_region *region, size_t size, size_t align,
		const char *location)
{
	size_t alloc_longs, offset;
	struct free_hdr *f;
	struct alloc_hdr *next;

	/* Align must be power of 2. */
	assert(!((align - 1) & align));

	/* This should be a constant. */
	assert(is_rodata(location));

	/* Unallocatable region? */
	if (region->type != REGION_SKIBOOT_HEAP)
		return NULL;

	/* First allocation? */
	if (region->free_list.n.next == NULL)
		init_allocatable_region(region);

	/* Don't do screwy sizes. */
	if (size > region->len)
		return NULL;

	/* Don't do tiny alignments, we deal in long increments. */
	if (align < sizeof(long))
		align = sizeof(long);

	/* Convert size to number of longs, too. */
	alloc_longs = (size + sizeof(long)-1) / sizeof(long) + ALLOC_HDR_LONGS;

	/* Can't be too small for when we free it, either. */
	if (alloc_longs < ALLOC_MIN_LONGS)
		alloc_longs = ALLOC_MIN_LONGS;

	/* Walk free list. */
	list_for_each(&region->free_list, f, list) {
		/* We may have to skip some to meet alignment. */
		if (fits(f, alloc_longs, align, &offset))
			goto found;
	}

	return NULL;

found:
	assert(f->hdr.free);
	assert(!f->hdr.prev_free);

	/* This block is no longer free. */
	list_del_from(&region->free_list, &f->list);
	f->hdr.free = false;
	f->hdr.location = location;

	next = next_hdr(region, &f->hdr);
	if (next) {
		assert(next->prev_free);
		next->prev_free = false;
	}

	if (offset != 0) {
		struct free_hdr *pre = f;

		f = (void *)f + offset * sizeof(long);
		assert(f >= pre + 1);

		/* Set up new header. */
		f->hdr.num_longs = pre->hdr.num_longs - offset;
		/* f->hdr.prev_free will be set by make_free below. */
		f->hdr.free = false;

		/* Fix up old header. */
		pre->hdr.num_longs = offset;
		pre->hdr.prev_free = false;

		/* This coalesces as required. */
		make_free(region, pre, location);
	}

	/* We might be too long; put the rest back. */
	discard_excess(region, &f->hdr, alloc_longs, location);

	/* Their pointer is immediately after header. */
	return &f->hdr + 1;
}

void mem_free(struct mem_region *region, void *mem, const char *location)
{
	struct alloc_hdr *hdr;

	/* This should be a constant. */
	assert(is_rodata(location));

	/* Freeing NULL is always a noop. */
	if (!mem)
		return;

	/* Your memory is in the region, right? */
	assert(mem >= region_start(region) + sizeof(*hdr));
	assert(mem < region_start(region) + region->len);

	/* Grab header. */
	hdr = mem - sizeof(*hdr);

	if (hdr->free)
		bad_header(region, hdr, "re-freed", location);

	make_free(region, (struct free_hdr *)hdr, location);
}

size_t mem_size(const struct mem_region *region __unused, const void *ptr)
{
	const struct alloc_hdr *hdr = ptr - sizeof(*hdr);
	return hdr->num_longs * sizeof(long);
}

bool mem_resize(struct mem_region *region, void *mem, size_t len,
		const char *location)
{
	struct alloc_hdr *hdr, *next;
	struct free_hdr *f;

	/* This should be a constant. */
	assert(is_rodata(location));

	/* Get header. */
	hdr = mem - sizeof(*hdr);
	if (hdr->free)
		bad_header(region, hdr, "resize", location);

	/* Round up size to multiple of longs. */
	len = (sizeof(*hdr) + len + sizeof(long) - 1) / sizeof(long);

	/* Can't be too small for when we free it, either. */
	if (len < ALLOC_MIN_LONGS)
		len = ALLOC_MIN_LONGS;

	/* Shrinking is simple. */
	if (len <= hdr->num_longs) {
		hdr->location = location;
		discard_excess(region, hdr, len, location);
		return true;
	}

	/* Check if we can expand. */
	next = next_hdr(region, hdr);
	if (!next || !next->free || hdr->num_longs + next->num_longs < len)
		return false;

	/* OK, it's free and big enough, absorb it. */
	f = (struct free_hdr *)next;
	list_del_from(&region->free_list, &f->list);
	hdr->num_longs += next->num_longs;
	hdr->location = location;

	/* Now we might have *too* much. */
	discard_excess(region, hdr, len, location);
	return true;
}

bool mem_check(const struct mem_region *region)
{
	size_t frees = 0;
	struct alloc_hdr *hdr, *prev_free = NULL;
	struct free_hdr *f;

	/* Check it's sanely aligned. */
	if (region->start % sizeof(struct alloc_hdr)) {
		prerror("Region '%s' not sanely aligned (%llx)\n",
			region->name, (unsigned long long)region->start);
		return false;
	}
	if ((long)region->len % sizeof(struct alloc_hdr)) {
		prerror("Region '%s' not sane length (%llu)\n",
			region->name, (unsigned long long)region->len);
		return false;
	}

	/* Not ours to play with, or empty?  Don't do anything. */
	if (region->type != REGION_SKIBOOT_HEAP ||
			region->free_list.n.next == NULL)
		return true;

	/* Walk linearly. */
	for (hdr = region_start(region); hdr; hdr = next_hdr(region, hdr)) {
		if (hdr->num_longs < ALLOC_MIN_LONGS) {
			prerror("Region '%s' %s %p (%s) size %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr_location(hdr),
				hdr->num_longs * sizeof(long));
				return false;
		}			
		if ((unsigned long)hdr + hdr->num_longs * sizeof(long) >
		    region->start + region->len) {
			prerror("Region '%s' %s %p (%s) oversize %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr_location(hdr),
				hdr->num_longs * sizeof(long));
				return false;
		}
		if (hdr->free) {
			if (hdr->prev_free || prev_free) {
				prerror("Region '%s' free %p (%s) has prev_free"
					" %p (%s) %sset?\n",
					region->name, hdr, hdr_location(hdr),
					prev_free,
					prev_free ? hdr_location(prev_free)
					: "NULL",
					hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = hdr;
			frees ^= (unsigned long)hdr - region->start;
		} else {
			if (hdr->prev_free != (bool)prev_free) {
				prerror("Region '%s' alloc %p (%s) has"
					" prev_free %p %sset?\n",
					region->name, hdr, hdr_location(hdr),
					prev_free, hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = NULL;
		}
	}

	/* Now walk free list. */
	list_for_each(&region->free_list, f, list)
		frees ^= (unsigned long)f - region->start;

	if (frees) {
		prerror("Region '%s' free list and walk do not match!\n",
			region->name);
		return false;
	}
	return true;
}

static struct mem_region *new_region(const char *name,
				     uint64_t start, uint64_t len,
				     struct dt_node *mem_node,
				     enum mem_region_type type)
{
	struct mem_region *region;

	/* Avoid lock recursion, call mem_alloc directly. */
	region = mem_alloc(&skiboot_heap,
			   sizeof(*region), __alignof__(*region), __location__);
	if (!region)
		return NULL;

	region->name = name;
	region->start = start;
	region->len = len;
	region->mem_node = mem_node;
	region->type = type;
	region->free_list.n.next = NULL;

	return region;
}

/* We always split regions, so we only have to replace one. */
static struct mem_region *split_region(struct mem_region *head,
				       uint64_t split_at,
				       enum mem_region_type type)
{
	struct mem_region *tail;
	uint64_t end = head->start + head->len;

	tail = new_region(head->name, split_at, end - split_at,
			  head->mem_node, type);
	/* Original region becomes head. */
	if (tail)
		head->len -= tail->len;

	return tail;
}

static bool intersects(const struct mem_region *region, uint64_t addr)
{
	return addr > region->start &&
		addr < region->start + region->len;
}

static bool maybe_split(struct mem_region *r, uint64_t split_at)
{
	struct mem_region *tail;

	if (!intersects(r, split_at))
		return true;

	tail = split_region(r, split_at, r->type);
	if (!tail)
		return false;

	/* Tail add is important: we may need to split again! */
	list_add_tail(&regions, &tail->list);
	return true;
}

static bool overlaps(const struct mem_region *r1, const struct mem_region *r2)
{
	return (r1->start + r1->len > r2->start
		&& r1->start < r2->start + r2->len);
}

static struct mem_region *get_overlap(const struct mem_region *region)
{
	struct mem_region *i;

	list_for_each(&regions, i, list) {
		if (overlaps(region, i))
			return i;
	}
	return NULL;
}

static bool add_region(struct mem_region *region)
{
	struct mem_region *r;

	/* First split any regions which intersect. */
	list_for_each(&regions, r, list)
		if (!maybe_split(r, region->start) ||
		    !maybe_split(r, region->start + region->len))
			return false;

	/* Now we have only whole overlaps, if any. */
	while ((r = get_overlap(region)) != NULL) {
		assert(r->start == region->start);
		assert(r->len == region->len);
		list_del_from(&regions, &r->list);
		/* We already hold mem_region lock */
		mem_free(&skiboot_heap, r, __location__);
	}

	/* Finally, add in our own region. */
	list_add(&regions, &region->list);
	return true;
}

/* Trawl through device tree, create memory regions from nodes. */
void mem_region_init(void)
{
	const struct dt_property *names, *ranges;
	struct mem_region *region;
	struct dt_node *i;

	lock(&mem_region_lock);

	/* Add each memory node. */
	dt_for_each_node(dt_root, i) {
		uint64_t start, len;

		if (!dt_has_node_property(i, "device_type", "memory"))
			continue;

		start = dt_get_address(i, 0, &len);
		region = new_region(i->name, start, len, i,
				REGION_SKIBOOT_HEAP);
		if (!region) {
			prerror("MEM: Could not add mem region %s!\n", i->name);
			abort();
		}
		list_add(&regions, &region->list);
	}

	/* Now we know how many CPU stacks we have, fix that up. */
	skiboot_cpu_stacks.len = cpu_max_pir * STACK_SIZE;

	/* Now carve out our own reserved areas. */
	if (!add_region(&skiboot_os_reserve) ||
	    !add_region(&skiboot_code_and_text) ||
	    !add_region(&skiboot_heap) ||
	    !add_region(&skiboot_after_heap) ||
	    !add_region(&skiboot_cpu_stacks)) {
		prerror("Out of memory adding skiboot reserved areas\n");
		abort();
	}

	/* Add reserved ranges from the DT */
	names = dt_find_property(dt_root, "reserved-names");
	ranges = dt_find_property(dt_root, "reserved-ranges");
	if (names && ranges) {
		uint64_t *range;
		int n, len;

		range = (void *)ranges->prop;

		for (n = 0; n < names->len; n += len, range += 2) {
			char *name;

			len = strlen(names->prop + n) + 1;

			name = mem_alloc(&skiboot_heap, len,
					__alignof__(*name), __location__);
			memcpy(name, names->prop + n, len);

			region = new_region(name,
					dt_get_number(range, 2),
					dt_get_number(range + 1, 2),
					NULL, REGION_RESERVED);
			list_add(&regions, &region->list);
		}
	} else if (names || ranges) {
		prerror("Invalid properties: reserved-names=%p "
				"with reserved-ranges=%p\n",
				names, ranges);
		abort();
	}

	unlock(&mem_region_lock);

	/* We generate the reservation properties from our own region list,
	 * which now includes the existing data.
	 */
	if (names)
		dt_del_property(dt_root, (struct dt_property *)names);
	if (ranges)
		dt_del_property(dt_root, (struct dt_property *)ranges);
}

static uint64_t allocated_length(const struct mem_region *r)
{
	struct free_hdr *f, *last = NULL;

	/* No allocations at all? */
	if (r->free_list.n.next == NULL)
		return 0;

	/* Find last free block. */
	list_for_each(&r->free_list, f, list)
		if (f > last)
			last = f;

	/* No free blocks? */
	if (!last)
		return r->len;

	/* Last free block isn't at end? */
	if (next_hdr(r, &last->hdr))
		return r->len;
	return (unsigned long)last - r->start;
}

/* Separate out allocated sections into their own region. */
void mem_region_release_unused(void)
{
	struct mem_region *r;

	lock(&mem_region_lock);

	printf("Releasing unused memory:\n");
	list_for_each(&regions, r, list) {
		uint64_t used_len;

		/* If it's not allocatable, ignore it. */
		if (r->type != REGION_SKIBOOT_HEAP)
			continue;

		used_len = allocated_length(r);

		printf("    %s: %llu/%llu used\n",
		       r->name, (long long)used_len, (long long)r->len);

		/* We keep the skiboot heap. */
		if (r == &skiboot_heap)
			continue;

		/* Nothing used?  Whole thing is for Linux. */
		if (used_len == 0)
			r->type = REGION_OS;
		/* Partially used?  Split region. */
		else if (used_len != r->len) {
			struct mem_region *for_linux;
			struct free_hdr *last = region_start(r) + used_len;

			/* Remove the final free block. */
			list_del_from(&r->free_list, &last->list);

			for_linux = split_region(r, r->start + used_len,
						 REGION_OS);
			if (!for_linux) {
				prerror("OOM splitting mem node %s for linux\n",
					r->name);
				abort();
			}
			list_add(&regions, &for_linux->list);
		}
	}
	unlock(&mem_region_lock);
}

static bool region_is_reserved(struct mem_region *region)
{
	return region->type != REGION_OS;
}

void mem_region_add_dt_reserved(void)
{
	int names_len, ranges_len, len;
	struct mem_region *region;
	void *names, *ranges;
	uint64_t *range;
	char *name;

	names_len = 0;
	ranges_len = 0;

	lock(&mem_region_lock);

	/* First pass: calculate length of property data */
	list_for_each(&regions, region, list) {
		if (!region_is_reserved(region))
			continue;
		names_len += strlen(region->name) + 1;
		ranges_len += 2 * sizeof(uint64_t);
	}

	/* Allocate property data with mem_alloc; malloc() acquires
	 * mem_region_lock */
	names = mem_alloc(&skiboot_heap, names_len,
			__alignof__(*names), __location__);
	ranges = mem_alloc(&skiboot_heap, ranges_len,
			__alignof__(*ranges), __location__);

	name = names;
	range = ranges;

	/* Second pass: populate property data */
	list_for_each(&regions, region, list) {
		if (!region_is_reserved(region))
			continue;
		len = strlen(region->name) + 1;
		memcpy(name, region->name, len);
		name += len;

		range[0] = cpu_to_fdt64(region->start);
		range[1] = cpu_to_fdt64(region->len);
		range += 2;
	}
	unlock(&mem_region_lock);

	dt_add_property(dt_root, "reserved-names", names, names_len);
	dt_add_property(dt_root, "reserved-ranges", ranges, ranges_len);

	free(names);
	free(ranges);
}
