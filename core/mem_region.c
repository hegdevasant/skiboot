/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <mem_region.h>
#include <lock.h>

struct lock mem_region_lock = LOCK_UNLOCKED;

struct mem_region skiboot_heap = {
	.name		= "ibm,firmware-heap",
	.start		= (void *)HEAP_BASE,
	.len		= HEAP_SIZE,
	.allocatable	= true
};

struct alloc_hdr {
	bool free : 1;
	bool prev_free : 1;
	unsigned long num_longs : BITS_PER_LONG-2; /* Including header. */
};

struct free_hdr {
	struct alloc_hdr hdr;
	struct list_node list;
	/* ... unsigned long tailer; */
};

#define ALLOC_HDR_LONGS (sizeof(struct alloc_hdr) / sizeof(long))
#define ALLOC_MIN_LONGS (sizeof(struct free_hdr) / sizeof(long) + 1)

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
	if (next >= region->start + region->len)
		next = NULL;
	return next;
}

/* Creates free block covering entire region. */
static void init_allocatable_region(struct mem_region *region)
{
	struct free_hdr *f = region->start;
	assert(region->allocatable);
	f->hdr.num_longs = region->len / sizeof(long);
	f->hdr.free = true;
	f->hdr.prev_free = false;
	*tailer(f) = f->hdr.num_longs;
	list_head_init(&region->free_list);
	list_add(&region->free_list, &f->list);
}

static void make_free(struct mem_region *region, struct free_hdr *f)
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
			make_free(region, next_free);
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
			   struct alloc_hdr *hdr, size_t alloc_longs)
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
		make_free(region, post);
	}
}

void *mem_alloc(struct mem_region *region, size_t size, size_t align)
{
	size_t alloc_longs, offset;
	struct free_hdr *f;
	struct alloc_hdr *next;

	/* Align must be power of 2. */
	assert(!((align - 1) & align));

	/* Unallocatable region? */
	if (!region->allocatable)
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
		make_free(region, pre);
	}

	/* We might be too long; put the rest back. */
	discard_excess(region, &f->hdr, alloc_longs);

	/* Their pointer is immediately after header. */
	return &f->hdr + 1;
}

void mem_free(struct mem_region *region, void *mem)
{
	struct alloc_hdr *hdr;

	/* Freeing NULL is always a noop. */
	if (!mem)
		return;

	/* Your memory is in the region, right? */
	assert(mem >= region->start + sizeof(*hdr));
	assert(mem < region->start + region->len);

	/* Grab header. */
	hdr = mem - sizeof(*hdr);
	assert(!hdr->free);
	assert(hdr->num_longs);

	make_free(region, (struct free_hdr *)hdr);
}

size_t mem_size(const struct mem_region *region __unused, const void *ptr)
{
	const struct alloc_hdr *hdr = ptr - sizeof(*hdr);
	return hdr->num_longs * sizeof(long);
}

bool mem_resize(struct mem_region *region, void *mem, size_t len)
{
	struct alloc_hdr *hdr, *next;
	struct free_hdr *f;

	/* Get header. */
	hdr = mem - sizeof(*hdr);
	assert(hdr->num_longs);

	/* Round up size to multiple of longs. */
	len = (sizeof(*hdr) + len + sizeof(long) - 1) / sizeof(long);

	/* Can't be too small for when we free it, either. */
	if (len < ALLOC_MIN_LONGS)
		len = ALLOC_MIN_LONGS;

	/* Shrinking is simple. */
	if (len <= hdr->num_longs) {
		discard_excess(region, hdr, len);
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

	/* Now we might have *too* much. */
	discard_excess(region, hdr, len);
	return true;
}

bool mem_check(const struct mem_region *region)
{
	size_t frees = 0;
	struct alloc_hdr *hdr, *prev_free = NULL;
	struct free_hdr *f;

	/* Check it's sanely aligned. */
	if ((long)region->start % sizeof(struct alloc_hdr)) {
		prerror("Region '%s' not sanely aligned (%p)\n",
			region->name, region->start);
		return false;
	}
	if ((long)region->len % sizeof(struct alloc_hdr)) {
		prerror("Region '%s' not sane length (%llu)\n",
			region->name, (unsigned long long)region->len);
		return false;
	}

	/* Not ours to play with, or empty?  Don't do anything. */
	if (!region->allocatable || region->free_list.n.next == NULL)
		return true;

	/* Walk linearly. */
	for (hdr = region->start; hdr; hdr = next_hdr(region, hdr)) {
		if (hdr->num_longs < ALLOC_MIN_LONGS) {
			prerror("Region '%s' %s %p size %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr->num_longs * sizeof(long));
				return false;
		}			
		if ((void *)hdr + hdr->num_longs * sizeof(long) >
		    region->start + region->len) {
			prerror("Region '%s' %s %p oversize %zu\n",
				region->name, hdr->free ? "free" : "alloc",
				hdr, hdr->num_longs * sizeof(long));
				return false;
		}
		if (hdr->free) {
			if (hdr->prev_free || prev_free) {
				prerror("Region '%s' free %p has prev_free"
					" %p %sset?\n",
					region->name, hdr,
					prev_free, hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = hdr;
			frees ^= (void *)hdr - region->start;
		} else {
			if (hdr->prev_free != (bool)prev_free) {
				prerror("Region '%s' alloc %p has prev_free"
					" %p %sset?\n",
					region->name, hdr,
					prev_free, hdr->prev_free ? "" : "un");
				return false;
			}
			prev_free = NULL;
		}
	}

	/* Now walk free list. */
	list_for_each(&region->free_list, f, list)
		frees ^= (void *)f - region->start;

	if (frees) {
		prerror("Region '%s' free list and walk do not match!\n",
			region->name);
		return false;
	}
	return true;
}
