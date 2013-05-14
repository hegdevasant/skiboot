/* Wrappers for malloc, et. al. */
#include <mem_region.h>
#include <lock.h>
#include <string.h>

#define DEFAULT_ALIGN __alignof__(long)

void *memalign(size_t blocksize, size_t bytes)
{
	void *p;

	lock(&mem_region_lock);
	p = mem_alloc(&skiboot_heap, bytes, blocksize);
	unlock(&mem_region_lock);

	return p;
}

void *malloc(size_t bytes)
{
	return memalign(DEFAULT_ALIGN, bytes);
}

void free(void *p)
{
	lock(&mem_region_lock);
	mem_free(&skiboot_heap, p);
	unlock(&mem_region_lock);
}

void *realloc(void *ptr, size_t size)
{
	void *newptr;

	/* Two classic malloc corner cases. */
	if (!size) {
		free(ptr);
		return NULL;
	}
	if (!ptr)
		return malloc(size);

	lock(&mem_region_lock);
	if (mem_resize(&skiboot_heap, ptr, size)) {
		newptr = ptr;
	} else {
		newptr = mem_alloc(&skiboot_heap, size, DEFAULT_ALIGN);
		if (newptr) {
			size_t copy = mem_size(&skiboot_heap, ptr);
			if (copy > size)
				copy = size;
			memcpy(newptr, ptr, copy);
			mem_free(&skiboot_heap, ptr);
		}
	}
	unlock(&mem_region_lock);
	return newptr;
}

void *zalloc(size_t bytes)
{
	void *p = malloc(bytes);

	if (p)
		memset(p, 0, bytes);
	return p;
}
