/* Wrappers for malloc, et. al. */
#include <mem_region.h>
#include <lock.h>
#include <string.h>

#define DEFAULT_ALIGN __alignof__(long)

void *__memalign(size_t blocksize, size_t bytes, const char *location)
{
	void *p;

	lock(&mem_region_lock);
	p = mem_alloc(&skiboot_heap, bytes, blocksize, location);
	unlock(&mem_region_lock);

	return p;
}

void *__malloc(size_t bytes, const char *location)
{
	return __memalign(DEFAULT_ALIGN, bytes, location);
}

void __free(void *p, const char *location)
{
	lock(&mem_region_lock);
	mem_free(&skiboot_heap, p, location);
	unlock(&mem_region_lock);
}

void *__realloc(void *ptr, size_t size, const char *location)
{
	void *newptr;

	/* Two classic malloc corner cases. */
	if (!size) {
		__free(ptr, location);
		return NULL;
	}
	if (!ptr)
		return __malloc(size, location);

	lock(&mem_region_lock);
	if (mem_resize(&skiboot_heap, ptr, size, location)) {
		newptr = ptr;
	} else {
		newptr = mem_alloc(&skiboot_heap, size, DEFAULT_ALIGN,
				   location);
		if (newptr) {
			size_t copy = mem_size(&skiboot_heap, ptr);
			if (copy > size)
				copy = size;
			memcpy(newptr, ptr, copy);
			mem_free(&skiboot_heap, ptr, location);
		}
	}
	unlock(&mem_region_lock);
	return newptr;
}

void *__zalloc(size_t bytes, const char *location)
{
	void *p = __malloc(bytes, location);

	if (p)
		memset(p, 0, bytes);
	return p;
}
