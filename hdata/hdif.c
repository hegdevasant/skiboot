#include <hdif.h>

const void *HDIF_get_idata(const void *hdif, unsigned int di,
			   unsigned int *size)
{
	const struct HDIF_common_hdr *hdr = hdif;
	const struct HDIF_idata_ptr *iptr;

	if (hdr->d1f0 != 0xd1f0) {
		prerror("HDIF: Bad header format !\n");
		return NULL;
	}

	if (di >= hdr->idptr_count) {
		prerror("HDIF: idata index out of range !\n");
		return NULL;
	}

	iptr = hdif + (hdr->idptr_off) + di * sizeof(struct HDIF_idata_ptr);

	if (size)
		*size = iptr->size;

	return hdif + iptr->offset;
}

const void *HDIF_get_iarray_item(const void *hdif, unsigned int di,
				 unsigned int ai, unsigned int *size)
{
	const struct HDIF_array_hdr *ahdr;
	unsigned int asize;
	const void *arr;

	arr = HDIF_get_idata(hdif, di, &asize);
	if (!arr)
		return NULL;

	if (asize < sizeof(struct HDIF_array_hdr)) {
		prerror("HDIF: idata block too small for array !\n");
		return NULL;
	}

	ahdr = arr;

	if (ai >= ahdr->ecnt) {
		prerror("HDIF: idata array index out of range !\n");
		return NULL;
	}

	if (size)
		*size = ahdr->eactsz;

	return arr + ahdr->offset + ai * ahdr->esize;
}

int HDIF_get_iarray_size(const void *hdif, unsigned int di)
{
	const struct HDIF_array_hdr *ahdr;
	unsigned int asize;
	const void *arr;

	arr = HDIF_get_idata(hdif, di, &asize);
	if (!arr)
		return -1;

	if (asize < sizeof(struct HDIF_array_hdr)) {
		prerror("HDIF: idata block too small for array !\n");
		return -1;
	}

	ahdr = arr;
	return ahdr->ecnt;
}

struct HDIF_child_ptr *
HDIF_child_arr(const struct HDIF_common_hdr *hdif, unsigned int idx)
{
	struct HDIF_child_ptr *children = (void *)hdif + hdif->child_off;

	if (idx >= hdif->child_count) {
		prerror("HDIF: child array idx out of range!\n");
		return NULL;
	}

	return &children[idx];
}

struct HDIF_common_hdr *HDIF_child(const struct HDIF_common_hdr *hdif,
				   const struct HDIF_child_ptr *child,
				   unsigned int idx,
				   const char *eyecatcher)
{
	void *base = (void *)hdif;
	struct HDIF_common_hdr *ret;
	long child_off;

	/* child must be in hdif's child array */
	child_off = (void *)child - (base + hdif->child_off);
	assert(child_off % sizeof(struct HDIF_child_ptr) == 0);
	assert(child_off / sizeof(struct HDIF_child_ptr)
	       < hdif->child_count);

	assert(idx < child->count);

	if (child->size < sizeof(struct HDIF_common_hdr)) {
		prerror("HDIF: %s child #%i too small: %u\n",
			eyecatcher, idx, child->size);
		return NULL;
	}

	ret = base + child->offset + child->size * idx;
	if (!HDIF_check(ret, eyecatcher)) {
		prerror("HDIF: %s child #%i bad type\n",
			eyecatcher, idx);
		return NULL;
	}

	return ret;
}
