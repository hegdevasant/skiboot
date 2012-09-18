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

