#ifndef __HDIF_H
#define __HDIF_H

#include <skiboot.h>

struct HDIF_common_hdr {
	uint64_t	id;		/* 0xd1f0xxxxxxxxxx with eye catcher */
	uint16_t	instnum;	/* instance number */
	uint16_t	version;	/* version */
	uint32_t	total_len;	/* total structure length */
	uint32_t	hdr_len;	/* header length (currently 0x20) */
	uint32_t	idptr_off;	/* offset to idata pointers */
	uint16_t	idptr_count;	/* number of idata pointers */
	uint16_t	child_count;	/* number of child structures */
	uint32_t	child_off;	/* offset to child structures array */
} __packed __align(0x10);

struct HDIF_idata_ptr {
	uint32_t	offset;
	uint32_t	size;
} __packed __align(0x8);

struct HDIF_array_hdr {
	uint32_t	offset;
	uint32_t	ecnt;
	uint32_t	esize;
	uint32_t	eactsz;
} __packed __align(0x10);

#define HDIF_FORMAT_ID		0xd1f0
#define HDIF_HDR_LEN		(sizeof(struct HDIF_common_hdr))
#define HDIF_ARRAY_OFFSET	(sizeof(struct HDIF_array_hdr))

#define HDIF_MKID(N1,N2,N3,N4,N5,N6)		\
	((uint64_t)HDIF_FORMAT_ID << 48 |	\
	 (uint64_t)(N1) << 40 |			\
	 (uint64_t)(N2) << 32 |			\
	 (uint64_t)(N3) << 24 |			\
	 (uint64_t)(N4) << 16 |			\
	 (uint64_t)(N5) <<  8 |			\
	 (uint64_t)(N6))


#define HDIF_SIMPLE_HDR(N1,N2,N3,N4,N5,N6, vers, type)		\
{								\
	.id		= HDIF_MKID(N1,N2,N3,N4,N5,N6),		\
	.instnum	= 0,					\
	.version	= vers,					\
	.total_len	= sizeof(type),				\
	.hdr_len	= HDIF_HDR_LEN,				\
	.idptr_off	= HDIF_HDR_LEN,				\
	.idptr_count	= 1,					\
	.child_count	= 0,					\
	.child_off	= 0,					\
}

static inline bool __HDIF_check(const void *hdif, uint64_t id)
{
	const struct HDIF_common_hdr *hdr = hdif;

	return hdr->id == id;
}
#define HDIF_check(hdif, N1,N2,N3,N4,N5,N6)	\
	__HDIF_check(hdif, HDIF_MKID(N1,N2,N3,N4,N5,N6))

/* HDIF_get_idata - Get a pointer to internal data block
 *
 * @hdif  : HDIF structure pointer
 * @di    : Index of the idata pointer
 * @size  : Return the data size (or NULL if ignored)
 */
extern const void *HDIF_get_idata(const void *hdif, unsigned int di,
				  unsigned int *size);

/* HDIF_get_iarray - Get a pointer to an elemnt of an internal data array
 *
 * @hdif  : HDIF structure pointer
 * @di    : Index of the idata pointer
 * @ai    : Index in the resulting array
 * @size  : Return the entry actual size (or NULL if ignored)
 */
extern const void *HDIF_get_iarray_item(const void *hdif, unsigned int di,
					unsigned int ai, unsigned int *size);

#endif /* __HDIF_H */
