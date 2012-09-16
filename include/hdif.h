#ifndef __HDIF_H
#define __HDIF_H

#include <stdint.h>

#define __packed		__attribute__((packed))
#define __align(x)		__attribute__((__aligned__(x)))
#define offsetof(type,m)	__builtin_offsetof(type,m)

struct HDIF_common_hdr {
	uint16_t	format_id;	/* 0xd1f0 */
	uint8_t		name[6];	/* eye catcher */
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
	uint32_t	idata_off;
	uint32_t	idata_size;
} __packed __align(0x10);

struct HDIF_array_hdr {
	uint32_t	offset;
	uint32_t	ecnt;
	uint32_t	esize;
	uint32_t	eactsz;
} __packed __align(0x10);

#define HDIF_FORMAT_ID		0xd1f0
#define HDIF_HDR_LEN		(sizeof(struct HDIF_common_hdr))
#define HDIF_ARRAY_OFFSET	(sizeof(struct HDIF_array_hdr))

#define HDIF_SIMPLE_HDR(N1,N2,N3,N4,N5,N6, vers, type)		\
{								\
	.format_id	= HDIF_FORMAT_ID,			\
	.name		= { N1,N2,N3,N4,N5,N6 },		\
	.instnum	= 0,					\
	.version	= vers,					\
	.total_len	= sizeof(type),				\
	.hdr_len	= HDIF_HDR_LEN,				\
	.idptr_off	= HDIF_HDR_LEN,				\
	.idptr_count	= 1,					\
	.child_count	= 0,					\
	.child_off	= 0,					\
}


#endif /* __HDIF_H */
