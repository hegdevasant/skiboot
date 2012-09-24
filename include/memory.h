#ifndef __MEMORY_H
#define __MEMORY_H
#include <hdif.h>

/* This is a linked list of all *functional* address ranges, with only one
 * entry for each shared one. */
extern struct list_head address_ranges;

struct HDIF_ram_area_id {
	uint16_t id;
#define RAM_AREA_INSTALLED	0x8000
#define RAM_AREA_FUNCTIONAL	0x4000
	uint16_t flags;
};

struct HDIF_ram_area_size {
	uint64_t mb;
};

struct ram_area {
	const struct HDIF_ram_area_id *raid;
	const struct HDIF_ram_area_size *rasize;
};

struct HDIF_ms_area_address_range {
	uint64_t start;
	uint64_t end;
	uint32_t chip;
	uint32_t mirror_attr;
	uint64_t mirror_start;
};

struct address_range {
	struct list_node list;

	/* This is the msarea we are inside, and shortcut to its FRU id */
	const struct HDIF_common_hdr *msarea;
	const void *fru_id;
	uint32_t fru_id_len;

	/* This is our element inside msarea's Address Range Array. */
	const struct HDIF_ms_area_address_range *arange;

	/* Which primary thread (ie. physical chip id) are we connected to? */
	struct cpu_thread *attached;

	/* Interleaved MS Area ID, or -1 if not shared. */
	int share_id;

	/* Other overlapping addresses (with same share id) */
	struct list_head shared;

	/* This basically represents each DIMM. */
	uint32_t num_ram_areas;
	struct ram_area ram_areas[];
};

/* This populates msareas list. */
extern void memory_parse(void);
#endif /* __MEMORY_H */
