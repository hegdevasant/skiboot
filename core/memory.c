#include <spira.h>
#include <memory.h>

struct list_head address_ranges = LIST_HEAD_INIT(address_ranges);

/* Mainstore Address Configuration */
struct HDIF_ms_vpd_msac {
	uint64_t max_configured_ms_address;
	uint64_t max_possible_ms_address;
	uint32_t deprecated;
	uint64_t mirrorable_memory_starting_address;
} __attribute__((packed));

/* Total Configured Mainstore */
struct HDIF_ms_vpd_tcms {
	uint64_t total_in_mb;
};

struct HDIF_ms_area_id {
	uint16_t id;
	uint16_t parent_type;
#define MS_AREA_INSTALLED	0x8000
#define MS_AREA_FUNCTIONAL	0x4000
#define MS_AREA_SHARED		0x2000
	uint16_t flags;
	uint16_t share_id;
};

static struct address_range *find_shared(int share_id, 
				 const struct HDIF_ms_area_address_range *ar)
{
	struct address_range *i;

	list_for_each(&address_ranges, i, list) {
		if (i->share_id != share_id)
			continue;
		if (i->arange->start != ar->start)
			continue;
		if (i->arange->end != ar->end)
			continue;
		return i;
	}
	return NULL;
}

static bool add_address_range(const struct HDIF_common_hdr *msarea,
			      const void *fruid, uint32_t fruidlen,
			      const struct HDIF_ms_area_id *id,
			      const struct HDIF_child_ptr *ramptr,
			      const struct HDIF_ms_area_address_range *arange)
{
	unsigned int i;
	struct address_range *new;

	new = malloc(sizeof(*new) + ramptr->count*sizeof(struct ram_area));
	if (!new) {
		prerror("Failed to allocate memory for %u ram areas\n",
			ramptr->count);
		return false;
	}

	printf("  Range 0x%llx - 0x%llx (chip %u)\n",
	       arange->start, arange->end, arange->chip);

	new->msarea = msarea;
	new->fru_id = fruid;
	new->fru_id_len = fruidlen;
	new->arange = arange;
	list_head_init(&new->shared);

	if (id->flags & MS_AREA_SHARED)
		new->share_id = id->share_id;
	else
		new->share_id = -1;

	new->num_ram_areas = ramptr->count;
	for (i = 0; i < new->num_ram_areas; i++) {
		const struct HDIF_common_hdr *ramarea;
		unsigned int size;

		ramarea = HDIF_child(msarea, ramptr, i, "RAM   ");
		if (!CHECK_SPPTR(ramarea))
			return false;

		new->ram_areas[i].raid = HDIF_get_idata(ramarea, 2, &size);
		if (!CHECK_SPPTR(new->ram_areas[i].raid))
			return false;
		if (size < sizeof(*new->ram_areas[i].raid)) {
			prerror("msarea %p ramarea %i id too small\n",
				msarea, i);
			return false;
		}

		new->ram_areas[i].rasize = HDIF_get_idata(ramarea, 3, &size);
		if (!new->ram_areas[i].rasize)
			return false;
		if (size < sizeof(*new->ram_areas[i].rasize)) {
			prerror("msarea %p ramarea %i size too small\n",
				msarea, i);
				return false;
		}

		/* If not installed and functional, don't include. */
		printf("    DIMM %u %s%s %lluMB\n",
		       new->ram_areas[i].raid->id,
		       new->ram_areas[i].raid->flags & RAM_AREA_INSTALLED
		       ? "installed" : "not installed",
		       new->ram_areas[i].raid->flags & RAM_AREA_FUNCTIONAL
		       ? "functional" : "not functional",
		       new->ram_areas[i].rasize->mb);

		/* FIXME: Don't barf on non-functional DIMMs */
		assert((new->ram_areas[i].raid->flags &
			(RAM_AREA_INSTALLED|RAM_AREA_FUNCTIONAL))
		       == (RAM_AREA_INSTALLED|RAM_AREA_FUNCTIONAL));
	}

	/* If it's shared, chain it off a previous one (if any) */
	if (id->flags & MS_AREA_SHARED) {
		/* FIXME: Untested code! */
		struct address_range *sharer = find_shared(id->share_id, arange);
		if (sharer) {
			list_add_tail(&sharer->shared, &new->list);
			return true;
		}
	}

	list_add_tail(&address_ranges, &new->list);
	return true;
}

static void get_msareas(const struct HDIF_common_hdr *ms_vpd)
{
	unsigned int i;
	const struct HDIF_child_ptr *msptr;

	/* First childptr refers to msareas. */
	msptr = HDIF_child_arr(ms_vpd, 0);
	if (!CHECK_SPPTR(msptr)) {
		prerror("ms_vpd: no children at %p\n", ms_vpd);
		return;
	}

	for (i = 0; i < msptr->count; i++) {
		const struct HDIF_common_hdr *msarea;
		const struct HDIF_array_hdr *arr;
		const struct HDIF_ms_area_address_range *arange;
		const struct HDIF_ms_area_id *id;
		const struct HDIF_child_ptr *ramptr;
		const void *fruid;
		unsigned int size, j;

		msarea = HDIF_child(ms_vpd, msptr, i, "MSAREA");
		if (!CHECK_SPPTR(msarea))
			return;

		id = HDIF_get_idata(msarea, 2, &size);
		if (!CHECK_SPPTR(id))
			return;
		if (size < sizeof(*id)) {
			prerror("ms_vpd %p msarea #%i id size too small!\n",
				ms_vpd, i);
			return;
		}

		printf("ms_vpd %p, area %i: %s %s %s\n",
		       ms_vpd, i,
		       id->flags & MS_AREA_INSTALLED ?
		       "installed" : "not installed",
		       id->flags & MS_AREA_FUNCTIONAL ?
		       "functional" : "not functional",
		       id->flags & MS_AREA_SHARED ?
		       "shared" : "not shared");

		if ((id->flags & (MS_AREA_INSTALLED|MS_AREA_FUNCTIONAL))
		    != (MS_AREA_INSTALLED|MS_AREA_FUNCTIONAL))
			continue;

		arr = HDIF_get_idata(msarea, 4, &size);
		if (!CHECK_SPPTR(arr))
			continue;

		if (size < sizeof(*arr)) {
			prerror("ms_vpd %p msarea #%i arr size too small!\n",
				ms_vpd, i);
			return;
		}

		if (arr->eactsz < sizeof(*arange)) {
			prerror("ms_vpd %p msarea #%i arange size too small!\n",
				ms_vpd, i);
			return;
		}

		ramptr = HDIF_child_arr(msarea, 0);
		if (!CHECK_SPPTR(ramptr))
			return;

		fruid = HDIF_get_idata(msarea, 0, &size);
		if (!CHECK_SPPTR(fruid))
			return;

		/* This offset is from the arr, not the header! */
		arange = (void *)arr + arr->offset;
		for (j = 0; j < arr->ecnt; j++) {
			if (!add_address_range(msarea, fruid, size, id, ramptr,
					       arange))
				return;
			arange = (void *)arange + arr->esize;
		}
	}
}

void memory_parse(void)
{
	struct HDIF_common_hdr *ms_vpd;
	unsigned int size, i;
	const struct HDIF_ms_vpd_msac *msac;
	const struct HDIF_ms_vpd_tcms *tcms;

	ms_vpd = spira.ntuples.ms_vpd.addr;
	if (!HDIF_check(ms_vpd, "MS VPD")) {
		prerror("ms_vpd: invalid id field at %p\n", ms_vpd);
		return;
	}
	if (spira.ntuples.ms_vpd.act_len < sizeof(*ms_vpd)) {
		prerror("ms_vpd: invalid size %u\n",
			spira.ntuples.ms_vpd.act_len);
		return;
	}

	for (i = 0; i < spira.ntuples.ms_vpd.act_cnt; i++) {
		printf("MSVPD[%i] is at %p\n", i, ms_vpd);

		msac = HDIF_get_idata(ms_vpd, 0, &size);
		if (!CHECK_SPPTR(msac) || size < sizeof(*msac)) {
			prerror("ms_vpd[%i]: bad msac size %u @ %p\n",
				i, size, msac);
			return;
		}
		printf("MSAC[%i] is at %p\n", i, msac);

		tcms = HDIF_get_idata(ms_vpd, 1, &size);
		if (!CHECK_SPPTR(tcms) || size < sizeof(*tcms)) {
			prerror("ms_vpd[%i]: bad tcms size %u @ %p\n",
				i, size, tcms);
			return;
		}
		printf("TCMS is at %p\n", tcms);

		printf("Maximum configured address: 0x%llx\n",
		       msac->max_configured_ms_address);
		printf("Maximum possible address: 0x%llx\n",
		       msac->max_possible_ms_address);

		get_msareas(ms_vpd);

		ms_vpd = (void *)ms_vpd + spira.ntuples.ms_vpd.act_len;
		printf("Total MB of RAM: 0x%llx\n", tcms->total_in_mb);
	}
}	
