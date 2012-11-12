#include <spira.h>
#include <memory.h>
#include <cpu.h>
#include <device_tree.h>
#include <device.h>
#include <ccan/str/str.h>
#include <hdif.h>
#include <libfdt/libfdt.h>

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

struct HDIF_ms_area_id {
	uint16_t id;
	uint16_t parent_type;
#define MS_AREA_INSTALLED	0x8000
#define MS_AREA_FUNCTIONAL	0x4000
#define MS_AREA_SHARED		0x2000
	uint16_t flags;
	uint16_t share_id;
};

static struct dt_node *find_shared(struct dt_node *root, u16 id, u64 start, u64 len)
{
	struct dt_node *i;

	for (i = dt_first(root); i; i = dt_next(root, i)) {
		u64 reg[2];
		struct dt_property *shared, *type;

		type = dt_find_property(i, "device-type");
		if (!type || strcmp(type->prop, "memory") != 0)
			continue;

		shared = dt_find_property(i, DT_PRIVATE "share-id");
		if (!shared || fdt32_to_cpu(*(u32 *)shared->prop) != id)
			continue;

		memcpy(reg, dt_find_property(i, "reg")->prop, sizeof(reg));
		if (reg[0] == start && reg[1] == len)
			break;
	}
	return i;
}

static bool add_address_range(struct dt_node *root,
			      const struct HDIF_ms_area_id *id,
			      const struct HDIF_ms_area_address_range *arange)
{
	struct dt_node *mem;
	u64 reg[2];
	char name[sizeof("memory@") + STR_MAX_CHARS(reg[0])];
	struct cpu_thread *attached;

	/* reg contains start and length */
	reg[0] = cleanup_addr(arange->start);
	reg[1] = cleanup_addr(arange->end) - reg[0];

	/* FIXME: Untested code! */
	if (id->flags & MS_AREA_SHARED) {
		/* Only enter shared nodes once. */ 
		if (find_shared(root, id->share_id, reg[0], reg[1]))
			return true;
	}
	sprintf(name, "memory@%llx", reg[0]);

	mem = dt_new(root, name);
	dt_add_property_string(mem, "device_type", "memory");
	dt_add_property(mem, "reg", reg, sizeof(reg));
	if (id->flags & MS_AREA_SHARED)
		dt_add_property_cell(mem, DT_PRIVATE "share-id", id->share_id);

	/* FIXME: Do numa properly using this! */
	attached = find_cpu_by_chip_id(arange->chip);
	if (!attached) {
		prerror("MS VPD: could not find chip id %u\n", arange->chip);
		return false;
	}

	return true;
}

static void get_msareas(struct dt_node *root,
			const struct HDIF_common_hdr *ms_vpd)
{
	unsigned int i;
	const struct HDIF_child_ptr *msptr;

	/* First childptr refers to msareas. */
	msptr = HDIF_child_arr(ms_vpd, MSVPD_CHILD_MS_AREAS);
	if (!CHECK_SPPTR(msptr)) {
		prerror("MS VPD: no children at %p\n", ms_vpd);
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
			prerror("MS VPD: %p msarea #%i id size too small!\n",
				ms_vpd, i);
			return;
		}

		printf("MS VPD: %p, area %i: %s %s %s\n",
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
			prerror("MS VPD: %p msarea #%i arr size too small!\n",
				ms_vpd, i);
			return;
		}

		if (arr->eactsz < sizeof(*arange)) {
			prerror("MS VPD: %p msarea #%i arange size too small!\n",
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
			if (!add_address_range(root, id, arange))
				return;
			arange = (void *)arange + arr->esize;
		}
	}
}

uint64_t __memory_parse(struct dt_node *root)
{
	struct HDIF_common_hdr *ms_vpd;
	const struct msvpd_ms_addr_config *msac;
	const struct msvpd_total_config_ms *tcms;
	unsigned int size;

	ms_vpd = spira.ntuples.ms_vpd.addr;
	if (!ms_vpd || !HDIF_check(ms_vpd, MSVPD_HDIF_SIG)) {
		prerror("MS VPD: invalid id field at %p\n", ms_vpd);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0000);
		return 0;
	}
	if (spira.ntuples.ms_vpd.act_len < sizeof(*ms_vpd)) {
		prerror("MS VPD: invalid size %u\n",
			spira.ntuples.ms_vpd.act_len);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0001);
		return 0;
	}

	printf("MS VPD: is at %p\n", ms_vpd);

	msac = HDIF_get_idata(ms_vpd, MSVPD_IDATA_MS_ADDR_CONFIG, &size);
	if (!CHECK_SPPTR(msac) || size < sizeof(*msac)) {
		prerror("MS VPD: bad msac size %u @ %p\n", size, msac);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0002);
		return 0;
	}
	printf("MS VPD: MSAC is at %p\n", msac);

	tcms = HDIF_get_idata(ms_vpd, MSVPD_IDATA_TOTAL_CONFIG_MS, &size);
	if (!CHECK_SPPTR(tcms) || size < sizeof(*tcms)) {
		prerror("MS VPD: Bad tcms size %u @ %p\n", size, tcms);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0003);
		return 0;
	}
	printf("MS VPD: TCMS is at %p\n", tcms);

	printf("MS VPD: Maximum configured address: 0x%llx\n",
	       msac->max_configured_ms_address);
	printf("MS VPD: Maximum possible address: 0x%llx\n",
	       msac->max_possible_ms_address);

	get_msareas(root, ms_vpd);

	printf("MS VPD: Total MB of RAM: 0x%llx\n", tcms->total_in_mb);

	return msac->max_configured_ms_address;
}

uint64_t memory_parse(void)
{
	uint64_t max_addr;

	max_addr = __memory_parse(dt_root);
	if (!max_addr) {
		prerror("MS VPD: Failed memory init !\n");
		abort();
	}
	return max_addr;
}

#ifdef FAST_REBOOT_CLEARS_MEMORY
static void fast_mem_clear(uint64_t start, uint64_t end)
{
	printf("MEMORY: Clearing %llx..%llx\n", start, end);

	while(start < end) {
		asm volatile("dcbz 0,%0" : : "r" (start) : "memory");
		start += 128;
	}
}

void memory_reset(void)
{
	struct address_range *i;
	uint64_t skistart = SKIBOOT_BASE;
	uint64_t skiend = SKIBOOT_BASE + SKIBOOT_SIZE;

	printf("MEMORY: Clearing ...\n");

	list_for_each(&address_ranges, i, list) {
		uint64_t start = cleanup_addr(i->arange->start);
		uint64_t end = cleanup_addr(i->arange->end);

		if (start >= skiend || end <= skistart)
			fast_mem_clear(start, end);
		else {
			if (start < skistart)
				fast_mem_clear(start, skistart);
			if (end > skiend)
				fast_mem_clear(skiend, end);
		}
	}
}
#endif /* FAST_REBOOT_CLEARS_MEMORY */
