#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <device_tree.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <device.h>

#define for_each_paca(p)						\
	for (p = spira.ntuples.paca.addr;				\
	     (void *)p < spira.ntuples.paca.addr			\
	     + (spira.ntuples.paca.act_cnt				\
		* spira.ntuples.paca.alloc_len);			\
	     p = (void *)p + spira.ntuples.paca.alloc_len)

static unsigned int paca_index(const struct HDIF_common_hdr *paca)
{
	return ((void *)paca - spira.ntuples.paca.addr)
		/ spira.ntuples.paca.alloc_len;
}

static const char *cpu_state(u32 flags)
{
	switch ((flags & CPU_ID_VERIFY_MASK) >> CPU_ID_VERIFY_SHIFT) {
	case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		return "OK";
	case CPU_ID_VERIFY_USABLE_FAILURES:
		return "FAILURES";
	case CPU_ID_VERIFY_NOT_INSTALLED:
		return "NOT-INSTALLED";
	case CPU_ID_VERIFY_UNUSABLE:
		return "UNUSABLE";
	}
	return "**UNKNOWN**";
}

static struct dt_node *add_cpu_node(struct dt_node *cpus,
				 const struct HDIF_common_hdr *paca,
				    const struct sppaca_cpu_id *id,
				    bool okay)
{
	static const uint32_t p7_sps[] = {
		0x0c, 0x000, 1, 0x0c, 0x0000,
		0x18, 0x100, 1,	0x18, 0x0000,
		0x14, 0x111, 1, 0x14, 0x0002,
		0x22, 0x120, 1, 0x22, 0x0003,
	};
	static const uint32_t p7_pss[] = {
		0x1c, 0x28, 0xffffffff, 0xffffffff
	};
	const struct sppaca_cpu_timebase *timebase;
	const struct sppaca_cpu_cache *cache;
	struct dt_node *cpu;
	const char *name;
	u32 no, size;

	/* We use the process_interrupt_line as the res id */
	no = id->process_interrupt_line;

	printf("CPU[%i]: PIR=%i RES=%i %s %s(%u threads)\n",
	       paca_index(paca), id->pir, no,
	       id->verify_exists_flags & CPU_ID_PACA_RESERVED
	       ? "**RESERVED**" : cpu_state(id->verify_exists_flags),
	       id->verify_exists_flags & CPU_ID_SECONDARY_THREAD
	       ? "[secondary] " : 
	       (id->pir == boot_cpu->pir ? "[boot] " : ""),
	       ((id->verify_exists_flags
		 & CPU_ID_NUM_SECONDARY_THREAD_MASK)
		>> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1);

	timebase = HDIF_get_idata(paca, SPPACA_IDATA_TIMEBASE, &size);
	if (!timebase || size < sizeof(*timebase)) {
		prerror("CPU[%i]: bad timebase size %u @ %p\n",
			paca_index(paca), size, timebase);
		return NULL;
	}

	cache = HDIF_get_idata(paca, SPPACA_IDATA_CACHE_SIZE, &size);
	if (!cache || size < sizeof(*cache)) {
		prerror("CPU[%i]: bad cache size %u @ %p\n",
			paca_index(paca), size, cache);
		return NULL;
	}

	printf("    Cache: I=%u D=%u/%u/%u/%u\n",
	       cache->icache_size_kb,
	       cache->l1_dcache_size_kb,
	       cache->l2_dcache_size_kb,
	       cache->l3_dcache_size_kb,
	       cache->l35_dcache_size_kb);

	/* Use the boot CPU PVR to make up a CPU name in the device-tree
	 * since the HDAT doesn't seem to tell....
	 */
	switch(PVR_TYPE(mfspr(SPR_PVR))) {
	case PVR_TYPE_P7:
		name = "PowerPC,POWER7";
		break;
	case PVR_TYPE_P7P:
		name = "PowerPC,POWER7+";
		break;
	case PVR_TYPE_P8:
		name = "PowerPC,POWER8";
		break;
	default:
		name = "PowerPC,Unknown";
	}

	cpu = dt_new_addr(cpus, name, no);
	dt_add_property_string(cpu, "device_type", "cpu");
	dt_add_property_string(cpu, "status", okay ? "okay" : "bad");
	dt_add_property_cells(cpu, "reg", no);
	dt_add_property(cpu, "ibm,segment-page-sizes", p7_sps, sizeof(p7_sps));
	dt_add_property(cpu, "ibm,processor-segment-sizes",
			p7_pss, sizeof(p7_pss));
	/* We append the secondary cpus in __cpu_parse */
	dt_add_property_cells(cpu, "ibm,ppc-interrupt-server#s", no);
	dt_add_property_cells(cpu, "ibm,slb-size", 0x20);
	dt_add_property_cells(cpu, "ibm,vmx", 0x2);

	dt_add_property_cells(cpu, "d-cache-block-size", cache->dcache_block_size);
	dt_add_property_cells(cpu, "i-cache-block-size", cache->icache_block_size);
	dt_add_property_cells(cpu, "d-cache-size", cache->l1_dcache_size_kb*1024);
	dt_add_property_cells(cpu, "i-cache-size", cache->icache_size_kb*1024);

	if (cache->icache_line_size != cache->icache_block_size)
		dt_add_property_cells(cpu, "i-cache-line-size",
				  cache->icache_line_size);
	if (cache->l1_dcache_line_size != cache->dcache_block_size)
		dt_add_property_cells(cpu, "d-cache-line-size",
				  cache->l1_dcache_line_size);
	dt_add_property_cells(cpu, "clock-frequency",
			  timebase->actual_clock_speed * 1000000);

	/* FIXME: Hardcoding is bad. */
	dt_add_property_cells(cpu, "timebase-frequency", 512000000);

	dt_add_property_cells(cpu, DT_PRIVATE "hw_proc_id",
			     id->hardware_proc_id);
	dt_add_property_u64(cpu, DT_PRIVATE "ibase", cleanup_addr(id->ibase));
	dt_add_property_cells(cpu, "ibm,pir", id->pir);
	dt_add_property_cells(cpu, "ibm,chip_id", id->processor_chip_id);
	return cpu;
}

static struct dt_node *find_cpu_by_hardware_proc_id(struct dt_node *root,
						    u32 hw_proc_id)
{
	struct dt_node *i;

	dt_for_each_node(root, i) {
		const struct dt_property *prop;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;

		prop = dt_find_property(i, DT_PRIVATE "hw_proc_id");
		if (*(u32 *)prop->prop == hw_proc_id)
			return i;
	}
	return NULL;
}

/* Note that numbers are small. */
static void add_u32_sorted(u32 arr[], u32 new, unsigned num)
{
	unsigned int i;

	/* Walk until we find where we belong (insertion sort). */
	for (i = 0; i < num; i++) {
		if (new < arr[i]) {
			u32 tmp = arr[i];
			arr[i] = new;
			new = tmp;
		}
	}
	arr[i] = new;
}

static bool __cpu_parse(void)
{
	const struct HDIF_common_hdr *paca;
	struct dt_node *cpus;

	cpus = dt_new(dt_root, "cpus");
	dt_add_property_cells(cpus, "#address-cells", 2);
	dt_add_property_cells(cpus, "#size-cells", 1);

	paca = spira.ntuples.paca.addr;
	if (!HDIF_check(paca, "SPPACA")) {
		/* FIXME: PACA is deprecated in favor of PCIA */
		prerror("Invalid PACA (PCIA = %p)\n", spira.ntuples.pcia.addr);
		return false;
	}

	if (spira.ntuples.paca.act_len < sizeof(*paca)) {
		prerror("PACA: invalid size %u\n",
			spira.ntuples.paca.act_len);
		return false;
	}

	for_each_paca(paca) {
		const struct sppaca_cpu_id *id;
		u32 size;
		bool okay;

		id = HDIF_get_idata(paca, SPPACA_IDATA_CPU_ID, &size);

		/* The ID structure on Blade314 is only 0x54 long. We can
		 * cope with it as we don't use all the additional fields.
		 * The minimum size we support is  0x40
		 */
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				paca_index(paca), size, id);
			return false;
		}
		switch ((id->verify_exists_flags & CPU_ID_VERIFY_MASK) >>
			CPU_ID_VERIFY_SHIFT) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			okay = true;
			break;
		default:
			okay = false;
		}

		printf("CPU[%i]: PIR=%i RES=%i %s\n",
		       paca_index(paca), id->pir, id->process_interrupt_line,
		       okay ? "OK" : "UNAVAILABLE");

		/* Secondary threads don't get their own node. */
		if (id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		if (!add_cpu_node(cpus, paca, id, okay))
			return false;
	}

	/* Now account for secondaries. */
	for_each_paca(paca) {
		const struct dt_property *prop;
		const struct sppaca_cpu_id *id;
		u32 size, state, num;
		struct dt_node *cpu;
		u32 *new_prop;

		id = HDIF_get_idata(paca, 2, &size);
		state = (id->verify_exists_flags & CPU_ID_VERIFY_MASK) >>
			CPU_ID_VERIFY_SHIFT;
		switch (state) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			break;
		default:
			continue;
		}

		/* Only interested in secondary threads. */
		if (!(id->verify_exists_flags & CPU_ID_SECONDARY_THREAD))
			continue;

		cpu = find_cpu_by_hardware_proc_id(cpus,
						   id->hardware_proc_id);
		if (!cpu) {
			prerror("CPU[%i]: could not find primary hwid %i\n",
				paca_index(paca), id->hardware_proc_id);
			return false;
		}

		/* Add the cpu #. */
		prop = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		num = prop->len / sizeof(u32);
		new_prop = malloc((num + 1) * sizeof(u32));
		if (!new_prop) {
			prerror("Property allocation length %lu failed\n",
				(num + 1) * sizeof(u32));
			return false;
		}
		memcpy(new_prop, prop->prop, prop->len);
		add_u32_sorted(new_prop, id->process_interrupt_line, num);
		dt_del_property(cpu, (struct dt_property *)prop);
		dt_add_property(cpu, "ibm,ppc-interrupt-server#s",
				new_prop, (num + 1) * sizeof(u32));
		free(new_prop);
	}
	return true;
}	

void cpu_parse(void)
{
	if (!__cpu_parse()) {
		prerror("CPU: Initial CPU parsing failed\n");
		abort();
	}
}
