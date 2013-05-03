/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include "spira.h"
#include <cpu.h>
#include <fsp.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <device.h>

#define PCIA_MAX_THREADS	8

#define for_each_pcia(p)						\
	for (p = spira.ntuples.pcia.addr;				\
	     (void *)p < spira.ntuples.pcia.addr			\
	     + (spira.ntuples.pcia.act_cnt				\
		* spira.ntuples.pcia.alloc_len);			\
	     p = (void *)p + spira.ntuples.pcia.alloc_len)

static unsigned int pcia_index(const void *pcia)
{
	return (pcia - (void *)get_hdif(&spira.ntuples.pcia, "SPPCIA"))
		/ spira.ntuples.pcia.alloc_len;
}

static const struct sppcia_cpu_thread *find_tada(const void *pcia,
						 unsigned int thread)
{
	unsigned int count = HDIF_get_iarray_size(pcia,
						  SPPCIA_IDATA_THREAD_ARRAY);
	unsigned int i;

	for (i = 0; i < count; i++) {
		const struct sppcia_cpu_thread *t;
		unsigned int size;

		t = HDIF_get_iarray_item(pcia, SPPCIA_IDATA_THREAD_ARRAY,
					 i, &size);
		if (!t || size < sizeof(*t))
			continue;
		if (t->phys_thread_id == thread)
			return t;
	}
	return NULL;
}

static void add_icp(const void *pcia, u32 tcount, const char *compat)
{
	const struct sppcia_cpu_thread *t;
	struct dt_node *icp;
	u64 reg[tcount * 2];
	u32 i, irange[2];

	for (i = 0; i < tcount; i++) {
		t = find_tada(pcia, i);
		assert(t);
		if (i == 0)
			irange[0] = t->proc_int_line;
		reg[i * 2] = cleanup_addr(t->ibase);
		reg[i * 2 + 1] = 0x1000;
	}
	irange[1] = tcount;

	icp = dt_new_addr(dt_root, "interrupt-controller", reg[0]);
	if (compat)
		dt_add_property_strings(icp, "compatible", "IBM,ppc-xicp", compat);
	else
		dt_add_property_strings(icp, "compatible", "IBM,ppc-xicp");
	dt_add_property(icp, "ibm,interrupt-server-ranges", irange, sizeof(irange));
	dt_add_property(icp, "interrupt-controller", NULL, 0);
	dt_add_property(icp, "reg", reg, sizeof(reg));
	dt_add_property_cells(icp, "#address-cells", 0);
	dt_add_property_cells(icp, "#interrupt-cells", 1);
	dt_add_property_string(icp, "device_type",
			       "PowerPC-External-Interrupt-Presentation");
}

static struct dt_node *add_core_node(struct dt_node *cpus,
				     const void *pcia,
				     const struct sppcia_core_unique *id,
				     bool okay)
{
	/* Page size encodings appear to be the same for P7 and P8 */
	static const uint32_t p7_sps[] = {
		0x0c, 0x000, 1, 0x0c, 0x0000,
		0x18, 0x100, 1,	0x18, 0x0000,
		0x14, 0x111, 1, 0x14, 0x0002,
		0x22, 0x120, 1, 0x22, 0x0003,
	};
	static const uint32_t p7_pss[] = {
		0x1c, 0x28, 0xffffffff, 0xffffffff
	};
	const struct sppcia_cpu_thread *t;
	const struct sppcia_cpu_timebase *timebase;
	const struct sppcia_cpu_cache *cache;
	struct dt_node *cpu;
	const char *name, *icp_compat;
	u32 i, size, threads;
	u32 iserv[PCIA_MAX_THREADS];

	/* Look for thread 0 */
	t = find_tada(pcia, 0);
	if (!t) {
		prerror("CORE[%i]: Failed to find thread 0 !\n",
			pcia_index(pcia));
		return NULL;
	}

	threads = ((id->verif_exist_flags & CPU_ID_NUM_SECONDARY_THREAD_MASK)
		   >> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1;
	assert(threads <= PCIA_MAX_THREADS);

	printf("CORE[%i]: PIR=%i RES=%i %s %s(%u threads)\n",
	       pcia_index(pcia), t->pir, t->proc_int_line,
	       id->verif_exist_flags & CPU_ID_PACA_RESERVED
	       ? "**RESERVED**" : cpu_state(id->verif_exist_flags),
	       t->pir == boot_cpu->pir ? "[boot] " : "", threads);

	timebase = HDIF_get_idata(pcia, SPPCIA_IDATA_TIMEBASE, &size);
	if (!timebase || size < sizeof(*timebase)) {
		prerror("CORE[%i]: bad timebase size %u @ %p\n",
			pcia_index(pcia), size, timebase);
		return NULL;
	}

	cache = HDIF_get_idata(pcia, SPPCIA_IDATA_CPU_CACHE, &size);
	if (!cache || size < sizeof(*cache)) {
		prerror("CORE[%i]: bad cache size %u @ %p\n",
			pcia_index(pcia), size, cache);
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
		icp_compat = "IBM,power7-icp";
		break;
	case PVR_TYPE_P7P:
		name = "PowerPC,POWER7+";
		icp_compat = "IBM,power7-icp";
		break;
	case PVR_TYPE_P8:
		name = "PowerPC,POWER8";
		icp_compat = "IBM,power8-icp";
		break;
	default:
		name = "PowerPC,Unknown";
		icp_compat = NULL;
	}

	cpu = dt_new_addr(cpus, name, t->proc_int_line);
	dt_add_property_string(cpu, "device_type", "cpu");
	dt_add_property_string(cpu, "status", okay ? "okay" : "bad");
	dt_add_property_cells(cpu, "reg", t->proc_int_line);
	dt_add_property(cpu, "ibm,segment-page-sizes", p7_sps, sizeof(p7_sps));
	dt_add_property(cpu, "ibm,processor-segment-sizes",
			p7_pss, sizeof(p7_pss));
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

	dt_add_property_cells(cpu, "ibm,pir", t->pir);

	/* XXX FIXME ? This value is a SW thingy, we want to get the real
	 * chip ID from the PIR or the XSCOM address (can be different
	 * between P7 and P8)
	 */
	dt_add_property_cells(cpu, "ibm,chip_id", id->proc_chip_id);

	/* Add private "ibase" property used by other bits of skiboot */
	dt_add_property_u64(cpu, DT_PRIVATE "ibase", cleanup_addr(t->ibase));

	/* Build ibm,ppc-interrupt-server#s with all threads */
	for (i = 0; i < threads; i++) {
		t = find_tada(pcia, i);
		if (!t) {
			threads = i;
			break;
		}
		iserv[i] = t->proc_int_line;
		assert(t->proc_int_line == t->pir);
	}

	dt_add_property(cpu, "ibm,ppc-interrupt-server#s", iserv, 4 * threads);

	/* Add the ICP node for this CPU */
	add_icp(pcia, threads, icp_compat);

	return cpu;
}

bool pcia_parse(void)
{
	const void *pcia;
	struct dt_node *cpus;
	bool got_pcia = false;

	/* Check PCIA exists... if not, maybe we are getting a PACA ? */
	pcia = get_hdif(&spira.ntuples.pcia, "SPPCIA");
	if (!pcia)
		return false;

	printf("Got PCIA !\n");

	got_pcia = true;

	cpus = dt_new(dt_root, "cpus");
	dt_add_property_cells(cpus, "#address-cells", 1);
	dt_add_property_cells(cpus, "#size-cells", 0);

	for_each_pcia(pcia) {
		const struct sppcia_core_unique *id;
		u32 size;
		bool okay;

		id = HDIF_get_idata(pcia, SPPCIA_IDATA_CORE_UNIQUE, &size);
		if (!id || size < sizeof(*id)) {
			prerror("CORE[%i]: bad id size %u @ %p\n",
				pcia_index(pcia), size, id);
			return false;
		}
		switch ((id->verif_exist_flags & CPU_ID_VERIFY_MASK) >>
			CPU_ID_VERIFY_SHIFT) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			okay = true;
			break;
		default:
			okay = false;
		}

		printf("CORE[%i]: HW_PROC_ID=%i PROC_CHIP_ID=%i EC=0x%x %s\n",
		       pcia_index(pcia), id->hw_proc_id,
		       id->proc_chip_id, id->chip_ec_level,
		       okay ? "OK" : "UNAVAILABLE");

		/* Secondary threads don't get their own node. */
		if (id->verif_exist_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		if (!add_core_node(cpus, pcia, id, okay))
			break;
	}
	return got_pcia;
}

