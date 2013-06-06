#include <skiboot.h>
#include "spira.h"
#include <cpu.h>
#include <ccan/str/str.h>
#include <device.h>

#include "hdata.h"

struct dt_node * add_core_common(struct dt_node *cpus,
				 const struct sppcia_cpu_cache *cache,
				 const struct sppaca_cpu_timebase *tb,
				 uint32_t int_server, bool okay)
{
	const char *name;
	struct dt_node *cpu;

	/* Page size encodings appear to be the same for P7 and P8 */
	/* XXX TODO: Add MPSS entries */
	static const uint32_t p7_sps[] = {
		0x0c, 0x000, 3, 0x0c, 0x0000, /*  4K seg  4k pages */
		                0x10, 0x0007, /*  4K seg 64k pages */
		                0x18, 0x0038, /*  4K seg 16M pages */
		0x10, 0x110, 2, 0x10, 0x0001, /* 64K seg 64k pages */
		                0x18, 0x0008, /* 64K seg 16M pages */
		0x18, 0x100, 1,	0x18, 0x0000, /* 16M seg 16M pages */
		0x22, 0x120, 1, 0x22, 0x0003, /* 16G seg 16G pages */
	};
	static const uint32_t p7_pps[] = {
		0xc, 0x10, 0x18, 0x22
	};
	static const uint32_t p7_pss[] = {
		0x1c, 0x28, 0xffffffff, 0xffffffff
	};
	static const uint8_t p7_pa_ftrs[] = {
		6, 0, 0xf6, 0x3f, 0xc7, 0x00, 0x80, 0xc0
	};

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
		/* XXX Not really supported with PACA, use PCIA */
		break;
	default:
		name = "PowerPC,Unknown";
	}

	cpu = dt_new_addr(cpus, name, int_server);
	dt_add_property_string(cpu, "device_type", "cpu");
	dt_add_property_string(cpu, "status", okay ? "okay" : "bad");
	dt_add_property_cells(cpu, "reg", int_server);
	dt_add_property(cpu, "64-bit", NULL, 0);
	dt_add_property(cpu, "32-64-bridge", NULL, 0);
	dt_add_property(cpu, "graphics", NULL, 0);
	dt_add_property(cpu, "general-purpose", NULL, 0);
	dt_add_property(cpu, "ibm,segment-page-sizes", p7_sps, sizeof(p7_sps));
	dt_add_property(cpu, "ibm,processor-segment-sizes",
			p7_pss, sizeof(p7_pss));
	dt_add_property(cpu, "ibm,processor-page-sizes",
			p7_pps, sizeof(p7_pps));
	dt_add_property(cpu, "ibm,pa-features", p7_pa_ftrs, sizeof(p7_pa_ftrs));
	dt_add_property_cells(cpu, "ibm,slb-size", 0x20);

	dt_add_property_cells(cpu, "ibm,vmx", 0x2);
	dt_add_property_cells(cpu, "ibm,dfp", 0x2);
	dt_add_property_cells(cpu, "ibm,purr", 0x1);
	dt_add_property_cells(cpu, "ibm,spurr", 0x1);

	dt_add_property_cells(cpu, "clock-frequency",
			  tb->actual_clock_speed * 1000000);
	/* FIXME: Hardcoding is bad. */
	dt_add_property_cells(cpu, "timebase-frequency", 512000000);

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
	return cpu;
}


