#include <skiboot.h>
#include <device_tree.h>
#include <cpu.h>
#include <ccan/str/str.h>

static uint32_t ics_phandle;

void add_icp_nodes(void)
{
	struct cpu_thread *t;
	char name[sizeof("interrupt-controller@")
		  + STR_MAX_CHARS(t->id->ibase)];
	static const char p7_icp_compat[] =
		"IBM,ppc-xicp\0IBM,power7-xicp";

	/* XXX FIXME: Hard coded #threads */
	for_each_available_cpu(t) {
		u32 irange[2];
		u64 reg[2 * 4];

		if (t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		/* One page is enough for a handful of regs. */
		reg[0] = cleanup_addr(t->id->ibase);
		reg[1] = 4096;
		reg[2] = cleanup_addr(t->id->ibase + 0x1000);
		reg[3] = 4096;
		reg[4] = cleanup_addr(t->id->ibase + 0x2000);
		reg[5] = 4096;
		reg[6] = cleanup_addr(t->id->ibase + 0x3000);
		reg[7] = 4096;

		sprintf(name, "interrupt-controller@%llx", reg[0]);
		dt_begin_node(name);
		dt_property("compatible", p7_icp_compat, sizeof(p7_icp_compat));

		irange[0] = t->id->process_interrupt_line; /* Index */
		irange[1] = 4;				   /* num servers */
		dt_property("ibm,interrupt-server-ranges",
			    irange, sizeof(irange));
		dt_property("reg", reg, sizeof(reg));
		dt_property_cell("#address-cells", 0);
		dt_property_cell("#interrupt-cells", 1);
		dt_property_string("device_type",
				   "PowerPC-External-Interrupt-Presentation");
		dt_end_node();
	}
}

void add_ics_node(void)
{
	ics_phandle = dt_begin_node("interrupt-controller@0");
	dt_property_cells("reg", 4, 0, 0, 0, 0);
	dt_property_string("compatible", "IBM,ppc-xics");
	dt_property_cell("#address-cells", 0);
	dt_property_cell("#interrupt-cells", 1);
	dt_property_string("device_type",
			   "PowerPC-Interrupt-Source-Controller");
	dt_end_node();
}

uint32_t get_ics_phandle(void)
{
	assert(ics_phandle != 0);

	return ics_phandle;
}

