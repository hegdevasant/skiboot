#include <skiboot.h>
#include <device_tree.h>
#include <cpu.h>
#include <fsp.h>
#include <interrupts.h>
#include <opal.h>
#include <ccan/str/str.h>

static uint32_t ics_phandle;


/*
 * This takes a 5-bit chip id (node:3 + chip:2) and returns a 20 bit
 * value representing the PSI interrupt. This includes all the fields
 * above, ie, is a global interrupt number
 */
uint32_t get_psi_interrupt(uint32_t chip_id)
{
	uint32_t irq;

	/* Get the node ID bits into position */
	irq  = (chip_id & 0x1c) << (4 + 9 + 1 + 2 + 1);
	/* Get the chip ID bits into position */
	irq |= (chip_id & 0x03) << (4 + 9 + 1);
	/* Add in the BUID */
	irq |= PSI_IRQ_BUID << 4;

	return irq;
}

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
		dt_property("interrupt-controller", NULL, 0);
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
	dt_property("interrupt-controller", NULL, 0);
	dt_end_node();
}

uint32_t get_ics_phandle(void)
{
	assert(ics_phandle != 0);

	return ics_phandle;
}

void add_opal_interrupts(void)
{
	/* We support up to 32 chips, thus 32 PSI interrupts */
#define MAX_PSI_IRQS	32

	uint32_t irqs[MAX_PSI_IRQS];
	unsigned int psi_irq_count;

	/* OPAL currently wants to be forwarded the PSI interrupts
	 *
	 * Later it might want to handle more interrupts, but for
	 * now let's stick to those
	 */
	psi_irq_count = fsp_get_interrupts(irqs, MAX_PSI_IRQS);

	/* The opal-interrupts property has one cell per interrupt,
	 * it is not a standard interrupt property
	 */
	dt_property("opal-interrupts", irqs, psi_irq_count * 4);
}

static int64_t opal_set_xive(uint32_t isn, uint16_t server, uint8_t priority)
{
	if (IRQ_BUID(isn) == PSI_IRQ_BUID)
		return fsp_set_xive(isn, server, priority);

	/* XXX Add PCI & NX */

	return OPAL_PARAMETER;
}
opal_call(OPAL_SET_XIVE, opal_set_xive);

static int64_t opal_get_xive(uint32_t isn, uint16_t *server, uint8_t *priority)
{
	if (IRQ_BUID(isn) == PSI_IRQ_BUID)
		return fsp_get_xive(isn, server, priority);

	/* XXX Add PCI & NX */

	return OPAL_PARAMETER;
}
opal_call(OPAL_GET_XIVE, opal_get_xive);

int64_t opal_handle_interrupt(uint32_t isn, uint64_t *outstanding_event_mask)
{
	/* We only support PSI interrupts atm */
	if (IRQ_BUID(isn) != PSI_IRQ_BUID)
		return OPAL_PARAMETER;

	/* Handle the interrupt at the FSP level (somewhat equivalent
	 * to fsp_poll(), see comments in the code for differences
	 */
	fsp_psi_interrupt(isn);

	/* Poll the console buffers on any interrupt since we don't
	 * get send notifications
	 */
	fsp_console_poll();

	/* Update output events */
	if (outstanding_event_mask)
		*outstanding_event_mask = opal_pending_events;

	return OPAL_SUCCESS;
}
opal_call(OPAL_HANDLE_INTERRUPT, opal_handle_interrupt);
