#include <skiboot.h>
#include <p7ioc.h>
#include <p7ioc-regs.h>
#include <spira.h>
#include <cec.h>
#include <opal.h>
#include <io.h>
#include <interrupts.h>
#include <device_tree.h>
#include <ccan/str/str.h>

static int64_t p7ioc_get_diag_data(struct io_hub *hub __unused,
				   void *diag_buffer __unused,
				   uint64_t diag_buffer_len __unused)
{
	/* XXX Not yet implemented */
	return OPAL_UNSUPPORTED;
}

static void p7ioc_add_nodes(struct io_hub *hub)
{
	struct p7ioc *ioc = iohub_to_p7ioc(hub);
	char name[sizeof("io-hub@") + STR_MAX_CHARS(ioc->regs)];
	static const char p7ioc_compat[] =
		"ibm,p7ioc\0ibm,ioda-hub";
	unsigned int i;
	u64 reg[2];

	reg[0] = cleanup_addr((uint64_t)ioc->regs);
	reg[1] = 0x2000000;

	sprintf(name, "io-hub@%llx", reg[0]);
	dt_begin_node(name);
	dt_property("compatible", p7ioc_compat, sizeof(p7ioc_compat));
	dt_property("reg", reg, sizeof(reg));
	dt_property_cell("#address-cells", 2);
	dt_property_cell("#size-cells", 2);
	dt_property_cells("ibm,opal-hubid", 2, 0, hub->hub_id);
	dt_property_cell("interrupt-parent", get_ics_phandle());
	/* XXX Fixme: how many RGC interrupts ? */
	dt_property_cell("interrupts", ioc->rgc_buid << 4);
	dt_property_cell("interrupt-base", ioc->rgc_buid << 4);
	/* XXX What about ibm,opal-mmio-real ? */
	dt_property("ranges", NULL, 0);
	for (i = 0; i < P7IOC_NUM_PHBS; i++)
		p7ioc_phb_add_nodes(&ioc->phbs[i]);
	dt_end_node();
}

static const struct io_hub_ops p7ioc_hub_ops = {
	.set_tce_mem	= NULL, /* No set_tce_mem for p7ioc, we use FMTC */
	.get_diag_data	= p7ioc_get_diag_data,
	.add_nodes	= p7ioc_add_nodes,
	.reset		= p7ioc_reset,
};

static int64_t p7ioc_rgc_get_xive(void *data, uint32_t isn,
				  uint16_t *server, uint8_t *prio)
{
	struct p7ioc *ioc = data;
	uint32_t irq = (isn & 0xf);
	uint32_t fbuid = IRQ_FBUID(isn);
	uint64_t xive;

	if (fbuid != ioc->rgc_buid)
		return OPAL_PARAMETER;

	xive = ioc->xive_cache[irq];
	*server = GETFIELD(IODA_XIVT_SERVER, xive);
	*prio = GETFIELD(IODA_XIVT_PRIORITY, xive);

	return OPAL_SUCCESS;
 }

static int64_t p7ioc_rgc_set_xive(void *data, uint32_t isn,
				  uint16_t server, uint8_t prio)
{
	struct p7ioc *ioc = data;
	uint32_t irq = (isn & 0xf);
	uint32_t fbuid = IRQ_FBUID(isn);
	uint64_t xive;
	uint64_t m_server, m_prio;

	if (fbuid != ioc->rgc_buid)
		return OPAL_PARAMETER;

	xive = SETFIELD(IODA_XIVT_SERVER, 0ull, server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, prio);
	ioc->xive_cache[irq] = xive;

	/* Now we mangle the server and priority */
	if (prio == 0xff) {
		m_server = 0;
		m_prio = 0xff;
	} else {
		m_server = server >> 3;
		m_prio = (prio >> 3) | ((server & 7) << 5);
	}

	/* Update the XIVE. Don't care HRT entry on P7IOC */
	out_be64(ioc->regs + 0x3e1820, (0x0002000000000000 | irq));
	xive = in_be64(ioc->regs + 0x3e1830);
	xive = SETFIELD(IODA_XIVT_SERVER, xive, m_server);
	xive = SETFIELD(IODA_XIVT_PRIORITY, xive, m_prio);
	out_be64(ioc->regs + 0x3e1830, xive);

	return OPAL_SUCCESS;
}

static void p7ioc_rgc_interrupt(void *data __unused, uint32_t isn)
{
	printf("IOC: Got RGC interrupt 0x%04x\n", isn);

	/* XXX TODO */
}

static const struct irq_source_ops p7ioc_rgc_irq_ops = {
	.get_xive = p7ioc_rgc_get_xive,
	.set_xive = p7ioc_rgc_set_xive,
	.interrupt = p7ioc_rgc_interrupt,
};

struct io_hub *p7ioc_create_hub(const struct cechub_io_hub *hub, uint32_t id)
{
	struct p7ioc *ioc;
	unsigned int i;

	ioc = zalloc(sizeof(struct p7ioc));
	if (!ioc)
		return NULL;
	ioc->hub.hub_id = id;
	ioc->hub.ops = &p7ioc_hub_ops;
	
	printf("P7IOC: Assigned OPAL Hub ID %d\n", ioc->hub.hub_id);
	printf("P7IOC: Chip: %d GX bus: %d Base BUID: 0x%x EC Level: 0x%x\n",
	       hub->proc_chip_id, hub->gx_index, hub->buid_ext, hub->ec_level);

	/* GX BAR assignment: see p7ioc.h */
	printf("P7IOC: GX BAR 0 = 0x%016llx\n", hub->gx_ctrl_bar0);
	printf("P7IOC: GX BAR 1 = 0x%016llx\n", hub->gx_ctrl_bar1);
	printf("P7IOC: GX BAR 2 = 0x%016llx\n", hub->gx_ctrl_bar2);
	printf("P7IOC: GX BAR 3 = 0x%016llx\n", hub->gx_ctrl_bar3);
	printf("P7IOC: GX BAR 4 = 0x%016llx\n", hub->gx_ctrl_bar4);

	/* We only know about memory map 1 */
	if (hub->mem_map_vers != 1) {
		prerror("P7IOC: Unknown memory map %d\n", hub->mem_map_vers);
		/* We try to continue anyway ... */
	}

	ioc->regs = (void *)hub->gx_ctrl_bar1;

	/* Should we read the GX BAR sizes via SCOM instead ? */
	ioc->mmio1_win_start = hub->gx_ctrl_bar1;
	ioc->mmio1_win_size = MWIN1_SIZE;
	ioc->mmio2_win_start = hub->gx_ctrl_bar2;
	ioc->mmio2_win_size = MWIN2_SIZE;

	ioc->buid_base = hub->buid_ext << 9;
	ioc->rgc_buid = ioc->buid_base + RGC_BUID_OFFSET;

	/* Clear the RGC XIVE cache */
	for (i = 0; i < 16; i++)
		ioc->xive_cache[i] = SETFIELD(IODA_XIVT_PRIORITY, 0ull, 0xff);

	/*
	 * Register RGC interrupts
	 *
	 * For now I assume only 0 is... to verify with Greg or HW guys,
	 * we support all 16
	 */
	register_irq_source(&p7ioc_rgc_irq_ops, ioc, ioc->rgc_buid << 4, 1);

	/* Setup PHB structures (no HW access yet).
	 *
	 * XXX FIXME: We assume all PHBs are active.
	 */
	for (i = 0; i < P7IOC_NUM_PHBS; i++)
		p7ioc_phb_setup(ioc, i, true);
	
	/* Now, we do the bulk of the inits */
	p7ioc_inits(ioc);

	printf("P7IOC: Initialization complete\n");

	return &ioc->hub;
}
