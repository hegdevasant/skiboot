#include <skiboot.h>
#include <p7ioc.h>
#include <spira.h>
#include <cec.h>
#include <opal.h>
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


static int64_t p7ioc_rgc_get_xive(struct p7ioc *ioc __unused,
				  uint32_t isn __unused,
				  uint16_t *server __unused,
				  uint8_t *prio __unused)
{
	/* XXX TODO */
	return OPAL_UNSUPPORTED;
}

static int64_t p7ioc_rgc_set_xive(struct p7ioc *ioc __unused,
				  uint32_t isn __unused,
				  uint16_t server __unused,
				  uint8_t prio __unused)
{
	/* XXX TODO */
	return OPAL_UNSUPPORTED;
}

static int64_t p7ioc_get_xive(struct io_hub *hub, uint32_t isn,
			      uint16_t *server, uint8_t *prio)
{
	struct p7ioc *ioc = iohub_to_p7ioc(hub);
	struct p7ioc_phb *p;
	uint32_t buid;
	uint32_t phb_idx;
	int64_t rc;

	buid = IRQ_BUID(isn);

	/* RGC */
	if (buid == ioc->rgc_buid)
		return p7ioc_rgc_get_xive(ioc, isn, server, prio);

	/* PCI */
	phb_idx	= BUID_TO_PHB(buid);
	if (phb_idx >= P7IOC_NUM_PHBS)
		return OPAL_PARAMETER;
	p = &ioc->phbs[phb_idx];
	p->phb.ops->lock(&p->phb);
	rc = p7ioc_phb_get_xive(p, isn, server, prio);
	p->phb.ops->unlock(&p->phb);

	return rc;
}

static int64_t p7ioc_set_xive(struct io_hub *hub, uint32_t isn,
			      uint16_t server, uint8_t prio)
{
	struct p7ioc *ioc = iohub_to_p7ioc(hub);
	struct p7ioc_phb *p;
	uint32_t buid;
	uint32_t phb_idx;
	int64_t rc;

	buid = IRQ_BUID(isn);

	/* RGC */
	if (buid == ioc->rgc_buid)
		return p7ioc_rgc_set_xive(ioc, isn, server, prio);

	/* PCI */
	phb_idx	= BUID_TO_PHB(buid);
	if (phb_idx >= P7IOC_NUM_PHBS)
		return OPAL_PARAMETER;
	p = &ioc->phbs[phb_idx];
	p->phb.ops->lock(&p->phb);
	rc = p7ioc_phb_set_xive(p, isn, server, prio);
	p->phb.ops->unlock(&p->phb);

	return rc;
}

static const struct io_hub_ops p7ioc_hub_ops = {
	.set_tce_mem	= NULL, /* No set_tce_mem for p7ioc, we use FMTC */
	.get_diag_data	= p7ioc_get_diag_data,
	.get_xive	= p7ioc_get_xive,
	.set_xive	= p7ioc_set_xive,
	.add_nodes	= p7ioc_add_nodes,
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

	ioc->buid_base = hub->buid_ext;
	ioc->rgc_buid = ioc->buid_base + RGC_BUID_OFFSET;

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
