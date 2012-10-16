#include <skiboot.h>
#include <p5ioc2.h>
#include <p5ioc2-regs.h>
#include <spira.h>
#include <cec.h>
#include <gx.h>
#include <opal.h>
#include <interrupts.h>
#include <device_tree.h>
#include <time.h>
#include <ccan/str/str.h>


static int64_t p5ioc2_set_tce_mem(struct io_hub *hub, uint64_t address,
				  uint64_t size)
{
	struct p5ioc2 *ioc = iohub_to_p5ioc2(hub);
	int64_t rc;

	printf("P5IOC2: set_tce_mem(0x%016llx size 0x%llx)\n",
	       address, size);

	/* The address passed must be naturally aligned */
	if (address && !is_pow2(size))
		return OPAL_PARAMETER;
	if (address & (size - 1))
		return OPAL_PARAMETER;

	ioc->tce_base = address;
	ioc->tce_size = size;

	rc = gx_configure_tce_bar(ioc->host_chip, ioc->gx_bus,
				  address, size);
	if (rc)
		return OPAL_INTERNAL_ERROR;
	return OPAL_SUCCESS;
}

static int64_t p5ioc2_get_diag_data(struct io_hub *hub __unused,
				   void *diag_buffer __unused,
				   uint64_t diag_buffer_len __unused)
{
	/* XXX Not yet implemented */
	return OPAL_UNSUPPORTED;
}

static void p5ioc2_add_nodes(struct io_hub *hub __unused)
{
	struct p5ioc2 *ioc = iohub_to_p5ioc2(hub);
	char name[sizeof("io-hub@") + STR_MAX_CHARS(ioc->regs)];
	static const char p5ioc2_compat[] =
		"ibm,p5ioc2";
	unsigned int i, irq;
	u64 reg[2];

	reg[0] = cleanup_addr((uint64_t)ioc->regs);
	reg[1] = 0x2000000;

	sprintf(name, "io-hub@%llx", reg[0]);
	dt_begin_node(name);
	dt_property("compatible", p5ioc2_compat, sizeof(p5ioc2_compat));
	dt_property("reg", reg, sizeof(reg));
	dt_property_cell("#address-cells", 2);
	dt_property_cell("#size-cells", 2);
	dt_property_cells("ibm,opal-hubid", 2, 0, hub->hub_id);
	dt_property_cell("interrupt-parent", get_ics_phandle());
	irq = (ioc->buid_base + 1) << 4;

	/* XXX These are the hub interrupts, we should add the calgary
	 * ones as well... but we don't handle any of them yet anyway
	 */
	dt_property_cells("interrupts", 2, irq, irq + 1);
	dt_property_cell("interrupt-base", irq);
	dt_property("ranges", NULL, 0);
	for (i = 0; i < 4; i++)
		p5ioc2_phb_add_nodes(&ioc->ca0_phbs[i]);
	for (i = 0; i < 4; i++)
		p5ioc2_phb_add_nodes(&ioc->ca1_phbs[i]);
	dt_end_node();
}


static int64_t p5ioc2_get_xive(struct io_hub *hub, uint32_t isn,
			       uint16_t *server, uint8_t *prio)
{
	struct p5ioc2 *ioc = iohub_to_p5ioc2(hub);
	struct p5ioc2_phb *p;
	uint32_t fbuid, ca, boff;
	int64_t rc;

	fbuid = IRQ_FBUID(isn);

	/* XXX Internal hub, not supported */
	if (BUID_BASE(fbuid) == 1 || BUID_BASE(fbuid) == 2)
		return OPAL_UNSUPPORTED;

	/* PCI */
	if (fbuid >= (ioc->buid_base + P5IOC2_CA1_BUID)) {
		ca = 1;
		boff = fbuid - (ioc->buid_base + P5IOC2_CA1_BUID);
	} else if (fbuid >= (ioc->buid_base + P5IOC2_CA0_BUID)) {
		ca = 0;
		boff = fbuid - (ioc->buid_base + P5IOC2_CA0_BUID);
	} else
		return OPAL_PARAMETER;

	/* XXX CA own interrupt, not supported */
	if (boff == 0)
		return OPAL_UNSUPPORTED;
	/* Out of range */
	if (boff > 4)
		return OPAL_PARAMETER;
	p = ca ? &ioc->ca1_phbs[boff - 1] : &ioc->ca0_phbs[boff - 1];
	p->phb.ops->lock(&p->phb);
	rc = p5ioc2_phb_get_xive(p, isn, server, prio);
	p->phb.ops->unlock(&p->phb);

	return rc;
}


static int64_t p5ioc2_set_xive(struct io_hub *hub, uint32_t isn,
			       uint16_t server, uint8_t prio)
{
	struct p5ioc2 *ioc = iohub_to_p5ioc2(hub);
	struct p5ioc2_phb *p;
	uint32_t fbuid, ca, boff;
	int64_t rc;

	fbuid = IRQ_FBUID(isn);

	/* XXX Internal hub, not supported */
	if (BUID_BASE(fbuid) == 1 || BUID_BASE(fbuid) == 2)
		return OPAL_UNSUPPORTED;

	/* PCI */
	if (fbuid >= (ioc->buid_base + P5IOC2_CA1_BUID)) {
		ca = 1;
		boff = fbuid - (ioc->buid_base + P5IOC2_CA1_BUID);
	} else if (fbuid >= (ioc->buid_base + P5IOC2_CA0_BUID)) {
		ca = 0;
		boff = fbuid - (ioc->buid_base + P5IOC2_CA0_BUID);
	} else
		return OPAL_PARAMETER;

	/* XXX CA own interrupt, not supported */
	if (boff == 0)
		return OPAL_UNSUPPORTED;
	/* Out of range */
	if (boff > 4)
		return OPAL_PARAMETER;
	p = ca ? &ioc->ca1_phbs[boff - 1] : &ioc->ca0_phbs[boff - 1];
	p->phb.ops->lock(&p->phb);
	rc = p5ioc2_phb_set_xive(p, isn, server, prio);
	p->phb.ops->unlock(&p->phb);

	return rc;
}

static const struct io_hub_ops p5ioc2_hub_ops = {
	.set_tce_mem	= p5ioc2_set_tce_mem,
	.get_diag_data	= p5ioc2_get_diag_data,
	.get_xive	= p5ioc2_get_xive,
	.set_xive	= p5ioc2_set_xive,
	.add_nodes	= p5ioc2_add_nodes,
};

static void p5ioc2_inits(struct p5ioc2 *ioc)
{
	uint64_t val;

	printf("P5IOC2: Initializing hub...\n");

	/*
	 * BML base inits
	 */
	/* mask off interrupt presentation timeout in FIRMC */
	out_be64(ioc->regs + (P5IOC2_FIRMC | P5IOC2_REG_OR),
		 0x0000080000000000);

	/* turn off display alter mode */
	out_be64(ioc->regs + (P5IOC2_CTL | P5IOC2_REG_AND),
		 0xffffff7fffffffff);

	/* setup hub and clustering interrupts BUIDs to 1 and 2 */
	out_be64(ioc->regs + P5IOC2_SBUID, 0x0001000200000000);

	/* Set XIXO bit 0 needed for "enhanced" TCEs or else TCE
	 * fetches appear as normal memory reads on GX causing
	 * P7 to checkstop when a TCE DKill collides with them.
	 */
	out_be64(ioc->regs + P5IOC2_XIXO, in_be64(ioc->regs + P5IOC2_XIXO)
		 | P5IOC2_XIXO_ENH_TCE);

	/*
	 * Setup routing. We use the same setup that pHyp appears
	 * to do (after inspecting the various registers with SCOM)
	 *
	 * We assume the BARs are already setup by the FSP such
	 * that BAR0 is 128G (8G region size) and BAR6 is
	 * 256M (16M region size).
	 *
	 * The routing is based on what pHyp and BML do, each Calgary
	 * get one slice of BAR6 and two slices of BAR0
	 */
	out_be64(ioc->regs + P5IOC2_TxRTE(0,0),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA0_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(0,1),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA0_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(0,2),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA1_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(0,3),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA1_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(6,0),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA0_RIO_ID);
	out_be64(ioc->regs + P5IOC2_TxRTE(6,1),
		 P5IOC2_TxRTE_VALID | P5IOC2_CA1_RIO_ID);

	/*
	 * BUID routing, we send entries 1 to CA0 and 2 to CA1
	 * just like pHyp and make sure the base and mask are
	 * both clear in SID to we route the whole 512 block
	 */
	val = in_be64(ioc->regs + P5IOC2_SID);
	val = SETFIELD(P5IOC2_SID_BUID_BASE, val, 0);
	val = SETFIELD(P5IOC2_SID_BUID_MASK, val, 0);
	out_be64(ioc->regs + P5IOC2_SID, val);
	out_be64(ioc->regs + P5IOC2_BUIDRTE(1),
		 P5IOC2_BUIDRTE_VALID | P5IOC2_BUIDRTE_RR_RET |
		 P5IOC2_CA0_RIO_ID);
	out_be64(ioc->regs + P5IOC2_BUIDRTE(2),
		 P5IOC2_BUIDRTE_VALID | P5IOC2_BUIDRTE_RR_RET |
		 P5IOC2_CA1_RIO_ID);
}

static void p5ioc2_ca_init(struct p5ioc2 *ioc, int ca)
{
	void *regs = ca ? ioc->ca1_regs : ioc->ca0_regs;
	uint64_t val;

	printf("P5IOC2: Initializing Calgary %d...\n", ca);

	/* Setup device BUID */
	val = SETFIELD(CA_DEVBUID, 0, ca ? P5IOC2_CA1_BUID : P5IOC2_CA0_BUID);
	out_be32(regs + CA_DEVBUID, val);

	/* Setup HubID in TARm (and keep TCE clear, Linux will init that)
	 *
	 * BML and pHyp sets the values to 1 for CA0 and 4 for CA1. We
	 * keep the TAR valid bit clear as well.
	 */
	val = SETFIELD(CA_TAR_HUBID, 0ul, ca ? 4 : 1);
	val = SETFIELD(CA_TAR_ALTHUBID, val, ca ? 4 : 1);
	out_be64(regs + CA_TAR0, val);
	out_be64(regs + CA_TAR1, val);
	out_be64(regs + CA_TAR2, val);
	out_be64(regs + CA_TAR3, val);
	
	/* Bridge config register. We set it up to the same value as observed
	 * under pHyp on a Juno machine. The difference from the IPL value is
	 * that TCE buffers are enabled, discard timers are increased and
	 * we disable response status to avoid errors.
	 */
	//out_be64(regs + CA_CCR, 0x5045DDDED2000000);
	// disable memlimit:
	out_be64(regs + CA_CCR, 0x5005DDDED2000000);

	/* The system memory base/limit etc... setup will be done when the
	 * user enables TCE via OPAL calls
	 */
}

struct io_hub *p5ioc2_create_hub(const struct cechub_io_hub *hub, uint32_t id)
{
	struct p5ioc2 *ioc;
	unsigned int i;

	ioc = zalloc(sizeof(struct p5ioc2));
	if (!ioc)
		return NULL;
	ioc->hub.hub_id = id;
	ioc->hub.ops = &p5ioc2_hub_ops;
	
	printf("P5IOC2: Assigned OPAL Hub ID %d\n", ioc->hub.hub_id);
	printf("P5IOC2: Chip: %d GX bus: %d Base BUID: 0x%x EC Level: 0x%x\n",
	       hub->proc_chip_id, hub->gx_index, hub->buid_ext, hub->ec_level);

	/* GX BAR assignment: see p5ioc2.h */
	printf("P5IOC2: GX BAR 0 = 0x%016llx\n", hub->gx_ctrl_bar0);
	printf("P5IOC2: GX BAR 1 = 0x%016llx\n", hub->gx_ctrl_bar1);
	printf("P5IOC2: GX BAR 2 = 0x%016llx\n", hub->gx_ctrl_bar2);
	printf("P5IOC2: GX BAR 3 = 0x%016llx\n", hub->gx_ctrl_bar3);
	printf("P5IOC2: GX BAR 4 = 0x%016llx\n", hub->gx_ctrl_bar4);

	/* We assume SBAR == GX0 + some hard coded offset */
	ioc->regs = (void *)hub->gx_ctrl_bar0 + P5IOC2_REGS_OFFSET;

	/* For debugging... */
	printf("P5IOC2: BAR0 = 0x%016llx\n",
	       in_be64(ioc->regs + P5IOC2_BAR(0)));
	printf("P5IOC2: BAR6 = 0x%016llx\n",
	       in_be64(ioc->regs + P5IOC2_BAR(6)));

	ioc->host_chip = hub->proc_chip_id;
	ioc->gx_bus = hub->gx_index;

	/* Rather than reading the BARs in P5IOC2, we "know" that
	 * BAR6 matches GX BAR 1 and BAR0 matches GX BAR 2. This
	 * is a bit fishy but will work for the few machines this
	 * is intended to work on
	 */
	ioc->bar6 = hub->gx_ctrl_bar1;
	ioc->bar0 = hub->gx_ctrl_bar2;

	/* We setup the corresponding Calgary register bases and memory
	 * regions. Note: those cannot be used until the routing has
	 * been setup by inits
	 */
	ioc->ca0_regs = (void *)ioc->bar6 + P5IOC2_CA0_REG_OFFSET;
	ioc->ca1_regs = (void *)ioc->bar6 + P5IOC2_CA1_REG_OFFSET;
	ioc->ca0_mm_region = ioc->bar0 + P5IOC2_CA0_MM_OFFSET;
	ioc->ca1_mm_region = ioc->bar0 + P5IOC2_CA1_MM_OFFSET;

	/* Base of our BUIDs, will be refined later */
	ioc->buid_base = hub->buid_ext << 9;

	/* So how do we know what PHBs to create ? Let's try all of them
	 * and we'll see if that causes problems
	 */
	for (i = 0; i < 4; i++)
		p5ioc2_phb_setup(ioc, &ioc->ca0_phbs[i], 0, i, true,
				 ioc->buid_base + P5IOC2_CA0_BUID + i + 1);
	for (i = 0; i < 4; i++)
		p5ioc2_phb_setup(ioc, &ioc->ca1_phbs[i], 1, i, true,
				 ioc->buid_base + P5IOC2_CA1_BUID + i + 1);

	/* Now, we do the bulk of the inits */
	p5ioc2_inits(ioc);
	p5ioc2_ca_init(ioc, 0);
	p5ioc2_ca_init(ioc, 1);

	for (i = 0; i < 4; i++)
		p5ioc2_phb_init(&ioc->ca0_phbs[i]);
	for (i = 0; i < 4; i++)
		p5ioc2_phb_init(&ioc->ca1_phbs[i]);

	/* Reset delay... synchronous, hope we never do that as a
	 * result of an OPAL callback. We shouldn't really need this
	 * here and may fold it in the generic slot init sequence but
	 * it's not like we care much about that p5ioc2 code...
	 *
	 * This is mostly to give devices a chance to settle after
	 * having lifted the reset pin on PCI-X.
	 */
	time_wait_ms(1000);

	printf("P5IOC2: Initialization complete\n");

	return &ioc->hub;
}
