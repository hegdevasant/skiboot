/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
/*
 * Service Processor serial console handling code
 */
#include <io.h>
#include <psi.h>
#include <fsp.h>
#include <opal.h>
#include <gx.h>
#include <interrupts.h>
#include <cpu.h>
#include <trace.h>

//#define DBG(fmt...)	printf(fmt)
#define DBG(fmt...)	do { } while(0)
//#define FSP_TRACE

struct psi *first_psi;

struct psi *psi_find_link(void *addr)
{
	struct psi *psi;

	if (!addr)
		return NULL;

	for (psi = first_psi; psi; psi = psi->link) {
		if (psi->gxhb_regs == addr)
			return psi;
	}
	return NULL;
}

void psi_enable_fsp_interrupt(struct psi *psi)
{
	if (!psi->working)
		return;

	/* Enable FSP interrupts in the GXHB */
	out_be64(psi->gxhb_regs + PSIHB_CR,
		 in_be64(psi->gxhb_regs + PSIHB_CR) | PSIHB_CR_FSP_IRQ_ENABLE);
}

static void handle_psi_interrupt(struct psi *psi __unused)
{
	/* TODO: Handle CEC PSI interrupts here */
	DBG("PSI: PSI interrupt received\n");
}

/* TODO: Determine which of these needs to be handled by powernv */
static void handle_extra_interrupt(struct psi *psi)
{
	u64 val;

	val = in_be64(psi->gxhb_regs + PSIHB_IRQ_STATUS);

	/*
	 * Decode interrupt type, call appropriate handlers
	 * when available.
	 *
	 * Host error not handled here.
	 */
	switch ((val >> 33) & 0x0f) {
	case 1:		/* Local error */
		DBG("PSI: Local error received\n");
		break;
	case 2:		/* LPC */
		DBG("PSI: LPC received\n");
		break;
	case 4:		/* FSI */
		DBG("PSI: FSI received\n");
		break;
	case 8:		/* OCC */
		DBG("PSI: OCC received\n");
		break;
	}

	/*
	 * TODO: Per Vicente Chung, CRESPs don't generate interrupts,
	 * and are just informational. Need to define the policy
	 * to handle them.
	 */
}

static void psi_interrupt(void *data, uint32_t isn __unused)
{
	struct psi *psi = data;
	u64 val;

	val = in_be64(psi->gxhb_regs + PSIHB_CR);
	if (val & PSIHB_CR_FSP_IRQ) /* FSP mailbox interrupt? */
		fsp_interrupt();
	else if (val & PSIHB_CR_PSI_IRQ) /* CEC PSI interrupt? */
		handle_psi_interrupt(psi);
	else if (proc_gen == proc_gen_p8) /* P8 additional interrupt? */
		handle_extra_interrupt(psi);
	else
		prerror("Received unknown interrupt!\n");

	/* Poll the console buffers on any interrupt since we don't
	 * get send notifications
	 */
	fsp_console_poll(NULL);
}

static int64_t psi_p7_set_xive(void *data, uint32_t isn __unused,
				   uint16_t server, uint8_t priority)
{
	struct psi *psi = data;
	uint64_t xivr;

	if (!psi->working)
		return OPAL_HARDWARE;

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |=	P7_IRQ_BUID(psi->interrupt) << 16;

	out_be64(psi->gxhb_regs + PSIHB_XIVR, xivr);

	return OPAL_SUCCESS;
}

static int64_t psi_p7_get_xive(void *data, uint32_t isn __unused,
				uint16_t *server, uint8_t *priority)
{
	struct psi *psi = data;
	uint64_t xivr;

	if (!psi->working)
		return OPAL_HARDWARE;

	/* Read & decode the XIVR */
	xivr = in_be64(psi->gxhb_regs + PSIHB_XIVR);

	*server = (xivr >> 40) & 0x7ff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

static int64_t psi_p8_set_xive(void *data, uint32_t isn,
				   uint16_t server, uint8_t priority)
{
	struct psi *psi = data;
	uint64_t xivr_p, xivr;

	switch(isn & 7) {
	case P8_IRQ_PSI_FSP:
		xivr_p = PSIHB_XIVR_FSP;
		break;
	case P8_IRQ_PSI_OCC:
		xivr_p = PSIHB_XIVR_OCC;
		break;
	case P8_IRQ_PSI_FSI:
		xivr_p = PSIHB_XIVR_FSI;
		break;
	case P8_IRQ_PSI_LPC:
		xivr_p = PSIHB_XIVR_LPC;
		break;
	case P8_IRQ_PSI_LOCAL_ERR:
		xivr_p = PSIHB_XIVR_LOCAL_ERR;
		break;
	case P8_IRQ_PSI_HOST_ERR:
		xivr_p = PSIHB_XIVR_HOST_ERR;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |= (uint64_t)(isn & 7) << 29;

	out_be64(psi->gxhb_regs + xivr_p, xivr);

	return OPAL_SUCCESS;
}

static int64_t psi_p8_get_xive(void *data, uint32_t isn __unused,
				   uint16_t *server, uint8_t *priority)
{
	struct psi *psi = data;
	uint64_t xivr_p, xivr;

	switch(isn & 7) {
	case P8_IRQ_PSI_FSP:
		xivr_p = PSIHB_XIVR_FSP;
		break;
	case P8_IRQ_PSI_OCC:
		xivr_p = PSIHB_XIVR_OCC;
		break;
	case P8_IRQ_PSI_FSI:
		xivr_p = PSIHB_XIVR_FSI;
		break;
	case P8_IRQ_PSI_LPC:
		xivr_p = PSIHB_XIVR_LPC;
		break;
	case P8_IRQ_PSI_LOCAL_ERR:
		xivr_p = PSIHB_XIVR_LOCAL_ERR;
		break;
	case P8_IRQ_PSI_HOST_ERR:
		xivr_p = PSIHB_XIVR_HOST_ERR;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Read & decode the XIVR */
	xivr = in_be64(psi->gxhb_regs + xivr_p);

	*server = (xivr >> 40) & 0xffff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

/* Called on a fast reset, make sure we aren't stuck with
 * an accepted and never EOId PSI interrupt
 */
void psi_irq_reset(void)
{
	struct psi *psi;
	uint64_t xivr;

	printf("FSP: Hot reset !\n");

	assert(proc_gen == proc_gen_p7);

	for (psi = first_psi; psi; psi = psi->link) {
		/* Mask the interrupt & clean the XIVR */
		xivr = 0x000000ff00000000;
		xivr |=	P7_IRQ_BUID(psi->interrupt) << 16;
		out_be64(psi->gxhb_regs + PSIHB_XIVR, xivr);

#if 0 /* Seems to checkstop ... */
		/*
		 * Maybe not anymore; we were just blindly sending
		 * this on all iopaths, not just the active one;
		 * We don't even know if those psis are even correct.
		 */
		/* Send a dummy EOI to make sure the ICP is clear */
		icp_send_eoi(psi->interrupt);
#endif
	}
}

static const struct irq_source_ops psi_p7_irq_ops = {
	.get_xive = psi_p7_get_xive,
	.set_xive = psi_p7_set_xive,
	.interrupt = psi_interrupt,
};

static const struct irq_source_ops psi_p8_irq_ops = {
	.get_xive = psi_p8_get_xive,
	.set_xive = psi_p8_set_xive,
	.interrupt = psi_interrupt,
};

static const struct irq_source_ops psi_p8_host_err_ops = {
	.get_xive = psi_p8_get_xive,
	.set_xive = psi_p8_set_xive,
};

static void psi_tce_enable(struct psi *psi, bool enable)
{
	void *addr;
	u64 val;

	switch (proc_gen) {
	case proc_gen_p7:
		addr = psi->gxhb_regs + PSIHB_CR;
		break;
	case proc_gen_p8:
		addr = psi->gxhb_regs + PSIHB_PHBSCR;
		break;
	default:
		prerror("%s: Unknown CPU type\n", __func__);
		return;
	}

	val = in_be64(addr);
	if (enable)
		val |=  PSIHB_CR_TCE_ENABLE;
	else
		val &= ~PSIHB_CR_TCE_ENABLE;
	out_be64(addr, val);
}

static int psi_init_phb(struct psi *psi)
{
	u64 reg;

	/* Disable and configure the  TCE table,
	 * it will be enabled below
	 */
	psi_tce_enable(psi, false);

	out_be64(psi->gxhb_regs + PSIHB_TAR, PSI_TCE_TABLE_BASE |
		 PSIHB_TAR_16K_ENTRIES);

	/* Disable interrupt emission in the control register,
	 * it will be re-enabled later, after the mailbox one
	 * will have been enabled.
	 */
	reg = in_be64(psi->gxhb_regs + PSIHB_CR);
	reg &= ~PSIHB_CR_FSP_IRQ_ENABLE;
	out_be64(psi->gxhb_regs + PSIHB_CR, reg);

	/* Configure the interrupt BUID and mask it */
	switch (proc_gen) {
	case proc_gen_p7:
		/* On P7, we get a single interrupt */
		out_be64(psi->gxhb_regs + PSIHB_XIVR,
			 P7_IRQ_BUID(psi->interrupt) << 16 |
			 0xffull << 32);

		/* Configure it in the GX controller as well */
		gx_configure_psi_buid(psi->chip_id,
				      P7_IRQ_BUID(psi->interrupt));

		/* Register the IRQ source */
		register_irq_source(&psi_p7_irq_ops,
				    psi, psi->interrupt, 1);
		break;
	case proc_gen_p8:
		/* On P8 we get a block of 8, set up the base/mask
		 * and mask all the sources for now
		 */
		out_be64(psi->gxhb_regs + PSIHB_IRQ_SRC_COMP,
			 (((u64)psi->interrupt) << 45) |
			 ((0x7fff8ul) << 13) | (0x3ull << 32));
		out_be64(psi->gxhb_regs + PSIHB_XIVR_FSP,
			 (0xffull << 32) | (P8_IRQ_PSI_FSP << 29));
		out_be64(psi->gxhb_regs + PSIHB_XIVR_OCC,
			 (0xffull << 32) | (P8_IRQ_PSI_OCC << 29));
		out_be64(psi->gxhb_regs + PSIHB_XIVR_FSI,
			 (0xffull << 32) | (P8_IRQ_PSI_FSI << 29));
		out_be64(psi->gxhb_regs + PSIHB_XIVR_LPC,
			 (0xffull << 32) | (P8_IRQ_PSI_LPC << 29));
		out_be64(psi->gxhb_regs + PSIHB_XIVR_LOCAL_ERR,
			 (0xffull << 32) | (P8_IRQ_PSI_LOCAL_ERR << 29));
		out_be64(psi->gxhb_regs + PSIHB_XIVR_HOST_ERR,
			 (0xffull << 32) | (P8_IRQ_PSI_HOST_ERR << 29));

		/*
		 * Register the IRQ sources FSP, OCC, FSI, LPC
		 * and Local Error.
		 *
		 * XXX: Current assumption is that all these interrupts
		 * will be handled in Sapphire. That could change in
		 * the future when more clarity on them emerges.
		 */
		register_irq_source(&psi_p8_irq_ops,
				    psi,
				    psi->interrupt + P8_IRQ_PSI_SKIBOOT_BASE,
				    P8_IRQ_PSI_SKIBOOT_COUNT);

		/*
		 * Host Error is handled by powernv; host error
		 * is at offset 5 from the PSI base.
		 */
		register_irq_source(&psi_p8_host_err_ops,
				    psi,
				    psi->interrupt + P8_IRQ_PSI_LINUX_BASE,
				    P8_IRQ_PSI_LINUX_COUNT);
		break;
	default:
		/* Unknown: just no interrupts */
		prerror("FSP: Unknown interrupt type\n");
	}

	/* Enable interrupts in the mask register. We enable everything
	 * except for bit "FSP command error detected" which the doc
	 * (P7 BookIV) says should be masked for normal ops. It also
	 * seems to be masked under OPAL.
	 */
	reg = 0x0000010000100000ull;
	out_be64(psi->gxhb_regs + PSIHB_SEMR, reg);

	/* Enable various other configuration register bits based
	 * on what pHyp does. We keep interrupts disabled until
	 * after the mailbox has been properly configured. We assume
	 * basic stuff such as PSI link enable is already there.
	 *
	 *  - FSP CMD Enable
	 *  - FSP MMIO Enable
	 *  - TCE Enable
	 *  - Error response enable
	 *
	 * Clear all other error bits
	 *
	 * XXX: Only on the active link for now
	 */
	if (psi->active) {
		reg = in_be64(psi->gxhb_regs + PSIHB_CR);
		reg |= PSIHB_CR_FSP_CMD_ENABLE;
		reg |= PSIHB_CR_FSP_MMIO_ENABLE;
		reg |= PSIHB_CR_FSP_ERR_RSP_ENABLE;
		reg &= ~0x00000000ffffffffull;
		out_be64(psi->gxhb_regs + PSIHB_CR, reg);
		psi_tce_enable(psi, true);
	}

	/* Dump the GXHB registers */
	printf("  PSIHB_BBAR   : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_BBAR));
	printf("  PSIHB_FSPBAR : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_FSPBAR));
	printf("  PSIHB_FSPMMR : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_FSPMMR));
	printf("  PSIHB_TAR    : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_TAR));
	printf("  PSIHB_CR     : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_CR));
	printf("  PSIHB_SEMR   : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_SEMR));
	printf("  PSIHB_XIVR   : %llx\n",
	       in_be64(psi->gxhb_regs + PSIHB_XIVR));

	return 0;
}

static bool psi_create(char *compat)
{
	struct dt_node *psi_node;
	struct psi *psi;
	bool inited = false;

	dt_for_each_compatible(dt_root, psi_node, compat) {
		psi = zalloc(sizeof(struct psi));
		if (!psi) {
			prerror("PSI: Can't allocate memory!\n");
			goto out;
		}
		psi->link = first_psi;
		first_psi = psi;
		inited = true;

		psi->gxhb_regs =
			(void *)dt_translate_address(psi_node, 0, NULL);
		psi->chip_id = dt_get_chip_id(psi_node);
		psi->interrupt = dt_prop_get_u32(psi_node, "interrupts");

		if (!strcmp(dt_prop_get(psi_node, "status"), "ok"))
			psi->working = true;
		if (psi->working &&
			dt_find_property(psi_node, "current-link") != NULL)
			psi->active = true;

		printf("PSI: PHB[%p] status: working %d, active %d\n",
			psi, psi->working, psi->active);

		psi_init_phb(psi);
	}
out:
	return inited;
}

void psi_init(void)
{
	printf("PSI init...\n");
	if (!psi_create("ibm,psi")) {
		printf("PSI: No PSI link initialized\n");
		return;
	}
	printf("PSI init... done\n");
}
