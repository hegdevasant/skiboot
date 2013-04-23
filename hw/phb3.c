/*
 * PHB3 support
 *
 * XXX This is a very mimimal implementation, all of the advanced
 * functionality such as EEH support still need to be added
 *
 * XXX Additionally, PBCQ-level errors need to be handled.
 *
 *     IE.
 *
 *     In case of FFFF's the procedure typically would be to follow
 *     first the PBCQ spec, ie, try to read from PHB regs, and if that
 *     return all 1's -> fenced -> extract diags via backdoor ASB
 *     (indirect via PBCQ XSCOM on PHB3) then reset. Else -> ER.
 *
 * (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”).
 */
#include <skiboot.h>
#include <io.h>
#include <time.h>
#include <pci.h>
#include <pci-cfg.h>
#include <interrupts.h>
#include <opal.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <xscom.h>
#include <phb3.h>
#include <phb3-regs.h>

static void phb3_trace(struct phb3 *p, FILE *s, const char *fmt, ...)
{
	/* Use a temp stack buffer to print all at once to avoid
	 * mixups of a trace entry on SMP
	 */
	char tbuf[128 + 10];
	va_list args;
	char *b = tbuf;

	b += sprintf(b, "PHB%d: ", p->phb.opal_id);
	va_start(args, fmt);
	vsnprintf(b, 128, fmt, args);
	va_end(args);
	fputs(tbuf, s);
}
#define PHBDBG(p, fmt...)	phb3_trace(p, stdout, fmt)
#define PHBERR(p, fmt...)	phb3_trace(p, stderr, fmt)

/*
 * Lock callbacks. Allows the OPAL API handlers to lock the
 * PHB around calls such as config space, EEH, etc...
 */
static void phb3_lock(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	lock(&p->lock);
}

static  void phb3_unlock(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	unlock(&p->lock);
}

/* Helper to select an IODA table entry */
static inline void phb3_ioda_sel(struct phb3 *p, uint32_t table,
				 uint32_t addr, bool autoinc)
{
	out_be64(p->regs + PHB_IODA_ADDR,
		 (autoinc ? PHB_IODA_AD_AUTOINC : 0)	|
		 SETFIELD(PHB_IODA_AD_TSEL, 0ul, table)	|
		 SETFIELD(PHB_IODA_AD_TADR, 0ul, addr));
}

/* Helper to set the state machine timeout */
static inline uint64_t phb3_set_sm_timeout(struct phb3 *p, uint64_t dur)
{
	uint64_t target, now = mftb();

	target = now + dur;
	if (target == 0)
		target++;
	p->delay_tgt_tb = target;

	return dur;
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t phb3_pcicfg_check(struct phb3 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint8_t *pe)
{
	uint32_t sm = size - 1;

	if (offset > 0xfff || bdfn > 0xffff)
		return OPAL_PARAMETER;
	if (offset & sm)
		return OPAL_PARAMETER;

	/* The root bus only has a device at 0 and we get into an
	 * error state if we try to probe beyond that, so let's
	 * avoid that and just return an error to Linux
	 */
	if ((bdfn >> 8) == 0 && (bdfn & 0xff))
		return OPAL_HARDWARE;

	/* Check PHB state */
	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* Fetch the PE# from cache */
	*pe = p->rte_cache[bdfn];

	return OPAL_SUCCESS;
}

#define PHB3_PCI_CFG_READ(size, type)	\
static int64_t phb3_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
                                      uint32_t offset, type *data)	\
{									\
        struct phb3 *p = phb_to_phb3(phb);				\
        uint64_t addr;							\
        int64_t rc;							\
        uint8_t pe;							\
									\
        /* Initialize data in case of error */				\
        *data = (type)0xffffffff;					\
									\
        rc = phb3_pcicfg_check(p, bdfn, offset, sizeof(type), &pe);	\
        if (rc)								\
                return rc;						\
									\
        addr = PHB_CA_ENABLE | ((uint64_t)bdfn << PHB_CA_FUNC_LSH);	\
        addr = SETFIELD(PHB_CA_REG, addr, offset);			\
        addr = SETFIELD(PHB_CA_PE, addr, pe);				\
        out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);			\
        *data = in_le##size(p->regs + PHB_CONFIG_DATA +			\
                                (offset & (4 - sizeof(type))));		\
									\
        return OPAL_SUCCESS;						\
}

#define PHB3_PCI_CFG_WRITE(size, type)	\
static int64_t phb3_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
                                       uint32_t offset, type data)	\
{									\
        struct phb3 *p = phb_to_phb3(phb);				\
        uint64_t addr;							\
        int64_t rc;							\
        uint8_t pe;							\
									\
        rc = phb3_pcicfg_check(p, bdfn, offset, sizeof(type), &pe);	\
        if (rc)								\
                return rc;						\
									\
        addr = PHB_CA_ENABLE | ((uint64_t)bdfn << PHB_CA_FUNC_LSH);	\
        addr = SETFIELD(PHB_CA_REG, addr, offset);			\
        addr = SETFIELD(PHB_CA_PE, addr, pe);				\
        out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);			\
        out_le##size(p->regs + PHB_CONFIG_DATA +			\
                     (offset & (4 - sizeof(type))), data);		\
									\
        return OPAL_SUCCESS;						\
}

PHB3_PCI_CFG_READ(8, u8)
PHB3_PCI_CFG_READ(16, u16)
PHB3_PCI_CFG_READ(32, u32)
PHB3_PCI_CFG_WRITE(8, u8)
PHB3_PCI_CFG_WRITE(16, u16)
PHB3_PCI_CFG_WRITE(32, u32)

static uint8_t phb3_choose_bus(struct phb *phb __unused,
			       struct pci_device *bridge __unused,
			       uint8_t candidate, uint8_t *max_bus __unused,
			       bool *use_max)
{
	/* Use standard bus number selection */
	*use_max = false;
	return candidate;
}

static int64_t phb3_presence_detect(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t slot_stat;
	int64_t rc;

	/* Test for PHB in error state ? */
	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* XXX Check bifurcation stuff ? Also, IBM "A/B" bits in the
	 * HotPlug override register might be of use though simics
	 * doesn't appear to set them to a useful state
	 */

	/* Read slot status register */
	rc = phb3_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTSTAT,
					&slot_stat);
	if (rc != OPAL_SUCCESS)
		return OPAL_HARDWARE;

	if (!(slot_stat & PCICAP_EXP_SLOTSTAT_PDETECTST))
		return OPAL_SHPC_DEV_NOT_PRESENT;

	return OPAL_SHPC_DEV_PRESENT;
}

/* Clear IODA cache tables */
static void phb3_init_ioda_cache(struct phb3 *p)
{
	uint32_t i;
	uint64_t *data64;

	/*
	 * RTT and PELTV. RTE should be 0xFF's to indicate
	 * invalid PE# for the corresponding RID.
	 */
	memset(p->rte_cache,   0xff, sizeof(p->rte_cache));
	memset(p->peltv_cache, 0x0,  sizeof(p->peltv_cache));

	/* Disable all LSI */
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = &p->lxive_cache[i];
		*data64 = SETFIELD(IODA2_LXIVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(IODA2_LXIVT_SERVER, *data64, 0x0);
	}

	/* Diable all MSI */
	for (i = 0; i < ARRAY_SIZE(p->ive_cache); i++) {
		data64 = &p->ive_cache[i];
		*data64 = SETFIELD(IODA2_IVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(IODA2_IVT_SERVER, *data64, 0x0);
	}

	/* Clear TVT */
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));
	/* Clear M32 domain */
	memset(p->m32d_cache, 0x0, sizeof(p->m32d_cache));
	/* Clear M64 domain */
	memset(p->m64d_cache, 0x0, sizeof(p->m64d_cache));
}

/* phb3_ioda_reset - Reset the IODA tables
 *
 * @purge: If true, the cache is cleared and the cleared values
 *         are applied to HW. If false, the cached values are
 *         applied to HW
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 */
static int64_t phb3_ioda_reset(struct phb *phb, bool purge)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t server, prio, m_server, m_prio;
	uint64_t *pdata64, data64;
	uint32_t i;

	if (purge)
		phb3_init_ioda_cache(p);

	/* Invalidate RTE, IVE, TCE cache */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_IVC_INVALIDATE, PHB_IVC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ALL);

	/* Init_27..28 - LIXVT */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = p->lxive_cache[i];
		server = GETFIELD(IODA2_LXIVT_SERVER, data64);
		prio = GETFIELD(IODA2_LXIVT_PRIORITY, data64);

		/* Now we mangle the server and priority */
		if (prio == 0xff) {
			m_server = 0;
			m_prio = 0xff;
		} else {
			m_server = server >> 3;
			m_prio = (prio >> 3) | ((server & 7) << 5);
		}

		data64 = SETFIELD(IODA2_LXIVT_SERVER, data64, m_server);
		data64 = SETFIELD(IODA2_LXIVT_PRIORITY, data64, m_prio);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_29..30 - MRT */
	phb3_ioda_sel(p, IODA2_TBL_MRT, 0, true);
	for (i = 0; i < 8; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_31..32 - TVT */
	phb3_ioda_sel(p, IODA2_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* Init_33..34 - M64BT */
	phb3_ioda_sel(p, IODA2_TBL_M64BT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m64d_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m64d_cache[i]);

	/* Init_35..36 - M32DT */
	phb3_ioda_sel(p, IODA2_TBL_M32DT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m32d_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m32d_cache[i]);

	/* Load RTE, PELTV */
	if (p->tbl_rtt)
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
	if (p->tbl_peltv)
		memcpy((void *)p->tbl_peltv, p->peltv_cache, PELTV_TABLE_SIZE);

	/* Load IVT */
	if (p->tbl_ivt) {
		pdata64 = (uint64_t *)p->tbl_ivt;
		for (i = 0; i < IVT_TABLE_ENTRIES; i++)
			pdata64[i * IVT_TABLE_STRIDE] = p->ive_cache[i];
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_set_phb_mem_window(struct phb *phb,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint64_t __unused starting_real_addr,
				       uint64_t starting_pci_addr,
				       uint16_t segment_size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t tbl, index, data64, *cache;

	/*
	 * By design, PHB3 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;
		if ((starting_pci_addr & 0xffffful) ||
		    (segment_size & 0xffffful))
			return OPAL_PARAMETER;

		tbl = IODA2_TBL_M64BT;
		index = window_num;
		segment_size *= PHB3_MAX_PE_NUM;
		cache = &p->m64d_cache[index];
		break;
	default:
		return OPAL_PARAMETER;
	}

	data64 = SETFIELD(IODA2_M64BT_BASE_ADDR, 0x0ul, starting_pci_addr);
	data64 = SETFIELD(IODA2_M64BT_ADDRMASK, data64, segment_size - 1);
	phb3_ioda_sel(p, tbl, index, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	*cache = data64;

	return OPAL_SUCCESS;
}

static int64_t phb3_phb_mmio_enable(struct phb *phb,
				    uint16_t window_type,
				    uint16_t window_num,
				    uint16_t enable)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t tbl, index, data64, *cache;

	/*
	 * By design, PHB3 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;

		tbl = IODA2_TBL_M64BT;
		index = window_num;
		cache = &p->m64d_cache[index];
		break;
	default:
		return OPAL_PARAMETER;
	}

	phb3_ioda_sel(p, tbl, index, false);
	data64 = in_be64(p->regs + PHB_IODA_DATA0);
	if (enable)
		data64 |= IODA2_M64BT_ENABLE;
	else
		data64 &= ~IODA2_M64BT_ENABLE;
	*cache = data64;

	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_mmio_window(struct phb *phb,
				       uint16_t pe_num,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint16_t segment_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t tbl, index, *cache;

	if (pe_num >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/*
	 * PHB3 doesn't support IODT any more. On the other
	 * hand, PHB3 support M64DT with much more flexibility.
	 * we need figure it out later. At least, we never use
	 * M64DT in kernel.
	 */
	switch(window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M64_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num >= PHB3_MAX_PE_NUM)
			return OPAL_PARAMETER;
		tbl = IODA2_TBL_M32DT;
		index = segment_num;
		cache = &p->m32d_cache[index];
		break;
	default:
		return OPAL_PARAMETER;
	}

	phb3_ioda_sel(p, tbl, index, false);
	out_be64(p->regs + PHB_IODA_DATA0,
		 SETFIELD(IODA2_M32DT_PE, 0ull, pe_num));
	*cache = SETFIELD(IODA2_M32DT_PE, 0ull, pe_num);

	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_dma_window(struct phb *phb,
				      uint16_t pe_num,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t tce_index;
	uint64_t data64 = 0;

	/*
	 * Sanity check. It's notable the window ID is meaningless
	 * to IODA2-compatible PHB3 because TVE index (window ID)
	 * is determined by PE# and DMA address[59].
	 */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    window_id >= 512 ||
	    tce_levels != 1 ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/*
	 * Figure out the TCE page size. The default value
	 * would be 4KB
	 */
	if (tce_page_size != 0x1000 && tce_page_size != 0x10000 &&
	    tce_page_size != 0x1000000 && tce_page_size != 0x10000000)
		tce_page_size = 0x1000;

	data64 = SETFIELD(IODA2_TVT_TABLE_ADDR, 0ul, tce_table_addr >> 12);
	tce_index = ilog2(tce_table_size / 0x1000) + 1;
	data64 = SETFIELD(IODA2_TVT_TCE_TABLE_SIZE, data64, tce_index);
	switch (tce_page_size) {
	case 0x1000:
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 1);
		break;
	case 0x10000:
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 5);
		break;
	case 0x1000000:
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 13);
		break;
	case 0x10000000:
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 17);
		break;
	}

	phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t phb3_set_ive_pe(struct phb *phb,
			       uint32_t pe_num,
			       uint32_t ive_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t *ive, data64;

	/* OS should enable the BAR in advance */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE reserves 128 bytes */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES)
		return OPAL_PARAMETER;

	/* Update IVE cache */
	ive = &p->ive_cache[ive_num];
	*ive = SETFIELD(IODA2_IVT_PE, *ive, pe_num);

	/* Update in-memory IVE */
	ive = (uint64_t *)p->tbl_ivt;
	ive += (ive_num * IVT_TABLE_STRIDE);
	*ive = SETFIELD(IODA2_IVT_PE, *ive, pe_num);

	/* Invalidate IVC */
	data64 = SETFIELD(PHB_IVC_INVALIDATE_SID, 0ul, ive_num);
	out_be64(p->regs + PHB_IVC_INVALIDATE, data64);

	return OPAL_SUCCESS;
}

static int64_t phb3_get_msi_32(struct phb *phb __unused,
			       uint32_t pe_num,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint32_t *msi_address,
			       uint32_t *message_data)
{
	/*
	 * Sanity check. We needn't check on mve_number (PE#)
	 * on PHB3 since the interrupt source is purely determined
	 * by its DMA address and data, but the check isn't
	 * harmful.
	 */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES ||
	    msi_range != 1 || !msi_address|| !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = (0xFFFF0000 | (ive_num << 4)) & 0xFFFFFF0F;
	*message_data = ive_num;

	return OPAL_SUCCESS;
}

static int64_t phb3_get_msi_64(struct phb *phb __unused,
			       uint32_t pe_num,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint64_t *msi_address,
			       uint32_t *message_data)
{
	/* Sanity check */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES ||
	    msi_range != 1 || !msi_address || !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = ((0x9ul << 60) | (ive_num << 4)) & 0xFFFFFFFFFFFFFF0Ful;
	*message_data = ive_num;

	return OPAL_SUCCESS;
}

static int64_t phb3_msi_get_xive(void *data,
				 uint32_t isn,
				 uint16_t *server,
				 uint8_t *prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq;
	uint64_t ive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id ||
	    index != p->index ||
	    irq > PHB3_MSI_IRQ_MAX)
		return OPAL_PARAMETER;

	/*
	 * Each IVE has 16 bytes in cache. Note that the kernel
	 * should strip the link bits from server field.
	 */
	ive = p->ive_cache[irq];
	*server = GETFIELD(IODA2_IVT_SERVER, ive);
	*prio = GETFIELD(IODA2_IVT_PRIORITY, ive);

	return OPAL_SUCCESS;
}

static int64_t phb3_msi_set_xive(void *data,
				 uint32_t isn,
				 uint16_t server,
				 uint8_t prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq;
	uint64_t *ive, data64, m_server, m_prio;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (!p->tbl_rtt)
		return OPAL_HARDWARE;
	if (chip != p->chip_id ||
	    index != p->index ||
	    irq > PHB3_MSI_IRQ_MAX)
		return OPAL_PARAMETER;

	/*
	 * We need strip the link from server. As Milton told
	 * me, the server is assigned as follows and the left
	 * bits unused: node/chip/core/thread/link = 2/3/4/3/2
	 *
	 * Note: the server has added the link bits to server.
	 */
	m_server = server;
	m_prio = prio;

	ive = &p->ive_cache[irq];
	*ive = SETFIELD(IODA2_IVT_SERVER, *ive, m_server);
	*ive = SETFIELD(IODA2_IVT_PRIORITY, *ive, m_prio);

	/*
	 * Update IVT and IVC. We need use IVC update register
	 * to do that. Each IVE in the table has 128 bytes
	 */
	ive = (uint64_t *)p->tbl_ivt;
	ive += (irq * IVT_TABLE_STRIDE);
	data64 = PHB_IVC_UPDATE_ENABLE_SERVER | PHB_IVC_UPDATE_ENABLE_PRI;
	data64 = SETFIELD(PHB_IVC_UPDATE_SERVER, data64, m_server);
	data64 = SETFIELD(PHB_IVC_UPDATE_PRI, data64, m_prio);

	*ive = SETFIELD(IODA2_IVT_SERVER, *ive, m_server);
	*ive = SETFIELD(IODA2_IVT_PRIORITY, *ive, m_prio);
	out_be64(p->regs + PHB_IVC_UPDATE, data64);

	return OPAL_SUCCESS;
}

static int64_t phb3_lsi_get_xive(void *data,
				 uint32_t isn,
				 uint16_t *server,
				 uint8_t *prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq;
	uint64_t lxive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id	||
	    index != p->index	||
	    irq < PHB3_LSI_IRQ_MIN ||
	    irq > PHB3_LSI_IRQ_MAX)
		return OPAL_PARAMETER;

	lxive = p->lxive_cache[irq - PHB3_LSI_IRQ_MIN];
	*server = GETFIELD(IODA2_LXIVT_SERVER, lxive);
	*prio = GETFIELD(IODA2_LXIVT_PRIORITY, lxive);

	return OPAL_SUCCESS;
}

static int64_t phb3_lsi_set_xive(void *data,
				 uint32_t isn,
				 uint16_t server,
				 uint8_t prio)
{
	struct phb3 *p = data;
	uint32_t chip, index, irq;
	uint64_t lxive, m_server, m_prio;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id	||
	    index != p->index	||
	    irq < PHB3_LSI_IRQ_MIN ||
	    irq > PHB3_LSI_IRQ_MAX)
		return OPAL_PARAMETER;

	lxive = SETFIELD(IODA2_LXIVT_SERVER, 0ul, server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, prio);

	/*
	 * We cache the arguments because we have to mangle
	 * it in order to hijack 3 bits of priority to extend
	 * the server number
	 */
	p->lxive_cache[irq - PHB3_LSI_IRQ_MIN] = lxive;

	/* Now we mangle the server and priority */
	if (prio == 0xff) {
		m_server = 0;
		m_prio = 0xff;
	} else {
		m_server = server >> 3;
		m_prio = (prio >> 3) | ((server & 7) << 5);
	}

	/* We use HRT entry 0 always for now */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, irq, false);
	lxive = in_be64(p->regs + PHB_IODA_DATA0);
	lxive = SETFIELD(IODA2_LXIVT_SERVER, lxive, m_server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, m_prio);
	out_be64(p->regs + PHB_IODA_DATA0, lxive);

	return OPAL_SUCCESS;
}

/* MSIs (OS owned) */
static const struct irq_source_ops phb3_msi_irq_ops = {
	.get_xive = phb3_msi_get_xive,
	.set_xive = phb3_msi_set_xive,
};

/* LSIs (OS owned) */
static const struct irq_source_ops phb3_lsi_irq_ops = {
	.get_xive = phb3_lsi_get_xive,
	.set_xive = phb3_lsi_set_xive,
};

static int64_t phb3_set_pe(struct phb *phb,
			   uint64_t pe_num,
                           uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t mask, val, tmp, idx;
	int32_t all = 0;
	uint16_t *rte;

	/* Sanity check */
	if (!p->tbl_rtt)
		return OPAL_HARDWARE;
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_num >= PHB3_MAX_PE_NUM || bdfn > 0xffff ||
	    bcompare > OpalPciBusAll ||
	    dcompare > OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare > OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_PARAMETER;

	/* Figure out the RID range */
	if (bcompare == OpalPciBusAny) {
		mask = 0x0;
		val  = 0x0;
		all  = 0x1;
	} else {
		tmp  = ((0x1 << (bcompare + 1)) - 1) << (15 - bcompare);
		mask = tmp;
		val  = bdfn & tmp;
	}

	if (dcompare == OPAL_IGNORE_RID_DEVICE_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0xf8;
		val  |= (bdfn & 0xf8);
	}

	if (fcompare == OPAL_IGNORE_RID_FUNCTION_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0x7;
		val  |= (bdfn & 0x7);
	}

	/* Map or unmap the RTT range */
	if (all == 0x7) {
		if (action == OPAL_MAP_PE) {
			for (idx = 0; idx < RTT_TABLE_SIZE/2; idx++)
				p->rte_cache[idx] = pe_num;
		} else {
			memset(p->rte_cache, 0xff, RTT_TABLE_SIZE);
		}
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
		out_be64(p->regs + PHB_RTC_INVALIDATE,
			 PHB_RTC_INVALIDATE_ALL);
	} else {
		rte = (uint16_t *)p->tbl_rtt;
		for (idx = 0; idx < RTT_TABLE_SIZE/2; idx++, rte++) {
			if ((idx & mask) != val)
				continue;
			p->rte_cache[idx] = (action ? pe_num : 0xffff);
			*rte = p->rte_cache[idx];

			/*
			 * We might not need invalidate RTC one by one since
			 * the RTT is expected to be updated in batch mode
			 * in host kernel.
			 */
			out_be64(p->regs + PHB_RTC_INVALIDATE,
				 SETFIELD(PHB_RTC_INVALIDATE_RID, 0ul, idx));
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_set_peltv(struct phb *phb,
			      uint32_t parent_pe,
			      uint32_t child_pe,
			      uint8_t state)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint8_t *peltv;
	uint32_t idx, mask;

	/* Sanity check */
	if (!p->tbl_peltv)
		return OPAL_HARDWARE;
	if (parent_pe >= PHB3_MAX_PE_NUM || child_pe >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/* Find index for parent PE */
	idx = parent_pe * (PHB3_MAX_PE_NUM / 8);
	idx += (child_pe / 8);
	mask = 0x1 << (child_pe % 8);

	peltv = (uint8_t *)p->tbl_peltv;
	peltv += idx;
	if (state) {
		*peltv |= mask;
		p->peltv_cache[idx] |= mask;
	} else {
		*peltv &= ~mask;
		p->peltv_cache[idx] &= ~mask;
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_link_state(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	uint16_t lstat;
	int64_t rc;

	/* XXX Test for PHB in error state ? */

	/* Link is up, let's find the actual speed */
	if (!(reg & PHB_PCIE_DLP_TC_DL_LINKACT))
		return OPAL_SHPC_LINK_DOWN;

	rc = phb3_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_LSTAT,
				&lstat);
	if (rc < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to read link status\n");
		return OPAL_HARDWARE;
	}
	if (!(lstat & PCICAP_EXP_LSTAT_DLLL_ACT))
		return OPAL_SHPC_LINK_DOWN;

	return GETFIELD(PCICAP_EXP_LSTAT_WIDTH, lstat);
}

static int64_t phb3_power_state(struct phb __unused *phb)
{
	/* XXX Test for PHB in error state ? */

	/* XXX TODO - External power control ? */

	return OPAL_SHPC_POWER_ON;
}

static int64_t phb3_slot_power_off(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;
	if (p->state != PHB3_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* XXX TODO - External power control ? */

	return OPAL_SUCCESS;
}

static int64_t phb3_slot_power_on(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;
	if (p->state != PHB3_STATE_FUNCTIONAL)
		return OPAL_BUSY;

	/* XXX TODO - External power control ? */

	return OPAL_SUCCESS;
}

static void phb3_setup_for_link_down(struct phb3 *p)
{
	uint32_t reg32;

	/* Mark link down */
	p->has_link = false;

	/* Mask PCIE port interrupts */
	out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0xffc3800000000000);

	/* Mask AER receiver error */
	out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0x7E00000000000000);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, &reg32);
	reg32 |= PCIECAP_AER_CE_RECVR_ERR;
	phb3_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, reg32);
}

static void phb3_setup_for_link_up(struct phb3 *p)
{
	uint32_t reg32;
	
	/* Clear AER receiver error status */
	phb3_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			    PCIECAP_AER_CE_RECVR_ERR);
	/* Unmask receiver error status in AER */
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, &reg32);
	reg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
	phb3_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_MASK, reg32);

	/* Clear spurrious errors and enable PCIE port interrupts */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, 0xffdfffffffffffff);
	out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0xffdb800000000000);

	/* Mark link down */
	p->has_link = true;
}

static int64_t phb3_sm_link_poll(struct phb3 *p)
{
	uint64_t reg;

	/* This is the state machine to wait for the link to come
	 * up. Currently we juts wait until we timeout, eventually
	 * we want to add retries and fallback to Gen1.
	 */
	switch(p->state) {
	case PHB3_STATE_WAIT_LINK:
		/* XXX I used the PHB_PCIE_LINK_MANAGEMENT register here but
		 *     simics doesn't seem to give me anything, so I've switched
		 *     to PCIE_DLP_TRAIN_CTL which appears more reliable
		 */
		//reg = in_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT);
		//if (reg & PHB_PCIE_LM_LINK_ACTIVE) {
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & PHB_PCIE_DLP_TC_DL_LINKACT) {
			/* Setup PHB for link up */
			phb3_setup_for_link_up(p);

			PHBDBG(p, "Link is up!\n");

			p->state = PHB3_STATE_FUNCTIONAL;
			return OPAL_SUCCESS;
		}

		if (p->retries-- == 0) {
			PHBDBG(p, "Timeout waiting for link up\n");
			/* No link, we still mark the PHB as functional */
			p->state = PHB3_STATE_FUNCTIONAL;
			return OPAL_SUCCESS;
		}

		return phb3_set_sm_timeout(p, msecs_to_tb(100));
	default:
		/* How did we get here ? */
		assert(false);
	}
	return OPAL_HARDWARE;
}

static int64_t phb3_start_link_poll(struct phb3 *p)
{
	p->retries = 10;
	p->state = PHB3_STATE_WAIT_LINK;
	return phb3_set_sm_timeout(p, msecs_to_tb(10));
}

static int64_t phb3_sm_fundamental_reset(struct phb3 *p)
{
	uint64_t reg;

	/* Handle boot time skipping of reset */
	if (p->skip_perst && p->state == PHB3_STATE_FUNCTIONAL) {
		p->state = PHB3_FRESET_DEASSERT_DELAY;
		p->skip_perst = false;
	}

	switch(p->state) {
	case PHB3_STATE_FUNCTIONAL:
		/* Prepare for link going down */
		phb3_setup_for_link_down(p);

		/* Check if there's something connected */
		if (phb3_presence_detect(&p->phb) != OPAL_SHPC_DEV_PRESENT) {
			PHBDBG(p, "Slot freset: no device\n");
			return OPAL_CLOSED;
		}

		/* Assert PERST */
		reg = in_be64(p->regs + PHB_RESET);
		reg &= ~0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		PHBDBG(p, "Asserting PERST...\n");

		/* XXX Check delay for PERST... doing 1s for now */
		p->state = PHB3_STATE_FRESET_ASSERT_DELAY;
		return phb3_set_sm_timeout(p, secs_to_tb(1));

	case PHB3_STATE_FRESET_ASSERT_DELAY:
		/* Deassert PERST */
		reg = in_be64(p->regs + PHB_RESET);
		reg |= 0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		PHBDBG(p, "Deasserting PERST...\n");

		/* Wait 200ms before polling link */
		p->state = PHB3_FRESET_DEASSERT_DELAY;
		return phb3_set_sm_timeout(p, msecs_to_tb(200));

	case PHB3_FRESET_DEASSERT_DELAY:
		/* Switch to generic link poll state machine */
		return phb3_start_link_poll(p);

	default:
		PHBDBG(p, "phb3_sm_fundamental_reset: wrong state %d\n",
		       p->state);
		break;
	}

	p->state = PHB3_STATE_FUNCTIONAL;
	return OPAL_HARDWARE;
}

static int64_t phb3_fundamental_reset(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state != PHB3_STATE_FUNCTIONAL) {
		PHBDBG(p, "phb3_fundamental_reset: wrong state %d\n", p->state);
		return OPAL_HARDWARE;
	}

	return phb3_sm_fundamental_reset(p);
}

static int64_t phb3_poll(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t now = mftb();

	if (p->state == PHB3_STATE_FUNCTIONAL)
		return OPAL_SUCCESS;

	/* Check timer */
	if (p->delay_tgt_tb &&
	    tb_compare(now, p->delay_tgt_tb) == TB_ABEFOREB)
		return p->delay_tgt_tb - now;

	/* Expired (or not armed), clear it */
	p->delay_tgt_tb = 0;

	/* Dispatch to the right state machine */
	switch(p->state) {
	case PHB3_STATE_FRESET_ASSERT_DELAY:
	case PHB3_FRESET_DEASSERT_DELAY:
		return phb3_sm_fundamental_reset(p);
	case PHB3_STATE_WAIT_LINK:
		return phb3_sm_link_poll(p);
	default:
		PHBDBG(p, "phb3_poll: wrong state %d\n", p->state);
		break;
	}

	/* Unknown state, could be a HW error */
	return OPAL_HARDWARE;
}

static int64_t phb3_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
				      uint8_t *freeze_state,
				      uint16_t *pci_error_type,
				      uint16_t *severity,
				      uint64_t __unused *phb_status)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t peev_bit = PPC_BIT(pe_number & 0x3f);
	uint64_t peev, pesta, pestb;

	/* Defaults: not frozen */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;

	/* Check dead */
	if (p->state == PHB3_STATE_BROKEN) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_DEAD;
		goto bail;
	}

#if 0
	/* Check fence */
	if (p7ioc_phb_fenced(p)) {
		/* Should be OPAL_EEH_STOPPED_TEMP_UNAVAIL ? */
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_FENCED;
		p->state = P7IOC_PHB_STATE_FENCED;
		goto bail;
	}
#endif

	/* Check the PEEV */
	phb3_ioda_sel(p, IODA2_TBL_PEEV, pe_number / 4, true);
	peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (!(peev & peev_bit))
		return OPAL_SUCCESS;

#if 0
	/* Indicate that we have an ER pending */
	p7ioc_phb_set_err_pending(p, true);
#endif
	if (severity)
		*severity = OPAL_EEH_SEV_PE_ER;

	/* Read the PESTA & PESTB */
	phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
	pesta = in_be64(p->regs + PHB_IODA_DATA0);
	phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
	pestb = in_be64(p->regs + PHB_IODA_DATA0);

	/* Convert them */
	if (pesta & IODA2_PESTA_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (pestb & IODA2_PESTB_DMA_STOPPED)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

	/* XXX Read the actual PEST error from the in-memory PEST */
 bail:
#if 0
	if (phb_status)
		p7ioc_eeh_read_phb_status(p, (struct OpalIoP7IOCPhbErrorData *)
					  phb_status);
#endif
	return OPAL_SUCCESS;
}

static void phb3_ER_err_clear(struct phb3 *p)
{
	u64 err, lem;
	u32 val;

	/* XXX This is the P7IOC recovery sequence quickly hacked...
	 *
	 * We need to rework that based on PHB3 specifics
	 */

	/* Rec 1,2 */
	lem = in_be64(p->regs + PHB_LEM_FIR_ACCUM);

	/* Rec 3,4,5 AER registers (could use cfg space accessors) */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000001c00000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x10000000);

	/* Rec 6,7,8 XXX DOC whacks payload & req size ... we don't */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000005000000000ull);
	val = in_be32(p->regs + PHB_CONFIG_DATA);
	out_be32(p->regs + PHB_CONFIG_DATA, (val & 0xe0700000) | 0x0f000f00);

	/* Rec 9,10,11 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000010400000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 12,13,14 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000011000000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 23,24,25 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000013000000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 26,27,28 */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000004000000000ull);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x470100f8);

	/* Rec 29..34 UTL registers */
	err = in_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS, err);
	err = in_be64(p->regs + UTL_PCIE_PORT_STATUS);
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, err);
	err = in_be64(p->regs + UTL_RC_STATUS);
	out_be64(p->regs + UTL_RC_STATUS, err);

	/* PHB error traps registers */
	err = in_be64(p->regs + PHB_ERR_STATUS);
	out_be64(p->regs + PHB_ERR_STATUS, err);
	out_be64(p->regs + PHB_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_ERR_LOG_1, 0);

	err = in_be64(p->regs + PHB_OUT_ERR_STATUS);
	out_be64(p->regs + PHB_OUT_ERR_STATUS, err);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1, 0);

	err = in_be64(p->regs + PHB_INA_ERR_STATUS);
	out_be64(p->regs + PHB_INA_ERR_STATUS, err);
	out_be64(p->regs + PHB_INA_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_INA_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_INA_ERR_LOG_1, 0);

	err = in_be64(p->regs + PHB_INB_ERR_STATUS);
	out_be64(p->regs + PHB_INB_ERR_STATUS, err);
	out_be64(p->regs + PHB_INB_ERR1_STATUS, 0);
	out_be64(p->regs + PHB_INB_ERR_LOG_0, 0);
	out_be64(p->regs + PHB_INB_ERR_LOG_1, 0);

	/* Rec 67, 68 LEM */
	out_be64(p->regs + PHB_LEM_FIR_AND_MASK, ~lem);
	out_be64(p->regs + PHB_LEM_WOF, 0);
}

static int64_t phb3_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				     uint64_t eeh_action_token)
{
	struct phb3 *p = phb_to_phb3(phb);

	/* XXX Minimal stuff to get working vs. PCI probe, proper
	 * EEH still needs to be done
	 */
	u64 err;

	/* Summary. If nothing, move to clearing the PESTs which can
	 * contain a freeze state from a previous error or simply set
	 * explicitely by the user
	 */
	err = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (err == 0)
		goto clear_pest;

	phb3_ER_err_clear(p);

 clear_pest:
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}


#if 0
	/* Update ER pending indication */
	phb3_ioda_sel(p, IODA_TBL_PEEV, 0, true);
	peev0 = in_be64(p->regs + PHB_IODA_DATA0);
	peev1 = in_be64(p->regs + PHB_IODA_DATA0);
	if (peev0 || peev1) {
		p->err.err_src   = P7IOC_ERR_SRC_PHB0 + p->index;
		p->err.err_class = P7IOC_ERR_CLASS_ER;
		p->err.err_bit   = 0;
		p7ioc_phb_set_err_pending(p, true);
	} else
		p7ioc_phb_set_err_pending(p, false);
#endif

	return OPAL_SUCCESS;
}

static const struct phb_ops phb3_ops = {
	.lock			= phb3_lock,
	.unlock			= phb3_unlock,
	.cfg_read8		= phb3_pcicfg_read8,
	.cfg_read16		= phb3_pcicfg_read16,
	.cfg_read32		= phb3_pcicfg_read32,
	.cfg_write8		= phb3_pcicfg_write8,
	.cfg_write16		= phb3_pcicfg_write16,
	.cfg_write32		= phb3_pcicfg_write32,
	.choose_bus		= phb3_choose_bus,
	.presence_detect	= phb3_presence_detect,
	.ioda_reset		= phb3_ioda_reset,
	.set_phb_mem_window	= phb3_set_phb_mem_window,
	.phb_mmio_enable	= phb3_phb_mmio_enable,
	.map_pe_mmio_window	= phb3_map_pe_mmio_window,
	.map_pe_dma_window	= phb3_map_pe_dma_window,
	.set_xive_pe		= phb3_set_ive_pe,
	.get_msi_32		= phb3_get_msi_32,
	.get_msi_64		= phb3_get_msi_64,
	.set_pe			= phb3_set_pe,
	.set_peltv		= phb3_set_peltv,
	.link_state		= phb3_link_state,
	.power_state		= phb3_power_state,
	.slot_power_off		= phb3_slot_power_off,
	.slot_power_on		= phb3_slot_power_on,
	.fundamental_reset	= phb3_fundamental_reset,
	.poll			= phb3_poll,
	.eeh_freeze_status	= phb3_eeh_freeze_status,
	.eeh_freeze_clear	= phb3_eeh_freeze_clear,
/*
	.complete_reset		= p7ioc_complete_reset,
	.hot_reset		= p7ioc_hot_reset,
	.get_diag_data		= p7ioc_get_diag_data,
	.next_error		= p7ioc_eeh_next_error,
*/
};

static void phb3_setup_aib(struct phb3 *p)
{
	/* Note: Odd, we do that over AIB ... I assume that
	 * the defaults are good enough for this to work. If there's a
	 * probblem we could change to using the indirect ASB accesses
	 * via XSCOM
	 */
	/* Init_2 - AIB TX Channel Mapping Register */
	/* use default value
	out_be64(p->regs + PHB_AIB_TX_CHAN_MAPPING, 0x011230000000000);
	*/

	/* Init_3 - AIB RX command credit register */
	out_be64(p->regs + PHB_AIB_RX_CMD_CRED,		0x0020000100010001);
	
	/* Init_4 - AIB rx data credit register */
	out_be64(p->regs + PHB_AIB_RX_DATA_CRED,	0x0020002000000001);

	/* Init_5 - AIB rx credit init timer register */
	out_be64(p->regs + PHB_AIB_RX_CRED_INIT_TIMER,	0x0f00000000000000);

	/* Init_6 - AIB Tag Enable register */
	/* use default value
	out_be64(p->regs + PHB_AIB_TAG_ENABLE,		0xffffffff00000000);
	*/

	/* Init_7 - TCE Tag Enable register */
	/* use default value
	out_be64(p->regs + PHB_TCE_TAG_ENABLE,		0xffffffff00000000);
	*/
}

static void phb3_init_ioda2(struct phb3 *p)
{
	/* Init_14 - LSI Source ID */
	out_be64(p->regs + PHB_LSI_SOURCE_ID,
		 SETFIELD(PHB_LSI_SRC_ID, 0ul, 0xff));

	/* Init_15 - IVT BAR / Length
	 * Note: This is left uninitialized until the OS configures it,
	 * we will not enable MSIs until this has been configured
	 */
	out_be64(p->regs + PHB_IVT_BAR, 0);

	/* Init_16 - RBA BAR
	 * Note: This is left uninitialized until the OS configures it,
	 * we will not enable MSIs until this has been configured
	 */
	out_be64(p->regs + PHB_RBA_BAR, 0);

	/* Init_16 - RTT BAR
	 * XXX: Handle using the OS value when available, for now always
	 * use our internal one
	 */
	out_be64(p->regs + PHB_RTT_BAR, p->tbl_rtt | PHB_RTT_BAR_ENABLE);
	
	/* Init_17 - PELT-V BAR
	 * XXX: Handle using the OS value when available, for now always
	 * use our internal one
	 */
	out_be64(p->regs + PHB_PELTV_BAR, p->tbl_peltv | PHB_PELTV_BAR_ENABLE);

	/* Init_18..21 - Setup M32 */
	out_be64(p->regs + PHB_M32_BASE_ADDR, p->mm_base + M32_PCI_START);
	out_be64(p->regs + PHB_M32_BASE_MASK, ~(M32_PCI_SIZE - 1));
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_22 - Setup PEST BAR */
	out_be64(p->regs + PHB_PEST_BAR, p->tbl_pest | PHB_PEST_BAR_ENABLE);

	/* Init_23 - PCIE Outbound upper address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_24 - Interrupt represent timers */
	out_be64(p->regs + PHB_INTREP_TIMER, 0);

	/* Init_25 - PHB3 Configuration Register */
	/* We keep MSI disabled until the IVT and RBA have been configured
	 * by the OS. First clear the TCE cache, then configure the PHB
	 */
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64B_TCE_EN);
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_M32_EN);

	/* Init_26 - At least 512ns delay according to spec */
	time_wait_ms(1);

	/* Init_27..36 - On-chip IODA tables init */
	phb3_ioda_reset(&p->phb, false);
}

static bool phb3_wait_dlp_reset(struct phb3 *p)
{
	unsigned int i;
	uint64_t val;

	/*
	 * Firmware cannot access the UTL core regs or PCI config space
	 * until the cores are out of DL_PGRESET.
	 * DL_PGRESET should be polled until it is inactive with a value
	 * of '0'. The recommended polling frequency is once every 1ms.
	 * Firmware should poll at least 200 attempts before giving up.
	 * MMIO Stores to the link are silently dropped by the UTL core if
	 * the link is down.
	 * MMIO Loads to the link will be dropped by the UTL core and will
	 * eventually time-out and will return an all ones response if the
	 * link is down.
	 */
#define DLP_RESET_ATTEMPTS	400

	PHBDBG(p, "Waiting for DLP PG reset to complete...\n");
	for (i = 0; i < DLP_RESET_ATTEMPTS; i++) {
		val = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(val & PHB_PCIE_DLP_TC_DL_PGRESET))
			break;
		time_wait_ms(1);
	}
	if (val & PHB_PCIE_DLP_TC_DL_PGRESET) {
		PHBERR(p, "Timeout waiting for DLP PG reset !\n");
		return false;
	}
	return true;
}

/* phb3_init_rc - Initialize the Root Complex config space
 */
static bool phb3_init_rc_cfg(struct phb3 *p)
{
	int64_t ecap, aercap;

	/* XXX Handle errors ? */

	/* Init_45..46:
	 *
	 * Set primary bus to 0, secondary to 1 and subordinate to 0xff
	 */
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_PRIMARY_BUS, 0x00ff0100);

	/* Init_47..52
	 *
	 * IO and Memory base & limits are set to base > limit, which
	 * allows all inbounds.
	 *
	 * XXX This has the potential of confusing the OS which might
	 * think that nothing is forwarded downstream. We probably need
	 * to fix this to match the IO and M32 PHB windows
	 */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_IO_BASE, 0x0010);
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_MEM_BASE, 0x00000010);
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_PREF_MEM_BASE, 0x00000010);

	/* Init_53..54 - Setup bridge control enable forwarding of CORR, FATAL,
	 * and NONFATAL errors
	*/
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, PCI_CFG_BRCTL_SERR_EN);

	/* Init_55..56
	 *
	 * PCIE Device control/status, enable error reporting, disable relaxed
	 * ordering, set MPS to 128 (see note), clear errors.
	 *
	 * Note: The doc recommends to set MPS to 4K. This has proved to have
	 * some issues as it requires specific claming of MRSS on devices and
	 * we've found devices in the field that misbehave when doing that.
	 *
	 * We currently leave it all to 128 bytes (minimum setting) at init
	 * time. The generic PCIe probing later on might apply a different
	 * value, or the kernel will, but we play it safe at early init
	 */
	ecap = pci_find_cap(&p->phb, 0, PCI_CFG_CAP_ID_EXP);
	if (ecap < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to locate PCI-E capability in bridge\n");
		return false;
	}
	p->ecap = ecap;

	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVSTAT,
			     PCICAP_EXP_DEVSTAT_CE	|
			     PCICAP_EXP_DEVSTAT_NFE	|
			     PCICAP_EXP_DEVSTAT_FE	|
			     PCICAP_EXP_DEVSTAT_UE);

	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVCTL,
			     PCICAP_EXP_DEVCTL_CE_REPORT	|
			     PCICAP_EXP_DEVCTL_NFE_REPORT	|
			     PCICAP_EXP_DEVCTL_FE_REPORT	|
			     PCICAP_EXP_DEVCTL_UR_REPORT	|
			     SETFIELD(PCICAP_EXP_DEVCTL_MPS, 0, PCIE_MPS_128B));

	/* Init_57..58
	 *
	 * Root Control Register. Enable error reporting
	 *
	 * Note: Added CRS visibility.
	 */
	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_RC,
			     PCICAP_EXP_RC_SYSERR_ON_CE		|
			     PCICAP_EXP_RC_SYSERR_ON_NFE	|
			     PCICAP_EXP_RC_SYSERR_ON_FE		|
			     PCICAP_EXP_RC_CRS_VISIBLE);

	/* Init_59..60
	 *
	 * Device Control 2. Enable ARI fwd, set timer to RTOS timer
	 */
	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DCTL2,
			     SETFIELD(PCICAP_EXP_DCTL2_CMPTOUT, 0, 0xf) |
			     PCICAP_EXP_DCTL2_ARI_FWD);

	/* Init_61..76
	 *
	 * AER inits
	 */
	aercap = pci_find_ecap(&p->phb, 0, PCIECAP_ID_AER, NULL);
	if (aercap < 0) {
		/* Shouldn't happen */
		PHBERR(p, "Failed to locate AER Ecapability in bridge\n");
		return false;
	}
	p->aercap = aercap;

	/* Clear all UE status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB3 spec */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_MASK,
			     PCIECAP_AER_UE_POISON_TLP		|
			     PCIECAP_AER_UE_COMPL_TIMEOUT	|
			     PCIECAP_AER_UE_COMPL_ABORT		|
			     PCIECAP_AER_UE_ECRC);
	/* Report some errors as fatal */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_SEVERITY,
			     PCIECAP_AER_UE_DLP 		|
			     PCIECAP_AER_UE_SURPRISE_DOWN	|
			     PCIECAP_AER_UE_FLOW_CTL_PROT	|
			     PCIECAP_AER_UE_UNEXP_COMPL		|
			     PCIECAP_AER_UE_RECV_OVFLOW		|
			     PCIECAP_AER_UE_MALFORMED_TLP);
	/* Clear all CE status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB3 spec */
	/* Note: When link down, also disable rcvr errors */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_MASK,
			    PCIECAP_AER_CE_ADV_NONFATAL |
			    p->has_link ? 0 : PCIECAP_AER_CE_RECVR_ERR);
	/* Enable ECRC generation & checking */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CAPCTL,
			     PCIECAP_AER_CAPCTL_ECRCG_EN	|
			     PCIECAP_AER_CAPCTL_ECRCC_EN);
	/* Enable reporting in root error control */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_CMD,
			     PCIECAP_AER_RERR_CMD_FE		|
			     PCIECAP_AER_RERR_CMD_NFE		|
			     PCIECAP_AER_RERR_CMD_CE);
	/* Clear root error status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_STA,
			     0xffffffff);

	return true;
}

static void phb3_init_utl(struct phb3 *p)
{
	/* Init_77..79: Clear spurrious errors and assign errors to the
	 * right "interrupt" signal
	 */
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS,       0xffffffffffffffff);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_ERR_SEVERITY, 0x0000000000000000);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_IRQ_EN,       0xfcc0000000000000);
	/* XXX BML uses:
	out_be64(p->regs + UTL_SYS_BUS_AGENT_IRQ_EN,       0xac80000000000000);
	*/

	/* Init_80..81: Setup tag allocations */
	/* using default values
	out_be64(p->regs + UTL_PCIE_TAGS_ALLOC,            0x0800000000000000);
	out_be64(p->regs + UTL_GBIF_READ_TAGS_ALLOC,       0x2000000000000000);
	*/

	/* Init_82: PCI Express port control */
	out_be64(p->regs + UTL_PCIE_PORT_CONTROL,          0x8580007000000000);

	/* Init_83..85: Clean & setup port errors */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,           0xffdfffffffffffff);
	out_be64(p->regs + UTL_PCIE_PORT_ERROR_SEV,        0x0038000000000000);

	if (p->has_link)
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xffdb800000000000);
	else
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xffc3800000000000);

	/* Init_86 : Cleanup RC errors */
	out_be64(p->regs + UTL_RC_STATUS,                  0xffffffffffffffff);
}

static void phb3_init_errors(struct phb3 *p)
{
	/* Init_88: LEM Error Mask : Temporarily disable error interrupts */
	out_be64(p->regs + PHB_LEM_ERROR_MASK,		   0xffffffffffffffff);

	/* Init_89..97: Disable all error interrupts until end of init */
	out_be64(p->regs + PHB_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_LEM_ENABLE,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_ERR_FREEZE_ENABLE,	   0x0000000080800000);
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,	   0xffffffdd0c00ffc0);
	out_be64(p->regs + PHB_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_STATUS_MASK,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_98_106: Configure MMIO error traps & clear old state */
	out_be64(p->regs + PHB_OUT_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_LEM_ENABLE,	   0xfdffffffffffffff);
	out_be64(p->regs + PHB_OUT_ERR_FREEZE_ENABLE,	   0x0000420800000000);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9cf3bc00f8dc700f);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_STATUS_MASK,	   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_107_115: Configure DMA_A error traps & clear old state */
	out_be64(p->regs + PHB_INA_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_INA_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR_LEM_ENABLE,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_INA_ERR_FREEZE_ENABLE,	   0xc00003a901006000);
	out_be64(p->regs + PHB_INA_ERR_AIB_FENCE_ENABLE,   0x3fff5452fe019fde);
	out_be64(p->regs + PHB_INA_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR_STATUS_MASK,	   0x0000000000000000);
	out_be64(p->regs + PHB_INA_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_116_124: Configure DMA_B error traps & clear old state */
	out_be64(p->regs + PHB_INB_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_INB_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR_LEM_ENABLE,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_INB_ERR_FREEZE_ENABLE,	   0x0000600000000060);
	out_be64(p->regs + PHB_INB_ERR_AIB_FENCE_ENABLE,   0xfcff80fbff7ff08c);
	out_be64(p->regs + PHB_INB_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR_STATUS_MASK,	   0x0000000000000000);
	out_be64(p->regs + PHB_INB_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_125..128: Cleanup & configure LEM */
	out_be64(p->regs + PHB_LEM_FIR_ACCUM,		   0x0000000000000000);
	out_be64(p->regs + PHB_LEM_ACTION0,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_LEM_ACTION1,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_LEM_WOF,			   0x0000000000000000);
}

static void phb3_init_hw(struct phb3 *p)
{
	uint64_t val;

	PHBDBG(p, "Initializing PHB...\n");

	/* Lift reset */
	xscom_write(p->chip_id, p->pci_xscom + 0xa, 0);

	/* Setup AIB credits etc... */
	phb3_setup_aib(p);

	/* Init_8 - PCIE System Configuration Register */
	/* note: default value but BML writes it anyway */
	out_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG,	   0x441000fc30000000);

	/* Init_9..12 - PCIE DLP Lane EQ control */
	/* XXX We need to get those parameters from HB */

	/* Init_13 - PCIE Reset */

	/* Note: At boot time, this will lift PERST in addition to the reset
	 *       to the various cores, meaning that Link training will begin
	 *       immediately to save time
	 */

	out_be64(p->regs + PHB_RESET,			   0xf000000000000000);

	/* Architected IODA2 inits */
	phb3_init_ioda2(p);

	/* Init_37..42 - Clear UTL & DLP error logs */
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG1,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG2,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG3,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG4,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG1,	   0xffffffffffffffff);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG2,	   0xffffffffffffffff);

	/* Init_43 - Wait for UTL core to come out of reset */
	if (!phb3_wait_dlp_reset(p))
		goto failed;

	/* Init_44 - Clear port status */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,	   0xffffffffffffffff);

	/* Init_45..76: Init root complex config space */
	if (!phb3_init_rc_cfg(p))
		goto failed;

	/* Init_77..86 : Init UTL */
	phb3_init_utl(p);

	/* Init_87: PHB Control register. Various PHB settings */
	out_be64(p->regs + PHB_CONTROL, 	       	   0xf3a8014b00000000);

	/* Init_88..128  : Setup error registers */
	phb3_init_errors(p);

	/* Init_129: Read error summary */
	val = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (val) {
		PHBERR(p, "Errors detected during PHB init: 0x%16llx\n", val);
		goto failed;
	}

	/* XXX I don't know why the spec does this now and not earlier, so
	 * to be sure to get it right we might want to move it to the freset
	 * state machine, though the generic PCI layer will probably do
	 * this anyway (ie, enable MEM, etc... in the RC)
	 *
	 * Note:The spec enables IO but PHB3 doesn't do IO space .... so we
	 * leave that clear.
	 */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD,
			    PCI_CFG_CMD_MEM_EN |
			    PCI_CFG_CMD_BUS_MASTER_EN |
			    PCI_CFG_CMD_PERR_RESP |
			    PCI_CFG_CMD_SERR_EN);

	/* Clear errors */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_STAT,
			    PCI_CFG_STAT_SENT_TABORT |
			    PCI_CFG_STAT_RECV_TABORT |
			    PCI_CFG_STAT_RECV_MABORT |
			    PCI_CFG_STAT_SENT_SERR |
			    PCI_CFG_STAT_RECV_PERR);

	/* Init_136 - Re-enable error interrupts */

	/* Note: Might need to check if some of these need masking
	 *       while there is no link
	 */
	out_be64(p->regs + PHB_ERR_IRQ_ENABLE,	   0x00000032f0f80000);
	out_be64(p->regs + PHB_OUT_ERR_IRQ_ENABLE, 0x600443fc03a000f0);
	out_be64(p->regs + PHB_INA_ERR_IRQ_ENABLE, 0xc000a3ff89260026);
	out_be64(p->regs + PHB_INB_ERR_IRQ_ENABLE, 0x0000400000800000);
	out_be64(p->regs + PHB_LEM_ERROR_MASK,	   0x42092f367f7028ae);

	/* Init_141 - Enable DMA address speculation */
	out_be64(p->regs + PHB_TCE_SPEC_CTL,		   0xf000000000000000);


	/* Mark the PHB as functional which enables all the various sequences */
	p->state = PHB3_STATE_FUNCTIONAL;

	PHBDBG(p, "Initialization complete\n");

	return;

 failed:
	PHBERR(p, "Initialization failed\n");
	p->state = PHB3_STATE_BROKEN;
}

static void phb3_allocate_tables(struct phb3 *p)
{
	/* XXX Our current memalign implementation sucks,
	 *
	 * It will do the job, however it doesn't support freeing
	 * the memory and wastes space by always allocating twice
	 * as much as requested (size + alignment)
	 */
	p->tbl_rtt = (uint64_t)memalign(RTT_TABLE_SIZE, RTT_TABLE_SIZE);
	assert(p->tbl_rtt);
	memset((void *)p->tbl_rtt, 0, RTT_TABLE_SIZE);

	p->tbl_peltv = (uint64_t)memalign(PELTV_TABLE_SIZE, PELTV_TABLE_SIZE);
	assert(p->tbl_peltv);
	memset((void *)p->tbl_peltv, 0, PELTV_TABLE_SIZE);

	p->tbl_pest = (uint64_t)memalign(PEST_TABLE_SIZE, PEST_TABLE_SIZE);
	assert(p->tbl_pest);
	memset((void *)p->tbl_pest, 0, PEST_TABLE_SIZE);

	p->tbl_ivt = (uint64_t)memalign(IVT_TABLE_SIZE, IVT_TABLE_SIZE);
	assert(p->tbl_ivt);
	memset((void *)p->tbl_ivt, 0, IVT_TABLE_SIZE);

	/* Doh.. that was ugly .. did I really do all these casts ?
	 * maybe I should break a leg instead...
	 */
}

static void phb3_add_properties(struct phb3 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t lsibase, icsp = get_ics_phandle();
	uint64_t m32b, reg, tkill;

	reg = cleanup_addr((uint64_t)p->regs);

	/* Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc...
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */

	dt_add_property_cells(np, "interrupt-parent", icsp);

	/* XXX FIXME: add slot-name */
	//dt_property_cell("bus-width", 8); /* Figure it out from VPD ? */

	/* "ranges", we only expose M32 (PHB3 doesn't do IO)
	 *
	 * Note: The kernel expects us to have chopped of 64k from the
	 * M32 size (for the 32-bit MSIs). If we don't do that, it will
	 * get confused (OPAL does it)
	 */
	m32b = cleanup_addr(p->mm_base + PHB_M32_OFFSET + M32_PCI_START);
	dt_add_property_cells(np, "ranges",
			      /* M32 space */
			      0x02000000, 0x00000000, M32_PCI_START,
			      hi32(m32b), lo32(m32b), 0, M32_PCI_SIZE - 0x10000);

	/* XXX FIXME: add opal-memwin32, 64, dmawins, etc... */
	//dt_add_property_cells(np, "ibm,opal-msi-ports", 2048);
	dt_add_property_cells(np, "ibm,opal-num-pes", 256);
	dt_add_property_cells(np, "ibm,opal-msi-ranges",
			      p->base_msi, PHB3_MSI_IRQ_COUNT);
	tkill = reg + PHB_TCE_KILL;
	dt_add_property_cells(np, "ibm,opal-tce-kill",
			      hi32(tkill), lo32(tkill));

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->base_lsi;
	p->phb.lstate.int_size = 1;
	p->phb.lstate.int_val[0][0] = lsibase + PHB3_LSI_PCIE_INTA;
	p->phb.lstate.int_val[1][0] = lsibase + PHB3_LSI_PCIE_INTB;
	p->phb.lstate.int_val[2][0] = lsibase + PHB3_LSI_PCIE_INTC;
	p->phb.lstate.int_val[3][0] = lsibase + PHB3_LSI_PCIE_INTD;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;
}

static void phb3_create(struct dt_node *np)
{
	struct phb3 *p = zalloc(sizeof(struct phb3));
	const struct dt_property *prop;
	char *path;

	assert(p);

	/* Populate base stuff */
	p->index = dt_prop_get_u32(np, "ibm,phb-index");
	p->chip_id = dt_prop_get_u32(np, "ibm,chip-id");
	p->regs = (void *)dt_get_address(np, 0, NULL);
	p->base_msi = PHB3_MSI_IRQ_BASE(p->chip_id, p->index);
	p->base_lsi = PHB3_LSI_IRQ_BASE(p->chip_id, p->index);
	p->phb.dt_node = np;
	p->phb.ops = &phb3_ops;
	p->phb.phb_type = phb_type_pcie_v3;
	p->phb.scan_map = 0x1; /* Only device 0 to scan */
	p->state = PHB3_STATE_UNINITIALIZED;

	/* Get PBCQ MMIO window from device-tree. We currently support
	 * only one out of the two the HW deals with
	 */
	prop = dt_require_property(np, "ibm,mmio-window", 2 * sizeof(uint64_t));
	p->mm_base = ((uint64_t *)prop->prop)[0];
	p->mm_size = ((uint64_t *)prop->prop)[1];

	/* Get the various XSCOM register bases from the device-tree */
	prop = dt_require_property(np, "ibm,xscom-bases", 3 * sizeof(uint32_t));
	p->pe_xscom = ((uint32_t *)prop->prop)[0];
	p->spci_xscom = ((uint32_t *)prop->prop)[1];
	p->pci_xscom = ((uint32_t *)prop->prop)[2];

	/* We skip the initial PERST requested by the generic code because
	 * our init sequence includes a PERST already so we save boot time
	 * that way. The PERST state machine will still handle waiting for the
	 * link to come up, it will just avoid actually asserting & deasserting
	 * the PERST output
	 */
	p->skip_perst = true;
	p->has_link = false;

	/* Hello ! */
	path = dt_get_path(np);
	printf("PHB3: Found %s @%p MMIO [0x%016llx..0x%016llx]\n",
	       path, p->regs, p->mm_base, p->mm_base + p->mm_size - 1);
	free(path);

	/* Allocate the SkiBoot internal in-memory tables for the PHB */
	phb3_allocate_tables(p);

	phb3_add_properties(p);

	/* We register the PHB before we initialize it so we
	 * get a useful OPAL ID for it
	 */
	pci_register_phb(&p->phb);

	/* Clear IODA2 cache */
	phb3_init_ioda_cache(p);

	/* Register OS interrupt sources */
	register_irq_source(&phb3_msi_irq_ops, p, p->base_msi,
			    PHB3_MSI_IRQ_COUNT);
	register_irq_source(&phb3_lsi_irq_ops, p, p->base_lsi,
			    PHB3_LSI_IRQ_COUNT);

	phb3_init_hw(p);
}

static void hack_create_phb3(uint32_t gcid, uint32_t pno)
{
	uint32_t spci_xscom = 0x09013c00 + (pno * 0x40);
	uint32_t pci_xscom = 0x09012000 + (pno * 0x400);
	uint32_t pe_xscom = 0x02012000 + (pno * 0x400);
	uint64_t val, phb_bar, mmio_bar, mmio_bmask, mmio_sz;
	uint64_t reg[2];
	struct dt_node *np;

	/* Check if CAPP mode */
	if (xscom_read(gcid, spci_xscom + 0x03, &val)) {
		prerror("PHB3[%d:%d]: Cannot read AIB CAPP ENABLE\n",
			gcid, pno);
		return;
	}
	if (val >> 63) {
		prerror("PHB3[%d:%d]: Ignoring bridge in CAPP mode\n",
			gcid, pno);
		return;
	}

	/* Get PE BARs, assume only 0 and 2 are used for now */
	xscom_read(gcid, pe_xscom + 0x42, &phb_bar);
	phb_bar >>= 14;
	printf("PHB3[%d:%d] REGS   = 0x%016llx [4k]\n",
		gcid, pno, phb_bar);

	/* Dbl check PHB BAR */
	xscom_read(gcid, pci_xscom + 0x0b, &val);
	printf("PHB3[%d:%d] PCIBAR = 0x%016llx\n",
		gcid, pno, (val >> 14));

	/* Check MMIO BAR */
	xscom_read(gcid, pe_xscom + 0x40, &mmio_bar);
	xscom_read(gcid, pe_xscom + 0x43, &mmio_bmask);
	mmio_bmask &= 0xffffffffc0000000ull;
	mmio_sz = ((~mmio_bmask) >> 14) + 1;
	mmio_bar >>= 14;
	printf("PHB3[%d:%d] MMIO   = 0x%016llx [0x%016llx]\n",
		gcid, pno, mmio_bar, mmio_sz);

	/* Check BAR enable */
	xscom_read(gcid, pe_xscom + 0x45, &val);
	printf("PHB3[%d:%d] BAREN  = 0x%016llx\n",
		gcid, pno, val);

	/* Set the interrupt routing stuff, 8 relevant bits in mask
	 * (11 bits per PHB)
	 */
	val = P8_CHIP_IRQ_PHB_BASE(gcid, pno);
	val = (val << 45);
	xscom_write(gcid, pe_xscom + 0x1a, val);
	xscom_write(gcid, pe_xscom + 0x1b, 0xff00000000000000ul);

	/* Configure LSI location to the top of the map */
	xscom_write(gcid, pe_xscom + 0x1f, 0xff00000000000000ul);

	xscom_read(gcid, pe_xscom + 0x1a, &val);
	printf("PHB3[%d:%d] IRSNC  = 0x%016llx\n",
		gcid, pno, val);
	xscom_read(gcid, pe_xscom + 0x1b, &val);
	printf("PHB3[%d:%d] IRSNM  = 0x%016llx\n",
		gcid, pno, val);
	printf("PHB3[%d:%d] LSI    = 0x%016llx\n",
		gcid, pno, val);

	reg[0] = phb_bar;
	reg[1] = 0x1000;

	np = dt_new_addr(dt_root, "pciex", reg[0]);
	dt_add_property_strings(np, "compatible", "ibm,p8-pciex",
				"ibm,ioda2-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));

	/* Everything else is handled later by skiboot, we just
	 * stick a few hints here
	 */
	dt_add_property_cells(np, "ibm,xscom-bases",
			      pe_xscom, spci_xscom, pci_xscom);
	dt_add_property_cells(np, "ibm,mmio-window",
			      hi32(mmio_bar), lo32(mmio_bar),
			      hi32(mmio_sz), lo32(mmio_sz));
	dt_add_property_cells(np, "ibm,phb-index", pno);

	/* We know on P8 that GCID == chip ID */
	dt_add_property_cells(np, "ibm,chip-id", gcid);
}

static void hack_create_phb3_nodes(uint32_t gcid)
{
	if (proc_gen != proc_gen_p8)
		return;
	hack_create_phb3(gcid, 0);
	hack_create_phb3(gcid, 1);
	hack_create_phb3(gcid, 2);

}

void probe_phb3(void)
{
	struct dt_node *np;

	/* XXX HACK: HB Doesn't create the nodes yet ! */
	hack_create_phb3_nodes(xscom_pir_to_gcid(this_cpu()->pir));

	dt_for_each_compatible(dt_root, np, "ibm,p8-pciex")
		phb3_create(np);
}

