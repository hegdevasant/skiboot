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
#include <timebase.h>
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

static void phb3_init_hw(struct phb3 *p);

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
	uint64_t hp_override;
	int64_t rc;

	/* Test for PHB in error state ? */
	if (p->state == PHB3_STATE_BROKEN)
		return OPAL_HARDWARE;

	/* XXX Check bifurcation stuff ? */

	/* Read slot status register */
	rc = phb3_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTSTAT,
					&slot_stat);
	if (rc != OPAL_SUCCESS)
		return OPAL_HARDWARE;

	/* Read hotplug override */
	hp_override = in_be64(p->regs + PHB_HOTPLUG_OVERRIDE);

	printf("PHB%d: slot_stat: 0x%04x, hp_override: 0x%016llx\n",
	       phb->opal_id, slot_stat, hp_override);

	/* So if the slot status says nothing connected, we bail out */
	if (!(slot_stat & PCICAP_EXP_SLOTSTAT_PDETECTST))
		return OPAL_SHPC_DEV_NOT_PRESENT;

	/*
	 * At this point, we can have one of those funky IBM
	 * systems that has the presence bit set in the slot
	 * status and nothing actually connected. If so, we
	 * check the hotplug override A/B bits
	 */
	if (p->use_ab_detect &&
	    (hp_override & PHB_HPOVR_PRESENCE_A) &&
	    (hp_override & PHB_HPOVR_PRESENCE_B))
		return OPAL_SHPC_DEV_NOT_PRESENT;

	/*
	 * Anything else, we assume device present, the link state
	 * machine will perform an early bail out if no electrical
	 * signaling is established after a second.
	 */
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
	 *
	 * Note: Instead we set all RTE entries to 0x00 to
	 * work around a problem where PE lookups might be
	 * done before Linux has established valid PE's
	 * (during PCI probing). We can revisit that once/if
	 * Linux has been fixed to always setup valid PEs.
	 *
	 * The value 0x00 corresponds to the default PE# Linux
	 * uses to check for config space freezes before it
	 * has assigned PE# to busses.
	 */
	memset(p->rte_cache, 0x00, RTT_TABLE_SIZE);
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
	memset(p->m64b_cache, 0x0, sizeof(p->m64b_cache));
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
	uint64_t server, prio;
	uint64_t *pdata64, data64;
	uint32_t i;

	if (purge) {
		printf("PHB%d: Purging all IODA tables...\n", p->phb.opal_id);
		phb3_init_ioda_cache(p);
	}

	/* Init_27..28 - LIXVT */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = p->lxive_cache[i];
		server = GETFIELD(IODA2_LXIVT_SERVER, data64);
		prio = GETFIELD(IODA2_LXIVT_PRIORITY, data64);
		data64 = SETFIELD(IODA2_LXIVT_SERVER, data64, server);
		data64 = SETFIELD(IODA2_LXIVT_PRIORITY, data64, prio);
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
	for (i = 0; i < ARRAY_SIZE(p->m64b_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m64b_cache[i]);

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

	/* Invalidate RTE, IVE, TCE cache */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_IVC_INVALIDATE, PHB_IVC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ALL);

	/* Clear freeze */
	for (i = 0; i < PHB3_MAX_PE_NUM; i++) {
		uint64_t pesta, pestb;

		phb3_ioda_sel(p, IODA2_TBL_PESTA, i, false);
		pesta = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		phb3_ioda_sel(p, IODA2_TBL_PESTB, i, false);
		pestb = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);

		if ((pesta & IODA2_PESTA_MMIO_FROZEN) ||
		    (pestb & IODA2_PESTB_DMA_STOPPED))
			printf("PHB%d: PE# %d was frozen\n", phb->opal_id, i);
	}
	return OPAL_SUCCESS;
}

static int64_t phb3_set_phb_mem_window(struct phb *phb,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint64_t addr,
				       uint64_t __unused pci_addr,
				       uint64_t size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64;

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

		data64 = p->m64b_cache[window_num];
		if (data64 & IODA2_M64BT_SINGLE_PE) {
			if ((addr & 0x1FFFFFFul) ||
			    (size & 0x1FFFFFFul))
				return OPAL_PARAMETER;
		} else {
			if ((addr & 0xFFFFFul) ||
			    (size & 0xFFFFFul))
				return OPAL_PARAMETER;
		}

		break;
	default:
		return OPAL_PARAMETER;
	}

	if (data64 & IODA2_M64BT_SINGLE_PE) {
		data64 = SETFIELD(IODA2_M64BT_SINGLE_BASE, data64,
				  addr >> 25);
		data64 = SETFIELD(IODA2_M64BT_SINGLE_MASK, data64,
				  0x10000000 - (size >> 25));
	} else {
		data64 = SETFIELD(IODA2_M64BT_BASE, data64,
				  addr >> 20);
		data64 = SETFIELD(IODA2_M64BT_MASK, data64,
				  0x10000000 - (size >> 20));
	}
	p->m64b_cache[window_num] = data64;

	return OPAL_SUCCESS;
}

/*
 * For one specific M64 BAR, it can be shared by all PEs,
 * or owned by single PE exclusively.
 */
static int64_t phb3_phb_mmio_enable(struct phb *phb,
				    uint16_t window_type,
				    uint16_t window_num,
				    uint16_t enable)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64, base, mask;

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
		if (window_num >= 16 ||
		    enable > OPAL_ENABLE_M64_NON_SPLIT)
			return OPAL_PARAMETER;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * We need check the base/mask while enabling
	 * the M64 BAR. Otherwise, invalid base/mask
	 * might cause fenced AIB unintentionally
	 */
	data64 = p->m64b_cache[window_num];
	switch (enable) {
	case OPAL_DISABLE_M64:
		data64 &= ~IODA2_M64BT_ENABLE;
		break;
	case OPAL_ENABLE_M64_SPLIT:
		base = GETFIELD(IODA2_M64BT_BASE, data64);
		base = (base << 20);
		mask = GETFIELD(IODA2_M64BT_MASK, data64);
		if (base < p->m64_base || !mask)
			return OPAL_PARTIAL;

		data64 &= ~IODA2_M64BT_SINGLE_PE;
		data64 |= IODA2_M64BT_ENABLE;
		break;
	case OPAL_ENABLE_M64_NON_SPLIT:
		base = GETFIELD(IODA2_M64BT_SINGLE_BASE, data64);
		base = (base << 25);
		mask = GETFIELD(IODA2_M64BT_SINGLE_MASK, data64);
		if (base < p->m64_base || !mask)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_SINGLE_PE;
		data64 |= IODA2_M64BT_ENABLE;
		break;
	}

	/* Update HW and cache */
	phb3_ioda_sel(p, IODA2_TBL_M64BT, window_num, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->m64b_cache[window_num] = data64;
	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_mmio_window(struct phb *phb,
				       uint16_t pe_num,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint16_t segment_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64, *cache;

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
		return OPAL_UNSUPPORTED;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num >= PHB3_MAX_PE_NUM)
			return OPAL_PARAMETER;

		cache = &p->m32d_cache[segment_num];
		phb3_ioda_sel(p, IODA2_TBL_M32DT, segment_num, false);
		out_be64(p->regs + PHB_IODA_DATA0,
			 SETFIELD(IODA2_M32DT_PE, 0ull, pe_num));
		*cache = SETFIELD(IODA2_M32DT_PE, 0ull, pe_num);

		break;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;
		cache = &p->m64b_cache[window_num];
		data64 = *cache;

		/* The BAR shouldn't be enabled yet */
		if (data64 & IODA2_M64BT_ENABLE)
			return OPAL_PARTIAL;

		data64 = SETFIELD(IODA2_M64BT_PE_HI, data64, pe_num >> 5);
		data64 = SETFIELD(IODA2_M64BT_PE_LOW, data64, pe_num);
		*cache = data64;

		break;
	default:
		return OPAL_PARAMETER;
	}

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

static int64_t phb3_pci_msi_eoi(struct phb *phb,
				uint32_t hwirq)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint32_t ive_num = PHB3_IRQ_NUM(hwirq);
	uint64_t ive, ivc, ffi;
	uint8_t *p_byte, *q_byte;

	/* OS might not configure IVT yet */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE has 16-bytes or 128-bytes */
	ive = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	p_byte = (uint8_t *)(ive + 4);
	q_byte = (uint8_t *)(ive + 5);
	ivc = SETFIELD(PHB_IVC_UPDATE_SID, 0, ive_num);
	ffi = SETFIELD(PHB_FFI_REQUEST_ISN, 0, ive_num);

	/*
	 * Clear P bit. As Milton suggested, we needn't
	 * clear it for multiple times in one shoot
	 */
	if (*p_byte & 0x1) {
		*p_byte = 0;
		out_be64(p->regs + PHB_IVC_UPDATE,
			 ivc | PHB_IVC_UPDATE_ENABLE_P);
	}

	/*
	 * Handle Q bit. If the Q bit doesn't show up,
	 * we would have CI load to make that.
	 */
	if (!(*q_byte & 0x1))
		in_be64(p->regs + PHB_IVC_UPDATE);
	if (*q_byte & 0x1) {
		/* Lock FFI and send interrupt */
                while (in_be64(p->regs + PHB_FFI_LOCK));
		/* Clear Q bit */
		*q_byte = 0;
		out_be64(p->regs + PHB_IVC_UPDATE,
			 ivc | PHB_IVC_UPDATE_ENABLE_Q);
		/* Resend interrupt */
		out_be64(p->regs + PHB_FFI_REQUEST, ffi);
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_set_ive_pe(struct phb *phb,
			       uint32_t pe_num,
			       uint32_t ive_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t *cache, ivep, data64;
	uint16_t *pe_word;

	/* OS should enable the BAR in advance */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE reserves 128 bytes */
	if (pe_num >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES)
		return OPAL_PARAMETER;

	/* Update IVE cache */
	cache = &p->ive_cache[ive_num];
	*cache = SETFIELD(IODA2_IVT_PE, *cache, pe_num);

	/* Update in-memory IVE without clobbering P and Q */
	ivep = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	pe_word = (uint16_t *)(ivep + 6);
	*pe_word = pe_num;

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

static bool phb3_err_check_pbcq(struct phb3 *p)
{
	uint64_t nfir, mask, wof, val64;
	int32_t class, bit;
	uint64_t severity[PHB3_ERR_CLASS_LAST] = {
		0x0000000000000000,	/* NONE	*/
		0x018000F800000000,	/* DEAD */
		0x7E7DC70000000000,	/* FENCED */
		0x0000000000000000,	/* ER	*/
		0x0000000000000000	/* INF	*/
	};

	/*
	 * Read on NFIR to see if XSCOM is working properly.
	 * If XSCOM doesn't work well, we need take the PHB
	 * into account any more.
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &nfir);
	if (nfir == 0xffffffffffffffff) {
		p->err.err_src = PHB3_ERR_SRC_NONE;
		p->err.err_class = PHB3_ERR_CLASS_DEAD;
		phb3_set_err_pending(p, true);
		return true;
	}

	/*
	 * Check WOF. We need handle unmasked errors firstly.
	 * We probably run into the situation (on simulator)
	 * where we have asserted FIR bits, but WOF has nothing.
	 * For that case, we should check FIR as well.
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x3, &mask);
	xscom_read(p->chip_id, p->pe_xscom + 0x8, &wof);
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		if (nfir & ~mask)
			nfir &= ~mask;
		if (!nfir)
			return false;
		wof = nfir;
	}

	/* We shouldn't hit class PHB3_ERR_CLASS_NONE */
	for (class = PHB3_ERR_CLASS_NONE;
	     class < PHB3_ERR_CLASS_LAST;
	     class++) {
		val64 = wof & severity[class];
		if (!val64)
			continue;

		for (bit = 0; bit < 64; bit++) {
			if (val64 & PPC_BIT(bit)) {
				p->err.err_src = PHB3_ERR_SRC_PBCQ;
				p->err.err_class = class;
				p->err.err_bit = 63 - bit;
				phb3_set_err_pending(p, true);
				return true;
			}
		}
	}

	return false;
}

static bool phb3_err_check_lem(struct phb3 *p)
{
	uint64_t fir, wof, mask, val64;
	int32_t class, bit;
	uint64_t severity[PHB3_ERR_CLASS_LAST] = {
		0x0000000000000000,	/* NONE */
		0x0000000000000000,	/* DEAD */
		0xADB670C980ADD151,	/* FENCED */
		0x000800107F500A2C,	/* ER   */
		0x42018E2200002482	/* INF  */
	};

	/*
	 * Read FIR. If XSCOM or ASB is frozen, we needn't
	 * go forward and just mark the PHB with dead state
	 */
	fir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
	if (fir == 0xffffffffffffffff) {
		p->err.err_src = PHB3_ERR_SRC_PHB;
		p->err.err_class = PHB3_ERR_CLASS_DEAD;
		phb3_set_err_pending(p, true);
		return true;
	}

	/*
	 * Check on WOF for the unmasked errors firstly. Under
	 * some situation where we run skiboot on simulator,
	 * we already had FIR bits asserted, but WOF is still zero.
	 * For that case, we check FIR directly.
	 */
	wof = phb3_read_reg_asb(p, PHB_LEM_WOF);
	mask = phb3_read_reg_asb(p, PHB_LEM_ERROR_MASK);
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		if (fir & ~mask)
			fir &= ~mask;
		if (!fir)
			return false;
		wof = fir;
	}

	/* We shouldn't hit PHB3_ERR_CLASS_NONE */
	for (class = PHB3_ERR_CLASS_NONE;
	     class < PHB3_ERR_CLASS_LAST;
	     class++) {
		val64 = wof & severity[class];
		if (!val64)
			continue;

		for (bit = 0; bit < 64; bit++) {
			if (val64 & PPC_BIT(bit)) {
				p->err.err_src = PHB3_ERR_SRC_PHB;
				p->err.err_class = class;
				p->err.err_bit = 63 - bit;
				phb3_set_err_pending(p, true);
				return true;
			}
		}
	}

	return false;
}

/*
 * The function can be called during error recovery for INF
 * and ER class. For INF case, it's expected to be called
 * when grabbing the error log. We will call it explicitly
 * when clearing frozen PE state for ER case.
 */
static void phb3_err_ER_clear(struct phb3 *p)
{
	uint32_t val32;
	uint64_t val64;
	uint64_t fir = in_be64(p->regs + PHB_LEM_FIR_ACCUM);

	/* Rec 1: Grab the PCI config lock */
	phb3_cfg_lock(p);

	/* Rec 2/3/4: Take all inbound transactions */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000001c00000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x10000000);

	/* Rec 5/6/7: Clear pending non-fatal errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000005000000000ul);
	val32 = in_be32(p->regs + PHB_CONFIG_DATA);
	out_be32(p->regs + PHB_CONFIG_DATA, (val32 & 0xe0700000) | 0x0f000f00);

	/* Rec 8/9/10: Clear pending fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000010400000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 11/12/13: Clear pending non-fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000011000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 22/23/24: Clear root port errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000013000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 25/26/27: Enable IO and MMIO bar */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000004000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x470100f8);

	/* Rec 28: Release the PCI config lock */
	phb3_cfg_unlock(p);

	/* Rec 29...34: Clear UTL errors */
	val64 = in_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_PCIE_PORT_STATUS);
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_RC_STATUS);
	out_be64(p->regs + UTL_RC_STATUS, val64);

	/* Rec 39...66: Clear PHB error trap */
	val64 = in_be64(p->regs + PHB_ERR_STATUS);
	out_be64(p->regs + PHB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_OUT_ERR_STATUS);
	out_be64(p->regs + PHB_OUT_ERR_STATUS, val64);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INA_ERR_STATUS);
	out_be64(p->regs + PHB_INA_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INA_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INB_ERR_STATUS);
	out_be64(p->regs + PHB_INB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_1, 0x0ul);

	/* Rec 67/68: Clear FIR/WOF */
	out_be64(p->regs + PHB_LEM_FIR_AND_MASK, ~fir);
	out_be64(p->regs + PHB_LEM_WOF, 0x0ul);
}

static void phb3_read_phb_status(struct phb3 *p,
				 struct OpalIoPhb3ErrorData *stat)
{
	uint16_t val;
	uint64_t *pPEST;
	uint32_t i;

	memset(stat, 0, sizeof(struct OpalIoPhb3ErrorData));

	/* Error data common part */
	stat->common.version = OPAL_PHB_ERROR_DATA_VERSION_1;
	stat->common.ioType  = OPAL_PHB_ERROR_DATA_TYPE_PHB3;
	stat->common.len     = sizeof(struct OpalIoPhb3ErrorData);

	/*
	 * We read some registers using config space through AIB.
	 *
	 * Get to other registers using ASB when possible to get to them
	 * through a fence if one is present.
	 */

	/* Grab RC bridge control, make it 32-bit */
	phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &val);
	stat->brdgCtl = val;

	/* Grab UTL status registers */
	stat->portStatusReg = hi32(phb3_read_reg_asb(p, UTL_PCIE_PORT_STATUS));
	stat->rootCmplxStatus = hi32(phb3_read_reg_asb(p, UTL_RC_STATUS));
	stat->busAgentStatus = hi32(phb3_read_reg_asb(p, UTL_SYS_BUS_AGENT_STATUS));

	/*
	 * Grab various RC PCIe capability registers. All device, slot
	 * and link status are 16-bit, so we grab the pair control+status
	 * for each of them
	 */
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_DEVCTL,
			   &stat->deviceStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTCTL,
			   &stat->slotStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL,
			   &stat->linkStatus);

	/*
	 * I assume those are the standard config space header, cmd & status
	 * together makes 32-bit. Secondary status is 16-bit so I'll clear
	 * the top on that one
	 */
	phb3_pcicfg_read32(&p->phb, 0, PCI_CFG_CMD, &stat->devCmdStatus);
	phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, &val);
	stat->devSecStatus = val;

	/* Grab a bunch of AER regs */
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_RERR_STA,
			   &stat->rootErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_UE_STATUS,
			   &stat->uncorrErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			   &stat->corrErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG0,
			   &stat->tlpHdr1);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG1,
			   &stat->tlpHdr2);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG2,
			   &stat->tlpHdr3);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG3,
			   &stat->tlpHdr4);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_SRCID,
			   &stat->sourceId);

	/* PHB3 inbound and outbound error Regs */
	stat->phbPlssr = phb3_read_reg_asb(p, PHB_CPU_LOADSTORE_STATUS);
	stat->phbPlssr = phb3_read_reg_asb(p, PHB_DMA_CHAN_STATUS);
	stat->lemFir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
	stat->lemErrorMask = phb3_read_reg_asb(p, PHB_LEM_ERROR_MASK);
	stat->lemWOF = phb3_read_reg_asb(p, PHB_LEM_WOF);
	stat->phbErrorStatus = phb3_read_reg_asb(p, PHB_ERR_STATUS);
	stat->phbFirstErrorStatus = phb3_read_reg_asb(p, PHB_ERR1_STATUS);
	stat->phbErrorLog0 = phb3_read_reg_asb(p, PHB_ERR_LOG_0);
	stat->phbErrorLog1 = phb3_read_reg_asb(p, PHB_ERR_LOG_1);
	stat->mmioErrorStatus = phb3_read_reg_asb(p, PHB_OUT_ERR_STATUS);
	stat->mmioFirstErrorStatus = phb3_read_reg_asb(p, PHB_OUT_ERR1_STATUS);
	stat->mmioErrorLog0 = phb3_read_reg_asb(p, PHB_OUT_ERR_LOG_0);
	stat->mmioErrorLog1 = phb3_read_reg_asb(p, PHB_OUT_ERR_LOG_1);
	stat->dma0ErrorStatus = phb3_read_reg_asb(p, PHB_INA_ERR_STATUS);
	stat->dma0FirstErrorStatus = phb3_read_reg_asb(p, PHB_INA_ERR1_STATUS);
	stat->dma0ErrorLog0 = phb3_read_reg_asb(p, PHB_INA_ERR_LOG_0);
	stat->dma0ErrorLog1 = phb3_read_reg_asb(p, PHB_INA_ERR_LOG_1);
	stat->dma1ErrorStatus = phb3_read_reg_asb(p, PHB_INB_ERR_STATUS);
	stat->dma1FirstErrorStatus = phb3_read_reg_asb(p, PHB_INB_ERR1_STATUS);
	stat->dma1ErrorLog0 = phb3_read_reg_asb(p, PHB_INB_ERR_LOG_0);
	stat->dma1ErrorLog1 = phb3_read_reg_asb(p, PHB_INB_ERR_LOG_1);

	/* Grab PESTA & B content */
	pPEST = (uint64_t *)p->tbl_pest;
	for (i = 0; i < OPAL_PHB3_NUM_PEST_REGS; i++) {
		stat->pestA[i] = pPEST[2 * i];
		stat->pestB[i] = pPEST[2 * i + 1];
	}
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
	uint32_t chip, index;
	uint64_t *cache, ive_num, data64, m_server, m_prio;
	uint32_t *ive;

	chip = P8_IRQ_TO_CHIP(isn);
	index = P8_IRQ_TO_PHB(isn);
	ive_num = PHB3_IRQ_NUM(isn);

	if (!p->tbl_rtt)
		return OPAL_HARDWARE;
	if (chip != p->chip_id ||
	    index != p->index ||
	    ive_num > PHB3_MSI_IRQ_MAX)
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

	cache = &p->ive_cache[ive_num];
	*cache = SETFIELD(IODA2_IVT_SERVER,   *cache, m_server);
	*cache = SETFIELD(IODA2_IVT_PRIORITY, *cache, m_prio);

	/*
	 * Update IVT and IVC. We need use IVC update register
	 * to do that. Each IVE in the table has 128 bytes
	 */
	ive = (uint32_t *)(p->tbl_ivt + ive_num * IVT_TABLE_STRIDE * 8);
	data64 = PHB_IVC_UPDATE_ENABLE_SERVER | PHB_IVC_UPDATE_ENABLE_PRI;
	data64 = SETFIELD(PHB_IVC_UPDATE_SID, data64, ive_num);
	data64 = SETFIELD(PHB_IVC_UPDATE_SERVER, data64, m_server);
	data64 = SETFIELD(PHB_IVC_UPDATE_PRI, data64, m_prio);

	/*
	 * Don't use SETFIELD to update IVE entry since that
	 * might have race condition to overwrite P/Q bits
	 */
	*ive = (m_server << 8) | m_prio;
	out_be64(p->regs + PHB_IVC_UPDATE, data64);

	/*
	 * Handle P/Q bit if we're going to enable the interrupt.
	 * The OS should make sure the interrupt handler has
	 * been installed already.
	 */
	if (prio != 0xff)
		return phb3_pci_msi_eoi(&p->phb, isn);

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
	uint32_t chip, index, irq, entry;
	uint64_t lxive;

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
	entry = irq - PHB3_LSI_IRQ_MIN;
	p->lxive_cache[entry] = lxive;

	/* We use HRT entry 0 always for now */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, entry, false);
	lxive = in_be64(p->regs + PHB_IODA_DATA0);
	lxive = SETFIELD(IODA2_LXIVT_SERVER, lxive, server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, prio);
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
			for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++)
				p->rte_cache[idx] = pe_num;
		} else {
			memset(p->rte_cache, 0xff, RTT_TABLE_SIZE);
		}
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
		out_be64(p->regs + PHB_RTC_INVALIDATE,
			 PHB_RTC_INVALIDATE_ALL);
	} else {
		rte = (uint16_t *)p->tbl_rtt;
		for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++, rte++) {
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
	case PHB3_STATE_WAIT_LINK_ELECTRICAL:
		/* Wait for the link electrical connection to be
		 * established (shorter timeout). This allows us to
		 * workaround spurrious presence detect on some machines
		 * without waiting 10s each time
		 *
		 * Note: We *also* check for the full link up bit here
		 * because simics doesn't seem to implement the electrical
		 * link bit at all
		 */
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & (PHB_PCIE_DLP_INBAND_PRESENCE |
			   PHB_PCIE_DLP_TC_DL_LINKACT)) {
			PHBDBG(p, "Electrical link detected...\n");
			p->state = PHB3_STATE_WAIT_LINK;
			p->retries = PHB3_LINK_WAIT_RETRIES;
		} else if (p->retries-- == 0) {
			PHBDBG(p, "Timeout waiting for electrical link\n");
			/* No link, we still mark the PHB as functional */
			p->state = PHB3_STATE_FUNCTIONAL;
			return OPAL_SUCCESS;
		}
		return phb3_set_sm_timeout(p, msecs_to_tb(100));
	case PHB3_STATE_WAIT_LINK:
		/* XXX I used the PHB_PCIE_LINK_MANAGEMENT register here but
		 *     simics doesn't seem to give me anything, so I've switched
		 *     to PCIE_DLP_TRAIN_CTL which appears more reliable
		 */
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
	/*
	 * Wait for link up to 10s. However, we give up after
	 * only a second if the electrical connection isn't
	 * stablished according to the DLP link control register
	 */
	p->retries = PHB3_LINK_ELECTRICAL_RETRIES;
	p->state = PHB3_STATE_WAIT_LINK_ELECTRICAL;
	return phb3_set_sm_timeout(p, msecs_to_tb(100));
}

static int64_t phb3_sm_hot_reset(struct phb3 *p)
{
	uint16_t brctl;

	switch (p->state) {
	case PHB3_STATE_FUNCTIONAL:
		/* We need do nothing with available slot */
		if (phb3_presence_detect(&p->phb) != OPAL_SHPC_DEV_PRESENT) {
			PHBDBG(p, "Slot hreset: no device\n");
			return OPAL_CLOSED;
		}

		/* Prepare for link going down */
		phb3_setup_for_link_down(p);

		/* Turn on hot reset */
		phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		PHBDBG(p, "Slot hreset: assert reset\n");

		p->state = PHB3_STATE_HRESET_DELAY;
		return phb3_set_sm_timeout(p, secs_to_tb(1));
	case PHB3_STATE_HRESET_DELAY:
		/* Turn off hot reset */
		phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		PHBDBG(p, "Slot hreset: deassert reset\n");

		return phb3_start_link_poll(p);
	default:
		PHBDBG(p, "Slot hreset: wrong state %d\n", p->state);
		break;
	}

	p->state = PHB3_STATE_FUNCTIONAL;
	return OPAL_HARDWARE;
}

static int64_t phb3_hot_reset(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->state != PHB3_STATE_FUNCTIONAL) {
		PHBDBG(p, "phb3_hot_reset: wrong state %d\n",
		       p->state);
		return OPAL_HARDWARE;
	}

	return phb3_sm_hot_reset(p);
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
		/* Check if there's something connected */
		if (phb3_presence_detect(&p->phb) != OPAL_SHPC_DEV_PRESENT) {
			PHBDBG(p, "Slot freset: no device\n");
			return OPAL_CLOSED;
		}

		/* Prepare for link going down */
		phb3_setup_for_link_down(p);

		/* Assert PERST */
		reg = in_be64(p->regs + PHB_RESET);
		reg &= ~0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		PHBDBG(p, "Slot freset: Asserting PERST\n");

		/* XXX Check delay for PERST... doing 1s for now */
		p->state = PHB3_STATE_FRESET_ASSERT_DELAY;
		return phb3_set_sm_timeout(p, secs_to_tb(1));

	case PHB3_STATE_FRESET_ASSERT_DELAY:
		/* Deassert PERST */
		reg = in_be64(p->regs + PHB_RESET);
		reg |= 0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		PHBDBG(p, "Slot freset: Deasserting PERST\n");

		/* Wait 200ms before polling link */
		p->state = PHB3_FRESET_DEASSERT_DELAY;
		return phb3_set_sm_timeout(p, msecs_to_tb(200));

	case PHB3_FRESET_DEASSERT_DELAY:
		/* Switch to generic link poll state machine */
		return phb3_start_link_poll(p);

	default:
		PHBDBG(p, "Slot freset: wrong state %d\n",
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

/*
 * The OS is expected to do fundamental reset after complete
 * reset to make sure the PHB could be recovered from the
 * fenced state. However, the OS needn't do that explicitly
 * since fundamental reset will be done automatically while
 * powering on the PHB.
 *
 *
 * Usually, we need power off/on the PHB. That includes the
 * fundamental reset. However, we don't know how to control
 * the power stuff yet. So skip that and do fundamental reset
 * directly after reinitialization the hardware.
 */
static int64_t phb3_complete_reset(struct phb *phb, uint8_t assert)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t nfir, cqsts, val;
	int i;

	if (assert == OPAL_ASSERT_RESET) {
		if (p->state != PHB3_STATE_FUNCTIONAL &&
		    p->state != PHB3_STATE_FENCED)
			return OPAL_HARDWARE;

		/* Clear errors in NFIR and raise ETU reset */
		xscom_read(p->chip_id, p->pe_xscom + 0x0, &nfir);
		xscom_write(p->chip_id, p->pci_xscom + 0xa,
			    0x8000000000000000);
		for (i = 0; i < 500; i++) {
			xscom_read(p->chip_id, p->pe_xscom + 0x1c, &val);
			xscom_read(p->chip_id, p->pe_xscom + 0x1d, &val);
			xscom_read(p->chip_id, p->pe_xscom + 0x1e, &val);
			xscom_read(p->chip_id, p->pe_xscom + 0xf, &cqsts);
			if (!(cqsts & 0xC000000000000000))
				break;
			time_wait_ms(10);
		}
		if (cqsts & 0xC000000000000000)
			PHBERR(p, "Timeout waiting for pending transaction\n");
		xscom_write(p->chip_id, p->pe_xscom + 0x1, ~nfir);
		time_wait_ms(100);

		/*
		 * Re-initialize the PHB and issue
		 * the fundamental reset.
		 */
		phb3_init_hw(p);
		return phb3_fundamental_reset(phb);
	} else {
		if (p->state != PHB3_STATE_FUNCTIONAL)
			return OPAL_HARDWARE;

		/* Issue hot reset */
		return phb3_hot_reset(phb);
        }

	/* We shouldn't run to here */
	return OPAL_PARAMETER;
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
	case PHB3_STATE_HRESET_DELAY:
		return phb3_sm_hot_reset(p);
	case PHB3_STATE_FRESET_ASSERT_DELAY:
	case PHB3_FRESET_DEASSERT_DELAY:
		return phb3_sm_fundamental_reset(p);
	case PHB3_STATE_WAIT_LINK_ELECTRICAL:
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
				      uint64_t *phb_status)
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

	/* Indicate that we have an ER pending */
	phb3_set_err_pending(p, true);
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

bail:
	if (phb_status)
		phb3_read_phb_status(p,
			(struct OpalIoPhb3ErrorData *)phb_status, 0);

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				     uint64_t eeh_action_token)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t err, peev[4];
	int32_t i;
	bool frozen_pe = false;

	/* Summary. If nothing, move to clearing the PESTs which can
	 * contain a freeze state from a previous error or simply set
	 * explicitely by the user
	 */
	err = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (err != 0)
		phb3_err_ER_clear(p);

	/*
	 * We have PEEV in system memory. It would give more performance
	 * to access that directly.
	 */
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}


	/* Update ER pending indication */
	phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
	for (i = 0; i < ARRAY_SIZE(peev); i++) {
		peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
		if (peev[i]) {
			frozen_pe = true;
			break;
		}
	}
	if (frozen_pe) {
		p->err.err_src	 = PHB3_ERR_SRC_PHB;
		p->err.err_class = PHB3_ERR_CLASS_ER;
		p->err.err_bit   = -1;
		phb3_set_err_pending(p, true);
	} else
		phb3_set_err_pending(p, false);

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_next_error(struct phb *phb,
				   uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type,
				   uint16_t *severity)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t fir, peev[4];
	uint32_t cfg32;
	int32_t i, j;

	/* If the PHB is broken, we needn't go forward */
	if (p->state == PHB3_STATE_BROKEN) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_SUCCESS;
	}

	/*
	 * Check if we already have pending errors. If that's
	 * the case, then to get more information about the
	 * pending errors. Here we try PBCQ prior to PHB.
	 */
	if (phb3_err_pending(p)) {
		if (!phb3_err_check_pbcq(p) &&
		    !phb3_err_check_lem(p)) {
			p->err.err_src   = PHB3_ERR_SRC_NONE;
			p->err.err_class = PHB3_ERR_CLASS_NONE;
			p->err.err_bit   = -1;
			phb3_set_err_pending(p, false);
		}
	}

	/* Clear result */
	*pci_error_type  = OPAL_EEH_NO_ERROR;
	*severity	 = OPAL_EEH_SEV_NO_ERROR;
	*first_frozen_pe = (uint64_t)-1;

	/* Check frozen PEs */
	if (!phb3_err_pending(p)) {
		phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
		for (i = 0; i < ARRAY_SIZE(peev); i++) {
			peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
			if (peev[i]) {
				p->err.err_src	 = PHB3_ERR_SRC_PHB;
				p->err.err_class = PHB3_ERR_CLASS_ER;
				p->err.err_bit	 = -1;
				phb3_set_err_pending(p, true);
				break;
			}
		}
        }

	/* Mapping errors */
	if (phb3_err_pending(p)) {
		/*
		 * If the frozen PE is caused by a malfunctioning TLP, we
		 * need reset the PHB. So convert ER to PHB-fatal error
		 * for the case.
		 */
		if (p->err.err_class == PHB3_ERR_CLASS_ER) {
			fir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
			if (fir & PPC_BIT(60)) {
				phb3_pcicfg_read32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_STATUS, &cfg32);
				if (cfg32 & PCIECAP_AER_UE_MALFORMED_TLP)
					p->err.err_class = PHB3_ERR_CLASS_FENCED;
			}
		}

		switch (p->err.err_class) {
		case PHB3_ERR_CLASS_DEAD:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_DEAD;
			break;
		case PHB3_ERR_CLASS_FENCED:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_FENCED;
			break;
		case PHB3_ERR_CLASS_ER:
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;

			phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
			for (i = 0; i < ARRAY_SIZE(peev); i++)
				peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
			for (i = ARRAY_SIZE(peev) - 1; i >= 0; i--) {
				for (j = 0; j < 64; j++) {
					if (peev[i] & PPC_BIT(j)) {
						*first_frozen_pe = i * 64 + j;
						break;
					}
				}

				if (*first_frozen_pe != (uint64_t)(-1))
					break;
			}

			/* No frozen PE ? */
			if (*first_frozen_pe == (uint64_t)-1) {
				*pci_error_type = OPAL_EEH_NO_ERROR;
				*severity = OPAL_EEH_SEV_NO_ERROR;
				p->err.err_src	 = PHB3_ERR_SRC_NONE;
				p->err.err_class = PHB3_ERR_CLASS_NONE;
				p->err.err_bit	 = -1;
				phb3_set_err_pending(p, false);
			}

                        break;
		case PHB3_ERR_CLASS_INF:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_INF;
			break;
		default:
			*pci_error_type = OPAL_EEH_NO_ERROR;
			*severity = OPAL_EEH_SEV_NO_ERROR;
			p->err.err_src   = PHB3_ERR_SRC_NONE;
			p->err.err_class = PHB3_ERR_CLASS_NONE;
			p->err.err_bit   = -1;
			phb3_set_err_pending(p, false);
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_get_diag_data(struct phb *phb,
				  void *diag_buffer,
				  uint64_t diag_buffer_len)
{
	struct phb3 *p = phb_to_phb3(phb);
	struct OpalIoPhb3ErrorData *data = diag_buffer;

	if (diag_buffer_len < sizeof(struct OpalIoPhb3ErrorData))
		return OPAL_PARAMETER;

	phb3_read_phb_status(p, data);

	/*
	 * We're running to here probably because of errors
	 * (INF class). For that case, we need clear the error
	 * explicitly.
	 */
	if (phb3_err_pending(p) &&
	    p->err.err_class == PHB3_ERR_CLASS_INF &&
	    p->err.err_src == PHB3_ERR_SRC_PHB)
		phb3_err_ER_clear(p);

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
	.pci_msi_eoi		= phb3_pci_msi_eoi,
	.set_xive_pe		= phb3_set_ive_pe,
	.get_msi_32		= phb3_get_msi_32,
	.get_msi_64		= phb3_get_msi_64,
	.set_pe			= phb3_set_pe,
	.set_peltv		= phb3_set_peltv,
	.link_state		= phb3_link_state,
	.power_state		= phb3_power_state,
	.slot_power_off		= phb3_slot_power_off,
	.slot_power_on		= phb3_slot_power_on,
	.hot_reset		= phb3_hot_reset,
	.fundamental_reset	= phb3_fundamental_reset,
	.complete_reset		= phb3_complete_reset,
	.poll			= phb3_poll,
	.eeh_freeze_status	= phb3_eeh_freeze_status,
	.eeh_freeze_clear	= phb3_eeh_freeze_clear,
	.next_error		= phb3_eeh_next_error,
	.get_diag_data		= NULL,
	.get_diag_data2		= phb3_get_diag_data,
};

static void phb3_setup_aib(struct phb3 *p)
{
	/* Note: Odd, we do that over AIB ... I assume that
	 * the defaults are good enough for this to work. If there's a
	 * probblem we could change to using the indirect ASB accesses
	 * via XSCOM
	 */
	/* Init_2 - AIB TX Channel Mapping Register */
	out_be64(p->regs + PHB_AIB_TX_CHAN_MAPPING,     0x0211230000000000);

	/* Init_3 - AIB RX command credit register */
	out_be64(p->regs + PHB_AIB_RX_CMD_CRED,		0x0020000100010001);
	
	/* Init_4 - AIB rx data credit register */
	out_be64(p->regs + PHB_AIB_RX_DATA_CRED,	0x0020002000000001);

	/* Init_5 - AIB rx credit init timer register */
	out_be64(p->regs + PHB_AIB_RX_CRED_INIT_TIMER,	0x0f00000000000000);

	/* Init_6 - AIB Tag Enable register */
	out_be64(p->regs + PHB_AIB_TAG_ENABLE,		0xffffffff00000000);

	/* Init_7 - TCE Tag Enable register */
	out_be64(p->regs + PHB_TCE_TAG_ENABLE,		0xffffffff00000000);
}

static void phb3_init_ioda2(struct phb3 *p)
{
	/* Init_14 - LSI Source ID */
	out_be64(p->regs + PHB_LSI_SOURCE_ID,
		 SETFIELD(PHB_LSI_SRC_ID, 0ul, 0xff));

	/* Init_15 - IVT BAR / Length
	 * Init_16 - RBA BAR
	 * 	   - RTT BAR
	 * Init_17 - PELT-V BAR
	 */
	out_be64(p->regs + PHB_RTT_BAR,
		 p->tbl_rtt | PHB_RTT_BAR_ENABLE);
	out_be64(p->regs + PHB_PELTV_BAR,
		 p->tbl_peltv | PHB_PELTV_BAR_ENABLE);
	out_be64(p->regs + PHB_IVT_BAR,
		 p->tbl_ivt | 0x800 | PHB_IVT_BAR_ENABLE);
	out_be64(p->regs + PHB_RBA_BAR,
		 p->tbl_rba | PHB_RBA_BAR_ENABLE);

	/* Init_18..21 - Setup M32 */
	out_be64(p->regs + PHB_M32_BASE_ADDR, p->m32_base);
	out_be64(p->regs + PHB_M32_BASE_MASK, ~(M32_PCI_SIZE - 1));
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_22 - Setup PEST BAR */
	out_be64(p->regs + PHB_PEST_BAR,
		 p->tbl_pest | PHB_PEST_BAR_ENABLE);

	/* Init_23 - PCIE Outbound upper address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_24 - Interrupt represent timers */
	out_be64(p->regs + PHB_INTREP_TIMER, 0);

	/* Init_25 - PHB3 Configuration Register. Clear TCE cache then
	 *           configure the PHB
	 */
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64B_TCE_EN);
	out_be64(p->regs + PHB_PHB3_CONFIG,
		 PHB_PHB3C_M32_EN | PHB_PHB3C_32BIT_MSI_EN |
		 PHB_PHB3C_64BIT_MSI_EN);

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
	out_be64(p->regs + UTL_SYS_BUS_AGENT_ERR_SEVERITY, 0x5000000000000000);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_IRQ_EN,       0xfcc0000000000000);

	/* Init_80..81: Setup tag allocations */
	out_be64(p->regs + UTL_PCIE_TAGS_ALLOC,            0x0800000000000000);
	out_be64(p->regs + UTL_GBIF_READ_TAGS_ALLOC,       0x2000000000000000);

	/* Init_82: PCI Express port control */
	out_be64(p->regs + UTL_PCIE_PORT_CONTROL,          0x8588006000000000);

	/* Init_83..85: Clean & setup port errors */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,           0xffdfffffffffffff);
	out_be64(p->regs + UTL_PCIE_PORT_ERROR_SEV,        0x5289500000000000);

	if (p->has_link)
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xffdbf80000000000);
	else
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xffc3f80000000000);

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
	out_be64(p->regs + PHB_ERR_FREEZE_ENABLE,	   0x0000000000800000);
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,	   0xffffffdd0c00ffc0);
	out_be64(p->regs + PHB_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR_STATUS_MASK,		   0x0000000000000000);
	out_be64(p->regs + PHB_ERR1_STATUS_MASK,	   0x0000000000000000);

	/* Init_98_106: Configure MMIO error traps & clear old state
	 *
	 * Don't enable BAR multi-hit detection
	 */
	out_be64(p->regs + PHB_OUT_ERR_STATUS,		   0xffffffffffffffff);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_LEM_ENABLE,	   0xfdffffffffAfffff);
	out_be64(p->regs + PHB_OUT_ERR_FREEZE_ENABLE,	   0x0000420800000000);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9cf3bc00f89c700f);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1,		   0x0000000000000000);
	out_be64(p->regs + PHB_OUT_ERR_STATUS_MASK,	   0x0000000000400000);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS_MASK,	   0x0000000000400000);

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
#ifdef IVT_TABLE_IVE_16B
	out_be64(p->regs + PHB_CONTROL, 	       	   0xf3a80f4b00000000);
#else
	out_be64(p->regs + PHB_CONTROL, 	       	   0xf3a80fcb00000000);
#endif
	/* Init_88..128  : Setup error registers */
	phb3_init_errors(p);

	/* Init_129: Read error summary */
	val = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (val) {
		PHBERR(p, "Errors detected during PHB init: 0x%16llx\n", val);
		goto failed;
	}

	/* NOTE: At this point the spec waits for the link to come up. We
	 * don't bother as we are doing a PERST soon.
	 */

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

	/* TBD: Should we mask any of these for PERST ? */
	out_be64(p->regs + PHB_ERR_IRQ_ENABLE,	   0x0000002280b80000);
	out_be64(p->regs + PHB_OUT_ERR_IRQ_ENABLE, 0x600c42fc042080f0);
	out_be64(p->regs + PHB_INA_ERR_IRQ_ENABLE, 0xc000a3a901826020);
	out_be64(p->regs + PHB_INB_ERR_IRQ_ENABLE, 0x0000600000800070);
	out_be64(p->regs + PHB_LEM_ERROR_MASK,	   0x42498e327f502eae);

	/* Init_141 - Enable DMA address speculation */
	out_be64(p->regs + PHB_TCE_SPEC_CTL,		   0xf000000000000000);

	/* Init_142 - PHB3 - Timeout Control Register 1 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL1,		   0x1111112016200000);

	/* Init_143 - PHB3 - Timeout Control Register 2 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL2,		   0x2320d10b00000000);

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

	p->tbl_rba = (uint64_t)memalign(RBA_TABLE_SIZE, RBA_TABLE_SIZE);
	assert(p->tbl_rba);
	memset((void *)p->tbl_rba, 0, RBA_TABLE_SIZE);
}

static void phb3_add_properties(struct phb3 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t lsibase, icsp = get_ics_phandle();
	uint64_t m32b, m64b, reg, tkill;

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
	m32b = cleanup_addr(p->m32_base + PHB_M32_OFFSET);
	m64b = cleanup_addr(p->m64_base);
	dt_add_property_cells(np, "ranges",
			      /* M32 space */
			      0x02000000, 0x00000000, M32_PCI_START,
			      hi32(m32b), lo32(m32b), 0, M32_PCI_SIZE - 0x10000);

	/* XXX FIXME: add opal-memwin32, dmawins, etc... */
	dt_add_property_cells(np, "ibm,opal-m64-window",
			      hi32(m64b), lo32(m64b),
			      hi32(m64b), lo32(m64b),
			      hi32(PHB_M64_SIZE), lo32(PHB_M64_SIZE));
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

	/* Indicators for variable tables */
	dt_add_property_cells(np, "ibm,opal-rtt-table",
		hi32(p->tbl_rtt), lo32(p->tbl_rtt), RTT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-peltv-table",
		hi32(p->tbl_peltv), lo32(p->tbl_peltv), PELTV_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-pest-table",
		hi32(p->tbl_pest), lo32(p->tbl_pest), PEST_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-ivt-table",
		hi32(p->tbl_ivt), lo32(p->tbl_ivt), IVT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-ive-stride",
		IVT_TABLE_STRIDE);
	dt_add_property_cells(np, "ibm,opal-rba-table",
		hi32(p->tbl_rba), lo32(p->tbl_rba), RBA_TABLE_SIZE);
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
	p->m32_base = p->mm_base + M32_PCI_START;
	p->m64_base = p->mm_base + PHB_M64_OFFSET;

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

	/* Check if we can use the A/B detect pins */
	p->use_ab_detect = dt_has_node_property(np, "ibm,use-ab-detect", NULL);

	/* Hello ! */
	path = dt_get_path(np);
	printf("PHB3: Found %s @%p MMIO [0x%016llx..0x%016llx]\n",
	       path, p->regs, p->mm_base, p->mm_base + p->mm_size - 1);
	printf("      M32 [0x%016llx..0x%016llx]\n",
	       p->m32_base, p->m32_base + M32_PCI_SIZE - 1);
	printf("      M64 [0x%016llx..0x%016llx]\n",
	       p->m64_base, p->m64_base + PHB_M64_SIZE - 1);
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

static void phb3_probe_pbcq(struct dt_node *pbcq)
{
	uint32_t spci_xscom, pci_xscom, pe_xscom, gcid, pno;
	uint64_t val, phb_bar, mmio_bar, mmio_bmask, mmio_sz;
	uint64_t reg[2];
	struct dt_node *np;
	char *path;

	gcid = dt_prop_get_u32(pbcq->parent, "ibm,chip-id");
	pno = dt_prop_get_u32(pbcq, "ibm,phb-index");
	path = dt_get_path(pbcq);
	printf("Chip %d Found PBCQ%d at %s\n", gcid, pno, path);
	free(path);

	pe_xscom = dt_get_address(pbcq, 0, NULL);
	pci_xscom = dt_get_address(pbcq, 1, NULL);
	spci_xscom = dt_get_address(pbcq, 2, NULL);
	printf("PHB3[%d:%d]: X[PE]=0x%08x X[PCI]=0x%08x X[SPCI]=0x%08x\n",
	       gcid, pno, pe_xscom, pci_xscom, spci_xscom);

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
	val >>= 14;
	printf("PHB3[%d:%d] PCIBAR = 0x%016llx\n", gcid, pno, val);
	if (phb_bar != val) {
		prerror("PHB3[%d:%d] PCIBAR invalid, fixing up...\n",
			gcid, pno);
		xscom_write(gcid, pci_xscom + 0x0b, phb_bar << 14);
	}

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

	/* Create PHB node */
	reg[0] = phb_bar;
	reg[1] = 0x1000;

	np = dt_new_addr(dt_root, "pciex", reg[0]);
	dt_add_property_strings(np, "compatible", "ibm,power8-pciex",
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
	dt_add_property_cells(np, "ibm,pbcq", pbcq->phandle);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	if (dt_has_node_property(pbcq, "ibm,use-ab-detect", NULL))
		dt_add_property(np, "ibm,use-ab-detect", NULL, 0);
}

void probe_phb3(void)
{
	struct dt_node *np;

	/* Look for PBCQ XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-pbcq")
		phb3_probe_pbcq(np);

	/* Look for newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-pciex")
		phb3_create(np);
}
