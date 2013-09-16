/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <device.h>
#include "spira.h"
#include <cpu.h>
#include <memory.h>
#include <vpd.h>
#include <interrupts.h>
#include <ccan/str/str.h>
#include <chip.h>

#include "hdata.h"

/* Processor Initialization structure, contains
 * the initial NIA and MSR values for the entry
 * point
 *
 * Note: It appears to be ignoring the entry point
 *       and always going to 0x180
 */

static int cpu_type;

__section(".procin.data") struct proc_init_data proc_init_data = {
	.hdr = HDIF_SIMPLE_HDR("PROCIN", 1, struct proc_init_data),
	.regs_ptr = HDIF_IDATA_PTR(offsetof(struct proc_init_data, regs), 0x10),
	.regs = {
		.nia = CPU_TO_BE64(0x180),
		.msr = CPU_TO_BE64(0x9000000000000000ULL), /* SF | HV */
	},
};

/* SP Interface Root Array, aka SPIRA */
__section(".spira.data") struct spira spira = {
	.hdr = HDIF_SIMPLE_HDR("SPIRA ", SPIRA_VERSION, struct spira),
	.ntuples_ptr = HDIF_IDATA_PTR(offsetof(struct spira, ntuples),
				      sizeof(struct spira_ntuples)),
	.ntuples = {
		.array_hdr = {
			.offset		= CPU_TO_BE32(HDIF_ARRAY_OFFSET),
			.ecnt		= CPU_TO_BE32(SPIRA_NTUPLES_COUNT),
			.esize
				= CPU_TO_BE32(sizeof(struct spira_ntuple)),
			.eactsz		= CPU_TO_BE32(0x18),
		},
		/* We only populate some n-tuples */
		.proc_init = {
			.addr  		= CPU_TO_BE64(PROCIN_OFF),
			.alloc_cnt	= CPU_TO_BE16(1),
			.act_cnt	= CPU_TO_BE16(1),
			.alloc_len
			= CPU_TO_BE32(sizeof(struct proc_init_data)),
		},
		.heap = {
			.addr		= CPU_TO_BE64(SPIRA_HEAP_BASE),
			.alloc_cnt	= CPU_TO_BE16(1),
			.alloc_len	= CPU_TO_BE32(SPIRA_HEAP_SIZE),
		},
	},
};

/* Overridden for testing. */
#ifndef spira_check_ptr
bool spira_check_ptr(const void *ptr, const char *file, unsigned int line)
{
	if (!ptr)
		return false;
	if (((unsigned long)ptr) >= SPIRA_HEAP_BASE &&
	    ((unsigned long)ptr) < (SPIRA_HEAP_BASE + SPIRA_HEAP_SIZE))
		return true;

	prerror("SPIRA: Bad pointer %p at %s line %d\n", ptr, file, line);
	return false;
}
#endif

struct HDIF_common_hdr *__get_hdif(struct spira_ntuple *n, const char id[],
				   const char *file, int line)
{
	struct HDIF_common_hdr *h = ntuple_addr(n);
	if (!spira_check_ptr(h, file, line))
		return NULL;

	if (!HDIF_check(h, id)) {
		prerror("SPIRA: bad tuple %p: expected %s at %s line %d\n",
			h, id, file, line);
		return NULL;
	}
	return h;
}

static struct dt_node *add_xscom_node(uint64_t base, uint32_t hw_id,
				      uint32_t proc_chip_id)
{
	struct dt_node *node;
	uint64_t addr, size;

	addr = base | ((uint64_t)hw_id << PPC_BITLSHIFT(28));
	size = (u64)1 << PPC_BITLSHIFT(28);

	printf("XSCOM: Found HW ID 0x%x (PCID 0x%x) @ 0x%llx\n",
	       hw_id, proc_chip_id, (long long)addr);

	node = dt_new_addr(dt_root, "xscom", addr);
	dt_add_property_cells(node, "ibm,chip-id", hw_id);
	dt_add_property_cells(node, "ibm,proc-chip-id", proc_chip_id);
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 1);
	dt_add_property(node, "scom-controller", NULL, 0);

	switch(proc_gen) {
	case proc_gen_p7:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power7-xscom");
		break;
	case proc_gen_p8:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power8-xscom");
		break;
	default:
		dt_add_property_strings(node, "compatible", "ibm,xscom");
	}
	dt_add_property_u64s(node, "reg", addr, size);

	return node;
}

struct dt_node *find_xscom_for_chip(uint32_t chip_id)
{
	struct dt_node *node;
	uint32_t id;

	dt_for_each_compatible(dt_root, node, "ibm,xscom") {
		id = dt_get_chip_id(node);
		if (id == chip_id)
			return node;
	}

	return NULL;
}

static void add_psihb_node(struct dt_node *np)
{
	u32 psi_scom, psi_slen;
	const char *psi_comp;

	/*
	 * We add a few things under XSCOM that aren't added
	 * by any other HDAT path
	 */

	/* PSI host bridge */
	switch(proc_gen) {
	case proc_gen_p7:
		psi_scom = 0x2010c00;
		psi_slen = 0x10;
		psi_comp = "ibm,power7-psihb-x";
		break;
	case proc_gen_p8:
		psi_scom = 0x2010900;
		psi_slen = 0x20;
		psi_comp = "ibm,power8-psihb-x";
		break;
	default:
		psi_comp = NULL;
	}
	if (psi_comp) {
		struct dt_node *psi_np;

		psi_np = dt_new_addr(np, "psihb", psi_scom);
		dt_add_property_cells(psi_np, "reg", psi_scom, psi_slen);
		dt_add_property_strings(psi_np, "compatible", psi_comp,
					"ibm,psihb-x");
	}
}

static bool add_xscom_sppcrd(uint64_t xscom_base)
{
	struct HDIF_common_hdr *hdif;
	unsigned int i, vpd_sz;
	const void *vpd;
	struct dt_node *np;

	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		u32 ve, version;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("XSCOM: Bad ChipID data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		/* Create the XSCOM node */
		np = add_xscom_node(xscom_base,
				    be32_to_cpu(cinfo->xscom_id),
				    be32_to_cpu(cinfo->proc_chip_id));
		if (!np)
			continue;

		version = be16_to_cpu(hdif->version);

		/* Version 0A has additional OCC related stuff */
		if (version >= 0x000a) {
			dt_add_property_cells(np, "ibm,dbob-id",
					      be32_to_cpu(cinfo->dbob_id));
			dt_add_property_cells(np, "ibm,occ-functional-state",
					      be32_to_cpu(cinfo->occ_state));
		}

		/* Add chip VPD */
		vpd = HDIF_get_idata(hdif, SPPCRD_IDATA_KW_VPD, &vpd_sz);
		if (CHECK_SPPTR(vpd))
			dt_add_property(np, "ibm,chip-vpd", vpd, vpd_sz);

		/* Add module VPD on version A and later */
		if (version >= 0x000a) {
			vpd = HDIF_get_idata(hdif, SPPCRD_IDATA_MODULE_VPD,
					     &vpd_sz);
			if (CHECK_SPPTR(vpd))
				dt_add_property(np, "ibm,module-vpd", vpd,
						vpd_sz);
		}

		/* Add PSI Host bridge */
		add_psihb_node(np);
	}

	return i > 0;
}

static void add_xscom_sppaca(uint64_t xscom_base)
{
	struct HDIF_common_hdr *hdif;
	unsigned int i, vpd_sz;
	const void *vpd;
	struct dt_node *np;

	for_each_ntuple_idx(&spira.ntuples.paca, hdif, i, PACA_HDIF_SIG) {
		const struct sppaca_cpu_id *id;
		unsigned int chip_id;
		int ve;

		/* We only suport old style PACA on P7 ! */
		assert(proc_gen == proc_gen_p7);

		id = HDIF_get_idata(hdif, SPPACA_IDATA_CPU_ID, NULL);

		if (!CHECK_SPPTR(id)) {
			prerror("XSCOM: Bad processor data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(id->verify_exists_flags) & CPU_ID_VERIFY_MASK;
		ve >>= CPU_ID_VERIFY_SHIFT;
		if (ve == CPU_ID_VERIFY_NOT_INSTALLED ||
		    ve == CPU_ID_VERIFY_UNUSABLE)
			continue;

		/* Convert to HW chip ID */
		chip_id = P7_PIR2GCID(be32_to_cpu(id->pir));

		/* do we already have an XSCOM for this chip? */
		if (find_xscom_for_chip(chip_id))
			continue;

		/* Create the XSCOM node */
		np = add_xscom_node(xscom_base, chip_id,
				    be32_to_cpu(id->processor_chip_id));

		/* Add chip VPD */
		vpd = HDIF_get_idata(hdif, SPPACA_IDATA_KW_VPD, &vpd_sz);
		if (CHECK_SPPTR(vpd))
			dt_add_property(np, "ibm,chip-vpd", vpd, vpd_sz);

		/* Add PSI Host bridge */
		add_psihb_node(np);
	}
}

static void add_xscom(void)
{
	const void *ms_vpd;
	const struct msvpd_pmover_bsr_synchro *pmbs;
	unsigned int size;
	uint64_t xscom_base;

	ms_vpd = get_hdif(&spira.ntuples.ms_vpd, MSVPD_HDIF_SIG);
	if (!ms_vpd) {
		prerror("XSCOM: Can't find MS VPD\n");
		return;
	}

	pmbs = HDIF_get_idata(ms_vpd, MSVPD_IDATA_PMOVER_SYNCHRO, &size);
	if (!CHECK_SPPTR(pmbs) || size < sizeof(*pmbs)) {
		prerror("XSCOM: absent or bad PMBS size %u @ %p\n", size, pmbs);
		return;
	}

	if (!(be32_to_cpu(pmbs->flags) & MSVPD_PMS_FLAG_XSCOMBASE_VALID)) {
		prerror("XSCOM: No XSCOM base in PMBS, using default\n");
		return;
	}

	xscom_base = be64_to_cpu(pmbs->xscom_addr);

	/* Some FSP (on P7) give me a crap base address for XSCOM (it has
	 * spurious bits set as far as I can tell). Since only 5 bits 18:22 can
	 * be programmed in hardware, let's isolate these. This seems to give
	 * me the right value on VPL1
	 */
	if (cpu_type == PVR_TYPE_P7)
		xscom_base &= 0x80003e0000000000ul;

	/* Get rid of the top bits */
	xscom_base = cleanup_addr(xscom_base);

	/* First, try the new proc_chip ntuples for chip data */
	if (add_xscom_sppcrd(xscom_base))
		return;

	/* Otherwise, check the old-style PACA, looking for unique chips */
	add_xscom_sppaca(xscom_base);
}

static void add_chiptod_node(unsigned int chip_id, int flags)
{
	struct dt_node *node, *xscom_node;
	const char *compat_str;
	uint32_t addr, len;

	if ((flags & CHIPTOD_ID_FLAGS_STATUS_MASK) !=
			CHIPTOD_ID_FLAGS_STATUS_OK)
		return;

	xscom_node = find_xscom_for_chip(chip_id);
	if (!xscom_node) {
		prerror("CHIPTOD: No xscom for chiptod %d?\n", chip_id);
		return;
	}

	addr = 0x40000;
	len = 0x34;

	switch(proc_gen) {
	case proc_gen_p7:
		compat_str = "ibm,power7-chiptod";
		break;
	case proc_gen_p8:
		compat_str = "ibm,power8-chiptod";
		break;
	default:
		return;
	}

	node = dt_new_addr(xscom_node, "chiptod", addr);
	dt_add_property_cells(node, "reg", addr, len);
	dt_add_property_strings(node, "compatible", "ibm,power-chiptod",
			       compat_str);

	if (flags & CHIPTOD_ID_FLAGS_PRIMARY)
		dt_add_property(node, "primary", NULL, 0);
	if (flags & CHIPTOD_ID_FLAGS_SECONDARY)
		dt_add_property(node, "secondary", NULL, 0);
}

static void add_chiptod_old(void)
{
	const void *hdif;
	unsigned int i;

	/*
	 * Locate chiptod ID structures in SPIRA
	 */
	if (!get_hdif(&spira.ntuples.chip_tod, "TOD   ")) {
		prerror("CHIPTOD: Cannot locate old style SPIRA TOD info\n");
		return;
	}

	for_each_ntuple_idx(&spira.ntuples.chip_tod, hdif, i, "TOD   ") {
		const struct chiptod_chipid *id;

		id = HDIF_get_idata(hdif, CHIPTOD_IDATA_CHIPID, NULL);
		if (!CHECK_SPPTR(id)) {
			prerror("CHIPTOD: Bad ChipID data %d\n", i);
			continue;
		}

		add_chiptod_node(pcid_to_chip_id(be32_to_cpu(id->chip_id)),
				 be32_to_cpu(id->flags));
	}
}

static void add_chiptod_new(uint32_t master_cpu)
{
	const void *hdif;
	unsigned int i, master_chip;

	/*
	 * Locate Proc Chip ID structures in SPIRA
	 */
	if (!get_hdif(&spira.ntuples.proc_chip, SPPCRD_HDIF_SIG)) {
		prerror("CHIPTOD: Cannot locate new style SPIRA TOD info\n");
		return;
	}

	master_chip = pir_to_chip_id(master_cpu);

	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		const struct sppcrd_chip_tod *tinfo;
		unsigned int size;
		u32 ve, flags;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("CHIPTOD: Bad ChipID data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		tinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_TOD, &size);
		if (!CHECK_SPPTR(tinfo)) {
			prerror("CHIPTOD: Bad TOD data %d\n", i);
			continue;
		}

		flags = be32_to_cpu(tinfo->flags);

		/* The FSP may strip the chiptod info from HDAT; if we find
		 * a zero-ed out entry, assume that the chiptod is
		 * present, but we don't have any primary/secondary info. In
		 * this case, pick the primary based on the CPU that was
		 * assigned master.
		 */
		if (!size) {
			flags = CHIPTOD_ID_FLAGS_STATUS_OK;
			if (be32_to_cpu(cinfo->xscom_id) == master_chip)
				flags |= CHIPTOD_ID_FLAGS_PRIMARY;
		}

		add_chiptod_node(be32_to_cpu(cinfo->xscom_id), flags);
	}
}

static void add_nx_node(u32 gcid)
{
	struct dt_node *nx;
	const char *cp_str;
	u32 addr;
	u32 size;
	struct dt_node *xscom;

	xscom = find_xscom_for_chip(gcid);
	if (xscom == NULL) {
		prerror("NX%d: did not found xscom node.\n", gcid);
		return;
	}

	/*
	 * The NX register space is relatively self contained on P7+ but
	 * a bit more messy on P8. However it's all contained within the
	 * PB chiplet port 1 so we'll stick to that in the "reg" property
	 * and let the NX "driver" deal with the details.
	 */
	addr = 0x2010000;
	size = 0x0004000;

	switch (proc_gen) {
	case proc_gen_p7:
		cp_str = "ibm,power7-nx";
		break;
	case proc_gen_p8:
		cp_str = "ibm,power8-nx";
		break;
	default:
		return;
	}
	nx = dt_new_addr(xscom, "nx", addr);

	dt_add_property_cells(nx, "reg", addr, size);
	dt_add_property_strings(nx, "compatible", "ibm,power-nx", cp_str);
}

static void add_nx(void)
{
	unsigned int i;
	void *hdif;

	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		u32 ve;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("NX: Bad ChipID data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
				ve == CHIP_VERIFY_UNUSABLE)
			continue;

		if (cinfo->nx_state)
			add_nx_node(be32_to_cpu(cinfo->xscom_id));
	}
}


static void add_iplparams_sys_params(const void *iplp, struct dt_node *node)
{
	const struct iplparams_sysparams *p;

	p = HDIF_get_idata(iplp, IPLPARAMS_SYSPARAMS, NULL);
	if (!CHECK_SPPTR(p)) {
		prerror("IPLPARAMS: No SYS Parameters\n");
		return;
	}

	node = dt_new(node, "sys-params");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 0);
	dt_add_property_cells(node, "#size-cells", 0);

	dt_add_property_nstr(node, "ibm,sys-model", p->sys_model, 4);

	/* XXX Add many more */
}

static void add_iplparams_ipl_params(const void *iplp, struct dt_node *node)
{
	const struct iplparams_iplparams *p;

	p = HDIF_get_idata(iplp, IPLPARAMS_IPLPARAMS, NULL);
	if (!CHECK_SPPTR(p)) {
		prerror("IPLPARAMS: No IPL Parameters\n");
		return;
	}

	node = dt_new(node, "ipl-params");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 0);
	dt_add_property_cells(node, "#size-cells", 0);

	dt_add_property_strings(node, "cec-ipl-side",
				(p->ipl_side & IPLPARAMS_CEC_FW_IPL_SIDE_TEMP) ?
				"temp" : "perm");
	dt_add_property_strings(node, "fsp-ipl-side",
				(p->ipl_side & IPLPARAMS_FSP_FW_IPL_SIDE_TEMP) ?
				"temp" : "perm");
	dt_add_property_cells(node, "os-ipl-mode", p->os_ipl_mode);

	/* XXX Add many more */
}

static void add_iplparams_serials(const void *iplp, struct dt_node *node)
{
	const struct iplparms_serial *ipser;
	struct dt_node *ser_node;
	int count, i;
	
	count = HDIF_get_iarray_size(iplp, IPLPARMS_IDATA_SERIAL);
	if (!count) {
		prerror("IPLPARAMS: No serial ports\n");
		return;
	}
	prerror("IPLPARAMS: %d serial ports in array\n", count);

	node = dt_new(node, "fsp-serial");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 0);

	for (i = 0; i < count; i++) {
		u16 rsrc_id;
		ipser = HDIF_get_iarray_item(iplp, IPLPARMS_IDATA_SERIAL,
					     i, NULL);
		if (!CHECK_SPPTR(ipser))
			continue;
		rsrc_id = be16_to_cpu(ipser->rsrc_id);
		printf("IPLPARAMS: Serial %d rsrc: %04x loc: %s\n",
		       i, rsrc_id, ipser->loc_code);
		ser_node = dt_new_addr(node, "serial", rsrc_id);
		dt_add_property_cells(ser_node, "reg", rsrc_id);
		dt_add_property_nstr(ser_node, "ibm,loc-code",
				     ipser->loc_code, 80);
		dt_add_property_string(ser_node, "compatible",
				       "ibm,fsp-serial");
		/* XXX handle CALLHOME flag ? */
	}
}

static void add_iplparams(void)
{
	struct dt_node *iplp_node;
	const void *ipl_parms;

	ipl_parms = get_hdif(&spira.ntuples.ipl_parms, "IPLPMS");
	if (!ipl_parms) {
		prerror("IPLPARAMS: Cannot find IPL Parms in SPIRA\n");
		return;
	}

	iplp_node = dt_new(dt_root, "ipl-params");
	assert(iplp_node);
	dt_add_property_cells(iplp_node, "#address-cells", 0);
	dt_add_property_cells(iplp_node, "#size-cells", 0);

	add_iplparams_sys_params(ipl_parms, iplp_node);
	add_iplparams_ipl_params(ipl_parms, iplp_node);
	add_iplparams_serials(ipl_parms, iplp_node);
}

/* Various structure contain a "proc_chip_id" which is an arbitrary
 * numbering used by HDAT to reference chips, which doesn't correspond
 * to the HW IDs. We want to use the HW IDs everywhere in the DT so
 * we convert using this.
 *
 * Note: On P7, the HW ID is the XSCOM "GCID" including the T bit which
 * is *different* from the chip ID portion of the interrupt server#
 * (or PIR). See the explanations in chip.h
 */
uint32_t pcid_to_chip_id(uint32_t proc_chip_id)
{
	unsigned int i;
	const void *hdif;

	/* First, try the proc_chip ntuples for chip data */
	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO,
						NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("XSCOM: Bad ChipID data %d\n", i);
			continue;
		}
		if (proc_chip_id == be32_to_cpu(cinfo->proc_chip_id))
			return be32_to_cpu(cinfo->xscom_id);
	}

	/* Otherwise, check the old-style PACA, looking for unique chips */
	for_each_ntuple_idx(&spira.ntuples.paca, hdif, i, PACA_HDIF_SIG) {
		const struct sppaca_cpu_id *id;

		/* We only suport old style PACA on P7 ! */
		assert(proc_gen == proc_gen_p7);

		id = HDIF_get_idata(hdif, SPPACA_IDATA_CPU_ID, NULL);

		if (!CHECK_SPPTR(id)) {
			prerror("XSCOM: Bad processor data %d\n", i);
			continue;
		}

		if (proc_chip_id == be32_to_cpu(id->processor_chip_id))
			return P7_PIR2GCID(be32_to_cpu(id->pir));
	}

	/* Not found, what to do ? Assert ? For now return a number
	 * guaranteed to not exist
	 */
	return (uint32_t)-1;
}

void parse_hdat(bool is_opal, uint32_t master_cpu)
{
	struct dt_node *ics;

	cpu_type = PVR_TYPE(mfspr(SPR_PVR));

	printf("\n");
	printf("-----------------------------------------------\n");
	printf("-------------- Parsing HDAT ... ---------------\n");
	printf("-----------------------------------------------\n");
	printf("\n");

	dt_root = dt_new_root("");

	/*
	 * Basic DT root stuff
	 */
	dt_add_property_string(dt_root, "compatible", "ibm,powernv");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);
	dt_add_property_string(dt_root, "lid-type", is_opal ? "opal" : "phyp");

	/* Parse SPPACA and/or PCIA */
	if (!pcia_parse())
		paca_parse();

	/* IPL params */
	add_iplparams();

	/* Get model property based on System VPD */
	sysvpd_parse();

	/* Parse MS VPD */
	memory_parse();

	/* Add XICS nodes */
	ics = add_ics_node();

	/* Add XSCOM node (must be before chiptod & IO ) */
	add_xscom();

	/* Add FSP */
	fsp_parse();

	/* Add ChipTOD's */
	add_chiptod_old();
	add_chiptod_new(master_cpu);

	/* Add NX */
	add_nx();

	/* Add IO HUBs and/or PHBs */
	io_parse(ics);

	printf("\n");
	printf("-----------------------------------------------\n");
	printf("\n");
}
