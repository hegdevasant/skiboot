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

static struct proc_init_data proc_init_data = {
	.hdr = HDIF_SIMPLE_HDR("PROCIN", 1, struct proc_init_data),
	.regs_ptr = {
		.offset	= offsetof(struct proc_init_data, regs),
		.size	= 0x10,
	},
	.regs = {
		.nia	= 0x180,
		.msr  	= 0x9000000000000000, /* SF | HV */
	},
};

/* SP Interface Root Array, aka SPIRA */
struct spira spira = {
	.hdr = HDIF_SIMPLE_HDR("SPIRA ", SPIRA_VERSION, struct spira),
	.ntuples_ptr = {
		.offset			= offsetof(struct spira, ntuples),
		.size			= sizeof(struct spira_ntuples),
	},
	.ntuples = {
		.array_hdr = {
			.offset		= HDIF_ARRAY_OFFSET,
			.ecnt		= SPIRA_NTUPLES_COUNT,
			.esize		= sizeof(struct spira_ntuple),
			.eactsz		= 0x18,
		},
		/* We only populate some n-tuples */
		.proc_init = {
			.addr  		= &proc_init_data,
			.alloc_cnt	= 1,
			.act_cnt	= 1,
			.alloc_len	= sizeof(struct proc_init_data),
		},
		.heap = {
			.addr		= (void *)SPIRA_HEAP_BASE,
			.alloc_cnt	= 1,
			.alloc_len	= SPIRA_HEAP_SIZE,
		},
	},
};

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

struct HDIF_common_hdr *__get_hdif(struct spira_ntuple *n, const char id[],
				   const char *file, int line)
{
	struct HDIF_common_hdr *h = n->addr;
	if (!spira_check_ptr(h, file, line))
		return NULL;

	if (!HDIF_check(h, id)) {
		prerror("SPIRA: bad tuple %p: expected %s at %s line %d\n",
			h, id, file, line);
		return NULL;
	}
	return h;
}

static void add_xscom_node(uint64_t base, uint32_t id)
{
	struct dt_node *node;
	uint64_t addr, size;

	addr = base | ((uint64_t)id << PPC_BITLSHIFT(28));
	size = 1ul << PPC_BITLSHIFT(28);

	printf("XSCOM: Found gcid 0x%x, address: 0x%llx\n", id, addr);

	node = dt_new_addr(dt_root, "xscom", addr);
	dt_add_property_cells(node, "ibm,chip-id", id);
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 1);

	/* XXX Use boot CPU PVR to decide on XSCOM type... */
	switch(cpu_type) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power7-xscom");
		break;
	case PVR_TYPE_P8:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power8-xscom");
		break;
	default:
		dt_add_property_strings(node, "compatible", "ibm,xscom");
	}
	dt_add_property_cells(node, "reg", hi32(addr), lo32(addr),
					   hi32(size), lo32(size));
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

static void add_xscom(void)
{
	const void *ms_vpd;
	const struct msvpd_pmover_bsr_synchro *pmbs;
	unsigned int size, i;
	uint64_t xscom_base;
	void *hdif;

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

	if (!(pmbs->flags & MSVPD_PMS_FLAG_XSCOMBASE_VALID)) {
		prerror("XSCOM: No XSCOM base in PMBS, using default\n");
		return;
	}

	xscom_base = pmbs->xscom_addr;

	/* Some FSP (on P7) give me a crap base address for XSCOM (it has
	 * spurious bits set as far as I can tell). Since only 5 bits 18:22 can
	 * be programmed in hardware, let's isolate these. This seems to give
	 * me the right value on VPL1
	 */
	if (cpu_type == PVR_TYPE_P7)
		xscom_base &= 0x80003e0000000000ul;

	xscom_base = cleanup_addr(xscom_base);

	/* First, try the proc_chip ntuples for chip data */
	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		u32 ve;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO,
						NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("XSCOM: Bad ChipID data %d\n", i);
			continue;
		}

		ve = cinfo->verif_exist_flags & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		add_xscom_node(xscom_base, cinfo->xscom_id);
	}

	if (i > 0)
		return;

	/* Otherwise, check the old-style PACA, looking for unique chips */
	for_each_ntuple_idx(&spira.ntuples.paca, hdif, i, PACA_HDIF_SIG) {
		const struct sppaca_cpu_id *id;
		unsigned int chip_id;
		int ve;

		/* We only suport old style PACA on P7 ! */
		assert(cpu_type == PVR_TYPE_P7);

		id = HDIF_get_idata(hdif, SPPACA_IDATA_CPU_ID, NULL);

		if (!CHECK_SPPTR(id)) {
			prerror("XSCOM: Bad processor data %d\n", i);
			continue;
		}

		ve = (id->verify_exists_flags & CPU_ID_VERIFY_MASK);
		ve >>= CPU_ID_VERIFY_SHIFT;
		if (ve == CPU_ID_VERIFY_NOT_INSTALLED ||
		    ve == CPU_ID_VERIFY_UNUSABLE)
			continue;

		/* Convert to HW chip ID */
		chip_id = P7_PIR2GCID(id->pir);

		/* do we already have an XSCOM for this chip? */
		if (find_xscom_for_chip(chip_id))
			continue;

		add_xscom_node(xscom_base, chip_id);
	}
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

	switch(cpu_type) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		compat_str = "ibm,power7-chiptod";
		break;
	case PVR_TYPE_P8:
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

		add_chiptod_node(pcid_to_chip_id(id->chip_id), id->flags);
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

		ve = cinfo->verif_exist_flags & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		tinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_TOD, &size);
		if (!CHECK_SPPTR(tinfo)) {
			prerror("CHIPTOD: Bad TOD data %d\n", i);
			continue;
		}

		flags = tinfo->flags;

		/* The FSP may strip the chiptod info from HDAT; if we find
		 * a zero-ed out entry, assume that the chiptod is
		 * present, but we don't have any primary/secondary info. In
		 * this case, pick the primary based on the CPU that was
		 * assigned master.
		 */
		if (!size) {
			flags = CHIPTOD_ID_FLAGS_STATUS_OK;
			if (cinfo->xscom_id == master_chip)
				flags |= CHIPTOD_ID_FLAGS_PRIMARY;
		}

		add_chiptod_node(cinfo->xscom_id, flags);
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
		ipser = HDIF_get_iarray_item(iplp, IPLPARMS_IDATA_SERIAL,
					     i, NULL);
		if (!CHECK_SPPTR(ipser))
			continue;
		printf("IPLPARAMS: Serial %d rsrc: %04x loc: %s\n",
		       i, ipser->rsrc_id, ipser->loc_code);
		ser_node = dt_new_addr(node, "serial", ipser->rsrc_id);
		dt_add_property_cells(ser_node, "reg", ipser->rsrc_id);
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
		if (proc_chip_id == cinfo->proc_chip_id)
			return cinfo->xscom_id;
	}

	/* Otherwise, check the old-style PACA, looking for unique chips */
	for_each_ntuple_idx(&spira.ntuples.paca, hdif, i, PACA_HDIF_SIG) {
		const struct sppaca_cpu_id *id;

		/* We only suport old style PACA on P7 ! */
		assert(cpu_type == PVR_TYPE_P7);

		id = HDIF_get_idata(hdif, SPPACA_IDATA_CPU_ID, NULL);

		if (!CHECK_SPPTR(id)) {
			prerror("XSCOM: Bad processor data %d\n", i);
			continue;
		}

		if (proc_chip_id == id->processor_chip_id)
			return P7_PIR2GCID(id->pir);
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

	/* Add IO HUBs and/or PHBs */
	io_parse(ics);

#if 0 /* Tests */
	{
		struct dt_node *n;

		n = dt_find_by_path(dt_root, "/");
		printf("test / %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus");
		printf("test /cpus %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/PowerPC,POWER7@10");
		printf("test /cpus/PowerPC,POWER7@10 %p [%s]\n",
		       n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/@10");
		printf("test /cpus/@10 %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/@30");
		printf("test /cpus/@30 %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/@15");
		printf("test /cpus/@15 %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/PowerPC,POWER7");
		printf("test /cpus/PowerPC,POWER7 %p [%s]\n",
		       n, dt_get_path(n));
	}
#endif
	printf("\n");
	printf("-----------------------------------------------\n");
	printf("\n");
}
