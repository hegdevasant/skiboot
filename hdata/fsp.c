/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <device.h>
#include <spira.h>
#include <cpu.h>
#include <memory.h>
#include <vpd.h>
#include <ccan/str/str.h>
#include <device_tree.h>
#include <interrupts.h>

#include "hdata.h"

static struct dt_node *fsp_create_node(const void *spss, int i,
				       struct dt_node *parent)
{
	const struct spss_sp_impl *sp_impl;
	struct dt_node *node;
	unsigned int mask;

	/* Find an check the SP Implementation structure */
	sp_impl = HDIF_get_idata(spss, SPSS_IDATA_SP_IMPL, NULL);
	if (!CHECK_SPPTR(sp_impl)) {
		prerror("FSP #%d: SPSS/SP_Implementation not found !\n", i);
		return NULL;
	}

	printf("FSP #%d: FSP HW version %d, SW version %d, chip DD%d.%d\n",
	       i, sp_impl->hw_version, sp_impl->sw_version,
	       sp_impl->chip_version >> 4, sp_impl->chip_version & 0xf);
	mask = SPSS_SP_IMPL_FLAGS_INSTALLED | SPSS_SP_IMPL_FLAGS_FUNCTIONAL;
	if ((sp_impl->func_flags & mask) != mask) {
		prerror("FSP #%d: FSP not installed or not functional\n", i);
		return NULL;
	}

	node = dt_new_addr(parent, "fsp", i);
	assert(node);
	dt_add_property_cells(node, "reg", i);

	if (sp_impl->hw_version == 1) {
		dt_add_property_strings(node, "compatible", "ibm,fsp1");
		/* Offset into the FSP MMIO space where the mailbox registers are */
		/* seen in the FSP1 spec */
		dt_add_property_cells(node, "reg-offset", 0xb0016000);
	} else if (sp_impl->hw_version == 2) {
		dt_add_property_strings(node, "compatible", "ibm,fsp2");
		dt_add_property_cells(node, "reg-offset", 0xb0011000);
	}
	dt_add_property_cells(node, "hw-version", sp_impl->hw_version);
	dt_add_property_cells(node, "sw-version", sp_impl->sw_version);

	if (sp_impl->func_flags & SPSS_SP_IMPL_FLAGS_PRIMARY)
		dt_add_property(node, "primary", NULL, 0);

	return node;
}

struct dt_node *fsp_create_link(const struct spss_iopath *iopath, int index,
				int fsp_index)
{
	struct dt_node *node;
	const char *ststr;
	bool current = false;
	bool working = false;
	uint32_t chip_id;
	uint64_t addr;

	switch(iopath->psi.link_status) {
	case SPSS_IO_PATH_PSI_LINK_BAD_FRU:
		ststr = "Broken";
		break;
	case SPSS_IO_PATH_PSI_LINK_CURRENT:
		ststr = "Active";
		current = working = true;
		break;
	case SPSS_IO_PATH_PSI_LINK_BACKUP:
		ststr = "Backup";
		working = true;
		break;
	default:
		ststr = "Unknown";
	}
	printf("FSP #%d: IO PATH %d is %s PSI Link, GXHB at %llx\n",
	       fsp_index, index, ststr, iopath->psi.gxhb_base);

	addr = cleanup_addr(iopath->psi.gxhb_base);
	chip_id = pcid_to_chip_id(iopath->psi.proc_chip_id);

	node = dt_new_addr(dt_root, "psi", addr);
	assert(node);

	/* XXX Read PSI BAR to determine size ? */
	dt_add_property_cells(node, "reg", hi32(addr), lo32(addr), 1, 0);
	dt_add_property_strings(node, "compatible", "ibm,psi",
				"ibm,power7-psi");
	dt_add_property_cells(node, "interrupt-parent", get_ics_phandle());
	dt_add_property_cells(node, "interrupts", get_psi_interrupt(chip_id));
	dt_add_property_cells(node, "ibm,chip-id", chip_id);
	if (current)
		dt_add_property(node, "current-link", NULL, 0);
	dt_add_property_strings(node, "status", working ? "ok" : "bad");

	return node;
}

static void fsp_create_links(const void *spss, int index, struct dt_node *fsp_node)
{
	uint32_t *links = NULL;
	unsigned int i, lp, lcount = 0;
	int count;

	count = HDIF_get_iarray_size(spss, SPSS_IDATA_SP_IOPATH);
	if (count < 0) {
		prerror("FSP #%d: Can't find IO PATH array size !\n", index);
		return;
	}
	printf("FSP #%d: Found %d IO PATH\n", index, count);

	/* Iterate all links */
	for (i = 0; i < count; i++) {
		const struct spss_iopath *iopath;
		unsigned int iopath_sz;
		struct dt_node *link;

		iopath = HDIF_get_iarray_item(spss, SPSS_IDATA_SP_IOPATH,
					      i, &iopath_sz);
		if (!CHECK_SPPTR(iopath)) {
			prerror("FSP #%d: Can't find IO PATH %d\n", index, i);
			break;
		}
		if (iopath->iopath_type != SPSS_IOPATH_TYPE_PSI) {
			prerror("FSP #%d: Unsupported IO PATH %d type 0x%04x\n",
				index, i, iopath->iopath_type);
			continue;
		}

		link = fsp_create_link(iopath, i, index);
		if (!link)
			continue;
		lp = lcount++;
		links = realloc(links, 4 * lcount);
		links[lp] = link->phandle;
	}
	if (links)
		dt_add_property(fsp_node, "links", links, lcount * 4);
}

void fsp_parse(void)
{
	const void *base_spss, *spss;
	struct dt_node *fsp_root, *fsp_node;
	int i;

	/*
	 * Note on DT representation of the PSI links and FSPs:
	 *
	 * We create a node for each functional PSI host bridge. However
	 * we do not put the FSP as children of these. Instead, we create
	 * a top-level /fsps node with the FSPs as children.
	 *
	 * Each FSP then has a "links" property which is an array of
	 * phandles to the corresponding PSI HBs.
	 *
	 * This handles link redudancy better.
	 */
	
	/* Find SPSS in SPIRA */
	base_spss = spira.ntuples.sp_subsys.addr;
	if (!base_spss) {
		printf("FSP: No SPSS in SPIRA !\n");
		return;
	}

	fsp_root = dt_new(dt_root, "fsps");
	assert(fsp_root);
	dt_add_property_cells(fsp_root, "#address-cells", 1);
	dt_add_property_cells(fsp_root, "#size-cells", 0);

	/* Iterate FSPs in SPIRA */
	for_each_ntuple_idx(spira.ntuples.sp_subsys, spss, i) {

		if (!HDIF_check(spss, SPSS_HDIF_SIG)) {
			prerror("FSP #%d: SPSS signature mismatch !\n", i);
			continue;
		}

		fsp_node = fsp_create_node(spss, i, fsp_root);
		if (fsp_node)
			fsp_create_links(spss, i, fsp_node);
	}	
}

