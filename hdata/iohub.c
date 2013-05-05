/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <device.h>
#include <p5ioc2.h>
#include <p7ioc.h>
#include <vpd.h>

#include "hdata.h"

static void io_add_common(struct dt_node *hn, const struct cechub_io_hub *hub,
			  struct dt_node *ics)
{
	dt_add_property_cells(hn, "#address-cells", 2);
	dt_add_property_cells(hn, "#size-cells", 2);
	dt_add_property_cells(hn, "interrupt-parent", ics->phandle);
	dt_add_property_cells(hn, "ibm,buid-ext", hub->buid_ext);
	dt_add_property_cells(hn, "ibm,chip-id",
			      pcid_to_chip_id(hub->proc_chip_id));
	dt_add_property_cells(hn, "ibm,gx-index", hub->gx_index);
	dt_add_property_cells(hn, "revision", hub->ec_level);

	/* Instead of exposing the GX BARs as separate ranges as we *should*
	 * do in an ideal world, we just create a pass-through ranges and
	 * we use separate properties for the BARs.
	 *
	 * This is hackish but will do for now and avoids us having to
	 * do too complex ranges property parsing
	 */
	dt_add_property(hn, "ranges", NULL, 0);
	dt_add_property_cells(hn, "ibm,gx-bar-1",
			      hi32(hub->gx_ctrl_bar1), lo32(hub->gx_ctrl_bar1));
	dt_add_property_cells(hn, "ibm,gx-bar-2",
			      hi32(hub->gx_ctrl_bar2), lo32(hub->gx_ctrl_bar2));

	/* Add presence detect if valid */
	if (hub->flags & CECHUB_HUB_FLAG_FAB_BR0_PDT)
		dt_add_property_cells(hn, "ibm,br0-presence-detect",
				      hub->fab_br0_pdt);
	if (hub->flags & CECHUB_HUB_FLAG_FAB_BR1_PDT)
		dt_add_property_cells(hn, "ibm,br1-presence-detect",
				      hub->fab_br1_pdt);
}

static struct dt_node *io_add_p5ioc2(const struct cechub_io_hub *hub)
{
	struct dt_node *hn;
	uint64_t reg[2];

	/* We assume SBAR == GX0 + some hard coded offset */
	reg[0] = cleanup_addr(hub->gx_ctrl_bar0 + P5IOC2_REGS_OFFSET);
	reg[1] = 0x2000000;

	hn = dt_new_addr(dt_root, "io-hub", reg[0]);
	dt_add_property(hn, "reg", reg, sizeof(reg));
	dt_add_property_strings(hn, "compatible", "ibm,p5ioc2");

	return hn;
}

static struct dt_node *io_add_p7ioc(const struct cechub_io_hub *hub)
{
	struct dt_node *hn;
	uint64_t reg[2];

	/* We only know about memory map 1 */
	if (hub->mem_map_vers != 1) {
		prerror("P7IOC: Unknown memory map %d\n", hub->mem_map_vers);
		/* We try to continue anyway ... */
	}

	reg[0] = cleanup_addr(hub->gx_ctrl_bar1);
	reg[1] = 0x2000000;

	hn = dt_new_addr(dt_root, "io-hub", reg[0]);
	dt_add_property(hn, "reg", reg, sizeof(reg));
	dt_add_property_strings(hn, "compatible", "ibm,p7ioc", "ibm,ioda-hub");

	return hn;
}

static struct dt_node *io_add_phb3(const struct cechub_io_hub *hub,
				   unsigned int index, struct dt_node *xcom,
				   unsigned int pe_xscom,
				   unsigned int pci_xscom,
				   unsigned int spci_xscom)
{
	struct dt_node *pbcq;
	uint32_t reg[6];

	/* Create PBCQ node under xscom */
	pbcq = dt_new_addr(xcom, "pbcq", pe_xscom);

	/* "reg" property contains in order the PE, PCI and SPCI XSCOM
	 * addresses
	 */
	reg[0] = pe_xscom;
	reg[1] = 0x20;
	reg[2] = pci_xscom;
	reg[3] = 0x05;
	reg[4] = spci_xscom;
	reg[5] = 0x15;
	dt_add_property(pbcq, "reg", reg, sizeof(reg));

	/* A couple more things ... */
	dt_add_property_strings(pbcq, "compatible", "ibm,power8-pbcq");
	dt_add_property_cells(pbcq, "ibm,phb-index", index);

	/* We indicate that this is an IBM setup, which means that
	 * the presence detect A/B bits are meaningful. So far we
	 * don't know whether they make any sense on customer setups
	 * so we only set that when booting with HDAT
	 */
	dt_add_property(pbcq, "ibm,use-ab-detect", NULL, 0);

	/* XXX This is changing in the HDAT spec ... */
	switch(index) {
	case 0:
		dt_add_property_cells(pbcq, "ibm,lane_eq", hub->phb0_lane_eq);
		break;
	case 1:
		dt_add_property_cells(pbcq, "ibm,lane_eq", hub->phb1_lane_eq);
		break;
	case 2:
		dt_add_property_cells(pbcq, "ibm,lane_eq", hub->phb2_lane_eq);
		break;
	case 4:
		dt_add_property_cells(pbcq, "ibm,lane_eq", hub->phb3_lane_eq);
		break;
	default: ;
	}

	/* Currently we only create a PBCQ node, the actual PHB nodes
	 * will be added by sapphire later on.
	 */
	return pbcq;
}

static struct dt_node *io_add_murano(const struct cechub_io_hub *hub)
{
	struct dt_node *xscom;
	unsigned int i;

	xscom = find_xscom_for_chip(hub->proc_chip_id);
	if (!xscom) {
		prerror("MURANO: Can't find XSCOM for chip %d\n",
			hub->proc_chip_id);
		return NULL;
	}

	/* Create PHBs, max 3 */
	for (i = 0; i < 3; i++) {
		if (hub->fab_br0_pdt & (0x80 >> i))
			/* XSCOM addresses for murano DD1.0 */
			io_add_phb3(hub, i, xscom,
				    0x02012000 + (i * 0x400),
				    0x09012000 + (i * 0x400),
				    0x09013c00 + (i * 0x40));
	}

	/* HACK: We return the XSCOM device for the VPD info */
	return xscom;
}

static struct dt_node *io_add_hea(const struct cechub_io_hub *hub,
				  const void *sp_io)
{
	struct dt_node *np, *gnp;
	uint64_t reg[2];
	unsigned int i, vpd_sz;
	uint8_t kw_sz;
	const void *iokid, *vpd, *ccin;
	const uint8_t *mac;
	const struct HDIF_child_ptr *iokids;

	/*
	 * We have a table of supported dauther cards looked up
	 * by CCIN. We don't use the 1008 slot map in the VPD.
	 *
	 * This is basically translated from BML and will do for
	 * now especially since we don't really support p5ioc2
	 * machine, this is just for lab use
	 *
	 * This is mostly untested on 10G ... we might need more
	 * info about the PHY in that case
	 */
	const struct hea_iocard {
		const char ccin[4];
		struct {
			uint32_t speed;
			uint16_t ports;
			uint16_t phy_id;
		} pg[2];
	} hea_iocards[] = {
		{
			.ccin = "1818", /* HV4 something */
			.pg[0] = { .speed = 1000, .ports = 2, .phy_id = 0 },
		},
		{
			.ccin = "1819", /* HV4 Titov Card */
			.pg[0] = { .speed = 1000, .ports = 2, .phy_id = 0 },
			.pg[1] = { .speed = 1000, .ports = 2, .phy_id = 0 },
		},
		{
			.ccin = "1830", /* HV4 Sergei Card */
			.pg[0] = { .speed = 10000, .ports = 1, .phy_id = 0 },
			.pg[1] = { .speed = 10000, .ports = 1, .phy_id = 0 },
		},
		{
			.ccin = "181A", /* L4 Evans Card */
			.pg[1] = { .speed = 1000, .ports = 2, .phy_id = 0 },
		},
		{
			.ccin = "181B", /* L4 Weber Card */
			.pg[0] = { .speed = 10000, .ports = 1, .phy_id = 0 },
			.pg[1] = { .speed = 10000, .ports = 1, .phy_id = 0 },
		},
		{
			.ccin = "181C", /* HV4 Gibson Card */
			.pg[0] = { .speed = 1000, .ports = 2, .phy_id = 0 },
			.pg[1] = { .speed = 1000, .ports = 2, .phy_id = 0 },
		},
		{
			.ccin = "2BC4", /* MR Riverside 2 */
			.pg[0] = { .speed = 1000, .ports = 1, .phy_id = 1 },
			.pg[1] = { .speed = 1000, .ports = 1, .phy_id = 1 },
		},
		{
			.ccin = "2BC5", /* MR Lions 2 */
			.pg[0] = { .speed = 10000, .ports = 1, .phy_id = 1 },
			.pg[1] = { .speed = 10000, .ports = 1, .phy_id = 1 },
		},
		{
			.ccin = "2BC6", /* MR Onion 2 */
			.pg[0] = { .speed = 10000, .ports = 1, .phy_id = 1 },
			.pg[1] = { .speed = 1000, .ports = 2, .phy_id = 1 },
		},
		{
			.ccin = "266D", /* Jupiter Bonzai */
			.pg[0] = { .speed = 1000, .ports = 2, .phy_id = 1 },
			.pg[1] = { .speed = 1000, .ports = 2, .phy_id = 1 },
		},
		/* The blade use an IO KID that's a bit oddball and seems to
		 * represent the backplane itself, but let's use it anyway
		 *
		 * XXX Probably want a different PHY type !
		 */
		{
			.ccin = "531C", /* P7 Blade */
			.pg[0] = { .speed = 1000, .ports = 2, .phy_id = 0 },
		},
	};
	const struct hea_iocard *card = NULL;

	/* WARNING: This makes quite a lot of nasty assumptions
	 * that appear to hold true on the few machines I care
	 * about, which is good enough for now. We don't officially
	 * support p5ioc2 anyway...
	 */

	/* Get first IO KID, we only support one. Real support would
	 * mean using the FRU ID and the SLCA to find the right "stuff"
	 * but at this stage it's unnecessary
	 */
	iokids = HDIF_child_arr(sp_io, CECHUB_CHILD_IO_KIDS);
	if (!CHECK_SPPTR(iokids)) {
		prerror("HEA: no IOKID in HDAT child array !\n");
		return NULL;
	}
	if (!iokids->count) {
		prerror("HEA: IOKID count is 0 !\n");
		return NULL;
	}
	if (iokids->count > 1) {
		printf("HEA: WARNING ! More than 1 IO KID !!! (%d)\n",
		       iokids->count);
	}
	iokid = HDIF_child(sp_io, iokids, 0, "IO KID");
	if (!iokid) {
		prerror("HEA: Failed to retrieve IO KID 0 !\n");
		return NULL;
	}

	/* Grab VPD */
	vpd = HDIF_get_idata(iokid, IOKID_KW_VPD, &vpd_sz);
	if (!CHECK_SPPTR(vpd)) {
		prerror("HEA: Failed to retrieve VPD from IO KID !\n");
		return NULL;
	}

	/* Grab the MAC address */
	mac = vpd_find(vpd, vpd_sz, "VINI", "B1", &kw_sz);
	if (!mac || kw_sz < 8) {
		prerror("HEA: Failed to retrieve MAC Address !\n");
		return NULL;
	}

	/* Grab the CCIN (card ID) */
	ccin = vpd_find(vpd, vpd_sz, "VINI", "CC", &kw_sz);
	if (!ccin || kw_sz < 4) {
		prerror("HEA: Failed to retrieve CCIN !\n");
		return NULL;
	}

	/* Now we could try to parse the 1008 slot map etc... but instead
	 * we'll do like BML and grab the CCIN & use it for known cards.
	 * We also grab the MAC
	 */
	for (i = 0; i < ARRAY_SIZE(hea_iocards) && !card; i++) {
		if (strncmp(hea_iocards[i].ccin, ccin, 4))
			continue;
		card = &hea_iocards[i];
	}
	if (!card) {
		prerror("HEA: Unknown CCIN 0x%.4s!\n", (const char *)ccin);
		return NULL;
	}

	/* Assume base address is BAR3 + 0x4000000000 */
	reg[0] = hub->gx_ctrl_bar3 + 0x4000000000;
	reg[1] = 0xc0000000;

	printf("CEC:    * Adding HEA to P5IOC2, assuming GBA=0x%llx\n", reg[0]);
	np = dt_new_addr(dt_root, "ibm,hea", reg[0]);
	dt_add_property(np, "reg", reg, sizeof(reg));
	dt_add_property_strings(np, "compatible", "ibm,p5ioc2-hea");
	dt_add_property_cells(np, "#address-cells", 1);
	dt_add_property_cells(np, "#size-cells", 0);
	dt_add_property(np, "ibm,vpd", vpd, vpd_sz);
	dt_add_property_cells(np, "#mac-address", mac[7]);
	dt_add_property(np, "mac-address-base", mac, 6);
	/* BUID is base + 0x30 */
	dt_add_property(np, "interrupt-controller", NULL, 0);
	dt_add_property_cells(np, "interrupt-base",
			      (hub->buid_ext << 9) | 0x30);
	dt_add_property_cells(np, "interrupt-max-count", 128);

	/* Always 2 port groups */
	for (i = 0; i < 2; i++) {
		unsigned int clause;

		switch(card->pg[i].speed) {
		case 1000:
			clause = 0x22;
			break;
		case 10000:
			clause = 0x45;
			break;
		default:
			/* Unused port group */
			continue;
		}
		gnp = dt_new_addr(np, "portgroup", i + 1);
		dt_add_property_cells(gnp, "reg", i + 1);
		dt_add_property_cells(gnp, "speed", card->pg[i].speed);
		/* XX FIXME */
		dt_add_property_strings(gnp, "phy-type", "mdio");
		dt_add_property_cells(gnp, "phy-mdio-addr", card->pg[i].phy_id);
		dt_add_property_cells(gnp, "phy-mdio-clause", clause);
		dt_add_property_cells(gnp, "subports", card->pg[i].ports);
	}
	return np;
}

static void io_parse_fru(const void *sp_iohubs, struct dt_node *ics,
			 int *lx_idx)
{
	unsigned int i, kwvpd_sz;	
	const void *kwvpd;
	struct dt_node *hn;
	int count;

	count = HDIF_get_iarray_size(sp_iohubs, CECHUB_FRU_IO_HUBS);
	if (count < 1) {
		prerror("CEC: IO Hub with no chips !\n");
		return;
	}

	printf("CEC:   %d chips in FRU\n", count);

	kwvpd = HDIF_get_idata(sp_iohubs, CECHUB_ASCII_KEYWORD_VPD, &kwvpd_sz);
	if (!kwvpd)
		*lx_idx = -1;

	/* Iterate IO hub array */
	for (i = 0; i < count; i++) {
		const struct cechub_io_hub *hub;
		unsigned int size;
		const void *lxr;

		hub = HDIF_get_iarray_item(sp_iohubs, CECHUB_FRU_IO_HUBS,
					   i, &size);
		if (!hub || size < sizeof(struct cechub_io_hub)) {
			prerror("CEC:     IO-HUB Chip %d bad idata\n", i);
			continue;
		}
		printf("CEC:   IO Hub Chip #%d:\n", i);
		switch (hub->flags & CECHUB_HUB_FLAG_STATE_MASK) {
		case CECHUB_HUB_FLAG_STATE_OK:
			printf("CEC:     OK\n");
			break;
		case CECHUB_HUB_FLAG_STATE_FAILURES:
			printf("CEC:     OK with failures\n");
			break;
		case CECHUB_HUB_FLAG_STATE_NOT_INST:
			printf("CEC:     Not installed\n");
			continue;
		case CECHUB_HUB_FLAG_STATE_UNUSABLE:
			printf("CEC:     Unusable");
			continue;
		}

		/* GX BAR assignment */
		printf("CEC:   PChip: %d GX: %d BUID_Ext: 0x%x EC: 0x%x\n",
		       hub->proc_chip_id, hub->gx_index, hub->buid_ext,
		       hub->ec_level);

		printf("    GX BAR 0 = 0x%016llx\n", hub->gx_ctrl_bar0);
		printf("    GX BAR 1 = 0x%016llx\n", hub->gx_ctrl_bar1);
		printf("    GX BAR 2 = 0x%016llx\n", hub->gx_ctrl_bar2);
		printf("    GX BAR 3 = 0x%016llx\n", hub->gx_ctrl_bar3);
		printf("    GX BAR 4 = 0x%016llx\n", hub->gx_ctrl_bar4);

		lxr = NULL;
		if (kwvpd) {
			/* Find next LXRn*/
			while(*lx_idx < 10) {
				char recname[5];

				strcpy(recname, "LXR0");
				recname[3] += *lx_idx;
				lxr = vpd_find(kwvpd, kwvpd_sz, recname,
					       "LX", NULL);
				if (lxr)
					break;
				(*lx_idx)++;
			}
			/* Not found, try VINI */
			if (!lxr) {
				lxr = vpd_find(kwvpd, kwvpd_sz, "VINI",
					       "LX",  NULL);
				if (lxr)
					*lx_idx = VPD_LOAD_LXRN_VINI;
			}
		}
		printf("CEC:     LXRn=%d LXR=%016lx\n", *lx_idx,
		       lxr ? *(unsigned long *)lxr : 0);

		switch(hub->iohub_id) {
		case CECHUB_HUB_P7IOC:
			printf("CEC:     P7IOC !\n");
			hn = io_add_p7ioc(hub);
			io_add_common(hn, hub, ics);
			break;
		case CECHUB_HUB_P5IOC2:
			printf("CEC:     P5IOC2 !\n");
			hn = io_add_p5ioc2(hub);
			io_add_common(hn, hub, ics);
			io_add_hea(hub, sp_iohubs);
			break;
		case CECHUB_HUB_MURANO:
		case CECHUB_HUB_MURANO_SEGU:
			printf("CEC:     Murano !\n");
			hn = io_add_murano(hub);
			break;
		default:
			printf("CEC:     Hub ID 0x%04x unsupported !\n",
			       hub->iohub_id);
			hn = NULL;
		}
		/* Add the LX info */
		if (hn) {
			dt_add_property_cells(hn, "ibm,vpd-lx-info",
					      *lx_idx,
					      ((uint32_t *)lxr)[0],
					      ((uint32_t *)lxr)[1]);

		}
		if ((*lx_idx) >= 0 && (*lx_idx) < 9)
			(*lx_idx)++;
		else
			(*lx_idx) = -1;
	}
}

void io_parse(struct dt_node *ics)
{
	const void *sp_iohubs;
	unsigned int i, size;
	int lx_idx;

	/* Look for IO Hubs */
	sp_iohubs = spira.ntuples.cec_iohub_fru.addr;
	if (!sp_iohubs) {
		prerror("CEC: Cannot locate IO Hub FRU data !\n");
		return;
	}

	/*
	 * Note about LXRn numbering ...
	 *
	 * I can't completely make sense of what that is supposed to be, so
	 * for now, what we do is look for the first one we can find and
	 * increment it for each chip. Works for the machines I have here
	 */

	/* Start with LX ID 0 */
	lx_idx = 0;

	for_each_ntuple_idx(spira.ntuples.cec_iohub_fru, sp_iohubs, i) {
		const struct cechub_hub_fru_id *fru_id_data;
		unsigned int type;
		static const char *typestr[] = {
			"Reservation",
			"Card",
			"CPU Card",
			"Backplane",
			"Backplane Extension"
		};
		fru_id_data = HDIF_get_idata(sp_iohubs, CECHUB_FRU_ID_DATA_AREA,
					     &size);
		if (!fru_id_data || size < sizeof(struct cechub_hub_fru_id)) {
			prerror("CEC: IO-HUB FRU %d, bad ID data\n", i);
			continue;
		}
		type = fru_id_data->card_type;

		printf("CEC: HUB FRU %d is %s\n",
		       i, type > 4 ? "Unknown" : typestr[type]);

		/*
		 * We currently only handle the backplane (Juno) and
		 * processor FRU (P8 machines)
		 */
		if (type != CECHUB_FRU_TYPE_CEC_BKPLANE &&
		    type != CECHUB_FRU_TYPE_CPU_CARD) {
			prerror("CEC:   Unsupported type\n");
			continue;
		}

		/* We don't support Hubs connected to pass-through ports */
		if (fru_id_data->flags & (CECHUB_FRU_FLAG_HEADLESS |
					  CECHUB_FRU_FLAG_PASSTHROUGH)) {
			prerror("CEC:   Headless or Passthrough unsupported\n");
			continue;
		}

		/* Ok, we have a reasonable candidate */
		io_parse_fru(sp_iohubs, ics, &lx_idx);
	}
}

