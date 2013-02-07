#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <device.h>
#include <p5ioc2.h>
#include <p7ioc.h>
#include <vpd.h>

static void io_add_common(struct dt_node *hn, const struct cechub_io_hub *hub,
			  struct dt_node *ics, int lx_idx, const void *lxr)
{
	dt_add_property_cells(hn, "#address-cells", 2);
	dt_add_property_cells(hn, "#size-cells", 2);
	dt_add_property_cells(hn, "interrupt-parent", ics->phandle);
	dt_add_property_cells(hn, "ibm,buid-ext", hub->buid_ext);
	dt_add_property_cells(hn, "ibm,chip-id", hub->proc_chip_id);
	dt_add_property_cells(hn, "ibm,gx-index", hub->gx_index);
	dt_add_property_cells(hn, "revision", hub->ec_level);

	/* Instead of exposing the GX BARs as spearate ranges as we *should*
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

	/* Add the LX info */
	dt_add_property_cells(hn, "ibm,vpd-lx-info",
			      lx_idx,
			      ((uint32_t *)lxr)[0],
			      ((uint32_t *)lxr)[1]);
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

static void io_parse_fru(const void *sp_iohubs, struct dt_node *ics)
{
	unsigned int i, kwvpd_sz;	
	const void *kwvpd;
	int count, lx_idx;
	struct dt_node *hn;

	count = HDIF_get_iarray_size(sp_iohubs, CECHUB_FRU_IO_HUBS);
	if (count < 1) {
		prerror("CEC: IO Hub with no chips !\n");
		return;
	}

	printf("CEC:   %d chips in FRU\n", count);

	/*
	 * Note about LXRn numbering ...
	 *
	 * I can't quite make sense of what that is supposed to be, so
	 * for now, what we do is look for the first one we can find
	 * and increment it for each chip. Works for the machines I
	 * have here but they only have 1 chip so ...
	 */

	/* Start with LX ID 0 */
	lx_idx = 0;
	kwvpd = HDIF_get_idata(sp_iohubs, CECHUB_ASCII_KEYWORD_VPD, &kwvpd_sz);
	if (!kwvpd)
		lx_idx = -1;

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
			while(lx_idx < 10) {
				char recname[5];

				strcpy(recname, "LXR0");
				recname[3] += lx_idx;
				lxr = vpd_find(kwvpd, kwvpd_sz, recname,
					       "LX", NULL);
				if (lxr)
					break;
				lx_idx++;
			}
			/* Not found, try VINI */
			if (!lxr) {
				lxr = vpd_find(kwvpd, kwvpd_sz, "VINI",
					       "LX",  NULL);
				if (lxr)
					lx_idx = VPD_LOAD_LXRN_VINI;
			}
		}
		printf("CEC:     LXRn=%d LXR=%016lx\n", lx_idx,
		       lxr ? *(unsigned long *)lxr : 0);

		switch(hub->iohub_id) {
		case CECHUB_HUB_P7IOC:
			printf("CEC:     P7IOC !\n");
			hn = io_add_p7ioc(hub);
			io_add_common(hn, hub, ics, lx_idx, lxr);
			break;
		case CECHUB_HUB_P5IOC2:
			printf("CEC:     P5IOC2 !\n");
			hn = io_add_p5ioc2(hub);
			io_add_common(hn, hub, ics, lx_idx, lxr);
			break;
		default:
			printf("CEC:     Hub ID 0x%04x unsupported !\n",
			       hub->iohub_id);
		}
		if (lx_idx >= 0 && lx_idx < 9)
			lx_idx++;
		else
			lx_idx = -1;
	}
}

void io_parse(struct dt_node *ics)
{
	const void *sp_iohubs;
	unsigned int i, size;

	/* Look for IO Hubs */
	sp_iohubs = spira.ntuples.cec_iohub_fru.addr;
	if (!sp_iohubs) {
		prerror("CEC: Cannot locate IO Hub FRU data !\n");
		return;
	}
	for (i = 0; i < spira.ntuples.cec_iohub_fru.act_cnt; i++) {
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
			goto next_hub;
		}
		type = fru_id_data->card_type;

		printf("CEC: HUB FRU %d is %s\n",
		       i, type > 4 ? "Unknown" : typestr[type]);

		/*
		 * We currently only handle the backplane (Juno). This might
		 * need to be revisited if we ever want to support more
		 */
		if (type != CECHUB_FRU_TYPE_CEC_BKPLANE) {
			prerror("CEC:   Unsupported type\n");
			goto next_hub;
		}

		/* We don't support Hubs connected to pass-through ports */
		if (fru_id_data->flags & (CECHUB_FRU_FLAG_HEADLESS |
					  CECHUB_FRU_FLAG_PASSTHROUGH)) {
			prerror("CEC:   Headless or Passthrough unsupported\n");
			goto next_hub;
		}

		/* Ok, we have a reasonable candidate */
		io_parse_fru(sp_iohubs, ics);
	next_hub:
		sp_iohubs += spira.ntuples.cec_iohub_fru.alloc_len;
	}
}

