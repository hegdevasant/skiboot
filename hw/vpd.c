/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <fsp.h>
#include <device.h>

#define CHECK_SPACE(_p, _n, _e) (((_e) - (_p)) >= (_n))

/* Locate a keyword in a record in a VPD blob
 *
 * Note: This works with VPD LIDs. It will scan until it finds
 * the first 0x84, so it will skip all those 0's that the VPD
 * LIDs seem to contain
 */
const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size)
{
	const uint8_t *p = rec, *end = rec + rec_sz;

	while (CHECK_SPACE(p, 3, end)) {
		uint8_t k1 = *(p++);
		uint8_t k2 = *(p++);
		uint8_t sz = *(p++);

		if (k1 == kw[0] && k2 == kw[1]) {
			if (kw_size)
				*kw_size = sz;
			return p;
		}
		p += sz;
	}
	return NULL;
}

/* Low level keyword search in a record. Can be used when we
 * need to find the next keyword of a given type, for example
 * when having multiple MF/SM keyword pairs
 */
const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz)
{
	const uint8_t *p = vpd, *end = vpd + vpd_size;
	bool first_start = true;
	size_t rec_sz;
	uint8_t namesz = 0;
	const char *rec_name;

	while (CHECK_SPACE(p, 4, end)) {
		/* Get header byte */
		if (*(p++) != 0x84) {
			/* Skip initial crap in VPD LIDs */
			if (first_start)
				continue;
			break;
		}
		first_start = false;
		rec_sz = *(p++);
		rec_sz |= *(p++) << 8;
		if (!CHECK_SPACE(p, rec_sz, end)) {
			prerror("VPD: Malformed or truncated VPD,"
				" record size doesn't fit\n");
			return NULL;
		}

		/* Find record name */
		rec_name = vpd_find_keyword(p, rec_sz, "RT", &namesz);
		if (!rec_name)
			goto next;

		/* Names are supposed to be only 4 chars but let's just use
		 * the record len, should work either way
		 */
		if (strncmp(record, rec_name, namesz) != 0)
			goto next;

		/* Find keyword */
		return vpd_find_keyword(p, rec_sz, keyword, sz);
	next:
		p += rec_sz;
		if (*(p++) != 0x78) {
			prerror("VPD: Malformed or truncated VPD,"
				" missing final 0x78 in record %.4s\n",
				rec_name ? rec_name : "????");
			return NULL;
		}
	}
	return NULL;
}

/* Helper to load a VPD LID. Pass a ptr to the corresponding LX keyword */
static void *vpd_lid_load(const uint8_t *lx, uint8_t lxrn, size_t *size)
{
	/* Now this is a guess game as we don't have the info from the
	 * pHyp folks. But basically, it seems to boil down to loading
	 * a LID whose name is 0x80e000yy where yy is the last 2 digits
	 * of the LX record in hex.
	 *
	 * [ Correction: After a chat with some folks, it looks like it's
	 * actually 4 digits, though the lid number is limited to fff
	 * so we weren't far off. ]
	 *
	 * For safety, we look for a matching LX record in an LXRn
	 * (n = lxrn argument) or in VINI if lxrn=0xff
	 */
	uint32_t lid_no = 0x80e00000 | ((lx[6] & 0xf) << 8) | lx[7];

	/* We don't quite know how to get to the LID directory so
	 * we don't know the size. Let's allocate 16K. All the VPD LIDs
	 * I've seen so far are much smaller.
	 */
#define VPD_LID_MAX_SIZE	0x4000
	void *data = malloc(VPD_LID_MAX_SIZE);
	char record[4] = "LXR0";
	const void *valid_lx;
	uint8_t lx_size;
	struct dt_node *iplp;
	const char *side = NULL;
	int rc;

	if (!data) {
		prerror("VPD: Failed to allocate memory for LID\n");
		return NULL;
	}

	/* Adjust LID number for flash side */
	iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
	if (iplp)
		side = dt_prop_get_def(iplp, "cec-ipl-side", NULL);
	if (!side || !strcmp(side, "temp"))
		lid_no |= 0x8000;

	printf("VPD: Trying to load VPD LID 0x%08x...\n", lid_no);

	/* Load it from the FSP */
	rc = fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid_no, 0, data, size);
	if (rc) {
		prerror("VPD: Error %d loading VPD LID\n", rc);
		goto fail;
	}

	/* Validate it */
	if (lxrn < 9)
		record[3] = '0' + lxrn;
	else
		memcpy(record, "VINI", 4);

	valid_lx = vpd_find(data, *size, record, "LX", &lx_size);
	if (!valid_lx || lx_size != 8) {
		prerror("VPD: Cannot find validation LX record\n");
		goto fail;
	}
	if (memcmp(valid_lx, lx, 8) != 0) {
		prerror("VPD: LX record mismatch !\n");
		goto fail;
	}

	printf("VPD: Loaded %zu bytes\n", *size);

	/* Got it ! */
	return realloc(data, *size);
 fail:
	free(data);
	return NULL;
}

void vpd_iohub_load(struct dt_node *hub_node)
{
	void *vpd;
	size_t sz;
	const uint32_t *p;
	unsigned int lx_idx;
	char *lxr;

	p = dt_prop_get_def(hub_node, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lx_idx = p[0];
	lxr = (char *)&p[1];

	vpd = vpd_lid_load(lxr, lx_idx, &sz);
	if (!vpd) {
		prerror("VPD: Failed to load VPD LID\n");
	} else {
		dt_add_property(hub_node, "ibm,io-vpd", vpd, sz);
		free(vpd);
	}
}
