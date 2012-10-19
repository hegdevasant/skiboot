#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <fsp.h>
#include <spira.h>

#define CHECK_SPACE(_p, _n, _e) (((_e) - (_p)) >= (_n))

const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size)
{
	const uint8_t *p = rec, *end = rec + rec_sz;

	while(CHECK_SPACE(p, 3, end)) {
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

const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz)
{
	const uint8_t *p = vpd, *end = vpd + vpd_size;
	bool first_start = true;
	size_t rec_sz;
	uint8_t namesz;
	const char *rec_name;

	while(CHECK_SPACE(p, 4, end)) {
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

const void *vpd_lid_load(const uint8_t *lx, uint8_t lxrn, size_t *size)
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
	 * So for a LID number, that means the LSB is the LSB of the
	 * LX record.
	 *
	 * For safety, we look for a matching LX record in an LXRn
	 * (n = lxrn argument) or in VINI if lxrn=0xff
	 */
	uint32_t lid_no = 0x80e00000 | (lx[4] << 4) | lx[5];

	/* We don't quite know how to get to the LID directory so
	 * we don't know the size. Let's allocate 16K. All the VPD LIDs
	 * I've seen so far are much smaller.
	 */
#define VPD_LID_MAX_SIZE	0x4000
	void *data = malloc(VPD_LID_MAX_SIZE);
	char record[4] = "LXR0";
	const void *valid_lx;
	uint8_t lx_size;
	int rc;

	if (!data) {
		prerror("VPD: Failed to allocate memory for LID\n");
		return NULL;
	}

	/* Adjust LID number for flash side */
	if (cec_ipl_temp_side)
		lid_no |= 0x8000;

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
	if (!valid_lx || lx_size != 6) {
		prerror("VPD: Cannot find validation LX record\n");
		goto fail;
	}
	if (memcmp(valid_lx, lx, 6) != 0) {
		prerror("VPD: LX record mismatch !\n");
		goto fail;
	}

	/* Got it ! */
	return data;
 fail:
	free(data);
	return NULL;
}

const void *vpd_find_from_spira(struct spira_ntuple *np, unsigned int idata,
				const char *record, const char *keyword,
				uint8_t *size)
{
	const void *idptr;
	unsigned int idsz;

	if (!np->addr)
		return NULL;
	idptr = HDIF_get_idata(np->addr, idata, &idsz);
	if (!CHECK_SPPTR(idptr))
		return NULL;

	return vpd_find(idptr, idsz, record, keyword, size);
}
