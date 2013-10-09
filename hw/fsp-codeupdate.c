/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */

#include <skiboot.h>
#include <fsp.h>
#include <fsp-sysparam.h>
#include <opal.h>
#include <lock.h>
#include <codeupdate.h>
#include <device.h>
#include <ccan/endian/endian.h>

/* TCE alignment */
#define TCE_PSIZE		0x1000

enum flash_state {
	FLASH_STATE_ABSENT,
	FLASH_STATE_INVALID, /* IPL side marker lid is invalid */
	FLASH_STATE_READING,
	FLASH_STATE_READ,
};

enum lid_fetch_side {
	FETCH_T_SIDE_ONLY,
	FETCH_P_SIDE_ONLY,
	FETCH_BOTH_SIDE,
};

static enum flash_state flash_state = FLASH_STATE_INVALID;
static enum lid_fetch_side lid_fetch_side = FETCH_BOTH_SIDE;

/* Image buffers */
static struct opal_sg_list *image_data;
static uint32_t tce_start;
static void *lid_data;
static char validate_buf[VALIDATE_BUF_SIZE];

/* TCE buffer lock */
static struct lock flash_lock = LOCK_UNLOCKED;

/* FW VPD data */
static struct fw_image_vpd fw_vpd[2];

/* Code update related sys parameters */
static uint32_t ipl_side;
static uint32_t fw_license;
static uint32_t hmc_managed;
static uint32_t update_policy;
static uint32_t in_flight_params;

/* If non-NULL, this gets called just before rebooting */
int (*fsp_flash_term_hook)(void);

static inline void code_update_tce_map(uint32_t tce_offset,
				       void *buffer, uint32_t size)
{
	uint32_t tlen = ALIGN_UP(size, TCE_PSIZE);

	fsp_tce_map(PSI_DMA_CODE_UPD + tce_offset, buffer, tlen);
}

static inline void code_update_tce_unmap(uint32_t size)
{
	fsp_tce_unmap(PSI_DMA_CODE_UPD, size);
}

/*
 * Get IPL side
 */
static void get_ipl_side(void)
{
	struct dt_node *iplp;
	const char *side = NULL;

	iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
	if (iplp)
		side = dt_prop_get_def(iplp, "cec-ipl-side", NULL);
	printf("CUPD: IPL SIDE = %s\n", side);

	if (!side || !strcmp(side, "temp"))
		ipl_side = FW_IPL_SIDE_TEMP;
	else
		ipl_side = FW_IPL_SIDE_PERM;
}


/*
 * Helper routines to retrieve code update related
 * system parameters from FSP.
 */

static void inc_in_flight_param(void)
{
	lock(&flash_lock);
	in_flight_params++;
	unlock(&flash_lock);
}

static void dec_in_flight_param(void)
{
	lock(&flash_lock);
	assert(in_flight_params > 0);
	in_flight_params--;
	unlock(&flash_lock);
}

static void got_fw_license_policy(uint32_t param_id __unused, int err_len,
				  void *data __unused)
{
	if (err_len != 4)
		prerror("CUPD: Error retrieving fw license policy: %d\n",
			err_len);
	else
		printf("CUPD: FW license policy from FSP: %d\n", fw_license);
	dec_in_flight_param();
}

static void get_fw_license_policy(void)
{
	int rc;

	inc_in_flight_param();
	rc = fsp_get_sys_param(SYS_PARAM_FW_LICENSE, &fw_license, 4,
			       got_fw_license_policy, NULL);
	if (rc) {
		prerror("CUPD: Error %d queueing param request\n", rc);
		dec_in_flight_param();
	}
}

static void got_code_update_policy(uint32_t param_id __unused, int err_len,
				   void *data __unused)
{
	if (err_len != 4)
		prerror("CUPD: Error retrieving code update policy: %d\n",
			err_len);
	else
		printf("CUPD: Code update policy from FSP: %d\n",
		       update_policy);
	dec_in_flight_param();
}

static void get_code_update_policy(void)
{
	int rc;

	inc_in_flight_param();
	rc = fsp_get_sys_param(SYS_PARAM_FLASH_POLICY, &update_policy, 4,
			       got_code_update_policy, NULL);
	if (rc) {
		prerror("CUPD: Error %d queueing param request\n", rc);
		dec_in_flight_param();
	}
}

static void got_platform_hmc_managed(uint32_t param_id __unused, int err_len,
				     void *data __unused)
{
	if (err_len != 4)
		prerror("CUPD: Error retrieving hmc managed status: %d\n",
			err_len);
	else
		printf("CUPD: HMC managed status from FSP: %d\n", hmc_managed);
	dec_in_flight_param();
}

static void get_platform_hmc_managed(void)
{
	int rc;

	inc_in_flight_param();
	rc = fsp_get_sys_param(SYS_PARAM_HMC_MANAGED, &hmc_managed, 4,
			       got_platform_hmc_managed, NULL);
	if (rc) {
		prerror("FLASH: Error %d queueing param request\n", rc);
		dec_in_flight_param();
	}
}

/*
 * Get common marker LID additional data section
 */
static void *get_adf_sec_data(struct com_marker_adf_sec *adf_sec,
			      uint32_t name)
{
	struct com_marker_adf_header *adf_header;
	int i;

	adf_header = (void *)adf_sec->adf_data;
	for (i = 0; i < be32_to_cpu(adf_sec->adf_cnt); i++) {
		if (be32_to_cpu(adf_header->name) == name)
			return adf_header;

		adf_header = (void *)adf_header + be32_to_cpu(adf_header->size);
	}
	return NULL;
}

/*
 * Parse common marker LID to get FW version details
 *
 * Note:
 *   At present, we are parsing "Service Pack Nomenclature ADF"
 *   section only. If we are adding FW IP support, then we have
 *   to parse "Firmware IP Protection ADF" as well.
 */
static void parse_marker_lid(uint32_t side)
{
	struct com_marker_header *header;
	struct com_marker_mi_section *mi_sec;
	struct com_marker_adf_sec *adf_sec;
	struct com_marker_adf_sp *adf_sp;

	header = (void *)lid_data;

	/* Get MI details */
	mi_sec = (void *)header + be32_to_cpu(header->MI_offset);
	/*
	 * If Marker LID is invalid, then FSP will return a Marker
	 * LID with ASCII zeros for the entire MI keyword.
	 */
	if (mi_sec->MI_keyword[0] == '0') {
		strncpy(fw_vpd[side].MI_keyword, FW_VERSION_UNKNOWN,
			MI_KEYWORD_SIZE);
		strncpy(fw_vpd[side].ext_fw_id, FW_VERSION_UNKNOWN,
			ML_KEYWORD_SIZE);
		return;
	}
	strncpy(fw_vpd[side].MI_keyword, mi_sec->MI_keyword, MI_KEYWORD_SIZE);
	printf("CUPD: %s side MI Keyword = %s\n",
	       side == 0x00 ? "P" : "T", fw_vpd[side].MI_keyword);

	/* Get ML details */
	adf_sec = (void *)header + be32_to_cpu(mi_sec->adf_offset);
	adf_sp = get_adf_sec_data(adf_sec, ADF_NAME_SP);
	if (!adf_sp) {
		strncpy(fw_vpd[side].ext_fw_id, FW_VERSION_UNKNOWN,
			ML_KEYWORD_SIZE);
		return;
	}
	strncpy(fw_vpd[side].ext_fw_id,
		(void *)adf_sp + be32_to_cpu(adf_sp->sp_name_offset),
		ML_KEYWORD_SIZE);
	printf("CUPD: %s side ML Keyword = %s\n",
	       side == 0x00 ? "P" : "T", fw_vpd[side].ext_fw_id);
}

static void validate_com_marker_lid(uint8_t status)
{
	if (!strncmp(fw_vpd[ipl_side].MI_keyword, FW_VERSION_UNKNOWN,
		     sizeof(FW_VERSION_UNKNOWN))) {
		prerror("CUPD: IPL side Marker LID is not valid\n");
		flash_state = FLASH_STATE_INVALID;
		return;
	}
	if (status == FSP_STATUS_SUCCESS)
		flash_state = FLASH_STATE_READ;
	else
		flash_state = FLASH_STATE_INVALID;
}

static void fetch_lid_data_complete(struct fsp_msg *msg)
{
	void *buffer;
	size_t length, chunk;
	uint32_t lid_id, offset;
	uint16_t id;
	uint8_t flags, status;

	status = (msg->resp->word1 >> 8) & 0xff;
	flags = (msg->data.words[0] >> 16) & 0xff;
	id = msg->data.words[0] & 0xffff;
	lid_id = msg->data.words[1];

	printf("CUPD: Marker LID id : size : status = 0x%x : 0x%x : 0x%x\n",
	       msg->data.words[1], msg->resp->data.words[2], status);

	switch (status) {
	case FSP_STATUS_SUCCESS: /* Read complete, parse VPD */
		parse_marker_lid(lid_id == P_COM_MARKER_LID_ID ? 0 : 1);
		break;
	case FSP_STATUS_MORE_DATA: /* More data left */
		offset = msg->resp->data.words[1];
		length = msg->resp->data.words[2];

		offset += length;
		chunk = MARKER_LID_SIZE - offset;
		if (chunk > 0) {
			buffer = (void *)PSI_DMA_CODE_UPD + offset;
			fsp_fetch_data_queue(flags, id, lid_id,
					     offset, buffer, &chunk,
					     fetch_lid_data_complete);
			return;
		}
		break;
	default:	/* Fetch LID call failed */
		break;
	}

	/* If required, fetch T side marker LID */
	if (lid_id == P_COM_MARKER_LID_ID &&
	    lid_fetch_side == FETCH_BOTH_SIDE) {
		length = MARKER_LID_SIZE;
		fsp_fetch_data_queue(flags, id, T_COM_MARKER_LID_ID,
				     0, (void *)PSI_DMA_CODE_UPD,
				     &length, fetch_lid_data_complete);
		return;
	}

	/* Validate marker LID data */
	validate_com_marker_lid(status);

	/* TCE unmap */
	code_update_tce_unmap(MARKER_LID_SIZE);
}

static void fetch_com_marker_lid(void)
{
	size_t length = MARKER_LID_SIZE;
	uint32_t lid_id;
	int rc;

	if (lid_fetch_side == FETCH_T_SIDE_ONLY)
		lid_id = T_COM_MARKER_LID_ID;
	else
		lid_id = P_COM_MARKER_LID_ID;

	code_update_tce_map(0, lid_data, length);
	rc = fsp_fetch_data_queue(0x00, 0x05, lid_id, 0,
				  (void *)PSI_DMA_CODE_UPD, &length,
				  fetch_lid_data_complete);
	if (!rc)
		flash_state = FLASH_STATE_READING;
	else
		flash_state = FLASH_STATE_INVALID;
}

/*
 * This is called right before starting the payload (Linux) to
 * ensure the common marker LID read and parsing has happened
 * before we transfer control.
 */
void fsp_code_update_wait_vpd(void)
{
	if (!fsp_present())
		return;

	printf("CUPD: Waiting read marker LID completion...\n");

	while(flash_state == FLASH_STATE_READING)
		fsp_poll();

	printf("CUPD: Waiting in flight params completion...\n");
	while(in_flight_params)
		fsp_poll();
}

static int64_t code_update_check_state(void)
{
	switch(flash_state) {
	case FLASH_STATE_ABSENT:
		return OPAL_HARDWARE;
	case FLASH_STATE_INVALID:
		return OPAL_INTERNAL_ERROR;
	case FLASH_STATE_READING:
		return OPAL_BUSY;
	default:
		break;
	}
	return OPAL_SUCCESS;
}

static int code_update_start(void)
{
	struct fsp_msg *msg;
	int rc;
	uint16_t comp = 0x00;	/* All components */
	uint8_t side = OPAL_COMMIT_TMP_SIDE;	/* Temporary side */

	msg = fsp_mkmsg(FSP_CMD_FLASH_START, 1, side << 16 | comp);
	if (!msg) {
		prerror("CUPD: message allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_sync_msg(msg, false)) {
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(msg);
	return rc;
}

static int code_update_write_lid(uint32_t lid_id, uint32_t size)
{
	struct fsp_msg *msg;
	int rc, n_pairs = 1;

	msg = fsp_mkmsg(FSP_CMD_FLASH_WRITE, 5, lid_id,
			n_pairs, 0, tce_start, size);
	if (!msg) {
		prerror("CUPD: message allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_sync_msg(msg, false)) {
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(msg);
	return rc;
}

static int code_update_del_lid(uint32_t lid_id)
{
	struct fsp_msg *msg;
	int rc;

	msg = fsp_mkmsg(FSP_CMD_FLASH_DEL, 1, lid_id);
	if (!msg) {
		prerror("CUPD: message allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_sync_msg(msg, false)) {
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(msg);
	return rc;
}

static int code_update_complete(uint32_t cmd)
{
	struct fsp_msg *msg;
	int rc;

	msg = fsp_mkmsg(cmd, 0);
	if (!msg) {
		prerror("CUPD: message allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_sync_msg(msg, false)) {
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(msg);
	return rc;
}

static int code_update_swap_side(void)
{
	struct fsp_msg *msg;
	int rc;

	msg = fsp_mkmsg(FSP_CMD_FLASH_SWAP, 0);
	if (!msg) {
		prerror("CUPD: message allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_sync_msg(msg, false)) {
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(msg);
	return rc;
}

static void code_update_commit_complete(struct fsp_msg *msg)
{
	int rc;
	uint8_t type;

	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(msg);
	if (rc) {
		prerror("CUPD: Code update commit failed, err 0x%x\n", rc);
		return;
	}

	/* Reset cached VPD data */
	lock(&flash_lock);

	/* Read in progress? */
	rc = code_update_check_state();
	if (rc == OPAL_BUSY)
		goto out;

	/* Find commit type */
	type = (msg->word1 >> 8) & 0xff;
	if (type == 0x01) {
		lid_fetch_side = FETCH_P_SIDE_ONLY;
	} else if (type == 0x02)
		lid_fetch_side = FETCH_T_SIDE_ONLY;
	else
		lid_fetch_side = FETCH_BOTH_SIDE;

	fetch_com_marker_lid();

out:
	unlock(&flash_lock);
}

static int code_update_commit(uint32_t cmd)
{
	struct fsp_msg *msg;

	msg = fsp_mkmsg(cmd, 0);
	if (!msg) {
		prerror("CUPD: message allocation failed !\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_queue_msg(msg, code_update_commit_complete)) {
		prerror("CUPD: Failed to queue code update commit message\n");
		fsp_freemsg(msg);
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}

/*
 * Inband code update is allowed?
 */
static int64_t validate_inband_policy(void)
{
	if ((update_policy != INBAND_UPDATE_ALLOWED) ||
	    (fw_license != FW_LICENSE_ACCEPT) ||
	    (hmc_managed == PLATFORM_HMC_MANAGED))
		return -1;
	return 0;
}

/*
 * Validate magic Number
 */
static int64_t validate_magic_num(uint16_t magic)
{
	if (magic != IMAGE_MAGIC_NUMBER)
		return -1;
	return 0;
}

/*
 * Compare MI keyword to make sure candidate image
 * is valid for this platform.
 */
static int64_t validate_image_version(struct update_image_header *header,
				      uint32_t *result)
{
	struct fw_image_vpd vpd;
	int t_valid = 0, p_valid = 0, cton_ver = -1, ptot_ver = -1;

	/* Valid flash image level? */
	if (strncmp(fw_vpd[0].MI_keyword, FW_VERSION_UNKNOWN,
		    sizeof(FW_VERSION_UNKNOWN)) != 0)
		p_valid = 1;

	if (strncmp(fw_vpd[1].MI_keyword, FW_VERSION_UNKNOWN,
		    sizeof(FW_VERSION_UNKNOWN)) != 0)
		t_valid = 1;

	/* Validate with IPL side image */
	vpd = fw_vpd[ipl_side];

	/* Validate platform identifier (first two char of MI keyword) */
	if (strncmp(vpd.MI_keyword, header->MI_keyword_data, 2) != 0) {
		*result = VALIDATE_INVALID_IMG;
		return OPAL_SUCCESS;
	}

	/* Don't flash different FW series (like P7 image on P8) */
	if (vpd.MI_keyword[2] != header->MI_keyword_data[2]) {
		*result = VALIDATE_INVALID_IMG;
		return OPAL_SUCCESS;
	}

	/* Get current to new version difference */
	cton_ver = strncmp(vpd.MI_keyword + 3, header->MI_keyword_data + 3, 6);

	/* Get P to T version difference */
	if (t_valid && p_valid)
		ptot_ver = strncmp(fw_vpd[0].MI_keyword + 3,
				   fw_vpd[1].MI_keyword + 3, 6);

	/* Update validation result */
	if (ipl_side == FW_IPL_SIDE_TEMP) {
		if (!ptot_ver && cton_ver > 0) /* downgrade T side */
			*result = VALIDATE_TMP_UPDATE_DL;
		else if (!ptot_ver && cton_ver <= 0) /* upgrade T side */
			*result = VALIDATE_TMP_UPDATE;
		else if (cton_ver > 0) /* Implied commit & downgrade T side */
			*result = VALIDATE_TMP_COMMIT_DL;
		else /* Implied commit & upgrade T side */
			*result = VALIDATE_TMP_COMMIT;
	} else {
		if (!t_valid)	/* Current unknown */
			*result = VALIDATE_CUR_UNKNOWN;
		else if (cton_ver > 0) /* downgrade FW version */
			*result = VALIDATE_TMP_UPDATE_DL;
		else		/* upgrade FW version */
			*result = VALIDATE_TMP_UPDATE;
	}
	return OPAL_SUCCESS;
}

/*
 * Validate candidate image
 */
static int validate_candidate_image(uint64_t buffer,
				    uint32_t size, uint32_t *result)
{
	struct update_image_header *header;
	int rc = OPAL_PARAMETER;

	if (size < VALIDATE_BUF_SIZE)
		goto out;

	rc = code_update_check_state();
	if (rc != OPAL_SUCCESS)
		goto out;

	if (validate_inband_policy() != 0) {
		*result = VALIDATE_FLASH_AUTH;
		rc = OPAL_SUCCESS;
		goto out;
	}

	memcpy(validate_buf, (void *)buffer, VALIDATE_BUF_SIZE);
	header = (struct update_image_header *)validate_buf;

	if (validate_magic_num(header->magic) != 0) {
		*result = VALIDATE_INVALID_IMG;
		rc = OPAL_SUCCESS;
		goto out;
	}
	rc = validate_image_version(header, result);
out:
	return rc;
}

static int validate_out_buf_mi_data(void *buffer, int offset, uint32_t result)
{
	struct update_image_header *header = (void *)validate_buf;

	/* Current T & P side MI data */
	strncpy(buffer + offset, "MI ", 3);
	offset += 3;
	strncpy(buffer + offset, fw_vpd[1].MI_keyword, MI_KEYWORD_SIZE);
	offset += MI_KEYWORD_SIZE;
	strncpy(buffer + offset, " ", 1);
	offset += 1;
	strncpy(buffer + offset, fw_vpd[0].MI_keyword, MI_KEYWORD_SIZE);
	offset += MI_KEYWORD_SIZE;
	strncpy(buffer + offset, "\n", 1);
	offset += 1;

	/* New T & P side MI data */
	strncpy(buffer + offset, "MI ", 3);
	offset += 3;
	strncpy(buffer + offset, header->MI_keyword_data, MI_KEYWORD_SIZE);
	offset += MI_KEYWORD_SIZE;
	strncpy(buffer + offset, " ", 1);
	offset += 1;
	if (result == VALIDATE_TMP_COMMIT_DL ||
	    result == VALIDATE_TMP_COMMIT)
		strncpy(buffer + offset,
			fw_vpd[1].MI_keyword, MI_KEYWORD_SIZE);
	else
		strncpy(buffer + offset,
			fw_vpd[0].MI_keyword, MI_KEYWORD_SIZE);
	offset += MI_KEYWORD_SIZE;
	strncpy(buffer + offset, "\n", 1);
	offset += 1;

	return offset;
}

static int validate_out_buf_ml_data(void *buffer, int offset, uint32_t result)
{
	struct update_image_header *header = (void *)validate_buf;
	/* Candidate image ML data */
	char *ext_fw_id = (void *)header->data;

	/* Current T & P side ML data */
	strncpy(buffer + offset, "ML ", 3);
	offset += 3;
	strncpy(buffer + offset, fw_vpd[1].ext_fw_id, ML_KEYWORD_SIZE);
	offset += ML_KEYWORD_SIZE;
	strncpy(buffer + offset, " ", 1);
	offset += 1;
	strncpy(buffer + offset, fw_vpd[0].ext_fw_id, ML_KEYWORD_SIZE);
	offset += ML_KEYWORD_SIZE;
	strncpy(buffer + offset, "\n", 1);
	offset += 1;

	/* New T & P side ML data */
	strncpy(buffer + offset, "ML ", 3);
	offset += 3;
	strncpy(buffer + offset, ext_fw_id, ML_KEYWORD_SIZE);
	offset += ML_KEYWORD_SIZE;
	strncpy(buffer + offset, " ", 1);
	offset += 1;
	if (result == VALIDATE_TMP_COMMIT_DL ||
	    result == VALIDATE_TMP_COMMIT)
		strncpy(buffer + offset,
			fw_vpd[1].ext_fw_id, ML_KEYWORD_SIZE);
	else
		strncpy(buffer + offset,
			fw_vpd[0].ext_fw_id, ML_KEYWORD_SIZE);
	offset += ML_KEYWORD_SIZE;
	strncpy(buffer + offset, "\n", 1);
	offset += 1;

	return offset;
}

/*
 * Copy LID data to TCE buffer
 */
static int get_lid_data(struct opal_sg_list *list,
			int lid_size, int lid_offset)
{
	struct opal_sg_list *sg;
	struct opal_sg_entry *entry;
	int length, num_entries, i, buf_pos = 0;

	/* Reset TCE start address */
	tce_start = 0;

	for (sg = list; sg; sg = sg->next) {
		length = (sg->length & ~(SG_LIST_VERSION << 56)) - 16;
		num_entries = length / sizeof(struct opal_sg_entry);
		if (num_entries <= 0)
			return -1;

		for (i = 0; i < num_entries; i++) {
			entry = &list->entry[i];

			/*
			 * Continue until we get data block which
			 * contains LID data
			 */
			if (lid_offset > entry->length) {
				lid_offset -= entry->length;
				continue;
			}

			if (!tce_start)
				tce_start = PSI_DMA_CODE_UPD + lid_offset;

			/* TCE mapping */
			code_update_tce_map(buf_pos, entry->data,
					    entry->length);
			buf_pos += entry->length;

			/* LID data is spread across multiple blocks ? */
			if ((entry->length - lid_offset) < lid_size) {
				lid_size -= (entry->length - lid_offset);
				lid_offset = 0;
			} else {
				return 0;
			}
		}
	} /* outer loop */
	return -1;
}

/*
 * If IPL side is T, then swap P & T sides to add
 * new fix to T side.
 */
static int validate_ipl_side(void)
{
	if (ipl_side == FW_IPL_SIDE_PERM)
		return 0;
	return code_update_swap_side();
}

static int64_t fsp_opal_validate_flash(uint64_t buffer,
				       uint32_t *size, uint32_t *result)
{
	int64_t rc = 0;
	int offset;

	lock(&flash_lock);

	rc = validate_candidate_image(buffer, *size, result);
	/* Fill output buffer
	 *
	 * Format:
	 *   MI<sp>current-T-image<sp>current-P-image<0x0A>
	 *   MI<sp>new-T-image<sp>new-P-image<0x0A>
	 *   ML<sp>current-T-image<sp>current-P-image<0x0A>
	 *   ML<sp>new-T-image<sp>new-P-image<0x0A>
	 */
	if (!rc && (*result != VALIDATE_FLASH_AUTH &&
		   *result != VALIDATE_INVALID_IMG)) {
		/* Clear output buffer */
		memset((void *)buffer, 0, VALIDATE_BUF_SIZE);

		offset = validate_out_buf_mi_data((void *)buffer, 0, *result);
		offset += validate_out_buf_ml_data((void *)buffer,
						   offset, *result);
		*size = offset;
	}

	unlock(&flash_lock);
	return rc;
}

/* Commit/Reject T side image */
static int64_t fsp_opal_manage_flash(uint8_t op)
{
	uint32_t cmd;

	if (code_update_check_state() == OPAL_BUSY)
		return OPAL_BUSY;

	if (op != OPAL_REJECT_TMP_SIDE && op != OPAL_COMMIT_TMP_SIDE)
		return OPAL_PARAMETER;

	if ((op == OPAL_COMMIT_TMP_SIDE && ipl_side == FW_IPL_SIDE_PERM) ||
	    (op == OPAL_REJECT_TMP_SIDE && ipl_side == FW_IPL_SIDE_TEMP))
		return OPAL_ACTIVE_SIDE_ERR;

	if (op == OPAL_COMMIT_TMP_SIDE)
		cmd = FSP_CMD_FLASH_NORMAL;
	else
		cmd = FSP_CMD_FLASH_REMOVE;

	return code_update_commit(cmd);
}

static int fsp_flash_firmware(void)
{
	struct update_image_header *header;
	struct lid_index_entry *idx_entry;
	struct opal_sg_list *list;
	struct opal_sg_entry *entry;
	int rc, i;

	lock(&flash_lock);

	/* Make sure no outstanding LID read is in progress */
	rc = code_update_check_state();
	if (rc == OPAL_BUSY)
		fsp_code_update_wait_vpd();

	/* Get LID Index */
	list = image_data;
	if (!list)
		goto out;
	entry = &list->entry[0];
	header = (struct update_image_header *)entry->data;
	idx_entry = (void *)header + be16_to_cpu(header->lid_index_offset);

	/* FIXME:
	 *   At present we depend on FSP to validate CRC for
	 *   individual LIDs. Calculate and validate individual
	 *   LID CRC here.
	 */

	if (validate_ipl_side() != 0)
		goto out;
	/* Start code update process */
	if (code_update_start() != 0)
		goto out;

	/*
	 * Delete T side LIDs before writing.
	 *
	 * Note:
	 *   - Applicable for FWv >= 760.
	 *   - Current Code Update design is to ignore
	 *     any delete lid failure, and continue with
	 *     the update.
	 */
	rc = code_update_del_lid(DEL_UPD_SIDE_LIDS);

	for (i = 0; i < be16_to_cpu(header->number_lids); i++) {
		if (be32_to_cpu(idx_entry->size) > LID_MAX_SIZE) {
			prerror("CUPD: LID size 0x%x is > max LID size\n",
				be32_to_cpu(idx_entry->size));
			goto abort_update;
		}

		rc = get_lid_data(list, be32_to_cpu(idx_entry->size),
				  be32_to_cpu(idx_entry->offset));
		if (rc)
			goto abort_update;

		rc = code_update_write_lid(be32_to_cpu(idx_entry->id),
					   be32_to_cpu(idx_entry->size));
		if (rc)
			goto abort_update;

		/* Unmap TCE */
		code_update_tce_unmap(PSI_DMA_CODE_UPD_SIZE);

		/* Next LID index */
		idx_entry = (void *)idx_entry + sizeof(struct lid_index_entry);
	}

	/* Code update completed */
	rc = code_update_complete(FSP_CMD_FLASH_COMPLETE);

	unlock(&flash_lock);
	return rc;

abort_update:
	rc = code_update_complete(FSP_CMD_FLASH_ABORT);
out:
	unlock(&flash_lock);
	return -1;
}

static int64_t validate_sglist(struct opal_sg_list *list)
{
	struct opal_sg_list *sg;
	struct opal_sg_entry *prev_entry, *entry;
	int length, num_entries, i;

	prev_entry = NULL;
	for (sg = list; sg; sg = sg->next) {
		length = (sg->length & ~(SG_LIST_VERSION << 56)) - 16;
		num_entries = length / sizeof(struct opal_sg_entry);
		if (num_entries <= 0)
			return -1;

		for (i = 0; i < num_entries; i++) {
			entry = &list->entry[i];

			/* All entries must be aligned */
			if (((uint64_t)entry->data) & 0xfff)
				return OPAL_PARAMETER;

			/* All non-terminal entries size must be aligned */
			if (prev_entry && (prev_entry->length & 0xfff))
				return OPAL_PARAMETER;

			prev_entry = entry;
		}
	}
	return OPAL_SUCCESS;
}

static int64_t fsp_opal_update_flash(struct opal_sg_list *list)
{
	struct opal_sg_entry *entry;
	int length, num_entries, result, rc = OPAL_PARAMETER;

	/* Ensure that the sg list honors our alignment requirements */
	rc = validate_sglist(list);
	if (rc) {
		prerror("CUPD: sglist fails alignment requirements\n");
		return rc;
	}

	lock(&flash_lock);
	if (!list) {	/* Cancel update request */
		fsp_flash_term_hook = NULL;
		image_data = NULL;
		rc = OPAL_SUCCESS;
		goto out;
	}
	length = (list->length & ~(SG_LIST_VERSION << 56)) - 16;
	num_entries = length / sizeof(struct opal_sg_entry);
	if (num_entries <= 0)
		goto out;

	/* Validate image header */
	entry = &list->entry[0];
	rc = validate_candidate_image((uint64_t)entry->data,
				      VALIDATE_BUF_SIZE, &result);
	if (!rc && (result != VALIDATE_FLASH_AUTH &&
		   result != VALIDATE_INVALID_IMG)) {
		image_data = list;
		fsp_flash_term_hook = fsp_flash_firmware;
		rc = OPAL_SUCCESS;
	}
out:
	unlock(&flash_lock);
	return rc;
}

/*
 * Code Update notifications
 *
 * Note: At present we just ACK these notifications.
 *       Reset cached VPD data if we are going to support
 *       concurrent image maint in future.
 */
static bool code_update_notify(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	int rc;
	uint32_t cmd;

	printf("CUPD: Got notification 0x%x\n", cmd_sub_mod);

	if (cmd_sub_mod == FSP_CMD_FLASH_CACHE) {
		cmd = FSP_CMD_FLASH_CACHE_RSP;
		printf("CUPD: Flash cache, data = 0x%x\n", msg->data.words[0]);
	} else {
		cmd = FSP_CMD_FLASH_OUT_RSP;
		printf("CUPD: Commit Type = 0x%x\n", (msg->word1 >> 8) & 0xff);
	}

	rc = fsp_queue_msg(fsp_mkmsg(cmd, 0), fsp_freemsg);
	if (rc)
		 prerror("CUPD: Failed to queue code update "
			 "notification response :%d\n", rc);
	return true;
}

static struct fsp_client fsp_get_notify = {
	.message = code_update_notify,
};

void fsp_code_update_init(void)
{
	if (!fsp_present()) {
		flash_state = FLASH_STATE_ABSENT;
		return;
	}

	/* OPAL interface */
	opal_register(OPAL_FLASH_VALIDATE, fsp_opal_validate_flash, 3);
	opal_register(OPAL_FLASH_MANAGE, fsp_opal_manage_flash, 1);
	opal_register(OPAL_FLASH_UPDATE, fsp_opal_update_flash, 1);

	/* register Code Update Class D3 */
	fsp_register_client(&fsp_get_notify, FSP_MCLASS_CODE_UPDATE);

	/* Flash hook */
	fsp_flash_term_hook = NULL;

	/* Fetch various code update related sys parameters */
	get_ipl_side();
	get_fw_license_policy();
	get_code_update_policy();
	get_platform_hmc_managed();

	/* Fetch common marker LID */
	lid_data = memalign(MARKER_LID_SIZE, TCE_PSIZE);
	if (!lid_data) {
		prerror("CUPD: Failed to allocate memory for marker LID\n");
		flash_state = FLASH_STATE_INVALID;
		return;
	}
	fetch_com_marker_lid();
}
