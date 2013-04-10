/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <lock.h>
#include <device.h>

//#define DBG(fmt...)	printf("RTC: " fmt)
#define DBG(fmt...)	do { } while(0)

/*
 * The FSP NVRAM API operates in "blocks" of 4K. It is entirely exposed
 * to the OS via the OPAL APIs.
 *
 * In order to avoid dealing with complicated read/modify/write state
 * machines (and added issues related to FSP failover in the middle)
 * we keep a memory copy of the entire nvram which we load at boot
 * time. We save only modified blocks.
 *
 * To limit the amount of memory used by the nvram image, we limit
 * how much nvram we support to NVRAM_SIZE. Additionally, this limit
 * of 1M is the maximum that the CHRP/PAPR nvram partition format
 * supports for a partition entry.
 *
 * (Q: should we save the whole thing in case of FSP failover ?)
 *
 * The nvram is expected to comply with the CHRP/PAPR defined format,
 * and specifically contain a System partition (ID 0x70). If present
 * SkiBoot will be able to obtain some configuration from it at boot
 * time.
 *
 * We do not exploit the ability of the FSP to store a checksum. This
 * is documented as possibly going away. The CHRP format for nvram
 * that Linux uses has its own (though weak) checksum mechanism already
 *
 * The supported configuration informations currently are:
 *
 * XXX TODO
 */

#define NVRAM_BLKSIZE	0x1000

struct nvram_triplet {
	uint64_t	dma_addr;
	uint32_t	blk_offset;
	uint32_t	blk_count;
} __packed;

#define NVRAM_FLAG_CLEAR_WPEND	0x80000000

enum nvram_state {
	NVRAM_STATE_CLOSED,
	NVRAM_STATE_OPENING,
	NVRAM_STATE_BROKEN,
	NVRAM_STATE_OPEN,
	NVRAM_STATE_ABSENT,
};

static void *nvram_image = (void *)NVRAM_BASE;
static uint32_t nvram_size;
static struct lock nvram_lock = LOCK_UNLOCKED;
static struct fsp_msg *nvram_msg;
static uint32_t nvram_dirty_start;
static uint32_t nvram_dirty_end;
static bool nvram_was_read;
static struct nvram_triplet nvram_triplet __align(0x1000);
static enum nvram_state nvram_state = NVRAM_STATE_CLOSED;

static void nvram_send_write(void);

static void nvram_wr_complete(struct fsp_msg *msg)
{
	struct fsp_msg *resp = msg->resp;
	uint8_t rc;

	lock(&nvram_lock);
	nvram_msg = NULL;
	opal_update_pending_evt(OPAL_EVENT_NVRAM, 0);

	/* Check for various errors. If an error occurred,
	 * we generally assume the nvram is completely dirty
	 * but we won't trigger a new write until we get
	 * either a new attempt at writing, or an FSP reset
	 * reload (TODO)
	 */
	if (!resp || resp->state != fsp_msg_response)
		goto fail_dirty;
	rc = (msg->word1 >> 8) & 0xff;
	switch(rc) {
	case 0:
	case 0x44:
		/* Sync to secondary required... XXX */
	case 0x45:
		break;
	case 0xef:
		/* Sync to secondary failed, let's ignore that for now,
		 * maybe when (if) we handle redundant FSPs ...
		 */
		prerror("FSP: NVRAM sync to secondary failed\n");
		break;
	default:
		prerror("FSP: NVRAM write return error 0x%02x\n", rc);
		goto fail_dirty;
	}
	fsp_freemsg(msg);
	if (nvram_dirty_start <= nvram_dirty_end)
		nvram_send_write();
	unlock(&nvram_lock);
	return;
 fail_dirty:
	nvram_dirty_start = 0;
	nvram_dirty_end = nvram_size - 1;
	fsp_freemsg(msg);
	unlock(&nvram_lock);
}

static void nvram_send_write(void)
{	uint32_t start = nvram_dirty_start;
	uint32_t end = nvram_dirty_end;
	uint32_t count;

	if (start > end || nvram_state != NVRAM_STATE_OPEN)
		return;
	count = (end - start) / NVRAM_BLKSIZE + 1;
	nvram_triplet.dma_addr = PSI_DMA_NVRAM_BODY + start;
	nvram_triplet.blk_offset = start / NVRAM_BLKSIZE;
	nvram_triplet.blk_count = count;
	nvram_msg = fsp_mkmsg(FSP_CMD_WRITE_VNVRAM, 6,
			      0, PSI_DMA_NVRAM_TRIPL, 1,
			      NVRAM_FLAG_CLEAR_WPEND, 0, 0);
	if (fsp_queue_msg(nvram_msg, nvram_wr_complete)) {
		fsp_freemsg(nvram_msg);
		nvram_msg = NULL;
		prerror("FSP: Error queueing nvram update\n");
		return;
	}
	nvram_dirty_start = nvram_size;
	nvram_dirty_end = 0;
	opal_update_pending_evt(OPAL_EVENT_NVRAM, OPAL_EVENT_NVRAM);
}

static void nvram_mark_dirty(uint64_t offset, uint64_t size)
{
	uint64_t end = offset + size - 1;

	offset &= ~(NVRAM_BLKSIZE - 1);
	end &= ~(NVRAM_BLKSIZE - 1);

	if (nvram_dirty_start > offset)
		nvram_dirty_start = offset;
	if (nvram_dirty_end < end)
		nvram_dirty_end = end;
	if (!nvram_msg)
		nvram_send_write();
}

static void nvram_rd_complete(struct fsp_msg *msg)
{
	int64_t rc;

	lock(&nvram_lock);

	/* Read complete, check status. What to do if the read fails ?
	 *
	 * Well, there could be various reasons such as an FSP reboot
	 * at the wrong time, but there is really not much we can do
	 * so for now I'll just mark the nvram as closed, and we'll
	 * attempt a re-open and re-read whenever the OS tries to
	 * access it
	 */
	rc = (msg->resp->word1 >> 8) & 0xff;
	nvram_msg = NULL;
	fsp_freemsg(msg);
	if (rc) {
		prerror("FSP: NVRAM read failed, will try again later\n");
		nvram_state = NVRAM_STATE_CLOSED;
	} else {
		/* nvram was read once, no need to do it ever again */
		nvram_was_read = true;
		nvram_state = NVRAM_STATE_OPEN;

		/* XXX Here we should look for nvram settings that concern
		 * us such as guest kernel arguments etc...
		 */
	}
	unlock(&nvram_lock);
}

static void nvram_send_read(void)
{
	nvram_msg = fsp_mkmsg(FSP_CMD_READ_VNVRAM, 4,
			      0, PSI_DMA_NVRAM_BODY, 0,
			      nvram_size / NVRAM_BLKSIZE);
	if (fsp_queue_msg(nvram_msg, nvram_rd_complete)) {
		/* If the nvram read fails to queue, we mark ourselves
		 * closed. Shouldn't have happened anyway. Not much else
		 * we can do.
		 */
		nvram_state = NVRAM_STATE_CLOSED;
		fsp_freemsg(nvram_msg);
		nvram_msg = NULL;
		prerror("FSP: Error queueing nvram read\n");
		return;
	}
}

static void nvram_open_complete(struct fsp_msg *msg)
{
	int8_t rc;

	lock(&nvram_lock);

	/* Open complete, check status */
	rc = (msg->resp->word1 >> 8) & 0xff;
	nvram_msg = NULL;
	fsp_freemsg(msg);
	if (rc) {
		prerror("FSP: NVRAM open failed, FSP error 0x%02x\n", rc);
		goto failed;
	}
	if (nvram_was_read)
		nvram_state = NVRAM_STATE_OPEN;
	else
		nvram_send_read();
	unlock(&nvram_lock);
	return;
 failed:
	nvram_state = NVRAM_STATE_CLOSED;
	unlock(&nvram_lock);
}

static void nvram_send_open(void)
{
	printf("FSP: Opening nvram...\n");
	nvram_msg = fsp_mkmsg(FSP_CMD_OPEN_VNVRAM, 1, nvram_size);
	assert(nvram_msg);
	nvram_state = NVRAM_STATE_OPENING;
	if (!fsp_queue_msg(nvram_msg, nvram_open_complete))
		return;

	prerror("FSP: Failed to queue nvram open message\n");
	fsp_freemsg(nvram_msg);
	nvram_msg = NULL;
	nvram_state = NVRAM_STATE_CLOSED;
}

static int64_t opal_nvram_check_state(void)
{
	switch(nvram_state) {
	case NVRAM_STATE_BROKEN:
		/* Broken nvram is currently irrecoverable */
		return OPAL_HARDWARE;
	case NVRAM_STATE_CLOSED:
		/* If the nvram is closed, try re-opening */
		nvram_send_open();
	case NVRAM_STATE_OPENING:
		return OPAL_BUSY;
	case NVRAM_STATE_ABSENT:
		return OPAL_UNSUPPORTED;
	default:
		break;
	}
	return OPAL_SUCCESS;
}

static int64_t opal_read_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	int64_t rc;

	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;

	lock(&nvram_lock);
	rc = opal_nvram_check_state();
	if (!rc)
		memcpy((void *)buffer, nvram_image + offset, size);
	unlock(&nvram_lock);

	return rc;
}
opal_call(OPAL_READ_NVRAM, opal_read_nvram);

static int64_t opal_write_nvram(uint64_t buffer, uint64_t size, uint64_t offset)
{
	int64_t rc;

	if (offset >= nvram_size || (offset + size) > nvram_size)
		return OPAL_PARAMETER;

	lock(&nvram_lock);
	rc = opal_nvram_check_state();
	if (!rc) {
		memcpy(nvram_image + offset, (void *)buffer, size);
		nvram_mark_dirty(offset, size);
	}
	unlock(&nvram_lock);

	return rc;
}
opal_call(OPAL_WRITE_NVRAM, opal_write_nvram);

static bool nvram_get_size(void)
{
	struct fsp_msg *msg;
	int rc, size;

	msg = fsp_mkmsg(FSP_CMD_GET_VNVRAM_SIZE, 0);
	rc = fsp_sync_msg(msg, false);
	size = msg->resp ? msg->resp->data.words[0] : 0;
	fsp_freemsg(msg);
	if (rc || size == 0) {
		prerror("FSP: Error %d querying nvram size\n", rc);
		nvram_state = NVRAM_STATE_BROKEN;
		return false;
	}
	printf("FSP: NVRAM file size is %d bytes\n", size);
	if (size > NVRAM_SIZE)
		size = NVRAM_SIZE;
	nvram_size = size;
	return true;
}

void fsp_nvram_init(void)
{
	if (!fsp_present()) {
		nvram_state = NVRAM_STATE_ABSENT;
		return;
	}

	/* Mark nvram as not dirty */
	nvram_dirty_start = nvram_size;
	nvram_dirty_end = 0;

	/* Map TCEs */
	fsp_tce_map(PSI_DMA_NVRAM_TRIPL, &nvram_triplet,
		    PSI_DMA_NVRAM_TRIPL_SZ);
	fsp_tce_map(PSI_DMA_NVRAM_BODY, nvram_image, PSI_DMA_NVRAM_BODY_SZ);

	/* Fetch the nvram size */
	if (!nvram_get_size())
		return;

	/* Start the opening sequence */
	lock(&nvram_lock);
	nvram_send_open();
	unlock(&nvram_lock);
}

/* This is called right before starting the payload (Linux) to
 * ensure the initial open & read of nvram has happened before
 * we transfer control as the guest OS. This is necessary as
 * Linux will not handle a OPAL_BUSY return properly and treat
 * it as an error
 */
void fsp_nvram_wait_open(void)
{
	if (!fsp_present())
		return;

	while(nvram_state == NVRAM_STATE_OPENING)
		fsp_poll();
}

void add_opal_nvram_node(struct dt_node *opal)
{
	struct dt_node *nvram;

	if (!fsp_present())
		return;

	nvram = dt_new(opal, "nvram");
	dt_add_property_cells(nvram, "#bytes", nvram_size);
	dt_add_property_string(nvram, "compatible", "ibm,opal-nvram");
}

