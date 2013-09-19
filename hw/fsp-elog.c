/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”).
 */

/*
 * This code will enable a feature of retrieving error log
 * from fsp-sapphire in sequence.
 * fsp sends next log only when sapphire sends new
 * log notification response to FSP.
 *
 * Completion of reading the log from FSP will result
 * in OPAL_EVENT_ERROR_LOG_AVAIL being signaled,
 * which will remain raised until it calls
 * opal_elog_read() and returns OPAL_SUCCESS,
 * at which point the operation is complete and
 * the event is cleared.
 */

/*
 * Design of error log :
 * When we receive a new error log entry notificatiion from FSP,
 * we create a list and we enqueue it into the "pending" list.
 * If the list was not empty, we start the fetching log from FSP.
 *
 * When Linux reads a log entry, we dequeue it from the "pending" list
 * and enqueue it to another "processed" list. At this point, if the
 * "pending" list is not empty, we start fetching next log.
 *
 * When Linux calls opal_resend_pending_logs(), we fetch the log
 * corresponding to the head of the pending list and move it to the
 * processed list, and continue this process this until the pending list is
 * empty. If the pending list was earlier empty and is now non-empty, we
 * initiate an error log fetch.
 *
 * When Linux acks an error log, we remove it from processed list.
 */

#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <cpu.h>
#include <lock.h>
#include <errno.h>
#include <psi.h>

/*
 * Maximum number of entries that are pre-allocated
 * to keep track of pending elogs to be fetched.
 */
#define	ELOG_MAX_RECORD		128
#define	ELOG_TYPE_PEL		0

/* Following variables are used to indicate state of the
 * head log entry which is being fetched from FSP and
 * these variables are not overwritten until next log is
 * retrieved from FSP.
 */
enum elog_head_state {
	ELOG_STATE_FETCHING,    /*In the process of reading log from FSP. */
	ELOG_STATE_FETCHED,     /* Indicates reading log from FSP completed */
	ELOG_STATE_NONE,        /* Indicates to fetch next log */
	ELOG_STATE_REJECTED,    /* resend all pending logs to linux */
};

/* structure to maintain log-id,log-size, pending and processed list */
struct fsp_log_entry {
	uint32_t log_id;
	size_t log_size;
	struct list_node link;
};

static LIST_HEAD(elog_pending);
static LIST_HEAD(elog_processed);
static LIST_HEAD(elog_free);
/*
 * lock is used to protect overwriting of processed and pending list
 * and also used while updating state of each log
 */
static struct lock elog_lock = LOCK_UNLOCKED;

/* log buffer  to copy FSP log */
static void *elog_buffer = (void *)ELOG_BUFFER_BASE;
static uint32_t elog_head_id;	/* FSP entry ID */
static uint32_t elog_head_size;	/* actual FSP log size */
static uint32_t elog_read_retries;	/* bad response status count */

/* Initialize the state of the log */
static enum elog_head_state elog_head_state = ELOG_STATE_NONE;

/* Need forward declaration because of Circular dependency */
static void fsp_elog_queue_fetch(void);

/*
 * check the response message for mbox acknowledgment
 * command send to FSP.
 */
static void fsp_elog_ack_complete(struct fsp_msg *msg)
{
	uint8_t val;

	if (!msg->resp)
		return;
	val = (msg->resp->word1 >> 8) & 0xff;
	if (val != 0)
		prerror("ELOG: Acknowledgment error\n");
	fsp_freemsg(msg);
}

/* send Error Log PHYP Acknowledgment to FSP with entry ID */
static int64_t fsp_send_elog_ack(uint32_t log_id)
{

	struct fsp_msg *ack_msg;

	ack_msg = fsp_mkmsg(FSP_CMD_ERRLOG_PHYP_ACK, 1, log_id);
	if (!ack_msg) {
		prerror("ELOG: Failed to allocate ack message\n");
		return OPAL_INTERNAL_ERROR;
	}
	if (fsp_queue_msg(ack_msg, fsp_elog_ack_complete)) {
		fsp_freemsg(ack_msg);
		ack_msg = NULL;
		prerror("ELOG: Error queueing elog ack complete\n");
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}

/* retrive error log from FSP with TCE for the data transfer */
static void fsp_elog_check_and_fetch_head(void)
{
	lock(&elog_lock);

	if (elog_head_state != ELOG_STATE_NONE || list_empty(&elog_pending)) {
		unlock(&elog_lock);
		return;
	}

	elog_read_retries = 0;

	/* Start fetching first entry from the pending list */
	fsp_elog_queue_fetch();

	unlock(&elog_lock);
}

/* this function should be called with the lock held */
static void fsp_elog_set_head_state(enum elog_head_state state)
{
	enum elog_head_state old_state = elog_head_state;

	elog_head_state = state;

	if (state == ELOG_STATE_FETCHED && old_state != ELOG_STATE_FETCHED)
		opal_update_pending_evt(OPAL_EVENT_ERROR_LOG_AVAIL,
					OPAL_EVENT_ERROR_LOG_AVAIL);
	if (state != ELOG_STATE_FETCHED && old_state == ELOG_STATE_FETCHED)
		opal_update_pending_evt(OPAL_EVENT_ERROR_LOG_AVAIL, 0);
}

/*
 * when we try maximum time of fetching log from fsp
 * we call following function to delete log from the
 * pending list and update the state to fetch next log
 *
 * this function should be called with the lock held
 */
void fsp_elog_fetch_failure(void)
{
	struct fsp_log_entry *log_data;

	/* read top list and delete the node */
	log_data = list_top(&elog_pending, struct fsp_log_entry, link);
	list_del(&log_data->link);
	list_add(&elog_free, &log_data->link);
	prerror("ELOG: received invalid data: %x\n", log_data->log_id);
	fsp_elog_set_head_state(ELOG_STATE_NONE);
}

/* Read response value from FSP for fetch sp data mbox command */
static void fsp_elog_read_complete(struct fsp_msg *read_msg)
{
	uint8_t val;
	/*struct fsp_log_entry *log_data;*/

	lock(&elog_lock);
	val = (read_msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(read_msg);

	switch (val) {
	case FSP_STATUS_SUCCESS:
		fsp_elog_set_head_state(ELOG_STATE_FETCHED);
		break;

	case FSP_STATUS_DMA_ERROR:
		if (elog_read_retries++ < 3) {
			/*
			 * for a error response value from FSP, we try to
			 * send fetch sp data mbox command again for three
			 * times if response from FSP is still not valid
			 * we send generic error response to fsp.
			 */
			fsp_elog_queue_fetch();
			break;
		}
		fsp_elog_fetch_failure();
		break;

	default:
		fsp_elog_fetch_failure();
	}
	if (elog_head_state == ELOG_STATE_REJECTED)
		fsp_elog_set_head_state(ELOG_STATE_NONE);
	unlock(&elog_lock);

	/* Check if a new log needs fetching */
	fsp_elog_check_and_fetch_head();
}

/* read error log from FSP through mbox commands */
static void fsp_elog_queue_fetch(void)
{
	int rc;
	uint8_t flags = 0;
	struct fsp_msg *elog_msg;
	struct fsp_log_entry *entry;

	entry = list_top(&elog_pending, struct fsp_log_entry, link);
	fsp_elog_set_head_state(ELOG_STATE_FETCHING);
	elog_head_id =  entry->log_id;
	elog_head_size = entry->log_size;

	elog_msg = fsp_mkmsg(FSP_CMD_FETCH_SP_DATA, 0x7,
			flags << 16 | FSP_DATASET_ERRLOG, elog_head_id, 0,
			0, PSI_DMA_ERRLOG_BUF, elog_head_size);
	if (!elog_msg) {
		prerror("ELOG: failed to allocate read message\n");
		fsp_elog_set_head_state(ELOG_STATE_NONE);
		return;
	}
	rc = fsp_queue_msg(elog_msg, fsp_elog_read_complete);
	if (rc) {
		fsp_freemsg(elog_msg);
		prerror("ELOG: failed to queue read message: %d\n", rc);
		fsp_elog_set_head_state(ELOG_STATE_NONE);
	}
	return;
}

/* opal interface for powrnv to read log ize and log ID from sapphire */
static int64_t fsp_opal_elog_info(uint64_t *opla_elog_id,
				size_t *opal_elog_size,	uint64_t *elog_type)
{
	struct fsp_log_entry *log_data;

	/* copy type of the error log */
	*elog_type = ELOG_TYPE_PEL;

	lock(&elog_lock);
	if (elog_head_state != ELOG_STATE_FETCHED) {
		unlock(&elog_lock);
		return OPAL_WRONG_STATE;
	}
	log_data = list_top(&elog_pending, struct fsp_log_entry, link);
	*opla_elog_id = log_data->log_id;
	*opal_elog_size = log_data->log_size;
	unlock(&elog_lock);
	return OPAL_SUCCESS;
}

/* opal interface for powrnv to read log from sapphire */
static int64_t fsp_opal_elog_read(uint64_t *buffer, size_t opal_elog_size,
				  uint64_t opla_elog_id)
{
	struct fsp_log_entry *log_data;

	/*
	 * Read top entry from list.
	 * as we know always top record of the list is fetched from FSP
	 */
	lock(&elog_lock);
	if (elog_head_state != ELOG_STATE_FETCHED) {
		unlock(&elog_lock);
		return OPAL_WRONG_STATE;
	}

	log_data = list_top(&elog_pending, struct fsp_log_entry, link);

	/* Check log ID and log size are same and then read log from buffer */
	if ((opla_elog_id != log_data->log_id) &&
				(opal_elog_size != log_data->log_size))
		return OPAL_PARAMETER;

	memcpy((void *)buffer, elog_buffer, opal_elog_size);

	/*
	 * once log is read from linux move record from pending
	 * to processed list and delete record from pending list
	 * and change state of the log to fetch next record
	 */
	list_del(&log_data->link);
	list_add(&elog_processed, &log_data->link);
	fsp_elog_set_head_state(ELOG_STATE_NONE);
	unlock(&elog_lock);


	/* read error log from FSP */
	fsp_elog_check_and_fetch_head();

	return OPAL_SUCCESS;
}

/* set state of the log head before fetching the log */
static void elog_reject_head(void)
{
	if (elog_head_state == ELOG_STATE_FETCHING)
		fsp_elog_set_head_state(ELOG_STATE_REJECTED);
	if (elog_head_state == ELOG_STATE_FETCHED)
		fsp_elog_set_head_state(ELOG_STATE_NONE);
}

/* opal Interface for powernv to send ack to fsp with log ID */
static int64_t fsp_opal_elog_ack(uint64_t ack_id)
{
	int rc = 0;
	struct fsp_log_entry  *record, *next_record;

	/* Send acknowledgement to FSP */
	rc = fsp_send_elog_ack(ack_id);
	if (rc != OPAL_SUCCESS) {
		prerror("ELOG: failed to send acknowledgement: %d\n", rc);
		return rc;
	}
	lock(&elog_lock);
	if (ack_id == elog_head_id)
		elog_reject_head();
	list_for_each_safe(&elog_pending, record, next_record, link) {
		if (record->log_id != ack_id)
			continue;
		list_del(&record->link);
		list_add(&elog_free, &record->link);
	}
	list_for_each_safe(&elog_processed, record, next_record, link) {
		if (record->log_id != ack_id)
			continue;
		list_del(&record->link);
		list_add(&elog_free, &record->link);
	}
	unlock(&elog_lock);

	return rc;
}

/*
 * once linux kexec's it ask to resend all logs which
 * are not acknowledged from  linux
 */
static void fsp_opal_resend_pending_logs(void)
{
	struct fsp_log_entry  *entry;

	lock(&elog_lock);

	/*
	 * If processed list is not empty add all record from
	 * processed list to pending list at head of the list
	 * and delete records from processed list.
	 */
	while (!list_empty(&elog_processed)) {
		entry = list_pop(&elog_processed, struct fsp_log_entry, link);
		list_add(&elog_pending, &entry->link);
	}

	/*
	 * If the current fetched or fetching log doesn't match our
	 * new pending list head, then reject it
	 */
	if (!list_empty(&elog_pending)) {
		entry = list_top(&elog_pending, struct fsp_log_entry, link);
		if (entry->log_id != elog_head_id)
			elog_reject_head();
	}

	unlock(&elog_lock);

	/* Read error log from FSP if needed */
	fsp_elog_check_and_fetch_head();
}

/* fsp elog notify function  */
static bool fsp_elog_msg(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	int rc = 0;
	struct fsp_log_entry  *record;
	uint32_t log_id;
	uint32_t log_size;


	if (cmd_sub_mod != FSP_CMD_ERRLOG_NOTIFICATION)
		return false;

	log_id = msg->data.words[0];
	log_size = msg->data.words[1];

	printf("ELOG: Notified of log 0x%08x (size: %d)\n",
	       log_id, log_size);

	/* take a lock until we take out the node from elog_free */
	lock(&elog_lock);
	if (!list_empty(&elog_free)) {
		/* Create a new entry in the pending list */
		record = list_pop(&elog_free, struct fsp_log_entry, link);
		list_del(&record->link);
		record->log_id = log_id;
		record->log_size = log_size;
		list_add_tail(&elog_pending, &record->link);
		unlock(&elog_lock);

		/* Send response back to FSP for a new elog notify message */
		rc = fsp_queue_msg(fsp_mkmsg(FSP_RSP_ERRLOG_NOTIFICATION,
					1, log_id), fsp_freemsg);
		if (rc)
			prerror("ELOG: Failed to queue errlog notification"
				" response: %d\n", rc);

		/* read error log from FSP */
		fsp_elog_check_and_fetch_head();

	} else {
		printf("ELOG: Log entry 0x%08x discarded\n", log_id);

		/* unlock if elog_free is empty */
		unlock(&elog_lock);
		/*
		 * if list is full with max record then we
		 * send discarded by phyp ack to FSP, so that once list is
		 * empty we can read the log again.
		 */
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_ERRLOG_PHYP_ACK | 0x01,
				1, log_id), fsp_freemsg);
		if (rc)
			prerror("ELOG: Failed to queue errlog notification"
				" response: %d\n", rc);
	}

	return true;
}

static struct fsp_client fsp_get_elog_notify = {
	.message = fsp_elog_msg,
};

/* pre allocate memory for error log list for 128 records */
static int init_elog_free_list(uint32_t num_entries)
{
	struct fsp_log_entry *entry;
	int i;

	entry = zalloc(sizeof(struct fsp_log_entry) * num_entries);
	if (!entry)
		goto out_err;

	for (i = 0; i < num_entries; ++i) {
		list_add_tail(&elog_free, &entry->link);
		entry++;
	}
	return 0;
out_err:
	return -ENOMEM;
}

/* fsp elog init function */
void fsp_elog_init(void)
{
	int val = 0;

	if (!fsp_present())
		return;

	/* Map TCEs */
	fsp_tce_map(PSI_DMA_ERRLOG_BUF, elog_buffer, PSI_DMA_ERRLOG_BUF_SZ);

	/* pre allocate memory for 128 record */
	val = init_elog_free_list(ELOG_MAX_RECORD);
	if (val != 0)
		return;

	/* register Eror log Class D2 */
	fsp_register_client(&fsp_get_elog_notify, FSP_MCLASS_ERR_LOG);

	/* register opal Interface */
	opal_register(OPAL_ELOG_READ, fsp_opal_elog_read, 3);
	opal_register(OPAL_ELOG_ACK, fsp_opal_elog_ack, 1);
	opal_register(OPAL_ELOG_RESEND, fsp_opal_resend_pending_logs, 0);
	opal_register(OPAL_ELOG_SIZE, fsp_opal_elog_info, 3);
}
