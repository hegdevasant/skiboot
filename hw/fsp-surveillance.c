#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <processor.h>
#include <timebase.h>
#include <opal.h>
#include <fsp-sysparam.h>

static bool fsp_surv_state = false;
static u64 surv_timer;
static u32 fsp_surv_ack_pend_cnt;
static u32 surv_state_param;
static struct lock surv_lock = LOCK_UNLOCKED;

static void fsp_surv_ack(struct fsp_msg *msg __unused)
{
	/*
	 * We just reset the pending flag.
	 *
	 * We may need to do more -- a host initiated reset needs
	 * to be initiated after a number of pending surveillance
	 * acks.
	 */
	printf("SURV: Received heartbeat acknowledge from FSP\n");

	lock(&surv_lock);
	if (fsp_surv_ack_pend_cnt)
		fsp_surv_ack_pend_cnt--;
	unlock(&surv_lock);
}


/* Send surveillance heartbeat based on a timebase trigger */
static void fsp_surv_hbeat(void)
{
	u64 now = mftb();

	/* add timebase callbacks */
	/*
	 * XXX This packet needs to be pushed to FSP in an interval
	 * less than 120s that's advertised to FSP.
	 *
	 * Verify if the command building format and call is fine.
	 */
	if (surv_timer == 0 ||
	    (tb_compare(now, surv_timer) == TB_AAFTERB) ||
	    (tb_compare(now, surv_timer) == TB_AEQUALB)) {
		printf("Sending the hearbeat command to FSP\n");
		fsp_queue_msg(fsp_mkmsg(FSP_CMD_SURV_HBEAT, 1, 120),
			      fsp_surv_ack);
		/*
		 * In future, if the count exceeds a certain threshold
		 * we will need to issue a host initiated reboot to FSP
		 */
		fsp_surv_ack_pend_cnt++;
		surv_timer = now + secs_to_tb(110);

		/* Handle the timer wrapping around */
		if (tb_compare(surv_timer, secs_to_tb(110)) == TB_ABEFOREB)
			surv_timer = secs_to_tb(110) - surv_timer;
	}
}

static void fsp_surv_poll(void *data __unused)
{
	if (!fsp_surv_state)
		return;
	lock(&surv_lock);
	fsp_surv_hbeat();
	unlock(&surv_lock);
}

static void fsp_surv_got_param(uint32_t param_id __unused, int err_len,
			       void *data __unused)
{
	if (err_len != 4) {
		prerror("SURV: Error retreiving surveillance status: %d\n",
			err_len);
		return;
	}
	printf("SURV: Status from FSP: %d\n", surv_state_param);
	if (!(surv_state_param & 0x01))
		return;

	lock(&surv_lock);
	fsp_surv_state = true;

	/* Also send one heartbeat now. The next one will not happen
	 * until we hit the OS.
	 */
	fsp_surv_hbeat();
	unlock(&surv_lock);
}

static void fsp_surv_query(void)
{
	int rc;

	printf("SURV: Querying FSP's surveillance status\n");

	/* Reset surveillance settings */
	lock(&surv_lock);
	fsp_surv_state = false;
	surv_timer = 0;
	fsp_surv_ack_pend_cnt = 0;
	unlock(&surv_lock);

	/* Query FPS for surveillance state */
	rc = fsp_get_sys_param(SYS_PARAM_SURV, &surv_state_param, 4,
			       fsp_surv_got_param, NULL);
	if (rc)
		prerror("SURV: Error %d queueing param request\n", rc);
}

/* This is called at boot time */
void fsp_init_surveillance(void)
{
	/* Always register the poller, so we don't have to add/remove
	 * it on reset-reload or change of surveillance state. Also the
	 * poller list has no locking so we don't want to play with it
	 * at runtime.
	 */
	opal_add_poller(fsp_surv_poll, NULL);

	/* Send query to FSP */
	fsp_surv_query();
}

