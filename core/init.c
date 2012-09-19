#include <skiboot.h>
#include <fsp.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
unsigned int boot_cpu_count __force_data = 0;

enum ipl_state {
	ipl_initial,
	ipl_opl_sent,
	ipl_got_continue,
} ipl_state = ipl_initial;

static bool state_control_msg(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	switch(cmd_sub_mod) {
	case FSP_CMD_CONTINUE_IPL:
		/* We get a CONTINUE_IPL as a response to OPL */
		printf("INIT: Got CONTINUE_IPL !\n");
		ipl_state = ipl_got_continue;
		free(msg);
		return true;

	case FSP_CMD_HV_STATE_CHG:
		printf("INIT: Got HV state change request to %d\n",
		       msg->data.bytes[0]);

		/* Send response synchronously for now, we might want to
		 * deal with that sort of stuff asynchronously if/when
		 * we add support for auto-freeing of messages
		 */
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_HV_STATE_CHG, 0), true);
	}
	return false;
}

static struct fsp_client state_control = {
	.message = state_control_msg,
};

static void start_fsp_state_control(void)
{
	/* Register for IPL/SERVICE messages */
	fsp_register_client(&state_control, FSP_MCLASS_IPL);

	/* Send OPL */
	ipl_state = ipl_opl_sent;
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_OPL, 0), true);
	while(ipl_state == ipl_opl_sent)
		fsp_poll();
	if (ipl_state != ipl_got_continue)
		prerror("INIT: Invalid IPL state, expected CONTINUE got %d\n",
			ipl_state);

	/* Send continue ACK */
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_CONTINUE_ACK, 0), true);
}

void main_cpu_entry(void)
{
	printf("SkiBoot starting...\n");

	/* Early initializations of the FSP interface */
	fsp_preinit();

	/* Start FSP/HV state controller */
	start_fsp_state_control();

	/* Nothing to do */
	while(true)
		fsp_poll();
}
