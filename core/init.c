#include <skiboot.h>
#include <fsp.h>
#include <memory.h>
#include <chiptod.h>
#include <cpu.h>
#include <processor.h>
#include <xscom.h>
#include <device_tree.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
enum ipl_state ipl_state = ipl_initial;

static bool state_control_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	switch(cmd_sub_mod) {
	case FSP_CMD_CONTINUE_IPL:
		/* We get a CONTINUE_IPL as a response to OPL */
		printf("INIT: Got CONTINUE_IPL !\n");
		ipl_state |= ipl_got_continue;
		return true;

	case FSP_CMD_HV_STATE_CHG:
		printf("INIT: Got HV state change request to %d\n",
		       msg->data.bytes[0]);

		/* Send response synchronously for now, we might want to
		 * deal with that sort of stuff asynchronously if/when
		 * we add support for auto-freeing of messages
		 */
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_HV_STATE_CHG, 0), true);
		return true;

	case FSP_CMD_SP_NEW_ROLE:
		/* FSP is assuming a new role */
		printf("INIT: FSP assuming new role\n");
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_SP_NEW_ROLE, 0), true);
		ipl_state |= ipl_got_new_role;
		return true;

	case FSP_CMD_SP_QUERY_CAPS:
		printf("INIT: FSP query capabilities\n");
		/* XXX Do something saner. For now do a synchronous
	         * response and hard code our capabilities
		 */
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_SP_QUERY_CAPS, 4,
				       0x3ff80000, 0, 0, 0), true);
		ipl_state |= ipl_got_caps;
		return true;
	case FSP_CMD_FSP_FUNCTNAL:
		printf("INIT: Got FSP Functional\n");
		ipl_state |= ipl_got_fsp_functional;
		return true;
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
	ipl_state |= ipl_opl_sent;
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_OPL, 0), true);
	while(!(ipl_state & ipl_got_continue))
		fsp_poll();

	/* Send continue ACK */
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_CONTINUE_ACK, 0), true);

	/* Wait for various FSP messages */
	printf("INIT: Waiting for FSP to advertize new role...\n");
	while(!(ipl_state & ipl_got_new_role))
		fsp_poll();
	printf("INIT: Waiting for FSP to request capabilities...\n");
	while(!(ipl_state & ipl_got_caps))
		fsp_poll();

	/* Tell FSP we are in standby */
	printf("INIT: Sending HV Functional: Standby...\n");
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_HV_FUNCTNAL, 1, 0x01000000), true);

	/* Wait for FSP functional */
	printf("INIT: Waiting for FSP functional\n");
	while(!(ipl_state & ipl_got_fsp_functional))
		fsp_poll();

	/* Tell FSP we are in running state */
	printf("INIT: Sending HV Functional: Runtime...\n");
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_HV_FUNCTNAL, 1, 0x02000000), true);
}


void main_cpu_entry(void)
{
	printf("SkiBoot starting...\n");

	/* Early initializations of the FSP interface */
	fsp_init();

	/* Get ready to receive E0 class messages. We need to respond
	 * to some of these for the init sequence to make forward progress
	 */
	fsp_console_preinit();

	/* Start FSP/HV state controller & perform OPL */
	start_fsp_state_control();

	op_display(OP_LOG, OP_MOD_INIT, 0x0000);

	/* Initialize XSCOM */
	xscom_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0001);

	/* Finish initializing the console */
	fsp_console_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/* Parse the PACA/PCIA */
	cpu_parse();

	op_display(OP_LOG, OP_MOD_INIT, 0x0003);

	/* Call in secondary CPUs */
	cpu_bringup();

	op_display(OP_LOG, OP_MOD_INIT, 0x0004);

	/* Enable timebase synchronization */
	chiptod_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0005);

	/* Parse the memory layout. */
	memory_parse();

	op_display(OP_LOG, OP_MOD_INIT, 0x9999);

	/* Create the device tree blob to boot OS. */
	create_dtb();

	/* Nothing to do */
	while(true) {
		cpu_process_jobs();
		fsp_poll();
	}
}

void secondary_cpu_entry(struct cpu_thread *cpu)
{
	printf("INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	/* Secondary CPU called in */
	cpu_callin(cpu);

	/* Wait for work to do */
	while(true) {
		cpu_process_jobs();
		smt_low();
	}
}
