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

void main_cpu_entry(void)
{
	printf("SkiBoot starting...\n");

	/* First we Parse the PACA/PCIA and create the per-CPU
	 * structures. These are going to be needed everywhere
	 * (locks etc...) so this needs to be done first
	 */
	cpu_parse();

	/* Now locks can be used */
	init_locks();

	/* Early initializations of the FSP interface */
	fsp_init();

	/* Get ready to receive E0 class messages. We need to respond
	 * to some of these for the init sequence to make forward progress
	 */
	fsp_console_preinit();

	/* Start FSP/HV state controller & perform OPL */
	fsp_opl();

	op_display(OP_LOG, OP_MOD_INIT, 0x0000);

	/* Initialize XSCOM */
	xscom_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0001);

	/* Finish initializing the console */
	fsp_console_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

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

void secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	printf("INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	/* Secondary CPU called in */
	cpu_callin(cpu);

	/* Wait for work to do */
	while(true) {
		cpu_process_jobs();
		smt_low();
	}
}
