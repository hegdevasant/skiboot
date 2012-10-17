#include <skiboot.h>
#include <spira.h>
#include <fsp.h>
#include <memory.h>
#include <chiptod.h>
#include <cpu.h>
#include <processor.h>
#include <xscom.h>
#include <device_tree.h>
#include <opal.h>
#include <elf.h>
#include <cec.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
enum ipl_state ipl_state = ipl_initial;

static uint64_t kernel_entry;
static uint64_t kernel_top;
static void *fdt;
bool cec_ipl_temp_side;

static void fetch_global_params(void)
{
	/* Get CEC IPL side from IPLPARAMS */
	const void *iplp = spira.ntuples.ipl_parms.addr;

	if (iplp && HDIF_check(iplp, "IPLPMS")) {
		const struct iplparams_iplparams *p;

		p = HDIF_get_idata(iplp, IPLPARAMS_IPLPARAMS, NULL);
		if (CHECK_SPPTR(p)) {
			if (p->ipl_side & IPLPARAMS_CEC_FW_IPL_SIDE_TEMP) {
				cec_ipl_temp_side = true;
				printf("FSP: CEC IPLed from Temp side\n");
			} else {
				cec_ipl_temp_side = false;
				printf("FSP: CEC IPLed from Perm side\n");
			}
		} else
			prerror("FSP: Invalid IPL params, assuming P side\n");
	} else
		prerror("FSP: Can't find IPL params, assuming P side\n");

}

/* LID numbers. For now we hijack some of pHyp's own until i figure
 * out the whole business with the MasterLID
 */
#define KERNEL_LID	0x80a00701

static bool load_kernel(void)
{
	struct elf64_hdr *kh = (void *)KERNEL_LOAD_BASE;
	struct elf64_phdr *ph;
	unsigned int i;
	uint32_t lid;
	size_t ksize;

	ksize = KERNEL_LOAD_SIZE;
	lid = KERNEL_LID;
	if (cec_ipl_temp_side)
		lid |= 0x8000;
	fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid, 0,
		       (void *)KERNEL_LOAD_BASE, &ksize);

	printf("INIT: Kernel loaded, size: %ld bytes\n", ksize);

	/* Check it's a ppc64 ELF */
	if (kh->ei_ident != ELF_IDENT		||
	    kh->ei_class != ELF_CLASS_64	||
	    kh->ei_data != ELF_DATA_MSB		||
	    kh->e_machine != ELF_MACH_PPC64) {
		prerror("INIT: Kernel doesn't look like an ppc64 ELF\n");
		return false;
	}

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf64_phdr *)(KERNEL_LOAD_BASE + kh->e_phoff);
	for (i = 0; i < kh->e_phnum; i++, ph++) {
		if (ph->p_type != ELF_PTYPE_LOAD)
			continue;
		if (ph->p_vaddr > kh->e_entry ||
		    (ph->p_vaddr + ph->p_memsz) < kh->e_entry)
			continue;

		/* Get our entry */
		kernel_entry = kh->e_entry - ph->p_vaddr + ph->p_offset;
		break;
	}

	if (!kernel_entry) {
		prerror("INIT: Failed to find kernel entry !\n");
		return false;
	}
	kernel_entry += KERNEL_LOAD_BASE;
	kernel_top = KERNEL_LOAD_BASE + ksize;

	printf("INIT: Kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

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

	/* Initialize XSCOM */
	xscom_init();

	/* Early initializations of the FSP interface */
	fsp_init();

	/* Collect some global parameters from SPIRA */
	fetch_global_params();

	/* Get ready to receive E0 class messages. We need to respond
	 * to some of these for the init sequence to make forward progress
	 */
	fsp_console_preinit();

	/* Start FSP/HV state controller & perform OPL */
	fsp_opl();

	op_display(OP_LOG, OP_MOD_INIT, 0x0000);

	/* Finish initializing the console */
	fsp_console_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0001);

	/* Call in secondary CPUs */
	cpu_bringup();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/* Enable timebase synchronization */
	chiptod_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0003);

	/* Parse the memory layout. */
	memory_parse();

	op_display(OP_LOG, OP_MOD_INIT, 0x0004);

	/* Initialize CEC hardware. This will also call out into
	 * Hubs, daugher cards etc... as needed and will take care
	 * of the IO Hubs
	 */
	cec_init();

	/* Create the OPAL call table */
	opal_table_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0005);

	/* Load kernel LID */
	if (!load_kernel()) {
		op_display(OP_FATAL, OP_MOD_INIT, 1);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x0006);

	/* Create the device tree blob to boot OS. */
	fdt = create_dtb();
	if (!fdt) {
		op_display(OP_FATAL, OP_MOD_INIT, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x0007);

	/* Start the kernel */
	cpu_give_self_os();
	start_kernel(kernel_entry, fdt);
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
