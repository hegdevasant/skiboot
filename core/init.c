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
#include <device.h>
#include <libfdt/libfdt.h>


/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
enum ipl_state ipl_state = ipl_initial;

static uint64_t kernel_entry;
static uint64_t kernel_top;
static void *fdt;
struct dt_node *dt_root;

/* LID numbers. For now we hijack some of pHyp's own until i figure
 * out the whole business with the MasterLID
 */
#define KERNEL_LID_PHYP	0x80a00701
#define KERNEL_LID_OPAL	0x80a00701 /* XXX FIXME */

static bool load_kernel(void)
{
	struct elf64_hdr *kh = (void *)KERNEL_LOAD_BASE;
	struct elf64_phdr *ph;
	struct dt_node *iplp;
	unsigned int i;
	uint32_t lid;
	size_t ksize;
	const char *side = NULL;

	ksize = KERNEL_LOAD_SIZE;

	if (!strcmp(dt_prop_get(dt_root, "lid-type"), "opal"))
		lid = KERNEL_LID_OPAL;
	else
		lid = KERNEL_LID_PHYP;

	iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
	if (iplp)
		side = dt_prop_get_def(iplp, "cec-ipl-side", NULL);
	if (!side || !strcmp(side, "temp"))
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

void load_and_boot_kernel(bool is_reboot)
{
	const struct dt_property *memprop;
	uint64_t mem_top;

	memprop = dt_find_property(dt_root, DT_PRIVATE "maxmem");
	mem_top = (u64)dt_property_get_cell(memprop, 0) << 32
		| dt_property_get_cell(memprop, 1);

	op_display(OP_LOG, OP_MOD_INIT, 0x0006);

	/* Load kernel LID */
	if (!load_kernel()) {
		op_display(OP_FATAL, OP_MOD_INIT, 1);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x0006);

	/* We wait for the nvram read to complete here so we can
	 * grab stuff from there such as the kernel arguments
	 */
	if (!is_reboot)
		fsp_nvram_wait_open();

	op_display(OP_LOG, OP_MOD_INIT, 0x0007);

	/* Create the device tree blob to boot OS. */
	fdt = create_dtb(dt_root);
	if (!fdt) {
		op_display(OP_FATAL, OP_MOD_INIT, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_INIT, 0x0008);

	/* Start the kernel */
	if (!is_reboot)
		op_panel_disable_src_echo();
	cpu_give_self_os();

	printf("INIT: Starting kernel at 0x%llx\n", kernel_entry);

	fdt_set_boot_cpuid_phys(fdt, this_cpu()->pir);
	start_kernel(kernel_entry, fdt, mem_top);
}

void main_cpu_entry(const void *fdt)
{
	printf("SkiBoot %s starting...\n", gitid);

	/* Initialize boot cpu's cpu_thread struct */
	init_boot_cpu();

	/* Now locks can be used */
	init_locks();

	/*
	 * If we are coming in with a flat device-tree, we expand it
	 * now. Else look for HDAT and create a device-tree from them
	 *
	 * Hack alert: When entering via the OPAL entry point, fdt
	 * is set to -1, we record that and pass it to parse_hdat
	 */
	if (fdt == (void *)-1ul)
		parse_hdat(true);
	else if (fdt == NULL)
		parse_hdat(false);
	else
		dt_expand(fdt);

	/* Initialize the rest of the cpu thread structs */
	init_all_cpus();

	/* Initialize XSCOM */
	xscom_init();

	/* Early initializations of the FSP interface */
	fsp_init();

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

	/* Initialize nvram access */
	fsp_nvram_init();

	/* Call in secondary CPUs */
	cpu_bringup();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/* Enable timebase synchronization */
	chiptod_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0003);

	op_display(OP_LOG, OP_MOD_INIT, 0x0004);

	/* Initialize CEC hardware. This will also call out into
	 * Hubs, daugher cards etc... as needed and will take care
	 * of the IO Hubs
	 */
	cec_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0005);

	/* Create the OPAL call table */
	opal_table_init();

	/* Add OPAL-specific node to dt_root before booting the kernel
	 *
	 * Note: This must be done fairly late as it has to account for
	 * various memory reservations done in previous stages of the
	 * boot process.
	 */
	add_opal_nodes();

	load_and_boot_kernel(false);
}

void __secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	/* Secondary CPU called in */
	cpu_callin(cpu);

	/* Wait for work to do */
	while(true) {
		cpu_process_jobs();
		smt_low();
	}
}

void secondary_cpu_entry(void)
{
	struct cpu_thread *cpu = this_cpu();

	printf("INIT: CPU PIR 0x%04x called in\n", cpu->pir);

	__secondary_cpu_entry();
}

