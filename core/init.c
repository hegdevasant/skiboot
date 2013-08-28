/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <fsp.h>
#include <fsp-sysparam.h>
#include <psi.h>
#include <memory.h>
#include <chiptod.h>
#include <nx.h>
#include <cpu.h>
#include <processor.h>
#include <xscom.h>
#include <device_tree.h>
#include <opal.h>
#include <elf.h>
#include <cec.h>
#include <device.h>
#include <pci.h>
#include <lpc.h>
#include <chip.h>
#include <interrupts.h>
#include <mem_region.h>
#include <trace.h>
#include <libfdt/libfdt.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
enum ipl_state ipl_state = ipl_initial;
enum proc_gen proc_gen;

static uint64_t kernel_entry;
static uint64_t kernel_top;
static bool kernel_32bit;
static void *fdt;

static bool try_load_elf64(struct elf_hdr *header, size_t ksize)
{
	struct elf64_hdr *kh = (struct elf64_hdr *)header;
	uint64_t load_base = (uint64_t)kh;
	struct elf64_phdr *ph;
	unsigned int i;

	/* Check it's a ppc64 ELF */
	if (kh->ei_ident != ELF_IDENT		||
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
	ph = (struct elf64_phdr *)(load_base + kh->e_phoff);
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
	kernel_entry += load_base;
	kernel_top = load_base + ksize;
	kernel_32bit = false;

	printf("INIT: 64-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

static bool try_load_elf32(struct elf_hdr *header, size_t ksize)
{
	struct elf32_hdr *kh;
	struct elf32_phdr *ph;
	unsigned int i;
	uint64_t load_base;

	/* Check it's a ppc32 ELF */
	if (header->ei_ident != ELF_IDENT		||
	    header->ei_data != ELF_DATA_MSB		||
	    header->e_machine != ELF_MACH_PPC32) {
		prerror("INIT: Kernel doesn't look like an ppc32 ELF\n");
		return false;
	}

	/* Move kernel to higher up since it's likely to be a zImage
	 * wrapper which doesn't like too much being down low
	 */
	memmove((void *)KERNEL_STRADALE_BASE, header, ksize);
	kh = (struct elf32_hdr *)KERNEL_STRADALE_BASE;
	load_base = KERNEL_STRADALE_BASE;

	/* Look for a loadable program header that has our entry in it
	 *
	 * Note that we execute the kernel in-place, we don't actually
	 * obey the load informations in the headers. This is expected
	 * to work for the Linux Kernel because it's a fairly dumb ELF
	 * but it will not work for any ELF binary.
	 */
	ph = (struct elf32_phdr *)(load_base + kh->e_phoff);
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

	kernel_entry += load_base;
	kernel_top = load_base + ksize;
	kernel_32bit = true;

	printf("INIT: 32-bit kernel entry at 0x%llx\n", kernel_entry);

	return true;
}

/* LID numbers. For now we hijack some of pHyp's own until i figure
 * out the whole business with the MasterLID
 */
#define KERNEL_LID_PHYP	0x80a00701
#define KERNEL_LID_OPAL	0x80f00101

static bool load_kernel(void)
{
	uint64_t load_base;
	struct elf_hdr *kh;
	struct dt_node *iplp;
	uint32_t lid;
	size_t ksize;
	const char *ltype, *side = NULL;

	ltype = dt_prop_get_def(dt_root, "lid-type", NULL);

	/* No lid-type, assume stradale, currently pre-loaded at fixed
	 * address
	 */
	if (!ltype) {
		load_base = KERNEL_STRADALE_BASE;
		ksize = KERNEL_STRADALE_SIZE;
		printf("No lid-type property, assuming FSP-less setup\n");
	} else {
		uint32_t sidemask = 0;

		/* Get flash side */
		iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
		if (iplp)
			side = dt_prop_get_def(iplp, "cec-ipl-side", NULL);
		if (!side || !strcmp(side, "temp"))
			sidemask |= 0x8000;

		load_base = KERNEL_LOAD_BASE;
		ksize = KERNEL_LOAD_SIZE;

		/* First try to load an OPAL secondary LID always */
		lid = KERNEL_LID_OPAL | sidemask;
		printf("Trying to load OPAL secondary LID...\n");
		if (fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid, 0,
				   (void *)load_base, &ksize) != 0) {	
			if (!strcmp(ltype, "opal")) {
				prerror("Failed to load in OPAL mode...\n");
				return false;
			}
			printf("Trying to load as PHYP LID...\n");
			lid = KERNEL_LID_PHYP | sidemask;
			ksize = KERNEL_LOAD_SIZE;
			if (fsp_fetch_data(0, FSP_DATASET_NONSP_LID, lid, 0,
					   (void *)load_base, &ksize) != 0) {	
				prerror("Failed to load kernel\n");
				return false;
			}
		}
	}

	printf("INIT: Kernel loaded, size: %zu bytes\n", ksize);

	kh = (struct elf_hdr *)load_base;
	if (kh->ei_class == ELF_CLASS_64)
		return try_load_elf64(kh, ksize);
	else if (kh->ei_class == ELF_CLASS_32)
		return try_load_elf32(kh, ksize);

	printf("INIT: Neither ELF32 not ELF64 ?\n");
	return false;
}

void load_and_boot_kernel(bool is_reboot)
{
	const struct dt_property *memprop;
	uint64_t mem_top;

	memprop = dt_find_property(dt_root, DT_PRIVATE "maxmem");
	if (memprop)
		mem_top = (u64)dt_property_get_cell(memprop, 0) << 32
			| dt_property_get_cell(memprop, 1);
	else /* XXX HB hack, might want to calc it */
		mem_top = 0x40000000;

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
	fsp_console_select_stdout();

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

	printf("INIT: Starting kernel at 0x%llx, fdt at %p\n",
	       kernel_entry, fdt);

	fdt_set_boot_cpuid_phys(fdt, this_cpu()->pir);
	if (kernel_32bit)
		start_kernel32(kernel_entry, fdt, mem_top);
	start_kernel(kernel_entry, fdt, mem_top);
}

static void dt_fixup_psi(uint32_t chip_id)
{
	uint64_t psibar;
	struct dt_node *node;

	/* Read PSI BAR */
	if (xscom_read(chip_id, 0x201090A, &psibar)) {
		prerror("DT_FIXUP: Error reading PSI BAR\n");
		return;
	}
	printf("DT_FIXUP: PSI on chip %d BAR: %llx\n", chip_id, psibar);
	psibar &= ~1ull;

	/* XXX Should check for valid bit ? */
	node = dt_new_addr(dt_root, "psi", psibar);
	dt_add_property_cells(node, "reg", hi32(psibar), lo32(psibar), 1, 0);
	dt_add_property_strings(node, "compatible", "ibm,psi","ibm,power8-psi");
	dt_add_property_cells(node, "interrupt-parent", get_ics_phandle());
	dt_add_property_cells(node, "interrupts", get_psi_interrupt(chip_id));
	dt_add_property_cells(node, "ibm,chip-id", chip_id);
	dt_add_property_strings(node, "status", "ok");
}

static void dt_fixups(void)
{
	struct dt_node *n;
	struct dt_node *primary_lpc = NULL;

	/* Missing PSI bridges on P8 */
	if (proc_gen == proc_gen_p8) {
		struct proc_chip *chip;

		for_each_chip(chip) {
			n = dt_find_compatible_node_on_chip(dt_root, NULL,
							    "ibm,psi",
							    chip->id);
			if (!n)
				dt_fixup_psi(chip->id);
		}
	}

	/* lpc node missing #address/size cells. Also pick one as
	 * primary for now (TBD: How to convey that from HB)
	 */
	dt_for_each_compatible(dt_root, n, "ibm,power8-lpc") {
		if (!primary_lpc || dt_has_node_property(n, "primary", NULL))
			primary_lpc = n;
		if (dt_has_node_property(n, "#address-cells", NULL))
			break;
		dt_add_property_cells(n, "#address-cells", 2);
		dt_add_property_cells(n, "#size-cells", 1);
		dt_add_property_strings(n, "status", "ok");
	}

	/* Missing UART in simics. Assume first/only LPC */
	if (primary_lpc) {
		/* Check if the "primary" property is missing */
		if (!dt_has_node_property(primary_lpc, "primary", NULL))
			dt_add_property(primary_lpc, "primary", NULL, 0);
	}

#ifdef ADD_SIMICS_LPC_UART
	if (primary_lpc) {
		/*
		 * The official OF ISA/LPC binding is a bit odd, it prefixes
		 * the unit address for IO with "i". It uses 2 cells, the first
		 * one indicating IO vs. Memory space (along with bits to
		 * represent aliasing).
		 *
		 * We pickup that binding and add to it "2" as a indication
		 * of FW space.
		 *
		 * TODO: Probe the UART instead ...
		 */
		struct dt_node *uart;
		char namebuf[32];
#define UART_IO_BASE	0x3f8
#define UART_IO_COUNT	8

		sprintf(namebuf, "serial@i%x", UART_IO_BASE);
		uart = dt_new(primary_lpc, namebuf);

		dt_add_property_cells(uart, "reg",
				      1, /* IO space */
				      UART_IO_BASE, UART_IO_COUNT);
		dt_add_property_strings(uart, "compatible",
					"ns16550",
					"pnpPNP,501");
		dt_add_property_cells(uart, "clock-frequency", 1843200);
		dt_add_property_cells(uart, "current-speed", 115200);

		/*
		 * This is needed by Linux for some obscure reasons,
		 * we'll eventually need to sanitize it but in the meantime
		 * let's make sure it's there
		 */
		dt_add_property_strings(uart, "device_type", "serial");

		/*
		 * Add interrupt. This simulates coming from HostBoot which
		 * does not know our interrupt numbering scheme. Instead, it
		 * just tells us which chip the interrupt is wired to, it will
		 * be the PSI "host error" interrupt of that chip. For now we
		 * assume the same chip as the LPC bus is on.
		 */
		dt_add_property_cells(uart, "ibm,irq-chip-id",
				      dt_get_chip_id(primary_lpc));
	}
#endif /* ADD_SIMICS_LPC_UART */
}

void main_cpu_entry(const void *fdt, u32 master_cpu)
{
	printf("SkiBoot %s starting...\n", gitid);

	/* Initialize boot cpu's cpu_thread struct */
	init_boot_cpu();

	/* Now locks can be used */
	init_locks();

	/* Create the OPAL call table early on, entries can be overridden
	 * later on (FSP console code for example)
	 */
	opal_table_init();

	/*
	 * If we are coming in with a flat device-tree, we expand it
	 * now. Else look for HDAT and create a device-tree from them
	 *
	 * Hack alert: When entering via the OPAL entry point, fdt
	 * is set to -1, we record that and pass it to parse_hdat
	 */
	if (fdt == (void *)-1ul)
		parse_hdat(true, master_cpu);
	else if (fdt == NULL)
		parse_hdat(false, master_cpu);
	else {
		dt_expand(fdt);

		/* The HB device-tree doesn't contain the OPAL generic
		 * interrupt-controller, add it now
		 */
		add_ics_node();
	}

	/* Put various bits & pieces in device-tree */
	dt_init_misc();

	/* Get out list of chips and allocate per-chip data */
	init_chips();

	/* Initialize the rest of the cpu thread structs */
	init_all_cpus();

	/* Mark out memory areas. */
	mem_region_init();

	/* Initialize XSCOM */
	xscom_init();

	/*
	 * Fix missing bits from device-tree. This is done after
	 * xscom_init as we might need to use xscom to read some
	 * BARs to setup the DT nodes appropriately
	 */
	dt_fixups();

	/* Initialize PSI */
	psi_init();

	/* Initialize LPC (P8 only) so we can get to UART */
	lpc_init();
	uart_init();

	/* Early initializations of the FSP interface */
	fsp_init();
	fsp_sysparam_init();

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

	/* Init SLW related stuff */
	slw_init();

	/* Call in secondary CPUs */
	cpu_bringup();

	op_display(OP_LOG, OP_MOD_INIT, 0x0002);

	/* Enable timebase synchronization */
	chiptod_init(master_cpu);

	/* NX init */
	nx_init();

	/* Read our initial RTC value */
	fsp_rtc_init();

	op_display(OP_LOG, OP_MOD_INIT, 0x0003);

	op_display(OP_LOG, OP_MOD_INIT, 0x0004);

	/* Probe IO hubs */
	probe_p5ioc2();
	probe_p7ioc();

	/* Probe PHB3 on P8 */
	probe_phb3();

	/* Initialize PCI */
	pci_init_slots();

	op_display(OP_LOG, OP_MOD_INIT, 0x0005);

	/* Trace node in DT. */
	trace_add_node();

	/* Add OPAL-specific node to dt_root before booting the kernel
	 *
	 * Note: This must be done fairly late as it has to account for
	 * various memory reservations done in previous stages of the
	 * boot process.
	 */
	add_opal_nodes();

	/* Now release parts of memory nodes we haven't used ourselves... */
	mem_region_release_unused();

	/* ... and add remaining reservations to the DT */
	mem_region_add_dt_reserved();

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

