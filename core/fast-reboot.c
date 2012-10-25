#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <device_tree.h>
#include <opal.h>
#include <xscom.h>
#include <interrupts.h>
#include <cec.h>
#include <time.h>

/*
 * To get control of all threads, we sreset them via XSCOM after
 * patching the 0x100 vector. This will work as long as the target
 * HRMOR is 0. If Linux ever uses HRMOR, we'll have to consider
 * a more messy approach.
 *
 * The SCOM register we want is called "Core RAS Control" in the doc
 * and EX0.EC.PC.TCTL_GENERATE#0.TCTL.DIRECT_CONTROLS in the SCOM list
 *
 * Bits in there change from CPU rev to CPU rev but the bit we care
 * about, bit 60 "sreset_request" appears to have stuck to the same
 * place in both P7 and P7+. The register also has the same SCOM
 * address
 */
#define EX0_TCTL_DIRECT_CONTROLS0	0x08010400
#define EX0_TCTL_DIRECT_CONTROLS1	0x08010440
#define EX0_TCTL_DIRECT_CONTROLS2	0x08010480
#define EX0_TCTL_DIRECT_CONTROLS3	0x080104c0
#define   TCTL_DC_SRESET_REQUEST	PPC_BIT(60)

/* Flag tested by the OPAL entry code */
uint8_t reboot_in_progress;
static struct cpu_thread *resettor, *resettee;

static void flush_caches(void)
{
	uint64_t base = SKIBOOT_BASE;
	uint64_t end = base + SKIBOOT_SIZE;

	/* Not sure what the effect of sreset is on cores, so let's
	 * shoot a series of dcbf's on all cachelines that make up
	 * our core memory just in case...
	 */
	while(base < end) {
		asm volatile("dcbf 0,%0" : : "r" (base) : "memory");
		base += 128;
	}
	sync();
}

static bool do_reset_core_p7(struct cpu_thread *cpu)
{
	uint32_t xscom_addr;
	uint64_t ctl;
	int rc;

	/* Add the Core# */
	xscom_addr = EX0_TCTL_DIRECT_CONTROLS0;
	xscom_addr |= ((cpu->pir >> 2) & 7) << 24;

	ctl = TCTL_DC_SRESET_REQUEST;
	rc = xscom_write(PIR2GCID(cpu->pir), xscom_addr, ctl);
	rc |= xscom_write(PIR2GCID(cpu->pir), xscom_addr + 0x40, ctl);
	rc |= xscom_write(PIR2GCID(cpu->pir), xscom_addr + 0x80, ctl);
	rc |= xscom_write(PIR2GCID(cpu->pir), xscom_addr + 0xc0, ctl);
	if (rc) {
		prerror("RESET: Error %d resetting CPU 0x%04x\n",
			rc, cpu->pir);
		return false;
	}
	return true;
}

static void fast_reset_p7(void)
{
	struct cpu_thread *cpu;

	resettee = this_cpu();
	resettor = NULL;

	/* Pick up a candidate resettor. We do that before we flush
	 * the caches
	 */
	for_each_cpu(cpu) {
		/*
		 * Some threads might still be in skiboot.
		 *
		 * But because we deal with entire cores and we don't want
		 * to special case things, we are just going to reset them
		 * too making the assumption that this is safe, they are
		 * holding no locks. This can only be true if they don't
		 * have jobs scheduled which is hopefully the case.
		 */
		if (cpu->state != cpu_state_os &&
		    cpu->state != cpu_state_active)
			continue;

		/*
		 * Only hit cores and only if they aren't on the same core
		 * as ourselves
		 */
		if (cpu_get_thread0(cpu) == cpu_get_thread0(this_cpu()) ||
		    cpu->pir & 0x3)
			continue;

		/* Pick up one of those guys as our "resettor". It will be
		 * in charge of resetting this CPU. We avoid resetting
		 * ourselves, not sure how well it would do with SCOM
		 */
		resettor = cpu;
		break;
	}

	if (!resettor) {
		printf("RESET: Can't find a resettor !\n");
		return;
	}
	printf("RESET: Resetting from 0x%04x, resettor 0x%04x\n",
	       this_cpu()->pir, resettor->pir);

	printf("RESET: Flushing caches...\n");

	/* Is that necessary ? */
	flush_caches();

	/* Reset everybody except self and except resettor */
	for_each_cpu(cpu) {
		if (cpu->state != cpu_state_os &&
		    cpu->state != cpu_state_active)
			continue;
		if (cpu_get_thread0(cpu) == cpu_get_thread0(this_cpu()) ||
		    cpu->pir & 0x3)
			continue;
		if (cpu_get_thread0(cpu) == cpu_get_thread0(resettor))
			continue;

		printf("RESET: Resetting CPU 0x%04x...\n", cpu->pir);

		if (!do_reset_core_p7(cpu))
			return;
	}

	/* Reset the resettor last because it's going to kill me ! */
	printf("RESET: Resetting CPU 0x%04x...\n", resettor->pir);
	if (!do_reset_core_p7(resettor))
		return;

	/* Don't return */
	for (;;)
		;
}

void fast_reset(void)
{
	uint32_t pvr = mfspr(SPR_PVR);
	extern uint32_t fast_reset_patch_start;
	extern uint32_t fast_reset_patch_end;
	uint32_t *dst, *src;

	printf("RESET: Fast reboot request !\n");

	/* XXX We need a way to ensure that no other CPU is in skiboot
	 * holding locks (via the OPAL APIs) and if they are, we need
	 * for them to get out
	 */
	reboot_in_progress = 1;
	time_wait_ms(200);

	/* Copy reset trampoline */
	printf("RESET: Copying reset trampoline...\n");
	src = &fast_reset_patch_start;
	dst = (uint32_t *)0x100;
	while(src < &fast_reset_patch_end)
		*(dst++) = *(src++);
	sync_icache();

	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		fast_reset_p7();
	}
}

/* Entry from asm after a fast reset */
void fast_reboot(void)
{
	static volatile bool fast_boot_release;
	struct cpu_thread *cpu;

	printf("INIT: CPU PIR 0x%04x reset in\n", this_cpu()->pir);

	/* If this CPU was chosen as the resettor, it must reset the
	 * resettee (the one that initiated the whole process
	 */
	if (this_cpu() == resettor)
		do_reset_core_p7(resettee);

	/* Are we the original boot CPU ? If not, we spin waiting
	 * for a relase signal from CPU 1, then we clean ourselves
	 * up and go processing jobs.
	 */
	if (this_cpu() != boot_cpu) {
		this_cpu()->state = cpu_state_present;
		while (!fast_boot_release) {
			smt_very_low();
			sync();
		}
		smt_medium();
		reset_cpu_icp();
		__secondary_cpu_entry();
	}

	/* We are the original boot CPU, wait for secondaries to
	 * be captured
	 */
	for_each_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		/* XXX Add a callin timeout ? */
		while (cpu->state != cpu_state_present) {
			smt_very_low();
			sync();
		}
		smt_medium();
	}

	printf("INIT: Releasing secondaries...\n");

	/* Release everybody */
	fast_boot_release = true;
	sync();

	/* Wait for them to respond */
	for_each_cpu(cpu) {
		if (cpu == this_cpu())
			continue;

		/* XXX Add a callin timeout ? */
		while (cpu->state == cpu_state_present) {
			smt_very_low();
			sync();
		}
	}

	printf("INIT: All done, resetting everything else...\n");

	/* Clear release flag for next time */
	fast_boot_release = false;
	reboot_in_progress = 0;

	/* Clean up our ICP, mask all interrupts */
	reset_cpu_icp();

	/* Set our state to active */
	this_cpu()->state = cpu_state_active;

	/* Reset/EOI the PSI interrupt */
	fsp_psi_irq_reset();

	/* Reset CEC */
	cec_reset();

	load_and_boot_kernel(true);
}
