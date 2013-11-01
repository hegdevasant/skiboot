/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
/*
 * Handle ChipTOD chip & configure core timebases
 */
#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <chiptod.h>
#include <interrupts.h>
#include <timebase.h>

#ifdef __HAVE_LIBPORE__
#include <p8_pore_table_gen_api.H>
#include <sbe_xip_image.h>
#endif

#define DBG(fmt...)	printf("SLW: " fmt)
//#define DBG(fmt...)	do { } while(0)

#define P8_EX_PCB_SLAVE_BASE	0x100F0000

#define XSCOM_ADDR_P8_EX_SLAVE(core, offset) \
     (P8_EX_PCB_SLAVE_BASE | (((core) & 0xF) << 24) | ((offset) & 0xFFFF))

#define XSCOM_ADDR_P8_EX(core, addr) \
		((((core) & 0xF) << 24) | (addr))

/* Per core power mgt slave regisers */
#define PM_GP0			0x0100
#define PM_GP1			0x0103
#define PM_SPECIAL_WAKEUP_FSP	0x010B
#define PM_SPECIAL_WAKEUP_OCC	0x010C
#define PM_SPECIAL_WAKEUP_PHYP	0x010D
#define PM_IDLE_STATE_HISTORY	0x0110
#define PM_CORE_PFET_VRET	0x0130
#define PM_CORE_ECO_VRET	0x0150

/* Per core power mgt registers */
#define PM_OHA_MODE_REG		0x1002000D

/* Power mgt settings */
#define PM_SETUP_GP1_FAST_SLEEP	0xD820000000000000ULL
#define PM_SETUP_GP1_DEEP_SLEEP	0x2420000000000000ULL

#define MAX_RESET_PATCH_SIZE	64
static uint32_t slw_saved_reset[MAX_RESET_PATCH_SIZE];

static bool slw_current_le = false;

/* Assembly in head.S */
extern void enter_rvwinkle(void);

static void slw_do_rvwinkle(void *data)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_thread *master = data;
	uint64_t lpcr = mfspr(SPR_LPCR);
	struct proc_chip *chip;

	/* Setup our ICP to receive IPIs */
	icp_prep_for_rvwinkle();

	/* Setup LPCR to wakeup on external interrupts only */
	mtspr(SPR_LPCR, ((lpcr & ~SPR_LPCR_P8_PECE) | SPR_LPCR_P8_PECE2));

	printf("SLW: CPU PIR 0x%04x goint to rvwinkle...\n", cpu->pir);

	/* Tell that we got it */
	cpu->state = cpu_state_rvwinkle;

	enter_rvwinkle();

	/* Ok, it's ours again */
	cpu->state = cpu_state_active;

	printf("SLW: CPU PIR 0x%04x woken up !\n", cpu->pir);

	/* Cleanup our ICP */
	reset_cpu_icp();

	/* Resync timebase */
	chiptod_wakeup_resync();

	/* Restore LPCR */
	mtspr(SPR_LPCR, lpcr);

	/* If we are passed a master pointer we are the designated
	 * waker, let's proceed. If not, return, we are finished.
	 */
	if (!master)
		return;

	printf("SLW: CPU PIR 0x%04x waiting for master...\n", cpu->pir);

	/* Allriiiight... now wait for master to go down */
	while(master->state != cpu_state_rvwinkle)
		sync();

	/* XXX Wait one second ! (should check xscom state ? ) */
	time_wait_ms(1000);

	for_each_chip(chip) {
		struct cpu_thread *c;
		uint64_t tmp;
		for_each_available_core_in_chip(c, chip->id) {
			xscom_read(chip->id,
				 XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
							PM_IDLE_STATE_HISTORY),
				   &tmp);	
			printf("SLW: core %x:%x history: 0x%016llx (mid2)\n",
			       chip->id, pir_to_core_id(c->pir), tmp);
		}
	}

	printf("SLW: Waking master (PIR 0x%04x)...\n", master->pir);

	/* Now poke all the secondary threads on the master's core */
	for_each_cpu(cpu) {
		if (!cpu_is_sibling(cpu, master) || (cpu == master))
			continue;
		icp_kick_cpu(cpu);

		/* Wait for it to claim to be back (XXX ADD TIMEOUT) */
		while(cpu->state != cpu_state_active)
			sync();
	}

	/* Now poke the master and be gone */
	icp_kick_cpu(master);
}

static void slw_patch_reset(void)
{
	extern uint32_t rvwinkle_patch_start;
	extern uint32_t rvwinkle_patch_end;
	uint32_t *src, *dst, *sav;

	BUILD_ASSERT((&rvwinkle_patch_end - &rvwinkle_patch_start) <=
		     MAX_RESET_PATCH_SIZE);

	src = &rvwinkle_patch_start;
	dst = (uint32_t *)0x100;
	sav = slw_saved_reset;
	while(src < &rvwinkle_patch_end) {
		*(sav++) = *(dst);
		*(dst++) = *(src++);
	}
	sync_icache();
}

static void slw_unpatch_reset(void)
{
	extern uint32_t rvwinkle_patch_start;
	extern uint32_t rvwinkle_patch_end;
	uint32_t *src, *dst, *sav;

	src = &rvwinkle_patch_start;
	dst = (uint32_t *)0x100;
	sav = slw_saved_reset;
	while(src < &rvwinkle_patch_end) {
		*(dst++) = *(sav++);
		src++;
	}
	sync_icache();
}

static bool slw_prepare_core(struct proc_chip *chip, struct cpu_thread *c)
{
	uint32_t core = pir_to_core_id(c->pir);
	uint64_t tmp;
	int rc;

	printf("SLW: Prepare core %x:%x\n", chip->id, core);

	/* PowerManagement GP0 clear PM_DISABLE */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, PM_GP0), &tmp);
	if (rc) {
		prerror("SLW: Failed to read PM_GP0\n");
		return false;
	}
	tmp = tmp & ~0x8000000000000000ULL;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, PM_GP0), tmp);
	if (rc) {
		prerror("SLW: Failed to write PM_GP0\n");
		return false;
	}
	DBG("SLW: PMGP0 set to 0x%016llx\n", tmp);

	/* Read back for debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, PM_GP0), &tmp);
	DBG("SLW: PMGP0 read   0x%016llx\n", tmp);

	/*
	 * Set ENABLE_IGNORE_RECOV_ERRORS in OHA_MODE_REG
	 *
	 * XXX FIXME: This should be only done for "forced" winkle such as
	 * when doing repairs or LE transition, and we should restore the
	 * original value when done
	 */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX(core, PM_OHA_MODE_REG),
			&tmp);
	if (rc) {
		prerror("SLW: Failed to read PM_OHA_MODE_REG\n");
		return false;
	}
	tmp = tmp | 0x8000000000000000ULL;
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX(core, PM_OHA_MODE_REG),
			 tmp);
	if (rc) {
		prerror("SLW: Failed to write PM_OHA_MODE_REG\n");
		return false;
	}
	DBG("SLW: PM_OHA_MODE_REG set to 0x%016llx\n", tmp);

	/* Read back for debug */
	rc = xscom_read(chip->id, XSCOM_ADDR_P8_EX(core, PM_OHA_MODE_REG),&tmp);
	DBG("SLW: PM_OHA_MODE_REG read   0x%016llx\n", tmp);

	/*
	 * Clear special wakeup bits that could hold power mgt
	 *
	 * XXX FIXME: See above
	 */
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, PM_SPECIAL_WAKEUP_FSP),
			 0);
	if (rc) {
		prerror("SLW: Failed to write PM_SPECIAL_WAKEUP_FSP\n");
		return false;
	}
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, PM_SPECIAL_WAKEUP_OCC),
			 0);
	if (rc) {
		prerror("SLW: Failed to write PM_SPECIAL_WAKEUP_OCC\n");
		return false;
	}
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, PM_SPECIAL_WAKEUP_PHYP),
			 0);
	if (rc) {
		prerror("SLW: Failed to write PM_SPECIAL_WAKEUP_PHYP\n");
		return false;
	}

	/* Init PM GP1 for fast mode or deep mode */
	rc = xscom_write(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, PM_GP1),
			 PM_SETUP_GP1_DEEP_SLEEP);
	if (rc) {
		prerror("SLW: Failed to write PM_GP1\n");
		return false;
	}

	/* Read back for debug */
	xscom_read(chip->id, XSCOM_ADDR_P8_EX_SLAVE(core, PM_GP1), &tmp);
	DBG("SLW: PMGP1 read   0x%016llx\n", tmp);

	/* Set CORE and ECO PFET Vret to select zero */
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, PM_CORE_PFET_VRET), 0);
	if (rc) {
		prerror("SLW: Failed to write PM_CORE_PFET_VRET\n");
		return false;
	}
	rc = xscom_write(chip->id,
			 XSCOM_ADDR_P8_EX_SLAVE(core, PM_CORE_ECO_VRET), 0);
	if (rc) {
		prerror("SLW: Failed to write PM_CORE_ECO_VRET\n");
		return false;
	}

	/* Cleanup history */
	xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, PM_IDLE_STATE_HISTORY),
		   &tmp);

	printf("SLW: core %x:%x history: 0x%016llx (old1)\n",
	       chip->id, core, tmp);

	xscom_read(chip->id,
		   XSCOM_ADDR_P8_EX_SLAVE(core, PM_IDLE_STATE_HISTORY),
		   &tmp);

	printf("SLW: core %x:%x history: 0x%016llx (old2)\n",
	       chip->id, core, tmp);

	return true;
}

static bool slw_prepare_chip(struct proc_chip *chip)
{
	struct cpu_thread *c;
	
	for_each_available_core_in_chip(c, chip->id) {
		if (!slw_prepare_core(chip, c))
			return false;
	}
	return true;
}

static void slw_cleanup_core(struct proc_chip *chip, struct cpu_thread *c)
{
	uint64_t tmp;
	int rc;

	/* Display history to check transition */
	rc = xscom_read(chip->id,
			XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
					       PM_IDLE_STATE_HISTORY),
			&tmp);
	if (rc) {
		prerror("SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		/* XXX error handling ? return false; */
	}

	printf("SLW: core %x:%x history: 0x%016llx (new1)\n",
	       chip->id, pir_to_core_id(c->pir), tmp);

	rc = xscom_read(chip->id,
			XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
					       PM_IDLE_STATE_HISTORY),
			&tmp);
	if (rc) {
		prerror("SLW: Failed to read PM_IDLE_STATE_HISTORY\n");
		/* XXX error handling ? return false; */
	}

	printf("SLW: core %x:%x history: 0x%016llx (new2)\n",
	       chip->id, pir_to_core_id(c->pir), tmp);

	/*
	 * XXX FIXME: Error out if the transition didn't reach rvwinkle ?
	 */

	/*
	 * XXX FIXME: We should restore a bunch of the EX bits we
	 * overwrite to sane values here
	 */
}

static void slw_cleanup_chip(struct proc_chip *chip)
{
	struct cpu_thread *c;
	
	for_each_available_core_in_chip(c, chip->id)
		slw_cleanup_core(chip, c);
}

#ifdef __HAVE_LIBPORE__
static void slw_patch_scans(struct proc_chip *chip, bool le_mode)
{
	int64_t rc;
	uint64_t old_val, new_val;

	rc = sbe_xip_get_scalar((void *)chip->slw_base,
				"skip_ex_override_ring_scans", &old_val);
	if (rc) {
		prerror("SLW: Failed to read scan override on chip %d\n",
			chip->id);
		return;
	}

	new_val = le_mode ? 0 : 1;

	DBG("SLW: Chip %d, LE value was: %lld, setting to %lld\n",
	    chip->id, old_val, new_val);

	rc = sbe_xip_set_scalar((void *)chip->slw_base,
				"skip_ex_override_ring_scans", new_val);
	if (rc) {
		prerror("SLW: Failed to set LE mode on chip %d\n", chip->id);
		return;
	}
}
#else
static inline void slw_patch_scans(struct proc_chip *chip __unused,
				   bool le_mode __unused ) { }
#endif /* __HAVE_LIBPORE__ */

int64_t slw_reinit(uint64_t flags)
{
	struct proc_chip *chip;
	struct cpu_thread *cpu;
	bool has_waker = false;
	bool target_le = slw_current_le;

#ifndef __HAVE_LIBPORE__
	return OPAL_UNSUPPORTED;
#endif

	if (flags & OPAL_REINIT_CPUS_HILE_BE)
		target_le = false;
	if (flags & OPAL_REINIT_CPUS_HILE_LE)
		target_le = true;

	DBG("SLW Reinit from CPU PIR 0x%04x, HILE set to %s endian...\n",
	    this_cpu()->pir, target_le ? "little" : "big");

	/* Prepare chips/cores for rvwinkle */
	for_each_chip(chip) {
		if (!chip->slw_base) {
			prerror("SLW: Not found on chip %d\n", chip->id);
			return OPAL_HARDWARE;
		}
		if (!slw_prepare_chip(chip)) {
			prerror("SLW: Error preparing chip %d\n", chip->id);
			return OPAL_HARDWARE;
		}
		slw_patch_scans(chip, target_le);
	}
	slw_current_le = target_le;

	/* XXX Save HIDs ? Or do that in head.S ... */

	slw_patch_reset();

	/* rvwinkle everybody and pick one to wake me once I rvwinkle myself */
	for_each_available_cpu(cpu) {
		struct cpu_thread *master = NULL;

		if (cpu == this_cpu())
			continue;

		/* Pick up a waker for myself: it must not be a sibling of
		 * the current CPU and must be a thread 0 (so it gets to
		 * sync its timebase before doing time_wait_ms()
		 */
		if (!has_waker && !cpu_is_sibling(cpu, this_cpu()) &&
		    cpu_is_thread0(cpu)) {
			has_waker = true;
			master = this_cpu();
		}
		__cpu_queue_job(cpu, slw_do_rvwinkle, master, true);

		/* Wait for it to claim to be down */
		while(cpu->state != cpu_state_rvwinkle)
			sync();		
	}

	/* XXX Wait one second ! (should check xscom state ? ) */
	DBG("SLW: [TB=0x%016lx] Waiting one second...\n", mftb());
	time_wait_ms(1000);
	DBG("SLW: [TB=0x%016lx] Done.\n", mftb());

	for_each_chip(chip) {
		struct cpu_thread *c;
		uint64_t tmp;
		for_each_available_core_in_chip(c, chip->id) {
			xscom_read(chip->id,
				 XSCOM_ADDR_P8_EX_SLAVE(pir_to_core_id(c->pir),
							PM_IDLE_STATE_HISTORY),
				   &tmp);
			printf("SLW: core %x:%x history: 0x%016llx (mid)\n",
			       chip->id, pir_to_core_id(c->pir), tmp);
		}
	}


	/* Wake everybody except on my core */
	for_each_cpu(cpu) {
		if (cpu->state != cpu_state_rvwinkle ||
		    cpu_is_sibling(cpu, this_cpu()))
			continue;
		icp_kick_cpu(cpu);

		/* Wait for it to claim to be back (XXX ADD TIMEOUT) */
		while(cpu->state != cpu_state_active)
			sync();
	}

	/* Did we find a waker ? If we didn't, that means we had no
	 * other core in the system, we can't do it
	 */
	if (!has_waker) {
		DBG("SLW: No candidate waker, giving up !\n");
		return OPAL_HARDWARE;
	}

	/* Our siblings are rvwinkling, and our waker is waiting for us
	 * so let's just go down now
	 */
	slw_do_rvwinkle(NULL);

	slw_unpatch_reset();

	for_each_chip(chip)
		slw_cleanup_chip(chip);

	DBG("SLW Reinit complete !\n");

	return OPAL_SUCCESS;
}

#ifdef __HAVE_LIBPORE__
static void slw_patch_regs(struct proc_chip *chip)
{
	struct cpu_thread *c;
	void *image = (void *)chip->slw_base;
	int rc;

	for_each_available_cpu(c) {
		if (c->chip_id != chip->id)
			continue;
	
		/* Clear HRMOR */
		rc =  p8_pore_gen_cpureg_fixed(image, chip->slw_image_size,
					       P8_SPR_HRMOR, 0,
					       cpu_get_core_index(c),
					       cpu_get_thread_index(c));
		if (rc) {
			prerror("SLW: Failed to set HRMOR for CPU %x\n",
				c->pir);
		}

		/* XXX Add HIDs etc... */
	}
}
#endif /* __HAVE_LIBPORE__ */

static void slw_init_chip(struct proc_chip *chip)
{
	int rc __unused;

	prerror("SLW: Init chip 0x%x\n", chip->id);

	if (!chip->slw_base) {
		prerror("SLW: No image found !\n");
		return;
	}

#ifdef __HAVE_LIBPORE__
	/* Check actual image size */
	rc = sbe_xip_get_scalar((void *)chip->slw_base, "image_size",
				&chip->slw_image_size);
	if (rc != 0) {
		prerror("SLW: Error %d reading SLW image size\n", rc);
		/* XXX Panic ? */
		chip->slw_base = 0;
		chip->slw_bar_size = 0;
		chip->slw_image_size = 0;
		return;
	}
	printf("SLW: Image size from image: 0x%llx\n", chip->slw_image_size);

	if (chip->slw_image_size > chip->slw_bar_size) {
		prerror("SLW: Built-in image size larger than BAR size !\n");
		/* XXX Panic ? */
	}

	/* Patch SLW image */
        slw_patch_regs(chip);
#endif /* __HAVE_LIBPORE__ */
}

void slw_init(void)
{
	struct proc_chip *chip;

	if (proc_gen != proc_gen_p8)
		return;

	for_each_chip(chip)
		slw_init_chip(chip);
}

