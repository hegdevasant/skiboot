/*
 * XXX TODO:
 *
 *  - Handle RAS issues
 *  - Check the setting of the low bits speed in TFMR
 */
#include <skiboot.h>
#include <chiptod.h>
#include <xscom.h>
#include <io.h>
#include <spira.h>
#include <cpu.h>

//#define DBG(fmt...)	printf("CHIPTOD: " fmt)
#define DBG(fmt...)	do { } while(0)

/* TOD chip XSCOM addresses */
#define TOD_TTYPE_0		0x00040011
#define TOD_TTYPE_1		0x00040012
#define TOD_TTYPE_2		0x00040013
#define TOD_TTYPE_3		0x00040014
#define TOD_TTYPE_4		0x00040015
#define TOD_TTYPE_5		0x00040016
#define TOD_CHIPTOD_TO_TB	0x00040017
#define TOD_LOAD_TOD_MOD	0x00040018
#define TOD_CHIPTOD_VALUE	0x00040020
#define TOD_CHIPTOD_LOAD_TB	0x00040021
#define TOD_CHIPTOD_FSM		0x00040024
#define TOD_PIB_MASTER		0x00040027

/* Magic TB value. One step cycle ahead of sync */
#define INIT_TB	0x000000000001ff0

/* Number of iterations for the various timeouts */
#define TIMEOUT_LOOPS		10000000

const struct chiptod_chipid *id_primary = NULL;
const struct chiptod_chipid *id_secondary = NULL;

static bool __chiptod_init(void)
{
	const void *p;
	unsigned int i;

	/*
	 * Locate chiptod ID structures in SPIRA
	 */
	p = spira.ntuples.chip_tod.addr;
	if (!CHECK_SPPTR(p)) {
		prerror("CHIPTOD: Cannot locate SPIRA TOD info\n");
		return false;
	}

	for (i = 0; i < spira.ntuples.chip_tod.act_cnt; i++) {
		const struct chiptod_chipid *id;

		id = HDIF_get_idata(p, CHIPTOD_IDATA_CHIPID, NULL);
		if (!CHECK_SPPTR(id)) {
			prerror("CHIPTOD: Bad ChipID data %d\n", i);
			continue;
		}

		if ((id->flags & CHIPTOD_ID_FLAGS_STATUS_MASK) !=
		    CHIPTOD_ID_FLAGS_STATUS_OK)
			continue;
		if (id->flags & CHIPTOD_ID_FLAGS_PRIMARY)
			id_primary = id;
		if (id->flags & CHIPTOD_ID_FLAGS_SECONDARY)
			id_secondary = id;

		p += spira.ntuples.chip_tod.alloc_len;
	}

	if (id_secondary && !id_primary) {
		prerror("CHIPTOD: Got secondary TOD (ID 0x%x) but no primary\n",
			id_secondary->chip_id);
		id_primary = id_secondary;
		id_secondary = NULL;
	}

	if (!id_primary) {
		prerror("CHIPTOD: Cannot find a primary TOD\n");
		return false;
	}

	printf("CHIPTOD: Primay chip ID 0x%x\n", id_primary->chip_id);
	if (id_secondary) {
		printf("CHIPTOD: Secondary chip ID 0x%x\n",
		       id_secondary->chip_id);
	}


	return true;
}

static void chiptod_setup_base_tmfr(void)
{
	uint64_t tfmr;

	tfmr = mfspr(SPR_TFMR);
	tfmr = PPC_SETFIELD(SPR_TFMR_MAX_CYC_BET_STEPS, tfmr, 0x4b);
	tfmr = PPC_SETFIELD(SPR_TFMR_N_CLKS_PER_STEP, tfmr, 0);
	tfmr = PPC_SETFIELD(SPR_TFMR_SYNC_BIT_SEL, tfmr, 4);
	tfmr |= SPR_TFMR_TB_ECLIPZ;
	mtspr(SPR_TFMR, tfmr);
}

static bool chiptod_mod_tb(void)
{
	uint64_t tfmr = mfspr(SPR_TFMR);
	uint64_t timeout = 0;

	/* Switch timebase to "Not Set" state */
	mtspr(SPR_TFMR, tfmr | SPR_TFMR_LOAD_TOD_MOD);
	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("CHIPTOD: TB \"Not Set\" timeout\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
		if (tfmr & SPR_TFMR_CHIP_TOD_TIMEOUT) {
			prerror("CHIPTOD: TB \"Not Set\" X timeout\n");
			return false;
		}
	} while(tfmr & SPR_TFMR_LOAD_TOD_MOD);

	return true;
}

static bool chiptod_interrupt_check(void)
{
	uint64_t tfmr = mfspr(SPR_TFMR);
	uint64_t timeout = 0;

	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("CHIPTOD: Interrupt check fail\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
	} while(tfmr & SPR_TFMR_CHIP_TOD_INTERRUPT);

	return true;
}

static bool chiptod_poll_running(void)
{
	uint64_t timeout = 0;
	uint64_t tval;

	/* Chip TOD running check */
	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("CHIPTOD: Running check fail timeout\n");
			return false;
		}
		if (xscom_readme(TOD_CHIPTOD_FSM, &tval) != 0) {
			prerror("CHIPTOD: XSCOM error polling run\n");
			return false;
		}
	} while(!(tval & 0x0800000000000000UL));

	return true;
}

static bool chiptod_to_tb(void)
{
	uint64_t tval, tfmr;
	uint64_t timeout = 0;

	/* Move chip TOD value to timebase
	 *
	 * Note: BML updates TOD reg. 0x27[24:31] as follow, this is
	 * not part of the documented procedure in the pervasive spec
	 */
	tval = (this_cpu()->pir >> 2) & 0x7;	/* Get core ID */
	tval |= 0x8;				/* Add b'1000 */
	tval <<= 32;				/* Move to top half */
	if (xscom_writeme(TOD_PIB_MASTER, tval) != 0) {
		prerror("CHIPTOD: XSCOM error writing PIB MASTER\n");
		return false;
	}

	tfmr = mfspr(SPR_TFMR);
	tfmr |= SPR_TFMR_MOVE_CHIP_TOD_TO_TB;
	mtspr(SPR_TFMR, tfmr);

	if (xscom_writeme(TOD_CHIPTOD_TO_TB, (1ULL << 63)) != 0) {
		prerror("CHIPTOD: XSCOM error writing CHIPTOD_TO_TB\n");
		return false;
	}

	timeout = 0;
	do {
		if (++timeout >= TIMEOUT_LOOPS) {
			prerror("CHIPTOD: Chip to TB timeout\n");
			return false;
		}
		tfmr = mfspr(SPR_TFMR);
	} while(tfmr & SPR_TFMR_MOVE_CHIP_TOD_TO_TB);

	return true;
}

static bool chiptod_wait_2sync(void)
{
	uint64_t tfmr, timeout;
	unsigned int i;

	/* Here BML adds this bit to wait for two sync pulses */
	for (i = 0; i < 2; i++) {
		tfmr = mfspr(SPR_TFMR);
		tfmr &= ~SPR_TFMR_TB_SYNC_OCCURED;
		mtspr(SPR_TFMR, tfmr);
		timeout = 0;
		do {
			if (++timeout >= TIMEOUT_LOOPS) {
				prerror("CHIPTOD: No sync pulses\n");
				return false;
			}
			tfmr = mfspr(SPR_TFMR);
		} while(!(tfmr & SPR_TFMR_TB_SYNC_OCCURED));
	}
	return true;
}

static void chiptod_sync_master(void *data)
{
	bool *result = data;

	printf("CHIPTOD: Master sync on CPU PIR 0x%04x...\n", this_cpu()->pir);

	/* Set TFMR 0:15 based on CPU frequency */
	chiptod_setup_base_tmfr();
	DBG("SYNC Master Step 1 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Switch timebase to "Not Set" state */
	if (!chiptod_mod_tb())
		goto error;
	DBG("SYNC MASTER Step 2 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD step checkers enable */
	if (xscom_writeme(TOD_TTYPE_2, (1UL << 63)) != 0) {
		prerror("CHIPTOD: XSCOM error enabling steppers\n");
		goto error;
	}

	DBG("SYNC MASTER Step 3 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD interrupt check */
	if (!chiptod_interrupt_check())
		goto error;	
	DBG("SYNC MASTER Step 4 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Switch local chiptod to "Not Set" state */
	if (xscom_writeme(TOD_LOAD_TOD_MOD, (1UL << 63)) != 0) {
		prerror("CHIPTOD: XSCOM error sending LOAD_TOD_MOD\n");
		goto error;
	}

	/* Switch all chiptod to "Not Set" state */
	if (xscom_writeme(TOD_TTYPE_5, (1UL << 63)) != 0) {
		prerror("CHIPTOD: XSCOM error sending TTYPE_5\n");
		goto error;
	}

	/* Chip TOD load value */
	if (xscom_writeme(TOD_CHIPTOD_LOAD_TB, INIT_TB) != 0) {
		prerror("CHIPTOD: XSCOM error setting init TB\n");
		goto error;
	}

	DBG("SYNC MASTER Step 5 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	if (!chiptod_poll_running())
		goto error;
	DBG("SYNC MASTER Step 6 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Move chiptod value to core TB */
	if (!chiptod_to_tb())
		goto error;
	DBG("SYNC MASTER Step 7 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Send local chip TOD to all chips TOD */
	if (xscom_writeme(TOD_TTYPE_4, (1ULL << 63)) != 0) {
		prerror("CHIPTOD: XSCOM error sending TTYPE_4\n");
		goto error;
	}

	if (!chiptod_wait_2sync())
		goto error;

	DBG("Master sync completed, TB=%lx\n", mfspr(SPR_TBRL));

	*result = true;
	return;
 error:
	printf("CHIPTOD: Master sync failed !\n");
	*result = false;
}

static void chiptod_sync_slave(void *data)
{
	bool *result = data;

	printf("CHIPTOD: Slave sync on CPU PIR 0x%04x...\n", this_cpu()->pir);

	/* Set TFMR 0:15 based on CPU frequency */
	chiptod_setup_base_tmfr();
	DBG("SYNC SLAVE Step 1 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Switch timebase to "Not Set" state */
	if (!chiptod_mod_tb())
		goto error;
	DBG("SYNC SLAVE Step 2 TFMR=0x%016lx\n", mfspr(SPR_TFMR));
	
	/* Chip TOD interrupt check */
	if (!chiptod_interrupt_check())
		goto error;	

	DBG("SYNC SLAVE Step 3 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Chip TOD running check */
	if (!chiptod_poll_running())
		goto error;
	DBG("SYNC SLAVE Step 4 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	/* Move chiptod value to core TB */
	if (!chiptod_to_tb())
		goto error;
	DBG("SYNC SLAVE Step 5 TFMR=0x%016lx\n", mfspr(SPR_TFMR));

	DBG("Slave sync completed, TB=%lx\n", mfspr(SPR_TBRL));

	*result = true;
	return;
 error:
	printf("CHIPTOD: Slave sync failed !\n");
	*result = false;
}

static void chiptod_print_tb(void *data __unused)
{
	printf("CHIPTOD: PIR 0x%04x TB=%lx\n",
	       this_cpu()->pir, mfspr(SPR_TBRL));
}

void chiptod_init(void)
{
	struct cpu_thread *cpu0, *cpu;
	bool sres;

	op_display(OP_LOG, OP_MOD_CHIPTOD, 0);

	if (!__chiptod_init()) {
		prerror("CHIPTOD: Failed ChipTOD init !\n");
		op_display(OP_FATAL, OP_MOD_CHIPTOD, 0);
		abort();
	}
	assert(id_primary);

	op_display(OP_LOG, OP_MOD_CHIPTOD, 1);

	/* Pick somebody on the primary */
	cpu0 = find_cpu_by_chip_id(id_primary->chip_id);
	if (!cpu0) {
		prerror("CHIPTOD: Failed to find a CPU on chip %d !\n",
			id_primary->chip_id);
		op_display(OP_FATAL, OP_MOD_CHIPTOD, 1);
		abort();
	}

	/* Schedule master sync */
	sres = false;
	cpu_wait_job(cpu_queue_job(cpu0, chiptod_sync_master, &sres), true);
	if (!sres) {
		prerror("CHIPTOD: Master sync failed !\n");
		op_display(OP_FATAL, OP_MOD_CHIPTOD, 2);
		abort();
	}

	op_display(OP_LOG, OP_MOD_CHIPTOD, 2);

	/* Schedule slave sync */
	for_each_available_cpu(cpu) {
		/* Only get primaries, not threads */
		if (cpu->pir & SPR_PIR_THREAD_MASK)
			continue;

		/* Skip master */
		if (cpu == cpu0)
			continue;

		/* Queue job */
		sres = false;
		cpu_wait_job(cpu_queue_job(cpu, chiptod_sync_slave, &sres),
			     true);
		if (!sres) {
			prerror("CHIPTOD: Slave sync failed on PIR 0x%04x !\n",
				cpu->pir);
			op_display(OP_WARN, OP_MOD_CHIPTOD, 3|(cpu->pir << 8));

			/* Disable threads */
			cpu_disable_all_threads(cpu);
		}
		op_display(OP_LOG, OP_MOD_CHIPTOD, 3|(cpu->pir << 8));
	}

	/* Display TBs */
	for_each_available_cpu(cpu) {
		/* Only do primaries, not threads */
		if (cpu->pir & SPR_PIR_THREAD_MASK)
			continue;
		cpu_wait_job(cpu_queue_job(cpu, chiptod_print_tb, NULL), true);
	}

	op_display(OP_LOG, OP_MOD_CHIPTOD, 4);
}
