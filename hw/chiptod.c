#include <skiboot.h>
#include <chiptod.h>
#include <xscom.h>
#include <io.h>
#include <spira.h>

static bool __chiptod_init(void)
{
	const struct chiptod_chipid *id_primary = NULL;
	const struct chiptod_chipid *id_secondary = NULL;
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

void chiptod_init(void)
{
	if (!__chiptod_init()) {
		op_display(OP_FATAL, OP_MOD_CHIPTOD, 0x0000);
		prerror("INIT: Failed ChipTOD init !\n");
		abort();
	}
}
