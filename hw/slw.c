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

//#define DBG(fmt...)	printf("SLW: " fmt)
#define DBG(fmt...)	do { } while(0)

#define PBA_BAR2	0x2013f02
#define PBA_BARMASK2	0x2013f06

static void slw_init_chip(struct proc_chip *chip)
{
	uint64_t bar2, mask2;
	uint64_t base, size;
	int rc;

	rc = xscom_read(chip->id, PBA_BAR2, &bar2);
	if (rc) {
		prerror("SLW: Failed to read PBA BAR2 on chip %d\n",
			chip->id);
		return;
	}
	rc = xscom_read(chip->id, PBA_BARMASK2, &mask2);
	if (rc) {
		prerror("SLW: Failed to read PBA BAR MASK2 on chip %d\n",
			chip->id);
		return;
	}

	printf("SLW chip %d\n", chip->id);
	printf("  PBA BAR2 : 0x%016llx\n", bar2);
	printf("  PBA MASK2: 0x%016llx\n", mask2);

	base = bar2 & 0x0ffffffffffffffful;
	size = (mask2 | 0xfffff) + 1;
	if (base == 0) {
		printf("  No image\n");
		return;
	}
	printf("  Image at 0x%llx size %lldMB\n", base, size / 0x100000);

	mem_reserve("ibn,slw-image", base, size);
}

void slw_init(void)
{
	struct proc_chip *chip;

	if (proc_gen != proc_gen_p8)
		return;

	/*
	 * XXX This is temporary, on P8 we look for any configured
	 * SLW BAR and reserve the memory. Eventually, this will be
	 * done via HostBoot using the device-tree "reserved-ranges"
	 * or we'll load the SLW image ourselves using Host Services.
	 */
	for_each_chip(chip)
		slw_init_chip(chip);
}

