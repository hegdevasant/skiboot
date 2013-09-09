/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>

#define PBA_BAR0	0x2013f00
#define PBA_BARMASK0	0x2013f04

static bool read_pba_bar(struct proc_chip *chip, unsigned int bar_no,
			 uint64_t *base, uint64_t *size)
{
	uint64_t bar, mask;
	int rc;

	rc = xscom_read(chip->id, PBA_BAR0 + bar_no, &bar);
	if (rc) {
		prerror("SLW: Error %d reading PBA BAR%d on chip %d\n",
			rc, bar_no, chip->id);
		return false;
	}
	rc = xscom_read(chip->id, PBA_BARMASK0 + bar_no, &mask);
	if (rc) {
		prerror("SLW: Error %d reading PBA BAR MASK%d on chip %d\n",
			rc, bar_no, chip->id);
		return false;
	}
	printf("  PBA BAR%d : 0x%016llx\n", bar_no, bar);
	printf("  PBA MASK%d: 0x%016llx\n", bar_no, mask);

	*base = bar & 0x0ffffffffffffffful;
	*size = (mask | 0xfffff) + 1;

	return base != 0;
}

static void homer_init_chip(struct proc_chip *chip)
{
	uint64_t base, size;

	/*
	 * PBA BARs assigned by HB:
	 *
	 *   0 : Entire HOMER
	 *   1 : OCC to Centaur path (we don't care)
	 *   2 : SLW image
	 *   3 : OCC Common area
	 *
	 * We need to reserve the memory covered by BAR 0 and BAR 3, however
	 * on earlier HBs, BAR0 isn't set so we need BAR 2 instead in that
	 * case to cover SLW (OCC not running).
	 */
	if (read_pba_bar(chip, 0, &base, &size)) {
		printf("  HOMER Image at 0x%llx size %lldMB\n",
		       base, size / 0x100000);
		mem_reserve("ibm,homer-image", base, size);
	} else if (read_pba_bar(chip, 2, &base, &size)) {
		printf("  SLW Image at 0x%llx size %lldMB\n",
		       base, size / 0x100000);
		mem_reserve("ibm,slw-image", base, size);
	}

	if (read_pba_bar(chip, 3, &base, &size)) {
		printf("  OCC Common Area at 0x%llx size %lldMB\n",
		       base, size / 0x100000);
		mem_reserve("ibm,occ-common-area", base, size);
	}
}

void homer_init(void)
{
	struct proc_chip *chip;

	if (proc_gen != proc_gen_p8)
		return;

	/*
	 * XXX This is temporary, on P8 we look for any configured
	 * SLW/OCC BAR and reserve the memory. Eventually, this will be
	 * done via HostBoot using the device-tree "reserved-ranges"
	 * or we'll load the SLW & OCC images ourselves using Host Services.
	 */
	for_each_chip(chip) {
		printf("HOMER: Init chip %d\n", chip->id);
		homer_init_chip(chip);
	}
}

