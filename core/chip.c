/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */

#include <skiboot.h>
#include <chip.h>
#include <device.h>

#define MAX_CHIPS	(1 << 6)	/* 6-bit chip ID */

static struct proc_chip *chips[MAX_CHIPS];

uint32_t pir_to_chip_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p8)
		return P8_PIR2GCID(pir);
	else
		return P7_PIR2GCID(pir);
}

struct proc_chip *next_chip(struct proc_chip *chip)
{
	unsigned int i;

	for (i = chip ? (chip->id + 1) : 0; i < MAX_CHIPS; i++)
		if (chips[i])
			return chips[i];
	return NULL;
}


struct proc_chip *get_chip(uint32_t chip_id)
{
	return chips[chip_id];
}

void init_chips(void)
{
	struct proc_chip *chip;
	struct dt_node *xn;

	/* We walk the chips based on xscom nodes in the tree */
	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		uint32_t id = dt_get_chip_id(xn);

		assert(id < MAX_CHIPS);

		chip = zalloc(sizeof(struct proc_chip));
		assert(chip);
		chip->id = id;
		chips[id] = chip;
	};
}
