/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <stdbool.h>
#include <elf.h>

/* WARNING: This code is used to self-relocate, it cannot have any
 * global reference nor TOC reference. It's also called before BSS
 * is cleared.
 */

/* Note: This code is simplified according to the assumptions
 *       that our link address is 0 and we are running at the
 *       target address already.
 */
int relocate(uint64_t offset, struct elf64_dyn *dyn, struct elf64_rela *rela)
{
	uint64_t dt_rela	= 0;
	uint64_t dt_relacount	= 0;
	unsigned int i;

	/* Look for relocation table */
	for (; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_RELA)
			dt_rela = dyn->d_val;
		else if (dyn->d_tag == DT_RELACOUNT)
			dt_relacount = dyn->d_val;
	}

	/* If we miss either rela or relacount, bail */
	if (!dt_rela || !dt_relacount)
		return false;

	/* Check if the offset is consistent */
	if ((offset + dt_rela) != (uint64_t)rela)
		return false;

	/* Perform relocations */
	for (i = 0; i < dt_relacount; i++, rela++) {
		uint64_t *t;

		if (ELF64_R_TYPE(rela->r_info) != R_PPC64_RELATIVE)
			return false;
		t = (uint64_t *)(rela->r_offset + offset);
		*t = rela->r_addend + offset;
	}

	return true;
}
