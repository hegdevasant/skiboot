/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */

#include <skiboot.h>
#include <chip.h>

uint32_t pir_to_chip_id(uint32_t pir)
{
	if (proc_gen == proc_gen_p8)
		return P8_PIR2GCID(pir);
	else
		return P7_PIR2GCID(pir);
}

