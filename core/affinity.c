/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <opal.h>
#include <device.h>
#include <console.h>
#include <trace.h>

void add_associativity_ref_point(struct dt_node *opal)
{
	/* XXX Hardcoding reference point to Processor Chip ID.
	 * We should consider physical node boundary (CCM Node ID)
	 * to support multi node system.
	 */
	dt_add_property_cells(opal, "ibm,associativity-reference-points",
			      0x4, 0x4);
}

