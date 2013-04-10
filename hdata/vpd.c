/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <spira.h>
#include <device.h>

void sysvpd_parse(void)
{
	const char *model;
	char *str;
	uint8_t sz;
	const void *sysvpd;
	unsigned int sysvpd_sz;

	if (!spira.ntuples.system_vpd.addr)
		goto no_sysvpd;

	sysvpd = HDIF_get_idata(spira.ntuples.system_vpd.addr,
				SYSVPD_IDATA_KW_VPD, &sysvpd_sz);
	if (!CHECK_SPPTR(sysvpd))
		goto no_sysvpd;

	dt_add_property(dt_root, "ibm,vpd", sysvpd, sysvpd_sz);

	model = vpd_find(sysvpd, sysvpd_sz, "VSYS", "TM", &sz);
	if (!model)
		goto no_sysvpd;
	str = zalloc(sz + 1);
	memcpy(str, model, sz);
	dt_add_property_string(dt_root, "model", str);
	free(str);

	return;

 no_sysvpd:
	dt_add_property_string(dt_root, "model", "Unknown");
}
