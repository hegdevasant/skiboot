/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */

#include "spira.h"
#include "hdata.h"

const char *get_loc_code(uint16_t rsrc_id)
{
	struct HDIF_common_hdr *slca_hdr;
	int count;
	unsigned int i;

	slca_hdr = get_hdif(&spira.ntuples.slca, SLCA_HDIF_SIG);
	if (!slca_hdr) {
		prerror("SLCA Invalid\n");
		return NULL;
	}

	count = HDIF_get_iarray_size(slca_hdr, SLCA_IDATA_ARRAY);
	if (count < 0) {
		prerror("SLCA: Can't find SLCA array size!\n");
		return NULL;
	}

	/* Iterate over SLCA array */
	for (i = 0; i < count; i++) {
		const struct slca_entry *s_entry;
		unsigned int entry_sz;

		s_entry = HDIF_get_iarray_item(slca_hdr, SLCA_IDATA_ARRAY,
					       i, &entry_sz);
		if (!s_entry || entry_sz < sizeof(*s_entry)) {
			printf("SLCA: Entry %d bad idata\n", i);
			continue;
		}

		if (be16_to_cpu(s_entry->rsrc_id) == rsrc_id)
			return s_entry->loc_code;
	}

	return NULL;
}
