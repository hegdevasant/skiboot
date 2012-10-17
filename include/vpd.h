#ifndef __VPD_H
#define __VPD_H

#include <stdint.h>

/* Locate a keyword in a record in a VPD blob
 *
 * Note: This works with VPD LIDs. It will scan until it finds
 * the first 0x84, so it will skip all those 0's that the VPD
 * LIDs seem to contain
 */
extern const void *vpd_find(const void *vpd, size_t vpd_size,
			    const char *record, const char *keyword,
			    uint8_t *sz);

/* Helper to load a VPD LID. Pass a ptr to the corresponding LX keyword */
#define VPD_LOAD_LXRN_VINI	0xff
extern const void *vpd_lid_load(const uint8_t *lx, uint8_t lxrn,
				size_t *size);

/* Some helpers to get at some VPDs more easily */
struct spira_ntuple;
extern const void *vpd_find_from_spira(struct spira_ntuple *np,
				       unsigned int idata,
				       const char *record, const char *kw,
				       uint8_t *size);
#endif /* __VPD_H */
