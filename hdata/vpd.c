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
