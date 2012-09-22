#include <skiboot.h>
#include <fsp.h>

void op_display(enum op_severity sev, enum op_module mod, uint16_t code)
{
	uint32_t w0 = sev << 16 | mod;
	uint32_t w1;

	w1 =  tohex((code >> 12) & 0xf) << 24;
	w1 |= tohex((code >>  8) & 0xf) << 16;
	w1 |= tohex((code >>  4) & 0xf) <<  8;
	w1 |= tohex((code      ) & 0xf);

	fsp_sync_msg(fsp_mkmsg(FSP_CMD_DISP_SRC_DIRECT, 3, 1, w0, w1), true);
}
