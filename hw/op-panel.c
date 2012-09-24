#include <skiboot.h>
#include <fsp.h>

static struct fsp_msg *op_msg;

void op_display(enum op_severity sev, enum op_module mod, uint16_t code)
{
	uint32_t w0 = sev << 16 | mod;
	uint32_t w1;

	w1 =  tohex((code >> 12) & 0xf) << 24;
	w1 |= tohex((code >>  8) & 0xf) << 16;
	w1 |= tohex((code >>  4) & 0xf) <<  8;
	w1 |= tohex((code      ) & 0xf);

	/* We don't use mkmsg, we try to re-use the same msg to avoid
	 * going down the malloc path etc... since this can be called
	 * in case of fatal errors
	 */
	if (!op_msg)
		op_msg = fsp_allocmsg(true);
	if (!op_msg)
		return;

	fsp_fillmsg(op_msg, FSP_CMD_DISP_SRC_DIRECT, 3, 1, w0, w1);
	fsp_sync_msg(op_msg, false);
}
