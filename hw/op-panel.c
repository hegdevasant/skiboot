#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <opal.h>
#include <device_tree.h>

static struct fsp_msg *op_msg;
static struct fsp_msg *op_req;
static struct lock op_lock = LOCK_UNLOCKED;

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
	lock(&op_lock);
	if (!op_msg)
		op_msg = fsp_allocmsg(true);
	if (!op_msg) {
		unlock(&op_lock);
		return;
	}

	fsp_fillmsg(op_msg, FSP_CMD_DISP_SRC_DIRECT, 3, 1, w0, w1);
	fsp_sync_msg(op_msg, false);
	unlock(&op_lock);
}

void op_panel_disable_src_echo(void)
{
	lock(&op_lock);
	if (!op_msg)
		op_msg = fsp_allocmsg(true);
	if (!op_msg) {
		unlock(&op_lock);
		return;
	}
	fsp_fillmsg(op_msg, FSP_CMD_DIS_SRC_ECHO, 0);
	fsp_sync_msg(op_msg, false);
	unlock(&op_lock);
}

/* opal_write_oppanel - Write to the physical op panel.
 *
 * Pass in an array of oppanel_line_t structs defining the ASCII characters
 * to display on each line of the oppanel. If there are two lines on the
 * physical panel, and you only want to write to the first line, you only
 * need to pass in one line. If you only want to write to the second line,
 * you need to pass in both lines, and set the line_len of the first line
 * to zero.
 *
 * This command is asynchronous. If OPAL_SUCCESS is returned, then the
 * operation was initiated successfully. Subsequent calls will return
 * OPAL_BUSY until the current operation is complete.
 *
 * TODO: Consider adding an OPAL event for completion like RTC
 */
struct op_src {
	uint8_t version;
#define OP_SRC_VERSION	2
	uint8_t	flags;
	uint8_t reserved;
	uint8_t	hex_word_cnt;
	uint16_t reserved2;
	uint16_t total_size;
	uint32_t word2; /* SRC format in low byte */
	uint32_t word3;
	uint32_t word4;
	uint32_t word5;
	uint32_t word6;
	uint32_t word7;
	uint32_t word8;
	uint32_t word9;
	uint8_t	ascii[32];
} __packed __align(4);

/* Page align for the sake of TCE mapping */
static struct op_src op_src __align(0x1000);

static void op_panel_write_complete(struct fsp_msg *msg)
{
	fsp_tce_unmap(PSI_DMA_OP_PANEL_MISC, 0x1000);
	lwsync();
	op_req = NULL;
	fsp_freemsg(msg);
}

static int64_t opal_write_oppanel(oppanel_line_t *lines, uint64_t num_lines)
{
	int64_t rc;
	int len;

	if (num_lines < 1 || num_lines > 2)
		return OPAL_PARAMETER;

	lock(&op_lock);
	if (op_req) {
		rc = OPAL_BUSY;
		goto bail;
	}
	op_req = fsp_allocmsg(true);
	if (!op_req) {
		rc = OPAL_NO_MEM;
		goto bail;
	}
	memset(&op_src, 0, sizeof(op_src) - 32);
	op_src.version = OP_SRC_VERSION;
	op_src.hex_word_cnt = 1; /* header word only */
	memset(&op_src.ascii, ' ', 32);
	len = lines[0].line_len > 16 ? 16 : lines[0].line_len;
	memcpy(&op_src.ascii[0], lines[0].line, len);
	if (num_lines > 1) {
		len = lines[1].line_len > 16 ? 16 : lines[1].line_len;
		memcpy(&op_src.ascii[16], lines[1].line, len);
	}
	fsp_tce_map(PSI_DMA_OP_PANEL_MISC, &op_src, 0x1000);
	fsp_fillmsg(op_req, FSP_CMD_DISP_SRC_INDIR, 3, 0,
		    PSI_DMA_OP_PANEL_MISC, sizeof(struct op_src));
	rc = fsp_queue_msg(op_req, op_panel_write_complete);
	if (rc)
		op_panel_write_complete(op_req);
 bail:
	unlock(&op_lock);
	return rc;
}
opal_call(OPAL_WRITE_OPPANEL, opal_write_oppanel);

void add_opal_oppanel_node(void)
{
	dt_begin_node("oppanel");
	dt_property_cell("#length", 16);
	dt_property_cell("#lines", 2);
	dt_property_string("compatible", "ibm,opal-oppanel");
	dt_end_node();
}
