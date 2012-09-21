/*
 * Service Processor serial console handling code
 */
#include <skiboot.h>
#include <processor.h>
#include <spira.h>
#include <io.h>
#include <fsp.h>
#include <console.h>

struct fsp_serbuf_hdr {
	uint16_t	partition_id;
	uint8_t		session_id;
	uint8_t		hmc_id;
	uint16_t	data_offset;
	uint16_t	last_valid;
	uint16_t	ovf_count;
	uint16_t	next_in;
	uint8_t		flags;
	uint8_t		reserved;
	uint16_t	next_out;
	uint8_t		data[];
};
#define SER_BUF_DATA_SIZE	(0x10000 - sizeof(struct fsp_serbuf_hdr))

struct fsp_serial {
	bool			available;
	bool			open;
	char			loc_code[LOC_CODE_SIZE];
	uint16_t		rsrc_id;
	struct fsp_serbuf_hdr	*in_buf;
	struct fsp_serbuf_hdr	*out_buf;
	uint32_t		msg_hdr0;
	uint32_t		msg_hdr1;
};

#define MAX_SERIAL	4

static struct fsp_serial fsp_serials[MAX_SERIAL];
static int fsp_ser_count;
static bool got_intf_query;

#ifdef DVS_CONSOLE
static int fsp_con_port = -1;

static size_t fsp_write_vserial(struct fsp_serial *fs, const char *buf, size_t len)
{
	struct fsp_serbuf_hdr *sb = fs->out_buf;
	uint16_t old_nin = sb->next_in;
	uint16_t space, chunk;

	sync();
	space = (old_nin + SER_BUF_DATA_SIZE - sb->next_out - 1) % SER_BUF_DATA_SIZE;
	if (space < len)
		len = space;
	if (!len)
		return 0;

	chunk = SER_BUF_DATA_SIZE - old_nin;
	memcpy(&sb->data[old_nin], buf, chunk);
	if (chunk < len)
		memcpy(&sb->data[0], buf + chunk, len - chunk);
	sb->next_in = (old_nin + len) % SER_BUF_DATA_SIZE;
	sync();

	/* XXX Make those messages asynchronous, handle the need for a new
	 * one if already pending via a flag & completion callback
	 */
	if (sb->next_out == old_nin)
		fsp_sync_msg(fsp_mkmsgw(FSP_CMD_VSERIAL_OUT, 2,
					fs->msg_hdr0, fs->msg_hdr1), true);

	return len;
}

static size_t fsp_con_write(const char *buf, size_t len)
{
	if (fsp_con_port < 0)
		return 0;

	return fsp_write_vserial(&fsp_serials[fsp_con_port], buf, len);
}

static struct con_ops fsp_con_ops = {
	.write = fsp_con_write,
};
#endif /* DVS_CONSOLE */

static void fsp_open_vserial(struct fsp_msg *msg)
{
	uint16_t part_id = msg->data.words[0] & 0xffff;
	uint16_t sess_id = msg->data.words[1] & 0xffff;
	uint8_t hmc_sess = msg->data.bytes[0];	
	uint8_t hmc_indx = msg->data.bytes[1];
	uint8_t authority = msg->data.bytes[4];
	uint32_t tce_in, tce_out;
	struct fsp_serial *fs;

	printf("FSPCON: Got VSerial Open\n");
	printf("  part_id   = 0x%04x\n", part_id);
	printf("  sess_id   = 0x%04x\n", sess_id);
	printf("  hmc_sess  = 0x%02x\n", hmc_sess);
	printf("  hmc_indx  = 0x%02x\n", hmc_indx);
	printf("  authority = 0x%02x\n", authority);

	if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_OPEN_VSERIAL | 0x2f, 0), true);
		return;
	}
	fs = &fsp_serials[sess_id];
	fs->open = true;

	tce_in = PSI_DMA_SER0_BASE + PSI_DMA_SER0_SIZE * sess_id;
	tce_out = tce_in + SER0_BUFFER_SIZE/2;

	fs->msg_hdr0 = msg->data.words[0];
	fs->msg_hdr1 = msg->data.words[1] & 0xffff;

	fs->in_buf->partition_id = fs->out_buf->partition_id = part_id;
	fs->in_buf->session_id	 = fs->out_buf->session_id   = sess_id;
	fs->in_buf->hmc_id       = fs->out_buf->hmc_id       = hmc_indx;
	fs->in_buf->data_offset  = fs->out_buf->data_offset  = sizeof(struct fsp_serbuf_hdr);
	fs->in_buf->last_valid   = fs->out_buf->last_valid   = SER_BUF_DATA_SIZE - 1;
	fs->in_buf->ovf_count    = fs->out_buf->ovf_count    = 0;
	fs->in_buf->next_in      = fs->out_buf->next_in      = 0;
	fs->in_buf->flags        = fs->out_buf->flags        = 0;
	fs->in_buf->reserved     = fs->out_buf->reserved     = 0;
	fs->in_buf->next_out     = fs->out_buf->next_out     = 0;

	fsp_sync_msg(fsp_mkmsgw(FSP_RSP_OPEN_VSERIAL, 6,
				fs->msg_hdr0,
				fs->msg_hdr1, /* XXX Check pHyp status meaning */
				0, tce_in, 0, tce_out), true);

#ifdef DVS_CONSOLE
	/* XXX Check authority ? */
	if (fs->rsrc_id == 0xffff) {
		fsp_con_port = sess_id;
		set_console(&fsp_con_ops);
	}
#endif
}

static void fsp_close_vserial(struct fsp_msg *msg)
{
	uint16_t part_id = msg->data.words[0] & 0xffff;
	uint16_t sess_id = msg->data.words[1] & 0xffff;
	uint8_t hmc_sess = msg->data.bytes[0];	
	uint8_t hmc_indx = msg->data.bytes[1];
	uint8_t authority = msg->data.bytes[4];

	printf("FSPCON: Got VSerial Close\n");
	printf("  part_id   = 0x%04x\n", part_id);
	printf("  sess_id   = 0x%04x\n", sess_id);
	printf("  hmc_sess  = 0x%02x\n", hmc_sess);
	printf("  hmc_indx  = 0x%02x\n", hmc_indx);
	printf("  authority = 0x%02x\n", authority);

	if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL | 0x2f, 0), true);
		return;
	}
#ifdef DVS_CONSOLE
	if (fsp_serials[sess_id].rsrc_id == 0xffff) {
		fsp_con_port = -1;
		set_console(NULL);
	}
#endif
	fsp_serials[sess_id].open = false;
	fsp_sync_msg(fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL, 0), true);

}

static bool fsp_con_msg_hmc(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	/* Associate response */
	if ((cmd_sub_mod >> 8) == 0xe08a) {
		printf("Got associate response, status 0x%02x\n",
		       cmd_sub_mod & 0xff);
		return true;
	}
	if ((cmd_sub_mod >> 8) == 0xe08b) {
		printf("Got unassociate response, status 0x%02x\n",
		       cmd_sub_mod & 0xff);
		return true;
	}
	switch(cmd_sub_mod) {
	case FSP_CMD_OPEN_VSERIAL:
		fsp_open_vserial(msg);
		free(msg);
		return true;
	case FSP_CMD_CLOSE_VSERIAL:
		fsp_close_vserial(msg);
		free(msg);
		return true;
	case FSP_CMD_HMC_INTF_QUERY:
		printf("Got HMC interface query\n");
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_HMC_INTF_QUERY, 4,
				       0,
				       msg->data.bytes[1],
				       msg->data.bytes[2],
				       msg->data.bytes[3]), true);
		free(msg);
		got_intf_query = true;
		return true;
	}
	return false;
}

static bool fsp_con_msg_vt(uint32_t cmd_sub_mod __unused, struct fsp_msg *msg)
{
	/* We just swallow incoming messages */
	free(msg);
	return true;
}

static struct fsp_client fsp_con_client_hmc = {
	.message = fsp_con_msg_hmc,
};

static struct fsp_client fsp_con_client_vt = {
	.message = fsp_con_msg_vt,
};

void fsp_console_preinit(void)
{
	int i;

	/* Initialize out data structure pointers & TCE maps */
	for (i = 0; i < MAX_SERIAL; i++) {
		struct fsp_serial *ser = &fsp_serials[i];

		ser->in_buf = (void *)SER0_BUFFER_BASE;
		ser->out_buf = (void *)(SER0_BUFFER_BASE + SER0_BUFFER_SIZE/2);
	}
	fsp_tce_map(PSI_DMA_SER0_BASE, (void*)SER0_BUFFER_BASE,
		    4 * PSI_DMA_SER0_SIZE);
	
	/* Register for class E0 and E1 */
	fsp_register_client(&fsp_con_client_hmc, FSP_MCLASS_HMC_INTFMSG);
	fsp_register_client(&fsp_con_client_vt, FSP_MCLASS_HMC_VT);
}

static void fsp_serial_add(uint16_t rsrc_id, const char *loc_code)
{
	struct fsp_serial *ser;
	int index;

	if (fsp_ser_count >= MAX_SERIAL)
		return;

	index = fsp_ser_count++;
	ser = &fsp_serials[index];

	ser->rsrc_id = rsrc_id;
	strncpy(ser->loc_code, loc_code, LOC_CODE_SIZE);
	ser->available = true;

	/* DVS doesn't have that */
	if (rsrc_id != 0xffff)
		fsp_sync_msg(fsp_mkmsgw(FSP_CMD_ASSOC_SERIAL, 2,
					rsrc_id << 16, index), true);
}

void fsp_console_init(void)
{
	/* XXX PARSE IPL PARAMS FOR SERIAL PORTS */
	while (!got_intf_query)
		fsp_poll();

	/* DVS somewhat has to be 0 */
	fsp_serial_add(0xffff, "DVS");
	fsp_serial_add(0x2a00, "T1");
}

