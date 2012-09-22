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
	u16	partition_id;
	u8	session_id;
	u8	hmc_id;
	u16	data_offset;
	u16	last_valid;
	u16	ovf_count;
	u16	next_in;
	u8	flags;
	u8	reserved;
	u16	next_out;
	u8	data[];
};
#define SER_BUF_DATA_SIZE	(0x10000 - sizeof(struct fsp_serbuf_hdr))

struct fsp_serial {
	bool			available;
	bool			open;
	bool			log_port;
	bool			out_poke;
	char			loc_code[LOC_CODE_SIZE];
	u16			rsrc_id;
	struct fsp_serbuf_hdr	*in_buf;
	struct fsp_serbuf_hdr	*out_buf;
	struct fsp_msg		*poke_msg;
};

#define MAX_SERIAL	4

static struct fsp_serial fsp_serials[MAX_SERIAL];
static bool got_intf_query;

#ifdef DVS_CONSOLE
static int fsp_con_port = -1;

static void fsp_pokemsg_reclaim(struct fsp_msg *msg)
{
	struct fsp_serial *fs = msg->user_data;

	/* Synchronize with fsp_write_serial() */
	lock(&con_lock);
	if (fs->open) {
		if (fs->out_poke) {
			fs->out_poke = false;
			fsp_queue_msg(fs->poke_msg, fsp_pokemsg_reclaim);
		} else
			fs->poke_msg->state = fsp_msg_unused;
	} else {
		fsp_freemsg(msg);
		fs->poke_msg = NULL;
	}
	unlock(&con_lock);
}

/* NOTE: This is meant to be called with the con_lock held. This will
 * be true as well of the runtime variant called via the OPAL APIs
 * unless we change the locking scheme (might be suitable to have
 * the console call this without lock, and use the FSP lock here,
 * since fsp_queue_msg() supports recursive locking. That would
 * limit the number of atomic ops on the console path.
 */
static size_t fsp_write_vserial(struct fsp_serial *fs, const char *buf, size_t len)
{
	struct fsp_serbuf_hdr *sb = fs->out_buf;
	u16 old_nin = sb->next_in;
	u16 space, chunk;

	if (!fs->open)
		return 0;

	sync();
	space = (old_nin + SER_BUF_DATA_SIZE - sb->next_out - 1)
		% SER_BUF_DATA_SIZE;
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

	if (sb->next_out == old_nin) {
		if (fs->poke_msg->state == fsp_msg_unused)
			fsp_queue_msg(fs->poke_msg, fsp_pokemsg_reclaim);
		else
			fs->out_poke = true;
	}
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
	u16 part_id = msg->data.words[0] & 0xffff;
	u16 sess_id = msg->data.words[1] & 0xffff;
	u8 hmc_sess = msg->data.bytes[0];	
	u8 hmc_indx = msg->data.bytes[1];
	u8 authority = msg->data.bytes[4];
	u32 tce_in, tce_out;
	struct fsp_serial *fs;

	printf("FSPCON: Got VSerial Open\n");
	printf("  part_id   = 0x%04x\n", part_id);
	printf("  sess_id   = 0x%04x\n", sess_id);
	printf("  hmc_sess  = 0x%02x\n", hmc_sess);
	printf("  hmc_indx  = 0x%02x\n", hmc_indx);
	printf("  authority = 0x%02x\n", authority);

	if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_OPEN_VSERIAL | 0x2f, 0),
			      fsp_freemsg);
		return;
	}

	fs = &fsp_serials[sess_id];
	fs->open = true;

	tce_in = PSI_DMA_SER0_BASE + PSI_DMA_SER0_SIZE * sess_id;
	tce_out = tce_in + SER0_BUFFER_SIZE/2;

	/* If we still have a msg, wait for it to go away */
	while (fs->poke_msg)
		fsp_poll();

	fs->poke_msg = fsp_mkmsg(FSP_CMD_VSERIAL_OUT, 2,
				 msg->data.words[0],
				 msg->data.words[1] & 0xffff);
	fs->poke_msg->user_data = fs;

	fs->in_buf->partition_id = fs->out_buf->partition_id = part_id;
	fs->in_buf->session_id	 = fs->out_buf->session_id   = sess_id;
	fs->in_buf->hmc_id       = fs->out_buf->hmc_id       = hmc_indx;
	fs->in_buf->data_offset  = fs->out_buf->data_offset  =
		sizeof(struct fsp_serbuf_hdr);
	fs->in_buf->last_valid   = fs->out_buf->last_valid   =
		SER_BUF_DATA_SIZE - 1;
	fs->in_buf->ovf_count    = fs->out_buf->ovf_count    = 0;
	fs->in_buf->next_in      = fs->out_buf->next_in      = 0;
	fs->in_buf->flags        = fs->out_buf->flags        = 0;
	fs->in_buf->reserved     = fs->out_buf->reserved     = 0;
	fs->in_buf->next_out     = fs->out_buf->next_out     = 0;

	fsp_queue_msg(fsp_mkmsg(FSP_RSP_OPEN_VSERIAL, 6,
				msg->data.words[0],
				msg->data.words[1] & 0xffff,
				0, tce_in, 0, tce_out), fsp_freemsg);

#ifdef DVS_CONSOLE
	if (fs->log_port) {
		fsp_con_port = sess_id;
		sync();
		set_console(&fsp_con_ops);
	}
#endif
}

static void fsp_close_vserial(struct fsp_msg *msg)
{
	u16 part_id = msg->data.words[0] & 0xffff;
	u16 sess_id = msg->data.words[1] & 0xffff;
	u8 hmc_sess = msg->data.bytes[0];	
	u8 hmc_indx = msg->data.bytes[1];
	u8 authority = msg->data.bytes[4];
	struct fsp_serial *fs;

	printf("FSPCON: Got VSerial Close\n");
	printf("  part_id   = 0x%04x\n", part_id);
	printf("  sess_id   = 0x%04x\n", sess_id);
	printf("  hmc_sess  = 0x%02x\n", hmc_sess);
	printf("  hmc_indx  = 0x%02x\n", hmc_indx);
	printf("  authority = 0x%02x\n", authority);

	if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
		fsp_queue_msg(fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL | 0x2f, 0),
			      fsp_freemsg);
		return;
	}

	fs = &fsp_serials[sess_id];

#ifdef DVS_CONSOLE
	if (fs->log_port) {
		fsp_con_port = -1;
		set_console(NULL);
	}
#endif
	
	lock(&con_lock);
	fs->open = false;
	fs->out_poke = false;
	if (fs->poke_msg && fs->poke_msg->state == fsp_msg_unused) {
		fsp_freemsg(fs->poke_msg);
		fs->poke_msg = NULL;
	}
	unlock(&con_lock);

	fsp_queue_msg(fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL, 0), fsp_freemsg);

}

static bool fsp_con_msg_hmc(u32 cmd_sub_mod, struct fsp_msg *msg)
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
		return true;
	case FSP_CMD_CLOSE_VSERIAL:
		fsp_close_vserial(msg);
		return true;
	case FSP_CMD_HMC_INTF_QUERY:
		printf("FSPCON: Got HMC interface query\n");

		/* Keep that synchronous due to FSP fragile ordering
		 * of the boot sequence
		 */
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_HMC_INTF_QUERY, 1,
				       msg->data.words[0] & 0x00ffffff), true);
		got_intf_query = true;
		return true;
	}
	return false;
}

static bool fsp_con_msg_vt(u32 cmd_sub_mod __unused,
			   struct fsp_msg *msg __unused)
{
	/* We just swallow incoming messages */
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

static void fsp_serial_add(int index, u16 rsrc_id, const char *loc_code,
			   bool log_port)
{
	struct fsp_serial *ser;

	lock(&con_lock);
	ser = &fsp_serials[index];

	if (ser->available) {
		unlock(&con_lock);
		return;
	}

	ser->rsrc_id = rsrc_id;
	strncpy(ser->loc_code, loc_code, LOC_CODE_SIZE);
	ser->available = true;
	ser->log_port = log_port;

	/* DVS doesn't have that */
	if (rsrc_id != 0xffff)
		fsp_sync_msg(fsp_mkmsg(FSP_CMD_ASSOC_SERIAL, 2,
				       (rsrc_id << 16) | 1, index), true);
}

void fsp_console_init(void)
{
	const struct iplparms_serial *ipser;
	const void *ipl_parms;
	int count, i;

	/* Wait until we got the intf query before moving on */
	while (!got_intf_query)
		fsp_poll();

	/* Add DVS ports. We currently have session 0 and 3, 0 is for
	 * OS use. 3 is our debug port
	 */
	fsp_serial_add(0, 0xffff, "DVS_OS", false);
	fsp_serial_add(3, 0xffff, "DVS_FW", true);

	/* Parse serial port data */
	ipl_parms = spira.ntuples.ipl_parms.addr;
	if (!ipl_parms) {
		prerror("FSPCON: Cannot find IPL Parms in SPIRA\n");
		return;
	}
	if (!HDIF_check(ipl_parms, "IPLPMS")) {
		prerror("FSPCON: IPL Parms has wrong header type\n");
		return;
	}

	count = HDIF_get_iarray_size(ipl_parms, IPLPARMS_IDATA_SERIAL);
	if (!count) {
		prerror("FSPCON: No serial port in the IPL Parms\n");
		return;
	}
	if (count > 2) {
		prerror("FSPCON: %d serial ports, truncating to 2\n", count);
		count = 2;
	}
	for (i = 0; i < count; i++) {
		ipser = HDIF_get_iarray_item(ipl_parms, IPLPARMS_IDATA_SERIAL,
					     i, NULL);
		printf("FSPCON: Serial %d rsrc: %04x loc: %s\n",
		       i, ipser->rsrc_id, ipser->loc_code);
		fsp_serial_add(i + 1, ipser->rsrc_id, ipser->loc_code, false);
	}
}

