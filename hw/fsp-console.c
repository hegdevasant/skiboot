/*
 * Service Processor serial console handling code
 */
#include <skiboot.h>
#include <processor.h>
#include <spira.h>
#include <io.h>
#include <fsp.h>

struct fsp_serbuf_hdr {
	uint16_t	partition_id;
	uint8_t		partition_sid;
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
};

#define MAX_SERIAL	4

static struct fsp_serial fsp_serials[MAX_SERIAL];
static int fsp_ser_count;
static bool got_intf_query;

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

	fsp_sync_msg(fsp_mkmsgw(FSP_CMD_ASSOC_SERIAL, 2,
				rsrc_id << 16, index), true);
}

static bool fsp_con_msg_hmc(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	uint16_t part_id = msg->data.words[0] & 0xffff;
	uint16_t sess_id = msg->data.words[1] & 0xffff;
	uint8_t hmc_sess = msg->data.bytes[0];	
	uint8_t hmc_indx = msg->data.bytes[1];
	uint8_t authority = msg->data.bytes[4];

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
#if 1
	printf("Got HMC cmd %06x\n", cmd_sub_mod);
	if (cmd_sub_mod == FSP_CMD_OPEN_VSERIAL ||
	    cmd_sub_mod == FSP_CMD_CLOSE_VSERIAL) {
		printf("  part_id   = 0x%04x\n", part_id);
		printf("  sess_id   = 0x%04x\n", sess_id);
		printf("  hmc_sess  = 0x%02x\n", hmc_sess);
		printf("  hmc_indx  = 0x%02x\n", hmc_indx);
		printf("  authority = 0x%02x\n", authority);
	}
#endif

	switch(cmd_sub_mod) {
	case FSP_CMD_OPEN_VSERIAL:
		free(msg);
		if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
			fsp_sync_msg(fsp_mkmsg(FSP_RSP_OPEN_VSERIAL | 0x2f, 0),
				     true);
		} else {
			fsp_serials[sess_id].open = true;
			fsp_sync_msg(fsp_mkmsg(FSP_RSP_OPEN_VSERIAL, 0), true);
		}
		return true;
	case FSP_CMD_CLOSE_VSERIAL:
		free(msg);
		if (sess_id >= MAX_SERIAL || !fsp_serials[sess_id].available) {
			fsp_sync_msg(fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL | 0x2f, 0),
				     true);
		} else {
			fsp_serials[sess_id].open = true;
			fsp_sync_msg(fsp_mkmsg(FSP_RSP_CLOSE_VSERIAL, 0), true);
		}
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

static bool fsp_con_msg_vt(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	return false;
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

void fsp_console_init(void)
{
	/* XXX PARSE IPL PARAMS FOR SERIAL PORTS */
	while (!got_intf_query)
		fsp_poll();

	fsp_serial_add(0x2a00, "foo");
}

