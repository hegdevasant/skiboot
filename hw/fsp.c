/*
 * Service Processor handling code
 *
 * TODO: - Handle redundant FSPs
 */
#include <processor.h>
#include <spira.h>
#include <io.h>
#include <fsp.h>
#include <stdarg.h>

//#define DBG(fmt...)	printf(fmt)
#define DBG(fmt...)	do { } while(0)
#define FSP_TRACE

#define FSP_MAX_IOPATH	4

struct fsp_iopath {
	unsigned short	link_status;	/* straight from SPSS */
	void		*gxhb_regs;
	void		*fsp_regs;
};

enum fsp_mbx_state {
	fsp_mbx_idle,	/* Mailbox ready to send */
	fsp_mbx_send,	/* Mailbox sent, waiting for ack */
	fsp_mbx_error,	/* Mailbox in error state */
};

struct fsp {
	struct fsp		*link;
	unsigned int		index;
	enum fsp_mbx_state	state;
	struct fsp_msg		*pending;

	unsigned int		iopath_count;
	int			active_iopath;	/* -1: no active IO path */
	struct fsp_iopath	iopath[FSP_MAX_IOPATH];
};

static struct fsp *first_fsp;
static struct fsp *active_fsp;
static uint16_t fsp_curseq = 0x8000;
static uint64_t *fsp_tce_table;
static uint32_t fsp_inbound_off;

struct fsp_cmdclass {
	int timeout;
	bool busy;
	struct list_head msgq;
	struct list_head clientq;
};

static struct fsp_cmdclass fsp_cmdclass[FSP_MCLASS_LAST - FSP_MCLASS_FIRST + 1]
= {
#define DEF_CLASS(_cl, _to) [_cl - FSP_MCLASS_FIRST] = { .timeout = _to }
	DEF_CLASS(FSP_MCLASS_SERVICE,		16),
	DEF_CLASS(FSP_MCLASS_PCTRL_MSG,		16),
	DEF_CLASS(FSP_MCLASS_PCTRL_ABORTS,	16),
	DEF_CLASS(FSP_MCLASS_ERR_LOG,		16),
	DEF_CLASS(FSP_MCLASS_CODE_UPDATE,	40),
	DEF_CLASS(FSP_MCLASS_FETCH_SPDATA,	16),
	DEF_CLASS(FSP_MCLASS_FETCH_HVDATA,	16),
	DEF_CLASS(FSP_MCLASS_NVRAM,		16),
	DEF_CLASS(FSP_MCLASS_MBOX_SURV,		 2),
	DEF_CLASS(FSP_MCLASS_RTC,		16),
	DEF_CLASS(FSP_MCLASS_SMART_CHIP,	20),
	DEF_CLASS(FSP_MCLASS_INDICATOR,	       180),
	DEF_CLASS(FSP_MCLASS_HMC_INTFMSG,	16),
	DEF_CLASS(FSP_MCLASS_HMC_VT,		16),
	DEF_CLASS(FSP_MCLASS_HMC_BUFFERS,	16),
	DEF_CLASS(FSP_MCLASS_SHARK,		16),
	DEF_CLASS(FSP_MCLASS_MEMORY_ERR,	16),
	DEF_CLASS(FSP_MCLASS_CUOD_EVENT,	16),
	DEF_CLASS(FSP_MCLASS_HW_MAINT,		16),
	DEF_CLASS(FSP_MCLASS_VIO,		16),
	DEF_CLASS(FSP_MCLASS_SRC_MSG,		16),
	DEF_CLASS(FSP_MCLASS_DATA_COPY,		16),
	DEF_CLASS(FSP_MCLASS_TONE,		16),
	DEF_CLASS(FSP_MCLASS_VIRTUAL_NVRAM,	16)
};

static void fsp_trace_msg(struct fsp_msg *msg __unused,
			  const char *act __unused)
{
#ifdef FSP_TRACE
	uint32_t csm;
	int i;

	csm =  (msg->word0 & 0xff) << 16;
	csm |= (msg->word1 & 0xff) << 8;
	csm |= (msg->word1 >> 8) & 0xff;

	printf("FSP: %s msg %06x %d bytes", act, csm, msg->dlen);
	for (i = 0; i < msg->dlen; i++)
		printf(" %02x", msg->data.bytes[i]);
	printf("\n");
#endif
}

struct fsp *fsp_get_active(void)
{
	/* XXX Handle transition between FSPs */
	return active_fsp;
}

static struct fsp_cmdclass *__fsp_get_cmdclass(uint8_t class)
{
	struct fsp_cmdclass *ret;

	/* Alias classes CE and CF as the FSP has a single queue */
	if (class == FSP_MCLASS_IPL)
		class = FSP_MCLASS_SERVICE;

	ret = &fsp_cmdclass[class - FSP_MCLASS_FIRST];

	/* Unknown class */
	if (ret->timeout == 0)
		return NULL;

	return ret;
}

static struct fsp_cmdclass *fsp_get_cmdclass(struct fsp_msg *msg)
{
	uint8_t c = msg->word0 & 0xff;

	return __fsp_get_cmdclass(c);
}

static void fsp_wreg(struct fsp *fsp, uint32_t reg, uint32_t val)
{
	struct fsp_iopath *iop;

	if (fsp->active_iopath < 0)
		return;
	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->link_status == SPSS_IO_PATH_PSI_LINK_BAD_FRU)
		return;
	out_be32(iop->fsp_regs + reg, val);
}

static uint32_t fsp_rreg(struct fsp *fsp, uint32_t reg)
{
	struct fsp_iopath *iop;

	if (fsp->active_iopath < 0)
		return 0xffffffff;
	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->link_status == SPSS_IO_PATH_PSI_LINK_BAD_FRU)
		return 0xffffffff;
	return in_be32(iop->fsp_regs + reg);
}

static bool fsp_check_err(struct fsp *fsp)
{
	uint32_t hstate;
	bool ret_abort = false;

	/* Check for an error state */
	hstate = fsp_rreg(fsp, FSP_HDES_REG);

	/* Clear errors */
	fsp_wreg(fsp, FSP_HDES_REG, FSP_DBERRSTAT_CLR1);

	/*
	 * Most of those errors shouldn't have happened, we just clear
	 * the error state and return. In the long run, we might want
	 * to start retrying commands, switching FSPs or links, etc...
	 *
	 * We currently don't set our mailbox to a permanent error state.
	 */
	if (hstate & FSP_DBERRSTAT_ILLEGAL1)
		prerror("FSP #%d: Illegal command error !\n", fsp->index);

	if (hstate & FSP_DBERRSTAT_WFULL1) {
		prerror("FSP #%d: Write to a full mbox !\n", fsp->index);
		/* Return true to make fsp_post_msg abort */
		ret_abort = true;
	}

	if (hstate & FSP_DBERRSTAT_REMPTY1)
		prerror("FSP #%d: Read from an empty mbox !\n", fsp->index);

	if (hstate & FSP_DBERRSTAT_PAR1)
		prerror("FSP #%d: Parity error !\n", fsp->index);

	return ret_abort;
}

static bool fsp_post_msg(struct fsp *fsp, struct fsp_msg *msg)
{
	uint32_t ctl, reg;
	int i, wlen;

	DBG("FSP #%d: fsp_post_msg (w0: 0x%08x w1: 0x%08x)\n",
	    fsp->index, msg->word0, msg->word1);

	assert(fsp->state == fsp_mbx_idle);

	/* Check for an error state */
	if (fsp_check_err(fsp))
		return false;

	fsp_trace_msg(msg, "snd");

	/* Sanity: XUP and SPPEND should both be clear */
	ctl = fsp_rreg(fsp, FSP_MBX1_HCTL_REG);
	DBG("    old ctl: %08x\n", ctl);
	assert(!(ctl & (FSP_MBX_CTL_SPPEND | FSP_MBX_CTL_XUP)));

	/* Set ourselves as busy */
	fsp->pending = msg;
	fsp->state = fsp_mbx_send;
	msg->state = fsp_msg_sent;

	/* Build the message in the mailbox */
	reg = FSP_MBX1_HDATA_AREA;
	fsp_wreg(fsp, reg, msg->word0); reg += 4;
	fsp_wreg(fsp, reg, msg->word1); reg += 4;
	wlen = (msg->dlen + 3) >> 2;
	for (i = 0; i < wlen; i++) {
		fsp_wreg(fsp, reg, msg->data.words[i]);
		reg += 4;
	}

	/* Write the header */
	fsp_wreg(fsp, FSP_MBX1_HHDR0_REG, (msg->dlen + 8) << 16);

	/* Write the control register */
	ctl = ctl & ~(FSP_MBX_CTL_HCHOST_MASK | FSP_MBX_CTL_DCHOST_MASK);
	ctl |= 4 << FSP_MBX_CTL_HCHOST_SHIFT;
	ctl |= (msg->dlen + 8) << FSP_MBX_CTL_DCHOST_SHIFT;
	ctl |= FSP_MBX_CTL_PTS | FSP_MBX_CTL_SPPEND;
	DBG("    new ctl: %08x\n", ctl);
	fsp_wreg(fsp, FSP_MBX1_HCTL_REG, ctl);

	return true;
}

static void fsp_poke_queue(struct fsp_cmdclass *cmdclass)
{
	struct fsp *fsp = fsp_get_active();
	struct fsp_msg *msg;

	if (!fsp)
		return;
	if (fsp->state != fsp_mbx_idle)
		return;
	if (cmdclass->busy || list_empty(&cmdclass->msgq))
		return;

	msg = list_top(&cmdclass->msgq, struct fsp_msg, link);
	assert(msg);
	cmdclass->busy = true;

	if (!fsp_post_msg(fsp, msg)) {
		prerror("FSP #%d: Failed to send message\n", fsp->index);
		cmdclass->busy = false;
		return;
	}
}

struct fsp_msg *fsp_mkmsg(uint32_t cmd_sub_mod, uint8_t add_len, ...)
{
	struct fsp_msg *msg = zalloc(sizeof(struct fsp_msg));
	va_list list;
	bool response = !!(cmd_sub_mod & 0x1000000);
	uint8_t cmd = (cmd_sub_mod >> 16) & 0xff;
	uint8_t sub = (cmd_sub_mod >>  8) & 0xff;
	uint8_t mod =  cmd_sub_mod & 0xff;
	int i;

	if (!msg) {
		prerror("FSP: Failed to allocate struct fsp_msg\n");
		return NULL;
	}
	msg->word0 = cmd & 0xff;
	msg->word1 = mod << 8 | sub;
	msg->dlen = add_len;
	msg->response = response;

	va_start(list, add_len);
	for (i = 0; i < add_len; i++)
		msg->data.bytes[i] = va_arg(list, int);
	va_end(list);

	return msg;
}

struct fsp_msg *fsp_mkmsgw(uint32_t cmd_sub_mod, uint8_t add_len, ...)
{
	struct fsp_msg *msg = zalloc(sizeof(struct fsp_msg));
	va_list list;
	bool response = !!(cmd_sub_mod & 0x1000000);
	uint8_t cmd = (cmd_sub_mod >> 16) & 0xff;
	uint8_t sub = (cmd_sub_mod >>  8) & 0xff;
	uint8_t mod =  cmd_sub_mod & 0xff;
	int i;

	if (!msg) {
		prerror("FSP: Failed to allocate struct fsp_msg\n");
		return NULL;
	}
	msg->word0 = cmd & 0xff;
	msg->word1 = mod << 8 | sub;
	msg->dlen = add_len * 4;
	msg->response = response;

	va_start(list, add_len);
	for (i = 0; i < add_len; i++)
		msg->data.words[i] = va_arg(list, unsigned int);
	va_end(list);

	return msg;
}

int fsp_queue_msg(struct fsp_msg *msg)
{
	struct fsp_cmdclass *cmdclass;
	uint16_t seq;

	/* Grab a new sequence number */
	seq = fsp_curseq;
	fsp_curseq = fsp_curseq + 1;
	if (fsp_curseq == 0)
		fsp_curseq = 0x8000;
	msg->word0 |= seq << 16;

	/* Queue the message in the appropriate queue */
	cmdclass = fsp_get_cmdclass(msg);
	if (!cmdclass) {
		prerror("FSP: Invalid message class\n");
		return -1;
	}

	list_add_tail(&cmdclass->msgq, &msg->link);
	msg->state = fsp_msg_queued;

	/* Poke the queue */
	fsp_poke_queue(cmdclass);

	return 0;
}

static void fsp_complete_msg(struct fsp_msg *msg)
{
	struct fsp_cmdclass *cmdclass = fsp_get_cmdclass(msg);
	assert(cmdclass);

	DBG("  completing msg,  word0: 0x%08x\n", msg->word0);

	list_del_from(&cmdclass->msgq, &msg->link);
	cmdclass->busy = false;
	msg->state = fsp_msg_done;
}

static void fsp_complete_send(struct fsp *fsp)
{
	struct fsp_msg *msg = fsp->pending;

	assert(msg);
	fsp->pending = NULL;

	DBG("  completing send, word0: 0x%08x, resp: %d\n",
	    msg->word0, msg->response);

	if (msg->response)
		msg->state = fsp_msg_wresp;
	else
		fsp_complete_msg(msg);
}

static void  fsp_alloc_inbound(struct fsp_msg *msg)
{
	uint16_t func_id = msg->data.words[0] & 0xffff;
	uint32_t len = msg->data.words[1];
	uint32_t tce_token = 0, act_len = 0;
	uint8_t rc = 0;
	void *buf;

	printf("FSP: Allocate inbound buffer func: %04x len: %d\n",
	       func_id, len);

	if ((fsp_inbound_off + len) > FSP_INBOUND_SIZE) {
		prerror("FSP: Out of space in buffer area !\n");
		rc = 0xeb;
		goto reply;
	}
	buf = (void *)FSP_INBOUND_BUFS + fsp_inbound_off;
	tce_token = PSI_DMA_INBOUND_BUF + fsp_inbound_off;
	len = (len + 0xfff) & ~0xfff;
	fsp_inbound_off += len;
	fsp_tce_map(tce_token, buf, len);
	act_len = len;

 reply:
	fsp_sync_msg(fsp_mkmsgw(FSP_RSP_ALLOC_INBOUND | rc,
				2, tce_token, act_len), true);
}

static void fsp_handle_command(struct fsp_msg *msg)
{
	struct fsp_cmdclass *cmdclass = fsp_get_cmdclass(msg);
	struct fsp_client *client, *next;
	uint32_t cmd_sub_mod;

	if (!cmdclass) {
		prerror("FSP: Got message for unknown class %x\n",
			msg->word0 & 0xff);
		goto free;
	}

	cmd_sub_mod =  (msg->word0 & 0xff) << 16;
	cmd_sub_mod |= (msg->word1 & 0xff) << 8;
	cmd_sub_mod |= (msg->word1 >> 8) & 0xff;
	
	/* Some commands are handled locally */
	switch(cmd_sub_mod) {
	case FSP_CMD_ALLOC_INBOUND:
		fsp_alloc_inbound(msg);
		goto free;
	}

	list_for_each_safe(&cmdclass->clientq, client, next, link) {
		if (client->message(cmd_sub_mod, msg))
			return;
	}

	prerror("FSP: Unhandled message %06x\n", cmd_sub_mod);
 free:
	free(msg);
}

static void fsp_handle_incoming(struct fsp *fsp)
{
	struct fsp_msg *msg = zalloc(sizeof(struct fsp_msg));
	uint32_t h0, w0, w1, reg;
	int i, dlen, wlen;
	bool special_response = false;

	h0 = fsp_rreg(fsp, FSP_MBX1_FHDR0_REG);
	dlen = (h0 >> 16) & 0xff;

	reg = FSP_MBX1_FDATA_AREA;
	w0 = fsp_rreg(fsp, reg); reg += 4;
	w1 = fsp_rreg(fsp, reg); reg += 4;

	DBG("  Incoming: w0: 0x%08x, w1: 0x%08x, dlen: %d\n",
	    w0, w1, dlen);

	msg->state = fsp_msg_incoming;
	msg->dlen = dlen - 8;
	msg->word0 = w0;
	msg->word1 = w1;
	wlen = (dlen + 3) >> 2;
	for (i = 0; i < wlen; i++) {
		msg->data.words[i] = fsp_rreg(fsp, reg);
		reg += 4;
	}

	/* Ack it (XDN) and clear HPEND & counts */
	fsp_wreg(fsp, FSP_MBX1_HCTL_REG,
		 FSP_MBX_CTL_XDN |
		 FSP_MBX_CTL_HPEND |
		 FSP_MBX_CTL_HCSP_MASK |
		 FSP_MBX_CTL_DCSP_MASK);

	fsp_trace_msg(msg, "got");

	/* Some responses are expected out of band */
	if ((w0 & 0xff) == FSP_MCLASS_HMC_INTFMSG  &&
	    ((w1 & 0xff) == 0x8a || ((w1 & 0xff) == 0x8b)))
		special_response = true;

	/* Check for response bit */
	if (w1 & 0x80 && !special_response) {
		struct fsp_cmdclass *cmdclass = fsp_get_cmdclass(msg);
		struct fsp_msg *req;

		if (!cmdclass->busy || list_empty(&cmdclass->msgq)) {
			prerror("FSP #%d: Got orphan response !\n", fsp->index);
			/* XXX DUMP MESSAGE */
			free(msg);
			return;
		}
		req = list_top(&cmdclass->msgq, struct fsp_msg, link);

		/* XXX Check matching req/resp ? */
		DBG("  -> resp for w0: %x w1: %x\n", req->word0, req->word1);
		req->resp = msg;
		fsp_complete_msg(req);
		return;
	}

	/* Handle FSP commands. This can recurse into fsp_queue_command etc.. */
	fsp_handle_command(msg);
}

static void fsp_check_queues(void)
{
	int i;

	/* XXX In the long run, we might want to have a queue of
	 * classes waiting to be serviced to speed this up, either
	 * that or a bitmap.
	 */
	for (i = 0; i <= (FSP_MCLASS_LAST - FSP_MCLASS_FIRST); i++) {
		struct fsp_cmdclass *cmdclass = &fsp_cmdclass[i];

		if (cmdclass->busy || list_empty(&cmdclass->msgq))
			continue;
		fsp_poke_queue(cmdclass);
	}
}

void fsp_poll(void)
{
	struct fsp *fsp = fsp_get_active();
	uint32_t ctl;

	/* Poll FSP CTL */
	ctl = fsp_rreg(fsp, FSP_MBX1_HCTL_REG);

	if (ctl & (FSP_MBX_CTL_XUP | FSP_MBX_CTL_HPEND))
		DBG("FSP #%d: poll, ctl: %x\n", fsp->index, ctl);

	/* Do we have a pending message waiting to complete ? */
	if (ctl & FSP_MBX_CTL_XUP) {
		fsp_wreg(fsp, FSP_MBX1_HCTL_REG, FSP_MBX_CTL_XUP);
		if (fsp->state == fsp_mbx_send) {

			/* Complete message */
			fsp_complete_send(fsp);

			/* mbox is free */
			fsp->state = fsp_mbx_idle;

			/* Check for something else to send */
			fsp_check_queues();
		} else {
			prerror("FSP #%d: Got XUP with no pending message !\n",
				fsp->index);
		}
	}

	if (fsp->state == fsp_mbx_send) {
		/* XXX Handle send timeouts!!! */
	}

	/* Is there an incoming message ? */
	if (ctl & FSP_MBX_CTL_HPEND)
		fsp_handle_incoming(fsp);
}

int fsp_wait_complete(struct fsp_msg *msg)
{
	/* XXX HANDLE TIMEOUTS */
	while(msg->state != fsp_msg_done)
		fsp_poll();

	return 0;
}

int fsp_sync_msg(struct fsp_msg *msg, bool free_it)
{
	int rc;

	rc = fsp_queue_msg(msg);
	if (rc)
		goto bail;

	rc = fsp_wait_complete(msg);
	if (rc == 0 && msg->resp)
		rc = (msg->resp->word1 >> 8) & 0xff;
 bail:
	if (free_it) {
		if (msg->resp)
			free(msg->resp);
		free(msg);
	}
	return rc;
}

static bool fsp_check_impl(const void *spss, int i)
{
	const struct spss_sp_impl *sp_impl;
	unsigned int mask;

	/* Find an check the SP Implementation structure */
	sp_impl = HDIF_get_idata(spss, SPSS_IDATA_SP_IMPL, NULL);
	if (!sp_impl) {
		prerror("FSP #%d: SPSS/SP_Implementation not found !\n", i);
		return false;
	}

	printf("FSP #%d: FSP HW version %d, SW version %d, chip DD%d.%d\n",
	       i, sp_impl->hw_version, sp_impl->sw_version,
	       sp_impl->chip_version >> 4, sp_impl->chip_version & 0xf);
	mask = SPSS_SP_IMPL_FLAGS_FUNCTIONAL | SPSS_SP_IMPL_FLAGS_FUNCTIONAL;
	if ((sp_impl->func_flags & mask) != mask) {
		prerror("FSP #%d: FSP not installed or not functional\n", i);
		return false;
	}

	return true;
}

void fsp_register_client(struct fsp_client *client, uint8_t msgclass)
{
	struct fsp_cmdclass *cmdclass = __fsp_get_cmdclass(msgclass);

	list_add_tail(&cmdclass->clientq, &client->link);
}

void fsp_unregister_client(struct fsp_client *client, uint8_t msgclass)
{
	struct fsp_cmdclass *cmdclass = __fsp_get_cmdclass(msgclass);

	list_del_from(&cmdclass->clientq, &client->link);
}

static void fsp_reg_dump(struct fsp *fsp __unused)
{
#if 0

#define FSP_DUMP_ONE(x)	\
	DBG("  %20s: %x\n", #x, fsp_rreg(fsp, x));

	DBG("FSP #%d: Register dump...\n", fsp->index);
	FSP_DUMP_ONE(FSP_DRCR_REG);
	FSP_DUMP_ONE(FSP_DISR_REG);
	FSP_DUMP_ONE(FSP_MBX1_HCTL_REG);
	FSP_DUMP_ONE(FSP_MBX1_FCTL_REG);
	FSP_DUMP_ONE(FSP_MBX2_HCTL_REG);
	FSP_DUMP_ONE(FSP_MBX2_FCTL_REG);
	FSP_DUMP_ONE(FSP_SDES_REG);
	FSP_DUMP_ONE(FSP_HDES_REG);
	FSP_DUMP_ONE(FSP_HDIR_REG);
	FSP_DUMP_ONE(FSP_HDIM_SET_REG);
	FSP_DUMP_ONE(FSP_PDIR_REG);
	FSP_DUMP_ONE(FSP_PDIM_SET_REG);
	FSP_DUMP_ONE(FSP_SCRATCH0_REG);
	FSP_DUMP_ONE(FSP_SCRATCH1_REG);
	FSP_DUMP_ONE(FSP_SCRATCH2_REG);
	FSP_DUMP_ONE(FSP_SCRATCH3_REG);
#endif
}

/* We use a single fixed TCE table for all PSI interfaces */
static void fsp_init_tce_table(void)
{
	fsp_tce_table = (uint64_t *)PSI_TCE_TABLE_BASE;

	memset(fsp_tce_table, 0, PSI_TCE_TABLE_SIZE);
}

void fsp_tce_map(uint32_t offset, void *addr, uint32_t size)
{
	uint64_t raddr = (uint64_t)addr;

	assert(!(offset & 0xfff));
	assert(!(raddr  & 0xfff));
	assert(!(size   & 0xfff));

	size   >>= 12;
	offset >>= 12;

	while(size--) {
		fsp_tce_table[offset++] = raddr | 0x3;
		raddr += 0x1000;
	}
}

void fsp_tce_unmap(uint32_t offset, uint32_t size)
{
	assert(!(offset & 0xfff));
	assert(!(size   & 0xfff));

	size   >>= 12;
	offset >>= 12;

	while(size--)
		fsp_tce_table[offset++] = 0;
}

static void fsp_create_fsp(const void *spss, int index)
{
	struct fsp *fsp;
	int count, i;

	fsp = zalloc(sizeof(struct fsp));
	if (!fsp) {
		prerror("FSP #%d: Can't allocate memory !\n", index);
		return;
	}

	fsp->index = index;
	fsp->active_iopath = -1;

	count = HDIF_get_iarray_size(spss, SPSS_IDATA_SP_IOPATH);
	if (count < 0) {
		prerror("FSP #%d: Can't find IO PATH array size !\n", index);
		free(fsp);
		return;
	}
	printf("FSP #%d: Found %d IO PATH\n", index, count);
	if (count > FSP_MAX_IOPATH) {
		prerror("FSP #%d: WARNING, limited to %d IO PATH\n",
			index, FSP_MAX_IOPATH);
		count = FSP_MAX_IOPATH;
	}
	fsp->iopath_count = count;
	fsp->state = fsp_mbx_idle;

	/* Iterate all links */
	for (i = 0; i < count; i++) {
		const struct spss_iopath *iopath;
		struct fsp_iopath *fiop;
		unsigned int iopath_sz;
		const char *ststr;
		bool active;
		uint64_t reg;

		iopath = HDIF_get_iarray_item(spss, SPSS_IDATA_SP_IOPATH,
					      i, &iopath_sz);
		if (!iopath) {
			prerror("FSP #%d: Can't find IO PATH %d\n", index, i);
			fsp->iopath_count = i;
			break;
		}
		if (iopath->iopath_type != SPSS_IOPATH_TYPE_PSI) {
			prerror("FSP #%d: Unsupported IO PATH %d type 0x%04x\n",
				index, i, iopath->iopath_type);
			continue;
		}
		fiop = &fsp->iopath[i];
		fiop->link_status = iopath->psi.link_status;
		fiop->gxhb_regs = (void *)iopath->psi.gxhb_base;
		active = false;
		switch(fiop->link_status) {
		case SPSS_IO_PATH_PSI_LINK_BAD_FRU:
			ststr = "Broken";
			break;
		case SPSS_IO_PATH_PSI_LINK_CURRENT:
			ststr = "Active";
			active = true;
			break;
		case SPSS_IO_PATH_PSI_LINK_BACKUP:
			ststr = "Backup";
			break;
		default:
			ststr = "Unknown";
		}
		printf("FSP #%d: IO PATH %d is %s PSI Link, GXHB at %llx\n",
		       index, i, ststr, iopath->psi.gxhb_base);
		if (active)
			fsp->active_iopath = i;

		/* Disable, configure and enable the TCE table */
		reg = in_be64(fiop->gxhb_regs + PSIHB_CR);
		reg &= ~0x2000000000000000ULL;
		out_be64(fiop->gxhb_regs + PSIHB_CR, reg);
		out_be64(fiop->gxhb_regs + PSIHB_TAR, PSI_TCE_TABLE_BASE | 1);
		reg |= 0x2000000000000000ULL;
		out_be64(fiop->gxhb_regs + PSIHB_CR, reg);

		/* Dump the GXHB registers */
#if 0
		DBG("  PSIHB_BBAR   : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_BBAR));
		DBG("  PSIHB_FSPBAR : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_FSPBAR));
		DBG("  PSIHB_FSPMMR : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_FSPMMR));
		DBG("  PSIHB_TAR    : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_TAR));
		DBG("  PSIHB_CR     : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_CR));
		DBG("  PSIHB_SEMR   : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_SEMR));
		DBG("  PSIHB_XIVR   : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_XIVR));
#endif

		/* Get the FSP register window */
		reg = in_be64(fiop->gxhb_regs + PSIHB_FSPBAR);
		fiop->fsp_regs =
			(void *)(reg | (1ULL << 63) | FSP1_REG_OFFSET);
		
	}
	if (fsp->active_iopath >= 0 && !active_fsp) {
		fsp_reg_dump(fsp);
		active_fsp = fsp;
	}

	fsp->link = first_fsp;
	first_fsp = fsp;
}

void fsp_init(void)
{
	void *base_spss, *spss;
	int i;
	
	/* Initialize the per-class msg queues */
	for (i = 0; i <= (FSP_MCLASS_LAST - FSP_MCLASS_FIRST); i++) {
		list_head_init(&fsp_cmdclass[i].msgq);
		list_head_init(&fsp_cmdclass[i].clientq);
	}

	/* Initialize a TCE table */
	fsp_init_tce_table();

	/* Find SPSS in SPIRA */
	base_spss = spira.ntuples.sp_subsys.addr;
	if (!base_spss) {
		prerror("FSP: Cannot locate SPSS !\n");
		return;
	}

	/* For each SPSS */
	for (i = 0; i < spira.ntuples.sp_subsys.act_cnt; i++) {
		spss = base_spss + i * spira.ntuples.sp_subsys.alloc_len;


		if (!HDIF_check(spss, "SPINFO")) {
			prerror("FSP #%d: SPSS signature mismatch !\n", i);
			continue;
		}

		/* Check SP Implementation */
		if (!fsp_check_impl(spss, i))
			continue;

		/* Create the FSP data structure */
		fsp_create_fsp(spss, i);
	}
	if (!active_fsp)
		prerror("FSP: No active FSP !\n");
}

