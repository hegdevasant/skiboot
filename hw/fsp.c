/*
 * Service Processor handling code
 *
 * TODO: - Handle redundant FSPs
 *       - Monitor PSI link state
 *         -> handle link errors, switch links, etc...
 *       - Handle reset/reload
 */
#include <stdarg.h>
#include <processor.h>
#include <spira.h>
#include <io.h>
#include <fsp.h>
#include <lock.h>

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
static u16 fsp_curseq = 0x8000;
static u64 *fsp_tce_table;
static u32 fsp_inbound_off;
static struct lock fsp_lock = LOCK_UNLOCKED;

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
	u32 csm;
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

static struct fsp_cmdclass *__fsp_get_cmdclass(u8 class)
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
	u8 c = msg->word0 & 0xff;

	return __fsp_get_cmdclass(c);
}

static struct fsp_msg *__fsp_allocmsg(void)
{
	return zalloc(sizeof(struct fsp_msg));
}

struct fsp_msg *fsp_allocmsg(bool alloc_response)
{
	struct fsp_msg *msg;

	msg = __fsp_allocmsg();
	if (!msg)
		return NULL;
	if (alloc_response)
		msg->resp = __fsp_allocmsg();
	return msg;
}

void __fsp_freemsg(struct fsp_msg *msg)
{
	free(msg);
}

void fsp_freemsg(struct fsp_msg *msg)
{
	if (msg->resp)
		__fsp_freemsg(msg->resp);
	__fsp_freemsg(msg);
}

static void fsp_wreg(struct fsp *fsp, u32 reg, u32 val)
{
	struct fsp_iopath *iop;

	if (fsp->active_iopath < 0)
		return;
	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->link_status == SPSS_IO_PATH_PSI_LINK_BAD_FRU)
		return;
	out_be32(iop->fsp_regs + reg, val);
}

static u32 fsp_rreg(struct fsp *fsp, u32 reg)
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
	u32 hstate;
	bool ret_abort = false;

	/* Check for an error state */
	hstate = fsp_rreg(fsp, FSP_HDES_REG);
	if (hstate == 0xffffffff) {
		prerror("FSP #%d: Link seems to be down\n", fsp->index);
		/* XXX Start recovery */
		fsp->state = fsp_mbx_error;
		return true;
	}

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
	u32 ctl, reg;
	int i, wlen;

	DBG("FSP #%d: fsp_post_msg (w0: 0x%08x w1: 0x%08x)\n",
	    fsp->index, msg->word0, msg->word1);

	assert(fsp->state == fsp_mbx_idle);

	/* Check for an error state */
	if (fsp_check_err(fsp))
		return false;

	/* Note: We used to read HCTL here and only modify some of
	 * the bits in it. This was bogus, because we would write back
	 * the incoming bits as '1' and clear them, causing fsp_poll()
	 * to then miss them. Let's just start with 0, which is how
	 * I suppose the HW intends us to do.
	 */

	/* Set ourselves as busy */
	fsp->pending = msg;
	fsp->state = fsp_mbx_send;
	msg->state = fsp_msg_sent;

	/* We trace after setting the mailbox state so that if the
	 * tracing recurses, it ends up just queuing the message up
	 */
	fsp_trace_msg(msg, "snd");

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
	ctl = 4 << FSP_MBX_CTL_HCHOST_SHIFT;
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

	/* From here to the point where fsp_post_msg() sets fsp->state
	 * to !idle we must not cause any re-entrency (no debug or trace)
	 * in a code path that may hit fsp_post_msg() (it's ok to do so
	 * if we are going to bail out), as we are committed to calling
	 * fsp_post_msg() and so a re-entrancy could cause us to do a
	 * double-send into the mailbox.
	 */
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

static void __fsp_fillmsg(struct fsp_msg *msg, u32 cmd_sub_mod,
			  u8 add_words, va_list list)
{
	bool response = !!(cmd_sub_mod & 0x1000000);
	u8 cmd = (cmd_sub_mod >> 16) & 0xff;
	u8 sub = (cmd_sub_mod >>  8) & 0xff;
	u8 mod =  cmd_sub_mod & 0xff;
	int i;

	msg->word0 = cmd & 0xff;
	msg->word1 = mod << 8 | sub;
	msg->response = response;
	msg->dlen = add_words << 2;

	for (i = 0; i < add_words; i++)
		msg->data.words[i] = va_arg(list, unsigned int);
	va_end(list);

}

extern void fsp_fillmsg(struct fsp_msg *msg, u32 cmd_sub_mod, u8 add_words, ...)
{
	va_list list;

	va_start(list, add_words);
	__fsp_fillmsg(msg, cmd_sub_mod, add_words, list);
	va_end(list);
}

struct fsp_msg *fsp_mkmsg(u32 cmd_sub_mod, u8 add_words, ...)
{
	struct fsp_msg *msg = fsp_allocmsg(!!(cmd_sub_mod & 0x1000000));
	va_list list;

	if (!msg) {
		prerror("FSP: Failed to allocate struct fsp_msg\n");
		return NULL;
	}

	va_start(list, add_words);
	__fsp_fillmsg(msg, cmd_sub_mod, add_words, list);
	va_end(list);

	return msg;
}

int fsp_queue_msg(struct fsp_msg *msg, void (*comp)(struct fsp_msg *msg))
{
	struct fsp_cmdclass *cmdclass;
	bool need_unlock;
	u16 seq;
	int rc = 0;

	if (!active_fsp)
		return -1;

	/* Recursive locking */
	need_unlock = lock_recursive(&fsp_lock);

	/* Grab a new sequence number */
	seq = fsp_curseq;
	fsp_curseq = fsp_curseq + 1;
	if (fsp_curseq == 0)
		fsp_curseq = 0x8000;
	msg->word0 = (msg->word0 & 0xffff) | seq << 16;

	/* Set completion */
	msg->complete = comp;

	/* Clear response state */
	if (msg->resp)
		msg->resp->state = fsp_msg_unused;

	/* Queue the message in the appropriate queue */
	cmdclass = fsp_get_cmdclass(msg);
	if (!cmdclass) {
		prerror("FSP: Invalid message class\n");
		rc = -1;
		goto unlock;
	}

	list_add_tail(&cmdclass->msgq, &msg->link);
	msg->state = fsp_msg_queued;

	/* Poke the queue */
	fsp_poke_queue(cmdclass);

 unlock:
	if (need_unlock)
		unlock(&fsp_lock);

	return rc;
}

/* WARNING: This will drop the FSP lock !!! */
static void fsp_complete_msg(struct fsp_msg *msg)
{
	struct fsp_cmdclass *cmdclass = fsp_get_cmdclass(msg);
	void (*comp)(struct fsp_msg *msg);

	assert(cmdclass);

	DBG("  completing msg,  word0: 0x%08x\n", msg->word0);

	comp = msg->complete;
	list_del_from(&cmdclass->msgq, &msg->link);
	cmdclass->busy = false;
	msg->state = fsp_msg_done;

	unlock(&fsp_lock);
	if (comp)
		(*comp)(msg);
}

/* WARNING: This will drop the FSP lock !!! */
static void fsp_complete_send(struct fsp *fsp)
{
	struct fsp_msg *msg = fsp->pending;

	assert(msg);
	fsp->pending = NULL;

	DBG("  completing send, word0: 0x%08x, resp: %d\n",
	    msg->word0, msg->response);

	if (msg->response) {
		msg->state = fsp_msg_wresp;
		unlock(&fsp_lock);
	} else
		fsp_complete_msg(msg);
}

static void  fsp_alloc_inbound(struct fsp_msg *msg)
{
	u16 func_id = msg->data.words[0] & 0xffff;
	u32 len = msg->data.words[1];
	u32 tce_token = 0, act_len = 0;
	u8 rc = 0;
	void *buf;

	printf("FSP: Allocate inbound buffer func: %04x len: %d\n",
	       func_id, len);

	lock(&fsp_lock);
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
	printf("FSP:  -> buffer at 0x%p, TCE: 0x%08x, alen: 0x%x\n",
	       buf, tce_token, len);
	act_len = len;

 reply:
	unlock(&fsp_lock);
	fsp_queue_msg(fsp_mkmsg(FSP_RSP_ALLOC_INBOUND | rc,
				3, 0, tce_token, act_len), fsp_freemsg);
}

static bool fsp_local_command(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	switch(cmd_sub_mod) {
	case FSP_CMD_CONTINUE_IPL:
		/* We get a CONTINUE_IPL as a response to OPL */
		printf("FSP: Got CONTINUE_IPL !\n");
		ipl_state |= ipl_got_continue;
		return true;

	case FSP_CMD_HV_STATE_CHG:
		printf("FSP: Got HV state change request to %d\n",
		       msg->data.bytes[0]);

		/* Send response synchronously for now, we might want to
		 * deal with that sort of stuff asynchronously if/when
		 * we add support for auto-freeing of messages
		 */
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_HV_STATE_CHG, 0), true);
		return true;

	case FSP_CMD_SP_NEW_ROLE:
		/* FSP is assuming a new role */
		printf("FSP: FSP assuming new role\n");
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_SP_NEW_ROLE, 0), true);
		ipl_state |= ipl_got_new_role;
		return true;

	case FSP_CMD_SP_QUERY_CAPS:
		printf("FSP: FSP query capabilities\n");
		/* XXX Do something saner. For now do a synchronous
	         * response and hard code our capabilities
		 */
		fsp_sync_msg(fsp_mkmsg(FSP_RSP_SP_QUERY_CAPS, 4,
				       0x3ff80000, 0, 0, 0), true);
		ipl_state |= ipl_got_caps;
		return true;
	case FSP_CMD_FSP_FUNCTNAL:
		printf("FSP: Got FSP Functional\n");
		ipl_state |= ipl_got_fsp_functional;
		return true;
	case FSP_CMD_ALLOC_INBOUND:
		fsp_alloc_inbound(msg);
		return true;
	case FSP_CMD_SP_RELOAD_COMP:
		printf("FSP: SP says Reset/Reload complete\n");
		printf("     There is %s FSP dump\n",
		       (msg->data.bytes[3] & 0x20) ? "an" : "no");
		/* XXX Handle FSP dumps ... one day maybe */
		return true;
	case FSP_CMD_PANELSTATUS:
	case FSP_CMD_PANELSTATUS_EX1:
	case FSP_CMD_PANELSTATUS_EX2:
		/* Panel status messages. We currently just ignore them */
		return true;
	}
	return false;
}

/* This is called without the FSP lock */
static void fsp_handle_command(struct fsp_msg *msg)
{
	struct fsp_cmdclass *cmdclass = fsp_get_cmdclass(msg);
	struct fsp_client *client, *next;
	u32 cmd_sub_mod;

	if (!cmdclass) {
		prerror("FSP: Got message for unknown class %x\n",
			msg->word0 & 0xff);
		goto free;
	}

	cmd_sub_mod =  (msg->word0 & 0xff) << 16;
	cmd_sub_mod |= (msg->word1 & 0xff) << 8;
	cmd_sub_mod |= (msg->word1 >> 8) & 0xff;
	
	/* Some commands are handled locally */
	if (fsp_local_command(cmd_sub_mod, msg))
		goto free;

	/* The rest go to clients */
	list_for_each_safe(&cmdclass->clientq, client, next, link) {
		if (client->message(cmd_sub_mod, msg))
			goto free;
	}

	prerror("FSP: Unhandled message %06x\n", cmd_sub_mod);

	/* We don't know whether the message expected some kind of
	 * response, so we send one anyway
	 */
	fsp_queue_msg(fsp_mkmsg((cmd_sub_mod & 0xffff00) | 0x008000, 0),
		      fsp_freemsg);
 free:
	fsp_freemsg(msg);
}

static void __fsp_fill_incoming(struct fsp *fsp, struct fsp_msg *msg,
				int dlen, u32 w0, u32 w1)
{
	unsigned int wlen, i, reg;

	msg->dlen = dlen - 8;
	msg->word0 = w0;
	msg->word1 = w1;
	wlen = (dlen + 3) >> 2;
	reg = FSP_MBX1_FDATA_AREA + 8;
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
}

static void __fsp_drop_incoming(struct fsp *fsp)
{
	/* Ack it (XDN) and clear HPEND & counts */
	fsp_wreg(fsp, FSP_MBX1_HCTL_REG,
		 FSP_MBX_CTL_XDN |
		 FSP_MBX_CTL_HPEND |
		 FSP_MBX_CTL_HCSP_MASK |
		 FSP_MBX_CTL_DCSP_MASK);
}

/* WARNING: This will drop the FSP lock */
static void fsp_handle_incoming(struct fsp *fsp)
{
	struct fsp_msg *msg;
	u32 h0, w0, w1;
	unsigned int dlen;
	bool special_response = false;

	h0 = fsp_rreg(fsp, FSP_MBX1_FHDR0_REG);
	dlen = (h0 >> 16) & 0xff;

	w0 = fsp_rreg(fsp, FSP_MBX1_FDATA_AREA);
	w1 = fsp_rreg(fsp, FSP_MBX1_FDATA_AREA + 4);

	DBG("  Incoming: w0: 0x%08x, w1: 0x%08x, dlen: %d\n",
	    w0, w1, dlen);

	/* Some responses are expected out of band */
	if ((w0 & 0xff) == FSP_MCLASS_HMC_INTFMSG  &&
	    ((w1 & 0xff) == 0x8a || ((w1 & 0xff) == 0x8b)))
		special_response = true;

	/* Check for response bit */
	if (w1 & 0x80 && !special_response) {
		struct fsp_cmdclass *cmdclass = __fsp_get_cmdclass(w0 & 0xff);
		struct fsp_msg *req;

		if (!cmdclass->busy || list_empty(&cmdclass->msgq)) {	
			unlock(&fsp_lock);
			prerror("FSP #%d: Got orphan response !\n", fsp->index);
			__fsp_drop_incoming(fsp);
			return;
		}
		req = list_top(&cmdclass->msgq, struct fsp_msg, link);

		/* Check if the response seems to match the message */
		if (req->state != fsp_msg_wresp ||
		    (req->word0 & 0xff) != (w0 & 0xff) ||
		    (req->word1 & 0xff) != (w1 & 0x7f)) {
			__fsp_drop_incoming(fsp);
			unlock(&fsp_lock);
			prerror("FSP #%d: Response doesn't match pending msg\n",
				fsp->index);
			return;
		}

		/* Allocate response if needed */
		if (!req->resp) {
			req->resp = __fsp_allocmsg();
			if (!req->resp) {
				__fsp_drop_incoming(fsp);
				unlock(&fsp_lock);
				prerror("FSP #%d: Failed to allocate response\n",
					fsp->index);
				return;
			}
		}

		/* Populate and complete (will drop the lock) */
		req->resp->state = fsp_msg_response;
		__fsp_fill_incoming(fsp, req->resp, dlen, w0, w1);
		fsp_complete_msg(req);
		return;
	}

	/* Allocate an incoming message */
	msg = __fsp_allocmsg();
	if (!msg) {
		__fsp_drop_incoming(fsp);
		unlock(&fsp_lock);
		prerror("FSP #%d: Failed to allocate incoming msg\n",
			fsp->index);
		return;
	}
	msg->state = fsp_msg_incoming;
	__fsp_fill_incoming(fsp, msg, dlen, w0, w1);
	unlock(&fsp_lock);

	/* Handle FSP commands. This can recurse into fsp_queue_msg etc.. */
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
	u32 ctl;

	if (!fsp)
		return;

	lock(&fsp_lock);

	/* Check for error state */
 again:
	if (fsp_check_err(fsp) || fsp->state == fsp_mbx_error) {
		unlock(&fsp_lock);
		return;
	}

	/* Poll FSP CTL */
	ctl = fsp_rreg(fsp, FSP_MBX1_HCTL_REG);

	if (ctl & (FSP_MBX_CTL_XUP | FSP_MBX_CTL_HPEND))
		DBG("FSP #%d: poll, ctl: %x\n", fsp->index, ctl);

	/* Do we have a pending message waiting to complete ? */
	if (ctl & FSP_MBX_CTL_XUP) {
		fsp_wreg(fsp, FSP_MBX1_HCTL_REG, FSP_MBX_CTL_XUP);
		if (fsp->state == fsp_mbx_send) {
			/* mbox is free */
			fsp->state = fsp_mbx_idle;

			/* Complete message (will srop lock) */
			fsp_complete_send(fsp);
			lock(&fsp_lock);

			/* Check for something else to send */
			fsp_check_queues();

			/* Lock can have been dropped, so ctl is now
			 * potentially invalid, let's recheck
			 */
			goto again;
		} else {
			prerror("FSP #%d: Got XUP with no pending message !\n",
				fsp->index);
		}
	}

	if (fsp->state == fsp_mbx_send) {
		/* XXX Handle send timeouts!!! */
	}

	/* Is there an incoming message ? This will drop the lock */
	if (ctl & FSP_MBX_CTL_HPEND) {
		fsp_handle_incoming(fsp);
		return;
	}

	unlock(&fsp_lock);
}

int fsp_sync_msg(struct fsp_msg *msg, bool autofree)
{
	int rc;

	rc = fsp_queue_msg(msg, NULL);
	if (rc)
		goto bail;

	while(fsp_msg_busy(msg))
		fsp_poll();

	switch(msg->state) {
	case fsp_msg_done:
		rc = 0;
		break;
	case fsp_msg_timeout:
		rc = -1; /* XXX to improve */
		break;
	default:
		rc = -1; /* Should not happen... (assert ?) */
	}

	if (msg->resp)
		rc = (msg->resp->word1 >> 8) & 0xff;
 bail:
	if (autofree)
		fsp_freemsg(msg);
	return rc;
}

static bool fsp_check_impl(const void *spss, int i)
{
	const struct spss_sp_impl *sp_impl;
	unsigned int mask;

	/* Find an check the SP Implementation structure */
	sp_impl = HDIF_get_idata(spss, SPSS_IDATA_SP_IMPL, NULL);
	if (!CHECK_SPPTR(sp_impl)) {
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

void fsp_register_client(struct fsp_client *client, u8 msgclass)
{
	struct fsp_cmdclass *cmdclass = __fsp_get_cmdclass(msgclass);

	list_add_tail(&cmdclass->clientq, &client->link);
}

void fsp_unregister_client(struct fsp_client *client, u8 msgclass)
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
	fsp_tce_table = (u64 *)PSI_TCE_TABLE_BASE;

	memset(fsp_tce_table, 0, PSI_TCE_TABLE_SIZE);
}

void fsp_tce_map(u32 offset, void *addr, u32 size)
{
	u64 raddr = (u64)addr;

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

void fsp_tce_unmap(u32 offset, u32 size)
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
		u64 reg;

		iopath = HDIF_get_iarray_item(spss, SPSS_IDATA_SP_IOPATH,
					      i, &iopath_sz);
		if (!CHECK_SPPTR(iopath)) {
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
#if 1
		printf("  PSIHB_BBAR   : %llx\n",
		       in_be64(fiop->gxhb_regs + PSIHB_BBAR));
		printf("  PSIHB_FSPBAR : %llx\n",
		       in_be64(fiop->gxhb_regs + PSIHB_FSPBAR));
		printf("  PSIHB_FSPMMR : %llx\n",
		       in_be64(fiop->gxhb_regs + PSIHB_FSPMMR));
		printf("  PSIHB_TAR    : %llx\n",
		       in_be64(fiop->gxhb_regs + PSIHB_TAR));
		printf("  PSIHB_CR     : %llx\n",
		       in_be64(fiop->gxhb_regs + PSIHB_CR));
		printf("  PSIHB_SEMR   : %llx\n",
		       in_be64(fiop->gxhb_regs + PSIHB_SEMR));
		printf("  PSIHB_XIVR   : %llx\n",
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

void fsp_opl(void)
{
	/* Send OPL */
	ipl_state |= ipl_opl_sent;
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_OPL, 0), true);
	while(!(ipl_state & ipl_got_continue))
		fsp_poll();

	/* Send continue ACK */
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_CONTINUE_ACK, 0), true);

	/* Wait for various FSP messages */
	printf("INIT: Waiting for FSP to advertize new role...\n");
	while(!(ipl_state & ipl_got_new_role))
		fsp_poll();
	printf("INIT: Waiting for FSP to request capabilities...\n");
	while(!(ipl_state & ipl_got_caps))
		fsp_poll();

	/* Tell FSP we are in standby */
	printf("INIT: Sending HV Functional: Standby...\n");
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_HV_FUNCTNAL, 1, 0x01000000), true);

	/* Wait for FSP functional */
	printf("INIT: Waiting for FSP functional\n");
	while(!(ipl_state & ipl_got_fsp_functional))
		fsp_poll();

	/* Tell FSP we are in running state */
	printf("INIT: Sending HV Functional: Runtime...\n");
	fsp_sync_msg(fsp_mkmsg(FSP_CMD_HV_FUNCTNAL, 1, 0x02000000), true);
}

int fsp_fetch_data(uint8_t flags, uint16_t id, uint32_t sub_id,
		   uint32_t offset, void *buffer, uint32_t *length)
{
	uint32_t total, remaining = *length;
	uint64_t baddr;
	uint64_t balign, boff, bsize;
	struct fsp_msg *msg;

	*length = total = 0;

	printf("FSP: Fetch data id: %02x sid: %08x to %p (0x%x bytes)\n",
	       id, sub_id, buffer, remaining);

	while(remaining) {
		uint32_t chunk, taddr, woffset, wlen;
		uint8_t rc;

		/* Calculate alignment squew */
		baddr = (uint64_t)buffer;
		balign = baddr & ~0xffful;
		boff = baddr & 0xffful;

		/* Get a chunk */
		chunk = remaining;
		if (chunk > (PSI_DMA_FETCH_SIZE - boff))
			chunk = PSI_DMA_FETCH_SIZE - boff;
		bsize = ((boff + chunk) + 0xfff) & ~0xffful;

		printf("FSP:  0x%08x bytes balign=%llx boff=%llx bsize=%llx\n",
		       chunk, balign, boff, bsize);
		fsp_tce_map(PSI_DMA_FETCH, (void *)balign, bsize);
		taddr = PSI_DMA_FETCH + boff;
		msg = fsp_mkmsg(FSP_CMD_FETCH_SP_DATA, 6,
				flags << 16 | id, sub_id, offset,
				0, taddr, chunk);
		rc = fsp_sync_msg(msg, false);
		fsp_tce_unmap(PSI_DMA_FETCH, bsize);

		woffset = msg->resp->data.words[1];
		wlen = msg->resp->data.words[2];
		printf("FSP:   -> rc=0x%02x off: %08x twritten: %08x\n",
		       rc, woffset, wlen);
		fsp_freemsg(msg);

		/* XXX Is flash busy (0x3f) a reason for retry ? */
		if (rc != 0 && rc != 2)
			return -EIO;

		remaining -= wlen;
		total += wlen;
		buffer += wlen;
		offset += wlen;

		/* The doc seems to indicate that we get rc=2 if there's
		 * more data and rc=0 if we reached the end of file, but
		 * it looks like I always get rc=0, so let's consider
		 * an EOF if we got less than what we asked
		 */
		if (wlen < chunk)
			break;
	}

	*length = total;

	return 0;
}

