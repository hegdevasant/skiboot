/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
/*
 * Service Processor handling code
 *
 * XXX This mixes PSI and FSP and currently only supports
 * P7/P7+ PSI and FSP1
 *
 * If we are going to support P8 PSI and FSP2, we probably want
 * to split the PSI support from the FSP support proper first.
 */
#include <stdarg.h>
#include <processor.h>
#include <io.h>
#include <fsp.h>
#include <lock.h>
#include <interrupts.h>
#include <opal.h>
#include <gx.h>
#include <device.h>

//#define DBG(fmt...)	printf(fmt)
#define DBG(fmt...)	do { } while(0)
//#define FSP_TRACE

#define FSP_MAX_IOPATH	4

enum fsp_path_state {
	fsp_path_bad,
	fsp_path_backup,
	fsp_path_active,
};

struct fsp_iopath {
	enum fsp_path_state	state;
	unsigned int		chip_id;
	unsigned int		interrupt;
	void			*gxhb_regs;
	void			*fsp_regs;
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
	if (iop->state == fsp_path_bad)
		return;
	out_be32(iop->fsp_regs + reg, val);
}

static u32 fsp_rreg(struct fsp *fsp, u32 reg)
{
	struct fsp_iopath *iop;

	if (fsp->active_iopath < 0)
		return 0xffffffff;
	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->state == fsp_path_bad)
		return 0xffffffff;
	return in_be32(iop->fsp_regs + reg);
}

static bool fsp_check_err(struct fsp *fsp)
{
	u32 hstate;
	bool ret_abort = false;
	static bool link_down_msg = false;

	/* Check for an error state */
	hstate = fsp_rreg(fsp, FSP_HDES_REG);
	if (hstate == 0xffffffff) {
		if (!link_down_msg) {
			link_down_msg = true;
			prerror("FSP #%d: Link seems to be down\n", fsp->index);
		}
		/* XXX Start recovery */
		fsp->state = fsp_mbx_error;
		return true;
	}
	link_down_msg = false;

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
	 * to !idle we must not cause any re-entrancy (no debug or trace)
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
	lock(&fsp_lock);
}

/* WARNING: This will drop the FSP lock !!! */
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
			prerror("FSP #%d: Response doesn't match pending msg\n",
				fsp->index);
			return;
		}

		/* Allocate response if needed */
		if (!req->resp) {
			req->resp = __fsp_allocmsg();
			if (!req->resp) {
				__fsp_drop_incoming(fsp);
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
		prerror("FSP #%d: Failed to allocate incoming msg\n",
			fsp->index);
		return;
	}
	msg->state = fsp_msg_incoming;
	__fsp_fill_incoming(fsp, msg, dlen, w0, w1);

	/* Handle FSP commands. This can recurse into fsp_queue_msg etc.. */
	unlock(&fsp_lock);
	fsp_handle_command(msg);
	lock(&fsp_lock);
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

static void __fsp_poll(bool interrupt)
{
	struct fsp *fsp = fsp_get_active();
	u32 ctl, hdir;

	if (!fsp)
		return;

	lock(&fsp_lock);

	/* Crazy interrupt handling scheme:
	 *
	 * In order to avoid "losing" interrupts when polling the mbox
	 * we only clear interrupt conditions when called as a result of
	 * an interrupt.
	 *
	 * That way, if a poll clears, for example, the HPEND condition,
	 * the interrupt remains, causing a dummy interrupt later on
	 * thus allowing the OS to be notified of a state change (ie it
	 * doesn't need every poll site to monitor every state change).
	 *
	 * However, this scheme is complicated by the fact that we need
	 * to clear the interrupt condition after we have cleared the
	 * original condition in HCTL, and we might have long stale
	 * interrupts which we do need to eventually get rid of. However
	 * clearing interrupts in such a way is racy, so we need to loop
	 * and re-poll HCTL after having done so or we might miss an
	 * event. It's a latency risk, but unlikely and probably worth it.
	 */

	/* Check for error state */
 again:
	if (fsp_check_err(fsp) || fsp->state == fsp_mbx_error) {	
		/* XXX Blind ack for now, do better ... */
		if (interrupt)
			fsp_wreg(fsp, FSP_HDIR_REG, FSP_DBIRQ_ALL);
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

			/* Complete message (will break the lock) */
			fsp_complete_send(fsp);

			/* Check for something else to send */
			fsp_check_queues();

			/* Lock can have been broken, so ctl is now
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

	/* Is there an incoming message ? This will break the lock as well */
	if (ctl & FSP_MBX_CTL_HPEND)
		fsp_handle_incoming(fsp);

	/* Note: Lock may have been broken above, thus ctl might be invalid
	 * now, don't use it any further.
	 */

	/* Clear interrupts, and recheck HCTL if any occurred */
	if (interrupt) {
		hdir = fsp_rreg(fsp, FSP_HDIR_REG);
		if (hdir) {
			fsp_wreg(fsp, FSP_HDIR_REG, hdir);
			goto again;
		}
	}
	unlock(&fsp_lock);
}

void fsp_poll(void)
{
	return __fsp_poll(false);
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

static void fsp_psi_enable_interrupt(struct fsp *fsp)
{
	struct fsp_iopath *iop;

	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->state == fsp_path_bad)
		return;

	/* Enable FSP interrupts in the GXHB */
	out_be64(iop->gxhb_regs + PSIHB_CR,
		 in_be64(iop->gxhb_regs + PSIHB_CR) | PSIHB_CR_FSP_IRQ_ENABLE);
}

static int fsp_init_mbox(struct fsp *fsp)
{
	unsigned int i;

	/*
	 * Note: The documentation contradicts itself as to
	 * whether the HDIM bits should be set or cleared to
	 * enable interrupts
	 *
	 * This seems to work...
	 */

	/* Mask all interrupts */
	fsp_wreg(fsp, FSP_HDIM_CLR_REG, FSP_DBIRQ_ALL);

	/* Clear all errors */
	fsp_wreg(fsp, FSP_HDES_REG, FSP_DBERRSTAT_CLR1 | FSP_DBERRSTAT_CLR2);

	/* Clear whatever crap may remain in HDCR */
	fsp_wreg(fsp, FSP_MBX1_HCTL_REG, FSP_MBX_CTL_XDN | FSP_MBX_CTL_HPEND |
		 FSP_MBX_CTL_HCSP_MASK | FSP_MBX_CTL_DCSP_MASK);
	fsp_wreg(fsp, FSP_MBX2_HCTL_REG, FSP_MBX_CTL_XDN | FSP_MBX_CTL_HPEND |
		 FSP_MBX_CTL_HCSP_MASK | FSP_MBX_CTL_DCSP_MASK);

	/* Clear all pending interrupts */
	fsp_wreg(fsp, FSP_HDIR_REG, FSP_DBIRQ_ALL);

	/* Initialize data area as the doco says */
	for (i = 0; i < 0x40; i += 4)
		fsp_wreg(fsp, FSP_MBX1_HDATA_AREA + i, 0);

	/* Enable all mbox1 interrupts */
	fsp_wreg(fsp, FSP_HDIM_SET_REG, FSP_DBIRQ_MBOX1);

	/* Enable interrupts in the PSI HB */
	fsp_psi_enable_interrupt(fsp);

	/* Debug ... */
	fsp_reg_dump(fsp);

	return 0;
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

static void fsp_psi_interrupt(void *data __unused, uint32_t isn __unused)
{
	/* XXX We should decode the chip, find the link, etc...
	 *
	 * then we should handle PSI interrupts (link errors etc...)
	 * vs. mailbox interrupts
	 *
	 * For now, we just poll the active FSP & clear the status bits
	 */
	__fsp_poll(true);


	/* Poll the console buffers on any interrupt since we don't
	 * get send notifications
	 */
	fsp_console_poll(NULL);
}

static int64_t fsp_psi_p7_set_xive(void *data, uint32_t isn __unused,
				   uint16_t server, uint8_t priority)
{
	struct fsp_iopath *iop = data;
	uint64_t xivr;

	if (iop->state == fsp_path_bad)
		return OPAL_HARDWARE;

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |=	P7_IRQ_BUID(iop->interrupt) << 16;

	out_be64(iop->gxhb_regs + PSIHB_XIVR, xivr);

	return OPAL_SUCCESS;
}

static int64_t fsp_psi_p7_get_xive(void *data, uint32_t isn __unused,
				uint16_t *server, uint8_t *priority)
{
	struct fsp_iopath *iop = data;
	uint64_t xivr;

	if (iop->state == fsp_path_bad)
		return OPAL_HARDWARE;

	/* Read & decode the XIVR */
	xivr = in_be64(iop->gxhb_regs + PSIHB_XIVR);

	*server = (xivr >> 40) & 0x7ff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

static int64_t fsp_psi_p8_set_xive(void *data, uint32_t isn,
				   uint16_t server, uint8_t priority)
{
	struct fsp_iopath *iop = data;
	uint64_t xivr_p, xivr;

	switch(isn & 7) {
	case 0:
		xivr_p = PSIHB_XIVR_FSP;
		break;
	case 1:
		xivr_p = PSIHB_XIVR_OCC;
		break;
	case 2:
		xivr_p = PSIHB_XIVR_FSI;
		break;
	case 3:
		xivr_p = PSIHB_XIVR_LPC;
		break;
	case 4:
		xivr_p = PSIHB_XIVR_LOCAL_ERR;
		break;
	case 5:
		xivr_p = PSIHB_XIVR_HOST_ERR;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Populate the XIVR */
	xivr  = (uint64_t)server << 40;
	xivr |= (uint64_t)priority << 32;
	xivr |= (uint64_t)(isn & 7) << 29;

	out_be64(iop->gxhb_regs + xivr_p, xivr);

	return OPAL_SUCCESS;
}

static int64_t fsp_psi_p8_get_xive(void *data, uint32_t isn __unused,
				   uint16_t *server, uint8_t *priority)
{
	struct fsp_iopath *iop = data;
	uint64_t xivr_p, xivr;

	switch(isn & 7) {
	case 0:
		xivr_p = PSIHB_XIVR_FSP;
		break;
	case 1:
		xivr_p = PSIHB_XIVR_OCC;
		break;
	case 2:
		xivr_p = PSIHB_XIVR_FSI;
		break;
	case 3:
		xivr_p = PSIHB_XIVR_LPC;
		break;
	case 4:
		xivr_p = PSIHB_XIVR_LOCAL_ERR;
		break;
	case 5:
		xivr_p = PSIHB_XIVR_HOST_ERR;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Read & decode the XIVR */
	xivr = in_be64(iop->gxhb_regs + xivr_p);

	*server = (xivr >> 40) & 0xffff;
	*priority = (xivr >> 32) & 0xff;

	return OPAL_SUCCESS;
}

/* Called on a fast reset, make sure we aren't stuck with
 * an accepted and never EOId PSI interrupt
 */
void fsp_psi_irq_reset(void)
{
	struct fsp_iopath *iop;
	struct fsp *fsp;
	unsigned int i;
	uint64_t xivr;

	printf("FSP: Hot reset !\n");

	assert(proc_gen == proc_gen_p7);

	for (fsp = first_fsp; fsp; fsp = fsp->link) {
		for (i = 0; i < fsp->iopath_count; i++) {
			iop = &fsp->iopath[i];

			/* Mask the interrupt & clean the XIVR */
			xivr = 0x000000ff00000000;
			xivr |=	P7_IRQ_BUID(iop->interrupt) << 16;
			out_be64(iop->gxhb_regs + PSIHB_XIVR, xivr);

#if 0 /* Seems to checkstop ... */
			/* Send a dummy EOI to make sure the ICP is clear */
			icp_send_eoi(iop->interrupt);
#endif
		}
	}
}

static const struct irq_source_ops fsp_psi_p7_irq_ops = {
	.get_xive = fsp_psi_p7_get_xive,
	.set_xive = fsp_psi_p7_set_xive,
	.interrupt = fsp_psi_interrupt,
};

static const struct irq_source_ops fsp_psi_p8_irq_ops = {
	.get_xive = fsp_psi_p8_get_xive,
	.set_xive = fsp_psi_p8_set_xive,
	.interrupt = fsp_psi_interrupt,
};

static void psi_tce_enable(struct fsp_iopath *fiop, bool enable)
{
	void *addr;
	u64 val;

	switch (proc_gen) {
	case proc_gen_p7:
		addr = fiop->gxhb_regs + PSIHB_CR;
		break;
	case proc_gen_p8:
		addr = fiop->gxhb_regs + PSIHB_PHBSCR;
		break;
	default:
		prerror("%s: Unknown CPU type\n", __func__);
		return;
	}

	val = in_be64(addr);
	if (enable)
		val |=  PSIHB_CR_TCE_ENABLE;
	else
		val &= ~PSIHB_CR_TCE_ENABLE;
	out_be64(addr, val);
}

static int fsp_psi_init_phb(struct fsp_iopath *fiop, bool active,
			    u64 reg_offset)
{
	u64 reg;

	/* Disable and configure the  TCE table,
	 * it will be enabled below
	 */
	psi_tce_enable(fiop, false);

	out_be64(fiop->gxhb_regs + PSIHB_TAR, PSI_TCE_TABLE_BASE |
		 PSIHB_TAR_16K_ENTRIES);

	/* Disable interrupt emission in the control register,
	 * it will be re-enabled later, after the mailbox one
	 * will have been enabled.
	 */
	reg = in_be64(fiop->gxhb_regs + PSIHB_CR);
	reg &= ~PSIHB_CR_FSP_IRQ_ENABLE;
	out_be64(fiop->gxhb_regs + PSIHB_CR, reg);

	/* Configure the interrupt BUID and mask it */
	switch (proc_gen) {
	case proc_gen_p7:
		/* On P7, we get a single interrupt */
		out_be64(fiop->gxhb_regs + PSIHB_XIVR,
			 P7_IRQ_BUID(fiop->interrupt) << 16 |
			 0xffull << 32);

		/* Configure it in the GX controller as well */
		gx_configure_psi_buid(fiop->chip_id,
				      P7_IRQ_BUID(fiop->interrupt));

		/* Register the IRQ source */
		register_irq_source(&fsp_psi_p7_irq_ops,
				    fiop, fiop->interrupt, 1);
		break;
	case proc_gen_p8:
		/* On P8 we get a block of 8, set up the base/mask
		 * and mask all the sources for now
		 */
		out_be64(fiop->gxhb_regs + PSIHB_IRQ_SRC_COMP,
			 (((u64)fiop->interrupt) << 45) |
			 ((0xffff0ul) << 13) | (0x3ull << 32));
		out_be64(fiop->gxhb_regs + PSIHB_XIVR_FSP,
			 (0xffull << 32) | (0 << 29));
		out_be64(fiop->gxhb_regs + PSIHB_XIVR_OCC,
			 (0xffull << 32) | (1 << 29));
		out_be64(fiop->gxhb_regs + PSIHB_XIVR_FSI,
			 (0xffull << 32) | (2 << 29));
		out_be64(fiop->gxhb_regs + PSIHB_XIVR_LPC,
			 (0xffull << 32) | (3 << 29));
		out_be64(fiop->gxhb_regs + PSIHB_XIVR_LOCAL_ERR,
			 (0xffull << 32) | (4 << 29));
		out_be64(fiop->gxhb_regs + PSIHB_XIVR_HOST_ERR,
			 (0xffull << 32) | (5 << 29));

		/* Register the IRQ sources.
		 *
		 * XXX: We only handle the main FSP interrupt for now
		 */
		register_irq_source(&fsp_psi_p8_irq_ops,
				    fiop, fiop->interrupt, 1);
		break;
	default:
		/* Unknown: just no interrupts */
		prerror("FSP: Unknown interrupt type\n");
	}
       
	/* Enable interrupts in the mask register. We enable everything
	 * except for bit "FSP command error detected" which the doc
	 * (P7 BookIV) says should be masked for normal ops. It also
	 * seems to be masked under OPAL.
	 */
	reg = 0x0000010000100000ull;
	out_be64(fiop->gxhb_regs + PSIHB_SEMR, reg);

	/* Enable various other configuration register bits based
	 * on what pHyp does. We keep interrupts disabled until
	 * after the mailbox has been properly configured. We assume
	 * basic stuff such as PSI link enable is already there.
	 *
	 *  - FSP CMD Enable
	 *  - FSP MMIO Enable
	 *  - TCE Enable
	 *  - Error response enable
	 *
	 * Clear all other error bits
	 *
	 * XXX: Only on the active link for now
	 */
	if (active) {
		reg = in_be64(fiop->gxhb_regs + PSIHB_CR);
		reg |= PSIHB_CR_FSP_CMD_ENABLE;
		reg |= PSIHB_CR_FSP_MMIO_ENABLE;
		reg |= PSIHB_CR_FSP_ERR_RSP_ENABLE;
		reg &= ~0x00000000ffffffffull;
		out_be64(fiop->gxhb_regs + PSIHB_CR, reg);
		psi_tce_enable(fiop, true);
	}
#if 1
	/* Dump the GXHB registers */
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
	fiop->fsp_regs = (void *)(reg | (1ULL << 63) | reg_offset);

	return 0;
}


static void fsp_create_fsp(struct dt_node *fsp_node)
{
	const struct dt_property *linksprop;
	struct fsp *fsp;
	int count, i, index;

	index = dt_prop_get_u32(fsp_node, "reg");
	prerror("FSP #%d: Found in device-tree, setting up...\n", index);

	linksprop = dt_find_property(fsp_node, "links");
	if (!linksprop || linksprop->len < 4) {	
		prerror("FSP #%d: No links !\n", index);
		return;
	}

	fsp = zalloc(sizeof(struct fsp));
	if (!fsp) {
		prerror("FSP #%d: Can't allocate memory !\n", index);
		return;
	}

	fsp->index = index;
	fsp->active_iopath = -1;

	count = linksprop->len / 4;
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
		struct dt_node *link;
		struct fsp_iopath *fiop;
		bool active, working;
		u32 lph;

		lph = ((const u32 *)linksprop->prop)[i];
		link = dt_find_by_phandle(dt_root, lph);
		if (!link) {
			prerror("FSP #%d: Can't find link 0x%x\n", index, lph);
			fsp->iopath_count = i;
			break;
		}

		if (!dt_node_is_compatible(link, "ibm,psi")) {
			prerror("FSP #%d: Unsupported link type at %s\n",
				index, link->name);
			continue;
		}

		working = !strcmp(dt_prop_get(link, "status"), "ok");
		active = working &&
			dt_find_property(link, "current-link") != NULL;

		fiop = &fsp->iopath[i];
		if (!working)
			fiop->state = fsp_path_bad;
		else if (active)
			fiop->state = fsp_path_active;
		else
			fiop->state = fsp_path_backup;

		fiop->gxhb_regs = (void *)dt_translate_address(link, 0, NULL);
		fiop->chip_id = dt_get_chip_id(link);
		fiop->interrupt = dt_prop_get_u32(link, "interrupts");

		if (active)
			fsp->active_iopath = i;

		/* XXX Handle errors */
		fsp_psi_init_phb(fiop, active,
				 dt_prop_get_u32(fsp_node, "reg-offset"));
	}
	if (fsp->active_iopath >= 0 && !active_fsp) {
		active_fsp = fsp;
		fsp_init_mbox(fsp);
	}

	fsp->link = first_fsp;
	first_fsp = fsp;
}

static void fsp_opal_poll(void *data __unused)
{
	__fsp_poll(false);
}

static bool fsp_init_one(char *compat)
{
	struct dt_node *fsp_node;
	bool inited = false;

	dt_for_each_compatible(dt_root, fsp_node, compat) {
		if (!inited) {
			int i;
	
			/* Initialize the per-class msg queues */
			for (i = 0;
			     i <= (FSP_MCLASS_LAST - FSP_MCLASS_FIRST); i++) {
				list_head_init(&fsp_cmdclass[i].msgq);
				list_head_init(&fsp_cmdclass[i].clientq);
			}

			/* Initialize a TCE table */
			fsp_init_tce_table();

			/* Register poller */
			opal_add_poller(fsp_opal_poll, NULL);

			inited = true;
		}

		/* Create the FSP data structure */
		fsp_create_fsp(fsp_node);
	}

	return inited;
}

static int64_t fsp_opal_cec_power_down(uint64_t request)
{
	/* Request is:
	 *
	 * 0 = normal
	 * 1 = immediate
	 * (we do not allow 2 for "pci cfg reset" just yet)
	 */

	if (request !=0 && request != 1)
		return OPAL_PARAMETER;

	if (fsp_queue_msg(fsp_mkmsg(FSP_CMD_POWERDOWN_NORM, 1, request),
			  fsp_freemsg))
		return OPAL_INTERNAL_ERROR;

	return OPAL_SUCCESS;
}

static int64_t fsp_opal_cec_reboot(void)
{
#ifdef ENABLE_FAST_RESET
	/* Try a fast reset first */
	fast_reset();
#endif

	/* If that failed, talk to the FSP */
	if (fsp_queue_msg(fsp_mkmsg(FSP_CMD_REBOOT, 0), fsp_freemsg))
		return OPAL_INTERNAL_ERROR;

	return OPAL_SUCCESS;
}

void fsp_init(void)
{
	printf("FSP: Looking for FSP...\n");

	if (!fsp_init_one("ibm,fsp1") && !fsp_init_one("ibm,fsp2")) {
		printf("FSP: No FSP on this machine\n");
		return;
	}
	opal_register(OPAL_CEC_POWER_DOWN, fsp_opal_cec_power_down);
	opal_register(OPAL_CEC_REBOOT, fsp_opal_cec_reboot);
}

bool fsp_present(void)
{
	return first_fsp != NULL;
}

void fsp_opl(void)
{
	if (!fsp_present())
		return;

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
		   uint32_t offset, void *buffer, size_t *length)
{
	uint32_t total, remaining = *length;
	uint64_t baddr;
	uint64_t balign, boff, bsize;
	struct fsp_msg *msg;

	*length = total = 0;

	if (!fsp_present())
		return -ENODEV;

	printf("FSP: Fetch data id: %02x sid: %08x to %p (0x%x bytes)\n",
	       id, sub_id, buffer, remaining);

	while(remaining) {
		uint32_t chunk, taddr, woffset, wlen;
		uint8_t rc;

		/* Calculate alignment skew */
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
