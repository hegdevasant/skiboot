#include <skiboot.h>
#include <fsp.h>
#include <lock.h>
#include <processor.h>
#include <psi.h>
#include <fsp-sysparam.h>

struct sysparam_req {
	sysparam_compl_t	completion;
	void			*comp_data;
	void			*ubuf;
	uint32_t		ulen;
	struct fsp_msg		msg;
	struct fsp_msg		resp;
	bool			done;
};

static int fsp_sysparam_process(struct sysparam_req *r)
{
	u32 param_id, len;
	int stlen = 0;
	u8 fstat;
	/* Snapshot completion before we set the "done" flag */
	sysparam_compl_t comp = r->completion;
	void *cdata = r->comp_data;

	if (r->msg.state != fsp_msg_done) {
		prerror("FSP: Request for sysparam 0x%x got FSP failure!\n",
			r->msg.data.words[0]);
		stlen = -1; /* XXX Find saner error codes */
		goto complete;
	}

	param_id = r->resp.data.words[0];
	len = r->resp.data.words[1] & 0xffff;

	/* Check params validity */
	if (param_id != r->msg.data.words[0]) {
		prerror("FSP: Request for sysparam 0x%x got resp. for 0x%x!\n",
			r->msg.data.words[0], param_id);
		stlen = -2; /* XXX Sane error codes */
		goto complete;
	}
	if (len > r->ulen) {
		prerror("FSP: Request for sysparam 0x%x truncated!\n",
			param_id);
		len = r->ulen;
	}

	/* Decode the request status */
	fstat = (r->msg.resp->word1 >> 8) & 0xff;
	switch(fstat) {
	case 0x00: /* XXX Is that even possible ? */
	case 0x11: /* Data in request */
		memcpy(r->ubuf, &r->resp.data.words[2], len);
		/* pass through */
	case 0x12: /* Data in TCE */
		stlen = len;
		break;
	default:
		stlen = -fstat;
	}
 complete:
	/* Call completion if any */
	if (comp)
		comp(r->msg.data.words[0], stlen, cdata);
	
	free(r);

	return stlen;
}

static void fsp_sysparam_get_complete(struct fsp_msg *msg)
{
	struct sysparam_req *r = container_of(msg, struct sysparam_req, msg);

	/* If it's an asynchronous request, process it now */
	if (r->completion) {
		fsp_sysparam_process(r);
		return;
	}

	/* Else just set the done flag */

	/* Another CPU can be polling on the "done" flag without the
	 * lock held, so let's order the udpates to the structure
	 */
	lwsync();
	r->done = true;
}

int fsp_get_sys_param(uint32_t param_id, void *buffer, uint32_t length,
		      sysparam_compl_t async_complete, void *comp_data)
{
	struct sysparam_req *r;
	uint64_t baddr, tce_token;
	int rc;

	/*
	 * XXX FIXME: We currently always allocate the sysparam_req here
	 * however, we want to avoid runtime allocations as much as
	 * possible, so if this is going to be used a lot at runtime,
	 * we probably want to pre-allocate a pool of these
	 */
	r = zalloc(sizeof(struct sysparam_req));
	if (!r)
		return -ENOMEM;
	if (length > 4096)
		return -EINVAL;
	r->completion = async_complete;
	r->comp_data = comp_data;
	r->done = false;
	r->ubuf = buffer;
	r->ulen = length;
	r->msg.resp = &r->resp;

	/* Map always 2 pages ... easier that way and none of that
	 * is performance critical
	 */
	baddr = (uint64_t)buffer;
	fsp_tce_map(PSI_DMA_SYSPARAM, (void *)(baddr & ~0xffful), 0x2000);
	tce_token = PSI_DMA_SYSPARAM | (baddr & 0xfff);
	fsp_fillmsg(&r->msg, FSP_CMD_QUERY_SPARM, 3,
		    param_id, length, tce_token);
	rc = fsp_queue_msg(&r->msg, fsp_sysparam_get_complete);

	/* Asynchronous operation or queueing failure, return */
	if (rc || async_complete)
		return rc;

	/* Synchronous operation requested, spin and process */
	while(!r->done)
		fsp_poll();

	/* Will free the request */
	return fsp_sysparam_process(r);
}

static bool fsp_sysparam_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	struct fsp_msg *rsp;
	int rc;

	switch(cmd_sub_mod) {
	case FSP_CMD_SP_SPARM_UPD_0:
	case FSP_CMD_SP_SPARM_UPD_1:
		printf("FSP: Got sysparam update, param ID 0x%x\n",
		       msg->data.words[0]);
		rsp = fsp_mkmsg((cmd_sub_mod & 0xffff00) | 0x008000, 0);
		rc = fsp_queue_msg(rsp, fsp_freemsg);
		if (rc) {
			prerror("FSP: Error %d queuing sysparam reply\n", rc);
			/* What to do here ? R/R ? */
			fsp_freemsg(rsp);
		}
		return true;
	}
	return false;
}

static struct fsp_client fsp_sysparam_client = {
	.message = fsp_sysparam_msg,
};

void fsp_sysparam_init(void)
{
	/* Register change notifications */
	fsp_register_client(&fsp_sysparam_client, FSP_MCLASS_SERVICE);
}
