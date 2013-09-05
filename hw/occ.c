/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <fsp.h>

static void occ_do_load(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct fsp_msg *rsp, *stat;
	struct proc_chip *chip;
	int rc = -ENOMEM;
	u8 err = 0;

	/* Check arguments */
	if (scope != 0x01 && scope != 0x02) {
		prerror("OCC: Load message with invalid scope 0x%x\n",
			scope);
		err = 0x22;
	}

	/* First queue up an OK response to the load message itself */
	rsp = fsp_mkmsg(FSP_RSP_LOAD_OCC, 0 | err);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		/* XXX Generate error logs */
		prerror("OCC: Error %d queueing FSP OCC LOAD reply\n", rc);
		return;
	}

	/* If we had an error, return */
	if (err)
		return;

	/*
	 * Then send a matching OCC Load Status message with an ok
	 * response code as well to all matching chip
	 */
	for_each_chip(chip) {
		if (scope == 0x01 && dbob_id != chip->dbob_id)
			continue;
		rc = -ENOMEM;
		stat = fsp_mkmsg(FSP_CMD_LOAD_OCC_STAT, 2,
				 chip->pcid & 0xff, seq_id);
		if (stat)
			rc = fsp_queue_msg(stat, fsp_freemsg);
		if (rc) {
			/* XXX Generate error logs */
			prerror("OCC: Error %d queueing FSP OCC LOAD STATUS"
					" message\n", rc);
		}
	}
}

static void occ_do_reset(u8 scope, u32 dbob_id, u32 seq_id)
{
	struct fsp_msg *rsp, *stat;
	struct proc_chip *chip;
	int rc = -ENOMEM;
	u8 err = 0;

	/* Check arguments */
	if (scope != 0x01 && scope != 0x02) {
		prerror("OCC: Reset message with invalid scope 0x%x\n",
			scope);
		err = 0x22;
	}

	/* First queue up an OK response to the reset message itself */
	rsp = fsp_mkmsg(FSP_RSP_RESET_OCC, 0 | err);
	if (rsp)
		rc = fsp_queue_msg(rsp, fsp_freemsg);
	if (rc) {
		/* XXX Generate error logs */
		prerror("OCC: Error %d queueing FSP OCC RESET reply\n", rc);
		return;
	}

	/* If we had an error, return */
	if (err)
		return;

	/*
	 * Then send a matching OCC Reset Status message with an 0xFE
	 * response code as well to all matching chip
	 */
	for_each_chip(chip) {
		if (scope == 0x01 && dbob_id != chip->dbob_id)
			continue;
		rc = -ENOMEM;
		stat = fsp_mkmsg(FSP_CMD_RESET_OCC_STAT, 2,
				 0xfe00 | (chip->pcid & 0xff), seq_id);
		if (stat)
			rc = fsp_queue_msg(stat, fsp_freemsg);
		if (rc) {
			/* XXX Generate error logs */
			prerror("OCC: Error %d queueing FSP OCC RESET STATUS"
					" message\n", rc);
		}
	}
}

static bool fsp_occ_msg(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	u32 dbob_id, seq_id;
	u8 scope;

	switch (cmd_sub_mod) {
	case FSP_CMD_LOAD_OCC:
		/*
		 * We get the "Load OCC" command at boot. We don't currently
		 * support loading it ourselves (we don't have the procedures,
		 * they will come with Host Services). For now HostBoot will
		 * have loaded a OCC firmware for us, but we still need to
		 * be nice and respond to OCC.
		 */
		scope = msg->data.bytes[3];
		dbob_id = msg->data.words[1];
		seq_id = msg->data.words[2];
		printf("OCC: Got OCC Load message, scope=0x%x dbob=0x%x"
		       " seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_load(scope, dbob_id, seq_id);
		return true;

	case FSP_CMD_RESET_OCC:
		/*
		 * We shouldn't be getting this one, but if we do, we have
		 * to reply something sensible or the FSP will get upset
		 */
		scope = msg->data.bytes[3];
		dbob_id = msg->data.words[1];
		seq_id = msg->data.words[2];
		printf("OCC: Got OCC Reset message, scope=0x%x dbob=0x%x"
		       " seq=0x%x\n", scope, dbob_id, seq_id);
		occ_do_reset(scope, dbob_id, seq_id);
		return true;
	}
	return false;
}

static struct fsp_client fsp_occ_client = {
	.message = fsp_occ_msg,
};

void occ_init(void)
{
	/* OCC is P8 only */
	if (proc_gen != proc_gen_p8)
		return;

	/* If we have an FSP, register for notifications */
	if (fsp_present())
		fsp_register_client(&fsp_occ_client, FSP_MCLASS_OCC);
}


