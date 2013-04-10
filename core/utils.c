/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <lock.h>
#include <fsp.h>

void abort(void)
{
	static bool in_abort = false;

	if (in_abort)
		for (;;) ;
	in_abort = true;

	bust_locks = true;

	op_display(OP_FATAL, OP_MOD_CORE, 0x6666);
	
	fputs("Aborting!\n", stderr);
	backtrace();
	for (;;)
		fsp_poll();
}

char tohex(uint8_t nibble)
{
	static const char __tohex[] = {'0','1','2','3','4','5','6','7','8','9',
				       'A','B','C','D','E','F'};
	if (nibble > 0xf)
		return '?';
	return __tohex[nibble];
}
