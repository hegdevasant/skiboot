/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <timebase.h>
#include <fsp.h>

void time_wait(unsigned long duration)
{
	unsigned long end = mftb() + duration;

	while(tb_compare(mftb(), end) != TB_AAFTERB)
		fsp_poll();
}

void time_wait_ms(unsigned long ms)
{
	time_wait(msecs_to_tb(ms));
}

