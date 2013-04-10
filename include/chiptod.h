/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __CHIPTOD_H
#define __CHIPTOD_H

/* The ChipTOD is the HW facility that maintains a synchronized
 * time base across the fabric.
 */

extern void chiptod_init(u32 master_cpu);

#endif /* __CHIPTOD_H */
