/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __HDATA_H
#define __HDATA_H

struct dt_node;

extern void paca_parse(void);
extern bool pcia_parse(void);
extern void fsp_parse(void);
extern void io_parse(struct dt_node *ics);
extern void sysvpd_parse(void);

#endif /* __HDATA_H */

