/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”).
 *
 * All functions in charge of generating the associativity/affinity
 * properties in the device-tree
 */

#ifndef __AFFINITY_H
#define __AFFINITY_H

#include <device.h>

extern void add_associativity_ref_point(struct dt_node *opal);

#endif /* __AFFINITY_H */
