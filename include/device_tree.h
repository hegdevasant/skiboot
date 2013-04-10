/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __DEVICE_TREE_H
#define __DEVICE_TREE_H
#include <stdint.h>

/* Note: Device tree creation has no locks. It's assumed to be done
 * by a single processor in a non racy way
 */
void *create_dtb(const struct dt_node *root);

/* Helpers to cache errors in fdt; use this instead of fdt_* */
uint32_t dt_begin_node(const char *name); /* returns phandle */
void dt_property_string(const char *name, const char *value);
void dt_property_cell(const char *name, u32 cell);
void dt_property_cells(const char *name, int count, ...);
void dt_property(const char *name, const void *val, size_t size);
void dt_end_node(void);


#endif /* __DEVICE_TREE_H */
