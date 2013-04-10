/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __CONSOLE_H
#define __CONSOLE_H

#include <lock.h>

/* Console driver */
struct con_ops {
	size_t (*write)(const char *buf, size_t len);
	size_t (*read)(char *buf, size_t len);
};

extern struct lock con_lock;

extern bool flush_console(void);
extern bool __flush_console(void);
extern void set_console(struct con_ops *driver);

extern void dummy_console_add_nodes(struct dt_node *opal);

#endif /* __CONSOLE_H */
