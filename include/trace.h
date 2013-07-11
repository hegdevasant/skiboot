/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __TRACE_H
#define __TRACE_H
#include <ccan/short_types/short_types.h>
#include <stddef.h>
#include <lock.h>
#include <trace_types.h>

#define TBUF_SZ (64 * 1024)

struct cpu_thread;

/* Here's one we prepared earlier. */
void init_boot_tracebuf(struct cpu_thread *boot_cpu);

struct tracebuf *trace_newbuf(void);

/* This will fill in timestamp and cpu; you must do type and len. */
void trace_add(union trace *trace);

#endif /* __TRACE_H */
