/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>
#include <processor.h>
#include <cpu.h>

/*
 * Error handling:
 *
 * Error codes TBD, 0 = success
 */

/* Targeted SCOM access */
extern int xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val);
extern int xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val);

/* gcid conversion */
extern uint32_t xscom_pir_to_gcid(uint32_t pir);
extern uint32_t xscom_chip_to_gcid(uint32_t chip_id);

/* This chip SCOM access */
extern int xscom_readme(uint32_t pcb_addr, uint64_t *val);
extern int xscom_writeme(uint32_t pcb_addr, uint64_t val);
extern void xscom_init(void);

#endif /* __XSCOM_H */
