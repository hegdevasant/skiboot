/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __LPC_H
#define __LPC_H

/* Routines for accessing the LPC bus on Power8 */

extern void lpc_init(void);

/* Specific bus accessors */
int __lpc_write(uint32_t chip_id, uint32_t addr, uint32_t data, unsigned int sz);
int __lpc_read(uint32_t chip_id, uint32_t addr, void *data, unsigned int sz);

/* Check for a default bus */
extern bool lpc_present(void);

/* Default bus accessors */
extern int lpc_write(uint32_t addr, uint32_t data, unsigned int sz);
extern int lpc_read(uint32_t addr, uint32_t *data, unsigned int sz);

static inline int lpc_write8(uint32_t addr, uint8_t data)
{
	return lpc_write(addr, data, 1);
}

static inline int lpc_read8(uint32_t addr, uint8_t *data)
{

	return lpc_read(addr, (uint32_t *)(char *)data, 1);	
}

static inline int lpc_write16(uint32_t addr, uint16_t data)
{
	return lpc_write(addr, data, 2);
}

static inline int lpc_read16(uint32_t addr, uint16_t *data)
{
	return lpc_read(addr, (uint32_t *)(char *)data, 2);	
}

static inline int lpc_write32(uint32_t addr, uint32_t data)
{
	return lpc_write(addr, data, 4);
}

static inline int lpc_read32(uint32_t addr, uint32_t *data)
{
	return lpc_read(addr, data, 4);
}

#endif /* __LPC_H */
