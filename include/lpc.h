/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __LPC_H
#define __LPC_H

#include <opal.h>
#include <ccan/endian/endian.h>

/* Routines for accessing the LPC bus on Power8 */

extern void lpc_init(void);

/* Check for a default bus */
extern bool lpc_present(void);

/* Default bus accessors */
extern int64_t lpc_write(enum OpalLPCAddressType addr_type, uint32_t addr,
			 uint32_t data, uint32_t sz);
extern int64_t lpc_read(enum OpalLPCAddressType addr_type, uint32_t addr,
			uint32_t *data, uint32_t sz);

/*
 * Simplified Little Endian IO space accessors
 *
 * Note: We do *NOT* handke unaligned accesses
 */

static inline void lpc_outb(uint8_t data, uint32_t addr)
{
	lpc_write(OPAL_LPC_IO, addr, data, 1);
}

static inline uint8_t lpc_inb(uint32_t addr)
{
	uint32_t d32;
	int64_t rc = lpc_read(OPAL_LPC_IO, addr, &d32, 1);
	return (rc == OPAL_SUCCESS) ? d32 : 0xff;
}

static inline void lpc_outw(uint16_t data, uint32_t addr)
{
	lpc_write(OPAL_LPC_IO, addr, cpu_to_le16(data), 2);
}

static inline uint16_t lpc_inw(uint32_t addr)
{
	uint32_t d32;
	int64_t rc = lpc_read(OPAL_LPC_IO, addr, &d32, 2);
	return (rc == OPAL_SUCCESS) ? le16_to_cpu(d32) : 0xffff;
}

static inline void lpc_outl(uint32_t data, uint32_t addr)
{
	lpc_write(OPAL_LPC_IO, addr, cpu_to_le32(data), 4);
}

static inline uint32_t lpc_inl(uint32_t addr)
{
	uint32_t d32;
	int64_t rc = lpc_read(OPAL_LPC_IO, addr, &d32, 4);
	return (rc == OPAL_SUCCESS) ? le32_to_cpu(d32) : 0xffffffff;
}

#endif /* __LPC_H */
