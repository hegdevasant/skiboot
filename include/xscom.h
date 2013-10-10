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
 * SCOM Address definition extracted from HWPs for documentation
 * purposes
 *
 * "Normal" (legacy) format
 *
 *            111111 11112222 22222233 33333333 44444444 44555555 55556666
 * 01234567 89012345 67890123 45678901 23456789 01234567 89012345 67890123
 * -------- -------- -------- -------- -------- -------- -------- --------
 * 00000000 00000000 00000000 00000000 0MCCCCCC ????PPPP 00LLLLLL LLLLLLLL
 *                                      ||          |    |
 *                                      ||          |    `-> Local Address*
 *                                      ||          |
 *                                      ||          `-> Port
 *                                      ||
 *                                      |`-> Chiplet ID**
 *                                      |
 *                                      `-> Multicast bit
 *
 *  * Local address is composed of "00" + 4-bit ring + 10-bit ID
 *    The 10-bit ID is usually 4-bit sat_id and 6-bit reg_id
 *
 * ** Chiplet ID turns into multicast operation type and group number
 *    if the multicast bit is set
 *
 * "Indirect" format
 *
 *
 *            111111 11112222 22222233 33333333 44444444 44555555 55556666
 * 01234567 89012345 67890123 45678901 23456789 01234567 89012345 67890123
 * -------- -------- -------- -------- -------- -------- -------- --------
 * 10000000 0000IIII IIIIIGGG GGGLLLLL 0MCCCCCC ????PPPP 00LLLLLL LLLLLLLL
 *              |         |      |      ||          |    |
 *              |         |      |      ||          |    `-> Local Address*
 *              |         |      |      ||          |
 *              |         |      |      ||          `-> Port
 *              |         |      |      ||
 *              |         |      |      |`-> Chiplet ID**
 *              |         |      |      |
 *              |         |      |      `-> Multicast bit
 *              |         |      |
 *              |         |      `-> Lane ID
 *              |         |
 *              |         `-> RX or TX Group ID
 *              |
 *              `-> Indirect Register Address
 *
 *  * Local address is composed of "00" + 4-bit ring + 4-bit sat_id + "111111"
 *
 * ** Chiplet ID turns into multicast operation type and group number
 *    if the multicast bit is set
 */

/*
 * Generate a local address from a given ring/satellite/offset
 * combination:
 *
 *     Ring    Satelite     offset
 *  +---------+---------+-------------+
 *  |    4    |    4    |     6       |
 *  +---------+---------+-------------+
 */
#define XSCOM_SAT(_r, _s, _o)	\
	(((_r) << 10) | ((_s) << 6) | (_o))


/*
 * Error handling:
 *
 * Error codes TBD, 0 = success
 */

/* Targeted SCOM access */
extern int xscom_read(uint32_t gcid, uint64_t pcb_addr, uint64_t *val);
extern int xscom_write(uint32_t gcid, uint64_t pcb_addr, uint64_t val);

/* This chip SCOM access */
extern int xscom_readme(uint64_t pcb_addr, uint64_t *val);
extern int xscom_writeme(uint64_t pcb_addr, uint64_t val);
extern void xscom_init(void);

#endif /* __XSCOM_H */
