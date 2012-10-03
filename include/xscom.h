#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>
#include <processor.h>
#include <cpu.h>

/*
 * Convert a PIR value to a Global Chip ID (insert Torrent bit)
 *
 * Global chip ID is a 6 bit number:
 *
 *     NodeID    T   ChipID
 * |           |   |       |
 * |___|___|___|___|___|___|
 *
 * Where T is the "torrent" bit and is 0 for P7 chips and 1 for
 * directly XSCOM'able IO chips such as Torrent
 */
#define PIR2GCID(pir) ({ 				\
	uint32_t _pir = pir;				\
	((_pir >> 4) & 0x38) | ((_pir >> 5) & 0x3); })

/* Convert a 5-bit Chip# (NodeID | ChipID) into a GCID */
#define CHIP2GCID(chip) ({				\
	uint32_t _chip = chip;				\
	((_chip << 1) & 0x38) | (_chip & 0x3); })

/*
 * Error handling:
 *
 * Error codes TBD, 0 = success
 */

/* Targetted SCOM access */
extern int xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val);
extern int xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val);

/* This chip SCOM access */
static inline int xscom_readme(uint32_t pcb_addr, uint64_t *val)
{
	uint32_t pir = this_cpu()->pir;

	return xscom_read(PIR2GCID(pir), pcb_addr, val);
}

static inline int xscom_writeme(uint32_t pcb_addr, uint64_t val)
{
	uint32_t pir = this_cpu()->pir;

	return xscom_write(PIR2GCID(pir), pcb_addr, val);
}

extern void xscom_init(void);

#endif /* __XSCOM_H */
