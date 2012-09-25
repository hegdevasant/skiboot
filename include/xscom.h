#ifndef __XSCOM_H
#define __XSCOM_H

#include <stdint.h>
#include <processor.h>

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


/* Targetted SCOM access */
extern uint64_t xscom_read(uint32_t gcid, uint32_t pcb_addr);
extern void xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val);

/* This chip SCOM access */
static inline uint64_t xscom_readme(uint32_t pcb_addr)
{
	return xscom_read(PIR2GCID(mfspr(SPR_PIR)), pcb_addr);
}

static inline void xscom_writeme(uint32_t pcb_addr, uint64_t val)
{
	xscom_write(PIR2GCID(mfspr(SPR_PIR)), pcb_addr, val);
}

#endif /* __XSCOM_H */
