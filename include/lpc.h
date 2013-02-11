#ifndef __LPC_H
#define __LPC_H

/* Routines for accessing the LPC bus on Power8 */

extern void lpc_init(void);

extern bool lpc_present(void);

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
