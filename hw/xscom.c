#include <xscom.h>
#include <io.h>

/*
 * XSCOM base address default.
 *
 * Technically, the address can be configured differently but there
 * doesn't seem to be a way to obtain it from the FSP provided data
 * structures so we just assume it's the default
 */
#define XSCOM_BASE	0x00001A0000000000UL

static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	uint64_t addr;

	addr  = XSCOM_BASE | ((uint64_t)gcid << PPC_BITLSHIFT(28));
	addr |= ((uint64_t)pcb_addr << 4) & ~0xfful;
	addr |= (pcb_addr << 3) & 0x78;

	return (void *)addr;
}

static uint64_t __xscom_read(uint32_t gcid, uint32_t pcb_addr)
{
	return in_be64(xscom_addr(gcid, pcb_addr));
}

static void __xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	out_be64(xscom_addr(gcid, pcb_addr), val);
}

uint64_t xscom_read(uint32_t gcid, uint32_t pcb_addr)
{
	/* XXX Implement error handling and recovery !!! */
	return __xscom_read(gcid, pcb_addr);
}

void xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	/* XXX Implement error handling and recovery !!! */
	__xscom_write(gcid, pcb_addr, val);
}

