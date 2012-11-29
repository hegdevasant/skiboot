#include <xscom.h>
#include <io.h>
#include <spira.h>
#include <processor.h>
#include <device.h>

/* XSCOM base address default */
#define XSCOM_DEFAULT_BASE	0x00001A0000000000UL
static uint64_t xscom_base = XSCOM_DEFAULT_BASE;

/* Mask of bits to clear in HMER before an access */
#define HMER_CLR_MASK	(~(SPR_HMER_XSCOM_FAIL | \
			   SPR_HMER_XSCOM_DONE | \
			   SPR_HMER_XSCOM_STATUS_MASK))

static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	uint64_t addr;

	addr  = xscom_base | ((uint64_t)gcid << PPC_BITLSHIFT(28));
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

bool xscom_handle_error(uint64_t hmer, uint32_t gcid, uint32_t pcb_addr,
			bool is_write)
{
	unsigned int stat = GETFIELD(SPR_HMER_XSCOM_STATUS, hmer);

	/* XXX Figure out error codes from doc and error
	 * recovery procedures
	 */
	switch(stat) {
	/* XSCOM blocked, just retry */
	case 1:
		return true;
	}

	prerror("XSCOM: %s error, gcid: 0x%x pcb_addr: 0x%x stat: 0x%x\n",
		is_write ? "write" : "read", gcid, pcb_addr, stat);

	/* Non recovered ... just fail */
	return false;
}

static uint64_t xscom_wait_done(void)
{
	uint64_t hmer;

	do
		hmer = mfspr(SPR_HMER);
	while(!(hmer & SPR_HMER_XSCOM_DONE));

	return hmer;
}

int xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val)
{
	uint64_t hmer;

	for (;;) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Read value from SCOM */
		*val = __xscom_read(gcid, pcb_addr);

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			break;

		/* Handle error and eventually retry */
		if (!xscom_handle_error(hmer, gcid, pcb_addr, false))
			return -1;
	}
	return 0;
}

int xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	uint64_t hmer;

	for (;;) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Write value to SCOM */
		__xscom_write(gcid, pcb_addr, val);

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			break;

		/* Handle error and eventually retry */
		if (!xscom_handle_error(hmer, gcid, pcb_addr, true))
			return -1;
	}
	return 0;
}

void xscom_init(void)
{
	struct dt_node *xn;
	const struct dt_property *reg;

	xn = dt_find_compatible_node(dt_root, NULL, "ibm,xscom");
	if (!xn) {
		prerror("XSCOM: No XSCOM node in device-tree\n");
		return;
	}

	/* XXX We need a proper address parsing. For now, we just
	 * "know" that we are looking at a u64
	 */
	reg = dt_find_property(xn, "reg");
	assert(reg);
	xscom_base = dt_translate_address(xn, 0, NULL);

	printf("XSCOM: Found base address from device-tree: 0x%llx\n",
	       xscom_base);
}
