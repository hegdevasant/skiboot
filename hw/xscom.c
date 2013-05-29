/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <processor.h>
#include <device.h>
#include <chip.h>

/* Mask of bits to clear in HMER before an access */
#define HMER_CLR_MASK	(~(SPR_HMER_XSCOM_FAIL | \
			   SPR_HMER_XSCOM_DONE | \
			   SPR_HMER_XSCOM_STATUS_MASK))

static bool xscom_p8_mode;
static uint64_t *xscoms;
static int max_gcid;

static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	uint64_t addr;

	addr  = xscoms[gcid];
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

bool xscom_gcid_ok(uint32_t gcid)
{
	return gcid <= max_gcid && xscoms[gcid];
}

int xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val)
{
	uint64_t hmer;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return -1;
	}

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

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return -1;
	}

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

int xscom_readme(uint32_t pcb_addr, uint64_t *val)
{
	return xscom_read(this_cpu()->chip_id, pcb_addr, val);
}

int xscom_writeme(uint32_t pcb_addr, uint64_t val)
{
	return xscom_write(this_cpu()->chip_id, pcb_addr, val);
}

void xscom_init(void)
{
	const struct dt_property *reg;
	struct dt_node *xn;
	bool found;
	int gcid;

	max_gcid = 0;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		gcid = dt_get_chip_id(xn);

		if (gcid > max_gcid)
			max_gcid = gcid;

		found = true;
	}

	if (!found) {
		prerror("XSCOM: No XSCOM nodes in device-tree\n");
		return;
	}

	xscoms = zalloc((max_gcid + 1) * sizeof(*xscoms));

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		gcid = dt_get_chip_id(xn);

		/* XXX We need a proper address parsing. For now, we just
		 * "know" that we are looking at a u64
		 */
		reg = dt_find_property(xn, "reg");
		assert(reg);
		xscoms[gcid] = dt_translate_address(xn, 0, NULL);

		/* Check for P8 variant (different GCID encoding) */
		xscom_p8_mode = dt_node_is_compatible(xn, "ibm,power8-xscom");

		printf("XSCOM: %s mode at 0x%llx\n",
		       xscom_p8_mode ? "P8" : "P7", xscoms[gcid]);
	}
}
