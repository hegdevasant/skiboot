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

#define XSCOM_ADDR_IND_FLAG		PPC_BIT(0)
#define XSCOM_ADDR_IND_ADDR_MASK	PPC_BITMASK(12,31)
#define XSCOM_ADDR_IND_ADDR_LSH		PPC_BITLSHIFT(31)
#define XSCOM_ADDR_IND_DATA_MSK		PPC_BITMASK(48,63)

#define XSCOM_DATA_IND_READ		PPC_BIT(0)
#define XSCOM_DATA_IND_COMPLETE		PPC_BIT(32)
#define XSCOM_DATA_IND_ERR_MASK		PPC_BITMASK(33,35)
#define XSCOM_DATA_IND_ERR_LSH		PPC_BITLSHIFT(35)
#define XSCOM_DATA_IND_DATA_MSK		PPC_BITMASK(48,63)

/* HB folks say: try 10 time for now */
#define XSCOM_IND_MAX_RETRIES		10

static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	struct proc_chip *chip = get_chip(gcid);
	uint64_t addr;

	assert(chip);
	addr  = chip->xscom_base;
	addr |= ((uint64_t)pcb_addr << 4) & ~0xfful;
	addr |= (pcb_addr << 3) & 0x78;

	return (void *)addr;
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

	/* XXX: Create error log entry ? */
	prerror("XSCOM: %s error gcid=0x%x pcb_addr=0x%x stat=0x%x\n",
		is_write ? "write" : "read", gcid, pcb_addr, stat);

	/* Non recovered ... just fail */
	return false;
}

void xscom_handle_ind_error(uint64_t data, uint32_t gcid, uint64_t pcb_addr,
			    bool is_write)
{
	unsigned int stat = GETFIELD(XSCOM_DATA_IND_ERR, data);
	bool timeout = !(data & XSCOM_DATA_IND_COMPLETE);

	/* XXX: Create error log entry ? */
	if (timeout)
		prerror("XSCOM: %s indirect timeout, gcid=0x%x pcb_addr=0x%llx"
			" stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
	else
		prerror("XSCOM: %s indirect error, gcid=0x%x pcb_addr=0x%llx"
			" stat=0x%x\n",
			is_write ? "write" : "read", gcid, pcb_addr, stat);
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
	return get_chip(gcid) != NULL;
}

/*
 * Low level XSCOM access functions, perform a single direct xscom
 * access via MMIO
 */
static int __xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val)
{
	uint64_t hmer;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return OPAL_PARAMETER;
	}

	for (;;) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Read value from SCOM */
		*val = in_be64(xscom_addr(gcid, pcb_addr));

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			break;

		/* Handle error and eventually retry */
		if (!xscom_handle_error(hmer, gcid, pcb_addr, false))
			return OPAL_HARDWARE;
	}
	return 0;
}

static int __xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	uint64_t hmer;

	if (!xscom_gcid_ok(gcid)) {
		prerror("%s: invalid XSCOM gcid 0x%x\n", __func__, gcid);
		return OPAL_PARAMETER;
	}

	for (;;) {
		/* Clear status bits in HMER (HMER is special
		 * writing to it *ands* bits
		 */
		mtspr(SPR_HMER, HMER_CLR_MASK);

		/* Write value to SCOM */
		out_be64(xscom_addr(gcid, pcb_addr), val);

		/* Wait for done bit */
		hmer = xscom_wait_done();

		/* Check for error */
		if (!(hmer & SPR_HMER_XSCOM_FAIL))
			break;

		/* Handle error and eventually retry */
		if (!xscom_handle_error(hmer, gcid, pcb_addr, true))
			return OPAL_HARDWARE;
	}
	return 0;
}

/*
 * Indirect XSCOM access functions
 */
static int xscom_indirect_read(uint32_t gcid, uint64_t pcb_addr, uint64_t *val)
{
	struct proc_chip *chip = get_chip(gcid);
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	if (proc_gen != proc_gen_p8) {
		*val = (uint64_t)-1;
		return OPAL_UNSUPPORTED;
	}

	/* Indirect, wow, we need a lock first ! */
	lock(&chip->xscom_lock);

	/* Write indirect address */
	addr = pcb_addr & 0x7fffffff;
	data = XSCOM_DATA_IND_READ |
		(pcb_addr & XSCOM_ADDR_IND_ADDR_MASK);
	rc = __xscom_write(gcid, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = __xscom_read(gcid, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR_MASK) == 0)) {
			*val = data & XSCOM_DATA_IND_DATA_MSK;
			break;
		}
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			xscom_handle_ind_error(data, gcid, pcb_addr,
					       false);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	unlock(&chip->xscom_lock);
	if (rc)
		*val = (uint64_t)-1;
	return rc;
}

static int xscom_indirect_write(uint32_t gcid, uint64_t pcb_addr, uint64_t val)
{
	struct proc_chip *chip = get_chip(gcid);
	uint32_t addr;
	uint64_t data;
	int rc, retries;

	if (proc_gen != proc_gen_p8)
		return OPAL_UNSUPPORTED;

	/* Indirect, wow, we need a lock first ! */
	lock(&chip->xscom_lock);

	/* Write indirect address & data */
	addr = pcb_addr & 0x7fffffff;
	data = pcb_addr & XSCOM_ADDR_IND_ADDR_MASK;
	data |= val & XSCOM_ADDR_IND_DATA_MSK;

	rc = __xscom_write(gcid, addr, data);
	if (rc)
		goto bail;

	/* Wait for completion */
	for (retries = 0; retries < XSCOM_IND_MAX_RETRIES; retries++) {
		rc = __xscom_read(gcid, addr, &data);
		if (rc)
			goto bail;
		if ((data & XSCOM_DATA_IND_COMPLETE) &&
		    ((data & XSCOM_DATA_IND_ERR_MASK) == 0))
			break;
		if ((data & XSCOM_DATA_IND_COMPLETE) ||
		    (retries >= XSCOM_IND_MAX_RETRIES)) {
			xscom_handle_ind_error(data, gcid, pcb_addr,
					       false);
			rc = OPAL_HARDWARE;
			goto bail;
		}
	}
 bail:
	unlock(&chip->xscom_lock);
	return rc;
}

/*
 * External API
 */
int xscom_read(uint32_t gcid, uint64_t pcb_addr, uint64_t *val)
{
	/* Direct vs indirect access */
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		return xscom_indirect_read(gcid, pcb_addr, val);
	else
		return __xscom_read(gcid, pcb_addr & 0x7fffffff, val);
}

opal_call(OPAL_XSCOM_READ, xscom_read, 3);

int xscom_write(uint32_t gcid, uint64_t pcb_addr, uint64_t val)
{
	/* Direct vs indirect access */
	if (pcb_addr & XSCOM_ADDR_IND_FLAG)
		return xscom_indirect_write(gcid, pcb_addr, val);
	else
		return __xscom_write(gcid, pcb_addr & 0x7fffffff, val);
}
opal_call(OPAL_XSCOM_WRITE, xscom_write, 3);

int xscom_readme(uint64_t pcb_addr, uint64_t *val)
{
	return xscom_read(this_cpu()->chip_id, pcb_addr, val);
}

int xscom_writeme(uint64_t pcb_addr, uint64_t val)
{
	return xscom_write(this_cpu()->chip_id, pcb_addr, val);
}

void xscom_init(void)
{
	struct dt_node *xn;

	dt_for_each_compatible(dt_root, xn, "ibm,xscom") {
		uint32_t gcid = dt_get_chip_id(xn);
		const struct dt_property *reg;
		struct proc_chip *chip;

		chip = get_chip(gcid);
		assert(chip);

		/* XXX We need a proper address parsing. For now, we just
		 * "know" that we are looking at a u64
		 */
		reg = dt_find_property(xn, "reg");
		assert(reg);

		chip->xscom_base = dt_translate_address(xn, 0, NULL);
		init_lock(&chip->xscom_lock);

		printf("XSCOM: chip %d at 0x%llx\n", gcid, chip->xscom_base);
	}
}
