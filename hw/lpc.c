/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <lock.h>
#include <chip.h>

#define ECCB_CTL	0 /* b0020 -> b00200 */
#define ECCB_STAT	2 /* b0022 -> b00210 */
#define ECCB_DATA	3 /* b0023 -> b00218 */

#define ECCB_CTL_MAGIC		0xd000000000000000ul
#define ECCB_CTL_DATASZ_MASK	PPC_BITMASK(4,7)
#define ECCB_CTL_DATASZ_LSH	PPC_BITLSHIFT(7)
#define ECCB_CTL_READ		PPC_BIT(15)
#define ECCB_CTL_ADDRLEN_MASK	PPC_BITMASK(23,25)
#define ECCB_CTL_ADDRLEN_LSH	PPC_BITLSHIFT(25)
#define 	ECCB_ADDRLEN_4B	0x4
#define ECCB_CTL_ADDR_MASK	PPC_BITMASK(32,63)
#define ECCB_CTL_ADDR_LSH	0

#define ECCB_STAT_PIB_ERR_MASK	PPC_BITMASK(0,5)
#define ECCB_STAT_PIB_ERR_LSH	PPC_BITLSHIFT(5)
#define ECCB_STAT_RD_DATA_MASK	PPC_BITMASK(6,37)
#define ECCB_STAT_RD_DATA_LSH	PPC_BITLSHIFT(37)
#define ECCB_STAT_BUSY		PPC_BIT(44)
#define ECCB_STAT_ERRORS1_MASK	PPC_BITMASK(45,51)
#define ECCB_STAT_ERRORS1_LSH	PPC_BITLSHIFT(51)
#define ECCB_STAT_OP_DONE	PPC_BIT(52)
#define ECCB_STAT_ERRORS2_MASK	PPC_BITMASK(53,55)
#define ECCB_STAT_ERRORS3_LSH	PPC_BITLSHIFT(55)

#define ECCB_STAT_ERR_MASK	(ECCB_STAT_PIB_ERR_MASK | \
				 ECCB_STAT_ERRORS1_MASK | \
				 ECCB_STAT_ERRORS2_MASK)

#define ECCB_TIMEOUT	100000

/* Default LPC bus */
static int32_t lpc_default_chip_id = -1;

/*
 * These are expected to be the same on all chips and should probably
 * be read (or configured) dynamically. This is how things are configured
 * today on Tuletta.
 */
static uint32_t lpc_io_opb_base		= 0xd0010000;
static uint32_t lpc_mem_opb_base 	= 0xe0000000;
static uint32_t lpc_fw_opb_base 	= 0xf0000000;

static int64_t opb_write(uint32_t chip_id, uint32_t addr, uint32_t data,
			 uint32_t sz)
{
	struct proc_chip *chip = get_chip(chip_id);
	uint64_t ctl = ECCB_CTL_MAGIC, stat;
	int64_t rc, tout;
	bool do_unlock;
	uint64_t data_reg;

	if (!chip || !chip->lpc_xbase)
		return OPAL_PARAMETER;

	switch(sz) {
	case 1:
		data_reg = ((uint64_t)data) << 56;
		break;
	case 2:
		data_reg = ((uint64_t)data) << 48;
		break;
	case 4:
		data_reg = ((uint64_t)data) << 32;
		break;
	default:
		prerror("LPC: Invalid data size %d\n", sz);
		return OPAL_PARAMETER;
	}

	do_unlock = lock_recursive(&chip->lpc_lock);
	rc = xscom_write(chip->id, chip->lpc_xbase + ECCB_DATA, data_reg);
	if (rc) {
		prerror("LPC: XSCOM write to ECCB DATA error %lld\n", rc);
		goto bail;
	}

	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(chip->id, chip->lpc_xbase + ECCB_CTL, ctl);
	if (rc) {
		prerror("LPC: XSCOM write to ECCB CTL error %lld\n", rc);
		goto bail;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(chip->id, chip->lpc_xbase + ECCB_STAT, &stat);
		if (rc) {
			prerror("LPC: XSCOM read from ECCB STAT err %lld\n",rc);
			goto bail;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			if (stat & ECCB_STAT_ERR_MASK) {
				prerror("LPC: Error status: 0x%llx\n", stat);
				rc = OPAL_HARDWARE;
				goto bail;
			}
			goto bail;
		}
	}
	prerror("LPC: Write timeout !\n");
	rc = OPAL_HARDWARE;
 bail:
	if (do_unlock)
		unlock(&chip->lpc_lock);
	return rc;
}

static int64_t opb_read(uint32_t chip_id, uint32_t addr, uint32_t *data,
		        uint32_t sz)
{
	struct proc_chip *chip = get_chip(chip_id);
	uint64_t ctl = ECCB_CTL_MAGIC | ECCB_CTL_READ, stat;
	int64_t rc, tout;
	bool do_unlock;

	if (!chip || !chip->lpc_xbase)
		return OPAL_PARAMETER;

	if (sz != 1 && sz != 2 && sz != 4) {
		prerror("LPC: Invalid data size %d\n", sz);
		return OPAL_PARAMETER;
	}

	do_unlock = lock_recursive(&chip->lpc_lock);
	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(chip->id, chip->lpc_xbase + ECCB_CTL, ctl);
	if (rc) {
		prerror("LPC: XSCOM write to ECCB CTL error %lld\n", rc);
		goto bail;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(chip->id, chip->lpc_xbase + ECCB_STAT, &stat);
		if (rc) {
			prerror("LPC: XSCOM read from ECCB STAT err %lld\n",rc);
			goto bail;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			uint32_t rdata = GETFIELD(ECCB_STAT_RD_DATA, stat);
			if (stat & ECCB_STAT_ERR_MASK) {
				prerror("LPC: Error status: 0x%llx\n", stat);
				rc = OPAL_HARDWARE;
				goto bail;
			}
			switch(sz) {
			case 1:
				*data = rdata >> 24;
				break;
			case 2:
				*data = rdata >> 16;
				break;
			default:
				*data = rdata;
				break;
			}
			goto bail;
		}
	}
	prerror("LPC: Read timeout !\n");
	rc = OPAL_HARDWARE;
 bail:
	if (do_unlock)
		unlock(&chip->lpc_lock);
	return rc;
}

static int64_t lpc_get_opb_base(enum OpalLPCAddressType addr_type,
				uint32_t addr, uint32_t sz,
				uint32_t *opb_base)
{
	uint32_t top = addr + sz;

	/* Address wraparound */
	if (top < addr)
		return OPAL_PARAMETER;

	/*
	 * Bound check access and get the OPB base address for
	 * the window corresponding to the access type
	 */
	switch(addr_type) {
	case OPAL_LPC_IO:
		/* IO space is 64K */
		if (top > 0x10000)
			return OPAL_PARAMETER;
		*opb_base = lpc_io_opb_base;
		break;
	case OPAL_LPC_MEM:
		/* MEM space is 256M (XXX dbl check) */
		if (top > 0x10000000)
			return OPAL_PARAMETER;
		*opb_base = lpc_mem_opb_base;
		break;
	case OPAL_LPC_FW:
		/* FW space is 256M (XXX dbl check) */
		if (top > 0x10000000)
			return OPAL_PARAMETER;
		*opb_base = lpc_fw_opb_base;
		break;
	default:
		return OPAL_PARAMETER;
	}
	return OPAL_SUCCESS;
}

static int64_t __lpc_write(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			   uint32_t addr, uint32_t data, uint32_t sz)
{
	uint32_t opb_base;
	int64_t rc;

	/* Convert to an OPB access */
	rc = lpc_get_opb_base(addr_type, addr, sz, &opb_base);
	if (rc)
		return rc;

	/* Perform OPB access */
	rc = opb_write(chip_id, opb_base + addr, data, sz);

	/* XXX Add LPC error handling/recovery */
	return rc;
}

int64_t lpc_write(enum OpalLPCAddressType addr_type, uint32_t addr,
		  uint32_t data, uint32_t sz)
{
	if (lpc_default_chip_id < 0)
		return OPAL_PARAMETER;
	return __lpc_write(lpc_default_chip_id, addr_type, addr, data, sz);
}

static int64_t __lpc_read(uint32_t chip_id, enum OpalLPCAddressType addr_type,
			  uint32_t addr, uint32_t *data, uint32_t sz)
{
	uint32_t opb_base;
	int64_t rc;

	/* Convert to an OPB access */
	rc = lpc_get_opb_base(addr_type, addr, sz, &opb_base);
	if (rc)
		return rc;

	/* Perform OPB access */
	rc = opb_read(chip_id, opb_base + addr, data, sz);

	/* XXX Add LPC error handling/recovery */
	return rc;
}

int64_t lpc_read(enum OpalLPCAddressType addr_type, uint32_t addr,
		 uint32_t *data, uint32_t sz)
{
	if (lpc_default_chip_id < 0)
		return OPAL_PARAMETER;
	return __lpc_read(lpc_default_chip_id, addr_type, addr, data, sz);
}

bool lpc_present(void)
{
	return lpc_default_chip_id >= 0;
}

void lpc_init(void)
{
	struct dt_node *xn;
	bool has_lpc = false;

	dt_for_each_compatible(dt_root, xn, "ibm,power8-lpc") {
		uint32_t gcid = dt_get_chip_id(xn);
		struct proc_chip *chip;

		chip = get_chip(gcid);
		assert(chip);

		chip->lpc_xbase = dt_get_address(xn, 0, NULL);
		init_lock(&chip->lpc_lock);

		if (lpc_default_chip_id < 0 ||
		    dt_has_node_property(xn, "primary", NULL)) {
			lpc_default_chip_id = chip->id;
		}

		printf("LPC: Bus on chip %d PCB_Addr=0x%x\n",
		       chip->id, chip->lpc_xbase);

		has_lpc = true;
	}
	if (lpc_default_chip_id >= 0)
		printf("LPC: Default bus on chip %d\n", lpc_default_chip_id);

	if (has_lpc) {
		opal_register(OPAL_LPC_WRITE, __lpc_write, 5);
		opal_register(OPAL_LPC_READ, __lpc_read, 5);
	}
}

