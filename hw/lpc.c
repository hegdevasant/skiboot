/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <bitutils.h>
#include <xscom.h>
#include <io.h>
#include <lock.h>

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

/* We assume as single LPC bus in use in the system for now */
static uint32_t lpc_gcid;
static uint32_t lpc_base;
static struct lock lpc_lock = LOCK_UNLOCKED;

int lpc_write(uint32_t addr, uint32_t data, unsigned int sz)
{
	uint64_t ctl = ECCB_CTL_MAGIC, stat;
	int rc, tout;
	bool do_unlock;
	uint64_t data_reg;

	if (!lpc_base)
		return -ENODEV;

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
		return -EINVAL;
	}

	do_unlock = lock_recursive(&lpc_lock);
	rc = xscom_write(lpc_gcid, lpc_base + ECCB_DATA, data_reg);
	if (rc) {
		prerror("LPC: XSCOM write to ECCB DATA error %d\n", rc);
		goto bail;
	}

	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(lpc_gcid, lpc_base + ECCB_CTL, ctl);
	if (rc) {
		prerror("LPC: XSCOM write to ECCB CTL error %d\n", rc);
		goto bail;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(lpc_gcid, lpc_base + ECCB_STAT, &stat);
		if (rc) {
			prerror("LPC: XSCOM read from ECCB STAT err %d\n", rc);
			goto bail;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			if (stat & ECCB_STAT_ERR_MASK) {
				prerror("LPC: Error status: 0x%llx\n", stat);
				rc = -EIO;
				goto bail;
			}
			goto bail;
		}
	}
	prerror("LPC: Write timeout !\n");
	rc = -EIO;
 bail:
	if (do_unlock)
		unlock(&lpc_lock);
	return rc;
}

int lpc_read(uint32_t addr, uint32_t *data, unsigned int sz)
{
	uint64_t ctl = ECCB_CTL_MAGIC | ECCB_CTL_READ, stat;
	int rc, tout;
	bool do_unlock;

	if (!lpc_base)
		return -ENODEV;

	if (sz != 1 && sz != 2 && sz != 4) {
		prerror("LPC: Invalid data size %d\n", sz);
		return -EINVAL;
	}

	do_unlock = lock_recursive(&lpc_lock);
	ctl = SETFIELD(ECCB_CTL_DATASZ, ctl, sz);
	ctl = SETFIELD(ECCB_CTL_ADDRLEN, ctl, ECCB_ADDRLEN_4B);
	ctl = SETFIELD(ECCB_CTL_ADDR, ctl, addr);
	rc = xscom_write(lpc_gcid, lpc_base + ECCB_CTL, ctl);
	if (rc) {
		prerror("LPC: XSCOM write to ECCB CTL error %d\n", rc);
		goto bail;
	}

	for (tout = 0; tout < ECCB_TIMEOUT; tout++) {
		rc = xscom_read(lpc_gcid, lpc_base + ECCB_STAT, &stat);
		if (rc) {
			prerror("LPC: XSCOM read from ECCB STAT err %d\n", rc);
			goto bail;
		}
		if (stat & ECCB_STAT_OP_DONE) {
			uint32_t rdata = GETFIELD(ECCB_STAT_RD_DATA, stat);
			if (stat & ECCB_STAT_ERR_MASK) {
				prerror("LPC: Error status: 0x%llx\n", stat);
				rc = -EIO;
				goto bail;
			}
			switch(sz) {
			case 1:
				*(uint8_t *)data = rdata >> 24;
				break;
			case 2:
				*(uint16_t *)data = rdata >> 16;
				break;
			case 4:
				*data = rdata;
				break;
			}
			goto bail;
		}
	}
	prerror("LPC: Read timeout !\n");
	rc = -EIO;
 bail:
	if (do_unlock)
		unlock(&lpc_lock);
	return rc;
}

bool lpc_present(void)
{
	return lpc_base != 0;
}

void lpc_init(void)
{
	struct dt_node *xn;
	const struct dt_property *reg;

	/* Assume only one LPC in device-tree for now ... */
	xn = dt_find_compatible_node(dt_root, NULL, "ibm,power8-lpc");
	if (!xn) {
		prerror("LPC: No LPC node in device-tree\n");
		return;
	}

	/* XSCOM addresses have two cells: GCID and PCB address */
	reg = dt_find_property(xn, "reg");
	assert(reg);
	lpc_gcid = ((uint32_t *)reg->prop)[0];
	lpc_base = ((uint32_t *)reg->prop)[1];

	printf("LPC: Found, GCID=0x%x PCB_Addr=0x%x\n", lpc_gcid, lpc_base);
}

