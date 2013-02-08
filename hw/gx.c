#include <skiboot.h>
#include <gx.h>
#include <xscom.h>

/* Configuration of the PSI BUID, see the explanation in
 * interrupts.h
 */
static int gx_p7_configure_psi_buid(uint32_t chip, uint32_t buid)
{
	uint32_t gcid = xscom_chip_to_gcid(chip);
	uint64_t mode1;
	int rc;

	rc = xscom_read(gcid, GX_P7_MODE1_REG, &mode1);
	if (rc) {
		prerror("GX: XSCOM error %d reading GX MODE1 REG\n", rc);
		return rc;
	}

	mode1 = SETFIELD(GX_P7_MODE1_PSI_BUID, mode1, buid);
	mode1 &= ~GX_P7_MODE1_PSI_BUID_DISABLE;

	printf("GX: MODE1_REG set to 0x%llx\n", mode1);
	rc = xscom_write(gcid, GX_P7_MODE1_REG, mode1);
	if (rc) {
		prerror("GX: XSCOM error %d writing GX MODE1 REG\n", rc);
		return rc;
	}

	return 0;
}

static int gx_p7p_configure_psi_buid(uint32_t chip, uint32_t buid)
{
	uint32_t gcid = xscom_chip_to_gcid(chip);
	uint64_t mode4;
	int rc;

	rc = xscom_read(gcid, GX_P7P_MODE4_REG, &mode4);
	if (rc) {
		prerror("GX: XSCOM error %d reading GX MODE1 REG\n", rc);
		return rc;
	}

	mode4 = SETFIELD(GX_P7P_MODE4_PSI_BUID, mode4, buid);
	mode4 &= ~GX_P7P_MODE4_PSI_BUID_DISABLE;

	rc = xscom_write(gcid, GX_P7P_MODE4_REG, mode4);
	if (rc) {
		prerror("GX: XSCOM error %d writing GX MODE1 REG\n", rc);
		return rc;
	}

	return 0;
}

/* Configure the BUID of the PSI interrupt in the GX
 * controller.
 *
 * @chip: Chip number (0..31)
 * @buid: 9-bit BUID value
 */
int gx_configure_psi_buid(uint32_t chip, uint32_t buid)
{
	uint32_t pvr = mfspr(SPR_PVR);

	printf("GX: PSI BUID for PVR %x (type %x) chip %d BUID 0x%x\n",
	       pvr, PVR_TYPE(pvr), chip, buid);
	       
	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P7:
		return gx_p7_configure_psi_buid(chip, buid);
	case PVR_TYPE_P7P:
		return gx_p7p_configure_psi_buid(chip, buid);
	}
	return -1;
}


static int gx_p7_configure_tce_bar(uint32_t chip, uint32_t gx, uint64_t addr,
				   uint64_t size)
{
	uint32_t gcid = xscom_chip_to_gcid(chip);
	uint32_t areg, mreg;
	int rc;

	switch (gx) {
	case 0:
		areg = GX_P7_GX0_TCE_BAR;
		mreg = GX_P7_GX0_TCE_MASK;
		break;
	case 1:
		areg = GX_P7_GX1_TCE_BAR;
		mreg = GX_P7_GX1_TCE_MASK;
		break;
	default:
		return -EINVAL;
	}

	if (addr) {
		uint64_t taddr, tmask;

		/* The address field contains bits 18 to 43 of the address */
		taddr = SETFIELD(GX_P7_TCE_BAR_ADDR, 0ul,
				 (addr >> GX_P7_TCE_BAR_ADDR_SHIFT));
		taddr |= GX_P7_TCE_BAR_ENABLE;
		tmask = SETFIELD(GX_P7_TCE_MASK, 0ul,
				 ((~(size - 1)) >> GX_P7_TCE_BAR_ADDR_SHIFT));
		rc = xscom_write(gcid, areg, 0);
		rc |= xscom_write(gcid, mreg, tmask);
		rc |= xscom_write(gcid, areg, taddr);
	} else {
		rc = xscom_write(gcid, areg, 0);
	}
	return rc ? -EIO : 0;
}

/* Configure the TCE BAR of a given GX bus
 *
 * @chip: Chip number (0..31)
 * @gx  : GX bus index
 * @addr: base address of TCE table
 * @size: size of TCE table
 */
int gx_configure_tce_bar(uint32_t chip, uint32_t gx, uint64_t addr,
			 uint64_t size)
{
	uint32_t pvr = mfspr(SPR_PVR);

	printf("GX: TCE BAR for PVR %x (type %x) chip %d gx %d\n",
	       pvr, PVR_TYPE(pvr), chip, gx);

	/* We only support P7... is there a P7+ with P5IOC2 ? */
	switch(PVR_TYPE(pvr)) {
	case PVR_TYPE_P7:
		return gx_p7_configure_tce_bar(chip, gx, addr, size);
	}
	return -EINVAL;
}


