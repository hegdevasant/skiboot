#include <skiboot.h>
#include <gx.h>
#include <xscom.h>

/* Configuration of the PSI BUID, see the explanation in
 * interrupts.h
 */
static int gx_p7_configure_psi_buid(uint32_t chip, uint32_t buid)
{
	uint32_t gcid = CHIP2GCID(chip);
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
	uint32_t gcid = CHIP2GCID(chip);
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


