#include <processor.h>
#include <spira.h>
#include <io.h>
#include <fsp.h>

static bool fsp_check_impl(const void *spss)
{
	const struct spss_sp_impl *sp_impl;
	unsigned int mask;

	/* Find an check the SP Implementation structure */
	sp_impl = HDIF_get_idata(spss, SPSS_IDATA_SP_IMPL, NULL);
	if (!sp_impl) {
		prerror("FSP: SPSS/SP_Implementation not found !\n");
		return false;
	}

	printf("FSP: FSP HW version %d, SW version %d, chip DD%d.%d\n",
	       sp_impl->hw_version, sp_impl->sw_version,
	       sp_impl->chip_version >> 4, sp_impl->chip_version & 0xf);
	mask = SPSS_SP_IMPL_FLAGS_FUNCTIONAL | SPSS_SP_IMPL_FLAGS_FUNCTIONAL;
	if ((sp_impl->func_flags & mask) != mask) {
		prerror("FSP: FSP not installed or not functional\n");
		return false;
	}

	return true;
}

/* fsp_preinit -- Early initialization of the FSP stack
 *
 */
void fsp_preinit(void)
{
	void *spss;

	/* Find SPSS in SPIRA */
	spss = spira.ntuples.sp_subsys.addr;
	if (!spss) {
		prerror("FSP: Cannot locate SPSS !\n");
		return;
	}
	if (!HDIF_check(spss, 'S','P','I','N','F','O')) {
		prerror("FSP: SPSS header signature mismatch !\n");
		return;
	}

	/* Check SP Implementation */
	if (!fsp_check_impl(spss))
		return;

}

