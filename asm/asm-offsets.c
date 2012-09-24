#include <stddef.h>
#include <types.h>
#include <skiboot.h>
#include <spira.h>
#include <processor.h>

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " %0 " #val : : "i" (val))

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

int main(void)
{
	OFFSET(SPIRA_ACTUAL_SIZE, spira, reserved);

#if 0 /* Test stuff */
	DEFINE(FOOBAR1M, SPR_TFMR_MAX_CYC_BET_STEPS_MASK);
	DEFINE(FOOBAR1S, SPR_TFMR_MAX_CYC_BET_STEPS_LSH);
	DEFINE(FOOBAR2M, SPR_TFMR_SYNC_BIT_SEL_MASK);
	DEFINE(FOOBAR2S, SPR_TFMR_SYNC_BIT_SEL_LSH);
#endif

	return 0;
}
