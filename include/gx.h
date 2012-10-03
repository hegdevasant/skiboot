/*
 * Definitions relative to the P7 and P7+ GX controller
 */
#ifndef __GX_H
#define __GX_H

#include <bitutils.h>

/* P7 GX Mode 1 register (contains PSI BUID) */
#define GX_P7_MODE1_REG		0x0201180A
#define GX_P7_MODE1_PSI_BUID_MASK	PPC_BITMASK(18,26)
#define GX_P7_MODE1_PSI_BUID_LSH	PPC_BITLSHIFT(26)
#define GX_P7_MODE1_PSI_BUID_DISABLE	PPC_BIT(27)

/* P7+ GX Mode 4 register (PSI and NX BUIDs ) */
#define GX_P7P_MODE4_REG	0x02011811
#define GX_P7P_MODE4_ENABLE_NX_BUID	PPC_BIT(0)
#define GX_P7P_MODE4_NX_BUID_BASE_MASK	PPC_BITMASK(1,9)
#define GX_P7P_MODE4_NX_BUID_BASE_LSH	PPC_BITLSHIFT(9)
#define GX_P7P_MODE4_NX_BUID_MASK_MASK	PPC_BITMASK(10,18)
#define GX_P7P_MODE4_NX_BUID_MASK_LSH	PPC_BITLSHIFT(18)
#define GX_P7P_MODE4_PSI_BUID_MASK	PPC_BITMASK(19,27)
#define GX_P7P_MODE4_PSI_BUID_LSH	PPC_BITLSHIFT(27)
#define GX_P7P_MODE4_PSI_BUID_DISABLE	PPC_BIT(28)

extern int gx_configure_psi_buid(uint32_t chip, uint32_t buid);

#endif /* __GX_H */
