#ifndef __P7IOC_H
#define __P7IOC_H

#include <spira.h>
#include <cec.h>
#include <pci.h>
#include <lock.h>

#include <ccan/container_of/container_of.h>

/*
 * Memory windows and BUID assignment
 *
 * - GX BAR assignment
 *
 *   I don't know of any spec here, so we're going to mimmic what
 *   OPAL seems to be doing:
 *
 *     - BAR 0 :   32M, disabled. We just leave it alone.
 *     - BAR 1 :    8G, enabled. Appears to correspond to the MMIO
 *                      space of the IOC itself and the PCI IO space
 *     - BAR 2:   128G,
 *     - BAR 3:   128G,
 *     - BAR 4:   128G, all 3 contiguous, forming a single 368G region
 *                      and is used for M32 and M64 PHB windows.
 *
 * - Memory map
 *
 *    MWIN1 = BAR1 (8G)
 *    MWIN2 = BAR2,3,4 (384G)
 *
 *    MWIN2 is divided into 6 * 4G regions for use by M32's (*) and
 *    6 * 32G regions for use by M64's.
 *
 * (*) The M32 will typically be configured to only 2G or so, however
 *     the OS is in control of that setting, and since we have to reserve
 *     a power of two, we reserve the whole 4G.
 *
 *    - RGC registers: MWIN1 + 0x00000000
 *    - PHBn IO space: MWIN1 + 0x01000000 + n * 0x00800000 (8M each)
 *    - PHBn M32     : MWIN2 + n * 0x1_00000000 (4G each)
 *    - PHBn M64     : MWIN2 + (n + 1) * 0x8_00000000 (32G each)
 *
 * - BUID map. The RGC has interrupts, each PHB has then its own
 *             interrupts (errors etc...), 4 LSIs and 256 LSIs so
 *             respectively 1 BUID for self, 1 for LSIs and 16 for LSIs
 *
 *   We keep all BUIDs below 0x10 reserved. They will be used for things
 *   like the PSI controller, the NX unit, etc.. in the P7 chip.
 *
 *    RGC	: 0x010
 *    PHBn LSI	: 0x040 + n * 0x40 (   1 BUID)
 *    PHBn MSI  : 0x060 + n * 0x40 (0x10 BUIDs)
 *
 * -> For routing, each PHB gets a block of 0x40 BUIDs:
 *
 *	from 0x40 * (n + 1) to 0x7f * (n + 1)
 */

/* Some definitions resulting from the above description
 *
 * Note: A better approach might be to read the GX BAR content
 *       and isolate the biggest contiguous windows. From there
 *       we could divide things algorithmically and thus be
 *       less sensitive to a change in the memory map by the FSP
 */
#define MWIN1_SIZE	0x200000000ul	/* MWIN1 is 8G */
#define MWIN2_SIZE     0x6000000000ul	/* MWIN2 is 384G */
#define PHB_IO_OFFSET	 0x01000000ul	/* Offset of PHB IO space in MWIN1 */
#define PHB_IO_SIZE	 0x00800000ul
#define PHB_M32_OFFSET	        0x0ul	/* Offset of PHB M32 space in MWIN2 */
#define PHB_M32_SIZE	0x100000000ul
#define PHB_M64_OFFSET	0x800000000ul	/* Offset of PHB M64 space in MWIN2 */
#define PHB_M64_SIZE	0x800000000ul
#define RGC_BUID_OFFSET		0x10	/* Offset of RGC BUID */
#define PHB_BUID_OFFSET		0x40	/* Offset of PHB BUID blocks */
#define PHB_BUID_SIZE		0x40	/* Size of PHB BUID blocks */
#define PHB_BUID_LSI_OFFSET	0x00	/* Offset of LSI in PHB BUID block */
#define PHB_BUID_MSI_OFFSET	0x20	/* Offset of MSI in PHB BUID block */
#define PHB_BUID_MSI_SIZE	0x10	/* Size of PHB MSI BUID block */

#define PHBn_IO_BASE(n)		(PHB_IO_OFFSET + (n) * PHB_IO_SIZE)
#define PHBn_M32_BASE(n)	(PHB_M32_OFFSET + (n) * PHB_M32_SIZE)
#define PHBn_M64_BASE(n)	(PHB_M64_OFFSET + (n) * PHB_M64_SIZE)
#define PHBn_BUID_BASE(n)	(PHB_BUID_OFFSET + (n) * PHB_BUID_SIZE)

#define BUID_TO_PHB(buid)	((buid - PHB_BUID_OFFSET) / PHB_BUID_SIZE)

/* p7ioc has 6 PHBs */
#define P7IOC_NUM_PHBS		6

/* M32 window setting at boot:
 *
 * To allow for DMA, we need to split the 32-bit PCI address space between
 * MMIO and DMA. For now, we use a 2G/2G split with MMIO at the top.
 *
 * Note: The top 64K of the M32 space are used by MSIs. This is not
 * visible here but need to be conveyed to the OS one way or another
 *
 * Note2: The space reserved in the system address space for M32 is always
 * 4G. That we chose to use a smaller portion of it is not relevant to
 * the upper levels. To keep things consistent, the offset we apply to
 * the window start is also applied on the host side.
 */
#define M32_PCI_START	0x80000000
#define M32_PCI_SIZE	0x80000000

/* PHB registers exist in both a hard coded space and a programmable
 * AIB space. We program the latter to the values recommended in the
 * documentation:
 *
 *	0x80000 + n * 0x10000
 */
#define PHBn_ASB_BASE(n)	(((n) << 16))
#define PHBn_ASB_SIZE		0x10000ul
#define PHBn_AIB_BASE(n)	(0x80000ul + ((n) << 16))
#define PHBn_AIB_SIZE		0x10000ul

/*
 * LSI interrupts
 *
 * The LSI interrupt block supports 8 interrupts. 4 of them are the
 * standard PCIe INTA..INTB. The rest is for additional functions
 * of the PHB
 */
#define PHB_LSI_PCIE_INTA		0
#define PHB_LSI_PCIE_INTB		1
#define PHB_LSI_PCIE_INTC		2
#define PHB_LSI_PCIE_INTD		3
#define PHB_LSI_PCIE_HOTPLUG		4
#define PHB_LSI_PCIE_PERFCTR		5
#define PHB_LSI_PCIE_UNUSED		6
#define PHB_LSI_PCIE_ERROR		7

/*
 * Register definitions
 *
 * We only define some registers here. Ideally we should auto-generate
 * the full list from the spec. For now I add them as I need them
 */

/* HSS registers */
#define P7IOC_HSS_BASE          0x3E8000 
#define P7IOC_HSS_STRIDE        0x200
#define P7IOC_HSSn_CTL2_OFFSET  0x10
#define P7IOC_HSSn_CTL3_OFFSET  0x18
#define P7IOC_HSSn_CTL8_OFFSET  0x40
#define P7IOC_HSSn_CTL9_OFFSET  0x48
#define P7IOC_HSSn_CTL10_OFFSET 0x50
#define P7IOC_HSSn_CTL11_OFFSET 0x58
#define P7IOC_HSSn_CTL12_OFFSET 0x60
#define P7IOC_HSSn_CTL13_OFFSET 0x68
#define P7IOC_HSSn_CTL14_OFFSET 0x70
#define P7IOC_HSSn_CTL15_OFFSET 0x78
#define P7IOC_HSSn_CTL16_OFFSET 0x80
#define P7IOC_HSSn_CTL17_OFFSET 0x88
#define P7IOC_HSSn_CTL18_OFFSET 0x90
#define P7IOC_HSSn_CTL19_OFFSET 0x98
#define P7IOC_HSSn_CTL20_OFFSET 0xa0
#define P7IOC_HSSn_CTL21_OFFSET 0xa8
#define P7IOC_HSSn_CTL22_OFFSET 0xb0
#define P7IOC_HSSn_CTL23_OFFSET 0xb8

/* CI Routing registers & helper macros */
#define P7IOC_CI_RMATC_REG(i)		(0x3D0400ul + ((i) << 4))
#define P7IOC_CI_RMASK_REG(i)		(0x3D0408ul + ((i) << 4))

#define P7IOC_CI_RMATC_PORT(n)		PPC_BIT(n)
#define P7IOC_CI_RMATC_ADDR_VALID	PPC_BIT(16)
#define P7IOC_CI_RMATC_BUID_VALID	PPC_BIT(17)
#define P7IOC_CI_RMATC_TYPE_VALID	PPC_BIT(18)

/* AIB Addresses are 48-bit, the top 32 are used in
 * the routing tables, we thus shift by 16
 */
#define P7IOC_CI_RMATC_ENCODE_ADDR(addr)	((uint32_t)((addr) >> 16))
#define P7IOC_CI_RMATC_ENCODE_BUID(buid)	((uint32_t)((buid) << 20))
#define P7IOC_CI_RMATC_ENCODE_TYPE(type)	((uint32_t)(type))

/* CI port numbers */
#define P7IOC_CI_PHB_PORT(pnum)		((pnum) + 2)
#define P7IOC_CI_UPSTREAM_PORT		0
#define P7IOC_CI_RGC_PORT		1

/*
 * PHB registers
 */

/* PHB Fundamental register set A */
#define PHB_BUID			0x100
#define   PHB_BUID_LSI_MASK		PPC_BITMASK(7,15)
#define   PHB_BUID_LSI_LSH		PPC_BITLSHIFT(15)
#define   PHB_BUID_MSI_MASK		PPC_BITMASK(23,31)
#define   PHB_BUID_MSI_LSH		PPC_BITLSHIFT(31)
#define PHB_DMA_CHAN_STATUS		0x110
#define PHB_CPU_LOADSTORE_STATUS	0x120
#define PHB_CONFIG_DATA			0x130
#define PHB_LOCK0			0x138
#define PHB_CONFIG_ADDRESS		0x140
#define   PHB_CA_ENABLE			PPC_BIT(0)
#define	  PHB_CA_BUS_MASK		PPC_BITMASK(4,11)
#define   PHB_CA_BUS_LSH		PPC_BITLSHIFT(11)
#define   PHB_CA_DEV_MASK		PPC_BITMASK(12,16)
#define   PHB_CA_DEV_LSH		PPC_BITLSHIFT(16)
#define   PHB_CA_FUNC_MASK		PPC_BITMASK(17,19)
#define   PHB_CA_FUNC_LSH		PPC_BITLSHIFT(19)
#define   PHB_CA_REG_MASK		PPC_BITMASK(20,31)
#define   PHB_CA_REG_LSH		PPC_BITLSHIFT(31)
#define PHB_LOCK1			0x148
#define PHB_PHB2_CONFIG			0x160
#define   PHB_PHB2C_64B_TCE_EN		PPC_BIT(2)
#define   PHB_PHB2C_32BIT_MSI_EN	PPC_BIT(8)
#define   PHB_PHB2C_IO_EN		PPC_BIT(12)
#define   PHB_PHB2C_64BIT_MSI_EN	PPC_BIT(14)
#define   PHB_PHB2C_M32_EN		PPC_BIT(16)
#define PHB_IO_BASE_ADDR		0x170
#define PHB_IO_BASE_MASK		0x178
#define PHB_IO_START_ADDR		0x180
#define PHB_M32_BASE_ADDR		0x190
#define PHB_M32_BASE_MASK		0x198
#define PHB_M32_START_ADDR		0x1a0
#define PHB_M64_UPPER_BITS		0x1f0
#define PHB_TCE_KILL			0x210
#define   PHB_TCEKILL_PAIR		PPC_BIT(0)
#define   PHB_TCEKILL_ADDR_MASK		PPC_BITMASK(16,59)
#define PHB_TCE_PREFETCH		0x218
#define PHB_IODA_ADDR			0x220
#define   PHB_IODA_AD_AUTOINC		PPC_BIT(0)
#define	  PHB_IODA_AD_TSEL_MASK		PPC_BITMASK(11,15)
#define	  PHB_IODA_AD_TSEL_LSH		PPC_BITLSHIFT(15)
#define	  PHB_IODA_AD_TADR_MASK		PPC_BITMASK(48,63)
#define	  PHB_IODA_AD_TADR_LSH		PPC_BITLSHIFT(63)
#define PHB_IODA_DATA0			0x228
#define PHB_IODA_DATA1			0x230
#define PHB_LOCK2			0x240
#define PHB_XIVE_UPDATE			0x248
#define PHB_PHB2_GEN_CAP		0x250
#define PHB_PHB2_TCE_CAP		0x258
#define PHB_PHB2_IRQ_CAP		0x260
#define PHB_PHB2_EEH_CAP		0x268
#define PHB_PAPR_ERR_INJ_CONTROL	0x2b0
#define PHB_PAPR_ERR_INJ_ADDR		0x2b8
#define PHB_PAPR_ERR_INJ_MASK		0x2c0
#define PHB_ETU_ERR_SUMMARY		0x2c8

/*  UTL registers */
#define UTL_SYS_BUS_CONTROL		0x400
#define UTL_STATUS			0x408
#define UTL_SYS_BUS_AGENT_STATUS	0x410
#define UTL_SYS_BUS_AGENT_ERR_SEVERITY	0x418
#define UTL_SYS_BUS_AGENT_IRQ_EN	0x420
#define UTL_SYS_BUS_BURST_SZ_CONF	0x440
#define UTL_REVISION_ID			0x448
#define UTL_OUT_POST_HDR_BUF_ALLOC	0x4c0
#define UTL_OUT_POST_DAT_BUF_ALLOC	0x4d0
#define UTL_IN_POST_HDR_BUF_ALLOC	0x4e0
#define UTL_IN_POST_DAT_BUF_ALLOC	0x4f0
#define UTL_OUT_NP_BUF_ALLOC		0x500
#define UTL_IN_NP_BUF_ALLOC		0x510
#define UTL_PCIE_TAGS_ALLOC		0x520
#define UTL_GBIF_READ_TAGS_ALLOC	0x530
#define UTL_PCIE_PORT_CONTROL		0x540
#define UTL_PCIE_PORT_STATUS		0x548
#define UTL_PCIE_PORT_ERROR_SEV		0x550
#define UTL_PCIE_PORT_IRQ_EN		0x558
#define UTL_RC_STATUS			0x560
#define UTL_RC_ERR_SEVERITY		0x568
#define UTL_RC_IRQ_EN			0x570
#define UTL_EP_STATUS			0x578
#define UTL_EP_ERR_SEVERITY		0x580
#define UTL_EP_ERR_IRQ_EN		0x588
#define UTL_PCI_PM_CTRL1		0x590
#define UTL_PCI_PM_CTRL2		0x598
#define UTL_GP_CTL1			0x5a0
#define UTL_GP_CTL2			0x5a8

/* PCI-E Stack registers */
#define PHB_PCIE_SYSTEM_CONFIG		0x600
#define PHB_PCIE_BUS_NUMBER		0x608
#define PHB_PCIE_SYSTEM_TEST		0x618
#define PHB_PCIE_LINK_MANAGEMENT	0x630
#define PHB_PCIE_DLP_TRAIN_CTL		0x640
#define   PHB_PCIE_DLP_TC_DL_LINKUP	PPC_BIT(21)
#define   PHB_PCIE_DLP_TC_DL_PGRESET	PPC_BIT(22)
#define   PHB_PCIE_DLP_TC_DL_LINKACT	PPC_BIT(23)
#define PHB_PCIE_SLOP_LOOPBACK_STATUS	0x648
#define PHB_PCIE_AER_CONTROL		0x650
#define PHB_PCIE_AUX_POWER_CONTROL	0x658
#define PHB_PCIE_SLOTCTL1		0x660
#define PHB_PCIE_SLOTCTL2		0x668
#define   PHB_PCIE_SLOTCTL2_SLOTWAKE	PPC_BIT(16)
#define   PHB_PCIE_SLOTCTL2_PWR_EN_STAT	PPC_BIT(17)
#define   PHB_PCIE_SLOTCTL2_RCK_EN_STAT	PPC_BIT(18)
#define   PHB_PCIE_SLOTCTL2_PERST_STAT	PPC_BIT(19)
#define   PHB_PCIE_SLOTCTL2_PLED_S_MASK	PPC_BITMASK(20,21)
#define   PHB_PCIE_SLOTCTL2_PLED_S_LSH	PPC_BITLSHIFT(21) /* use PCIE_INDIC_* */
#define   PHB_PCIE_SLOTCTL2_ALED_S_MASK	PPC_BITMASK(22,23)
#define   PHB_PCIE_SLOTCTL2_ALED_S_LSH	PPC_BITLSHIFT(23)
#define   PHB_PCIE_SLOTCTL2_PRSTN_STAT	PPC_BIT(24)
#define   PHB_PCIE_SLOTCTL2_PWRFLT_STAT	PPC_BIT(25)
#define PHB_PCIE_UTL_CONFIG		0x670
#define PHB_PCIE_DLP_CONTROL		0x678
#define PHB_PCIE_UTL_ERRLOG1		0x680
#define PHB_PCIE_UTL_ERRLOG2		0x688
#define PHB_PCIE_UTL_ERRLOG3		0x690
#define PHB_PCIE_UTL_ERRLOG4		0x698
#define PHB_PCIE_DLP_ERRLOG1		0x6a0
#define PHB_PCIE_DLP_ERRLOG2		0x6a8
#define PHB_PCIE_UTL_ERR_INJECT		0x6c0
#define PHB_PCIE_TLDLP_ERR_INJECT	0x6c8
#define PHB_PCIE_STRAPPING		0x700

/* Fundamental register set B */
#define PHB_VERSION			0x800
#define PHB_RESET			0x808
#define PHB_CONTROL			0x810
#define PHB_AIB_RX_CRED_INIT_TIMER	0x818
#define PHB_AIB_RX_CMD_CRED		0x820
#define PHB_AIB_RX_DATA_CRED		0x828
#define PHB_AIB_TX_CMD_CRED		0x830
#define PHB_AIB_TX_DATA_CRED		0x838
#define PHB_AIB_TX_CHAN_MAPPING		0x840
#define PHB_AIB_TX_CRED_SYNC_CTRL	0x848
#define PHB_LEGACY_CTRL			0x850
#define PHB_AIB_TAG_ENABLE		0x858
#define PHB_AIB_FENCE_CTRL		0x860
#define PHB_TCE_TAG_ENABLE		0x868
#define PHB_TCE_WATERMARK		0x870
#define PHB_TIMEOUT_CTRL1		0x878
#define PHB_TIMEOUT_CTRL2		0x880
#define PHB_QUIESCE_DMA_G		0x888
#define PHB_AIB_TAG_STATUS		0x900
#define PHB_TCE_TAG_STATUS		0x908

/* FIR & Error registers */
#define PHB_LEM_FIR_ACCUM		0xc00
#define PHB_LEM_FIR_AND_MASK		0xc08
#define PHB_LEM_FIR_OR_MASK		0xc10
#define PHB_LEM_ERROR_MASK		0xc18
#define PHB_LEM_ERROR_AND_MASK		0xc20
#define PHB_LEM_ERROR_OR_MASK		0xc28
#define PHB_LEM_ACTION0			0xc30
#define PHB_LEM_ACTION1			0xc38
#define PHB_LEM_WOF			0xc40
#define PHB_ERR_STATUS			0xc80
#define PHB_ERR1_STATUS			0xc88
#define PHB_ERR_INJECT			0xc90
#define PHB_ERR_LEM_ENABLE		0xc98
#define PHB_ERR_IRQ_ENABLE		0xca0
#define PHB_ERR_FREEZE_ENABLE		0xca8
#define PHB_ERR_AIB_FENCE_ENABLE	0xcb0
#define PHB_ERR_LOG_0			0xcc0
#define PHB_ERR_LOG_1			0xcc8
#define PHB_ERR_STATUS_MASK		0xcd0
#define PHB_ERR1_STATUS_MASK		0xcd8

#define PHB_OUT_ERR_STATUS		0xd00
#define PHB_OUT_ERR1_STATUS		0xd08
#define PHB_OUT_ERR_INJECT		0xd10
#define PHB_OUT_ERR_LEM_ENABLE		0xd18
#define PHB_OUT_ERR_IRQ_ENABLE		0xd20
#define PHB_OUT_ERR_FREEZE_ENABLE	0xd28
#define PHB_OUT_ERR_AIB_FENCE_ENABLE	0xd30
#define PHB_OUT_ERR_LOG_0		0xd40
#define PHB_OUT_ERR_LOG_1		0xd48
#define PHB_OUT_ERR_STATUS_MASK		0xd50
#define PHB_OUT_ERR1_STATUS_MASK	0xd58

#define PHB_INA_ERR_STATUS		0xd80
#define PHB_INA_ERR1_STATUS		0xd88
#define PHB_INA_ERR_INJECT		0xd90
#define PHB_INA_ERR_LEM_ENABLE		0xd98
#define PHB_INA_ERR_IRQ_ENABLE		0xda0
#define PHB_INA_ERR_FREEZE_ENABLE	0xda8
#define PHB_INA_ERR_AIB_FENCE_ENABLE	0xdb0
#define PHB_INA_ERR_LOG_0		0xdc0
#define PHB_INA_ERR_LOG_1		0xdc8
#define PHB_INA_ERR_STATUS_MASK		0xdd0
#define PHB_INA_ERR1_STATUS_MASK	0xdd8

#define PHB_INB_ERR_STATUS		0xe00
#define PHB_INB_ERR1_STATUS		0xe08
#define PHB_INB_ERR_INJECT		0xe10
#define PHB_INB_ERR_LEM_ENABLE		0xe18
#define PHB_INB_ERR_IRQ_ENABLE		0xe20
#define PHB_INB_ERR_FREEZE_ENABLE	0xe28
#define PHB_INB_ERR_AIB_FENCE_ENABLE	0xe30
#define PHB_INB_ERR_LOG_0		0xe40
#define PHB_INB_ERR_LOG_1		0xe48
#define PHB_INB_ERR_STATUS_MASK		0xe50
#define PHB_INB_ERR1_STATUS_MASK	0xe58

/* Performance monitor & Debug registers */
#define PHB_TRACE_CONTROL		0xf80
#define PHB_PERFMON_CONFIG		0xf88
#define PHB_PERFMON_CTR0		0xf90
#define PHB_PERFMON_CTR1		0xf98
#define PHB_PERFMON_CTR2		0xfa0
#define PHB_PERFMON_CTR3		0xfa8
#define PHB_HOTPLUG_OVERRIDE		0xfb0

/*
 * IODA tables
 */

#define IODA_TBL_HRT		0
#define IODA_TBL_LIST		1
#define IODA_TBL_LXIVT		2
#define IODA_TBL_MIST		3
#define IODA_TBL_MXIVT		4
#define IODA_TBL_MVT		5
#define IODA_TBL_PELTM		6
#define IODA_TBL_PESTA		7
#define IODA_TBL_PESTB		8
#define IODA_TBL_TVT		9
#define IODA_TBL_TCAM		10
#define IODA_TBL_TDR		11
#define IODA_TBL_PELTV		12
#define IODA_TBL_M64BT		16
#define IODA_TBL_IODT		17
#define IODA_TBL_M32DT		18
#define IODA_TBL_M64DT		19
#define IODA_TBL_PEEV		20

/* L/M XIVT */
#define IODA_XIVT_SERVER_MASK		PPC_BITMASK(8,23)
#define IODA_XIVT_SERVER_LSH		PPC_BITLSHIFT(23)
#define IODA_XIVT_PRIORITY_MASK		PPC_BITMASK(24,31)
#define IODA_XIVT_PRIORITY_LSH		PPC_BITLSHIFT(31)
#define IODA_XIVT_PENUM_MASK		PPC_BITMASK(41,47)
#define IODA_XIVT_PENUM_LSH		PPC_BITLSHIFT(47)
#define IODA_XIVT_HUBNUM_MASK		PPC_BITMASK(58,59)
#define IODA_XIVT_HUBNUM_LSH		PPC_BITLSHIFT(59)

/* IODT/M32DT/M64DX */
#define IODA_XXDT_PE_MASK		PPC_BITMASK(0,6)
#define IODA_XXDT_PE_LSH		PPC_BITLSHIFT(6)

/* PELTM */
#define IODA_PELTM_BUS_MASK		PPC_BITMASK(0,7)
#define IODA_PELTM_BUS_LSH		PPC_BITLSHIFT(7)
#define IODA_PELTM_DEV_MASK		PPC_BITMASK(8,12)
#define IODA_PELTM_DEV_LSH		PPC_BITLSHIFT(12)
#define IODA_PELTM_FUNC_MASK		PPC_BITMASK(13,15)
#define IODA_PELTM_FUNC_LSH		PPC_BITLSHIFT(15)
#define IODA_PELTM_BUS_VALID_MASK	PPC_BITMASK(16,18)
#define IODA_PELTM_BUS_VALID_LSH	PPC_BITLSHIFT(18)
#define  IODA_BUS_VALID_ANY		0
#define  IODA_BUS_VALID_3_BITS		2
#define  IODA_BUS_VALID_4_BITS		3
#define  IODA_BUS_VALID_5_BITS		4
#define  IODA_BUS_VALID_6_BITS		5
#define  IODA_BUS_VALID_7_BITS		6
#define  IODA_BUS_VALID_ALL		7
#define IODA_PELTM_DEV_VALID		PPC_BIT(19)
#define IODA_PELTM_FUNC_VALID		PPC_BIT(20)

/* TVT */
#define IODA_TVT0_TABLE_ADDR_MASK	PPC_BITMASK(0,47)
#define IODA_TVT0_TABLE_ADDR_LSH	PPC_BITLSHIFT(47)
#define IODA_TVT0_BUS_VALID_MASK	PPC_BITMASK(48,50)
#define IODA_TVT0_BUS_VALID_LSH		PPC_BITLSHIFT(50)
#define IODA_TVT0_TCE_TABLE_SIZE_MASK	PPC_BITMASK(51,55)
#define IODA_TVT0_TCE_TABLE_SIZE_LSH	PPC_BITLSHIFT(55)
#define IODA_TVT0_BUS_NUM_MASK		PPC_BITMASK(56,63)
#define IODA_TVT0_BUS_NUM_LSH		PPC_BITLSHIFT(63)
#define IODA_TVT1_DEV_VALID		PPC_BIT(2)
#define IODA_TVT1_DEV_NUM_MASK		PPC_BITMASK(3,7)
#define IODA_TVT1_DEV_NUM_LSH		PPC_BITLSHIFT(7)
#define IODA_TVT1_HUB_NUM_MASK		PPC_BITMASK(10,11)
#define IODA_TVT1_HUB_NUM_LSH		PPC_BITLSHIFT(11)
#define IODA_TVT1_FUNC_VALID		PPC_BIT(12)
#define IODA_TVT1_FUNC_NUM_MASK		PPC_BITMASK(13,15)
#define IODA_TVT1_FUNC_NUM_LSH		PPC_BITLSHIFT(15)
#define IODA_TVT1_IO_PSIZE_MASK		PPC_BITMASK(19,23)
#define IODA_TVT1_IO_PSIZE_LSH		PPC_BITLSHIFT(23)
#define IODA_TVT1_PE_NUM_MASK		PPC_BITMASK(57,63)
#define IODA_TVT1_PE_NUM_LSH		PPC_BITLSHIFT(63)

/* MVT */
#define IODA_MVT_VALID			PPC_BIT(0)
#define IODA_MVT_BUS_VALID_MASK		PPC_BITMASK(21,23)
#define IODA_MVT_BUS_VALID_LSH		PPC_BITLSHIFT(23)
#define IODA_MVT_BUS_NUM_MASK		PPC_BITMASK(24,31)
#define IODA_MVT_BUS_NUM_LSH		PPC_BITLSHIFT(31)
#define IODA_MVT_PE_NUM_MASK		PPC_BITMASK(41,47)
#define IODA_MVT_PE_NUM_LSH		PPC_BITLSHIFT(47)
#define IODA_MVT_DEV_VALID		PPC_BIT(50)
#define IODA_MVT_DEV_NUM_MASK		PPC_BITMASK(51,55)
#define IODA_MVT_DEV_NUM_LSH		PPC_BITLSHIFT(55)
#define IODA_MVT_FUNC_VALID		PPC_BIT(60)
#define IODA_MVT_FUNC_NUM_MASK		PPC_BITMASK(61,63)
#define IODA_MVT_FUNC_NUM_LSH		PPC_BITLSHIFT(63)

/* PESTA */
#define IODA_PESTA_MMIO_FROZEN		PPC_BIT(0)
#define IODA_PESTA_MMIO_CAUSE		PPC_BIT(2)
#define IODA_PESTA_CFG_READ		PPC_BIT(3)
#define IODA_PESTA_CFG_WRITE		PPC_BIT(4)
#define IODA_PESTA_TTYPE_MASK		PPC_BITMASK(5,7)
#define IODA_PESTA_TTYPE_LSH		PPC_BITLSHIFT(7)
#define   PESTA_TTYPE_DMA_WRITE		0
#define   PESTA_TTYPE_MSI		1
#define   PESTA_TTYPE_DMA_READ		2
#define   PESTA_TTYPE_DMA_READ_RESP	3
#define   PESTA_TTYPE_MMIO_LOAD		4
#define   PESTA_TTYPE_MMIO_STORE	5
#define   PESTA_TTYPE_OTHER		7
#define IODA_PESTA_CA_RETURN		PPC_BIT(8)
#define IODA_PESTA_UTL_RTOS_TIMEOUT	PPC_BIT(8) /* Same bit as CA return */
#define IODA_PESTA_UR_RETURN		PPC_BIT(9)
#define IODA_PESTA_UTL_NONFATAL		PPC_BIT(10)
#define IODA_PESTA_UTL_FATAL		PPC_BIT(11)
#define IODA_PESTA_TAG_REUSE_ERROR	PPC_BIT(12)
#define IODA_PESTA_PARITY_UE		PPC_BIT(13)
#define IODA_PESTA_UTL_CORRECTABLE	PPC_BIT(14)
#define IODA_PESTA_UTL_INTERRUPT	PPC_BIT(15)
#define IODA_PESTA_MMIO_XLATE		PPC_BIT(16)
#define IODA_PESTA_IODA_ERROR		PPC_BIT(16) /* Same bit as MMIO xlate */
#define IODA_PESTA_TVT_EXT_ERROR	PPC_BIT(17)
#define IODA_PESTA_TCE_PAGE_FAULT	PPC_BIT(18)
#define IODA_PESTA_TCE_ACCESS_FAULT	PPC_BIT(19)
#define IODA_PESTA_DMA_RESP_TIMEOUT	PPC_BIT(20)
#define IODA_PESTA_AIB_SIZE_INVALID	PPC_BIT(21)
#define IODA_PESTA_LEM_BIT_MASK		PPC_BITMASK(26,31)
#define IODA_PESTA_LEM_BIT_LSH		PPC_BITLSHIFT(31)
#define IODA_PESTA_RID_MASK		PPC_BITMASK(32,47)
#define IODA_PESTA_RID_LSH		PPC_BITLSHIFT(47)
#define IODA_PESTA_MSI_DATA_MASK	PPC_BITMASK(48,63)
#define IODA_PESTA_MSI_DATA_LSH		PPC_BITLSHIFT(63)

/* PESTB */
#define IODA_PESTB_DMA_STOPPED		PPC_BIT(0)
#define IODA_PESTB_FAIL_ADDR_MASK	PPC_BITMASK(3,63)
#define IODA_PESTB_FAIL_ADDR_LSH	PPC_BITLSHIFT(63)

/*
 * State structure for a PHB on P7IOC
 */

/*
 * The PHB State structure is essentially used during PHB reset
 * or recovery operations to indicate that the PHB cannot currently
 * be used for normal operations.
 *
 * Some states involve waiting for the timebase to reach a certain
 * value. In which case the field "delay_tgt_tb" is set and the
 * state machine will be run from the "state_poll" callback.
 *
 * At IPL time, we call this repeatedly during the various sequences
 * however under OS control, this will require a change in API.
 *
 * Fortunately, the OPAL API for slot power & reset are not currently
 * used by Linux, so changing them isn't going to be an issue. The idea
 * here is that some of these APIs will return a positive integer when
 * neededing such a delay to proceed. The OS will then be required to
 * call a new function opal_poll_phb() after that delay. That function
 * will potentially return a new delay, or OPAL_SUCCESS when the original
 * operation has completed successfully. If the operation has completed
 * with an error, then opal_poll_phb() will return that error.
 *
 * Note: Should we consider also returning optionally some indication
 * of what operation is in progress for OS debug/diag purposes ?
 *
 * Any attempt at starting a new "asynchronous" operation while one is
 * already in progress will result in an error.
 *
 * Internally, this is represented by the state being PHB_STATE_FUNCTIONAL
 * when no operation is in progress, which it reaches at the end of the
 * boot time initializations. Any attempt at performing a slot operation
 * on a PHB in that state will change the state to the corresponding
 * operation state machine. Any attempt while not in that state will
 * return an error.
 *
 * Some operations allow for a certain amount of retries, this is
 * provided for by the "retries" structure member for use by the state
 * machine as it sees fit.
 */
enum p7ioc_phb_state {
	/* First init state */
	PHB_STATE_UNINITIALIZED,

	/* During PHB HW inits */
	PHB_STATE_INITIALIZING,

	/* Set if the PHB is for some reason unusable */
	PHB_STATE_BROKEN,

	/* Slot Power up state machine */
	PHB_STATE_SPUP_STABILIZE_DELAY,		/* Step 3 Delay 2s */
	PHB_STATE_SPUP_SLOT_STATUS,		/* Step 4 waiting for status */
	PHB_STATE_SPUP_WAIT_LINK,		/* Step 9 Wait link training */
	PHB_STATE_SPUP_HOT_RESET_DELAY,		/* Step 12 Activate Hot Reset */

	/* Slot Power down state machine */
	PHB_STATE_SPDOWN_STABILIZE_DELAY,	/* Step 2 Delay 2s */
	PHB_STATE_SPDOWN_SLOT_STATUS,		/* Step 3 waiting for status */

	/* Hot Reset sequence */
	PHB_STATE_HRESET_DELAY,			/* Hot reset delay */

	/* Normal PHB functional state */
	PHB_STATE_FUNCTIONAL,
};

struct p7ioc;

struct p7ioc_phb {
	bool				active;	/* Is this PHB functional ? */
	uint8_t				index;	/* 0..5 index inside p7ioc */
	void				*regs_asb;
	void				*regs;	/* AIB regs */
	struct lock			lock;
	uint32_t			buid_lsi;
	uint32_t			buid_msi;
	uint64_t			io_base;
	uint64_t			m32_base;
	uint64_t			m64_base;
	enum p7ioc_phb_state		state;
	uint64_t			delay_tgt_tb;
	uint64_t			retries;
	int64_t				ecap;	/* cached PCI-E cap offset */
	int64_t				aercap; /* cached AER ecap offset */
	uint64_t			xive_cache[256 + 8];
	struct p7ioc			*ioc;
	struct phb			phb;
};

static inline struct p7ioc_phb *phb_to_p7ioc_phb(struct phb *phb)
{
	return container_of(phb, struct p7ioc_phb, phb);
}

/*
 * State structure for P7IOC IO HUB
 */
struct p7ioc {
	/* MMIO regs */
	void				*regs;

	/* Main MMIO window from GX for registers & PCI IO space */
	uint64_t			mmio1_win_start;
	uint64_t			mmio1_win_size;

	/* Secondary MMIO window for PCI MMIO space */
	uint64_t			mmio2_win_start;
	uint64_t			mmio2_win_size;

	/* BUID base for the PHB. This does include the top bits
	 * (chip, GX bus ID, etc...). This is initialized from the
	 * SPIRA. It does not contain the offset 0x10 for RGC
	 * interrupts.
	 *
	 * The OPAL-defined "interrupt-base" property will contain
	 * the RGC BUID, not this base value, since this is the real
	 * starting point of interrupts for the IOC and we don't want
	 * to cover the BUID 0..f gap which is reserved for P7 on-chip
	 * interrupt sources.
	 */
	uint32_t			buid_base;
	uint32_t			rgc_buid;

	/* PHB array */
	struct p7ioc_phb		phbs[P7IOC_NUM_PHBS];
	   
	const struct cechub_io_hub	*sp_data;
	struct io_hub			hub;
};

static inline struct p7ioc *iohub_to_p7ioc(struct io_hub *hub)
{
	return container_of(hub, struct p7ioc, hub);
}

extern struct io_hub *p7ioc_create_hub(const struct cechub_io_hub *hub,
				       uint32_t id);
extern int64_t p7ioc_inits(struct p7ioc *ioc);

extern void p7ioc_phb_setup(struct p7ioc *ioc, uint8_t index, bool active);
extern int64_t p7ioc_phb_init(struct p7ioc_phb *p);
extern void p7ioc_phb_add_nodes(struct p7ioc_phb *p);

extern int64_t p7ioc_phb_get_xive(struct p7ioc_phb *p, uint32_t isn,
				  uint16_t *server, uint8_t *prio);
extern int64_t p7ioc_phb_set_xive(struct p7ioc_phb *p, uint32_t isn,
				  uint16_t server, uint8_t prio);


#endif /* __P7IOC_H */
