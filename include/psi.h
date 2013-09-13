/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */

/*
 * IBM System P PSI (Processor Service Interface)
 */
#ifndef __PSI_H
#define __PSI_H

#include <skiboot.h>

/*
 * PSI Host Bridge Registers
 *
 * The PSI interface is the bridge to the FPS, it has its own
 * registers. The FSP registers appear at an offset within the
 * aperture defined by the PSI_FSPBAR
 */
/* Base address of the PSI MMIO space and LSB is the enable/valid bit */
#define PSIHB_BBAR			0x00

/* FSP MMIO region -- this is where the mbx regs are (offset defined below) */
#define PSIHB_FSPBAR			0x08

/* FSP MMIO region mask register -- determines size of region */
#define PSIHB_FSPMMR			0x10

/* TCE address register */
#define PSIHB_TAR			0x18
#define  PSIHB_TAR_8K_ENTRIES		0
#define  PSIHB_TAR_16K_ENTRIES		1
#define  PSIHB_TAR_256K_ENTRIES		2 /* P8 only */
#define  PSIHB_TAR_512K_ENTRIES		4 /* P8 only */

/* PSI Host Bridge Control Register
 *
 * note: TCE_ENABLE moved to the new PSIHB_PHBSCR on P8 but is
 * the same bit position
 */
#define PSIHB_CR			0x20
#define   PSIHB_CR_FSP_CMD_ENABLE	PPC_BIT(0)
#define   PSIHB_CR_FSP_MMIO_ENABLE	PPC_BIT(1)
#define   PSIHB_CR_TCE_ENABLE		PPC_BIT(2)	/* P7 only */
#define   PSIHB_CR_FSP_IRQ_ENABLE	PPC_BIT(3)
#define   PSIHB_CR_FSP_ERR_RSP_ENABLE	PPC_BIT(4)
#define   PSIHB_CR_PSI_LINK_ENABLE	PPC_BIT(5)
#define   PSIHB_CR_FSP_RESET		PPC_BIT(6)
#define   PSIHB_CR_PSIHB_RESET		PPC_BIT(7)
#define   PSIHB_CR_PSI_IRQ		PPC_BIT(16)	/* PSIHB interrupt */
#define   PSIHB_CR_FSP_IRQ		PPC_BIT(17)	/* FSP interrupt */
#define   PSIHB_CR_FSP_LINK_ACTIVE	PPC_BIT(18)	/* FSP link active */

/* PSI Status / Error Mask Register */
#define PSIHB_SEMR			0x28

/* XIVR and BUID used for PSI interrupts on P7 */
#define PSIHB_XIVR			0x30

/* XIVR and BUID used for PSI interrupts on P8 */
#define PSIHB_XIVR_FSP			0x30
#define PSIHB_XIVR_OCC			0x60
#define PSIHB_XIVR_FSI			0x68
#define PSIHB_XIVR_LPC			0x70
#define PSIHB_XIVR_LOCAL_ERR		0x78
#define PSIHB_XIVR_HOST_ERR		0x80
#define PSIHB_IRQ_SRC_COMP		0x88

#define PSIHB_IRQ_STATUS		0x58
#define   PSIHB_IRQ_STAT_OCC		PPC_BIT(27)
#define   PSIHB_IRQ_STAT_FSI		PPC_BIT(28)
#define   PSIHB_IRQ_STAT_LPC		PPC_BIT(29)
#define   PSIHB_IRQ_STAT_LOCAL_ERR	PPC_BIT(30)
#define   PSIHB_IRQ_STAT_HOST_ERR	PPC_BIT(31)

/* Secure version of CR for P8 (TCE enable bit) */
#define PSIHB_PHBSCR			0x90

/*
 * Layout of the PSI DMA address space
 *
 * We instanciate a TCE table of 16K mapping 64M
 *
 * Currently we have:
 *
 *   - 4x256K serial areas (each divided in 2: in and out buffers)
 *   - 1M region for inbound buffers
 *   - 2M region for generic data fetches
 */
/*
 * Layout of the PSI DMA address space
 *
 * We instanciate a TCE table of 16K mapping 64M
 *
 * Currently we have:
 *
 *   - 4x256K serial areas (each divided in 2: in and out buffers)
 *   - 1M region for inbound buffers
 *   - 2M region for generic data fetches
 */
#define PSI_DMA_SER0_BASE	0x00000000
#define PSI_DMA_SER0_SIZE	0x00040000
#define PSI_DMA_SER1_BASE	0x00040000
#define PSI_DMA_SER1_SIZE	0x00040000
#define PSI_DMA_SER2_BASE	0x00080000
#define PSI_DMA_SER2_SIZE	0x00040000
#define PSI_DMA_SER3_BASE	0x000c0000
#define PSI_DMA_SER3_SIZE	0x00040000
#define PSI_DMA_INBOUND_BUF	0x00100000
#define PSI_DMA_INBOUND_SIZE	0x00100000
#define PSI_DMA_FETCH		0x00200000
#define PSI_DMA_FETCH_SIZE	0x00800000
#define PSI_DMA_NVRAM_BODY	0x00a00000
#define PSI_DMA_NVRAM_BODY_SZ	0x00100000
#define PSI_DMA_NVRAM_TRIPL	0x00b00000
#define PSI_DMA_NVRAM_TRIPL_SZ	0x00001000
#define PSI_DMA_OP_PANEL_MISC	0x00b01000
#define PSI_DMA_OP_PANEL_SIZE	0x00001000
#define PSI_DMA_SYSPARAM	0x00b02000
#define PSI_DMA_SYSPARAM_SIZE	0x00002000

struct psi {
	struct psi		*link;
	void			*gxhb_regs;
	unsigned int		chip_id;
	unsigned int		interrupt;
	bool			working;
	bool			active;
};

extern struct psi *first_psi;
extern void psi_init(void);
extern struct psi *psi_find_link(void *addr);

/* Interrupts */
extern void psi_irq_reset(void);
extern void psi_enable_fsp_interrupt(struct psi *psi);

#endif /* __PSI_H */
