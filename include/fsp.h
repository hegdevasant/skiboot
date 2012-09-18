
/*
 * IBM System P FSP (Flexible Service Processor)
 *
 * By Sonny Rao, copyright IBM corp 2010
 */
#ifndef __FSP_H
#define __FSP_H

/* Current max number of FSPs
 * one primary and one secondary is all we support
 */
#define FSP_MAX			2

/* Command protocol.
 *
 * Commands have a byte class and a byte subcommand. With the exception
 * of some HMC related commands (class 0xe0) which we don't support,
 * only one outstanding command is allowed for a given class.
 *
 * Note: 0xCE and 0xCF fall into the same class, ie, only one of them can
 *       be outstanding.
 *
 * A command is outstanding until it has been acknowledged. This doesn't
 * imply a response, the response can come later.
 */

/* Protocol status error codes used by the protocol */
#define FSP_STATUS_SUCCESS		0x00	/* Command successful */
#define FSP_STATUS_DATA_INLINE		0x11	/* Data inline in mbox */
#define FSP_STATUS_INVALID_SUBCMD	0x20
#define FSP_STATUS_INVALID_MOD		0x21
#define FSP_STATUS_INVALID_DATA		0x22
#define FSP_STATUS_INVALID_CMD		0x2c
#define FSP_STATUS_SEQ_ERROR		0x2d
#define FSP_STATUS_BAD_STATE		0x2e
#define FSP_STATUS_NOT_SUPPORTED	0x2f
#define FSP_STATUS_GENERIC_ERROR	0xfe

/* System parameter numbers used in the protocol
 *
 * these are the only ones we care about right now
 */
#define SYS_PARAM_SURV			0xf0000001
#define SYS_PARAM_NEED_HMC		0xf0000016

/*
 * FSP registers
 *
 * All of the below register defintions come from the FSP0 "Black Widow" spec
 * They are the same for FSP1 except they are presented big-endian vs
 * little-endian for FSP0 -- which used PCI
 * all regs are 4 bytes wide, and we read the larger data areas in 4 byte
 * granularity as well 
 *
 * there are actually two defined sets of MBX registers
 * MBX2 can't generate interrupts to the host and only MBX1 is currently 
 * used by firmware running on the FSP, so we're mostly ignoring MBX2
 */

/* Device Reset Control Register */
#define FSP_DRCR_REG			0x00

/* Device Immediate Status Register */
#define FSP_DISR_REG			0x08

/* The host version of the control register shares bits with the FSP's
 * control reg. Those bits are defined such that one side can set
 * a bit and the other side can clear it
 */
#define FSP_MBX1_HCTL_REG		0x080
#define FSP_MBX1_FCTL_REG		0x090
#define FSP_MBX2_HCTL_REG		0x0a0
#define FSP_MBX2_FCTL_REG		0x0b0

/* Bits in the control reg */
#define FSP_MBX_CTL_PTS			(1 << 31)
#define FSP_MBX_CTL_ABORT		(1 << 30)
#define FSP_MBX_CTL_SPPEND		(1 << 29)
#define FSP_MBX_CTL_HPEND		(1 << 28)
#define FSP_MBX_CTL_XDN			(1 << 26)
#define FSP_MBX_CTL_XUP			(1 << 25)
#define FSP_MBX_CTL_HCHOST_MASK		(0xf << 20)
#define FSP_MBX_CTL_HCHOST_SHIFT	20
#define FSP_MBX_CTL_DCHOST_MASK		(0xff << 12)
#define FSP_MBX_CTL_DCHOST_SHIFT	12
#define FSP_MBX_CTL_HCSP_MASK		(0xf << 8)
#define FSP_MBX_CTL_HCSP_SHIFT		8
#define FSP_MBX_CTL_DCSP_MASK		(0xff)
#define FSP_MBX_CTL_DCSP_SHIFT		0

/* Three header registers owned by the host */
#define FSP_MBX1_HHDR0_REG		0x84
#define FSP_MBX1_HHDR1_REG		0x88
#define FSP_MBX1_HHDR2_REG		0x8C
#define FSP_MBX2_HHDR0_REG		0xa4
#define FSP_MBX2_HHDR1_REG		0xa8
#define FSP_MBX2_HHDR2_REG		0xaC

/* SP Doorbell Error Status register */
#define FSP_SDES_REG			0xc0
/* Host Doorbell Error Status register */
#define FSP_HDES_REG			0xc4

/* Bit definitions for both SDES and HDES
 *
 * Notes:
 *
 * - CLR: is written to clear the status and always reads
 *   as 0. It can be used to detect an error state (a HB
 *   freeze will return all 1's)
 * - ILLEGAL: illegal operation such as host trying to write
 *   to an FSP only register etc...
 * - WFULL: set if host tried to write to the SP doorbell while
 *   the pending bit is still set
 * - REMPTY: tried to read while host pending bit not set
 * - PAR: SP RAM partity error
 */
#define FSP_DBERRSTAT_ILLEGAL1		(1 << 27)
#define FSP_DBERRSTAT_WFULL1		(1 << 26
#define FSP_DBERRSTAT_REMPTY1		(1 << 25)
#define FSP_DBERRSTAT_PAR1		(1 << 24)
#define FSP_DBERRSTAT_CLR1		(1 << 16)
#define FSP_DBERRSTAT_ILLEGAL2		(1 << 11)
#define FSP_DBERRSTAT_WFULL2		(1 << 10)
#define FSP_DBERRSTAT_REMPTY2		(1 <<  9)
#define FSP_DBERRSTAT_PAR2		(1 <<  8)
#define FSP_DBERRSTAT_CLR2		(1 <<  0)

/* Host Doorbell Interrupt Register and mask
 *
 * Note that while HDIR has bits for MBX2, only
 * MBX1 can actually generate interrupts. Thus only the
 * MBX1 bits are implemented in the mask register.
 */
#define FSP_HDIR_REG			0xc8
#define FSP_HDIM_SET_REG		0xcc
#define FSP_HDIM_CLR_REG		0xd0
#define FSP_DBIRQ_ERROR2		(1 << 10)
#define FSP_DBIRQ_XUP2			(1 <<  9)
#define FSP_DBIRQ_HPEND2		(1 <<  8)
#define FSP_DBIRQ_ERROR1		(1 <<  2)
#define FSP_DBIRQ_XUP1			(1 <<  1)
#define FSP_DBIRQ_HPEND1		(1 <<  0)

/* Doorbell Interrupt Register (FSP internal interrupt latch
 * read-only on host side
 */
#define FSP_PDIR_REG			0xd4
/* And associated mask */
#define FSP_PDIM_SET_REG       		0xd8
#define FSP_PDIM_CLR_REG       		0xdc

/* Bits for the above */
#define FSP_PDIRQ_ABORT2		(1 << 7)
#define FSP_PDIRQ_ABORT1		(1 << 6)
#define FSP_PDIRQ_ERROR2		(1 << 5)
#define FSP_PDIRQ_ERROR1		(1 << 4)
#define FSP_PDIRQ_XDN2			(1 << 3)
#define FSP_PDIRQ_XDN1			(1 << 2)
#define FSP_PDIRQ_SPPEND2		(1 << 1)
#define FSP_PDIRQ_SPPEND1		(1 << 0)

/* FSP owned headers */
#define FSP_MBX1_FHDR0_REG		0x094
#define FSP_MBX1_FHDR1_REG		0x098
#define FSP_MBX1_FHDR2_REG		0x09C
#define FSP_MBX2_FHDR0_REG		0x0b4
#define FSP_MBX2_FHDR1_REG		0x0b8
#define FSP_MBX2_FHDR2_REG		0x0bC

/* Data areas, we can only write to host data, and read from FSP data
 *
 * Each area is 0x140 bytes long
 */
#define FSP_MBX1_HDATA_AREA		0x100
#define FSP_MBX1_FDATA_AREA		0x200
#define FSP_MBX2_HDATA_AREA		0x300
#define FSP_MBX2_FDATA_AREA		0x400

/* These are scratch registers */
#define FSP_SCRATCH0_REG		0xe0
#define FSP_SCRATCH1_REG		0xe4
#define FSP_SCRATCH2_REG		0xe8
#define FSP_SCRATCH3_REG		0xec

/*
 * PSI Host Bridge Registers
 *
 * The PSI interface is the bridge to the FPS, it has its own
 * registers. The FSP registers appeat at an offset within the
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

/* PSI Host Bridge Control Register*/
#define PSIHB_CR			0x20

/* PSI Status / Error Mask Register */
#define PSIHB_SEMR			0x28

/* XIVR and BUID used for PSI interrupts */
#define PSIHB_XIVR			0x30

/* Offset into the FSP MMIO space where the mailbox registers are */
/* seen in the FSP1 spec */
#define FSP1_REG_OFFSET			0xb0016000ULL


/*
 * Functions exposed to the rest of skiboot
 */
extern void fsp_preinit(void);

#endif /* __FSP_H */
