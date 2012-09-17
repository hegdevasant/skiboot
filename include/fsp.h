
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
#define FSP_MAX		(2)

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
#define FSP_STATUS_SUCCESS         (0x00)	/* Command successful */
#define FSP_STATUS_DATA_INLINE     (0x11)	/* Data inline in mbox */
#define FSP_STATUS_INVALID_SUBCMD  (0x20)
#define FSP_STATUS_INVALID_MOD     (0x21)
#define FSP_STATUS_INVALID_DATA    (0x22)
#define FSP_STATUS_INVALID_CMD     (0x2C)
#define FSP_STATUS_SEQ_ERROR       (0x2D)
#define FSP_STATUS_BAD_STATE       (0x2E)
#define FSP_STATUS_NOT_SUPPORTED   (0x2F)
#define FSP_STATUS_GENERIC_ERROR   (0xFE)

/* System parameter numbers used in the protocol
 *
 * these are the only ones we care about right now
 */
#define SYS_PARAM_SURV     (0xF0000001)
#define SYS_PARAM_NEED_HMC (0xF0000016)

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
 *
 * The host version of the control register shares bits with the FSP's
 * control reg. Those bits are defined such that one side can set
 * a bit and the other side can clear it
 */
#define FSP_MBX1_HCTL_REG	(0x080)

/* Bits in the control reg */
#define FSP_MBX_CTL_PERM    (1 << 31)
#define FSP_MBX_CTL_ABORT   (1 << 30)
#define FSP_MBX_CTL_SPPEND  (1 << 29)
#define FSP_MBX_CTL_HPEND   (1 << 28)
#define FSP_MBX_CTL_XDN     (1 << 26)
#define FSP_MBX_CTL_XUP     (1 << 25)

/* Three header registers owned by the host */
#define FSP_MBX1_HHDR0_REG	(0x084)
#define FSP_MBX1_HHDR1_REG	(0x088)
#define FSP_MBX1_HHDR2_REG	(0x08C)

/* Doorbell interrupt register and mask */
#define FSP_MBX1_DBEL_IREG	(0x0C8)
#define FSP_MBX1_DBEL_IREG_MASK	(0x0CC)

/* Bits in the interrupt register */
#define FSP_MBX1_IREG_ERR     (1 << 2)
#define FSP_MBX1_IREG_XUP     (1 << 1)
#define FSP_MBX1_IREG_HPEND   (1 << 0)

/* FSP owned headers */
#define FSP_MBX1_FHDR0_REG         (0x094)
#define FSP_MBX1_FHDR1_REG         (0x098)
#define FSP_MBX1_FHDR2_REG         (0x09C)

/* Data areas, we can only write to host data, and read from FSP data
 *
 * Each area is 0x140 bytes long
 */
#define FSP_MBX1_HDATA		(0x100)
#define FSP_MBX1_FDATA		(0x200)

/* Common registers shared between host and FSP */

/* This register describes a number of possible error states */
#define FPS_MBX_HERROR_REG	(0x0C4)

/* bits 31:28 should always be 0, I'll pick one of them to check  */
/* for a host bridge freeze -- in which case all MMIO reads will */
/* return all 1s */
#define HERROR_MBX1_RESERVED0          (1 << 0)

/* Example: host attempted write to 0x200-0x23F */
#define HERROR_MBX1_ILLEGAL_OPER       (1 << 27)

/* Write to SP doorbell while SP pending still set */
#define HERROR_MBX1_WRITE_FULL_HOST    (1 << 26)

/* read from host doorbell with host pending not set */
#define HERROR_MBX1_READ_EMPTY         (1 << 25)

/* Internal FSP RAM parity error */
#define HERROR_MBX1_SP_RAM_PARITY      (1 << 24)

/* 23:17 Word Address of Last FSP RAM Parity error */
#define HERROR_SP_PARITY_ADDR_MASK(val)  (((val) & 0xFE0000) >> 17)

/* If set on write, will clear other bits 27:17 */
#define HERROR_MBX1_CLEAR_STATUS       (1 << 16)

/* These are scratch registers
 * note IIRC these are shared between MBX1 and MBX2
 * since we're using MBX1 only, probably doesn't matter
 */
#define FSP_MBX_SCRATCH0           (0x0E0)
#define FSP_MBX_SCRATCH1           (0x0E4)
#define FSP_MBX_SCRATCH2           (0x0E8)
#define FSP_MBX_SCRATCH3           (0x0EC)

/*
 * PSI Host Bridge Registers
 *
 * The PSI interface is the bridge to the FPS, it has its own
 * registers. The FSP registers appeat at an offset within the
 * aperture defined by the PSI_FSPBAR
 */
/* Base address of the PSI MMIO space and LSB is the enable/valid bit */
#define PSIHB_BBAR    (0x00)

/* FSP MMIO region -- this is where the mbx regs are (offset defined below) */
#define PSIHB_FSPBAR  (0x08)

/* FSP MMIO region mask register -- determines size of region */
#define PSIHB_FSPMMR  (0x10)

/* TCE address register */
#define PSIHB_TAR     (0x18)

/* PSI Host Bridge Control Register*/
#define PSIHB_CR      (0x20)

/* PSI Status / Error Mask Register */
#define PSIHB_SEMR    (0x28)

/* XIVR and BUID used for PSI interrupts */
#define PSIHB_XIVR    (0x30)

/* Offset into the FSP MMIO space where the mailbox registers are */
/* seen in the FSP1 spec */
#define FSP1_MBX_REG_OFFSET (0xB0016000ULL)


/*
 * Functions exposed to the rest of skiboot
 */
extern void fsp_preinit(void);

#endif /* __FSP_H */
