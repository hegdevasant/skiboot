
/*
 * IBM System P FSP (Flexible Service Processor)
 */
#ifndef __FSP_H
#define __FSP_H

#include <skiboot.h>

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
#define FSP_DBERRSTAT_WFULL1		(1 << 26)
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
 * Message classes
 */
#define FSP_MCLASS_FIRST		0xce
#define FSP_MCLASS_SERVICE		0xce
#define FSP_MCLASS_IPL			0xcf
#define FSP_MCLASS_PCTRL_MSG		0xd0
#define FSP_MCLASS_PCTRL_ABORTS		0xd1
#define FSP_MCLASS_ERR_LOG		0xd2
#define FSP_MCLASS_CODE_UPDATE		0xd3
#define FSP_MCLASS_FETCH_SPDATA		0xd4
#define FSP_MCLASS_FETCH_HVDATA		0xd5
#define FSP_MCLASS_NVRAM		0xd6
#define FSP_MCLASS_MBOX_SURV		0xd7
#define FSP_MCLASS_RTC			0xd8
#define FSP_MCLASS_SMART_CHIP		0xd9
#define FSP_MCLASS_INDICATOR		0xda
#define FSP_MCLASS_HMC_INTFMSG		0xe0
#define FSP_MCLASS_HMC_VT		0xe1
#define FSP_MCLASS_HMC_BUFFERS		0xe2
#define FSP_MCLASS_SHARK		0xe3
#define FSP_MCLASS_MEMORY_ERR		0xe4
#define FSP_MCLASS_CUOD_EVENT		0xe5
#define FSP_MCLASS_HW_MAINT		0xe6
#define FSP_MCLASS_VIO			0xe7
#define FSP_MCLASS_SRC_MSG		0xe8
#define FSP_MCLASS_DATA_COPY		0xe9
#define FSP_MCLASS_TONE			0xea
#define FSP_MCLASS_VIRTUAL_NVRAM	0xeb
#define FSP_MCLASS_LAST			0xeb

/*
 * Commands are provided in rxxyyzz form where:
 *
 *   -  r is 0: no response or 1: response expected
 *   - xx is class
 *   - yy is subcommand
 *   - zz is mod
 *
 * WARNING: We only set the r bit for HV->FSP commands
 *          long run, we want to remove use of that bit
 *          and instead have a table of all commands in
 *          the FSP driver indicating which ones take a
 *          response...
 */

/*
 * Class 0xCF
 */
#define FSP_CMD_OPL	    	0x0cf7100 /* HV->FSP: Operational Load Compl. */
#define FSP_CMD_HV_STATE_CHG	0x0cf0200 /* FSP->HV: Request HV state change */
#define FSP_RSP_HV_STATE_CHG	0x0cf8200
#define FSP_CMD_SP_NEW_ROLE	0x0cf0700 /* FSP->HV: FSP assuming a new role */
#define FSP_RSP_SP_NEW_ROLE	0x0cf8700
#define FSP_CMD_SP_RELOAD_COMP	0x0cf0102 /* FSP->HV: FSP reload complete */


/*
 * Class 0xCE
 */
#define FSP_CMD_CONTINUE_IPL	0x0ce7000 /* FSP->HV: HV has control */
#define FSP_CMD_CONTINUE_ACK	0x0ce5700 /* HV->FSP: HV acks CONTINUE IPL */
#define FSP_CMD_HV_FUNCTNAL	0x1ce5707 /* HV->FSP: Set HV functional state */
#define FSP_CMD_HV_QUERY_CAPS	0x1ce0400 /* HV->FSP: Query capabilities */
#define FSP_RSP_HV_QUERY_CAPS	0x1ce8400
#define FSP_CMD_SP_QUERY_CAPS	0x0ce0501 /* FSP->HV */
#define FSP_RSP_SP_QUERY_CAPS	0x0ce8500

/*
 * Class 0xD5
 */
#define FSP_CMD_ALLOC_INBOUND	0x0d50400 /* FSP->HV: Allocate inbound buf. */
#define FSP_RSP_ALLOC_INBOUND	0x0d58400

/*
 * Class 0xD7
 */
#define FSP_CMD_SURV_ACK	0x1d70000 /* FSP->HV */

/*
 * Class 0xE0
 *
 * HACK ALERT: We mark E00A01 (associate serial port) as not needing
 * a response. We need to do that because the FSP will send as a result
 * an Open Virtual Serial of the same class *and* expect a reply before
 * it will respond to associate serial port. That breaks our logic of
 * supporting only one cmd/resp outstanding per class.
 */
#define FSP_CMD_HMC_INTF_QUERY	0x0e00100 /* FSP->HV */
#define FSP_RSP_HMC_INTF_QUERY	0x0e08100 /* HV->FSP */
#define FSP_CMD_ASSOC_SERIAL	0x0e00a01 /* HV->FSP: Associate with a port */
#define FSP_RSP_ASSOC_SERIAL	0x0e08a00 /* FSP->HV */
#define FSP_CMD_UNASSOC_SERIAL	0x0e00b01 /* HV->FSP: Deassociate */
#define FSP_RSP_UNASSOC_SERIAL	0x0e08b00 /* FSP->HV */
#define FSP_CMD_OPEN_VSERIAL	0x0e00601 /* FSP->HV: Open serial session */
#define FSP_RSP_OPEN_VSERIAL	0x0e08600 /* HV->FSP */
#define FSP_CMD_CLOSE_VSERIAL	0x0e00701 /* FSP->HV: Close serial session */
#define FSP_RSP_CLOSE_VSERIAL	0x0e08700 /* HV->FSP */

/*
 * Class E1
 */
#define FSP_CMD_VSERIAL_IN	0x0e10100 /* FSP->HV */
#define FSP_CMD_VSERIAL_OUT	0x0e10200 /* HV->FSP */

/*
 * Layout of the PSI DMA address space
 *
 * We instanciate a TCE table of 16K mapping 64M
 *
 * Currently we have:
 *
 *   - 4x256K serial areas (each divided in 2: in and out buffers)
 *   - 1M region for inbound buffers
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


/*
 * Functions exposed to the rest of skiboot
 */

/* An FSP message */

enum fsp_msg_state {
	fsp_msg_unused,
	fsp_msg_queued,
	fsp_msg_sent,
	fsp_msg_wresp,
	fsp_msg_done,
	fsp_msg_timeout,
	fsp_msg_incoming,
};

struct fsp_msg {
	/*
	 * User fields. Don't populate word0.seq (upper 16 bits), this
	 * will be done by fsp_queue_msg()
	 */
	u8			dlen;	/* not including word0/word1 */
	u32			word0;	/* seq << 16 | cmd */
	u32			word1;	/* mod << 8 | sub */
	union {
		u32		words[14];
		u8		bytes[56];
	} data;

	/* Completion function */
	void (*complete)(struct fsp_msg *msg);

	/*
	 * Driver updated fields
	 */

	/* Set if the message expects a response */
	bool			response;

	/* Response will be filed by driver when response received */
	struct fsp_msg		*resp;

	/* Current msg state */
	enum fsp_msg_state	state;

	/* Internal queuing */
	struct list_node	link;
};

extern void fsp_init(void);

/* Allocate and populate an fsp_msg structure
 *
 * WARNING: Do _NOT_ use free() on an fsp_msg, use fsp_freemsg()
 * instead as we will eventually use pre-allocated message pools
 */
extern struct fsp_msg *fsp_allocmsg(void);
extern struct fsp_msg *fsp_mkmsg(u32 cmd_sub_mod, u8 add_words, ...);

/* Free a message
 *
 * WARNING: This will also free an attached response if any
 */
extern void fsp_freemsg(struct fsp_msg *msg);

/* Free a message and not the attached reply */
extern void __fsp_freemsg(struct fsp_msg *msg);

/* Enqueue it in the appropriate FSP queue */
extern int fsp_queue_msg(struct fsp_msg *msg,
			 void (*comp)(struct fsp_msg *msg));

/* Synchronously send a command. If there's a response, the status is
 * returned as a positive number. A negative result means an error
 * sending the message.
 *
 * If autofree is set, the message and the reply (if any) are freed
 * after extracting the status. If not set, you are responsible for
 * freeing both the message and an eventual response
 *
 * NOTE: This will call fsp_queue_msg(msg, NULL), hence clearing the
 * completion field of the message. No synchronous message is expected
 * to utilize asynchronous completions.
 */
extern int fsp_sync_msg(struct fsp_msg *msg, bool autofree);

/* Process FSP mailbox activity */
extern void fsp_poll(void);

/* An FSP client is interested in messages for a given class */
struct fsp_client {
	/* Return true to "own" the message (you can free it) */
	bool	(*message)(u32 cmd_sub_mod, struct fsp_msg *msg);
	struct list_node	link;
};

/* WARNING: command class FSP_MCLASS_IPL is aliased to FSP_MCLASS_SERVICE,
 * thus a client of one will get both types of messages
 */
extern void fsp_register_client(struct fsp_client *client, u8 msgclass);
extern void fsp_unregister_client(struct fsp_client *client, u8 msgclass);

/* FSP TCE map/unmap functions */
extern void fsp_tce_map(u32 offset, void *addr, u32 size);
extern void fsp_tce_unmap(u32 offset, u32 size);

/* FSP console stuff */
extern void fsp_console_preinit(void);
extern void fsp_console_init(void);

#endif /* __FSP_H */
