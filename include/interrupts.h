#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#include <stdint.h>

/*
 * Note about interrupt numbers
 * ============================
 *
 * The form of an interrupt number in the system on P7/P7+ is as follow:
 *
 * |  Node  | T| Chip|GX|           BUID           |   Level   |
 * |--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|--|
 *
 * Where:
 *
 *  - Node   : The 3-bit node number
 *  - T      : 1 for a Torrent chip, 0 otherwise
 *  - Chip   : 2-bit chip number in a node
 *  - GX     : GX bus identifier
 *  - BUID   : Bus identifier (*)
 *  - Level  : Interrupt number
 *
 * (*) The BUID/Level distinction is mostly historial, interrupt
 *     controllers such as the ICS in the PHBs "use" some of the
 *     low BUID bits as an extension to the interrupt number
 *
 * The NodeID and ChipID together form a 5-bit Processor Chip ID as
 * found in the PIR or in the SPIRA data structures (without the T bit)
 *
 * PSI interrupt numbering scheme:
 * -------------------------------
 *
 * This is tentatively deduced from stuff I found in some SCOM regs
 * and in the BookIV. The PSIHB can be used to specify the 9-bit BUID,
 * the Level is always 0. The doc also says that it prepends the 6-bit
 * PowerBus chipID (Node + T + Chip). I *assume* that it also prepends
 * a 0 in place of the GX bit.
 *
 * OPAL seems to be arbitrarily using a BUID value of 0x3, I shall do
 * the same "just in case" :-)
 *
 * NOTE: From grep'ing around the giant SCOM file for "Build", I found
 *       what looks like a register in the GX controller (Mode1
 *       register) where the PSI BUID can be stored as well. From
 *       looking around with the FSP getscom command, it appears
 *       that both pHyp and OPAL set this consistently to the same
 *       value that appears in the PHB configuration.
 *
 * PCI interrupt numbering scheme:
 * -------------------------------
 *
 * TBD
 *
 * NX interrupt numbering scheme (p7+):
 * ------------------------------------
 *
 * TBD
 *
 * 
 * Additional note about routing of interrupts in P7 and P7+
 * =========================================================
 *
 * There are two on-chip sources of interrupts on these that need a
 * special treatment: The PSI interrupt and the NX interrupts.
 *
 * The problem is that they use the same BUID space as the IO chips
 * connected to the GX bus, so the GX controller needs to be told
 * about these BUIDs in order to avoid forwarding them down the GX
 * link (and possibly choking due to the lack of reply).
 *
 * The bad news is that it's all undocumented. The good news is that
 * I found the info after chatting with Bill Daly (HW design) and
 * looking at the SCOM register maps.
 *
 * The way to set that up differs between P7 and P7+:
 *
 * - On P7, it's in the GX_MODE1 register at SCOM 0x0201180A, which
 *   among other things, contains those bits:
 *
 *     18:26 PSI_BUID: BUID to be used to indicate the interrupt is
 *                     for the PSI
 *        27 DISABLE_PSI_BUID: set to 1 to disable the buid reservation
 *                             for PSI
 *
 *   So one must write the 9-bit BUID (without the top chipID) of the
 *   PSI interrupt in there and clear the disable bit.
 *
 * - On P7+ it's in the GX_MODE4 register at SCOM 0x02011811
 *
 *         0 ENABLE_NX_BUID: set to 1 to enable the buid reservation for nx
 *       1:9 NX_BUID_BASE: BUID BASE to be used to indicate the interrupt
 *                         is for the nx
 *     10:18 NX_BUID_MASK: BUID mask for the nx buid base
 *     19:27 PSI_BUID: BUID to be used to indicate the interrupt is for
 *                     the PSI
 *        28 DISABLE_PSI_BUID: set to 1 to disable the buid reservation
 *                             for PSI
 *
 * Note: The NX_BUID_MASK should have bits set to 1 that are relevant for
 *       the comparison to NX_BUID_BASE, ie 4 interrupts means a mask
 *       value of b'111111100
 *
 */
#define PSI_IRQ_BUID	0x3	/* 9-bit BUID for the PSI interrupts */

/* Extract individual components of an IRQ number */
#define IRQ_BUID(irq)	(((irq) >>  4) & 0x1ff)
#define IRQ_GXID(irq)	(((irq) >> 13) & 0x1)
#define IRQ_CHIP(irq)	(((irq) >> 14) & 0x3)
#define IRQ_TBIT(irq)	(((irq) >> 16) & 0x1)
#define IRQ_NODE(irq)	(((irq) >> 17) & 0x7)

/* Extract the "full BUID" (extension + BUID) */
#define IRQ_FBUID(irq)	(((irq) >> 4) & 0xffff)

/* BUID Extension (GX + CHIP + T + NODE) */
#define IRQ_BEXT(irq)	(((irq) >> 13) & 0x7f)

/* Strip extension from BUID */
#define BUID_BASE(buid)	((buid) & 0x1ff)

extern uint32_t get_psi_interrupt(uint32_t chip_id);

extern void add_icp_nodes(void);
extern void add_ics_node(void);
extern void add_opal_interrupts(void);
extern uint32_t get_ics_phandle(void);

extern void reset_cpu_icp(void);
extern void icp_send_eoi(uint32_t interrupt);

#endif /* __INTERRUPTS_H */
