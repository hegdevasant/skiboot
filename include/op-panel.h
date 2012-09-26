#ifndef __OP_PANEL_H
#define __OP_PANEL_H

#include <stdint.h>

/* Severity */
enum op_severity {
	OP_LOG		= 0x4341,	/* 'CA' - Progress info */
	OP_WARN		= 0x4541,	/* 'EA' - Information condition */
	OP_ERROR	= 0x4441,	/* 'DA' - Non fatal error */
	OP_FATAL	= 0x4241,	/* 'BA' - Fatal error */
};

/* Module */
enum op_module {
	OP_MOD_CORE	= 0x3030,	/* '00' - Anything really */
	OP_MOD_INIT	= 0x3031,	/* '01' - init */
	OP_MOD_LOCK	= 0x3032,	/* '02' - spinlocks */
	OP_MOD_FSP	= 0x3033,	/* '03' - FSP */
	OP_MOD_FSPCON	= 0x3034,	/* '04' - FSPCON */
	OP_MOD_CHIPTOD	= 0x3035,	/* '05' - ChipTOP */
	OP_MOD_CPU	= 0x3036,	/* '06' - CPU bringup */
	OP_MOD_MEM	= 0x3037,	/* '07' - Memory */
	OP_MOD_XSCOM	= 0x3038,	/* '08' - XSCOM */
};

/* Common codes:
 *
 * 'BA010000' : Locking already owned lock
 * 'BA010001' : Unlocking unlocked lock
 * 'BA010002' : Unlocking not-owned lock
 * 'BA006666' : Abort
 * 'BA050000' : Failed ChipTOD init/sync
 * 'BA050001' : Failed to find a CPU on the master chip
 * 'BA050002' : Master chip sync failed
 * 'EA05xxx2' : Slave sync failed (xxx = PIR)
 * 'BA060000' : Invalid SPPACA
 * 'BA060001' : Failed to allocate CPU array
 * 'BA060002' : Bad (or not found) CPU timebase data
 * 'BA060003' : Bad (or not found) CPU id data
 * 'BA060004' : Primary CPU marked unavailable
 * 'BA060005' : Bad (or not found) CPU cache data
 * 'BA070000' : Cannot find MS VPD or invalid
 * 'BA070001' : MS VPD wrong size
 * 'BA070002' : MS VPD doesn't have an MSAC
 * 'BA070003' : MS VPD doesn't have a total config
 * 'BA080000' : Cannot find MS VPD or invalid
 * 'EA080001' : Absent or bad PMBS in MS VPD, using default base
 * 'EA080002' : No XSCOM base in PMBS, using default
 */

extern void op_display(enum op_severity, enum op_module, uint16_t code);

#endif /* __OP_PANEL_H */
