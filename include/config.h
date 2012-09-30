#ifndef __CONFIG_H
#define __CONFIG_H

#define HAVE_TYPEOF		1

/* Enable lock debugging */
#define DEBUG_LOCKS		1

/* Enable malloc debugging */
#define DEBUG_MALLOC		1

/* Enable OPAL entry point tracing */
#define OPAL_TRACE_ENTRY	1

/* Boot stack size set to 64K as well */
#define STACK_SIZE		0x10000

/* Enable this for mambo console */
//#define MAMBO_CONSOLE		1

/* Enable this to hookup SkiBoot log to the DVS console */
#define DVS_CONSOLE		1

/* This is our main offset for relocation. All our buffers
 * are offset from that and our code relocates itself to
 * that location
 */
#define SKIBOOT_BASE		0x30000000

/* This is the location of our console buffer at base + 16M */
#define INMEM_CON_START		(SKIBOOT_BASE + 0x01000000)
#define INMEM_CON_LEN  		0x100000

/* PSI TCE table is 16K naturally aligned at base + 17M */
#define PSI_TCE_TABLE_BASE	(SKIBOOT_BASE + 0x01100000)
#define PSI_TCE_TABLE_SIZE	0x00004000UL

/* 4*256K areas for serial port buffers at base + 18M */
#define SER0_BUFFER_BASE	(SKIBOOT_BASE + 0x01200000)
#define SER0_BUFFER_SIZE	0x00040000UL
#define SER1_BUFFER_BASE	(SER0_BUFFER_BASE + 1*SER0_BUFFER_SIZE)
#define SER2_BUFFER_BASE	(SER0_BUFFER_BASE + 2*SER0_BUFFER_SIZE)
#define SER3_BUFFER_BASE	(SER0_BUFFER_BASE + 2*SER0_BUFFER_SIZE)

/* 1M area for inbound buffers at base + 19M */
#define FSP_INBOUND_BUFS	(SKIBOOT_BASE + 0x01300000)
#define FSP_INBOUND_SIZE	0x00100000UL

/* Tell FSP to put the init data at base + 20M, allocate 4M */
#define SPIRA_HEAP_BASE		(SKIBOOT_BASE + 0x01400000)
#define SPIRA_HEAP_SIZE		0x00400000

/* This is our heap at base + 24M, the max size is set to be 16M */
#define HEAP_BASE		(SKIBOOT_BASE + 0x01800000)
#define HEAP_SIZE		0x01000000

/* This is our total size, currenly 40M XXX we can reduce that a lot ! */
#define SKIBOOT_SIZE		0x28000000

#endif /* __CONFIG_H */

