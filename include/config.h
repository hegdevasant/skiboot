/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __CONFIG_H
#define __CONFIG_H

#define HAVE_TYPEOF			1
#define HAVE_BUILTIN_TYPES_COMPATIBLE_P	1

/* Enable lock debugging */
#define DEBUG_LOCKS		1

/* Enable malloc debugging */
#define DEBUG_MALLOC		1

/* Enable OPAL entry point tracing */
//#define OPAL_TRACE_ENTRY	1

/* Enable tracing of event state change */
//#define OPAL_TRACE_EVT_CHG	1

/* Enable various levels of OPAL_console debug */
//#define OPAL_DEBUG_CONSOLE_IO	1
//#define OPAL_DEBUG_CONSOLE_POLL	1

/* Stack size set to 16K, some of it will be used for
 * machine check (see stack.h)
 */
#define STACK_SHIFT		14
#define STACK_SIZE		(1 << STACK_SHIFT)

/* Enable this for mambo console */
//#define MAMBO_CONSOLE		1

/* Enable this to make fast reboot clear memory */
//#define FAST_REBOOT_CLEARS_MEMORY	1

/* Enable this to hookup SkiBoot log to the DVS console */
#define DVS_CONSOLE		1

/* Enable this to do fast resets. Currently unreliable... */
//#define ENABLE_FAST_RESET	1

/* Enable this to disable setting of the output pending event when
 * sending things on the console. The FSP is very slow to consume
 * and older kernels wait after each character during early boot so
 * things get very slow. Eventually, we may want to create an OPAL
 * API for the kernel to activate or deactivate that functionality
 */
#define DISABLE_CON_PENDING_EVT	1

/* This is our main offset for relocation. All our buffers
 * are offset from that and our code relocates itself to
 * that location
 */
#define SKIBOOT_BASE		0x30000000

/* We keep a gap of 4M for skiboot text & bss for now, then
 * we have our heap which goes up to base + 16M (so 12M for
 * now, though we can certainly reduce that a lot)
 */
#define HEAP_BASE		(SKIBOOT_BASE + 0x00400000)
#define HEAP_SIZE		0x00c00000


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
#define SER3_BUFFER_BASE	(SER0_BUFFER_BASE + 3*SER0_BUFFER_SIZE)

/* 1M area for inbound buffers at base + 19M */
#define FSP_INBOUND_BUFS	(SKIBOOT_BASE + 0x01300000)
#define FSP_INBOUND_SIZE	0x00100000UL

/* Tell FSP to put the init data at base + 20M, allocate 4M */
#define SPIRA_HEAP_BASE		(SKIBOOT_BASE + 0x01400000)
#define SPIRA_HEAP_SIZE		0x00400000

/* This is our NVRAM image at base + 24M, it is set to be 1M in size */
#define NVRAM_BASE		(SKIBOOT_BASE + 0x01800000)
#define NVRAM_SIZE		0x00100000

/* Total size of the above area */
#define SKIBOOT_SIZE		0x01900000

/* We start laying out the CPU stacks from here, indexed by PIR
 * each stack is STACK_SIZE in size (naturally aligned power of
 * two) and the bottom of the stack contains the cpu thread
 * structure for the processor, so it can be obtained by a simple
 * bit mask from the stack pointer.
 *
 * The size of this array is dynamically determined at boot time
 */
#define CPU_STACKS_BASE		(SKIBOOT_BASE + SKIBOOT_SIZE)

/* Address at which we load the kernel LID. Currently +1M */
#define KERNEL_LOAD_BASE	0x00100000
#define KERNEL_LOAD_SIZE	0x20000000

/* Hard wired addresses for Stradale kernel */
#define KERNEL_STRADALE_BASE	0x20000000
#define KERNEL_STRADALE_SIZE	0x01000000

/* Size allocated to build the device-tree */
#define	DEVICE_TREE_MAX_SIZE	0x80000

#endif /* __CONFIG_H */

