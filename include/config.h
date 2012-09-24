#ifndef __CONFIG_H
#define __CONFIG_H

#define HAVE_TYPEOF		1

/* Enable lock debugging */
#define DEBUG_LOCKS		1

/* Enable malloc debugging */
#define DEBUG_MALLOC		1

/* Heap size set to 1M for now */
#define HEAP_SIZE		0x100000

/* Boot stack size set to 1M as well */
#define STACK_SIZE		0x100000

/* Enable this for mambo console */
//#define MAMBO_CONSOLE		1

/* Enable this to hookup SkiBoot log to the DVS console */
#define DVS_CONSOLE		1

/* This is the location of our console buffer */
#define INMEM_CON_START		0x30000000UL
#define INMEM_CON_LEN  		0x100000

/* Tell FSP to put the data at 64M, allocate 4M */
#define SPIRA_HEAP_BASE		0x04000000UL
#define SPIRA_HEAP_SIZE		0x00400000

/* PSI TCE table is 16K naturally aligned */
#define PSI_TCE_TABLE_BASE	0x04400000UL
#define PSI_TCE_TABLE_SIZE	0x00004000UL

/* 4*256K areas for serial port buffers */
#define SER0_BUFFER_BASE	0x04500000UL
#define SER0_BUFFER_SIZE	0x00040000UL
#define SER1_BUFFER_BASE	0x04540000UL
#define SER1_BUFFER_SIZE	0x00040000UL
#define SER2_BUFFER_BASE	0x04580000UL
#define SER2_BUFFER_SIZE	0x00040000UL
#define SER3_BUFFER_BASE	0x045c0000UL
#define SER3_BUFFER_SIZE	0x00040000UL

/* 1M area for inbound buffers */
#define FSP_INBOUND_BUFS	0x04600000UL
#define FSP_INBOUND_SIZE	0x00100000UL


#endif /* __CONFIG_H */

