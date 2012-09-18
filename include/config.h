#ifndef __CONFIG_H
#define __CONFIG_H

/* Heap size set to 1M for now */
#define HEAP_SIZE	0x100000

/* Boot stack size set to 1M as well */
#define STACK_SIZE	0x100000

/* Enable this for mambo console */
//#define MAMBO_CONSOLE	1

/* Enable this for in-memory console */
#define INMEM_CONSOLE	1
#define INMEM_CON_START	0x30000000UL
#define INMEM_CON_LEN  	0x100000

/* Tell FSP to put the data at 64M, allocate 4M */
#define SPIRA_HEAP_BASE	0x04000000UL
#define SPIRA_HEAP_SIZE	0x00400000

#define HAVE_TYPEOF 1

#endif /* __CONFIG_H */

