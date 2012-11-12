#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>

#include <op-panel.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

/* General utilities */
#define prerror(fmt...)	do { fprintf(stderr, fmt); } while(0)

/* Location codes */
#define LOC_CODE_SIZE	128

enum ipl_state {
	ipl_initial		= 0x00000000,
	ipl_opl_sent		= 0x00000001,
	ipl_got_continue	= 0x00000002,
	ipl_got_new_role	= 0x00000004,
	ipl_got_caps		= 0x00000008,
	ipl_got_fsp_functional	= 0x00000010
};
extern enum ipl_state ipl_state;

/* Set to true if CEC booted from the T side, else false,
 * can be used to get to the right LIDs
 */
extern bool cec_ipl_temp_side;

/* Boot stack top */
extern void *boot_stack_top;

/* For use by debug code */
extern void backtrace(void);

/* Convert a 4-bit number to a hex char */
extern char tohex(uint8_t nibble);

/* Bit position of the most significant 1-bit (LSB=0, MSB=63) */
static inline int ilog2(unsigned long val)
{
	int left_zeros;

	asm volatile ("cntlzd %0,%1" : "=r" (left_zeros) : "r" (val));

	return 63 - left_zeros;
}

static inline bool is_pow2(unsigned long val)
{
	return val == (1ul << ilog2(val));
}

#define lo32(x)	((x) & 0xffffffff)
#define hi32(x)	(((x) >> 32) & 0xffffffff)

/* Start the kernel */
extern void start_kernel(uint64_t entry, void* fdt,
			 uint64_t mem_top) __noreturn;
extern void start_kernel_secondary(uint64_t entry) __noreturn;

/* Get description of machine (eg. from paca).  Initializes dt_root. */
extern void parse_machine(uint64_t *mem_top);

/* Root of device tree. */
extern struct dt_node *dt_root;

/* Fast reboot support */
extern void fast_reset(void);
extern void __secondary_cpu_entry(void);
extern void load_and_boot_kernel(bool is_reboot);
extern void cleanup_tlb(void);
extern void init_shared_sprs(void);
extern void init_replicated_sprs(void);

#endif /* __SKIBOOT_H */

