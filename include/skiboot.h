/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
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
#include <bitutils.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/build_assert/build_assert.h>

#include <op-panel.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

/* Readonly section start and end. */
extern char __rodata_start[], __rodata_end[];

static inline bool is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

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

/* Processor generation */
enum proc_gen {
	proc_gen_unknown,
	proc_gen_p7,		/* P7 and P7+ */
	proc_gen_p8,
};
extern enum proc_gen proc_gen;

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

/* Clean the stray high bit which the FSP inserts: we only have 52 bits real */
static inline u64 cleanup_addr(u64 addr)
{
	return addr & ((1ULL << 52) - 1);
}

/* Start the kernel */
extern void start_kernel(uint64_t entry, void* fdt,
			 uint64_t mem_top) __noreturn;
extern void start_kernel32(uint64_t entry, void* fdt,
			   uint64_t mem_top) __noreturn;
extern void start_kernel_secondary(uint64_t entry) __noreturn;

/* Get description of machine from HDAT and create device-tree */
extern void parse_hdat(bool is_opal, uint32_t master_cpu);

/* Root of device tree. */
extern struct dt_node *dt_root;

/* Generated git id. */
extern const char gitid[];

/* Fast reboot support */
extern void fast_reset(void);
extern void __secondary_cpu_entry(void);
extern void load_and_boot_kernel(bool is_reboot);
extern void cleanup_tlb(void);
extern void init_shared_sprs(void);
extern void init_replicated_sprs(void);

/* Various probe routines, to replace with an initcall system */
extern void probe_p5ioc2(void);
extern void probe_p7ioc(void);
extern void probe_phb3(void);
extern void uart_init(void);
extern void slw_init(void);
extern void occ_init(void);

/* Flatten device-tree */
extern void *create_dtb(const struct dt_node *root);
#endif /* __SKIBOOT_H */

