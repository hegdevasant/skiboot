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

/* General utilities */
#define prerror(fmt...)	do { fprintf(stderr, fmt); } while(0)

/* Location codes */
#define LOC_CODE_SIZE	128

enum ipl_state {
	ipl_initial		= 0x00000000,
	ipl_opl_sent		= 0x00000001,
	ipl_got_continue	= 0x00000002,
	ipl_got_new_role	= 0x00000004,
	ipl_got_caps		= 0x00000008
};
extern enum ipl_state ipl_state;

/* For use by debug code */
extern void backtrace(void);

/* Convert a 4-bit number to a hex char */
extern char tohex(uint8_t nibble);

#endif /* __SKIBOOT_H */

