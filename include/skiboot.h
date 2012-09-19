#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <ccan/container_of/container_of.h>
#include <ccan/list/list.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

/* General utilities */
#define prerror(fmt...)	do { fprintf(stderr, fmt); } while(0)


#endif /* __SKIBOOT_H */

