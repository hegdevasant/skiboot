#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <compiler.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/* Special ELF sections */
#define __force_data		__section(".force.data")

/* General utilities */
#define prerror(fmt...)	do { fprintf(stderr, fmt); } while(0)


#endif /* __SKIBOOT_H */

