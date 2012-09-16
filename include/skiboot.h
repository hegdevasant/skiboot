#ifndef __SKIBOOT_H
#define __SKIBOOT_H

#include <stddef.h>

/* Macros for various compiler bits and pieces */
#define __packed		__attribute__((packed))
#define __align(x)		__attribute__((__aligned__(x)))
#define __unused		__attribute__((unused))
#define __section(x)		__attribute__((__section__(x)))

#if 0 /* Provided by gcc stddef.h */
#define offsetof(type,m)	__builtin_offsetof(type,m)
#endif

/* Special ELF sections */
#define __force_data		__section(".force.data")


#endif /* __SKIBOOT_H */

