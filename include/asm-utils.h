#ifndef __ASM_UTILS_H
#define __ASM_UTILS_H

/*
 * Do NOT use the immediate load helpers with symbols
 * only with constants. Symbols will _not_ be resolved
 * by the linker since we are building -pie, and will
 * instead generate relocs of a type our little built-in
 * relocator can't handle
 */

/* Load an immediate 64-bit value into a register */
#define LOAD_IMM64(r, e)			\
	lis     r,(e)@highest;			\
	ori     r,r,(e)@higher;			\
	rldicr  r,r, 32, 31;			\
	oris    r,r, (e)@h;			\
	ori     r,r, (e)@l;

/* Load an immediate 32-bit value into a register */
#define LOAD_IMM32(r, e)			\
	lis     r,(e)@h;			\
	ori     r,r,(e)@l;		

/* Load an address via the TOC */
#define LOAD_ADDR_FROM_TOC(r, e)	ld r,e@got(%r2)


#endif /* __ASM_UTILS_H */
