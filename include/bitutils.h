#ifndef __BITUTILS_H
#define __BITUTILS_H

/* PPC bit number conversion */
#ifdef __ASSEMBLY__
#define PPC_BIT(bit)		(0x8000000000000000 >> (bit))
#else
#define PPC_BIT(bit)		(0x8000000000000000UL >> (bit))
#endif
#define PPC_BITMASK(bs,be)	((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))
#define PPC_BITLSHIFT(be)	(63 - (be))

/*
 * PPC bitmask field manipulation
 */

/* Extract field fname from val */
#define GETFIELD(fname, val)			\
	(((val) & fname##_MASK) >> fname##_LSH)

/* Set field fname of oval to fval
 * NOTE: oval isn't modified, the combined result is returned
 */
#define SETFIELD(fname, oval, fval)			\
	(((oval) & ~fname##_MASK) | \
	 ((((typeof(oval))(fval)) << fname##_LSH) & fname##_MASK))

#endif /* __BITUTILS_H */
