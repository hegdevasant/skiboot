/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __BITUTILS_H
#define __BITUTILS_H

/* PPC bit number conversion */
#ifdef __ASSEMBLY__
#define PPC_BIT(bit)		(0x8000000000000000 >> (bit))
#define PPC_BIT32(bit)		(0x80000000 >> (bit))
#else
#define PPC_BIT(bit)		(0x8000000000000000UL >> (bit))
#define PPC_BIT32(bit)		(0x80000000UL >> (bit))
#endif
#define PPC_BITMASK(bs,be)	((PPC_BIT(bs) - PPC_BIT(be)) | PPC_BIT(bs))
#define PPC_BITMASK32(bs,be)	((PPC_BIT32(bs) - PPC_BIT32(be))|PPC_BIT32(bs))
#define PPC_BITLSHIFT(be)	(63 - (be))
#define PPC_BITLSHIFT32(be)	(31 - (be))

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
