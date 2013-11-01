#ifndef __FAPI_SBE_COMMON_H
#define __FAPI_SBE_COMMON_H

// $Id: fapi_sbe_common.H,v 1.1 2012/04/16 23:55:37 bcbrock Exp $
// $Source: /afs/awd/projects/eclipz/KnowledgeBase/.cvsroot/eclipz/chips/p8/working/procedures/fapi_sbe_common.H,v $
//------------------------------------------------------------------------------
// *! (C) Copyright International Business Machines Corp. 2011
// *! All Rights Reserved -- Property of IBM
// *! *** IBM Confidential ***
//------------------------------------------------------------------------------
// *! OWNER NAME  :               Email:

/// \file fapi_sbe_common.H
/// \brief Definitions common to FAPI and SBE procedures
///
/// Several preprocessor macros are required to have different definitions in
/// C, C++ and SBE assembly procedures.  These common forms are collected here.

#if defined __ASSEMBLER__

#define CONST_UINT8_T(name, expr) .set name, (expr)
#define CONST_UINT32_T(name, expr) .set name, (expr)
#define CONST_UINT64_T(name, expr) .set name, (expr)

#define ULL(x) x

#elif defined __cplusplus

#include <stdint.h>

#define CONST_UINT8_T(name, expr) const uint8_t name = (expr);
#define CONST_UINT32_T(name, expr) const uint32_t name = (expr);
#define CONST_UINT64_T(name, expr) const uint64_t name = (expr);

#define ULL(x) x##ull

#else // C code

// CONST_UINT[8,3,64]_T() can't be used in C code/headers; Use 
//
//     #define <symbol> <value> [ or ULL(<value>) for 64-bit constants

#define ULL(x) x##ull

#endif  // __ASSEMBLER__

#endif  // __FAPI_SBE_COMMON_H
