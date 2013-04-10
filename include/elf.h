/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __ELF_H
#define __ELF_H

#include <stdint.h>

/* 64-bit ELF header */
struct elf64_hdr {
	uint32_t ei_ident;
#define ELF_IDENT	0x7F454C46
	uint8_t ei_class;
#define ELF_CLASS_32	1
#define ELF_CLASS_64	2
	uint8_t ei_data;
#define ELF_DATA_LSB	1
#define ELF_DATA_MSB	2
	uint8_t ei_version;
	uint8_t ei_pad[9];
	uint16_t e_type;
	uint16_t e_machine;
#define ELF_MACH_PPC64	0x15
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

/* 64-bit ELF program header */
struct elf64_phdr {
	uint32_t p_type;
#define ELF_PTYPE_LOAD	1
	uint32_t p_flags;
#define ELF_PFLAGS_R	0x4
#define ELF_PFLAGS_W	0x2
#define ELF_PFLAGS_X	0x1
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Some relocation related stuff used in relocate.c */
struct elf64_dyn {
	int64_t	 d_tag;
#define DT_NULL	 	0
#define DT_RELA	 	7
#define DT_RELASZ	8
#define DT_RELAENT	9
#define DT_RELACOUNT	0x6ffffff9
	uint64_t d_val;
};

struct elf64_rela {
	uint64_t	r_offset;
	uint64_t	r_info;
#define ELF64_R_TYPE(info)		((info) & 0xffffffffu)
	int64_t		r_addend;
};

/* relocs we support */
#define R_PPC64_RELATIVE	22



#endif /* __ELF_H */
