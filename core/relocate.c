#include <stdint.h>
#include <stdbool.h>

/* WARNING: This code is used to self-relocate, it cannot have any
 * global reference nor TOC reference. It's also called before BSS
 * is cleared.
 */

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

/* Note: This code is simplified according to the assumptions
 *       that our link address is 0 and we are running at the
 *       target address already.
 */
int relocate(uint64_t offset, struct elf64_dyn *dyn, struct elf64_rela *rela)
{
	uint64_t dt_rela	= 0;
	uint64_t dt_relacount	= 0;
	unsigned int i;

	/* Look for relocation table */
	for (; dyn->d_tag != DT_NULL; dyn++) {
		if (dyn->d_tag == DT_RELA)
			dt_rela = dyn->d_val;
		else if (dyn->d_tag == DT_RELACOUNT)
			dt_relacount = dyn->d_val;
	}

	/* If we miss either rela or relacount, bail */
	if (!dt_rela || !dt_relacount)
		return false;

	/* Check if the offset is consistent */
	if ((offset + dt_rela) != (uint64_t)rela)
		return false;

	/* Perform relocations */
	for (i = 0; i < dt_relacount; i++, rela++) {
		uint64_t *t;

		if (ELF64_R_TYPE(rela->r_info) != R_PPC64_RELATIVE)
			return false;
		t = (uint64_t *)(rela->r_offset + offset);
		*t = rela->r_addend + offset;
	}

	return true;
}
