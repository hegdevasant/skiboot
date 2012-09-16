#ifndef __SPIRA_H
#define __SPIRA_H

#include <hdif.h>

/* The SPIRA structure */

#define SPIRA_VERSION		0x20	/* Like 730 ? */

struct spira_ntuple {
	uint64_t	addr;
	uint16_t	alloc_cnt;
	uint16_t	act_cnt;
	uint32_t	alloc_len;
	uint32_t	act_len;
	uint32_t	tce_off;
	uint64_t	padding;
} __packed;

#define SPIRA_NTUPLES_COUNT	0x17

struct spira_ntuples {
	struct HDIF_array_hdr	array_hdr;
	struct spira_ntuple	sp_subsys;		/* 0x040 */
	struct spira_ntuple	ipl_params;		/* 0x060 */
	struct spira_ntuple	nt_enclosure_vpd;	/* 0x080 */
	struct spira_ntuple	slca;			/* 0x0a0 */
	struct spira_ntuple	backplane_vpd;		/* 0x0c0 */
	struct spira_ntuple	system_vpd;		/* 0x0e0 */
	struct spira_ntuple	chip_tod;		/* 0x100 */
	struct spira_ntuple	proc_init;		/* 0x120 */
	struct spira_ntuple	clock_vpd;		/* 0x140 */
	struct spira_ntuple	anchor_vpd;		/* 0x160 */
	struct spira_ntuple	op_panel_vpd;		/* 0x180 */
	struct spira_ntuple	ext_cache_fru_vpd;	/* 0x1a0 */
	struct spira_ntuple	misc_cec_fru_vpd;	/* 0x1c0 */
	struct spira_ntuple	paca;			/* 0x1e0 */
	struct spira_ntuple	ms_vpd;			/* 0x200 */
	struct spira_ntuple	cec_iohub_fru;		/* 0x220 */
	struct spira_ntuple	cpu_ctrl;		/* 0x240 */
	struct spira_ntuple	mdump_src;		/* 0x260 */
	struct spira_ntuple	mdump_dst;		/* 0x280 */
	struct spira_ntuple	mdump_res;		/* 0x2a0 */
	struct spira_ntuple	heap;			/* 0x2c0 */
	struct spira_ntuple	pcia;			/* 0x2e0 */
	struct spira_ntuple	proc_chip;		/* 0x300 */
};

struct spira {
	struct HDIF_common_hdr	hdr;
	struct HDIF_idata_ptr	ntuples_ptr;
	struct spira_ntuples	ntuples;
	uint8_t			reserved[0x4e0];
} __packed __align(0x100);

struct proc_init_data {
	struct HDIF_common_hdr	hdr;
	struct HDIF_idata_ptr	regs_ptr;
	struct {
		uint64_t	nia;
		uint64_t	msr;
	} regs;
} __packed __align(0x10);


#endif /* __SPIRA_H */
