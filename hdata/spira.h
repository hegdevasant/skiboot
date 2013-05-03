/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __SPIRA_H
#define __SPIRA_H

#include "hdif.h"

/*
 * The SPIRA structure
 *
 * NOTE: This is one of the only HDIF structure that we layout entirely
 * as a C struct because it's provided by us to the FSP. Almost everything
 * else is generated by the FSP, and thus must be "parsed" since the various
 * offsets and alignments might change.
 */

#define SPIRA_VERSION		0x20	/* Like 730 ? */

struct spira_ntuple {
	void		*addr;
	u16		alloc_cnt;
	u16		act_cnt;
	u32		alloc_len;
	u32		act_len;
	u32		tce_off;
	u64		padding;
} __packed;

#define SPIRA_NTUPLES_COUNT	0x17

struct spira_ntuples {
	struct HDIF_array_hdr	array_hdr;
	struct spira_ntuple	sp_subsys;		/* 0x040 */
	struct spira_ntuple	ipl_parms;		/* 0x060 */
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
	u64			pad;
	struct spira_ntuples	ntuples;
	u8			reserved[0x4e0];
} __packed __align(0x100);

extern struct spira spira;

/* This macro can be used to check the validity of a pointer returned
 * by one of the HDIF API functions. It returns true if the pointer
 * appears valid. If it's not valid and not NULL, it will print some
 * error in the log as well.
 */
#define CHECK_SPPTR(_ptr)	spira_check_ptr(_ptr, __FILE__, __LINE__)

#define get_hdif(ntuple, id) __get_hdif((ntuple), (id), __FILE__, __LINE__)

extern struct HDIF_common_hdr *__get_hdif(struct spira_ntuple *n,
					  const char id[],
					  const char *file, int line);

#define for_each_ntuple_idx(_ntuples, _p, _idx, _id)			\
	for (_p = get_hdif((_ntuples), _id ""), _idx = 0;		\
	     _p && _idx < (_ntuples)->act_cnt;				\
	     _p = (void *)_p + (_ntuples)->alloc_len, _idx++)

#define for_each_ntuple(_ntuples, _p, _id)				\
	for (_p = get_hdif((_ntuples), _id "");				\
	     _p && (void *)_p < (_ntuples)->addr			\
		     + ((_ntuples)->act_cnt * (_ntuples)->alloc_len);	\
	     _p = (void *)_p + (_ntuples)->alloc_len)


extern bool spira_check_ptr(const void *ptr, const char *file,
			    unsigned int line);

struct proc_init_data {
	struct HDIF_common_hdr	hdr;
	struct HDIF_idata_ptr	regs_ptr;
	struct {
		u64	nia;
		u64	msr;
	} regs;
} __packed __align(0x10);

/*
 * The FRU ID structure is used in several tuples, so we
 * define it generically here
 */
struct spira_fru_id {
	uint16_t	slca_index;
	uint16_t	rsrc_id;	/* formerly VPD port number */
};

/*
 * The FRU operational status structure is used in several
 * tuples, so we define it generically here
 */
struct spira_fru_op_status {
	uint8_t	flags;
#define FRU_OP_STATUS_FLAG_USED		0x02 /* If 0 -> not used (redundant) */
#define FRU_OP_STATUS_FLAG_FUNCTIONAL	0x01 /* If 0 -> non-functional */
	uint8_t	reserved[3];
};

/*
 * Move VPD related stuff to another file ...
 */
#define VPD_ID(_a, _b)	((_a) << 8 | (_b))

/*
 * Service Processor Subsystem Structure
 *
 * This structure contains several internal data blocks
 * describing the service processor(s) in the system
 */

#define SPSS_HDIF_SIG	"SPINFO"

/* Idata index 0 : FRU ID Data */
#define SPSS_IDATA_FRU_ID	0

/* Idata index 1 : Keyword VPD for the FSP instance */
#define SPSS_IDATA_KEYWORD_VPD	1

/* Idata index 2 : SP Implementation */
#define SPSS_IDATA_SP_IMPL	2

struct spss_sp_impl {
	u16	hw_version;
	u16	sw_version;
	u16	func_flags;
#define SPSS_SP_IMPL_FLAGS_INSTALLED	0x8000
#define SPSS_SP_IMPL_FLAGS_FUNCTIONAL	0x4000
#define SPSS_SP_IMPL_FLAGS_PRIMARY	0x2000
	u8	chip_version;
	u8	reserved;
};

/* Idata index 3 is deprecated */

/* Idata index 4 : SP Memory Locator */
#define SPSS_IDATA_SP_MEMLOC	4

/* Idata index 5 : SP I/O path array */
#define SPSS_IDATA_SP_IOPATH	5

/* An HDIF array of IO path */
struct spss_iopath {
	u16	iopath_type;
#define SPSS_IOPATH_TYPE_IOHUB_PHB	0x0001
#define SPSS_IOPATH_TYPE_PSI		0x0002
	union {
		struct {
			u16	iohub_chip_inst;
			u16	iohub_chip_port;
			u16	phb_id;
		} __packed iohub_phb;

		struct {
			u16	link_status;
#define SPSS_IO_PATH_PSI_LINK_BAD_FRU	0x0000
#define SPSS_IO_PATH_PSI_LINK_CURRENT	0x0001
#define SPSS_IO_PATH_PSI_LINK_BACKUP	0x0002
			u8	ml2_version;
			u8	reserved;
			u16	slca_count;
			u8	slca_idx[16];
			u32	proc_chip_id;
			u32	reserved2;
			u64	gxhb_base;
		} __packed psi;
	};
} __packed;

/*
 * IPL Parms structure
 *
 */

/* Idata index 0: System Parameters */
#define IPLPARAMS_SYSPARAMS	0

struct iplparams_sysparams {
	char		sys_model[4];
	char		cpu_feature_code[4];
	uint32_t	effective_pvr;
	uint32_t	system_type;
	uint8_t		num_lpar_oct[8];
	uint32_t	abc_bus_speed;
	uint32_t	wxyz_bus_speed;
	uint32_t	sys_eco_mode;
	uint32_t	sys_attributes;
	uint32_t	mem_scrubbing;
	uint16_t	cur_spl_value;
	uint8_t		pump_mode;
	uint8_t		use_pore_sleep;
	uint32_t	pore_image_size;
} __packed;

/* Idata index 1: IPL parameters */
#define IPLPARAMS_IPLPARAMS	1

struct iplparams_iplparams {
	uint8_t		reserved;
	uint8_t		hv_ipl_dest;
	uint8_t		ipl_side;
#define IPLPARAMS_CEC_FW_IPL_SIDE_TEMP	0x10
#define IPLPARAMS_FSP_FW_IPL_SIDE_TEMP	0x01
	uint8_t		ipl_speed;
	uint16_t	cec_ipl_attrib;
	uint8_t		cec_ipl_maj_type;
	uint8_t		cec_ipl_min_type;
	uint8_t		os_ipl_mode;
	uint8_t		keylock_pos;
	uint8_t		lmb_size;
	uint8_t		deprecated;
	uint32_t	max_hsl_opticonnect;
	uint32_t	other_attrib;
#define IPLPARAMS_OATTR_CLEAR_NVRAM	0x04000000
	uint16_t	huge_page_count;
	uint8_t		huge_page_size;
#define IPLPARAMS_HUGE_PG_SIZE_16G	0
	uint8_t		num_vlan_switches;
	uint64_t	reserved2;
};

/* Idata index 8: serial ports */
#define IPLPARMS_IDATA_SERIAL	8

/* An HDIF array of serial descriptions */
struct iplparms_serial {
	uint8_t		loc_code[80];
	uint16_t	rsrc_id;
	uint16_t	flags;
#define PLPARMS_SERIAL_FLAGS_CALLHOME	0x8000
} __packed;

/*
 * Chip TOD structure
 *
 * This is an array of 32 entries (I assume per possible chip)
 */

/* Idata index 0: Chip ID data (array) */
#define CHIPTOD_IDATA_CHIPID	0

struct chiptod_chipid {
	uint32_t	chip_id;
	uint32_t	flags;
#define CHIPTOD_ID_FLAGS_PRIMARY	0x02
#define CHIPTOD_ID_FLAGS_SECONDARY	0x01
#define CHIPTOD_ID_FLAGS_STATUS_MASK	0x0c
#define CHIPTOD_ID_FLAGS_STATUS_OK	0x04
#define CHIPTOD_ID_FLAGS_STATUS_NOK	0x08
} __packed;

/* Idata index 0: Chip Initialization data */
#define CHIPTOD_IDATA_CHIPINIT	1

struct chiptod_chipinit {
	uint32_t	ctrl_reg_internal;
	uint32_t	tod_ctrl_reg;
} __packed;

/*
 * MS VPD - Memory Description Tree
 *
 * One such structure pointing to the various memory arrays
 * along with other infos about the BCRs, Page Mover, XSCOM,...
 */
#define MSVPD_HDIF_SIG	"MS VPD"

/* Idata index 0: Mainstore address config */
#define MSVPD_IDATA_MS_ADDR_CONFIG	0

/* Mainstore Address Configuration */
struct msvpd_ms_addr_config {
	uint64_t max_configured_ms_address;
	uint64_t max_possible_ms_address;
	uint32_t deprecated;
	uint64_t mirrorable_memory_starting_address;
} __attribute__((packed));

/* Idata index 1: Total configured mainstore */
#define MSVPD_IDATA_TOTAL_CONFIG_MS	1

struct msvpd_total_config_ms {
	uint64_t total_in_mb;
};

/* Idata index 2: Page mover and sync structure */
#define MSVPD_IDATA_PMOVER_SYNCHRO	2

struct msvpd_pmover_bsr_synchro {
	uint32_t	flags;
#define MSVPD_PMS_FLAG_HWLOCK_EN	0x80000000
#define MSVPD_PMS_FLAG_PMOVER_EN	0x40000000
#define MSVPD_PMS_FLAG_BSR_EN		0x20000000
#define MSVPD_PMS_FLAG_XSCOMBASE_VALID	0x10000000
	/* P7 values for BSR mode */
#define MSVPD_PMS_FLAG_P7BSR_1M_MODE	0x00000000
#define MSVPD_PMS_FLAG_P7BSR_2M_MODE	0x02000000
#define MSVPD_PMS_FLAG_P7BSR_4M_MODE	0x04000000
#define MSVPD_PMS_FLAG_P7BSR_8M_MODE	0x06000000
	uint32_t	hwlocks_per_page;
	uint64_t	hwlock_addr;
	uint64_t	pmover_addr;
	uint64_t	bsr_addr;
	uint64_t	xscom_addr;

};

/* Idata index 3: Memory Trace Array */

/* Idata index 4: UE Address Array */

/* Child index 0: MS area child structure */
#define MSVPD_CHILD_MS_AREAS		0

/*
 * CEC I/O Hub FRU
 *
 * This is an array of CEC Hub FRU HDIF structures
 *
 * Each of these has some idata pointers to generic info about the
 * hub and a possible child pointer for daughter card.
 *
 * Actual ports are in the SLCA and need to be cross referenced
 *
 * Note that slots meant for the addition of GX+ adapters that
 * are currently unpopulated but support hotplug will have a
 * minimum "placeholder" entry, which will be fully populated
 * when the array is rebuild during concurrent maintainance.
 * This "placeholder" is called a "reservation".
 *
 * WARNING: The array rebuild by concurrent maintainance is not
 * guaranteed to be in the same order as the IPL array, not is
 * the order stable between concurrent maintainance operations.
 *
 * There's also a child pointer to daugher card structures but
 * we aren't going to handle that just yet.
 */
#define CECHUB_FRU_HDIF_SIG	"IO HUB"

/* Idata index 0: FRU ID data
 *
 * This is a generic struct spira_fru_id defined above
 */
#define CECHUB_FRU_ID_DATA		0

/* Idata index 1: ASCII Keyword VPD */
#define CECHUB_ASCII_KEYWORD_VPD	1

/* Idata index 2: Hub FRU ID data area */
#define CECHUB_FRU_ID_DATA_AREA		2

struct cechub_hub_fru_id {
	uint32_t	card_type;
#define CECHUB_FRU_TYPE_IOHUB_RSRV	0
#define CECHUB_FRU_TYPE_IOHUB_CARD	1
#define CECHUB_FRU_TYPE_CPU_CARD	2
#define CECHUB_FRU_TYPE_CEC_BKPLANE	3
#define CECHUB_FRU_TYPE_BKPLANE_EXT	4
	uint32_t	unused;
	uint16_t	total_chips;
	uint8_t		flags;
#define CECHUB_FRU_FLAG_HEADLESS	0x80 /* not connected to CPU */
#define CECHUB_FRU_FLAG_PASSTHROUGH	0x40 /* connected to passhtrough
						port of another hub */
	uint8_t		reserved;
	uint16_t	parent_hub_id;	/* chip instance number of the
					   hub that contains the passthrough
					   port this one is connected to */
	uint16_t	reserved2;
} __packed;


/* Idata index 3: IO HUB array */

#define CECHUB_FRU_IO_HUBS		3

/* This is an HDIF array of IO Hub structures
 *
 * Note that a lot of that stuff seems to be unused (not
 * populated) on our Juno machines (both p5ioc2 and p7ioc
 * based). The flags are 0, the pdt too.
 *
 * The BUID extension field seems to be 0 as well, however
 * on those machines, the hub is connected to node 0, chip 0,
 * GX 0, ... so it's hard to tell the layout of the field,
 * but we can reconstruct it ourselves from proc_chip_id
 * and GX bus index anyway.
 */
struct cechub_io_hub {
	uint64_t	fmtc_address;
	uint32_t	fmtc_tce_size;
	uint16_t	hub_num;	/* unique hub number (I/O Hub ID) */
	uint8_t		flags;
#define CECHUB_HUB_FLAG_STATE_MASK	0xc0
#define CECHUB_HUB_FLAG_STATE_OK	0x00
#define CECHUB_HUB_FLAG_STATE_FAILURES	0x40
#define CECHUB_HUB_FLAG_STATE_NOT_INST	0x80
#define CECHUB_HUB_FLAG_STATE_UNUSABLE	0xc0
#define CECHUB_HUB_FLAG_MASTER_HUB	0x20
#define CECHUB_HUB_FLAG_GARD_MASK_VALID	0x08
#define CECHUB_HUB_FLAG_SWITCH_MASK_PDT	0x04
#define CECHUB_HUB_FLAG_FAB_BR0_PDT	0x02
#define CECHUB_HUB_FLAG_FAB_BR1_PDT	0x01
	uint8_t		nr_ports;
	uint8_t		fab_br0_pdt;	/* p5ioc2 PCI-X */
#define CECHUB_HUB_FAB_BR0_PDT_PHB0	0x80
#define CECHUB_HUB_FAB_BR0_PDT_PHB1	0x40
#define CECHUB_HUB_FAB_BR0_PDT_PHB2	0x20
#define CECHUB_HUB_FAB_BR0_PDT_PHB3	0x10
	uint8_t		fab_br1_pdt;	/* p5ioc2 & p7ioc PCI-E */
#define CECHUB_HUB_FAB_BR1_PDT_PHB0	0x80
#define CECHUB_HUB_FAB_BR1_PDT_PHB1	0x40
#define CECHUB_HUB_FAB_BR1_PDT_PHB2	0x20
#define CECHUB_HUB_FAB_BR1_PDT_PHB3	0x10
#define CECHUB_HUB_FAB_BR1_PDT_PHB4	0x08 /* p7ioc only */
#define CECHUB_HUB_FAB_BR1_PDT_PHB5	0x04 /* p7ioc only */
	uint16_t	iohub_id;	/* the type of hub */
#define CECHUB_HUB_P5IOC2	0x1061	/* from VPL1 */
#define CECHUB_HUB_P7IOC	0x60e7	/* from VPL3 */
	uint32_t	ec_level;
	uint32_t	aff_dom2;	/* relates to aff_dom2 of PACA */
	uint32_t	aff_dom3;	/* relates to aff_dom3 of PACA */
	uint64_t	reserved;
	uint32_t	proc_chip_id;	/* cpu the hub is connected to */
	uint32_t	gx_index;	/* GX bus index on cpu */
	uint32_t	buid_ext;	/* BUID Extension (unused on juno ?) */
	uint32_t	xscom_chip_id;	/* TORRENT ONLY */
	uint32_t	mrid;		/* no idea, got 0x00040000 on vpl3 */
	uint32_t	mem_map_vers;	/* Memory map version (1 on vpl3) */
	uint64_t	gx_ctrl_bar0;	/* vpl3 has: 0x00003ebffe000000 */
	uint64_t	gx_ctrl_bar1;	/* vpl3 has: 0x00003efe00000000 */
	uint64_t	gx_ctrl_bar2;	/* vpl3 has: 0x00003da000000000 */
	uint64_t	gx_ctrl_bar3;	/* vpl3 has: 0x00003dc000000000 */
	uint64_t	gx_ctrl_bar4;	/* vpl3 has: 0x00003de000000000 */
	uint32_t	sw_mask_pdt;
	uint16_t	gard_mask;	/* vpl3 has: 0x0f79 */
} __packed;

/* Child index 0: IO Daugther Card */
#define CECHUB_CHILD_IO_KIDS		0

/*
 * IO KID is a dauther card structure
 */
#define IOKID_FRU_ID_DATA	0
#define IOKID_KW_VPD		1

/*
 * Slot Location Code Array (aka SLCA)
 *
 * This is a pile of location codes referenced by various other
 * structures such as the IO Hubs for things on the CEC. Not
 * everything in there is a physical port. The SLCA is actually
 * a tree which represent the topology of the system.
 *
 * The tree works as follow: A parent has a pointer to the first
 * child. A child has a pointer to its parent. Siblings are
 * consecutive entries.
 *
 * Note: If we ever support concurrent maintainance... this is
 * completely rebuilt, invalidating all indices, though other
 * structures that may reference SLCA by index will be rebuilt
 * as well.
 *
 * Note that a lot of that stuff is based on VPD documentation
 * such as the identification keywords. I will list the ones
 * I manage to figure out without the doc separately.
 */
#define SLCA_HDIF_SIG	"SLCA "

/* Idata index 0 : SLCA root pointer
 *
 * The SLCA array is an HDIF array of all the entries. The tree
 * structure is based on indices inside the entries and order of
 * the entries
 */
#define SLCA_IDATA_ARRAY	0

/* Note: An "index" (or idx) is always an index into the SLCA array
 * and "id" is a reference to some other object.
 */
struct slca_entry {
	uint16_t	my_index;	/* redundant, useful */
	uint16_t	rsrc_id;	/* formerly VPD port number */
	uint8_t		fru_id[2];	/* ASCII VPD ID */
#define SLCA_ROOT_VPD_ID	VPD_ID('V','V')
#define SLCA_SYSTEM_VPD_ID	VPD_ID('S','V')
	uint16_t	parent_index;	/* Parent entry index */
	uint8_t		flags;
#define SLCA_FLAG_NON_FUNCTIONAL	0x02	/* For redundant entries */
#define SLCA_FLAG_IMBEDDED		0x01	/* not set => pluggable */
	uint8_t		old_nr_child;	/* Legacy: Nr of children */
	uint16_t	child_index;	/* First child index */
	uint16_t	child_rsrc_id;	/* Resource ID of first child */
	uint8_t		loc_code_allen;	/* Alloc len of loc code */
	uint8_t		loc_code_len;	/* Loc code len */
	uint8_t		loc_code[80];	/* NULL terminated (thus max 79 chr) */
	uint16_t	first_dup_idx;	/* First redundant resource index */
	uint8_t		nr_dups;	/* Number of redundant entries */
	uint8_t		reserved;
	uint16_t	nr_child;	/* New version */
	uint8_t		install_indic;	/* Installed indicator */
#define SLCA_INSTALL_NO_HW_PDT		1 /* No HW presence detect */
#define SLCA_INSTALL_INSTALLED		2
#define SLCA_INSTALL_NOT_INSTALLED	3
	uint8_t		vpd_collected;
#define SLCA_VPD_COLLECTED		2
#define SLCA_VPD_NOT_COLLECTED		3
} __packed;

/*
 * System VPD
 */
#define SYSVPD_HDIF_SIG	"SYSVPD"

/* Idata index 0 : FRU ID Data */
#define SYSVPD_IDATA_FRU_ID	0

/* Idata index 1 : Keyword VPD */
#define SYSVPD_IDATA_KW_VPD	1

/* Idata index 2 : Operational status */
#define SYSVPD_IDATA_OP_STATUS	2


/*
 * SPPACA structure. The SPIRA contain an array of these, one
 * per processor thread
 */
#define PACA_HDIF_SIG	"SPPACA"

/* Idata index 0 : FRU ID Data */
#define SPPACA_IDATA_FRU_ID	0

/* Idata index 1 : Keyword VPD */
#define SPPACA_IDATA_KW_VPD	1

/* Idata index 2 : CPU ID data area */
#define SPPACA_IDATA_CPU_ID	2

struct sppaca_cpu_id {
	u32 pir;
	u32 fru_id;
	u32 hardware_proc_id;
#define CPU_ID_VERIFY_MASK			0xC0000000
#define CPU_ID_VERIFY_SHIFT			30
#define CPU_ID_VERIFY_USABLE_NO_FAILURES	0
#define CPU_ID_VERIFY_USABLE_FAILURES		1
#define CPU_ID_VERIFY_NOT_INSTALLED		2
#define CPU_ID_VERIFY_UNUSABLE			3
#define CPU_ID_SECONDARY_THREAD			0x20000000
#define CPU_ID_PACA_RESERVED			0x10000000
#define CPU_ID_NUM_SECONDARY_THREAD_MASK	0x00FF0000
#define CPU_ID_NUM_SECONDARY_THREAD_SHIFT	16
	u32 verify_exists_flags;
	u32 chip_ec_level;
	u32 processor_chip_id;
	u32 logical_processor_id;
	/* This is the resource number, too. */
	u32 process_interrupt_line;
	u32 reserved1;
	u32 hardware_module_id;
	u64 ibase;
	u32 deprecated1;
	u32 physical_thread_id;
	u32 deprecated2;
	u32 ccm_node_id;
	/* This fields are not always present, check struct size */
#define SPIRA_CPU_ID_MIN_SIZE	0x40
	u32 hw_card_id;
	u32 internal_drawer_node_id;
	u32 drawer_book_octant_blade_id;
	u32 memory_interleaving_scope;
	u32 lco_target;
} __packed;

/* Idata index 3 : Timebase data */
#define SPPACA_IDATA_TIMEBASE	3

struct sppaca_cpu_timebase {
	u32 cycle_time;
	u32 time_base;
	u32 actual_clock_speed;
	u32 memory_bus_frequency;
} __packed;

/* Idata index 4 : Cache size structure */
#define SPPACA_IDATA_CACHE_SIZE	4

struct sppaca_cpu_cache {
	u32 icache_size_kb;
	u32 icache_line_size;
	u32 l1_dcache_size_kb;
	u32 l1_dcache_line_size;
	u32 l2_dcache_size_kb;
	u32 l2_line_size;
	u32 l3_dcache_size_kb;
	u32 l3_line_size;
	u32 dcache_block_size;
	u32 icache_block_size;
	u32 dcache_assoc_sets;
	u32 icache_assoc_sets;
	u32 dtlb_entries;
	u32 dtlb_assoc_sets;
	u32 itlb_entries;
	u32 itlb_assoc_sets;
	u32 reservation_size;
	u32 l2_cache_assoc_sets;
	u32 l35_dcache_size_kb;
	u32 l35_cache_line_size;
};


/*
 * SPPCIA structure. The SPIRA contain an array of these, one
 * per processor core
 */
#define SPPCIA_HDIF_SIG	"SPPCIA"

/* Idata index 0 : Core unique data */
#define SPPCIA_IDATA_CORE_UNIQUE	0

struct sppcia_core_unique {
	u32 reserved;
	u32 proc_fru_id;
	u32 hw_proc_id;
	u32 verif_exist_flags;	/* Same as PACA */
	u32 chip_ec_level;
	u32 proc_chip_id;
	u32 reserved2;
	u32 reserved3;
	u32 reserved4;
	u32 hw_module_id;
	u64 reserved5;
	u32 reserved6;
	u32 reserved7;
	u32 reserved8;
	u32 ccm_node_id;
	u32 hw_card_id;
	u32 fabric_id;
	u32 drawer_id;
	u32 mem_interleave_scope;
	u32 lco_target;
	u32 reserved9;
} __packed;

/* Idata index 1 : CPU Time base structure */
#define SPPCIA_IDATA_TIMEBASE		1

struct sppcia_cpu_timebase {
	u32 cycle_time;
	u32 time_base;
	u32 actual_clock_speed;
	u32 memory_bus_frequency;
} __packed;

/* Idata index 2 : CPU Cache Size Structure */
#define SPPCIA_IDATA_CPU_CACHE		2

struct sppcia_cpu_cache {
	u32 icache_size_kb;
	u32 icache_line_size;
	u32 l1_dcache_size_kb;
	u32 l1_dcache_line_size;
	u32 l2_dcache_size_kb;
	u32 l2_line_size;
	u32 l3_dcache_size_kb;
	u32 l3_line_size;
	u32 dcache_block_size;
	u32 icache_block_size;
	u32 dcache_assoc_sets;
	u32 icache_assoc_sets;
	u32 dtlb_entries;
	u32 dtlb_assoc_sets;
	u32 itlb_entries;
	u32 itlb_assoc_sets;
	u32 reservation_size;
	u32 l2_cache_assoc_sets;
	u32 l35_dcache_size_kb;
	u32 l35_cache_line_size;
} __packed;

/* Idata index 3 : Thread Array Data
 *
 * HDIF array of
 */
#define SPPCIA_IDATA_THREAD_ARRAY	3

struct sppcia_cpu_thread {
	u32 proc_int_line;
	u32 phys_thread_id;
	u64 ibase;
	u32 pir;
} __packed;

/* Idata index 4 : CPU Attributes */
#define SPPCIA_IDATA_CPU_ATTR		4

struct sppcia_cpu_attr {
	u32 attr;
} __packed;

/*
 * Processor Chip Related Data. The SPIRA contain an array of these, one
 * per chip
 */
#define SPPCRD_HDIF_SIG	"SPPCRD"

/* Idata index 0 : Chip info */
#define SPPCRD_IDATA_CHIP_INFO	0

struct sppcrd_chip_info {
	u32 proc_chip_id;
	u32 verif_exist_flags;
#define CHIP_VERIFY_MASK			0xC0000000
#define CHIP_VERIFY_SHIFT			30
#define CHIP_VERIFY_USABLE_NO_FAILURES		0
#define CHIP_VERIFY_USABLE_FAILURES		1
#define CHIP_VERIFY_NOT_INSTALLED		2
#define CHIP_VERIFY_UNUSABLE			3
	u32 nx_state;
	u32 pore_state;
	u32 xscom_id;
} __packed;

/* Idata index 1 : Chip TOD */
#define SPPCRD_IDATA_CHIP_TOD	1

struct sppcrd_chip_tod {
	u32 flags;
	/* CHIPTOD_ID_... values */
	u32 ctrl_reg_internal;
	u32 tod_ctrl_reg;
} __packed;

static inline const char *cpu_state(u32 flags)
{
	switch ((flags & CPU_ID_VERIFY_MASK) >> CPU_ID_VERIFY_SHIFT) {
	case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		return "OK";
	case CPU_ID_VERIFY_USABLE_FAILURES:
		return "FAILURES";
	case CPU_ID_VERIFY_NOT_INSTALLED:
		return "NOT-INSTALLED";
	case CPU_ID_VERIFY_UNUSABLE:
		return "UNUSABLE";
	}
	return "**UNKNOWN**";
}
#endif /* __SPIRA_H */
