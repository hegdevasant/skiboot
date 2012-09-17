#include <spira.h>

/* Processor Initialization structure, contains
 * the initial NIA and MSR values for the entry
 * point
 */
static struct proc_init_data proc_init_data = {
	.hdr = HDIF_SIMPLE_HDR('P','R','O','C','I','N',
			       1, struct proc_init_data),
	.regs = {
		.nia	= 0x180,
		.msr  	= 0x9000000000000000,
	},
};

/* SP Interface Root Array, aka SPIRA */
struct spira spira = {
	.hdr = HDIF_SIMPLE_HDR('S','P','I','R','A',' ', SPIRA_VERSION,
			       struct spira),
	.ntuples_ptr = {
		.idata_off	= offsetof(struct spira, ntuples),
		.idata_size	= sizeof(struct spira_ntuples),
	},
	.ntuples = {
		.array_hdr = {
			.offset		= HDIF_ARRAY_OFFSET,
			.ecnt		= SPIRA_NTUPLES_COUNT,
			.esize		= sizeof(struct spira_ntuple),
			.eactsz		= 0x18,
		},
		/* We only populate some n-tuples */
		.proc_init = {
			.addr  		= (uint64_t)&proc_init_data,
			.alloc_cnt	= 1,
			.alloc_len	= sizeof(struct proc_init_data),
		},
		.heap = {
			.addr		= SPIRA_HEAP_BASE,
			.alloc_cnt	= 1,
			.alloc_len	= SPIRA_HEAP_SIZE,
		},
	},
};

