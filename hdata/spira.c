#include <device.h>
#include <spira.h>
#include <cpu.h>
#include <memory.h>
#include <vpd.h>
#include <ccan/str/str.h>
#include <device_tree.h>

/* Processor Initialization structure, contains
 * the initial NIA and MSR values for the entry
 * point
 *
 * Note: It appears to be ignoring the entry point
 *       and always going to 0x180
 */

static struct proc_init_data proc_init_data = {
	.hdr = HDIF_SIMPLE_HDR("PROCIN", 1, struct proc_init_data),
	.regs_ptr = {
		.offset	= offsetof(struct proc_init_data, regs),
		.size	= 0x10,
	},
	.regs = {
		.nia	= 0x180,
		.msr  	= 0x9000000000000000, /* SF | HV */
	},
};

/* SP Interface Root Array, aka SPIRA */
struct spira spira = {
	.hdr = HDIF_SIMPLE_HDR("SPIRA ", SPIRA_VERSION, struct spira),
	.ntuples_ptr = {
		.offset			= offsetof(struct spira, ntuples),
		.size			= sizeof(struct spira_ntuples),
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
			.addr  		= &proc_init_data,
			.alloc_cnt	= 1,
			.act_cnt	= 1,
			.alloc_len	= sizeof(struct proc_init_data),
		},
		.heap = {
			.addr		= (void *)SPIRA_HEAP_BASE,
			.alloc_cnt	= 1,
			.alloc_len	= SPIRA_HEAP_SIZE,
		},
	},
};

bool spira_check_ptr(const void *ptr, const char *file, unsigned int line)
{
	if (!ptr)
		return false;
	if (((unsigned long)ptr) >= SPIRA_HEAP_BASE &&
	    ((unsigned long)ptr) < (SPIRA_HEAP_BASE + SPIRA_HEAP_SIZE))
		return true;

	prerror("SPIRA: Bad pointer %p at %s line %d\n", ptr, file, line);
	return false;
}

/* Adds private cec_ipl_temp_side property if we're booting from temp side. */
static void fetch_global_params(void)
{
	/* Get CEC IPL side from IPLPARAMS */
	const void *iplp = spira.ntuples.ipl_parms.addr;

	if (iplp && HDIF_check(iplp, "IPLPMS")) {
		const struct iplparams_iplparams *p;

		p = HDIF_get_idata(iplp, IPLPARAMS_IPLPARAMS, NULL);
		if (CHECK_SPPTR(p)) {
			if (p->ipl_side & IPLPARAMS_CEC_FW_IPL_SIDE_TEMP) {
				dt_add_property(dt_root,
						DT_PRIVATE "cec_ipl_temp_side",
						NULL, 0);
				printf("FSP: CEC IPLed from Temp side\n");
			} else {
				printf("FSP: CEC IPLed from Perm side\n");
			}
		} else
			prerror("FSP: Invalid IPL params, assuming P side\n");
	} else
		prerror("FSP: Can't find IPL params, assuming P side\n");

}

static void add_ics_reg_property(struct dt_node *ics,
				 u64 ibase,
				 unsigned int num_threads)
{
	unsigned int i;
	u64 reg[num_threads * 2];

	for (i = 0; i < num_threads*2; i += 2) {
		reg[i] = ibase;
		/* One page is enough for a handful of regs. */
		reg[i+1] = 4096;
		ibase += reg[i+1];
	}
	dt_add_property(ics, "reg", reg, sizeof(reg));
}

static void add_interrupt_controllers(void)
{
	struct dt_node *cpu, *ics;

	ics = dt_new_addr(dt_root, "interrupt-controller", 0);
	dt_add_property_cells(ics, "reg", 0, 0, 0, 0);
	dt_add_property_string(ics, "compatible", "IBM,ppc-xics");
	dt_add_property_cells(ics, "#address-cells", 0);
	dt_add_property_cells(ics, "#interrupt-cells", 1);
	dt_add_property_string(ics, "device_type",
			       "PowerPC-Interrupt-Source-Controller");
	dt_add_property(ics, "interrupt-controller", NULL, 0);

	dt_for_each_node(dt_root, cpu) {
		u32 irange[2];
		const struct dt_property *intsrv;
		u64 ibase;
		unsigned int num_threads;

		if (!dt_has_node_property(cpu, "device_type", "cpu"))
			continue;

		intsrv = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		ibase = dt_prop_get_u64(cpu, DT_PRIVATE "ibase");

		num_threads = intsrv->len / sizeof(u32);

		ics = dt_new_addr(dt_root, "interrupt-controller", ibase);
		dt_add_property_strings(ics, "compatible",
					"IBM,ppc-xicp",
					"IBM,power7-xicp");

		irange[0] = dt_property_get_cell(intsrv, 0); /* Index */
		irange[1] = num_threads;		     /* num servers */
		dt_add_property(ics, "ibm,interrupt-server-ranges",
				irange, sizeof(irange));
		dt_add_property(ics, "interrupt-controller", NULL, 0);
		add_ics_reg_property(ics, ibase, num_threads);
		dt_add_property_cells(ics, "#address-cells", 0);
		dt_add_property_cells(ics, "#interrupt-cells", 1);
		dt_add_property_string(ics, "device_type",
				   "PowerPC-External-Interrupt-Presentation");
	}
}

static void add_xscom(void)
{
	const void *ms_vpd = spira.ntuples.ms_vpd.addr;
	const struct msvpd_pmover_bsr_synchro *pmbs;
	struct dt_node *xn;
	unsigned int size;
	uint64_t xscom_base, xscom_size;

	if (!ms_vpd || !HDIF_check(ms_vpd, MSVPD_HDIF_SIG)) {
		prerror("XSCOM: Can't find MS VPD\n");
		return;
	}

	pmbs = HDIF_get_idata(ms_vpd, MSVPD_IDATA_PMOVER_SYNCHRO, &size);
	if (!CHECK_SPPTR(pmbs) || size < sizeof(*pmbs)) {
		prerror("XSCOM: absent or bad PMBS size %u @ %p\n", size, pmbs);
		return;
	}

	if (!(pmbs->flags & MSVPD_PMS_FLAG_XSCOMBASE_VALID)) {
		prerror("XSCOM: No XSCOM base in PMBS, using default\n");
		return;
	}

	xscom_base = pmbs->xscom_addr;

	/* Some FSP give me a crap base address for XSCOM (it has spurrious
	 * bits set as far as I can tell). Since only 5 bits 18:22 can
	 * be programmed in hardware, let's isolate these. This seems to
	 * give me the right value on VPL1
	 */
	xscom_base &= 0x80003e0000000000ul;
	printf("XSCOM: Found base address: 0x%llx\n", xscom_base);

	xscom_base = cleanup_addr(xscom_base);

	xn = dt_new_addr(dt_root, "xscom", xscom_base);
	assert(xn);

	/* We hard wire the XSCOM size for now, it seems to be the same
	 * everywhere so far
	 */
	xscom_size = 0x400000000000;

	/* XXX Use boot CPU PVR to decide on XSCOM type... */
	switch(PVR_TYPE(mfspr(SPR_PVR))) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		dt_add_property_strings(xn, "compatible",
					"ibm,xscom", "ibm,power7-xscom");
		break;
	case PVR_TYPE_P8:
		dt_add_property_strings(xn, "compatible",
					"ibm,xscom", "ibm,power8-xscom");
		break;
	default:
		dt_add_property_strings(xn, "compatible", "ibm,xscom");
	}
	dt_add_property_cells(xn, "reg", hi32(xscom_base), lo32(xscom_base),
			      hi32(xscom_size), lo32(xscom_size));
}

void parse_hdat(void)
{
	dt_root = dt_new_root("");

	/* We need to know if we're booting from temp size before vpd access */
	fetch_global_params();

	add_dtb_model();
	dt_add_property_string(dt_root, "compatible", "ibm,powernv");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	cpu_parse();
	memory_parse();
	add_interrupt_controllers();
	add_xscom();
}
