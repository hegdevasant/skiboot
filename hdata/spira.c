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

static void add_iplparams_sys_params(const void *iplp, struct dt_node *node)
{
	const struct iplparams_sysparams *p;

	p = HDIF_get_idata(iplp, IPLPARAMS_SYSPARAMS, NULL);
	if (!CHECK_SPPTR(p)) {
		prerror("IPLPARAMS: No SYS Parameters\n");
		return;
	}

	node = dt_new(node, "sys-params");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 0);
	dt_add_property_cells(node, "#size-cells", 0);

	dt_add_property_nstr(node, "ibm,sys-model", p->sys_model, 4);

	/* XXX Add many more */
}

static void add_iplparams_ipl_params(const void *iplp, struct dt_node *node)
{
	const struct iplparams_iplparams *p;

	p = HDIF_get_idata(iplp, IPLPARAMS_IPLPARAMS, NULL);
	if (!CHECK_SPPTR(p)) {
		prerror("IPLPARAMS: No IPL Parameters\n");
		return;
	}

	node = dt_new(node, "ipl-params");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 0);
	dt_add_property_cells(node, "#size-cells", 0);

	dt_add_property_strings(node, "cec-ipl-side",
				(p->ipl_side & IPLPARAMS_CEC_FW_IPL_SIDE_TEMP) ?
				"temp" : "perm");
	dt_add_property_strings(node, "fsp-ipl-side",
				(p->ipl_side & IPLPARAMS_FSP_FW_IPL_SIDE_TEMP) ?
				"temp" : "perm");

	/* XXX Add many more */
}

static void add_iplparams_serials(const void *iplp, struct dt_node *node)
{
	const struct iplparms_serial *ipser;
	struct dt_node *ser_node;
	int count, i;
	
	count = HDIF_get_iarray_size(iplp, IPLPARMS_IDATA_SERIAL);
	if (!count) {
		prerror("IPLPARAMS: No serial ports\n");
		return;
	}
	prerror("IPLPARAMS: %d serial ports in array\n", count);

	node = dt_new(node, "fsp-serial");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 0);

	for (i = 0; i < count; i++) {
		ipser = HDIF_get_iarray_item(iplp, IPLPARMS_IDATA_SERIAL,
					     i, NULL);
		if (!CHECK_SPPTR(ipser))
			continue;
		printf("IPLPARAMS: Serial %d rsrc: %04x loc: %s\n",
		       i, ipser->rsrc_id, ipser->loc_code);
		ser_node = dt_new_addr(node, "serial", ipser->rsrc_id);
		dt_add_property_cells(ser_node, "reg", ipser->rsrc_id);
		dt_add_property_nstr(ser_node, "ibm,loc-code",
				     ipser->loc_code, 80);
		dt_add_property_string(ser_node, "compatible",
				       "ibm,fsp-serial");
		/* XXX handle CALLHOME flag ? */
	}
}

static void add_iplparams(void)
{
	struct dt_node *iplp_node;
	const void *ipl_parms;

	ipl_parms = spira.ntuples.ipl_parms.addr;
	if (!CHECK_SPPTR(ipl_parms)) {
		prerror("IPLPARAMS: Cannot find IPL Parms in SPIRA\n");
		return;
	}
	if (!HDIF_check(ipl_parms, "IPLPMS")) {
		prerror("IPLPARAMS: IPL Parms has wrong header type\n");
		return;
	}

	iplp_node = dt_new(dt_root, "ipl-params");
	assert(iplp_node);
	dt_add_property_cells(iplp_node, "#address-cells", 0);
	dt_add_property_cells(iplp_node, "#size-cells", 0);

	add_iplparams_sys_params(ipl_parms, iplp_node);
	add_iplparams_ipl_params(ipl_parms, iplp_node);
	add_iplparams_serials(ipl_parms, iplp_node);
}

void parse_hdat(void)
{
	dt_root = dt_new_root("");

	/*
	 * Basic DT root stuff
	 */
	dt_add_property_string(dt_root, "compatible", "ibm,powernv");
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	/*
	 * IPL params go first, they contain stuff that may be
	 * needed at any point later on such as the IPL side to
	 * fetch VPD LIDs etc...
	 */
	add_iplparams();

	/* Get model property based on System VPD */
	add_dtb_model();

	/* Parse SPPACAs (TODO: Add SPICA) */
	cpu_parse();

	/* Parse MS VPD */
	memory_parse();

	/* Add XICS nodes */
	add_interrupt_controllers();

	/* Add XSCOM node */
	add_xscom();

#if 0 /* Tests */
	{
		struct dt_node *n;

		n = dt_find_by_path(dt_root, "/");
		printf("test / %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus");
		printf("test /cpus %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/PowerPC,POWER7@10");
		printf("test /cpus/PowerPC,POWER7@10 %p [%s]\n",
		       n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/@10");
		printf("test /cpus/@10 %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/@30");
		printf("test /cpus/@30 %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/@15");
		printf("test /cpus/@15 %p [%s]\n", n, dt_get_path(n));
		n = dt_find_by_path(dt_root, "/cpus/PowerPC,POWER7");
		printf("test /cpus/PowerPC,POWER7 %p [%s]\n",
		       n, dt_get_path(n));
	}
#endif
}
