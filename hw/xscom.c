#include <xscom.h>
#include <io.h>
#include <spira.h>

/* XSCOM base address default */
#define XSCOM_DEFAULT_BASE	0x00001A0000000000UL

static uint64_t xscom_base = XSCOM_DEFAULT_BASE;


static inline void *xscom_addr(uint32_t gcid, uint32_t pcb_addr)
{
	uint64_t addr;

	addr  = xscom_base | ((uint64_t)gcid << PPC_BITLSHIFT(28));
	addr |= ((uint64_t)pcb_addr << 4) & ~0xfful;
	addr |= (pcb_addr << 3) & 0x78;

	return (void *)addr;
}

static uint64_t __xscom_read(uint32_t gcid, uint32_t pcb_addr)
{
	return in_be64(xscom_addr(gcid, pcb_addr));
}

static void __xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	out_be64(xscom_addr(gcid, pcb_addr), val);
}

int xscom_read(uint32_t gcid, uint32_t pcb_addr, uint64_t *val)
{
	/* XXX Implement error handling and recovery !!! */
	*val = __xscom_read(gcid, pcb_addr);
	return 0;
}

int xscom_write(uint32_t gcid, uint32_t pcb_addr, uint64_t val)
{
	/* XXX Implement error handling and recovery !!! */
	__xscom_write(gcid, pcb_addr, val);
	return 0;
}

void xscom_init(void)
{
	const void *ms_vpd = spira.ntuples.ms_vpd.addr;
	const struct msvpd_pmover_bsr_synchro *pmbs;
	unsigned int size;

	if (!ms_vpd || !HDIF_check(ms_vpd, MSVPD_HDIF_SIG)) {
		prerror("XSCOM: Can't find MS VPD\n");
		op_display(OP_FATAL, OP_MOD_XSCOM, 0x0000);
		return;
	}

	pmbs = HDIF_get_idata(ms_vpd, MSVPD_IDATA_PMOVER_SYNCHRO, &size);
	if (!CHECK_SPPTR(pmbs) || size < sizeof(*pmbs)) {
		prerror("XSCOM: absent or bad PMBS size %u @ %p\n", size, pmbs);
		op_display(OP_WARN, OP_MOD_XSCOM, 0x0001);
		return;
	}

	if (!(pmbs->flags & MSVPD_PMS_FLAG_XSCOMBASE_VALID)) {
		prerror("XSCOM: No XSCOM base in PMBS, using default\n");
		op_display(OP_WARN, OP_MOD_XSCOM, 0x0002);
		return;
	}

	xscom_base = pmbs->xscom_addr;
	printf("XSCOM: Found base address: 0x%llx\n", xscom_base);

	op_display(OP_LOG, OP_MOD_XSCOM, 0x0000);
}
