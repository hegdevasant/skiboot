/*
 * Service Processor handling code
 *
 * TODO: - Handle redundant FSPs
 */
#include <processor.h>
#include <spira.h>
#include <io.h>
#include <fsp.h>
#include <stdarg.h>

#define DBG(fmt...)	printf(fmt)

#define FSP_MAX_IOPATH	4

struct fsp_iopath {
	unsigned short	link_status;	/* straight from SPSS */
	void		*gxhb_regs;
	void		*fsp_regs;
};

struct fsp {
	struct fsp		*link;
	unsigned int		index;

	unsigned int		iopath_count;
	int			active_iopath;	/* -1: no active IO path */
	struct fsp_iopath	iopath[FSP_MAX_IOPATH];
};

static struct fsp *first_fsp;
static struct fsp *active_fsp;
static struct fsp_msg *fsp_msgq;
static uint16_t fsp_curseq = 0x8000
struct fsp_cmdclass {
	int timeout;
	struct fsp_msg *pending;	
};

static struct fsp_cmdclass fsp_cmdclass[FSP_MCLASS_LAST - FSP_MCLASS_FIRST + 1]
= {
#define DEF_CLASS(_cl, _to) [_cl - FSP_MCLASS_FIRST] = { .timeout = _to }
	DEF_CLASS(FSP_MCLASS_SERVICE,		16),
	DEF_CLASS(FSP_MCLASS_IPL,		16),
	DEF_CLASS(FSP_MCLASS_PCTRL_MSG,		16),
	DEF_CLASS(FSP_MCLASS_PCTRL_ABORTS,	16),
	DEF_CLASS(FSP_MCLASS_ERR_LOG,		16),
	DEF_CLASS(FSP_MCLASS_CODE_UPDATE,	40),
	DEF_CLASS(FSP_MCLASS_FETCH_SPDATA,	16),
	DEF_CLASS(FSP_MCLASS_FETCH_HVDATA,	16),
	DEF_CLASS(FSP_MCLASS_NVRAM,		16),
	DEF_CLASS(FSP_MCLASS_MBOX_SURV,		 2),
	DEF_CLASS(FSP_MCLASS_RTC,		16),
	DEF_CLASS(FSP_MCLASS_SMART_CHIP,	20),
	DEF_CLASS(FSP_MCLASS_INDICATOR,	       180),
	DEF_CLASS(FSP_MCLASS_HMC_INTFMSG,	16),
	DEF_CLASS(FSP_MCLASS_HMC_VT,		16),
	DEF_CLASS(FSP_MCLASS_HMC_BUFFERS,	16),
	DEF_CLASS(FSP_MCLASS_SHARK,		16),
	DEF_CLASS(FSP_MCLASS_MEMORY_ERR,	16),
	DEF_CLASS(FSP_MCLASS_CUOD_EVENT,	16),
	DEF_CLASS(FSP_MCLASS_HW_MAINT,		16),
	DEF_CLASS(FSP_MCLASS_VIO,		16),
	DEF_CLASS(FSP_MCLASS_SRC_MSG,		16),
	DEF_CLASS(FSP_MCLASS_DATA_COPY,		16),
	DEF_CLASS(FSP_MCLASS_TONE,		16),
	DEF_CLASS(FSP_MCLASS_VIRTUAL_NVRAM,	16)
};

static struct fsp_cmdclass *fsp_get_cmdclass(struct fsp_msg *msg)
{
	struct fsp_cmdclass *ret;
	uint8_t c = msg->word0 & 0xff;

	/* Alias classes CE and CF as the FSP has a single queue */
	if (c == 0xcf)
		c == 0xce;

	ret = &fsp_cmdclass[c - FSP_MCLASS_FIRST];

	/* Unknown class */
	if (ret->timeout == 0)
		return NULL;

	return ret;
}

static void fsp_wreg(struct fsp *fsp, uint32_t reg, uint32_t val)
{
	struct fsp_iopath *iop;

	if (fsp->active_iopath < 0)
		return;
	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->link_status == SPSS_IO_PATH_PSI_LINK_BAD_FRU)
		return;
	out_be32(iop->fsp_regs + reg, val);
}

static uint32_t fsp_rreg(struct fsp *fsp, uint32_t reg)
{
	struct fsp_iopath *iop;

	if (fsp->active_iopath < 0)
		return 0xffffffff;
	iop = &fsp->iopath[fsp->active_iopath];
	if (iop->link_status == SPSS_IO_PATH_PSI_LINK_BAD_FRU)
		return 0xffffffff;
	return in_be32(iop->fsp_regs + reg);
}

static bool fsp_check_impl(const void *spss, int i)
{
	const struct spss_sp_impl *sp_impl;
	unsigned int mask;

	/* Find an check the SP Implementation structure */
	sp_impl = HDIF_get_idata(spss, SPSS_IDATA_SP_IMPL, NULL);
	if (!sp_impl) {
		prerror("FSP #%d: SPSS/SP_Implementation not found !\n", i);
		return false;
	}

	printf("FSP #%d: FSP HW version %d, SW version %d, chip DD%d.%d\n",
	       i, sp_impl->hw_version, sp_impl->sw_version,
	       sp_impl->chip_version >> 4, sp_impl->chip_version & 0xf);
	mask = SPSS_SP_IMPL_FLAGS_FUNCTIONAL | SPSS_SP_IMPL_FLAGS_FUNCTIONAL;
	if ((sp_impl->func_flags & mask) != mask) {
		prerror("FSP #%d: FSP not installed or not functional\n", i);
		return false;
	}

	return true;
}

static void fsp_reg_dump(struct fsp *fsp)
{
#define FSP_DUMP_ONE(x)	\
	DBG("  %20s: %x\n", #x, fsp_rreg(fsp, x));

	DBG("FSP #%d: Register dump...\n", fsp->index);
	FSP_DUMP_ONE(FSP_DRCR_REG);
	FSP_DUMP_ONE(FSP_DISR_REG);
	FSP_DUMP_ONE(FSP_MBX1_HCTL_REG);
	FSP_DUMP_ONE(FSP_MBX1_FCTL_REG);
	FSP_DUMP_ONE(FSP_MBX2_HCTL_REG);
	FSP_DUMP_ONE(FSP_MBX2_FCTL_REG);
	FSP_DUMP_ONE(FSP_SDES_REG);
	FSP_DUMP_ONE(FSP_HDES_REG);
	FSP_DUMP_ONE(FSP_HDIR_REG);
	FSP_DUMP_ONE(FSP_HDIM_SET_REG);
	FSP_DUMP_ONE(FSP_PDIR_REG);
	FSP_DUMP_ONE(FSP_PDIM_SET_REG);
	FSP_DUMP_ONE(FSP_SCRATCH0_REG);
	FSP_DUMP_ONE(FSP_SCRATCH1_REG);
	FSP_DUMP_ONE(FSP_SCRATCH2_REG);
	FSP_DUMP_ONE(FSP_SCRATCH3_REG);
}

static void fsp_create_fsp(const void *spss, int index)
{
	struct fsp *fsp;
	int count, i;

	fsp = zalloc(sizeof(struct fsp));
	if (!fsp) {
		prerror("FSP #%d: Can't allocate memory !\n", index);
		return;
	}

	fsp->index = index;
	fsp->active_iopath = -1;

	count = HDIF_get_iarray_size(spss, SPSS_IDATA_SP_IOPATH);
	if (count < 0) {
		prerror("FSP #%d: Can't find IO PATH array size !\n", index);
		free(fsp);
		return;
	}
	printf("FSP #%d: Found %d IO PATH\n", index, count);
	if (count > FSP_MAX_IOPATH) {
		prerror("FSP #%d: WARNING, limited to %d IO PATH\n",
			index, FSP_MAX_IOPATH);
		count = FSP_MAX_IOPATH;
	}
	fsp->iopath_count = count;

	for (i = 0; i < count; i++) {
		const struct spss_iopath *iopath;
		struct fsp_iopath *fiop;
		unsigned int iopath_sz;
		const char *ststr;
		bool active;
		uint64_t reg;

		iopath = HDIF_get_iarray_item(spss, SPSS_IDATA_SP_IOPATH,
					      i, &iopath_sz);
		if (!iopath) {
			prerror("FSP #%d: Can't find IO PATH %d\n", index, i);
			fsp->iopath_count = i;
			break;
		}
		if (iopath->iopath_type != SPSS_IOPATH_TYPE_PSI) {
			prerror("FSP #%d: Unsupported IO PATH %d type 0x%04x\n",
				index, i, iopath->iopath_type);
			continue;
		}
		fiop = &fsp->iopath[i];
		fiop->link_status = iopath->psi.link_status;
		fiop->gxhb_regs = (void *)iopath->psi.gxhb_base;
		active = false;
		switch(fiop->link_status) {
		case SPSS_IO_PATH_PSI_LINK_BAD_FRU:
			ststr = "Broken";
			break;
		case SPSS_IO_PATH_PSI_LINK_CURRENT:
			ststr = "Active";
			active = true;
			break;
		case SPSS_IO_PATH_PSI_LINK_BACKUP:
			ststr = "Backup";
			break;
		default:
			ststr = "Unknown";
		}
		printf("FSP #%d: IO PATH %d is %s PSI Link, GXHB at %llx\n",
		       index, i, ststr, iopath->psi.gxhb_base);
		if (active)
			fsp->active_iopath = i;

		/* Dump the GXHB registers */
		DBG("  PSIHB_BBAR   : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_BBAR));
		DBG("  PSIHB_FSPBAR : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_FSPBAR));
		DBG("  PSIHB_FSPMMR : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_FSPMMR));
		DBG("  PSIHB_TAR    : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_TAR));
		DBG("  PSIHB_CR     : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_CR));
		DBG("  PSIHB_SEMR   : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_SEMR));
		DBG("  PSIHB_XIVR   : %llx\n",
		    in_be64(fiop->gxhb_regs + PSIHB_XIVR));

		/* Get the FSP register window */
		reg = in_be64(fiop->gxhb_regs + PSIHB_FSPBAR);
		fiop->fsp_regs =
			(void *)(reg | (1ULL << 63) | FSP1_REG_OFFSET);
	}
	if (fsp->active_iopath >= 0 && !active_fsp) {
		fsp_reg_dump(fsp);
		active_fsp = fsp;
	}

	fsp->link = first_fsp;
	first_fsp = fsp;
}

struct fsp_msg *fsp_mkmsg(uint8_t cmd, uint8_t sub, uint8_t mod,
			  bool response, uint8_t add_len, ...)
{
	struct fsp_msg *msg = zalloc(sizeof(struct fsp_msg));
	va_list list;
	int i;

	if (!msg) {
		prerror("FSP: Failed to allocate struct fsp_msg\n");
		return NULL;
	}
	msg->word0 = cmd;
	msg->word1 = mod << 8 | sub;
	msg->dlen = add_len;
	msg->response = response;

	va_start(list, add_len);
	for (i = 0; i < add_len; i++)
		msg->data.bytes[i] = va_arg(list, int);
	va_end(list);

	return msg;
}

int fsp_queue_msg(struct fsp_msg *msg)
{
	struct fsp_cmdclass *cmdclass;
	uint16_t seq;

	/* Grab a new sequence number */
	seq = fsp_curseq;
	fsp_curseq = fsp_curseq + 1;
	if (fsp_curseq == 0)
		fsp_curseq = 0x8000;
	msg->word0 |= seq << 16;

	/* Queue the message in the appropriate queue */
	cmdclass = fsp_get_cmdclass(msg);
	if (!cmdclass) {
		prerror("FSP: Invalid message class\n");
		return -1;
	}

	/* XXX ENQUEUE XXX */
	msg->state = fsp_msg_queued;

}

void fsp_poll(void)
{
}

int fsp_wait_complete(struct fsp_msg *msg)
{
	/* XXX HANDLE TIMEOUTS */
	while(msg->state != fsp_msg_done)
		fsp_poll();
}

/* fsp_preinit -- Early initialization of the FSP stack
 *
 */
void fsp_preinit(void)
{
	void *base_spss, *spss;
	int i;
	
	/* Find SPSS in SPIRA */
	base_spss = spira.ntuples.sp_subsys.addr;
	if (!base_spss) {
		prerror("FSP: Cannot locate SPSS !\n");
		return;
	}

	/* For each SPSS */
	for (i = 0; i < spira.ntuples.sp_subsys.act_cnt; i++) {
		spss = base_spss + i * spira.ntuples.sp_subsys.alloc_len;


		if (!HDIF_check(spss, "SPINFO")) {
			prerror("FSP #%d: SPSS signature mismatch !\n", i);
			continue;
		}

		/* Check SP Implementation */
		if (!fsp_check_impl(spss, i))
			continue;

		/* Create the FSP data structure */
		fsp_create_fsp(spss, i);
	}
	if (!active_fsp)
		prerror("FSP: No active FSP !\n");
}

