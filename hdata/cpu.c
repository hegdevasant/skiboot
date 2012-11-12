#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <device_tree.h>
#include <opal.h>
#include <ccan/str/str.h>

static void cpu_find_max_pir(void)
{
	const void *paca;
	unsigned int count, i;

	paca = spira.ntuples.paca.addr;

	/* Iterate all PACAs to locate the highest PIR value */
	count = spira.ntuples.paca.act_cnt;
	for (i = 0; i < count; i++, paca += spira.ntuples.paca.alloc_len) {
		const struct HDIF_cpu_id *id;
		unsigned int size;

		id = HDIF_get_idata(paca, 2, &size);
		if (!CHECK_SPPTR(id) || size < sizeof(*id))
			continue;
		if (id->pir > SPR_PIR_MASK)
			continue;
		if (id->pir > cpu_max_pir)
			cpu_max_pir = id->pir;
	}
	printf("CPU: Max PIR set to 0x%04x\n", cpu_max_pir);
}

static const char *cpu_state(u32 flags)
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

static struct cpu_thread *populate_cpu_thread(const struct HDIF_cpu_id *id)
{
	struct cpu_thread *t;
	u32 state;

	t = &cpu_threads[id->pir];
	init_lock(&t->job_lock);
	list_head_init(&t->job_queue);
	t->pir = id->pir;
	t->id = id;

	state = (t->id->verify_exists_flags & CPU_ID_VERIFY_MASK) >>
		CPU_ID_VERIFY_SHIFT;
	switch(state) {
	case CPU_ID_VERIFY_USABLE_NO_FAILURES:
	case CPU_ID_VERIFY_USABLE_FAILURES:
		printf("CPU: PIR=%i RES=%i OK\n",
		       id->pir, id->process_interrupt_line);
		t->state = cpu_state_present;
		break;
	default:
		printf("CPU: PIR=%i RES=%i UNAVAILABLE\n",
		       id->pir, id->process_interrupt_line);
		t->state = cpu_state_unavailable;
	}
	return t;
}

void early_init_boot_cpu_thread(void)
{
	const struct HDIF_common_hdr *paca = spira.ntuples.paca.addr;
	const struct HDIF_cpu_id *id = NULL;
	uint32_t boot_pir = mfspr(SPR_PIR);
	unsigned int i;
	struct cpu_thread *t;

	if (boot_pir > SPR_PIR_MASK) {
		prerror("Invalid boot pir %u\n", boot_pir);
		abort();
	}

	if (!HDIF_check(paca, "SPPACA")) {
		/* FIXME: PACA is deprecated in favor of PCIA */
		prerror("Invalid PACA (PCIA = %p)\n", spira.ntuples.pcia.addr);
		abort();
	}

	if (spira.ntuples.paca.act_len < sizeof(*paca)) {
		prerror("PACA: invalid size %u\n",
			spira.ntuples.paca.act_len);
		abort();
	}

	for (i = 0; i < spira.ntuples.paca.act_cnt; i++) {
		u32 size;

		id = HDIF_get_idata(paca, 2, &size);

		/* The ID structure on Blade314 is only 0x54 long. We can
		 * cope with it as we don't use all the additional fields.
		 * The minimum size we support is  0x40
		 */
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				i, size, id);
			abort();
		}
		if (id->pir == boot_pir)
			break;

		paca = (void *)paca + spira.ntuples.paca.alloc_len;
	}

	if (i == spira.ntuples.paca.act_cnt) {
		prerror("Boot cpu PIR %u not found!\n", boot_pir);
		abort();
	}

	t = populate_cpu_thread(id);
	if (!t)
		abort();

	if (t->state != cpu_state_present) {
		prerror("CPU: Boot CPU unavailable!\n");
		abort();
	}

	t->state = cpu_state_active;
	t->stack = boot_stack_top;
	cpu_stacks[t->pir] = t->stack;
	__this_cpu = boot_cpu = t;
}

static bool __cpu_parse(void)
{
	const struct HDIF_common_hdr *paca;
	uint32_t boot_pir = mfspr(SPR_PIR);
	unsigned int i;

	paca = spira.ntuples.paca.addr;
	if (!HDIF_check(paca, "SPPACA")) {
		/* FIXME: PACA is deprecated in favor of PCIA */
		prerror("Invalid PACA (PCIA = %p)\n", spira.ntuples.pcia.addr);
		return false;
	}

	if (spira.ntuples.paca.act_len < sizeof(*paca)) {
		prerror("PACA: invalid size %u\n",
			spira.ntuples.paca.act_len);
		return false;
	}

	cpu_find_max_pir();

	for (i = 0; i < spira.ntuples.paca.act_cnt; i++) {
		const struct HDIF_cpu_id *id;
		u32 size;

		id = HDIF_get_idata(paca, 2, &size);

		/* The ID structure on Blade314 is only 0x54 long. We can
		 * cope with it as we don't use all the additional fields.
		 * The minimum size we support is  0x40
		 */
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				i, size, id);
			return false;
		}
		if (id->pir > cpu_max_pir) {
			prerror("CPU[%i]: PIR 0x%04x out of range\n",
				i, id->pir);
			return false;
		}

		/* This one is already done. */
		if (id->pir != boot_pir) {
			if (!populate_cpu_thread(id))
				return false;
		}

		paca = (void *)paca + spira.ntuples.paca.alloc_len;
	}
	return true;
}	

void cpu_parse(void)
{
	if (!__cpu_parse()) {
		prerror("CPU: Initial CPU parsing failed\n");
		abort();
	}
}

bool add_cpu_nodes(void)
{
	const struct HDIF_common_hdr *paca;
	unsigned int i;
	static const uint32_t p7_sps[] = {
		0x0c, 0x000, 1, 0x0c, 0x0000,
		0x18, 0x100, 1,	0x18, 0x0000,
		0x14, 0x111, 1, 0x14, 0x0002,
		0x22, 0x120, 1, 0x22, 0x0003,
	};
	static const uint32_t p7_pss[] = {
		0x1c, 0x28, 0xffffffff, 0xffffffff
	};

	dt_begin_node("cpus");
	dt_property_cell("#address-cells", 2);
	dt_property_cell("#size-cells", 1);

	paca = spira.ntuples.paca.addr;

	for (i = 0; i < spira.ntuples.paca.act_cnt; i++, paca = (void *)paca + spira.ntuples.paca.alloc_len) {
		char name[sizeof("PowerPC,POWER7@") + STR_MAX_CHARS(u32)];
		const struct HDIF_cpu_id *id;
		const struct HDIF_cpu_timebase *timebase;
		const struct HDIF_cpu_cache *cache;
		u32 size, no;

		id = HDIF_get_idata(paca, 2, &size);
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				i, size, id);
			return false;
		}

		/* Only cpus we brought up OK. */
		if (id->pir > cpu_max_pir ||
		    cpu_threads[id->pir].state != cpu_state_active)
			continue;

		/* We use the process_interrupt_line as the res id */
		no = id->process_interrupt_line;

		printf("CPU: PIR=%i RES=%i %s %s(%u threads)\n",
		       id->pir, no,
		       id->verify_exists_flags & CPU_ID_PACA_RESERVED
		       ? "**RESERVED**" : cpu_state(id->verify_exists_flags),
		       id->verify_exists_flags & CPU_ID_SECONDARY_THREAD
		       ? "[secondary] " : 
		       (id->pir == boot_cpu->pir ? "[boot] " : ""),
		       ((id->verify_exists_flags
			 & CPU_ID_NUM_SECONDARY_THREAD_MASK)
			>> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1);

		if (id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		timebase = HDIF_get_idata(paca, 3, &size);
		if (!timebase || size < sizeof(*timebase)) {
			prerror("CPU[%i]: bad timebase size %u @ %p\n",
				id->pir, size, timebase);
			return false;
		}

		cache = HDIF_get_idata(paca, 4, &size);
		if (!cache || size < sizeof(*cache)) {
			prerror("CPU[%i]: bad cache size %u @ %p\n",
				id->pir, size, cache);
			return false;
		}

		printf("    Cache: I=%u D=%u/%u/%u/%u\n",
		       cache->icache_size_kb,
		       cache->l1_dcache_size_kb,
		       cache->l2_dcache_size_kb,
		       cache->l3_dcache_size_kb,
		       cache->l35_dcache_size_kb);

		/* FIXME: Don't hardcode this! */
		sprintf(name, "PowerPC,POWER7@%u", no);
		dt_begin_node(name);
		*strchr(name, '@') = '\0';
		dt_property_string("device_type", "cpu");
		dt_property_string("status", "okay");
		dt_property_cell("reg", no);
		dt_property("ibm,segment-page-sizes", p7_sps, sizeof(p7_sps));
		dt_property("ibm,processor-segment-sizes", p7_pss,
			    sizeof(p7_pss));
		/* XXX FIXME: Don't hardcode... */
		dt_property_cells("ibm,ppc-interrupt-server#s", 4,
				  no, no + 1, no + 2, no + 3);
		dt_property_cell("ibm,slb-size", 0x20);
		dt_property_cell("ibm,vmx", 0x2);

		dt_property_cell("d-cache-block-size",
				 cache->dcache_block_size);
		dt_property_cell("i-cache-block-size",
				 cache->icache_block_size);
		dt_property_cell("d-cache-size",
				 cache->l1_dcache_size_kb*1024);
		dt_property_cell("i-cache-size",
				 cache->icache_size_kb*1024);

		if (cache->icache_line_size != cache->icache_block_size)
			dt_property_cell("i-cache-line-size",
					 cache->icache_line_size);
		if (cache->l1_dcache_line_size !=
		    cache->dcache_block_size)
			dt_property_cell("d-cache-line-size",
					 cache->l1_dcache_line_size);
		dt_property_cell("clock-frequency",
				 timebase->actual_clock_speed * 1000000);

		/* FIXME: Hardcoding is bad. */
		dt_property_cell("timebase-frequency", 512000000);
		dt_end_node();
	}
	dt_end_node();
	return true;
}
