#include <spira.h>
#include <cpu.h>

struct cpu_thread *cpu_threads;

u32 num_cpu_threads(void)
{
	return spira.ntuples.paca.act_cnt;
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
	abort();
}

struct cpu_thread *find_cpu_by_processor_chip_id(u32 id)
{
	unsigned int i;

	for (i = 0; i < num_cpu_threads(); i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;
		if (t->id->processor_chip_id == id)
			return t;
	}
	return NULL;
}

void cpu_parse(void)
{
	struct HDIF_common_hdr *paca;
	unsigned int i;

	paca = spira.ntuples.paca.addr;
	if (!HDIF_check(paca, "SPPACA")) {
		/* FIXME: PACA is deprecated in favor of PCIA */
		prerror("Invalid PACA (PCIA = %p)\n", spira.ntuples.pcia.addr);
		return;
	}

	if (spira.ntuples.paca.act_len < sizeof(*paca)) {
		prerror("PACA: invalid size %u\n",
			spira.ntuples.paca.act_len);
		return;
	}

	printf("Found %u CPUS\n", num_cpu_threads());

	cpu_threads = malloc(num_cpu_threads() * sizeof(*cpu_threads));
	if (!cpu_threads) {
		prerror("PACA: could not allocate for %u cpus\n",
			num_cpu_threads());
		return;
	}

	for (i = 0; i < num_cpu_threads(); i++) {
		u32 size;
		struct cpu_thread *t = &cpu_threads[i];

		t->timebase = HDIF_get_idata(paca, 3, &size);
		if (!t->timebase || size < sizeof(*t->timebase)) {
			prerror("CPU[%i]: bad timebase size %u @ %p\n",
				i, size, t->timebase);
			return;
		}
		t->id = HDIF_get_idata(paca, 2, &size);
		if (!t->id || size < sizeof(*t->id)) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				i, size, t->id);
			return;
		}
		t->cache = HDIF_get_idata(paca, 4, &size);
		if (!t->cache || size < sizeof(*t->cache)) {
			prerror("CPU[%i]: bad cache size %u @ %p\n",
				i, size, t->cache);
			return;
		}

		printf("CPU %i: PIR=%i RES=%i %s %s(%u threads)\n",
		       i, t->id->pir, t->id->process_interrupt_line,
		       t->id->verify_exists_flags & CPU_ID_PACA_RESERVED
		       ? "**RESERVED**" : cpu_state(t->id->verify_exists_flags),
		       t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD
		       ? "[secondary] " : "",
		       ((t->id->verify_exists_flags
			 & CPU_ID_NUM_SECONDARY_THREAD_MASK)
			>> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1);
		printf("    Cache: I=%u D=%u/%u/%u/%u\n",
		       t->cache->icache_size_kb,
		       t->cache->l1_dcache_size_kb,
		       t->cache->l2_dcache_size_kb,
		       t->cache->l3_dcache_size_kb,
		       t->cache->l35_dcache_size_kb);

		paca = (void *)paca + spira.ntuples.paca.alloc_len;
	}
	
}	
