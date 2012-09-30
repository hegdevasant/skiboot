/*
 * TODO: Index array by PIR to be able to catch them easily
 * from assembly such as machine checks etc...
 */
#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <device_tree.h>
#include <ccan/str/str.h>

/* The cpu_threads array is static and indexed by PIR in
 * order to speed up lookup from asm entry points
 */
struct cpu_thread cpu_threads[SPR_PIR_MASK + 1];
extern void *cpu_stacks[];
unsigned int cpu_max_pir;
struct cpu_thread *boot_cpu;

unsigned long cpu_secondary_start __force_data = 0;

struct cpu_job {
	struct list_node	link;
	void			(*func)(void *data);
	void			*data;
	bool			complete;
};

struct cpu_job *cpu_queue_job(struct cpu_thread *cpu,
			      void (*func)(void *data), void *data)
{
	struct cpu_job *job;

	job = zalloc(sizeof(struct cpu_job));
	if (!job)
		return NULL;
	job->func = func;
	job->data = data;
	job->complete = false;

	if (cpu != this_cpu()) {
		lock(&cpu->job_lock);
		list_add_tail(&cpu->job_queue, &job->link);
		unlock(&cpu->job_lock);
	} else {
		func(data);
		job->complete = true;
	}

	/* XXX Add poking of CPU with interrupt */

	return job;
}

bool cpu_poll_job(struct cpu_job *job)
{
	lwsync();
	return job->complete;
}

void cpu_wait_job(struct cpu_job *job, bool free_it)
{
	if (!job)
		return;

	while(!job->complete) {
		/* Handle mbox if master CPU */
		if (this_cpu() == boot_cpu)
			fsp_poll();
		else
			smt_low();
		lwsync();
	}
	lwsync();
	smt_medium();

	if (free_it)
		free(job);
}

void cpu_free_job(struct cpu_job *job)
{
	if (!job)
		return;

	assert(job->complete);
	free(job);
}

void cpu_process_jobs(void)
{
	struct cpu_thread *cpu = this_cpu();
	struct cpu_job *job;

	lock(&cpu->job_lock);
	while (true) {
		if (list_empty(&cpu->job_queue))
			break;
		smt_medium();
		job = list_pop(&cpu->job_queue, struct cpu_job, link);
		if (!job)
			break;
		unlock(&cpu->job_lock);
		job->func(job->data);
		lock(&cpu->job_lock);
		job->complete = true;
	}
	unlock(&cpu->job_lock);
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

struct cpu_thread *find_cpu_by_chip_id(u32 id)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;
		if (t->id->processor_chip_id == id)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_pir(u32 pir)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (t->pir == pir)
			return t;
	}
	return NULL;
}

struct cpu_thread *first_cpu(void)
{
	return &cpu_threads[0];
}

struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	unsigned int index = cpu - cpu_threads;

	if (index >= cpu_max_pir)
		return NULL;
	return &cpu_threads[index + 1];
}

struct cpu_thread *next_available_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && cpu->state != cpu_state_active);

	return cpu;
}

void cpu_disable_all_threads(struct cpu_thread *cpu)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (((t->pir ^ cpu->pir) & SPR_PIR_THREAD_MASK) == 0)
			t->state = cpu_state_disabled;
	}

	/* XXX Do something to actually stop the core */
}

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

bool __cpu_parse(void)
{
	struct HDIF_common_hdr *paca;
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
		struct cpu_thread *t;
		u32 size, state;
		bool is_boot_cpu;

		id = HDIF_get_idata(paca, 2, &size);
		if (!id || size < sizeof(*id)) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				i, size, id);
			return false;
		}
		if (id->pir > cpu_max_pir) {
			prerror("CPU[%i]: PIR 0x%04x out of range\n",
				i, id->pir);
			return false;
		}

		t = &cpu_threads[id->pir];
		init_lock(&t->job_lock);
		list_head_init(&t->job_queue);
		t->id = id;
		t->pir = id->pir;
		is_boot_cpu = t->pir == boot_pir;

		t->timebase = HDIF_get_idata(paca, 3, &size);
		if (!t->timebase || size < sizeof(*t->timebase)) {
			prerror("CPU[%i]: bad timebase size %u @ %p\n",
				i, size, t->timebase);
			return false;
		}

		t->cache = HDIF_get_idata(paca, 4, &size);
		if (!t->cache || size < sizeof(*t->cache)) {
			prerror("CPU[%i]: bad cache size %u @ %p\n",
				i, size, t->cache);
			return false;
		}

		printf("CPU %i: PIR=%i RES=%i %s %s(%u threads)\n",
		       i, t->id->pir, t->id->process_interrupt_line,
		       t->id->verify_exists_flags & CPU_ID_PACA_RESERVED
		       ? "**RESERVED**" : cpu_state(t->id->verify_exists_flags),
		       t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD
		       ? "[secondary] " : (is_boot_cpu ? "[boot] " : ""),
		       ((t->id->verify_exists_flags
			 & CPU_ID_NUM_SECONDARY_THREAD_MASK)
			>> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1);
		printf("    Cache: I=%u D=%u/%u/%u/%u\n",
		       t->cache->icache_size_kb,
		       t->cache->l1_dcache_size_kb,
		       t->cache->l2_dcache_size_kb,
		       t->cache->l3_dcache_size_kb,
		       t->cache->l35_dcache_size_kb);

		state = (t->id->verify_exists_flags & CPU_ID_VERIFY_MASK) >>
			CPU_ID_VERIFY_SHIFT;
		switch(state) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			t->state = cpu_state_present;
			break;
		default:
			t->state = cpu_state_unavailable;
		}

		/* Mark boot CPU */
		if (is_boot_cpu) {
			if (t->state != cpu_state_present) {
				prerror("CPU: Boot CPU unavailable !\n");
				return false;
			}
			t->state = cpu_state_active;
			t->stack = boot_stack_top;
			cpu_stacks[t->pir] = t->stack;
			__this_cpu = boot_cpu = t;
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

void add_cpu_nodes(void)
{
	struct cpu_thread *t;
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

	for_each_available_cpu(t) {
		char name[sizeof("PowerPC,POWER7@") + STR_MAX_CHARS(u32)];
		uint32_t no = t->id->process_interrupt_line;

		if (t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		/* FIXME: Don't hardcode this! */
		sprintf(name, "PowerPC,POWER7@%u", no);
		dt_begin_node(name);
		*strchr(name, '@') = '\0';
		dt_property_string("name", name);
		dt_property_string("device-type", "cpu");
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
				 t->cache->dcache_block_size);
		dt_property_cell("i-cache-block-size",
				 t->cache->icache_block_size);
		dt_property_cell("d-cache-size",
				 t->cache->l1_dcache_size_kb*1024);
		dt_property_cell("i-cache-size",
				 t->cache->icache_size_kb*1024);

		if (t->cache->icache_line_size != t->cache->icache_block_size)
			dt_property_cell("i-cache-line-size",
					 t->cache->icache_line_size);
		if (t->cache->l1_dcache_line_size !=
		    t->cache->dcache_block_size)
			dt_property_cell("d-cache-line-size",
					 t->cache->l1_dcache_line_size);
		dt_property_cell("clock-frequency",
				 t->timebase->actual_clock_speed);

		/* FIXME: Hardcoding is bad. */
		dt_property_cell("timebase-frequency", 512000);
		dt_end_node();
	}
	dt_end_node();
}

void cpu_bringup(void)
{
	struct cpu_thread *t;

	printf("CPU: Allocating secondary CPU stacks\n");

	op_display(OP_LOG, OP_MOD_CPU, 0x0000);

	/* Alloc all stacks for functional CPUs and count available ones */
	for_each_cpu(t) {
		void *stack;

		if (t->state != cpu_state_present)
			continue;
		stack = memalign(16, STACK_SIZE);
		if (!stack) {
			prerror("CPU: Failed to allocate stack !\n");
			t->state = cpu_state_unavailable;
			break;
		}
		cpu_stacks[t->pir] = t->stack = stack + STACK_SIZE - 256;
	}

	op_display(OP_LOG, OP_MOD_CPU, 0x0001);

	/* Tell everybody to chime in ! */	
	printf("CPU: Calling in all processors...\n");
	cpu_secondary_start = 1;
	sync();

	op_display(OP_LOG, OP_MOD_CPU, 0x0002);

	for_each_cpu(t) {
		if (t->state != cpu_state_present &&
		    t->state != cpu_state_active)
			continue;

		/* Add a callin timeout ? */
		while (t->state != cpu_state_active) {
			smt_very_low();
			sync();
		}
	}

	op_display(OP_LOG, OP_MOD_CPU, 0x0003);
}

void cpu_callin(struct cpu_thread *cpu)
{
	cpu->state = cpu_state_active;
}
