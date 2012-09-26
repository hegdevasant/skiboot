/*
 * TODO: Index array by PIR to be able to catch them easily
 * from assembly such as machine checks etc...
 */
#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>

struct cpu_thread *cpu_threads;
unsigned int cpu_threads_count;
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

u32 num_cpu_threads(void)
{
	return cpu_threads_count;
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

	for (i = 0; i < num_cpu_threads(); i++) {
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

	for (i = 0; i < num_cpu_threads(); i++) {
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

	if (index >= cpu_threads_count)
		return NULL;
	return &cpu_threads[index + 1];
}

struct cpu_thread *next_available_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && cpu->state != cpu_state_boot &&
		cpu->state != cpu_state_idle);
	return cpu;
}

void cpu_disable_all_threads(struct cpu_thread *cpu)
{
	unsigned int i;

	for (i = 0; i < num_cpu_threads(); i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (((t->pir ^ cpu->pir) & SPR_PIR_THREAD_MASK) == 0)
			t->state = cpu_state_disabled;
	}

	/* XXX Do something to actually stop the core */
}

bool __cpu_parse(void)
{
	struct HDIF_common_hdr *paca;
	unsigned int i;
	uint32_t boot_pir = mfspr(SPR_PIR);

	paca = spira.ntuples.paca.addr;
	if (!HDIF_check(paca, "SPPACA")) {
		/* FIXME: PACA is deprecated in favor of PCIA */
		prerror("Invalid PACA (PCIA = %p)\n", spira.ntuples.pcia.addr);
		op_display(OP_FATAL, OP_MOD_CPU, 0);
		return false;
	}

	if (spira.ntuples.paca.act_len < sizeof(*paca)) {
		prerror("PACA: invalid size %u\n",
			spira.ntuples.paca.act_len);
		op_display(OP_FATAL, OP_MOD_CPU, 0);
		return false;
	}

	cpu_threads_count = spira.ntuples.paca.act_cnt;

	printf("CPU: Found %u CPUS\n", num_cpu_threads());

	cpu_threads = zalloc(cpu_threads_count * sizeof(*cpu_threads));
	if (!cpu_threads) {
		prerror("PACA: could not allocate for %u cpus\n",
			num_cpu_threads());
		op_display(OP_FATAL, OP_MOD_CPU, 1);
		return false;
	}

	for (i = 0; i < num_cpu_threads(); i++) {
		u32 size, state;
		struct cpu_thread *t = &cpu_threads[i];
		bool is_boot_cpu;

		init_lock(&t->job_lock);
		list_head_init(&t->job_queue);

		t->timebase = HDIF_get_idata(paca, 3, &size);
		if (!t->timebase || size < sizeof(*t->timebase)) {
			prerror("CPU[%i]: bad timebase size %u @ %p\n",
				i, size, t->timebase);
			op_display(OP_FATAL, OP_MOD_CPU, 2);
			return false;
		}
		t->id = HDIF_get_idata(paca, 2, &size);
		if (!t->id || size < sizeof(*t->id)) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				i, size, t->id);
			op_display(OP_FATAL, OP_MOD_CPU, 3);
			return false;
		}
		t->pir = t->id->pir;
		is_boot_cpu = t->pir == boot_pir;

		t->cache = HDIF_get_idata(paca, 4, &size);
		if (!t->cache || size < sizeof(*t->cache)) {
			prerror("CPU[%i]: bad cache size %u @ %p\n",
				i, size, t->cache);
			op_display(OP_FATAL, OP_MOD_CPU, 5);
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
			t->state = cpu_state_available;
			break;
		default:
			t->state = cpu_state_unavailable;
		}

		/* Mark boot CPU */
		if (is_boot_cpu) {
			if (t->state != cpu_state_available) {
				prerror("CPU: Boot CPU unavailable !\n");
				op_display(OP_FATAL, OP_MOD_CPU, 4);
			}
			t->state = cpu_state_boot;
			t->stack = boot_stack_top;
			mtspr(SPR_HSPRG0, (uint64_t)t);
			boot_cpu = t;
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

void cpu_bringup(void)
{
	unsigned int i;

	printf("CPU: Allocating secondary CPU stacks\n");

	/* Alloc all stacks for functional CPUs and count available ones */
	for (i = 0; i < num_cpu_threads(); i++) {
		struct cpu_thread *t = &cpu_threads[i];
		void *stack;

		if (t->state != cpu_state_available)
			continue;
		stack = memalign(16, STACK_SIZE);
		if (!stack) {
			prerror("CPU: Failed to allocate stack !\n");
			t->state = cpu_state_unavailable;
			break;
		}
		t->stack = stack + STACK_SIZE - 256;
	}

	/* Tell everybody to chime in ! */	
	printf("CPU: Calling in all processors...\n");
	cpu_secondary_start = 1;
	sync();

	for (i = 0; i < num_cpu_threads(); i++) {
		struct cpu_thread *t = &cpu_threads[i];
		
		if (t->state != cpu_state_available &&
		    t->state != cpu_state_idle)
			continue;

		/* Add a callin timeout ? */
		while (t->state != cpu_state_idle) {
			smt_very_low();
			sync();
		}
	}
}

void cpu_callin(struct cpu_thread *cpu)
{
	cpu->state = cpu_state_idle;
}
