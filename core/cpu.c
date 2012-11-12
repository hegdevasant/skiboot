/*
 * TODO: Index array by PIR to be able to catch them easily
 * from assembly such as machine checks etc...
 */
#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <device_tree.h>
#include <opal.h>
#include <ccan/str/str.h>

/* The cpu_threads array is static and indexed by PIR in
 * order to speed up lookup from asm entry points
 */
struct cpu_thread cpu_threads[SPR_PIR_MASK + 1];
unsigned int cpu_max_pir;
struct cpu_thread *boot_cpu;

unsigned long cpu_secondary_start __force_data = 0;

struct cpu_job {
	struct list_node	link;
	void			(*func)(void *data);
	void			*data;
	bool			complete;
	bool		        no_return;
};

struct cpu_job *__cpu_queue_job(struct cpu_thread *cpu,
				void (*func)(void *data), void *data,
				bool no_return)
{
	struct cpu_job *job;

	if (cpu->state != cpu_state_active) {
		prerror("CPU: Tried to queue job on unavailable CPU 0x%04x\n",
			cpu->pir);
		return NULL;
	}

	job = zalloc(sizeof(struct cpu_job));
	if (!job)
		return NULL;
	job->func = func;
	job->data = data;
	job->complete = false;
	job->no_return = no_return;

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

struct cpu_job *cpu_queue_job(struct cpu_thread *cpu,
			      void (*func)(void *data), void *data)
{
	return __cpu_queue_job(cpu, func, data, false);
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
	void (*func)(void *);
	void *data;

	sync();
	if (list_empty(&cpu->job_queue))
		return;

	lock(&cpu->job_lock);
	while (true) {
		if (list_empty(&cpu->job_queue))
			break;
		smt_medium();
		job = list_pop(&cpu->job_queue, struct cpu_job, link);
		if (!job)
			break;
		func = job->func;
		data = job->data;
		unlock(&cpu->job_lock);
		if (job->no_return)
			free(job);
		func(data);
		lock(&cpu->job_lock);
		job->complete = true;
	}
	unlock(&cpu->job_lock);
}

struct cpu_thread *find_cpu_by_chip_id(u32 id)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (t->state == cpu_state_no_cpu)
			continue;
		if (t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;
		if (t->id->processor_chip_id == id)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_active_cpu_by_chip_id(u32 id)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_threads[i];

		if (t->state != cpu_state_active)
			continue;
		if (t->id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;
		if (t->id->processor_chip_id == id)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_pir(u32 pir)
{
	if (pir > cpu_max_pir)
		return NULL;
	return &cpu_threads[pir];
}

struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	unsigned int index;

	if (cpu == NULL)
		index = 0;
	else
		index = cpu - cpu_threads + 1;
	for (; index <= cpu_max_pir; index++) {
		cpu = &cpu_threads[index];
		if (cpu->state != cpu_state_no_cpu)
			return cpu;
	}
	return NULL;
}

struct cpu_thread *first_cpu(void)
{
	return next_cpu(NULL);
}

struct cpu_thread *next_available_cpu(struct cpu_thread *cpu)
{
	do {
		cpu = next_cpu(cpu);
	} while(cpu && cpu->state != cpu_state_active);

	return cpu;
}

struct cpu_thread *first_available_cpu(void)
{
	return next_available_cpu(NULL);
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

struct cpu_thread *init_cpu_thread(u32 pir, enum cpu_thread_state state,
				   const struct HDIF_cpu_id *id)
{
	struct cpu_thread *t;

	t = &cpu_threads[pir];
	init_lock(&t->job_lock);
	list_head_init(&t->job_queue);
	t->pir = pir;
	t->state = state;
	assert(pir == id->pir);
	t->id = id;

	return t;
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
			cpu_remove_node(t);
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

		/* Add a callin timeout ?  If so, call cpu_remove_node(t). */
		while (t->state != cpu_state_active) {
			smt_very_low();
			sync();
		}
		smt_medium();
	}

	op_display(OP_LOG, OP_MOD_CPU, 0x0003);
}

void cpu_callin(struct cpu_thread *cpu)
{
	cpu->state = cpu_state_active;
}

static void opal_start_thread_job(void *data)
{
	cpu_give_self_os();

	/* We do not return, so let's mark the job as
	 * complete
	 */
	start_kernel_secondary((uint64_t)data);
}

int64_t opal_start_cpu_thread(uint64_t pir, uint64_t start_address)
{
	struct cpu_thread *cpu;
	struct cpu_job *job;

	printf("OPAL: Start CPU 0x%04llx -> 0x%016llx\n", pir, start_address);

	cpu = find_cpu_by_pir(pir);
	if (!cpu) {
		prerror("OPAL: Invalid CPU !\n");
		return OPAL_PARAMETER;
	}
	if (cpu->state != cpu_state_active) {
		prerror("OPAL: CPU not active in OPAL !\n");
		return OPAL_PARAMETER;
	}
	job = __cpu_queue_job(cpu, opal_start_thread_job, (void *)start_address,
			      true);
	if (!job) {
		prerror("OPAL: Failed to create CPU start job !\n");
		return OPAL_INTERNAL_ERROR;
	}
	return OPAL_SUCCESS;
}
opal_call(OPAL_START_CPU, opal_start_cpu_thread);

int64_t opal_query_cpu_status(uint64_t pir, uint8_t *thread_status)
{
	struct cpu_thread *cpu;

	cpu = find_cpu_by_pir(pir);
	if (!cpu) {
		prerror("OPAL: Invalid CPU !\n");
		return OPAL_PARAMETER;
	}
	if (cpu->state != cpu_state_active && cpu->state != cpu_state_os) {
		prerror("OPAL: CPU not active in OPAL nor OS !\n");
		return OPAL_PARAMETER;
	}
	if (cpu->state == cpu_state_os)
		*thread_status = OPAL_THREAD_STARTED;
	else
		*thread_status = OPAL_THREAD_INACTIVE;

	return OPAL_SUCCESS;
}
opal_call(OPAL_QUERY_CPU_STATUS, opal_query_cpu_status);
