/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
/*
 * TODO: Index array by PIR to be able to catch them easily
 * from assembly such as machine checks etc...
 */
#include <skiboot.h>
#include <cpu.h>
#include <fsp.h>
#include <device.h>
#include <opal.h>
#include <stack.h>
#include <ccan/str/str.h>
#include <ccan/container_of/container_of.h>

/* The cpu_threads array is static and indexed by PIR in
 * order to speed up lookup from asm entry points
 */
struct cpu_stack {
	union {
		uint8_t	stack[STACK_SIZE];
		struct cpu_thread cpu;
	};
} __align(STACK_SIZE);

static struct cpu_stack *cpu_stacks = (struct cpu_stack *)CPU_STACKS_BASE;
unsigned int cpu_thread_count;
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

void *cpu_stack_bottom(unsigned int pir)
{
	return (void *)&cpu_stacks[pir] + sizeof(struct cpu_thread);
}

void *cpu_stack_top(unsigned int pir)
{
	/* This is the top of the MC stack which is above the normal
	 * stack, which means a SP between cpu_stack_bottom() and
	 * cpu_stack_top() can either be a normal stack pointer or
	 * a Machine Check stack pointer
	 */
	return (void *)&cpu_stacks[pir] + STACK_SIZE - STACK_TOP_GAP;
}

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

struct dt_node *get_cpu_node(u32 pir)
{
	struct cpu_thread *t = find_cpu_by_pir(pir);

	return t ? t->node : NULL;
}

/* This only covers primary, active cpus */
struct cpu_thread *find_cpu_by_chip_id(u32 chip_id)
{
	struct cpu_thread *t;

	for_each_available_cpu(t) {
		if (t->is_secondary)
			continue;
		if (t->chip_id == chip_id)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_node(struct dt_node *cpu)
{
	struct cpu_thread *t;

	for_each_available_cpu(t) {
		if (t->node == cpu)
			return t;
	}
	return NULL;
}

struct cpu_thread *find_cpu_by_pir(u32 pir)
{
	if (pir > cpu_max_pir)
		return NULL;
	return &cpu_stacks[pir].cpu;
}

struct cpu_thread *find_cpu_by_server(u32 server_no)
{
	struct cpu_thread *t;

	for_each_cpu(t) {
		if (t->server_no == server_no)
			return t;
	}
	return NULL;
}

struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	struct cpu_stack *s = container_of(cpu, struct cpu_stack, cpu);
	unsigned int index;

	if (cpu == NULL)
		index = 0;
	else
		index = s - cpu_stacks + 1;
	for (; index <= cpu_max_pir; index++) {
		cpu = &cpu_stacks[index].cpu;
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

void cpu_remove_node(const struct cpu_thread *t)
{
	struct dt_node *i;

	/* Find this cpu node */
	dt_for_each_node(dt_root, i) {
		const struct dt_property *p;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;
		p = dt_find_property(i, "ibm,pir");
		if (dt_property_get_cell(p, 0) == t->pir) {
			dt_free(i);
			return;
		}
	}
	prerror("CPU: Could not find cpu node %i to remove!\n", t->pir);
	abort();
}

void cpu_disable_all_threads(struct cpu_thread *cpu)
{
	unsigned int i;

	for (i = 0; i <= cpu_max_pir; i++) {
		struct cpu_thread *t = &cpu_stacks[i].cpu;

		if (t->primary == cpu->primary)
			t->state = cpu_state_disabled;
	}

	/* XXX Do something to actually stop the core */
}

static void init_cpu_thread(struct cpu_thread *t,
			    enum cpu_thread_state state,
			    unsigned int pir)
{
	init_lock(&t->job_lock);
	list_head_init(&t->job_queue);
	t->state = state;
	t->pir = pir;
	assert(pir == container_of(t, struct cpu_stack, cpu) - cpu_stacks);
}

void init_boot_cpu(void)
{
	unsigned int i, pir;

	pir = mfspr(SPR_PIR);

	/* Get a CPU thread count and an initial max PIR based on PVR */
	switch(PVR_TYPE(mfspr(SPR_PVR))) {
	case PVR_TYPE_P7:
	case PVR_TYPE_P7P:
		cpu_thread_count = 4;
		cpu_max_pir = SPR_PIR_P7_MASK;
		proc_gen = proc_gen_p7;
		break;
	case PVR_TYPE_P8:
		cpu_thread_count = 8;
		cpu_max_pir = SPR_PIR_P8_MASK;
		proc_gen = proc_gen_p8;
		break;
	default:
		prerror("CPU: Unknown PVR, assuming 1 thread\n");
		cpu_thread_count = 1;
		cpu_max_pir = mfspr(SPR_PIR);
		proc_gen = proc_gen_unknown;
	}

	printf("CPU: Boot CPU PIR is 0x%04x\n", pir);
	printf("CPU: Initial max PIR set to 0x%x\n", cpu_max_pir);
	printf("CPU: Assuming max %d threads per core\n", cpu_thread_count);

	/* Clear the CPU structs */
	for (i = 0; i <= cpu_max_pir; i++)
		memset(&cpu_stacks[i].cpu, 0, sizeof(struct cpu_thread));

	/* Setup boot CPU state */
	boot_cpu = &cpu_stacks[pir].cpu;
	init_cpu_thread(boot_cpu, cpu_state_active, pir);
	assert(this_cpu() == boot_cpu);
}

void init_all_cpus(void)
{
	struct dt_node *cpus, *cpu;
	unsigned int thread, new_max_pir = 0;

	cpus = dt_find_by_path(dt_root, "/cpus");
	assert(cpus);

	/* Iterate all CPUs in the device-tree */
	dt_for_each_child(cpus, cpu) {
		unsigned int pir, server_no, chip_id;
		enum cpu_thread_state state;
		const struct dt_property *p;
		struct cpu_thread *t, *pt;

		/* Skip cache nodes */
		if (strcmp(dt_prop_get(cpu, "device_type"), "cpu"))
			continue;

		server_no = dt_prop_get_u32(cpu, "reg");

		/* If PIR property is absent, assume it's the same as the
		 * server number
		 */
		pir = dt_prop_get_u32_def(cpu, "ibm,pir", server_no);

		/* If the chip ID is absent, assume 0 */
		chip_id = dt_prop_get_u32_def(cpu, "ibm,chip_id", 0);

		/* Only use operational CPUs */
		if (!strcmp(dt_prop_get(cpu, "status"), "okay"))
			state = cpu_state_present;
		else
			state = cpu_state_unavailable;

		printf("CPU: CPU from DT PIR=0x%04x Server#=0x%x State=%d\n",
		       pir, server_no, state);

		/* Setup thread 0 */
		t = pt = &cpu_stacks[pir].cpu;
		if (t != boot_cpu)
			init_cpu_thread(t, state, pir);
		t->server_no = server_no;
		t->primary = t;
		t->node = cpu;
		t->chip_id = chip_id;

		/* Adjust max PIR */
		if (new_max_pir < (pir + cpu_thread_count - 1))
			new_max_pir = pir + cpu_thread_count - 1;

		/* Iterate threads */
		p = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		if (!p)
			continue;
		for (thread = 1; thread < (p->len / 4); thread++) {
			printf("CPU:   secondary thread %d found\n", thread);
			t = &cpu_stacks[pir + thread].cpu;
			init_cpu_thread(t, state, pir + thread);
			t->server_no = ((u32 *)p->prop)[thread];
			t->is_secondary = true;
			t->primary = pt;
			t->node = cpu;
			t->chip_id = chip_id;
		}
	}
	cpu_max_pir = new_max_pir;
	printf("CPU: New max PIR set to 0x%x\n", new_max_pir);
}

void cpu_bringup(void)
{
	struct cpu_thread *t;

	printf("CPU: Setting up secondary CPU state\n");

	op_display(OP_LOG, OP_MOD_CPU, 0x0000);

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

	printf("CPU: All processors called in...\n");

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

int64_t opal_start_cpu_thread(uint64_t server_no, uint64_t start_address)
{
	struct cpu_thread *cpu;
	struct cpu_job *job;

	cpu = find_cpu_by_server(server_no);
	if (!cpu) {
		prerror("OPAL: Start invalid CPU 0x%04llx !\n", server_no);
		return OPAL_PARAMETER;
	}
	printf("OPAL: Start CPU 0x%04llx (PIR 0x%04x) -> 0x%016llx\n",
	       server_no, cpu->pir, start_address);

	if (cpu->state != cpu_state_active) {
		prerror("OPAL: CPU not active in OPAL !\n");
		return OPAL_WRONG_STATE;
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

int64_t opal_query_cpu_status(uint64_t server_no, uint8_t *thread_status)
{
	struct cpu_thread *cpu;

	cpu = find_cpu_by_server(server_no);
	if (!cpu) {
		prerror("OPAL: Query invalid CPU 0x%04llx !\n", server_no);
		return OPAL_PARAMETER;
	}
	printf("OPAL: Query CPU 0x%04llx (PIR 0x%04x) state...\n",
	       server_no, cpu->pir);

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
