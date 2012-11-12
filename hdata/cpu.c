#include <skiboot.h>
#include <spira.h>
#include <cpu.h>
#include <fsp.h>
#include <device_tree.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <device.h>

#define for_each_paca(p)						\
	for (p = spira.ntuples.paca.addr;				\
	     (void *)p < spira.ntuples.paca.addr			\
	     + (spira.ntuples.paca.act_cnt				\
		* spira.ntuples.paca.alloc_len);			\
	     p = (void *)p + spira.ntuples.paca.alloc_len)

static unsigned int paca_index(const struct HDIF_common_hdr *paca)
{
	return ((void *)paca - spira.ntuples.paca.addr)
		/ spira.ntuples.paca.alloc_len;
}

static void cpu_find_max_pir(void)
{
	const struct HDIF_common_hdr *paca;

	/* Iterate all PACAs to locate the highest PIR value */
	for_each_paca(paca) {
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

static struct cpu_thread *populate_cpu_thread(const struct HDIF_cpu_id *id,
					      unsigned int index)
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
		printf("CPU[%i]: PIR=%i RES=%i OK\n",
		       index, id->pir, id->process_interrupt_line);
		t->state = cpu_state_present;
		break;
	default:
		printf("CPU[%i]: PIR=%i RES=%i UNAVAILABLE\n",
		       index, id->pir, id->process_interrupt_line);
		t->state = cpu_state_unavailable;
	}
	return t;
}

static struct dt_node *add_cpu_node(struct dt_node *cpus,
				 const struct HDIF_common_hdr *paca,
				 const struct HDIF_cpu_id *id)
{
	static const uint32_t p7_sps[] = {
		0x0c, 0x000, 1, 0x0c, 0x0000,
		0x18, 0x100, 1,	0x18, 0x0000,
		0x14, 0x111, 1, 0x14, 0x0002,
		0x22, 0x120, 1, 0x22, 0x0003,
	};
	static const uint32_t p7_pss[] = {
		0x1c, 0x28, 0xffffffff, 0xffffffff
	};
	const struct HDIF_cpu_timebase *timebase;
	const struct HDIF_cpu_cache *cache;
	u32 no, size;
	char name[sizeof("PowerPC,POWER7@") + STR_MAX_CHARS(no)];
	struct dt_node *cpu;

	/* We use the process_interrupt_line as the res id */
	no = id->process_interrupt_line;

	printf("CPU[%i]: PIR=%i RES=%i %s %s(%u threads)\n",
	       paca_index(paca), id->pir, no,
	       id->verify_exists_flags & CPU_ID_PACA_RESERVED
	       ? "**RESERVED**" : cpu_state(id->verify_exists_flags),
	       id->verify_exists_flags & CPU_ID_SECONDARY_THREAD
	       ? "[secondary] " : 
	       (id->pir == boot_cpu->pir ? "[boot] " : ""),
	       ((id->verify_exists_flags
		 & CPU_ID_NUM_SECONDARY_THREAD_MASK)
		>> CPU_ID_NUM_SECONDARY_THREAD_SHIFT) + 1);

	timebase = HDIF_get_idata(paca, 3, &size);
	if (!timebase || size < sizeof(*timebase)) {
		prerror("CPU[%i]: bad timebase size %u @ %p\n",
			paca_index(paca), size, timebase);
		return NULL;
	}

	cache = HDIF_get_idata(paca, 4, &size);
	if (!cache || size < sizeof(*cache)) {
		prerror("CPU[%i]: bad cache size %u @ %p\n",
			paca_index(paca), size, cache);
		return NULL;
	}

	printf("    Cache: I=%u D=%u/%u/%u/%u\n",
	       cache->icache_size_kb,
	       cache->l1_dcache_size_kb,
	       cache->l2_dcache_size_kb,
	       cache->l3_dcache_size_kb,
	       cache->l35_dcache_size_kb);

	/* FIXME: Don't hardcode this! */
	sprintf(name, "PowerPC,POWER7@%u", no);
	cpu = dt_new(cpus, name);
	*strchr(name, '@') = '\0';
	dt_add_property_string(cpu, "name", name);
	dt_add_property_string(cpu, "device_type", "cpu");
	dt_add_property_string(cpu, "status", "okay");
	dt_add_property_cell(cpu, "reg", no);
	dt_add_property(cpu, "ibm,segment-page-sizes", p7_sps, sizeof(p7_sps));
	dt_add_property(cpu, "ibm,processor-segment-sizes",
			p7_pss, sizeof(p7_pss));
	/* We append the secondary cpus in __cpu_parse */
	dt_add_property_cell(cpu, "ibm,ppc-interrupt-server#s", no);
	dt_add_property_cell(cpu, "ibm,slb-size", 0x20);
	dt_add_property_cell(cpu, "ibm,vmx", 0x2);

	dt_add_property_cell(cpu, "d-cache-block-size", cache->dcache_block_size);
	dt_add_property_cell(cpu, "i-cache-block-size", cache->icache_block_size);
	dt_add_property_cell(cpu, "d-cache-size", cache->l1_dcache_size_kb*1024);
	dt_add_property_cell(cpu, "i-cache-size", cache->icache_size_kb*1024);

	if (cache->icache_line_size != cache->icache_block_size)
		dt_add_property_cell(cpu, "i-cache-line-size",
				  cache->icache_line_size);
	if (cache->l1_dcache_line_size != cache->dcache_block_size)
		dt_add_property_cell(cpu, "d-cache-line-size",
				  cache->l1_dcache_line_size);
	dt_add_property_cell(cpu, "clock-frequency",
			  timebase->actual_clock_speed * 1000000);

	/* FIXME: Hardcoding is bad. */
	dt_add_property_cell(cpu, "timebase-frequency", 512000000);

	dt_add_property_cell(cpu, DT_PRIVATE "hw_proc_id",
			     id->hardware_proc_id);
	return cpu;
}

static struct dt_node *dt_root;

void early_init_boot_cpu_thread(void)
{
	const struct HDIF_common_hdr *paca = spira.ntuples.paca.addr;
	const struct HDIF_cpu_id *id = NULL;
	uint32_t boot_pir = mfspr(SPR_PIR);
	struct cpu_thread *t;
	struct dt_node *cpus, *cpu;

	dt_root = dt_new_root("cpus-root");
	cpus = dt_new(dt_root, "cpus");
	dt_add_property_cell(cpus, "#address-cells", 2);
	dt_add_property_cell(cpus, "#size-cells", 1);

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

	for_each_paca(paca) {
		u32 size;

		id = HDIF_get_idata(paca, 2, &size);

		/* The ID structure on Blade314 is only 0x54 long. We can
		 * cope with it as we don't use all the additional fields.
		 * The minimum size we support is  0x40
		 */
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				paca_index(paca), size, id);
			abort();
		}
		if (id->pir == boot_pir)
			break;
	}

	if (paca_index(paca) == spira.ntuples.paca.act_cnt) {
		prerror("Boot cpu PIR %u not found!\n", boot_pir);
		abort();
	}

	cpu = add_cpu_node(cpus, paca, id);
	if (!cpu)
		abort();

	t = populate_cpu_thread(id, paca_index(paca));
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

static struct dt_node *find_cpus(void)
{
	struct dt_node *cpus;

	/* Find our cpus node */
	for (cpus = dt_first(dt_root); cpus; cpus = dt_next(dt_root, cpus)) {
		if (streq(cpus->name, "cpus"))
			break;
	}
	assert(cpus);
	return cpus;
}

static struct dt_node *find_cpu_by_hardware_proc_id(struct dt_node *root,
						 u32 hw_proc_id)
{
	struct dt_node *i;

	for (i = dt_first(root); i; i = dt_next(root, i)) {
		struct dt_property *prop;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;

		prop = dt_find_property(i, DT_PRIVATE "hw_proc_id");
		if (*(u32 *)prop->prop == hw_proc_id)
			return i;
	}
	return NULL;
}

/* Note that numbers are small. */
static void add_u32_sorted(u32 arr[], u32 new, unsigned num)
{
	unsigned int i;

	/* Walk until we find where we belong (insertion sort). */
	for (i = 0; i < num; i++) {
		if (new < arr[i]) {
			u32 tmp = arr[i];
			arr[i] = new;
			new = tmp;
		}
	}
	arr[i] = new;
}

static bool __cpu_parse(void)
{
	const struct HDIF_common_hdr *paca;
	uint32_t boot_pir = mfspr(SPR_PIR);
	struct dt_node *cpus = find_cpus();

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

	for_each_paca(paca) {
		const struct HDIF_cpu_id *id;
		u32 size;

		id = HDIF_get_idata(paca, 2, &size);

		/* The ID structure on Blade314 is only 0x54 long. We can
		 * cope with it as we don't use all the additional fields.
		 * The minimum size we support is  0x40
		 */
		if (!id || size < SPIRA_CPU_ID_MIN_SIZE) {
			prerror("CPU[%i]: bad id size %u @ %p\n",
				paca_index(paca), size, id);
			return false;
		}
		if (id->pir > cpu_max_pir) {
			prerror("CPU[%i]: PIR 0x%04x out of range\n",
				paca_index(paca), id->pir);
			return false;
		}

		/* This one is already done. */
		if (id->pir == boot_pir)
			continue;

		if (!populate_cpu_thread(id, paca_index(paca)))
			return false;

		/* Only cpus we found. */
		if (cpu_threads[id->pir].state != cpu_state_present)
			continue;

		/* Secondary threads don't get their own node. */
		if (id->verify_exists_flags & CPU_ID_SECONDARY_THREAD)
			continue;

		if (!add_cpu_node(cpus, paca, id))
			return false;
	}

	/* Now account for secondaries. */
	for_each_paca(paca) {
		const struct HDIF_cpu_id *id;
		u32 size, state, num;
		struct dt_node *cpu;
		struct dt_property *prop;
		u32 *new_prop;

		id = HDIF_get_idata(paca, 2, &size);
		state = (id->verify_exists_flags & CPU_ID_VERIFY_MASK) >>
			CPU_ID_VERIFY_SHIFT;
		switch (state) {
		case CPU_ID_VERIFY_USABLE_NO_FAILURES:
		case CPU_ID_VERIFY_USABLE_FAILURES:
			break;
		default:
			continue;
		}

		/* Only interested in secondary threads. */
		if (!(id->verify_exists_flags & CPU_ID_SECONDARY_THREAD))
			continue;

		cpu = find_cpu_by_hardware_proc_id(cpus,
						   id->hardware_proc_id);
		if (!cpu) {
			prerror("CPU[%i]: could not find primary hwid %i\n",
				paca_index(paca), id->hardware_proc_id);
			return false;
		}

		/* Add the cpu #. */
		prop = dt_find_property(cpu, "ibm,ppc-interrupt-server#s");
		num = prop->len / sizeof(u32);
		new_prop = malloc((num + 1) * sizeof(u32));
		if (!new_prop) {
			prerror("Property allocation length %lu failed\n",
				(num + 1) * sizeof(u32));
			return false;
		}
		memcpy(new_prop, prop->prop, prop->len);
		add_u32_sorted(new_prop, id->process_interrupt_line, num);
		dt_del_property(cpu, prop);
		dt_add_property(cpu, "ibm,ppc-interrupt-server#s",
				new_prop, (num + 1) * sizeof(u32));
		free(new_prop);
	}
	return true;
}	

/* FIXME: Move this out to core/cpu.c */
void cpu_remove_node(const struct cpu_thread *t)
{
	struct dt_node *cpus, *i;

	cpus = find_cpus();

	/* Find this cpu node */
	for (i = dt_first(cpus); i; i = dt_next(cpus, i)) {
		struct dt_property *p;

		if (!dt_has_node_property(i, "device_type", "cpu"))
			continue;
		p = dt_find_property(i, "reg");
		if (dt_property_get_cell(p, 0) == t->id->process_interrupt_line) {
			dt_free(i);
			return;
		}
	}
	prerror("CPU: Could not find cpu node %i to remove!\n",
		t->id->process_interrupt_line);
	abort();
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
	struct dt_node *cpus, *i;
	struct dt_property *p;

	cpus = find_cpus();

	dt_begin_node(cpus->name);
	list_for_each(&cpus->properties, p, list)
		dt_property(p->name, p->prop, p->len);

	/* This only works because the tree under cpus is flat. */
	for (i = dt_first(cpus); i; i = dt_next(cpus, i)) {
		dt_begin_node(i->name);
		list_for_each(&i->properties, p, list)
			dt_property(p->name, p->prop, p->len);
		dt_end_node();
	}
	dt_end_node();
	return true;
}
