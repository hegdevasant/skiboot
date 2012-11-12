#ifndef __CPU_H
#define __CPU_H

#include <hdif.h>
#include <processor.h>
#include <ccan/list/list.h>
#include <lock.h>

/* This is the array of all threads. */
struct HDIF_cpu_id {
	u32 pir;
	u32 fru_id;
	u32 hardware_proc_id;
#define CPU_ID_VERIFY_MASK			0xC0000000
#define CPU_ID_VERIFY_SHIFT			30
#define CPU_ID_VERIFY_USABLE_NO_FAILURES	0
#define CPU_ID_VERIFY_USABLE_FAILURES		1
#define CPU_ID_VERIFY_NOT_INSTALLED		2
#define CPU_ID_VERIFY_UNUSABLE			3
#define CPU_ID_SECONDARY_THREAD			0x20000000
#define CPU_ID_PACA_RESERVED			0x10000000
#define CPU_ID_NUM_SECONDARY_THREAD_MASK	0x00FF0000
#define CPU_ID_NUM_SECONDARY_THREAD_SHIFT	16
	u32 verify_exists_flags;
	u32 chip_ec_level;
	u32 processor_chip_id;
	u32 logical_processor_id;
	/* This is the resource number, too. */
	u32 process_interrupt_line;
	u32 reserved1;
	u32 hardware_module_id;
	u64 ibase;
	u32 deprecated1;
	u32 physical_thread_id;
	u32 deprecated2;
	u32 ccm_node_id;
	/* This fields are not always present, check struct size */
#define SPIRA_CPU_ID_MIN_SIZE	0x40
	u32 hw_card_id;
	u32 internal_drawer_node_id;
	u32 drawer_book_octant_blade_id;
	u32 memory_interleaving_scope;
	u32 lco_target;
};

struct HDIF_cpu_timebase {
	u32 cycle_time;
	u32 time_base;
	u32 actual_clock_speed;
	u32 memory_bus_frequency;
};

struct HDIF_cpu_cache {
	u32 icache_size_kb;
	u32 icache_line_size;
	u32 l1_dcache_size_kb;
	u32 l1_dcache_line_size;
	u32 l2_dcache_size_kb;
	u32 l2_line_size;
	u32 l3_dcache_size_kb;
	u32 l3_line_size;
	u32 dcache_block_size;
	u32 icache_block_size;
	u32 dcache_assoc_sets;
	u32 icache_assoc_sets;
	u32 dtlb_entries;
	u32 dtlb_assoc_sets;
	u32 itlb_entries;
	u32 itlb_assoc_sets;
	u32 reservation_size;
	u32 l2_cache_assoc_sets;
	u32 l35_dcache_size_kb;
	u32 l35_cache_line_size;
};	

/*
 * cpu_thread is our internal structure representing each
 * thread in the system
 */

enum cpu_thread_state {
	cpu_state_no_cpu	= 0,	/* Nothing there */
	cpu_state_unknown,		/* In PACA, not called in yet */
	cpu_state_unavailable,		/* Not available */
	cpu_state_present,		/* Assumed to spin in asm entry */
	cpu_state_active,		/* Secondary called in */
	cpu_state_os,			/* Under OS control */
	cpu_state_disabled,		/* Disabled by us due to error */
};

struct cpu_job;

struct cpu_thread {
	uint32_t		pir;
	enum cpu_thread_state	state;
	void			*stack;

	struct lock		job_lock;
	struct list_head	job_queue;

	/* SPIRA structures */
	const struct HDIF_cpu_id *id;
};

/* This global is set to 1 to allow secondaries to callin,
 * typically set after the primary has allocated the cpu_thread
 * array and stacks
 */
extern unsigned long cpu_secondary_start;

/* Boot CPU, set after early_init_boot_cpu_thread(). */
extern struct cpu_thread *boot_cpu;

/* This sets up the cpu_thread structure for the boot cpu. */
extern void early_init_boot_cpu_thread(void);

/* This sets up the cpu_thread structures for everyone else. */
extern void cpu_parse(void);

/* This brings up our secondaries */
extern void cpu_bringup(void);

/* This is called by secondaries as they call in */
extern void cpu_callin(struct cpu_thread *cpu);

/* For cpus which fail to call in. */
extern void cpu_remove_node(const struct cpu_thread *t);

extern struct cpu_thread *find_cpu_by_chip_id(u32 id);
extern struct cpu_thread *find_active_cpu_by_chip_id(u32 id);
extern struct cpu_thread *find_cpu_by_pir(u32 pir);

/* Iterator */
extern struct cpu_thread *first_cpu(void);
extern struct cpu_thread *next_cpu(struct cpu_thread *cpu);

/* WARNING: CPUs that have been picked up by the OS are no longer
 *          appearing as available and can not have jobs scheduled
 *          on them. Essentially that means that after the OS is
 *          fully started, all CPUs are seen as unavailable from
 *          this API standpoint.
 */
extern struct cpu_thread *first_available_cpu(void);
extern struct cpu_thread *next_available_cpu(struct cpu_thread *cpu);

#define for_each_cpu(cpu)	\
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))

#define for_each_available_cpu(cpu)	\
	for (cpu = first_available_cpu(); cpu; cpu = next_available_cpu(cpu))

/* Return the caller CPU (only after init_cpu_threads) */
register struct cpu_thread *__this_cpu asm("r13");
static inline struct cpu_thread *this_cpu(void)
{
	return __this_cpu;
}

/* Get the thread # of a cpu within the core */
static inline uint32_t cpu_get_thread_index(struct cpu_thread *cpu)
{
	/* XXX Handle P8 */
	return cpu->pir & 0x3;
}

/* Get the PIR of thread 0 of the same core */
static inline uint32_t cpu_get_thread0(struct cpu_thread *cpu)
{
	/* XXX Handle P8 */
	return cpu->pir & ~3;
}

static inline bool cpu_is_thread0(struct cpu_thread *cpu)
{
	/* XXX Handle P8 */
	return (cpu->pir & 3) == 0;
}

/* Called when some error condition requires disabling a core */
void cpu_disable_all_threads(struct cpu_thread *cpu);

/* Allocate & queue a job on target CPU */
extern struct cpu_job *cpu_queue_job(struct cpu_thread *cpu,
				     void (*func)(void *data), void *data);

/* Poll job status, returns true if completed */
extern bool cpu_poll_job(struct cpu_job *job);

/* Synchronously wait for a job to complete, this will
 * continue handling the FSP mailbox if called from the
 * boot CPU. Set free_it to free it automatically.
 */
extern void cpu_wait_job(struct cpu_job *job, bool free_it);

/* Free a CPU job, only call on a completed job */
extern void cpu_free_job(struct cpu_job *job);

/* Called by init to process jobs */
extern void cpu_process_jobs(void);

static inline void cpu_give_self_os(void)
{
	__this_cpu->state = cpu_state_os;
}

extern bool add_cpu_nodes(void);

extern unsigned int cpu_max_pir;
extern struct cpu_thread cpu_threads[SPR_PIR_MASK + 1];
extern void *cpu_stacks[SPR_PIR_MASK + 1];
#endif /* __CPU_H */
