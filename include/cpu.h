#ifndef __CPU_H
#define __CPU_H

#include <hdif.h>
#include <processor.h>
#include <ccan/list/list.h>
#include <lock.h>

/* This is the array of all threads. */
extern struct cpu_thread *cpu_threads;

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
	u32 ibase;
	u32 deprecated1;
	u32 physical_thread_id;
	u32 deprecated2;
	u32 ccm_node_id;
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
	cpu_state_unknown	= 0,	/* At boot time */
	cpu_state_unavailable,		/* Not available */
	cpu_state_available,		/* Assumed to spin in asm entry */
	cpu_state_boot,			/* Our boot CPU */
	cpu_state_idle,			/* Secondary called in */
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
	const struct HDIF_cpu_timebase *timebase;
	const struct HDIF_cpu_cache *cache;
};

/* This global is set to 1 to allow secondaries to callin,
 * typically set after the primary has allocated the cpu_thread
 * array and stacks
 */
extern unsigned long cpu_secondary_start;

/* Boot CPU, set after cpu_parse() */
extern struct cpu_thread *boot_cpu;

/* This populates cpu_threads array. */
extern void cpu_parse(void);

/* This brings up our secondaries */
extern void cpu_bringup(void);

/* This is called by secondaries as they call in */
extern void cpu_callin(struct cpu_thread *cpu);

extern u32 num_cpu_threads(void);

extern struct cpu_thread *find_cpu_by_chip_id(u32 id);

extern struct cpu_thread *find_cpu_by_pir(u32 pir);

/* Return the caller CPU (only after cpu_bringup) */
static inline struct cpu_thread *this_cpu(void)
{
	return (struct cpu_thread *)mfspr(SPR_HSPRG0);
}

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

#endif /* __CPU_H */
