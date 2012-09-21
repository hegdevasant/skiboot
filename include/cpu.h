#ifndef __CPU_H
#define __CPU_H
#include <hdif.h>

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

struct cpu_thread {
	const struct HDIF_cpu_id *id;
	const struct HDIF_cpu_timebase *timebase;
};

/* This populates cpu_threads array. */
extern void cpu_parse(void);
#endif /* __CPU_H */
