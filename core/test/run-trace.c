/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <config.h>
#include <stdlib.h>
#include <assert.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Don't include these: PPC-specific */
#define __CPU_H
#define __TIME_H
#define __PROCESSOR_H

#if defined(__i386__) || defined(__x86_64__)
/* This is more than a lwsync, but it'll work */
static void full_barrier(void)
{
	asm volatile("mfence" : : : "memory");
}
#define lwsync full_barrier
#define sync full_barrier
#else
#error "Define sync & lwsync for this arch"
#endif

#define zalloc(size) calloc((size), 1)

struct cpu_thread {
	struct trace_info *trace;
	int server_no;
	bool is_secondary;
	struct cpu_thread *primary;
};
static struct cpu_thread *this_cpu(void);

#define CPUS 4

static struct cpu_thread fake_cpus[CPUS];

static inline struct cpu_thread *next_cpu(struct cpu_thread *cpu)
{
	if (cpu == NULL)
		return &fake_cpus[0];
	cpu++;
	if (cpu == &fake_cpus[CPUS])
		return NULL;
	return cpu;
}

#define first_cpu() next_cpu(NULL)

#define for_each_cpu(cpu)	\
	for (cpu = first_cpu(); cpu; cpu = next_cpu(cpu))

static unsigned long timestamp;
static unsigned long mftb(void)
{
	return timestamp;
}

static void *local_alloc(struct cpu_thread *cpu __attribute__((unused)),
			 size_t size, size_t align)
{
	void *p;
	if (posix_memalign(&p, align, size))
		p = NULL;
	return p;
}

#include "../trace.c"

#define rmb() lwsync()

#include "../external/trace.c"
#include "../device.c"

char __rodata_start[1], __rodata_end[1];
struct dt_node *dt_root;

void lock(struct lock *l)
{
	assert(!l->lock_val);
	l->lock_val = 1;
}

void unlock(struct lock *l)
{
	assert(l->lock_val);
	l->lock_val = 0;
}

struct cpu_thread *my_fake_cpu;
static struct cpu_thread *this_cpu(void)
{
	return my_fake_cpu;
}

#include <sys/mman.h>
#define PER_CHILD_TRACES (1024*1024)

static void write_trace_entries(int id)
{
	void exit(int);
	unsigned int i;
	union trace trace;

	timestamp = id;
	for (i = 0; i < PER_CHILD_TRACES; i++) {
		timestamp = i * CPUS + id;
		assert(sizeof(trace.hdr) % 8 == 0);
		trace.hdr.len_div_8 = sizeof(trace.hdr) / 8;
		/* First child never repeats, second repeats once, etc. */
		trace.hdr.type = 3 + ((i / (id + 1)) % 0x40);
		trace_add(&trace);
	}

	/* Final entry has special type, so parent knows it's over. */
	trace.hdr.type = 0x70;
	trace_add(&trace);
	exit(0);
}

static bool all_done(const bool done[])
{
	unsigned int i;

	for (i = 0; i < CPUS; i++)
		if (!done[i])
			return false;
	return true;
}

static void test_parallel(void)
{
	void *p;
	unsigned int i, counts[CPUS] = { 0 }, overflows[CPUS] = { 0 };
	unsigned int repeats[CPUS] = { 0 }, num_overflows[CPUS] = { 0 };
	bool done[CPUS] = { false };
	size_t len = sizeof(struct trace_info) + TBUF_SZ + sizeof(union trace);
	int last = 0;

	/* Use a shared mmap to test actual parallel buffers. */
	i = (CPUS*len + getpagesize()-1)&~(getpagesize()-1);
	p = mmap(NULL, i, PROT_READ|PROT_WRITE,
		 MAP_ANONYMOUS|MAP_SHARED, -1, 0);

	for (i = 0; i < CPUS; i++) {
		fake_cpus[i].trace = p + i * len;
		fake_cpus[i].trace->tb.mask = TBUF_SZ - 1;
		fake_cpus[i].trace->tb.max_size = sizeof(union trace);
		fake_cpus[i].is_secondary = false;
	}

	for (i = 0; i < CPUS; i++) {
		if (!fork()) {
			/* Child. */
			my_fake_cpu = &fake_cpus[i];
			write_trace_entries(i);
		}
	}

	while (!all_done(done)) {
		union trace t;

		for (i = 0; i < CPUS; i++) {
			if (trace_get(&t, &fake_cpus[(i+last) % CPUS].trace->tb))
				break;
		}

		if (i == CPUS) {
			sched_yield();
			continue;
		}
		i = (i + last) % CPUS;
		last = i;

		assert(t.hdr.cpu < CPUS);
		assert(!done[t.hdr.cpu]);

		if (t.hdr.type == TRACE_OVERFLOW) {
			/* Conveniently, each record is 16 bytes here. */
			assert(t.overflow.bytes_missed % 16 == 0);
			overflows[i] += t.overflow.bytes_missed / 16;
			num_overflows[i]++;
			continue;
		}

		assert(t.hdr.timestamp % CPUS == t.hdr.cpu);
		if (t.hdr.type == TRACE_REPEAT) {
			assert(t.hdr.len_div_8 * 8 == sizeof(t.repeat));
			assert(t.repeat.num != 0);
			assert(t.repeat.num <= t.hdr.cpu);
			repeats[t.hdr.cpu] += t.repeat.num;
		} else if (t.hdr.type == 0x70) {
			done[t.hdr.cpu] = true;
		} else {
			counts[t.hdr.cpu]++;
		}
	}

	/* Gather children. */
	for (i = 0; i < CPUS; i++) {
		int status;
		wait(&status);
	}

	for (i = 0; i < CPUS; i++) {
		printf("Child %i: %u produced, %u overflows, %llu total\n", i,
		       counts[i], overflows[i],
		       (long long)fake_cpus[i].trace->tb.end);
		assert(counts[i] + repeats[i] <= PER_CHILD_TRACES);
	}
	/* Child 0 never repeats. */
	assert(repeats[0] == 0);
	assert(counts[0] + overflows[0] == PER_CHILD_TRACES);

	/*
	 * FIXME: Other children have some fuzz, since overflows may
	 * include repeat record we already read.  And odd-numbered
	 * overflows may include more repeat records than normal
	 * records (they alternate).
	 */
}

int main(void)
{
	union trace minimal;
	union trace large;
	union trace trace;
	unsigned int i;

	for (i = 0; i < CPUS; i++) {
		fake_cpus[i].server_no = i;
		fake_cpus[i].is_secondary = (i & 0x1);
		fake_cpus[i].primary = &fake_cpus[i & ~0x1];
	}
	init_trace_buffers();
	my_fake_cpu = &fake_cpus[0];

	for (i = 0; i < CPUS; i++) {
		assert(trace_empty(&fake_cpus[i].trace->tb));
		assert(!trace_get(&trace, &fake_cpus[i].trace->tb));
	}

	assert(sizeof(trace.hdr) % 8 == 0);
	timestamp = 1;
	minimal.hdr.len_div_8 = sizeof(trace.hdr) / 8;
	minimal.hdr.type = 100;
	trace_add(&minimal);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.timestamp == timestamp);

	/* Make it wrap once. */
	for (i = 0; i < TBUF_SZ / (minimal.hdr.len_div_8 * 8) + 1; i++) {
		minimal.hdr.type = 99 + (i%2);
		timestamp = i;
		trace_add(&minimal);
	}

	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	/* First one must be overflow marker. */
	assert(trace.hdr.type == TRACE_OVERFLOW);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.overflow));
	assert(trace.overflow.bytes_missed == minimal.hdr.len_div_8 * 8);

	for (i = 0; i < TBUF_SZ / (minimal.hdr.len_div_8 * 8); i++) {
		assert(trace_get(&trace, &my_fake_cpu->trace->tb));
		assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
		assert(trace.hdr.timestamp == i+1);
		assert(trace.hdr.type == 99 + ((i+1)%2));
	}
	assert(!trace_get(&trace, &my_fake_cpu->trace->tb));

	/* Now put in some weird-length ones, to test overlap.
	 * Last power of 2, minus 8. */
	for (i = 0; (1 << i) < sizeof(large); i++);
	large.hdr.len_div_8 = (1 << (i-1)) / 8 - 1;
	for (i = 0; i < TBUF_SZ; i++) {
		timestamp = i;
		large.hdr.type = 100 + (i%2);
		trace_add(&large);
	}
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.type == TRACE_OVERFLOW);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.len_div_8 == large.hdr.len_div_8);
	i = trace.hdr.timestamp;
	while (trace_get(&trace, &my_fake_cpu->trace->tb))
		assert(trace.hdr.timestamp == ++i);

	/* Test repeats. */
	for (i = 0; i < 65538; i++) {
		minimal.hdr.type = 100;
		timestamp = i;
		trace_add(&minimal);
	}
	minimal.hdr.type = 101;
	timestamp = i;
	trace_add(&minimal);
	timestamp = i+1;
	trace_add(&minimal);

	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.timestamp == 0);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 100);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.type == TRACE_REPEAT);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
	assert(trace.repeat.num == 65535);
	assert(trace.repeat.timestamp == 65535);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.timestamp == 65536);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 100);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.type == TRACE_REPEAT);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
	assert(trace.repeat.num == 1);
	assert(trace.repeat.timestamp == 65537);

	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.timestamp == 65538);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 101);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.type == TRACE_REPEAT);
	assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
	assert(trace.repeat.num == 1);
	assert(trace.repeat.timestamp == 65539);

	/* Now, test adding repeat while we're reading... */
	minimal.hdr.type = 100;
	timestamp = 0;
	trace_add(&minimal);
	assert(trace_get(&trace, &my_fake_cpu->trace->tb));
	assert(trace.hdr.timestamp == 0);
	assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
	assert(trace.hdr.type == 100);

	for (i = 1; i < TBUF_SZ; i++) {
		timestamp = i;
		trace_add(&minimal);
		assert(trace_get(&trace, &my_fake_cpu->trace->tb));
		if (i % 65536 == 0) {
			assert(trace.hdr.type == 100);
			assert(trace.hdr.len_div_8 == minimal.hdr.len_div_8);
		} else {
			assert(trace.hdr.type == TRACE_REPEAT);
			assert(trace.hdr.len_div_8 * 8 == sizeof(trace.repeat));
			assert(trace.repeat.num == 1);
		}
		assert(trace.repeat.timestamp == i);
		assert(!trace_get(&trace, &my_fake_cpu->trace->tb));
	}

	for (i = 0; i < CPUS; i++)
		if (!fake_cpus[i].is_secondary)
			free(fake_cpus[i].trace);

	test_parallel();

	return 0;
}
