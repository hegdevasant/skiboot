/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <trace.h>
#include <timebase.h>
#include <lock.h>
#include <string.h>
#include <stdlib.h>
#include <cpu.h>

#define MAX_SIZE sizeof(union trace)

static struct {
	struct tracebuf tracebuf;
	char buf[TBUF_SZ + MAX_SIZE];
} boot_tracebuf = { { .mask = TBUF_SZ - 1, .max_size = MAX_SIZE }, { 0 } };

void init_boot_tracebuf(struct cpu_thread *boot_cpu)
{
	boot_cpu->tracebuf = &boot_tracebuf.tracebuf;
}

struct tracebuf *trace_newbuf(void)
{
	struct tracebuf *tb;

	/* We make room for the largest possible record */
	tb = zalloc(sizeof(*tb) + TBUF_SZ + MAX_SIZE);
	tb->mask = TBUF_SZ - 1;
	tb->max_size = MAX_SIZE;
	return tb;
}

/* To avoid bloating each entry, repeats are actually specific entries.
 * tb->last points to the last (non-repeat) entry. */
static bool handle_repeat(struct tracebuf *tb, const union trace *trace)
{
	struct trace_hdr *prev;
	struct trace_repeat *rpt;
	u32 len;

	prev = (void *)tb->buf + (tb->last % TBUF_SZ);

	if (prev->type != trace->hdr.type
	    || prev->len_div_8 != trace->hdr.len_div_8
	    || prev->cpu != trace->hdr.cpu)
		return false;

	len = prev->len_div_8 * 8;
	if (memcmp(prev + 1, &trace->hdr + 1, len - sizeof(*prev)) != 0)
		return false;

	/* If they've consumed prev entry, don't repeat. */
	if (tb->last < tb->start)
		return false;

	/* OK, it's a duplicate.  Do we already have repeat? */
	if (tb->last + len != tb->end) {
		/* FIXME: Reader is not protected from seeing this! */
		rpt = (void *)tb->buf + ((tb->last + len) % TBUF_SZ);
		assert(tb->last + len + rpt->len_div_8*8 == tb->end);

		/* If this repeat entry is full, generate another. */
		if (rpt->num < 0xFFFF) {
			rpt->num++;
			rpt->timestamp = trace->hdr.timestamp;
			return true;
		}
	}

	/* Generate repeat entry: it's the smallest possible entry, so we
	 * must have eliminated old entries. */
	assert(trace->hdr.len_div_8 * 8 >= sizeof(*rpt));

	rpt = (void *)tb->buf + (tb->end % TBUF_SZ);
	rpt->timestamp = trace->hdr.timestamp;
	rpt->type = TRACE_REPEAT;
	rpt->len_div_8 = sizeof(*rpt) / 8;
	rpt->cpu = trace->hdr.cpu;
	rpt->prev_len = trace->hdr.len_div_8 * 8;
	rpt->num = 1;
	lwsync(); /* write barrier: complete repeat record before exposing */
	tb->end += sizeof(*rpt);
	return true;
}

void trace_add(union trace *trace)
{
	struct tracebuf *tb = this_cpu()->tracebuf;

	assert(trace->hdr.len_div_8 * 8 >= sizeof(trace->hdr));
	assert(trace->hdr.len_div_8 * 8 <= sizeof(*trace));
	assert(trace->hdr.type != TRACE_REPEAT);
	assert(trace->hdr.type != TRACE_OVERFLOW);

	trace->hdr.timestamp = mftb();
	trace->hdr.cpu = this_cpu()->server_no;

	/* Throw away old entries before we overwrite them. */
	while (tb->start + TBUF_SZ < tb->end + trace->hdr.len_div_8 * 8) {
		struct trace_hdr *hdr;

		hdr = (void *)tb->buf + (tb->start % TBUF_SZ);
		tb->start += hdr->len_div_8 * 8;
	}

	/* Must update ->start before we rewrite new entries. */
	lwsync(); /* write barrier */

	/* Check for duplicates... */
	if (!handle_repeat(tb, trace)) {
		/* This may go off end, and that's why tb->buf is oversize. */
		memcpy(tb->buf + (tb->end % TBUF_SZ), trace,
		       trace->hdr.len_div_8 * 8);
		tb->last = tb->end;
		lwsync(); /* write barrier: write entry before exposing */
		tb->end += trace->hdr.len_div_8 * 8;
	}
}
