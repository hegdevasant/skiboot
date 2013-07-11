/* API for kernel to read trace buffer. */
#ifndef __TRACE_TYPES_H
#define __TRACE_TYPES_H

#define TRACE_REPEAT 1
#define TRACE_OVERFLOW 2

/* One per cpu, plus one for NMIs */
struct tracebuf {
	/* Mask to apply to get buffer offset. */
	u64 mask;
	/* This where the buffer starts. */
	u64 start;
	/* This is where writer has written to. */
	u64 end;
	/* This is where the writer wrote to previously. */
	u64 last;
	/* This is where the reader is up to. */
	u64 rpos;
	/* If the last one we read was a repeat, this shows how many. */
	u32 last_repeat;
	/* Maximum possible size of a record. */
	u32 max_size;

	char buf[/* TBUF_SZ + max_size */];
};

/* Common header for all trace entries. */
struct trace_hdr {
	u64 timestamp;
	u8 type;
	u8 len_div_8;
	u16 cpu;
	u8 unused[4];
};

/* Note: all other entries must be at least as large as this! */
struct trace_repeat {
	u64 timestamp; /* Last repeat happened at this timestamp */
	u8 type; /* == TRACE_REPEAT */
	u8 len_div_8;
	u16 cpu;
	u16 prev_len;
	u16 num; /* Starts at 1, ie. 1 repeat, or two traces. */
	/* Note that the count can be one short, if read races a repeat. */
};

struct trace_overflow {
	u64 unused64; /* Timestamp is unused */
	u8 type; /* == TRACE_OVERFLOW */
	u8 len_div_8;
	u8 unused[6]; /* ie. hdr.cpu is indeterminate */
	u64 bytes_missed;
};

union trace {
	struct trace_hdr hdr;
	/* Trace types go here... */
	struct trace_repeat repeat;
	struct trace_overflow overflow;
};

#endif /* __TRACE_TYPES_H */
