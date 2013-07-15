/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include "../ccan/endian/endian.h"
#include "../ccan/short_types/short_types.h"
#include <trace_types.h>

/* Handles trace from debugfs (one record at a time) or file */ 
static bool get_trace(int fd, union trace *t, int *len)
{
	void *dest = t;
	int r;

	/* Move down any extra we read last time. */
	if (*len >= sizeof(t->hdr) && *len >= t->hdr.len_div_8 * 8) {
		u8 rlen = t->hdr.len_div_8 * 8;
		memmove(dest, dest + rlen, *len - rlen);
		*len -= rlen;
	}

	r = read(fd, dest + *len, sizeof(*t) - *len);
	if (r < 0)
		return false;

	*len += r;
	/* We should have a complete record. */
	return *len >= sizeof(t->hdr) && *len >= t->hdr.len_div_8 * 8;
}

static void append_timestamp(const union trace *t)
{
	static u64 prev_ts;
	u64 ts = be64_to_cpu(t->hdr.timestamp);

	if (prev_ts)
		printf(" (+%"PRIu64")\n", ts - prev_ts);
	else
		printf(" (%"PRIu64")\n", ts);
	prev_ts = ts;
}

int main(int argc, char *argv[])
{
	int fd, len = 0;
	unsigned int i, n;
	union trace t;
	const char *in = "/sys/kernel/debug/firmware_trace";

	if (argc > 2)
		errx(1, "Usage: dump_trace [file]");

	if (argv[1])
		in = argv[1];
	fd = open(in, O_RDONLY);
	if (fd < 0)
		err(1, "Opening %s", in);

	while (get_trace(fd, &t, &len)) {
		switch (t.hdr.type) {
		case TRACE_REPEAT:
			printf("REPEATS: %u times",
			       be32_to_cpu(t.repeat.num));
			append_timestamp(&t);
			break;
		case TRACE_OVERFLOW:
			printf("**OVERFLOW**: %"PRIu64" bytes missed\n",
			       be64_to_cpu(t.overflow.bytes_missed));
			break;
		case TRACE_OPAL:
			printf("OPAL: CALL %"PRIu64" CPU %u",
			       be64_to_cpu(t.opal.token),
			       be16_to_cpu(t.opal.cpu));
			printf(" LR=0x%016"PRIx64" SP=0x%016"PRIx64,
			       be64_to_cpu(t.opal.lr), be64_to_cpu(t.opal.sp));
			n = (t.opal.len_div_8 * 8 - offsetof(union trace, opal.r3_to_11))
				/ sizeof(u64);
			for (i = 0; i < n; i++)
				printf(" R%u=0x%016"PRIx64,
				       i+3, be64_to_cpu(t.opal.r3_to_11[i]));
			append_timestamp(&t);
			break;
		case TRACE_FSP:
			printf("FSP: CMD %u SEQ %u MOD %u SUB %u DLEN %u %s [",
			       be32_to_cpu(t.fsp.word0) & 0xFFFF,
			       be32_to_cpu(t.fsp.word0) >> 16,
			       be32_to_cpu(t.fsp.word1) >> 8,
			       be32_to_cpu(t.fsp.word1) & 0xFF,
			       t.fsp.dlen,
			       t.fsp.dir == TRACE_FSP_IN ? "IN" :
			       t.fsp.dir == TRACE_FSP_OUT ? "OUT" : "UNKNOWN");
			for (i = 0; i < t.fsp.dlen; i++) 
				printf("%s%02x", i ? " " : "", t.fsp.data[i]);
			printf("] CPU %u\n", be16_to_cpu(t.fsp.cpu));
			append_timestamp(&t);
			break;
		default:
			printf("UNKNOWN(%u) CPU %u length %u",
			       t.hdr.type, be16_to_cpu(t.hdr.cpu),
			       t.hdr.len_div_8 * 8);
			append_timestamp(&t);
		}
	}
	return 0;
}
