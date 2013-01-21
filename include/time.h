/*
 * Timebase helpers.
 *
 * Note: Only use after the TODs are in sync !
 */
#ifndef __TIME_H
#define __TIME_H

static inline unsigned long mftb(void)
{
	unsigned long tb;

	/* We use a memory clobber to avoid this being
	 * moved in the instruction stream
	 */
	asm volatile("mftb %0" : "=r"(tb) : : "memory");
	return tb;
}

enum tb_cmpval {
	TB_ABEFOREB = -1,
	TB_AEQUALB  = 0,
	TB_AAFTERB  = 1
};

static inline enum tb_cmpval tb_compare(unsigned long a,
					unsigned long b)
{
	if (a == b)
		return TB_AEQUALB;
	return ((long)(b - a)) > 0 ? TB_ABEFOREB : TB_AAFTERB;
}

#if 0
extern unsigned long tb_hz;
#else
/* Architected timebase */
static const unsigned long tb_hz = 512000000;
#endif

static inline unsigned long secs_to_tb(unsigned long secs)
{
	return secs * tb_hz;
}

static inline unsigned long msecs_to_tb(unsigned long msecs)
{
	return msecs * (tb_hz / 1000);
}

static inline unsigned long tb_to_msecs(unsigned long tb)
{
	return (tb * 1000) / tb_hz;
}

/* wait_poll - Wait a certain number of TB ticks while polling FSP */
extern void time_wait(unsigned long duration);

/* wait_poll_ms - Wait a certain number of milliseconds while polling FSP */
extern void time_wait_ms(unsigned long ms);

#endif /* __TIME_H */
