#include <time.h>
#include <fsp.h>

void time_wait(unsigned long duration)
{
	unsigned long end = mftb() + duration;

	while(tb_compare(mftb(), end) != TB_AAFTERB)
		fsp_poll();
}

void time_wait_ms(unsigned long ms)
{
	time_wait(ms * (tb_hz / 1000));
}

