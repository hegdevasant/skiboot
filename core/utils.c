#include <skiboot.h>
#include <lock.h>
#include <fsp.h>

void abort(void)
{
	static bool in_abort = false;

	if (in_abort)
		for (;;) ;
	in_abort = true;

	bust_locks = true;

	op_display(OP_FATAL, OP_MOD_CORE, 0x6666);
	
	fputs(stderr, "Aborting!\n");
	backtrace();
	for (;;)
		fsp_poll();
}

char tohex(uint8_t nibble)
{
	static const char __tohex[] = {'0','1','2','3','4','5','6','7','8','9',
				       'A','B','C','D','E','F'};
	if (nibble > 0xf)
		return '?';
	return __tohex[nibble];
}
