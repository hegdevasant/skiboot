#include <skiboot.h>

void abort(void)
{
	fputs(stderr, "Aborting!\n");
	backtrace();
	for (;;);
}

