#include <skiboot.h>
#include <fsp.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
unsigned int boot_cpu_count __force_data = 0;

void main_cpu_entry(void)
{
	printf("SkiBoot starting...\n");

	/* Early initializations of the FSP interface */
	fsp_preinit();
}
