#include <skiboot.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Boot semaphore, incremented by each CPU calling in
 *
 * Forced into data section as it will be used before BSS is initialized
 */
unsigned int boot_cpu_count __attribute__((__section__(".force.data"))) = 0;

void main_cpu_entry(void)
{
	printf("Hello World ! Skiboot reached C code !\n");
}
