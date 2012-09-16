/*
 * Console IO routine for use by libc
 *
 * fd is the classic posix 0,1,2 (stdin, stdout, stderr)
 */
#include <skiboot.h>
#include <unistd.h>


#ifdef MAMBO_CONSOLE
static void mambo_write(const char *buf, size_t count)
{
#define SIM_WRITE_CONSOLE_CODE	0
	register int c asm("r3") = 0; /* SIM_WRITE_CONSOLE_CODE */
	register unsigned long a1 asm("r4") = (unsigned long)buf;
	register unsigned long a2 asm("r5") = count;
	register unsigned long a3 asm("r6") = 0;
	asm volatile (".long 0x000eaeb0":"=r" (c):"r"(c), "r"(a1), "r"(a2),
		      "r"(a3));
}
#else
static void mambo_write(const char *buf, size_t count) { }
#endif /* MAMBO_CONSOLE */

#ifdef INMEM_CONSOLE
static char *inmem_con_buf = (char *)INMEM_CON_START;
static unsigned int inmem_con_pos;

static void inmem_write(const char *buf, size_t count)
{
	while(count--) {
		inmem_con_buf[inmem_con_pos++] = *(buf++);
		if (inmem_con_pos > INMEM_CON_LEN)
			inmem_con_pos = 0;
	}
}
#endif /* INMEM_CONSOLE */

ssize_t write(int fd __unused, const void *buf, size_t count)
{
	mambo_write(buf, count);
	inmem_write(buf, count);

	return count;
}

ssize_t read(int fd __unused, void *buf __unused, size_t count __unused)
{
	return 0;
}

