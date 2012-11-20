/*
 * Console IO routine for use by libc
 *
 * fd is the classic posix 0,1,2 (stdin, stdout, stderr)
 */
#include <skiboot.h>
#include <unistd.h>
#include <console.h>

static char *con_buf = (char *)INMEM_CON_START;
static size_t con_in;
static size_t con_out;
static struct con_ops *con_driver;

struct lock con_lock = LOCK_UNLOCKED;

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
static void mambo_write(const char *buf __unused, size_t count __unused) { }
#endif /* MAMBO_CONSOLE */

/* Flush the console buffer into the driver, returns true
 * if there is more to go
 */
bool __flush_console(void)
{
	size_t req, len = 0;
	static bool in_flush, more_flush;

	/* We need to be careful here, due to some tracing in the
	 * FSP code, we might end up having more data being added
	 * to the console buffer, and even re-enter, while inside
	 * the write callback. So let's prevent re-entrancy and
	 * make sure we re-evaluate con_in after a write.
	 */
	if (in_flush) {
		more_flush = true;
		return false;
	}
	if (con_in == con_out || !con_driver)
		return false;
	in_flush = true;

	do {
		more_flush = false;
		if (con_out > con_in) {
			req = INMEM_CON_LEN - con_out;
			len = con_driver->write(con_buf + con_out, req);				con_out = (con_out + len) % INMEM_CON_LEN;
			if (len < req)
				goto bail;
		}
		if (con_out < con_in) {
			len = con_driver->write(con_buf + con_out,
						con_in - con_out);
			con_out = (con_out + len) % INMEM_CON_LEN;
		}
	} while(more_flush);
bail:
	in_flush = false;
	return con_out != con_in;
}

bool flush_console(void)
{
	bool ret;

	lock(&con_lock);
	ret = __flush_console();
	unlock(&con_lock);

	return ret;
}

static void inmem_write(char c)
{
	con_buf[con_in++] = c;
	if (con_in >= INMEM_CON_LEN)
		con_in = 0;

	/* If head reaches tail, push tail around & drop chars */
	if (con_in == con_out)
		con_out = (con_in + 1) % INMEM_CON_LEN;
}

static void write_char(char c)
{
	mambo_write(&c, 1);
	inmem_write(c);
}

ssize_t write(int fd __unused, const void *buf, size_t count)
{
	/* We use recursive locking here as we can get called
	 * from fairly deep debug path
	 */
	bool need_unlock = lock_recursive(&con_lock);
	const char *cbuf = buf;

	while(count--) {
		char c = *(cbuf++);
		if (c == 10)
			write_char(13);
		write_char(c);
	}

	__flush_console();

	if (need_unlock)
		unlock(&con_lock);

	return count;
}

ssize_t read(int fd __unused, void *buf __unused, size_t count __unused)
{
	return 0;
}

void set_console(struct con_ops *driver)
{
	con_driver = driver;
	if (driver)
		flush_console();
}
