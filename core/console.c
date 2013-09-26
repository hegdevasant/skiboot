/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
/*
 * Console IO routine for use by libc
 *
 * fd is the classic posix 0,1,2 (stdin, stdout, stderr)
 */
#include <skiboot.h>
#include <unistd.h>
#include <console.h>
#include <opal.h>
#include <device.h>
#include <processor.h>

/*
 * Our internal console uses the format of BML new-style in-memory
 * console and supports input for setups without a physical console
 * facility or FSP
 */
struct memcons {
	char *ostart, *ocur, *oend;
	char *istart, *icur, *iend;
	uint64_t magic;
#define MEMCONS_MAGIC	0x6630696567726173
};


#define INMEM_CON_IN_LEN	16
#define INMEM_CON_OUT_LEN	(INMEM_CON_LEN - INMEM_CON_IN_LEN)

static char *con_buf = (char *)INMEM_CON_START;
static size_t con_in;
static size_t con_out;
static struct con_ops *con_driver;

struct lock con_lock = LOCK_UNLOCKED;

struct memcons memcons = {
	.ostart	= (char *)INMEM_CON_START,
	.ocur	= (char *)INMEM_CON_START,
	.oend	= (char *)INMEM_CON_START + INMEM_CON_OUT_LEN,
	.istart	= (char *)INMEM_CON_START + INMEM_CON_OUT_LEN,
	.icur	= (char *)INMEM_CON_START + INMEM_CON_OUT_LEN,
	.iend	= (char *)INMEM_CON_START + INMEM_CON_LEN,
	.magic	= MEMCONS_MAGIC,
};

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

void clear_console(void)
{
	memset(con_buf, 0, INMEM_CON_LEN);
}

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
			req = INMEM_CON_OUT_LEN - con_out;
			len = con_driver->write(con_buf + con_out, req);				con_out = (con_out + len) % INMEM_CON_OUT_LEN;
			if (len < req)
				goto bail;
		}
		if (con_out < con_in) {
			len = con_driver->write(con_buf + con_out,
						con_in - con_out);
			con_out = (con_out + len) % INMEM_CON_OUT_LEN;
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
	if (!c)
		return;
	con_buf[con_in++] = c;
	if (con_in >= INMEM_CON_OUT_LEN)
		con_in = 0;
	lwsync();
	memcons.ocur = con_buf + con_in;

	/* If head reaches tail, push tail around & drop chars */
	if (con_in == con_out)
		con_out = (con_in + 1) % INMEM_CON_OUT_LEN;
}

static size_t inmem_read(char *buf, size_t req)
{
	size_t read = 0;
	char *next, *cur = memcons.icur;
	
	while (req && *cur) {
		*(buf++) = *cur;
		read++;
		next = cur + 1;
		if (next == memcons.iend || *next == 0)
			next = memcons.istart;
		memcons.icur = next;
		lwsync();
		*cur = 0;
		cur = next;
	}
	return read;
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

ssize_t read(int fd __unused, void *buf, size_t req_count)
{
	bool need_unlock = lock_recursive(&con_lock);
	size_t count = 0;

	if (con_driver && con_driver->read)
		count = con_driver->read(buf, req_count);
	if (!count)
		count = inmem_read(buf, req_count);
	if (need_unlock)
		unlock(&con_lock);
	return count;
}

void set_console(struct con_ops *driver)
{
	con_driver = driver;
	if (driver)
		flush_console();
}

void memcons_add_properties(struct dt_node *opal)
{
	uint64_t addr = (u64)&memcons;

	dt_add_property_cells(opal, "ibm,opal-memcons",
			      hi32(addr), lo32(addr));
}

/*
 * Default OPAL console provided if nothing else overrides it
 */
static int64_t dummy_console_write(int64_t term_number, int64_t *length,
				   const uint8_t *buffer)
{
	if (term_number != 0)
		return OPAL_PARAMETER;
	write(0, buffer, *length);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CONSOLE_WRITE, dummy_console_write, 3);

static int64_t dummy_console_write_buffer_space(int64_t term_number,
						int64_t *length)
{
	if (term_number != 0)
		return OPAL_PARAMETER;
	if (length)
		*length = INMEM_CON_OUT_LEN;

	return OPAL_SUCCESS;
}
opal_call(OPAL_CONSOLE_WRITE_BUFFER_SPACE, dummy_console_write_buffer_space, 2);

static int64_t dummy_console_read(int64_t term_number, int64_t *length,
				  uint8_t *buffer)
{
	if (term_number != 0)
		return OPAL_PARAMETER;
	*length = read(0, buffer, *length);

	return OPAL_SUCCESS;
}
opal_call(OPAL_CONSOLE_READ, dummy_console_read, 3);

void dummy_console_add_nodes(struct dt_node *opal)
{
	struct dt_node *con, *consoles;

	consoles = dt_new(opal, "consoles");
	assert(consoles);
	dt_add_property_cells(consoles, "#address-cells", 1);
	dt_add_property_cells(consoles, "#size-cells", 0);

	con = dt_new_addr(consoles, "serial", 0);
	assert(con);
	dt_add_property_string(con, "compatible", "ibm,opal-console-raw");
	dt_add_property_cells(con, "#write-buffer-size", INMEM_CON_OUT_LEN);
	dt_add_property_cells(con, "reg", 0);
	dt_add_property_string(con, "device_type", "serial");

	dt_add_property_string(dt_chosen, "linux,stdout-path",
			       "/ibm,opal/consoles/serial@0");
}
