/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <lpc.h>
#include <console.h>
#include <opal.h>
#include <device.h>

/* UART reg defs */
#define REG_RBR		0
#define REG_THR		0
#define REG_DLL		0
#define REG_IER		1
#define REG_DLM		1
#define REG_FCR		2
#define REG_IIR		2
#define REG_LCR		3
#define REG_MCR		4
#define REG_LSR		5
#define REG_MSR		6
#define REG_SCR		7

#define LSR_DR   0x01  /* Data ready */
#define LSR_OE   0x02  /* Overrun */
#define LSR_PE   0x04  /* Parity error */
#define LSR_FE   0x08  /* Framing error */
#define LSR_BI   0x10  /* Break */
#define LSR_THRE 0x20  /* Xmit holding register empty */
#define LSR_TEMT 0x40  /* Xmitter empty */
#define LSR_ERR  0x80  /* Error */

#define LCR_DLAB 0x80  /* DLL access */

static uint32_t uart_base;

static inline uint8_t uart_read(unsigned int reg)
{
	return lpc_inb(uart_base + reg);
}

static inline void uart_write(unsigned int reg, uint8_t val)
{
	lpc_outb(val, uart_base + reg);
}

static size_t uart_con_write(const char *buf, size_t len)
{
	size_t written = 0;

	while(written < len) {
		while ((uart_read(REG_LSR) & LSR_THRE) == 0)
			/* wait for idle */;
		uart_write(REG_THR, buf[written++]);
	};

	return written;
}

static size_t uart_con_read(char *buf, size_t len)
{
	size_t read_cnt = 0;
	uint8_t lsr;

	for (;;) {
		lsr = uart_read(REG_LSR);
		if (read_cnt >= len || (lsr & LSR_DR) == 0)
			break;
		buf[read_cnt++] = uart_read(REG_RBR);
	}
	if (lsr & LSR_DR)
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT,
					OPAL_EVENT_CONSOLE_INPUT);
	else
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT, 0);

	return read_cnt;
}

static struct con_ops uart_con_driver = {
	.read = uart_con_read,
	.write = uart_con_write
};

#ifdef ENABLE_DUMMY_CONSOLE
static void uart_console_poll(void *data __unused)
{
	uint8_t lsr = uart_read(REG_LSR);

	if (lsr & LSR_DR)
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT,
					OPAL_EVENT_CONSOLE_INPUT);
	else
		opal_update_pending_evt(OPAL_EVENT_CONSOLE_INPUT, 0);
}
#endif /* ENABLE_DUMMY_CONSOLE */

static void uart_init_hw(unsigned int speed, unsigned int clock)
{
	unsigned int dll = (clock / 16) / speed;

	uart_write(REG_LCR, 0x00);
	uart_write(REG_IER, 0xff);
	uart_write(REG_IER, 0x00);
	uart_write(REG_LCR, LCR_DLAB);
	uart_write(REG_DLL, dll & 0xff);
	uart_write(REG_DLM, dll >> 8);
	uart_write(REG_LCR, 0x03); /* 8N1 */
	uart_write(REG_MCR, 0x03); /* RTS/DTR */
	uart_write(REG_FCR, 0x07); /* clear & en. fifos */
}

void uart_init(void)
{
	const struct dt_property *prop;
	struct dt_node *n;
	char *path __unused;

	if (!lpc_present())
		return;

	/* We support only one */
	n = dt_find_compatible_node(dt_root, NULL, "ns16550");
	if (!n)
		return;

	/* Get IO base */
	prop = dt_find_property(n, "reg");
	if (!prop) {
		prerror("UART: Can't find reg property\n");
		return;
	}
	if (dt_property_get_cell(prop, 0) != OPAL_LPC_IO) {
		prerror("UART: Only supports IO addresses\n");
		return;
	}
	uart_base = dt_property_get_cell(prop, 1);

	uart_init_hw(dt_prop_get_u32(n, "current-speed"),
		     dt_prop_get_u32(n, "clock-frequency"));

	set_console(&uart_con_driver);

#ifdef ENABLE_DUMMY_CONSOLE
	/*
	 * If the dummy console is enabled, we mark the UART as reserved
	 * since we don't want the kernel to start using it with its own
	 * 8250 driver
	 */
	dt_add_property_strings(n, "status", "reserved");

	/*
	 * We also need to register it as a poller in order to set the
	 * event bits for inbound chars.
	 */
	opal_add_poller(uart_console_poll, NULL);
#else
	/* Else, we expose it as our chosen console */
	dt_add_property_strings(n, "status", "ok");
	path = dt_get_path(n);
	dt_add_property_string(dt_chosen, "linux,stdout-path", path);
	free(path);
#endif
}
