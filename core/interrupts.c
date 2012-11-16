#include <skiboot.h>
#include <device_tree.h>
#include <cpu.h>
#include <fsp.h>
#include <interrupts.h>
#include <opal.h>
#include <io.h>
#include <cec.h>
#include <device.h>
#include <ccan/str/str.h>

/* ICP registers */
#define ICP_XIRR		0x4	/* 32-bit access */
#define ICP_CPPR		0x4	/* 8-bit access */
#define ICP_MFRR		0xc	/* 8-bit access */


/*
 * This takes a 5-bit chip id (node:3 + chip:2) and returns a 20 bit
 * value representing the PSI interrupt. This includes all the fields
 * above, ie, is a global interrupt number
 */
uint32_t get_psi_interrupt(uint32_t chip_id)
{
	uint32_t irq;

	/* Get the node ID bits into position */
	irq  = (chip_id & 0x1c) << (4 + 9 + 1 + 2 + 1);
	/* Get the chip ID bits into position */
	irq |= (chip_id & 0x03) << (4 + 9 + 1);
	/* Add in the BUID */
	irq |= PSI_IRQ_BUID << 4;

	return irq;
}

uint32_t get_ics_phandle(void)
{
	struct dt_node *i;

	for (i = dt_first(dt_root); i; i = dt_next(dt_root, i)) {
		if (streq(i->name, "interrupt-controller@0")) {
			return i->phandle;
		}
	}
	abort();
}

void add_opal_interrupts(struct dt_node *opal)
{
	/* We support up to 32 chips, thus 32 PSI interrupts */
#define MAX_PSI_IRQS	32

	uint32_t irqs[MAX_PSI_IRQS];
	unsigned int psi_irq_count;

	/* OPAL currently wants to be forwarded the PSI interrupts
	 *
	 * Later it might want to handle more interrupts, but for
	 * now let's stick to those
	 */
	psi_irq_count = fsp_get_interrupts(irqs, MAX_PSI_IRQS);

	/* The opal-interrupts property has one cell per interrupt,
	 * it is not a standard interrupt property
	 */
	dt_add_property(opal, "opal-interrupts", irqs, psi_irq_count * 4);
}

static u64 this_thread_ibase(void)
{
	u64 ibase;
	struct dt_node *cpu = get_cpu_node(cpu_get_thread0(this_cpu()));

	ibase = dt_property_get_u64(dt_find_property(cpu, DT_PRIVATE "ibase"));
	
	/* Adjust for thread */
	ibase += 0x1000 * cpu_get_thread_index(this_cpu());

	return ibase;
}

/* This is called on a fast reboot to sanitize the ICP. We set our priority
 * to 0 to mask all interrupts and make sure no IPI is on the way
 */
void reset_cpu_icp(void)
{
	void *icp = (void *)this_thread_ibase();

	/* Clear pending IPIs */
	out_8(icp + ICP_MFRR, 0xff);

	/* Set priority to max, ignore all incoming interrupts, EOI IPIs */
	out_be32(icp + ICP_XIRR, 2);
}

/* Used by the PSI code to send an EOI during reset. This will also
 * set the CPPR to 0 which should already be the case anyway
 */
void icp_send_eoi(uint32_t interrupt)
{
	void *icp = (void *)this_thread_ibase();

	/* Set priority to max, ignore all incoming interrupts */
	out_be32(icp + ICP_XIRR, interrupt & 0xffffff);
}

static int64_t opal_set_xive(uint32_t isn, uint16_t server, uint8_t priority)
{
	if (IRQ_BUID(isn) == PSI_IRQ_BUID)
		return fsp_set_xive(isn, server, priority);

	/* XXX Add NX */

	/* Everything else goes to the IOCs */
	return cec_set_xive(isn, server, priority);
}
opal_call(OPAL_SET_XIVE, opal_set_xive);

static int64_t opal_get_xive(uint32_t isn, uint16_t *server, uint8_t *priority)
{
	if (IRQ_BUID(isn) == PSI_IRQ_BUID)
		return fsp_get_xive(isn, server, priority);

	/* XXX Add NX */

	/* Everything else goes to the IOCs */
	return cec_get_xive(isn, server, priority);
}
opal_call(OPAL_GET_XIVE, opal_get_xive);

int64_t opal_handle_interrupt(uint32_t isn, uint64_t *outstanding_event_mask)
{
	/* We only support PSI interrupts atm */
	if (IRQ_BUID(isn) != PSI_IRQ_BUID)
		return OPAL_PARAMETER;

	/* Handle the interrupt at the FSP level (somewhat equivalent
	 * to fsp_poll(), see comments in the code for differences
	 */
	fsp_psi_interrupt(isn);

	/* Poll the console buffers on any interrupt since we don't
	 * get send notifications
	 */
	fsp_console_poll();

	/* Update output events */
	if (outstanding_event_mask)
		*outstanding_event_mask = opal_pending_events;

	return OPAL_SUCCESS;
}
opal_call(OPAL_HANDLE_INTERRUPT, opal_handle_interrupt);
