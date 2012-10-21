#include <skiboot.h>
#include <opal.h>
#include <stack.h>
#include <lock.h>
#include <fsp.h>
#include <device_tree.h>
#include <cpu.h>
#include <interrupts.h>

/* Pending events to signal via opal_poll_events */
uint64_t opal_pending_events;

void opal_table_init(void)
{
	struct opal_table_entry *s = &__opal_table_start;
	struct opal_table_entry *e = &__opal_table_end;
	extern uint64_t opal_branch_table[];

	printf("OPAL table: %p .. %p, branch table: %p\n",
	       s, e, opal_branch_table);
	while(s < e) {
		uint64_t *func = s->func;
		opal_branch_table[s->token] = *func;
		s++;
	}
}

long opal_bad_token(uint64_t token)
{
	prerror("OPAL: Called with bad token %lld !\n", token);

	return OPAL_PARAMETER;
}

void opal_trace_entry(struct stack_frame *eframe)
{
	if (this_cpu()->pir != mfspr(SPR_PIR)) {
		printf("CPU MISMATCH ! PIR=%04lx cpu @%p -> pir=%04x\n",
		       mfspr(SPR_PIR), this_cpu(), this_cpu()->pir);
		abort();
	}
	printf("OPAL: Entry, token %lld args:\n", eframe->gpr[0]);
	printf("OPAL:  r3=%016llx\n", eframe->gpr[3]);
	printf("OPAL:  r4=%016llx\n", eframe->gpr[4]);
	printf("OPAL:  r5=%016llx\n", eframe->gpr[5]);
	printf("OPAL:  r6=%016llx\n", eframe->gpr[6]);
	printf("OPAL:  r7=%016llx\n", eframe->gpr[7]);
	printf("OPAL:  r8=%016llx\n", eframe->gpr[8]);
	printf("OPAL:  r9=%016llx\n", eframe->gpr[9]);
	printf("OPAL: r10=%016llx\n", eframe->gpr[10]);
	printf("OPAL: r11=%016llx\n", eframe->gpr[11]);
	printf("OPAL: caller LR: %016llx SP: %016llx\n",
	       eframe->lr, eframe->gpr[1]);
}

void add_opal_nodes(void)
{
	uint64_t base, entry, size;
	extern uint32_t opal_entry;

	base = SKIBOOT_BASE;
	size = SKIBOOT_SIZE;
	entry = (uint64_t)&opal_entry;

	dt_begin_node("ibm,opal");
	dt_property_cell("#address-cells", 0);
	dt_property_cell("#size-cells", 0);
	dt_property_string("compatible", "ibm,opal-v2");
	dt_property_cells("opal-base-address", 2, base >> 32,
			  base & 0xffffffff);
	dt_property_cells("opal-entry-address", 2, entry >> 32,
			  entry & 0xffffffff);
	dt_property_cells("opal-runtime-size", 2, size >> 32,
			  size & 0xffffffff);
	add_opal_interrupts();
	add_opal_console_nodes();
	add_opal_nvram_node();
	//add_opal_oppanel_node();
	//add_opal_firmware_node();
	//add_opal_errlog_node();
	dt_end_node();
}

void opal_update_pending_evt(uint64_t evt_mask, uint64_t evt_values)
{
	static struct lock evt_lock = LOCK_UNLOCKED;
	uint64_t new_evts;

	/* XXX FIXME: Use atomics instead ??? Or caller locks (con_lock ?) */
	lock(&evt_lock);
	new_evts = (opal_pending_events & ~evt_mask) | evt_values;
#ifdef OPAL_TRACE_EVT_CHG
	printf("OPAL: Evt change: 0x%016llx -> 0x%016llx\n",
	       opal_pending_events, new_evts);
#endif
	opal_pending_events = new_evts;
	unlock(&evt_lock);
}


static uint64_t opal_test_func(uint64_t arg)
{
	printf("OPAL: Test function called with arg 0x%llx\n", arg);

	return 0xfeedf00d;
}
opal_call(OPAL_TEST, opal_test_func);

static int64_t opal_poll_events(uint64_t *outstanding_event_mask)
{
	/* Poll the FSP */
	fsp_poll();

	/* Poll the console buffers */
	fsp_console_poll();

	if (outstanding_event_mask)
		*outstanding_event_mask = opal_pending_events;

	return OPAL_SUCCESS;
}
opal_call(OPAL_POLL_EVENTS, opal_poll_events);

static int64_t opal_cec_power_down(uint64_t request)
{
	/* Request is:
	 *
	 * 0 = normal
	 * 1 = immediate
	 * (we do not allow 2 for "pci cfg reset" just yet)
	 */

	if (request !=0 && request != 1)
		return OPAL_PARAMETER;

	if (fsp_queue_msg(fsp_mkmsg(FSP_CMD_POWERDOWN_NORM, 1, request),
			  fsp_freemsg))
		return OPAL_INTERNAL_ERROR;

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_POWER_DOWN, opal_cec_power_down);

static int64_t opal_cec_reboot(void)
{
	if (fsp_queue_msg(fsp_mkmsg(FSP_CMD_REBOOT, 0), fsp_freemsg))
		return OPAL_INTERNAL_ERROR;

	return OPAL_SUCCESS;
}
opal_call(OPAL_CEC_REBOOT, opal_cec_reboot);

