/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <opal.h>
#include <stack.h>
#include <lock.h>
#include <fsp.h>
#include <cpu.h>
#include <interrupts.h>
#include <op-panel.h>
#include <device.h>
#include <console.h>
#include <trace.h>
#include <timebase.h>
#include <affinity.h>

/* Pending events to signal via opal_poll_events */
uint64_t opal_pending_events;

/* OPAL dispatch table defined in head.S */
extern uint64_t opal_branch_table[];

/* Number of args expected for each call. */
static u8 opal_num_args[OPAL_LAST+1];

void opal_table_init(void)
{
	struct opal_table_entry *s = __opal_table_start;
	struct opal_table_entry *e = __opal_table_end;

	printf("OPAL table: %p .. %p, branch table: %p\n",
	       s, e, opal_branch_table);
	while(s < e) {
		uint64_t *func = s->func;
		opal_branch_table[s->token] = *func;
		opal_num_args[s->token] = s->nargs;
		s++;
	}
}

long opal_bad_token(uint64_t token)
{
	prerror("OPAL: Called with bad token %lld !\n", token);

	return OPAL_PARAMETER;
}

/* FIXME: Do this in asm */ 
void opal_trace_entry(struct stack_frame *eframe)
{
	union trace t;
	unsigned nargs;

	if (this_cpu()->pir != mfspr(SPR_PIR)) {
		printf("CPU MISMATCH ! PIR=%04lx cpu @%p -> pir=%04x\n",
		       mfspr(SPR_PIR), this_cpu(), this_cpu()->pir);
		abort();
	}
	if (eframe->gpr[0] > OPAL_LAST)
		nargs = 0;
	else
		nargs = opal_num_args[eframe->gpr[0]];

	t.opal.timestamp = mftb();
	t.opal.type = TRACE_OPAL;
	t.opal.len_div_8 = offsetof(struct trace_opal, r3_to_11[nargs]) / 8;
	t.opal.cpu = this_cpu()->pir;
	t.opal.token = eframe->gpr[0];
	t.opal.lr = eframe->lr;
	t.opal.sp = eframe->gpr[1];
	memcpy(t.opal.r3_to_11, &eframe->gpr[3], nargs*sizeof(u64));

	trace_add(&t);
}

void __opal_register(uint64_t token, void *func, unsigned int nargs)
{
	uint64_t *opd = func;

	assert(token <= OPAL_LAST);

	opal_branch_table[token] = *opd;
	opal_num_args[token] = nargs;
}

static void add_opal_firmware_node(struct dt_node *opal)
{
	struct dt_node *firmware = dt_new(opal, "firmware");

	dt_add_property_string(firmware, "compatible", "ibm,opal-firmware");
	dt_add_property_string(firmware, "name", "firmware");
	dt_add_property_string(firmware, "git-id", gitid);
}

void add_opal_nodes(void)
{
	uint64_t base, entry, size;
	extern uint32_t opal_entry;
	struct dt_node *opal;

	/* XXX TODO: Reorg this. We should create the base OPAL
	 * node early on, and have the various sub modules populate
	 * their own entries (console etc...)
	 *
	 * The logic of which console backend to use should be
	 * extracted
	 */

	entry = (uint64_t)&opal_entry;
	base = SKIBOOT_BASE;
	size = (CPU_STACKS_BASE +
		(cpu_max_pir + 1) * STACK_SIZE) - SKIBOOT_BASE;

	opal = dt_new(dt_root, "ibm,opal");
	dt_add_property_cells(opal, "#address-cells", 0);
	dt_add_property_cells(opal, "#size-cells", 0);
	dt_add_property_strings(opal, "compatible", "ibm,opal-v2",
				"ibm,opal-v3");
	dt_add_property_u64(opal, "opal-base-address", base);
	dt_add_property_u64(opal, "opal-entry-address", entry);
	dt_add_property_u64(opal, "opal-runtime-size", size);
	add_opal_interrupts(opal);
	add_opal_nvram_node(opal);
	add_opal_oppanel_node(opal);
	add_opal_firmware_node(opal);
	add_associativity_ref_point(opal);

	if (fsp_present())
		fsp_console_add_nodes(opal);
#ifdef ENABLE_DUMMY_CONSOLE
	else
		dummy_console_add_nodes(opal);
#endif

	//add_opal_errlog_node();
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
opal_call(OPAL_TEST, opal_test_func, 1);

struct opal_poll_entry {
	struct list_node	link;
	void			(*poller)(void *data);
	void			*data;
};

static struct list_head opal_pollers = LIST_HEAD_INIT(opal_pollers);

void opal_add_poller(void (*poller)(void *data), void *data)
{
	struct opal_poll_entry *ent;

	ent = zalloc(sizeof(struct opal_poll_entry));
	assert(ent);
	ent->poller = poller;
	ent->data = data;
	list_add_tail(&opal_pollers, &ent->link);
}

void opal_del_poller(void (*poller)(void *data))
{
	struct opal_poll_entry *ent;

	list_for_each(&opal_pollers, ent, link) {
		if (ent->poller == poller) {
			list_del(&ent->link);
			free(ent);
			return;
		}
	}
}


static int64_t opal_poll_events(uint64_t *outstanding_event_mask)
{
	struct opal_poll_entry *poll_ent;

	list_for_each(&opal_pollers, poll_ent, link)
		poll_ent->poller(poll_ent->data);

	if (outstanding_event_mask)
		*outstanding_event_mask = opal_pending_events;

	return OPAL_SUCCESS;
}
opal_call(OPAL_POLL_EVENTS, opal_poll_events, 1);

