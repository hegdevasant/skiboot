#include <skiboot.h>
#include <stack.h>
#include <opal.h>
#include <processor.h>
#include <ccan/build_assert/build_assert.h>

static uint64_t client_mc_address;

extern uint8_t exc_primary_start;
extern uint8_t exc_primary_end;

extern uint32_t exc_primary_patch_branch;

extern uint8_t exc_secondary_start;
extern uint8_t exc_secondary_end;

extern uint32_t exc_secondary_patch_stack;
extern uint32_t exc_secondary_patch_mfsrr0;
extern uint32_t exc_secondary_patch_mfsrr1;
extern uint32_t exc_secondary_patch_type;
extern uint32_t exc_secondary_patch_mtsrr0;
extern uint32_t exc_secondary_patch_mtsrr1;
extern uint32_t exc_secondary_patch_rfid;

void exception_entry(struct stack_frame *stack)
{
	switch(stack->type) {
	case STACK_ENTRY_MCHECK:
		/* XXX TODO : Implement machine check */
		break;
	case STACK_ENTRY_HMI:
		/* XXX TODO : Implement machine check */
		break;
	case STACK_ENTRY_SOFTPATCH:
		/* XXX TODO : Implement softpatch ? */
		break;
	}
}

static int64_t patch_exception(uint64_t vector, uint64_t glue, bool hv)
{
	uint64_t iaddr;

	/* Copy over primary exception handler */
	memcpy((void *)vector, &exc_primary_start,
	       &exc_primary_end - &exc_primary_start);

	/* Patch branch instruction in primary handler */
	iaddr = vector + exc_primary_patch_branch;
	*(uint32_t *)iaddr |= (glue - iaddr) & 0x03fffffc;

	/* Copy over secondary exception handler */
	memcpy((void *)glue, &exc_secondary_start,
	       &exc_secondary_end - &exc_secondary_start);

	/* Patch-in the vector number */
	*(uint32_t *)(glue + exc_secondary_patch_type) |= vector;

	/*
	 * If machine check, patch GET_STACK to get to the MC stack
	 * instead of the normal stack.
	 *
	 * To simplify the arithmetic involved I make assumptions
	 * on the fact that the base of all CPU stacks is 64k aligned
	 * and that our stack size is < 32k, which means that the
	 * "addi" instruction used in GET_STACK() is always using a
	 * small (<32k) positive offset, which we can then easily
	 * fixup with a simple addition
	 */
	BUILD_ASSERT(STACK_SIZE < 0x8000);
	BUILD_ASSERT(!(CPU_STACKS_BASE & 0xffff));

	if (vector == 0x200) {
		/*
		 * The addi we try to patch is the 3rd instruction
		 * of GET_STACK(). If you change the macro, you must
		 * update this code
		 */
		iaddr = glue + exc_secondary_patch_stack + 8;
		*(uint32_t *)iaddr += MC_STACK_SIZE;
	}

	/* Standard exception ? All done */
	if (!hv)
		goto flush;

	/* HV exception, change the SRR's to HSRRs and rfid to hrfid
	 *
	 * The magic is that mfspr/mtspr of SRR can be turned into the
	 * equivalent HSRR version by OR'ing 0x4800. For rfid to hrfid
	 * we OR 0x200.
	 */
	*(uint32_t *)(glue + exc_secondary_patch_mfsrr0) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_mfsrr1) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_mtsrr0) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_mtsrr1) |= 0x4800;
	*(uint32_t *)(glue + exc_secondary_patch_rfid) |= 0x200;

 flush:
	/* On P7 and later all we need is : */
	sync_icache();

	return OPAL_SUCCESS;
}

static int64_t opal_register_exc_handler(uint64_t opal_exception,
					 uint64_t handler_address,
					 uint64_t glue_cache_line)
{
	switch(opal_exception) {
	case OPAL_MACHINE_CHECK_HANDLER:
		client_mc_address = handler_address;
		return patch_exception(0x200, glue_cache_line, false);
	case OPAL_HYPERVISOR_MAINTENANCE_HANDLER:
		return patch_exception(0xe60, glue_cache_line, true);
#if 0 /* We let Linux handle softpatch */
	case OPAL_SOFTPATCH_HANDLER:
		return patch_exception(0x1500, glue_cache_line, true);
#endif
	default:
		break;
	}
	return OPAL_PARAMETER;
}
opal_call(OPAL_REGISTER_OPAL_EXCEPTION_HANDLER, opal_register_exc_handler);

