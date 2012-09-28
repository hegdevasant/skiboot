#ifndef __STACKFRAME_H
#define __STACKFRAME_H

#define STACK_ENTRY_OPAL_API	0	/* OPAL call */
#define STACK_ENTRY_MCHECK	1	/* Machine check */
#define STACK_ENTRY_HMI		2	/* Hypervisor maintainance */
#define STACK_ENTRY_RESET	3	/* System reset */

#ifndef __ASSEMBLY__

#include <stdint.h>

/* This is the struct used to save GPRs etc.. on OPAL entry
 * and from some exceptions. It is not always entirely populated
 * depending on the entry type
 */
struct stack_frame {
	/* An ABI GAP where the callee might save things. 112 bytes
	 * should be enough, 256 is nice and round. The first dword
	 * here is the backlink which should pretty much always be 0
	 */
	uint64_t	gap[32];

	/* Entry type */
	uint64_t	type;

	/* GPR save area
	 *
	 * We don't necessarily save everything in here
	 */
	uint64_t	gpr[32];

	/* Other SPR saved
	 *
	 * Only for some exceptions.
	 */
	uint32_t	cr;
	uint32_t	xer;
	uint64_t	ctr;
	uint64_t	lr;
	uint64_t	pc;
	uint64_t	cfar;
};

#endif /* __ASSEMBLY__ */
#endif /* __STACKFRAME_H */

