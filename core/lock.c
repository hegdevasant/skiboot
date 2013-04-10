/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#include <skiboot.h>
#include <lock.h>
#include <assert.h>
#include <cpu.h>

/* Set to bust locks. Note, this is initialized to true because our
 * lock debugging code is not going to work until we have the per
 * CPU data initialized
 */
bool bust_locks = true;

#ifdef DEBUG_LOCKS

static void lock_error(struct lock *l, const char *reason, uint16_t err)
{
	op_display(OP_FATAL, OP_MOD_LOCK, err);

	fprintf(stderr, "LOCK ERROR: %s @%p (state: 0x%016lx)\n",
		reason, l, l->lock_val);
	abort();
}

void lock_check(struct lock *l)
{
	if ((l->lock_val & 1) && (l->lock_val >> 32) == this_cpu()->pir)
		lock_error(l, "Invalid recursive lock", 0);
}

void unlock_check(struct lock *l)
{
	if (!(l->lock_val & 1))
		lock_error(l, "Unlocking unlocked lock", 1);

	if ((l->lock_val >> 32) != this_cpu()->pir)
		lock_error(l, "Unlocked non-owned lock", 2);
}

#else
static inline void lock_check(struct lock *l) { };
static inline void unlock_check(struct lock *l) { };
#endif /* DEBUG_LOCKS */


void lock(struct lock *l)
{
	if (bust_locks)
		return;

	lock_check(l);
	for (;;) {
		if (try_lock(l))
			break;
		smt_low();
	}
	smt_medium();
}

void unlock(struct lock *l)
{
	if (bust_locks)
		return;

	unlock_check(l);

	lwsync();
	l->lock_val = 0;
}

bool lock_recursive(struct lock *l)
{
	if (bust_locks)
		return false;

	if ((l->lock_val & 1) &&
	    (l->lock_val >> 32) == this_cpu()->pir)
		return false;

	lock(l);
	return true;
}

void init_locks(void)
{
	bust_locks = false;
}
