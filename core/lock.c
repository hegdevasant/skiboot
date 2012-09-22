#include <skiboot.h>
#include <lock.h>
#include <assert.h>

#ifdef DEBUG_LOCKS

static void lock_error(struct lock *l, const char *reason)
{
	fprintf(stderr, "LOCK ERROR: %s @%p (state: 0x%016lx)\n",
		reason, l, l->lock_val);
	abort();
}

void lock_check(struct lock *l)
{
	if ((l->lock_val & 1) && (l->lock_val >> 32) == mfspr(SPR_PIR))
		lock_error(l, "Invalid recursive lock");
}

void unlock_check(struct lock *l)
{
	if (!(l->lock_val & 1))
		lock_error(l, "Unlocking unlocked lock");

	if ((l->lock_val >> 32) != mfspr(SPR_PIR))
		lock_error(l, "Unlocked non-owned lock");
}

#endif /* DEBUG_LOCKS */
