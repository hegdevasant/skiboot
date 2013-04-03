#ifndef __LOCK_H
#define __LOCK_H

#include <stdbool.h>
#include <assert.h>
#include <processor.h>
#include <lock.h>

struct lock {
	/* Lock value has bit 63 as lock bit and the PIR of the owner
	 * in the top 32-bit
	 */
	unsigned long lock_val;
};

/* Initializer */
#define LOCK_UNLOCKED	{ .lock_val = 0 }

/* Note vs. libc and locking:
 *
 * The libc only uses locks to protect the malloc pool. The core
 * "sbrk" function will be called under the protection of that lock.
 *
 * It also has very little global state. The printf() family of
 * functions use stack based t buffers and call into skiboot
 * underlying read() and write() which use a console lock.
 *
 * The underlying FSP console code will thus operate within that
 * console lock.
 *
 * The libc does *NOT* lock stream buffer operations, so don't
 * try to scanf() from the same FILE from two different processors.
 *
 * FSP operations are locked using an FSP lock, so all processors
 * can safely call the FSP API
 *
 * Note about ordering:
 *
 * lock() is a full memory barrier. unlock() is a lwsync
 *
 */

extern bool bust_locks;

static inline void init_lock(struct lock *l)
{
	l->lock_val = 0;
}

extern bool try_lock(struct lock *l);
extern void lock(struct lock *l);
extern void unlock(struct lock *l);

/* The debug output can happen while the FSP lock, so we need some kind
 * of recursive lock support here. I don't want all locks to be recursive
 * though, thus the caller need to explicitly call lock_recursive which
 * returns false if the lock was already held by this cpu. If it returns
 * true, then the caller shall release it when done.
 */
extern bool lock_recursive(struct lock *l);

/* Called after per-cpu data structures are available */
extern void init_locks(void);

#endif /* __LOCK_H */
