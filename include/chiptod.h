#ifndef __CHIPTOD_H
#define __CHIPTOD_H

/* The ChipTOD is the HW facility that maintains a synchronized
 * time base across the fabric.
 */

extern void chiptod_init(u32 master_cpu);

#endif /* __CHIPTOD_H */
