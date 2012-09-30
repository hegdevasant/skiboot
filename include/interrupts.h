#ifndef __INTERRUPTS_H
#define __INTERRUPTS_H

#include <stdint.h>

extern void add_icp_nodes(void);
extern void add_ics_node(void);
extern uint32_t get_ics_phandle(void);

#endif /* __INTERRUPTS_H */
