#ifndef __CONSOLE_H
#define __CONSOLE_H

#include <lock.h>

/* Console driver */
struct con_ops {
	size_t (*write)(const char *buf, size_t len);
};

extern struct lock con_lock;

extern bool flush_console(void);
extern bool __flush_console(void);
extern void set_console(struct con_ops *driver);

#endif /* __CONSOLE_H */
