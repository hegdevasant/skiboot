#ifndef __CONSOLE_H
#define __CONSOLE_H

/* Console driver */
struct con_ops {
	size_t (*write)(const char *buf, size_t len);
};

extern bool flush_console(void);
extern void set_console(struct con_ops *driver);

#endif /* __CONSOLE_H */
