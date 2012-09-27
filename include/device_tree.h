#ifndef __DEVICE_TREE_H
#define __DEVICE_TREE_H
#include <stdint.h>

int create_dtb(void);

/* Helpers to cache errors in fdt; use this instead of fdt_* */
void dt_begin_node(const char *name);
void dt_property_string(const char *name, const char *value);
void dt_property_cell(const char *name, u32 cell);
void dt_property(const char *name, const void *val, size_t size);
void dt_end_node(void);
#endif /* __DEVICE_TREE_H */
