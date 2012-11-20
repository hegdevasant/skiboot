#ifndef __DEVICE_H
#define __DEVICE_H
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>

/* Any property or node with this prefix will not be passed to the kernel. */
#define DT_PRIVATE	"skiboot,"

/*
 * An in-memory representation of a node in the device tree.
 *
 * This is trivially flattened into an fdt.
 *
 * Note that the add_* routines will make a copy of the name if it's not
 * a read-only string (ie. usually a string literal).
 */
struct dt_property {
	struct list_node list;
	const char *name;
	/* For our internal use. */
	void *priv;
	size_t len;
	char prop[/* len */];
};

struct dt_node {
	const char *name;
	struct list_node list;
	struct list_head properties;
	struct list_head children;
	struct dt_node *parent;
	u32 phandle;
	/* For our internal use. */
	void *priv;
};

/* Create a root node: ie. a parentless one. */
struct dt_node *dt_new_root(const char *name);
/* Graft a root node into this tree. */
void dt_attach_root(struct dt_node *parent, struct dt_node *root);

/* Add a child node. */
struct dt_node *dt_new(struct dt_node *parent, const char *name);
struct dt_node *dt_new_addr(struct dt_node *parent, const char *name,
			    uint64_t unit_addr);

/* Add a property node, various forms. */
struct dt_property *dt_add_property(struct dt_node *node,
				    const char *name,
				    const void *val, size_t size);
struct dt_property *dt_add_property_string(struct dt_node *node,
					   const char *name,
					   const char *value);
/* Given out enough GCC extensions, we will achieve enlightenment! */
#define dt_add_property_strings(node, name, ...)			\
	__dt_add_property_strings((node), ((name)),			\
			    sizeof((const char *[]) { __VA_ARGS__ })/sizeof(const char *), \
			    __VA_ARGS__)

struct dt_property *__dt_add_property_strings(struct dt_node *node,
					      const char *name,
					      int count, ...);

/* Given out enough GCC extensions, we will achieve enlightenment! */
#define dt_add_property_cells(node, name, ...)				\
	__dt_add_property_cells((node), ((name)),			\
			    sizeof((u32[]) { __VA_ARGS__ })/sizeof(u32), \
			    __VA_ARGS__)

struct dt_property *__dt_add_property_cells(struct dt_node *node,
					    const char *name,
					    int count, ...);

static inline struct dt_property *dt_add_property_u64(struct dt_node *node,
						      const char *name, u64 val)
{
	return dt_add_property_cells(node, name, (u32)(val >> 32), (u32)val);
}

void dt_del_property(struct dt_node *node, struct dt_property *prop);

u32 dt_property_get_cell(const struct dt_property *prop, u32 index);

static inline u64 dt_property_get_u64(struct dt_property *prop)
{
	assert(prop->len == sizeof(u64));
	return ((u64)dt_property_get_cell(prop, 0) << 32)
		| dt_property_get_cell(prop, 1);
}

/* First child of this node. */
struct dt_node *dt_first(const struct dt_node *root);

/* Return next node, or NULL. */
struct dt_node *dt_next(const struct dt_node *root, const struct dt_node *prev);

/* Find a property by name. */
struct dt_property *dt_find_property(const struct dt_node *node,
				     const char *name);

/* Find a property by name, check if it's the same as val. */
bool dt_has_node_property(const struct dt_node *node,
			  const char *name, const char *val);

/* Free a node (and any children). */
void dt_free(struct dt_node *node);

/* Return an fdt. */
void *dt_flatten(const struct dt_node *root);

/* Parse an initial fdt */
void dt_expand(const void *fdt);

#endif /* __DEVICE_H */
