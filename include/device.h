#ifndef __DEVICE_H
#define __DEVICE_H
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>

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

/* Add a property node, various forms. */
struct dt_property *dt_add_property(struct dt_node *node,
				    const char *name,
				    const void *val, size_t size);
struct dt_property *dt_add_property_string(struct dt_node *node,
					   const char *name,
					   const char *value);
struct dt_property *dt_add_property_cell(struct dt_node *node,
					 const char *name,
					 u32 cell);
struct dt_property *dt_add_property_multicell(struct dt_node *node,
					      const char *name,
					      int count, ...);
void dt_del_property(struct dt_node *node, struct dt_property *prop);

/* First child of this node. */
struct dt_node *dt_first(const struct dt_node *root);

/* Return next node, or NULL. */
struct dt_node *dt_next(const struct dt_node *root, const struct dt_node *prev);

/* Find a property by name. */
struct dt_property *dt_find_property(const struct dt_node *node,
				     const char *name);

/* Free a node (and any children). */
void dt_free(struct dt_node *node);

/* Return an fdt. */
void *dt_flatten(const struct dt_node *root);
#endif /* __DEVICE_H */
