/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
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

/* This is shared with device_tree.c .. make it static when
 * the latter is gone (hopefully soon)
 */
extern u32 last_phandle;

extern struct dt_node *dt_root;
extern struct dt_node *dt_chosen;

/* Create a root node: ie. a parentless one. */
struct dt_node *dt_new_root(const char *name);

/* Graft a root node into this tree. */
bool dt_attach_root(struct dt_node *parent, struct dt_node *root);

/* Add a child node. */
struct dt_node *dt_new(struct dt_node *parent, const char *name);
struct dt_node *dt_new_addr(struct dt_node *parent, const char *name,
			    uint64_t unit_addr);
struct dt_node *dt_new_2addr(struct dt_node *parent, const char *name,
			     uint64_t unit_addr0, uint64_t unit_addr1);

/* Add a property node, various forms. */
struct dt_property *dt_add_property(struct dt_node *node,
				    const char *name,
				    const void *val, size_t size);
struct dt_property *dt_add_property_string(struct dt_node *node,
					   const char *name,
					   const char *value);
struct dt_property *dt_add_property_nstr(struct dt_node *node,
					 const char *name,
					 const char *value, unsigned int vlen);

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

/* First child of this node. */
struct dt_node *dt_first(const struct dt_node *root);

/* Return next node, or NULL. */
struct dt_node *dt_next(const struct dt_node *root, const struct dt_node *prev);

/* Iterate nodes */
#define dt_for_each_node(root, node) \
	for (node = dt_first(root); node; node = dt_next(root, node))

#define dt_for_each_child(parent, node) \
	list_for_each(&parent->children, node, list)

/* Check a compatible property */
bool dt_node_is_compatible(const struct dt_node *node, const char *compat);

/* Find a node based on compatible property */
struct dt_node *dt_find_compatible_node(struct dt_node *root,
					struct dt_node *prev,
					const char *compat);

#define dt_for_each_compatible(root, node, compat)	\
	for (node = NULL; 			        \
	     (node = dt_find_compatible_node(root, node, compat)) != NULL;)

/* Build the full path for a node. Return a new block of memory, caller
 * shall free() it
 */
char *dt_get_path(const struct dt_node *node);

/* Find a node by path */
struct dt_node *dt_find_by_path(struct dt_node *root, const char *path);

/* Find a node by phandle */
struct dt_node *dt_find_by_phandle(struct dt_node *root, u32 phandle);

/* Find a property by name. */
const struct dt_property *dt_find_property(const struct dt_node *node,\
					   const char *name);
const struct dt_property *dt_require_property(const struct dt_node *node,
					      const char *name, int wanted_len);

/* Find a property by name, check if it's the same as val. */
bool dt_has_node_property(const struct dt_node *node,
			  const char *name, const char *val);

/* Free a node (and any children). */
void dt_free(struct dt_node *node);

/* Parse an initial fdt */
void dt_expand(const void *fdt);

/* Simplified accessors */
u64 dt_prop_get_u64(const struct dt_node *node, const char *prop);
u64 dt_prop_get_u64_def(const struct dt_node *node, const char *prop, u64 def);
u32 dt_prop_get_u32(const struct dt_node *node, const char *prop);
u32 dt_prop_get_u32_def(const struct dt_node *node, const char *prop, u32 def);
const void *dt_prop_get(const struct dt_node *node, const char *prop);
const void *dt_prop_get_def(const struct dt_node *node, const char *prop,
			    void *def);

/* Parsing helpers */
u32 dt_n_address_cells(const struct dt_node *node);
u32 dt_n_size_cells(const struct dt_node *node);
u64 dt_get_number(const void *pdata, unsigned int cells);

/* Address accessors ("reg" properties parsing). No translation,
 * only support "simple" address forms (1 or 2 cells). Asserts
 * if address doesn't exist
 */
u64 dt_get_address(const struct dt_node *node, unsigned int index,
		   u64 *out_size);

/* Count "reg" property entries */
unsigned int dt_count_addresses(const struct dt_node *node);

/* Address translation
 *
 * WARNING: Current implementation is simplified and will not
 * handle complex address formats with address space indicators
 * nor will it handle "ranges" translations yet... (XX TODO)
 */
u64 dt_translate_address(const struct dt_node *node, unsigned int index,
			 u64 *out_size);

void dt_init_misc(void);

#endif /* __DEVICE_H */
