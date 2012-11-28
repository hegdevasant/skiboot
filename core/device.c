#include <device.h>
#include <stdlib.h>
#include <skiboot.h>
#include <libfdt/libfdt.h>
#include <libfdt/libfdt_internal.h>
#include <ccan/str/str.h>

static bool is_rodata(const void *p)
{
	return ((char *)p >= __rodata_start && (char *)p < __rodata_end);
}

static const char *take_name(const char *name)
{
	if (!is_rodata(name) && !(name = strdup(name))) {
		prerror("Failed to allocate copy of name");
		abort();
	}
	return name;
}

static void free_name(const char *name)
{
	if (!is_rodata(name))
		free((char *)name);
}

/* Used to give unique handles. */
static u32 phandle = 0;

static struct dt_node *new_node(const char *name)
{
	struct dt_node *node = malloc(sizeof *node);
	if (!node) {
		prerror("Failed to allocate node\n");
		abort();
	}

	node->name = take_name(name);
	node->parent = NULL;
	list_head_init(&node->properties);
	list_head_init(&node->children);
	/* FIXME: locking? */
	node->phandle = ++phandle;
	node->priv = NULL;
	return node;
}

struct dt_node *dt_new_root(const char *name)
{
	return new_node(name);
}

bool dt_attach_root(struct dt_node *parent, struct dt_node *root)
{
	struct dt_node *node;

	/* Look for duplicates */

	assert(!root->parent);
	dt_for_each_child(parent, node) {
		if (!strcmp(node->name, root->name)) {
			prerror("DT: dt_attach_node failed, duplicate %s\n",
				root->name);
			return false;
		}
	}
	list_add_tail(&parent->children, &root->list);
	root->parent = parent;

	return true;
}
	
struct dt_node *dt_new(struct dt_node *parent, const char *name)
{
	struct dt_node *new;
	assert(parent);

	new = new_node(name);
	if (!dt_attach_root(parent, new)) {
		free_name(new->name);
		free(new);
		return NULL;
	}
	return new;
}

struct dt_node *dt_new_addr(struct dt_node *parent, const char *name,
			    uint64_t addr)
{
	char lname[strlen(name) + STR_MAX_CHARS(addr) + 2];
	struct dt_node *new;
	assert(parent);

	snprintf(lname, sizeof(lname), "%s@%llx", name, addr);
	new = new_node(lname);
	dt_attach_root(parent, new);
	return new;
}

static struct dt_property *new_property(struct dt_node *node,
					const char *name, size_t size)
{
	struct dt_property *p = malloc(sizeof(*p) + size);
	if (!p) {
		prerror("Failed to allocate property %s for %s of %lu bytes\n",
			name, node->name, size);
		abort();
	}
	assert(!dt_find_property(node, name));
	assert(strcmp(name, "linux,phandle") != 0);
	assert(strcmp(name, "phandle") != 0);
	p->name = take_name(name);
	p->priv = NULL;
	p->len = size;
	list_add_tail(&node->properties, &p->list);
	return p;
}

struct dt_property *dt_add_property(struct dt_node *node,
				    const char *name,
				    const void *val, size_t size)
{
	struct dt_property *p = new_property(node, name, size);
	memcpy(p->prop, val, size);
	return p;
}

struct dt_property *dt_add_property_string(struct dt_node *node,
					   const char *name,
					   const char *value)
{
	return dt_add_property(node, name, value, strlen(value)+1);
}

struct dt_property *__dt_add_property_cells(struct dt_node *node,
					    const char *name,
					    int count, ...)
{
	struct dt_property *p;
	u32 *val;
	unsigned int i;
	va_list args;

	p = new_property(node, name, count * sizeof(u32));
	val = (u32 *)p->prop;
	va_start(args, count);
	for (i = 0; i < count; i++)
		val[i] = cpu_to_fdt32(va_arg(args, u32));
	va_end(args);
	return p;
}

struct dt_property *__dt_add_property_strings(struct dt_node *node,
					      const char *name,
					      int count, ...)
{
	struct dt_property *p;
	unsigned int i, size;
	va_list args;
	char *s;

	va_start(args, count);
	for (i = size = 0; i < count; i++)
		size += strlen(va_arg(args, const char *)) + 1;
	va_end(args);
	if (!size)
		size = 1;
	p = new_property(node, name, size);
	s = (char *)p->prop;
	*s = 0;
	va_start(args, count);
	for (i = 0; i < count; i++) {
		strcpy(s, va_arg(args, const char *));
		s = s + strlen(s) + 1;
	}
	va_end(args);
	return p;
}

void dt_del_property(struct dt_node *node, struct dt_property *prop)
{
	list_del_from(&node->properties, &prop->list);
	free(prop);
}

u32 dt_property_get_cell(const struct dt_property *prop, u32 index)
{
	assert(prop->len >= (index+1)*sizeof(u32));
	/* Always aligned, so this works. */
	return fdt32_to_cpu(((u32 *)prop->prop)[index]);
}

/* First child of this node. */
struct dt_node *dt_first(const struct dt_node *root)
{
	return list_top(&root->children, struct dt_node, list);
}

/* Return next node, or NULL. */
struct dt_node *dt_next(const struct dt_node *root,
			const struct dt_node *prev)
{
	/* Children? */
	if (!list_empty(&prev->children))
		return dt_first(prev);

	do {
		/* More siblings? */
		if (prev->list.next != &prev->parent->children.n)
			return list_entry(prev->list.next, struct dt_node,list);

		/* No more siblings, move up to parent. */
		prev = prev->parent;
	} while (prev != root);

	return NULL;
}

const struct dt_property *dt_find_property(const struct dt_node *node,
					   const char *name)
{
	const struct dt_property *i;

	list_for_each(&node->properties, i, list)
		if (strcmp(i->name, name) == 0)
			return i;
	return NULL;
}

bool dt_has_node_property(const struct dt_node *node,
			  const char *name, const char *val)
{
	const struct dt_property *p = dt_find_property(node, name);

	if (!p)
		return false;

	return p->len == strlen(val) + 1 && memcmp(p->prop, val, p->len) == 0;
}

bool dt_node_is_compatible(const struct dt_node *node, const char *compat)
{
	const struct dt_property *p = dt_find_property(node, "compatible");
	const char *c, *end;
	if (!p)
		return false;
	c = p->prop;
	end = c + p->len;

	while(c < end) {
		if (!strcmp(compat, c))
			return true;
		c += strlen(c) + 1;
	}
	return false;
}

struct dt_node *dt_find_compatible_node(const struct dt_node *root,
					const char *compat)
{
	struct dt_node *node;

	dt_for_each_node(root, node)
		if (dt_node_is_compatible(node, compat))
			return node;
	return NULL;
}

u64 dt_prop_get_u64(const struct dt_node *node, const char *prop)
{
	const struct dt_property *p = dt_find_property(node, prop);

	assert(p);
	assert(p->len == sizeof(u64));

	return ((u64)dt_property_get_cell(p, 0) << 32)
		| dt_property_get_cell(p, 1);
}

u64 dt_prop_get_u64_def(const struct dt_node *node, const char *prop, u64 def)
{
	const struct dt_property *p = dt_find_property(node, prop);

	if (!p)
		return def;

	assert(p->len == sizeof(u64));

	return ((u64)dt_property_get_cell(p, 0) << 32)
		| dt_property_get_cell(p, 1);
}

u32 dt_prop_get_u32(const struct dt_node *node, const char *prop)
{
	const struct dt_property *p = dt_find_property(node, prop);

	assert(p);
	assert(p->len == sizeof(u32));

	return dt_property_get_cell(p, 0);
}

u32 dt_prop_get_u32_def(const struct dt_node *node, const char *prop, u32 def)
{
	const struct dt_property *p = dt_find_property(node, prop);

	if (!p)
		return def;

	assert(p->len == sizeof(u32));

	return dt_property_get_cell(p, 0);
}

void dt_free(struct dt_node *node)
{
	struct dt_node *child;
	struct dt_property *p;

	while ((child = list_top(&node->children, struct dt_node, list)))
		dt_free(child);

	while ((p = list_pop(&node->properties, struct dt_property, list))) {
		free_name(p->name);
		free(p);
	}

	if (node->parent)
		list_del_from(&node->parent->children, &node->list);
	free_name(node->name);
	free(node);
}

static int node_to_fdt(void *fdt, const struct dt_node *node)
{
	int err;
	const struct dt_property *p;
	const struct dt_node *child;

	if (strstarts(node->name, DT_PRIVATE))
		return 0;

	err = fdt_begin_node(fdt, node->name);
	if (err)
		return err;

	err = fdt_property_cell(fdt, "phandle", node->phandle);
	if (err)
		return err;

	list_for_each(&node->properties, p, list) {
		if (strstarts(p->name, DT_PRIVATE))
			continue;
			
		err = fdt_property(fdt, p->name, p->prop, p->len);
		if (err)
			return err;
	}

	list_for_each(&node->children, child, list) {
		err = node_to_fdt(fdt, child);
		if (err)
			return err;
	}
	return fdt_end_node(fdt);
}

void *dt_flatten(const struct dt_node *root)
{
	size_t len = DEVICE_TREE_MAX_SIZE;
	int err;
	void *fdt;

	do {
		fdt = malloc(len);
		if (!fdt) {
			prerror("dtb: could not malloc %lu\n", (long)len);
			return NULL;
		}

		fdt_create(fdt, len);
		err = fdt_add_reservemap_entry(fdt, SKIBOOT_BASE,
					       SKIBOOT_SIZE);
		if (!err)
			err = fdt_finish_reservemap(fdt);
		if (!err)
			err = node_to_fdt(fdt, root);
		if (!err)
			return fdt;

		free(fdt);
		len *= 2;
	} while (err == -FDT_ERR_NOSPACE);

	prerror("dtb: error %s\n", fdt_strerror(err));
	return NULL;
}

static int dt_expand_node(struct dt_node *node, const void *fdt, int fdt_node)
{
	const struct fdt_property *prop;
	int offset, nextoffset, err;
	struct dt_node *child;
	const char *name;
	uint32_t tag;

	if (((err = fdt_check_header(fdt)) != 0)
	    || ((err = _fdt_check_node_offset(fdt, fdt_node)) < 0)) {
		prerror("FDT: Error %d parsing node 0x%x\n", err, fdt_node);
		return -1;
	}

	nextoffset = err;
	do {
		offset = nextoffset;

		tag = fdt_next_tag(fdt, offset, &nextoffset);
		switch (tag) {
		case FDT_PROP:
			prop = _fdt_offset_ptr(fdt, offset);
			name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
			dt_add_property(node, name, prop->data,
					fdt32_to_cpu(prop->len));
			break;
		case FDT_BEGIN_NODE:
			name = fdt_get_name(fdt, offset, NULL);
			child = dt_new_root(name);
			assert(child);
			nextoffset = dt_expand_node(child, fdt, offset);

			/*
			 * This may fail in case of duplicate, keep it
			 * going for now, we may ultimately want to
			 * assert
			 */
			(void)dt_attach_root(node, child);
			break;
		case FDT_END:
			return -1;
		}
	} while (tag != FDT_END_NODE);

	return nextoffset;
}

void dt_expand(const void *fdt)
{
	printf("FDT: Parsing fdt @%p\n", fdt);

	dt_root = dt_new_root("/");

	dt_expand_node(dt_root, fdt, 0);
}

u64 dt_get_number(const void *pdata, unsigned int cells)
{
	const u32 *p = pdata;
	u64 ret = 0;

	while(cells--)
		ret = (ret << 32) | *(p++);
	return ret;
}

u32 dt_n_address_cells(const struct dt_node *node)
{
	if (!node->parent)
		return 0;
	return dt_prop_get_u32_def(node->parent, "#address-cells", 2);
}

u32 dt_n_size_cells(const struct dt_node *node)
{
	if (!node->parent)
		return 0;
	return dt_prop_get_u32_def(node->parent, "#size-cells", 1);
}

u64 dt_get_address(const struct dt_node *node, unsigned int index,
		   u64 *out_size)
{
	const struct dt_property *p;
	u32 na = dt_n_address_cells(node);
	u32 ns = dt_n_size_cells(node);
	u32 pos, n;

	p = dt_find_property(node, "reg");
	assert(p);
	n = (na + ns) * sizeof(u32);
	pos = n * index;
	assert((pos + n) <= p->len);
	if (out_size)
		*out_size = dt_get_number(p->prop + pos + na * sizeof(u32), ns);
	return dt_get_number(p->prop + pos, na);
}

unsigned int dt_count_addresses(const struct dt_node *node)
{
	const struct dt_property *p;
	u32 na = dt_n_address_cells(node);
	u32 ns = dt_n_size_cells(node);
	u32 n;

	p = dt_find_property(node, "reg");
	assert(p);
	n = (na + ns) * sizeof(u32);
	return p->len / n;
}

u64 dt_translate_address(const struct dt_node *node, unsigned int index,
			 u64 *out_size)
{
	/* XXX TODO */
	return dt_get_address(node, index, out_size);
}
