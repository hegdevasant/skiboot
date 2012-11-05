#include <skiboot.h>

/* Override this for testing. */
char __rodata_start[16];

#define __rodata_end (__rodata_start + sizeof(__rodata_start))

#include "../device.c"
#include <assert.h>

/* These make it link... */
int fdt_begin_node(void *fdt, const char *name)
{
	return -1;
}

int fdt_property(void *fdt, const char *name, const void *val, int len)
{
	return -1;
}

int fdt_end_node(void *fdt)
{
	return -1;
}

int fdt_create(void *buf, int bufsize)
{
	return -1;
}

int fdt_add_reservemap_entry(void *fdt, uint64_t addr, uint64_t size)
{
	return -1;
}

int fdt_finish_reservemap(void *fdt)
{
	return -1;
}

const char *fdt_strerror(int errval)
{
	return NULL;
}

int main(void)
{
	struct dt_node *root, *c1, *c2, *gc1, *gc2, *gc3, *ggc1, *i;
	struct dt_property *p;
	unsigned int n;

	root = dt_new_root("root");
	assert(!list_top(&root->properties, struct dt_property, list));
	c1 = dt_new(root, "c1");
	assert(!list_top(&c1->properties, struct dt_property, list));
	c2 = dt_new(root, "c2");
	assert(!list_top(&c2->properties, struct dt_property, list));
	gc1 = dt_new(c1, "gc1");
	assert(!list_top(&gc1->properties, struct dt_property, list));
	gc2 = dt_new(c1, "gc2");
	assert(!list_top(&gc2->properties, struct dt_property, list));
	gc3 = dt_new(c1, "gc3");
	assert(!list_top(&gc3->properties, struct dt_property, list));
	ggc1 = dt_new(gc1, "ggc1");
	assert(!list_top(&ggc1->properties, struct dt_property, list));

	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		assert(!list_top(&i->properties, struct dt_property, list));
		dt_add_property_cell(i, "visited", 1);
	}
	assert(n == 6);

	for (n = 0, i = dt_first(root); i; i = dt_next(root, i), n++) {
		p = list_top(&i->properties, struct dt_property, list);
		assert(strcmp(p->name, "visited") == 0);
		assert(p->len == sizeof(u32));
		assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	}
	assert(n == 6);

	dt_add_property_cell(c1, "some-property", 1, 2, 3);
	p = dt_find_property(c1, "some-property");
	assert(p);
	assert(strcmp(p->name, "some-property") == 0);
	assert(p->len == sizeof(u32) * 3);
	assert(fdt32_to_cpu(*(u32 *)p->prop) == 1);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 1)) == 2);
	assert(fdt32_to_cpu(*((u32 *)p->prop + 2)) == 3);

	/* Test freeing a single node */
	assert(!list_empty(&gc1->children));
	dt_free(ggc1);
	assert(list_empty(&gc1->children));

	/* Test rodata logic. */
	assert(!is_rodata("hello"));
	assert(is_rodata(__rodata_start));
	strcpy(__rodata_start, "name");
	ggc1 = dt_new(root, __rodata_start);
	assert(ggc1->name == __rodata_start);

	/* Test string node. */
	dt_add_property_string(ggc1, "somestring", "someval");
	assert(dt_has_node_property(ggc1, "somestring", "someval"));
	assert(!dt_has_node_property(ggc1, "somestrin", "someval"));
	assert(!dt_has_node_property(ggc1, "somestring", "someva"));
	assert(!dt_has_node_property(ggc1, "somestring", "somevale"));

	/* No leaks for valgrind! */
	dt_free(root);
	return 0;
}
