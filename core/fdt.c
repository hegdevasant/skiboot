#include <skiboot.h>
#include <stdarg.h>
#include <libfdt.h>
#include <device.h>
#include <cpu.h>
#include <memory.h>
#include <opal.h>
#include <interrupts.h>
#include <fsp.h>
#include <cec.h>
#include <vpd.h>
#include <ccan/str/str.h>

static int fdt_error;
static void *fdt;

#undef DEBUG_FDT

static void __save_err(int err, const char *str)
{
#ifdef DEBUG_FDT
	printf("FDT: rc: %d from \"%s\"\n", err, str);
#endif
	if (err && !fdt_error) {
		prerror("FDT: Error %d from \"%s\"\n", err, str);
		fdt_error = err;
	}
}

#define save_err(...) __save_err(__VA_ARGS__, #__VA_ARGS__)

static void dt_property_cell(const char *name, u32 cell)
{
	save_err(fdt_property_cell(fdt, name, cell));
}

static void dt_begin_node(const char *name, uint32_t phandle)
{
	save_err(fdt_begin_node(fdt, name));

	/*
	 * We add both the new style "phandle" and the legacy
	 * "linux,phandle" properties
	 */
	dt_property_cell("linux,phandle", phandle);
	dt_property_cell("phandle", phandle);
}

static void dt_property(const char *name, const void *val, size_t size)
{
	save_err(fdt_property(fdt, name, val, size));
}

static void dt_end_node(void)
{
	save_err(fdt_end_node(fdt));
}

static void dump_fdt(void)
{
#ifdef DEBUG_FDT
	int i, off, depth, err;

	printf("Device tree %u@%p\n", fdt_totalsize(fdt), fdt);

	err = fdt_check_header(fdt);
	if (err) {
		prerror("fdt_check_header: %s\n", fdt_strerror(err));
		return;
	}
	printf("fdt_check_header passed\n");

	printf("fdt_num_mem_rsv = %u\n", fdt_num_mem_rsv(fdt));
	for (i = 0; i < fdt_num_mem_rsv(fdt); i++) {
		u64 addr, size;

		err = fdt_get_mem_rsv(fdt, i, &addr, &size);
		if (err) {
			printf(" ERR %s\n", fdt_strerror(err));
			return;
		}
		printf("  mem_rsv[%i] = %lu@%#lx\n", i, (long)addr, (long)size);
	}

	for (off = fdt_next_node(fdt, 0, &depth);
	     off > 0;
	     off = fdt_next_node(fdt, off, &depth)) {
		int len;
		const char *name;

		name = fdt_get_name(fdt, off, &len);
		if (!name) {
			prerror("fdt: offset %i no name!\n", off);
			return;
		}
		printf("name: %s [%u]\n", name, off);
	}
#endif
}

static void flatten_dt_node(const struct dt_node *root)
{
	const struct dt_node *i;
	const struct dt_property *p;

#ifdef DEBUG_FDT
	printf("FDT: node: %s\n", root->name);
#endif

	list_for_each(&root->properties, p, list) {
		if (strstarts(p->name, DT_PRIVATE))
			continue;
#ifdef DEBUG_FDT
		printf("FDT:   prop: %s size: %ld\n", p->name, p->len);
#endif
		dt_property(p->name, p->prop, p->len);
	}

	list_for_each(&root->children, i, list) {
		dt_begin_node(i->name, i->phandle);
		flatten_dt_node(i);
		dt_end_node();
	}
}

void *create_dtb(const struct dt_node *root)
{
	size_t len = DEVICE_TREE_MAX_SIZE;
	uint64_t sbase, total_size;
	uint32_t old_last_phandle = last_phandle;

	/* Calculate our total size, which is SKIBOOT_SIZE
	 * plus all the CPU stacks
	 */
	sbase = opal_get_base();
	total_size = opal_get_size();

	do {
		if (fdt)
			free(fdt);
		last_phandle = old_last_phandle;
		fdt_error = 0;
		fdt = malloc(len);
		if (!fdt) {
			prerror("dtb: could not malloc %lu\n", (long)len);
			return NULL;
		}

		fdt_create(fdt, len);
		save_err(fdt_add_reservemap_entry(fdt, sbase, total_size));
		save_err(fdt_finish_reservemap(fdt));

		/* Open root node */
		dt_begin_node(root->name, root->phandle);

		/* Unflatten our live tree */
		flatten_dt_node(root);

		/* Close root node */
		dt_end_node();

		save_err(fdt_finish(fdt));

		if (!fdt_error)
			break;

		len *= 2;
	} while (fdt_error == -FDT_ERR_NOSPACE);

	dump_fdt();

	if (fdt_error) {
		prerror("dtb: error %s\n", fdt_strerror(fdt_error));
		return NULL;
	}
	return fdt;
}
