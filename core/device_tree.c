#include <skiboot.h>
#include <stdarg.h>
#include <libfdt.h>
#include <device_tree.h>
#include <cpu.h>
#include <memory.h>
#include <opal.h>
#include <interrupts.h>

static int fdt_error;
static void *fdt;
static u32 lphandle;

static void save_err(int err)
{
	if (err && !fdt_error)
		fdt_error = err;
}

uint32_t dt_begin_node(const char *name)
{
	save_err(fdt_begin_node(fdt, name));

	dt_property_cell("linux,phandle", ++lphandle);

	return lphandle;
}

void dt_property_string(const char *name, const char *value)
{
	save_err(fdt_property_string(fdt, name, value));
}

void dt_property_cell(const char *name, u32 cell)
{
	save_err(fdt_property_cell(fdt, name, cell));
}

void dt_property_cells(const char *name, int count, ...)
{
	va_list args;

	va_start(args, count);
	save_err(fdt_property_cells_v(fdt, name, count, args));
	va_end(args);
}

void dt_property(const char *name, const void *val, size_t size)
{
	save_err(fdt_property(fdt, name, val, size));
}

void dt_end_node(void)
{
	save_err(fdt_end_node(fdt));
}

static void dump_fdt(void)
{
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
}

void create_dtb(void)
{
	size_t len = 0x10000;

	do {
		lphandle = 0;
		fdt_error = 0;
		fdt = malloc(len);
		if (!fdt) {
			prerror("dtb: could not malloc %lu\n", (long)len);
			return;
		}

		fdt_create(fdt, len);
		save_err(fdt_add_reservemap_entry(fdt, SKIBOOT_BASE,
						  SKIBOOT_SIZE));
		save_err(fdt_finish_reservemap(fdt));

		dt_begin_node("device-tree");
		dt_property_string("name", "device-tree");
		dt_property_string("model", "FIXME");
		dt_property_string("compatible", "ibm,powernv");
		dt_property_cell("#address-cells", 2);
		dt_property_cell("#size-cells", 2);

		/* The ICS node must come before anything that wants to
		 * reference its phandle (ie, anything with interrupt-parent
		 * or interrupt-map properties
		 */
		add_ics_node();
		add_cpu_nodes();
		add_memory_nodes();
		add_icp_nodes();
		add_opal_nodes();
		//add_chosen_node();
		dt_end_node();

		save_err(fdt_finish(fdt));

		if (!fdt_error)
			break;

		free(fdt);
		len *= 2;
	} while (fdt_error == -FDT_ERR_NOSPACE);

	dump_fdt();

	if (fdt_error)
		prerror("dtb: error %s\n", fdt_strerror(fdt_error));
}
