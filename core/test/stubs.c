/* Add any stub functions required for linking here. */
#include <stdlib.h>

static void stub_function(void)
{
	abort();
}

#define STUB(fnname) \
	extern void *fnname __attribute__((weak, alias ("stub_function")))

STUB(fdt_begin_node);
STUB(fdt_property);
STUB(fdt_end_node);
STUB(fdt_create);
STUB(fdt_add_reservemap_entry);
STUB(fdt_finish_reservemap);
STUB(fdt_strerror);
STUB(fdt_check_header);
STUB(_fdt_check_node_offset);
STUB(fdt_next_tag);
STUB(fdt_string);
STUB(fdt_get_name);
STUB(dt_first);
STUB(dt_next);
STUB(dt_has_node_property);
STUB(dt_get_address);
