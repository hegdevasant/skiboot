#include <skiboot.h>
#include <spira.h>
#include <cec.h>
#include <p7ioc.h>
#include <p5ioc2.h>
#include <interrupts.h>

/* We keep an array of IO Hubs indexed on the BUID Extension
 *
 * NOTE: If we have to deal with pass-through GX we might want
 *       to add one more bit
 *
 * |  Node  | T| Chip|GX|
 * |--|--|--|--|--|--|--|
 *
 * The OPAL hub ID is thus the index in that array
 *
 * XXX We have no hub level locking, that might be an issue
 * with get_diag_data...
 *
 * XXX This numbering is P7/P7+ centric. P8 has no IO hubs and
 *     much more lax BUID numbering. We simply don't use that
 *     code on P8 at all and directly instanciate PHBs.
 */
#define MAX_IO_HUBS	0x80

static struct io_hub *cec_iohubs[MAX_IO_HUBS];

struct io_hub *cec_get_hub_by_id(uint32_t hub_id)
{
	if (hub_id >= MAX_IO_HUBS)
		return NULL;
	return cec_iohubs[hub_id];
}

void cec_register(struct io_hub *hub)
{
	cec_iohubs[hub->hub_id] = hub;
}

void cec_reset(void)
{
	unsigned int i;

	/* Reset IO Hubs */
	for (i = 0; i < MAX_IO_HUBS; i++) {
		if (!cec_iohubs[i] || !cec_iohubs[i]->ops->reset)
			continue;
		cec_iohubs[i]->ops->reset(cec_iohubs[i]);
	}
}

static int64_t opal_pci_set_hub_tce_memory(uint64_t hub_id,
					   uint64_t tce_mem_addr,
					   uint64_t tce_mem_size)
{
	struct io_hub *hub = cec_get_hub_by_id(hub_id);

	if (!hub)
		return OPAL_PARAMETER;

	if (!hub->ops->set_tce_mem)
		return OPAL_UNSUPPORTED;

	return hub->ops->set_tce_mem(hub, tce_mem_addr, tce_mem_size);
}
opal_call(OPAL_PCI_SET_HUB_TCE_MEMORY, opal_pci_set_hub_tce_memory);

static int64_t opal_pci_get_hub_diag_data(uint64_t hub_id,
					  void *diag_buffer,
					  uint64_t diag_buffer_len)
{
	struct io_hub *hub = cec_get_hub_by_id(hub_id);

	if (!hub)
		return OPAL_PARAMETER;

	if (!hub->ops->get_diag_data)
		return OPAL_UNSUPPORTED;

	return hub->ops->get_diag_data(hub, diag_buffer, diag_buffer_len);
}
opal_call(OPAL_PCI_GET_HUB_DIAG_DATA, opal_pci_get_hub_diag_data);
