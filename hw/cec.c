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
 */
#define MAX_IO_HUBS	0x80

static struct io_hub *cec_iohubs[MAX_IO_HUBS];

struct io_hub *cec_get_hub_by_id(uint32_t hub_id)
{
	if (hub_id >= MAX_IO_HUBS)
		return NULL;
	return cec_iohubs[hub_id];
}

int64_t cec_get_xive(uint32_t isn, uint16_t *server, uint8_t *priority)
{
	struct io_hub *hub;
	uint32_t id;

	/* We index our hubs by BUID extension */
	id = IRQ_BEXT(isn);
	if (id >= MAX_IO_HUBS)
		return OPAL_PARAMETER;

	hub = cec_iohubs[id];
	if (!hub)
		return OPAL_PARAMETER;

	return hub->ops->get_xive(hub, isn, server, priority);
}

int64_t cec_set_xive(uint32_t isn, uint16_t server, uint8_t priority)
{
	struct io_hub *hub;
	uint32_t id;

	/* We index our hubs by BUID extension */
	id = IRQ_BEXT(isn);
	if (id >= MAX_IO_HUBS)
		return OPAL_PARAMETER;

	hub = cec_iohubs[id];
	if (!hub)
		return OPAL_PARAMETER;

	return hub->ops->set_xive(hub, isn, server, priority);
}

void add_cec_nodes(void)
{
	unsigned int i;

	for (i = 0; i < MAX_IO_HUBS; i++) {
		if (!cec_iohubs[i] || !cec_iohubs[i]->ops->add_nodes)
			continue;
		cec_iohubs[i]->ops->add_nodes(cec_iohubs[i]);
	}
}

/*
 * TODO: Currently we just walk the HDIF data and instanciate
 * the backplane IO Hubs if we find any, that's it
 *
 * If we are going to support more hardware, we shoudl operate
 * in two passes instead:
 *
 *  - Build a tree of detected hubs, so we can handle cards,
 *    pass-through etc... and know the dependencies
 *
 *  - Walk that tree to intialize the Hubs in the right order
 *
 * XXX Locking in case we do hotplug of IO drawers ?
 */

static void cec_make_iochips(const void *sp_iohubs)
{
	unsigned int i, hub_id;
	int count;	

	count = HDIF_get_iarray_size(sp_iohubs, CECHUB_FRU_IO_HUBS);
	if (count < 1) {
		prerror("CEC: IO Hub with no chips !\n");
		return;
	}

	printf("CEC:   %d chips:\n", count);

	for (i = 0; i < count; i++) {
		const struct cechub_io_hub *hub;
		unsigned int size;

		hub = HDIF_get_iarray_item(sp_iohubs, CECHUB_FRU_IO_HUBS,
					   i, &size);
		if (!hub || size < sizeof(struct cechub_io_hub)) {
			prerror("CEC:     IO-HUB Chip %d bad idata\n", i);
			continue;
		}
		printf("CEC:   Chip %d:\n", i);
		switch (hub->flags & CECHUB_HUB_FLAG_STATE_MASK) {
		case CECHUB_HUB_FLAG_STATE_OK:
			printf("CEC:     OK\n");
			break;
		case CECHUB_HUB_FLAG_STATE_FAILURES:
			printf("CEC:     OK with failures\n");
			break;
		case CECHUB_HUB_FLAG_STATE_NOT_INST:
			printf("CEC:     Not installed\n");
			continue;
		case CECHUB_HUB_FLAG_STATE_UNUSABLE:
			printf("CEC:     Unusable");
			continue;
		}

		hub_id = hub->buid_ext;
		if (hub_id > MAX_IO_HUBS) {
			printf("CEC:     BUID Extension out of "
			       " supported range (%x)!\n", hub->buid_ext);
			continue;
		}
		if (cec_iohubs[hub_id]) {
			printf("CEC:     BUID Extension collision (%x) !\n",
			       hub->buid_ext);
			continue;
		}
		switch(hub->iohub_id) {
		case CECHUB_HUB_P7IOC:
			printf("CEC:     P7IOC !\n");
			cec_iohubs[hub_id] = p7ioc_create_hub(hub, hub_id);
			break;
		case CECHUB_HUB_P5IOC2:
			printf("CEC:     P5IOC2 !\n");
			cec_iohubs[hub_id] = p5ioc2_create_hub(hub, hub_id);
			break;
		default:
			printf("CEC:     Hub ID 0x%04x unsupported !\n",
			       hub->iohub_id);
		}
	}
}

void cec_init(void)
{
	const void *sp_iohubs;
	unsigned int i, size;

	/* Look for IO Hubs */
	sp_iohubs = spira.ntuples.cec_iohub_fru.addr;
	if (!sp_iohubs) {
		prerror("CEC: Cannot locate IO Hub FRU data !\n");
		return;
	}
	for (i = 0; i < spira.ntuples.cec_iohub_fru.act_cnt; i++) {
		const struct cechub_hub_fru_id *fru_id_data;
		unsigned int type;
		static const char *typestr[] = {
			"Reservation",
			"Card",
			"CPU Card",
			"Backplane",
			"Backplane Extension"
		};
		fru_id_data = HDIF_get_idata(sp_iohubs, CECHUB_FRU_ID_DATA_AREA,
					     &size);
		if (!fru_id_data || size < sizeof(struct cechub_hub_fru_id)) {
			prerror("CEC: IO-HUB FRU %d, bad ID data\n", i);
			goto next_hub;
		}
		type = fru_id_data->card_type;

		printf("CEC: HUB FRU %d is %s\n",
		       i, type > 4 ? "Unknown" : typestr[type]);

		/*
		 * We currently only handle the backplane (Juno). This might
		 * need to be revisited if we ever want to support more
		 */
		if (type != CECHUB_FRU_TYPE_CEC_BKPLANE) {
			prerror("CEC:   Unsupported type\n");
			goto next_hub;
		}

		/* We don't support Hubs connected to pass-through ports */
		if (fru_id_data->flags & (CECHUB_FRU_FLAG_HEADLESS |
					  CECHUB_FRU_FLAG_PASSTHROUGH)) {
			prerror("CEC:   Headless or Passthrough unsupported\n");
			goto next_hub;
		}

		/* Ok, we have a reasonable candidate */
		cec_make_iochips(sp_iohubs);
	next_hub:
		sp_iohubs += spira.ntuples.cec_iohub_fru.alloc_len;
	}

	/* Initialize all discovered PCI slots */
	pci_init_slots();
}

void cec_reset(void)
{
	unsigned int i;

	/* Remove all PCI devices */
	pci_reset();

	/* Reset IO Hubs */
	for (i = 0; i < MAX_IO_HUBS; i++) {
		if (!cec_iohubs[i] || !cec_iohubs[i]->ops->reset)
			continue;
		cec_iohubs[i]->ops->reset(cec_iohubs[i]);
	}

	/* Initialize all discovered PCI slots */
	pci_init_slots();
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
