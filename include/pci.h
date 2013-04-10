/* (C) Copyright IBM Corp., 2013 and provided pursuant to the Technology
 * Licensing Agreement between Google Inc. and International Business
 * Machines Corporation, IBM License Reference Number AA130103030256 and
 * confidentiality governed by the Parties’ Mutual Nondisclosure Agreement
 * number V032404DR, executed by the parties on November 6, 2007, and
 * Supplement V032404DR-3 dated August 16, 2012 (the “NDA”). */
#ifndef __PCI_H
#define __PCI_H

#include <opal.h>
#include <device.h>
#include <ccan/list/list.h>

/*
 * While this might not be necessary in the long run, the existing
 * Linux kernels expect us to provide a device-tree that contains
 * a representation of all PCI devices below the host bridge. Thus
 * we need to perform a bus scan. We don't need to assign MMIO/IO
 * resources, but we do need to assign bus numbers in a way that
 * is going to be compatible with the HW constraints for PE filtering
 * that is naturally aligned power of twos for ranges below a bridge.
 *
 * Thus the structure pci_device is used for the tracking of the
 * detected devices and the later generation of the device-tree.
 *
 * We do not keep a separate structure for a bus, however a device
 * can have children in which case a device is a bridge.
 *
 * Because this is likely to change, we avoid putting too much
 * information in that structure nor relying on it for anything
 * else but the construction of the flat device-tree.
 */
struct pci_device {
	uint16_t		bdfn;
	bool			is_bridge;
	bool			is_pcie;
	bool			is_multifunction;
	uint8_t			dev_type; /* PCIE */
	uint32_t		scan_map;
	struct list_head	children;
	struct list_node	link;
};

/*
 * When generating the device-tree, we need to keep track of
 * the LSI mapping & swizzle it. This state structure is
 * passed by the PHB to pci_add_nodes() and will be used
 * internally.
 *
 * We assume that the interrupt parent (PIC) #address-cells
 * is 0 and #interrupt-cells has a max value of 2.
 */
struct pci_lsi_state {
#define MAX_INT_SIZE	2
	uint32_t int_size;			/* #cells */
	uint32_t int_val[4][MAX_INT_SIZE];	/* INTA...INTD */
	uint32_t int_parent[4];	
};

/*
 * NOTE: All PCI functions return negative OPAL error codes
 *
 * In addition, some functions may return a positive timeout
 * value or some other state information, see the description	
 * of individual functions. If nothing is specified, it's
 * just an error code or 0 (success).
 *
 * Functions that operate asynchronously will return a positive
 * delay value and will require the ->poll() op to be called after
 * that delay. ->poll() will then return success, a negative error
 * code, or another delay.
 *
 * Note: If an asynchronous function returns 0, it has completed
 * successfully and does not require a call to ->poll(). Similarly
 * if ->poll() is called while no operation is in progress, it will
 * simply return 0 (success)
 *
 * Note that all functions except ->lock() itself assume that the
 * caller is holding the PHB lock.
 *
 * TODO: Add more interfaces to control things like link width
 *       reduction for power savings etc...
 */

struct phb;

struct phb_ops {
	/*
	 * Locking. This is called around OPAL accesses
	 */
	void (*lock)(struct phb *phb);
	void (*unlock)(struct phb *phb);

	/*
	 * Config space ops
	 */
	int64_t (*cfg_read8)(struct phb *phb, uint32_t bdfn,
			     uint32_t offset, uint8_t *data);
	int64_t (*cfg_read16)(struct phb *phb, uint32_t bdfn,
			      uint32_t offset, uint16_t *data);
	int64_t (*cfg_read32)(struct phb *phb, uint32_t bdfn,
			      uint32_t offset, uint32_t *data);
	int64_t (*cfg_write8)(struct phb *phb, uint32_t bdfn,
			      uint32_t offset, uint8_t data);
	int64_t (*cfg_write16)(struct phb *phb, uint32_t bdfn,
			       uint32_t offset, uint16_t data);
	int64_t (*cfg_write32)(struct phb *phb, uint32_t bdfn,
			       uint32_t offset, uint32_t data);

	/*
	 * Bus number selection. See pci_scan() for a description
	 */
	uint8_t (*choose_bus)(struct phb *phb, struct pci_device *bridge,
			      uint8_t candidate, uint8_t *max_bus,
			      bool *use_max);
	/*
	 * EEH methods
	 *
	 * The various arguments are identical to the corresponding
	 * OPAL functions
	 */
	int64_t (*eeh_freeze_status)(struct phb *phb, uint64_t pe_number,
				     uint8_t *freeze_state,
				     uint16_t *pci_error_type,
				     uint16_t *severity,
				     uint64_t *phb_status);
	int64_t (*eeh_freeze_clear)(struct phb *phb, uint64_t pe_number,
				    uint64_t eeh_action_token);

	int64_t (*get_diag_data)(struct phb *phb, void *diag_buffer,
				 uint64_t diag_buffer_len);

	int64_t (*next_error)(struct phb *phb, uint64_t *first_frozen_pe,
			      uint16_t *pci_error_type, uint16_t *severity);

	/*
	 * Other IODA methods
	 *
	 * The various arguments are identical to the corresponding
	 * OPAL functions
	 */
	int64_t (*phb_mmio_enable)(struct phb *phb, uint16_t window_type,
				   uint16_t window_num, uint16_t enable);

	int64_t (*set_phb_mem_window)(struct phb *phb, uint16_t window_type,
				      uint16_t window_num,
				      uint64_t starting_real_address,
				      uint64_t starting_pci_address,
				      uint16_t segment_size);

	int64_t (*map_pe_mmio_window)(struct phb *phb, uint16_t pe_number,
				      uint16_t window_type, uint16_t window_num,
				      uint16_t segment_num);

	int64_t (*set_pe)(struct phb *phb, uint64_t pe_number,
			  uint64_t bus_dev_func, uint8_t bus_compare,
			  uint8_t dev_compare, uint8_t func_compare,
			  uint8_t pe_action);

	int64_t (*set_peltv)(struct phb *phb, uint32_t parent_pe,
			     uint32_t child_pe, uint8_t state);

	int64_t (*map_pe_dma_window)(struct phb *phb, uint16_t pe_number,
				     uint16_t window_id, uint16_t tce_levels,
				     uint64_t tce_table_addr,
				     uint64_t tce_table_size,
				     uint64_t tce_page_size);

	int64_t (*map_pe_dma_window_real)(struct phb *phb, uint16_t pe_number,
					  uint16_t dma_window_number,
					  uint64_t pci_start_addr,
					  uint64_t pci_mem_size);

	int64_t (*set_mve)(struct phb *phb, uint32_t mve_number,
			   uint32_t pe_number);

	int64_t (*set_mve_enable)(struct phb *phb, uint32_t mve_number,
				  uint32_t state);

	int64_t (*set_xive_pe)(struct phb *phb, uint32_t pe_number,
			       uint32_t xive_num);

	int64_t (*get_xive_source)(struct phb *phb, uint32_t xive_num,
				   int32_t *interrupt_source_number);

	int64_t (*get_msi_32)(struct phb *phb, uint32_t mve_number,
			      uint32_t xive_num, uint8_t msi_range,
			      uint32_t *msi_address, uint32_t *message_data);

	int64_t (*get_msi_64)(struct phb *phb, uint32_t mve_number,
			      uint32_t xive_num, uint8_t msi_range,
			      uint64_t *msi_address, uint32_t *message_data);

	int64_t (*ioda_reset)(struct phb *phb, bool purge);

	/*
	 * P5IOC2 only
	 */
	int64_t (*set_phb_tce_memory)(struct phb *phb, uint64_t tce_mem_addr,
				      uint64_t tce_mem_size);

	/*
	 * Slot control
	 */

	/* presence_detect - Check for a present device
	 *
	 * Immediate return of:
	 *
	 * OPAL_SHPC_DEV_NOT_PRESENT = 0,
	 * OPAL_SHPC_DEV_PRESENT = 1
	 *
	 * or a negative OPAL error code
	 */
	int64_t (*presence_detect)(struct phb *phb);

	/* link_state - Check link state
	 *
	 * Immediate return of:
	 *
	 * OPAL_SHPC_LINK_DOWN = 0,
	 * OPAL_SHPC_LINK_UP_x1 = 1,
	 * OPAL_SHPC_LINK_UP_x2 = 2,
	 * OPAL_SHPC_LINK_UP_x4 = 4,
	 * OPAL_SHPC_LINK_UP_x8 = 8,
	 * OPAL_SHPC_LINK_UP_x16 = 16,
	 * OPAL_SHPC_LINK_UP_x32 = 32
	 *
	 * or a negative OPAL error code
	 */
	int64_t (*link_state)(struct phb *phb);

	/* power_state - Check slot power state
	 *
	 * Immediate return of:
	 *
	 * OPAL_SLOT_POWER_OFF = 0,
	 * OPAL_SLOT_POWER_ON = 1,
	 *
	 * or a negative OPAL error code
	 */
	int64_t (*power_state)(struct phb *phb);

	/* slot_power_off - Start slot power off sequence
	 *
	 * Asynchronous function, returns a positive delay
	 * or a negative error code
	 */
	int64_t (*slot_power_off)(struct phb *phb);

	/* slot_power_on - Start slot power on sequence
	 *
	 * Asynchronous function, returns a positive delay
	 * or a negative error code.
	 */
	int64_t (*slot_power_on)(struct phb *phb);

	/* PHB power off and on after complete init */
	int64_t (*complete_reset)(struct phb *phb, uint8_t assert);

	/* hot_reset - Hot Reset sequence */
	int64_t (*hot_reset)(struct phb *phb);

	/* Fundamental reset */
	int64_t (*fundamental_reset)(struct phb *phb);

	/* poll - Poll and advance asynchronous operations
	 *
	 * Returns a positive delay, 0 for success or a
	 * negative OPAL error code
	 */
	int64_t (*poll)(struct phb *phb);
};

enum phb_type {
	phb_type_pci,
	phb_type_pcix_v1,
	phb_type_pcix_v2,
	phb_type_pcie_v1,
	phb_type_pcie_v2,
	phb_type_pcie_v3,
};

struct phb {
	struct dt_node		*dt_node;
	int			opal_id;
	uint32_t		scan_map;
	enum phb_type		phb_type;
	struct list_head	devices;
	const struct phb_ops	*ops;
	struct pci_lsi_state	lstate;
};

/* Config space ops wrappers */
static inline int64_t pci_cfg_read8(struct phb *phb, uint32_t bdfn,
				    uint32_t offset, uint8_t *data)
{
	return phb->ops->cfg_read8(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_read16(struct phb *phb, uint32_t bdfn,
				     uint32_t offset, uint16_t *data)
{
	return phb->ops->cfg_read16(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_read32(struct phb *phb, uint32_t bdfn,
				     uint32_t offset, uint32_t *data)
{
	return phb->ops->cfg_read32(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_write8(struct phb *phb, uint32_t bdfn,
				     uint32_t offset, uint8_t data)
{
	return phb->ops->cfg_write8(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_write16(struct phb *phb, uint32_t bdfn,
				      uint32_t offset, uint16_t data)
{
	return phb->ops->cfg_write16(phb, bdfn, offset, data);
}

static inline int64_t pci_cfg_write32(struct phb *phb, uint32_t bdfn,
				      uint32_t offset, uint32_t data)
{
	return phb->ops->cfg_write32(phb, bdfn, offset, data);
}

/* Utilities */
extern int64_t pci_find_cap(struct phb *phb, uint16_t bdfn, uint8_t cap);
extern int64_t pci_find_ecap(struct phb *phb, uint16_t bdfn, uint16_t cap,
			     uint8_t *version);

/* Manage PHBs */
extern int64_t pci_register_phb(struct phb *phb);
extern int64_t pci_unregister_phb(struct phb *phb);
extern struct phb *pci_get_phb(uint64_t phb_id);
static inline void pci_put_phb(struct phb *phb __unused) { }

/* Device tree */
extern void pci_std_swizzle_irq_map(struct dt_node *dt_node,
				    struct pci_device *pd,
				    struct pci_lsi_state *lstate,
				    uint8_t swizzle);

/* Initialize all PCI slots */
extern void pci_init_slots(void);
extern void pci_reset(void);

#endif /* __PCI_H */
