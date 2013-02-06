#ifndef __VPD_H
#define __VPD_H

const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size);

const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz);

/* Add model property to dt_root */
void add_dtb_model(void);

#define VPD_LOAD_LXRN_VINI	0xff
void *vpd_lid_load(const uint8_t *lx, uint8_t lxrn, size_t *size);


#endif /* __VPD_H */
