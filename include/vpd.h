#ifndef __VPD_H
#define __VPD_H

const void *vpd_find_keyword(const void *rec, size_t rec_sz,
			     const char *kw, uint8_t *kw_size);

const void *vpd_find(const void *vpd, size_t vpd_size,
		     const char *record, const char *keyword,
		     uint8_t *sz);

/* Add model property to dt_root */
void add_dtb_model(void);

void vpd_iohub_load(struct dt_node *hub_node);

#define VPD_LOAD_LXRN_VINI	0xff


#endif /* __VPD_H */
