#ifndef __HDATA_H
#define __HDATA_H

struct dt_node;

extern void paca_parse(void);
extern bool pcia_parse(void);
extern void fsp_parse(void);
extern void io_parse(struct dt_node *ics);

#endif /* __HDATA_H */

