#ifndef __FSP_SYSPARAM_H
#define __FSP_SYSPARAM_H

/* System parameter numbers used in the protocol
 *
 * these are the only ones we care about right now
 */
#define SYS_PARAM_SURV			0xf0000001
#define SYS_PARAM_HMC_MANAGED		0xf0000003
#define SYS_PARAM_FLASH_POLICY		0xf0000012
#define SYS_PARAM_FW_LICENSE		0xf000001d
#define SYS_PARAM_NEED_HMC		0xf0000016


/* Completion for a sysparam call. err_len is either a negative error
 * code or the positive length of the returned data
 */
typedef void (*sysparam_compl_t)(uint32_t param_id, int err_len, void *data);


/* Send a sysparam query request. Operation can be synchronous or
 * asynchronous:
 *
 * - synchronous (async_complete is NULL), the result code is either
 *   a negative error code or a positive returned length.
 *
 * - asynchronous (async_complete non NULL). The result code is 0 for
 *   successfully queued request or an error for an immediate error.
 *   A successfully queued request will complete via the completion
 *   callback defined above
 */
int fsp_get_sys_param(uint32_t param_id, void *buffer, uint32_t length,
		      sysparam_compl_t async_complete, void *comp_data);


void fsp_sysparam_init(void);

#endif /*  __FSP_SYSPARAM_H */
