#include <stddef.h>
#include <types.h>
#include <skiboot.h>

#define DEFINE(sym, val) \
        asm volatile("\n->" #sym " %0 " #val : : "i" (val))

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

int main(void)
{
//	OFFSET(HTHREAD_HV_TREGS, hthread, hv_tregs);

	return 0;
}
