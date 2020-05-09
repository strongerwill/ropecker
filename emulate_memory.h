#ifndef __EMULATE_MEMORY_H__
#define __EMULATE_MEMORY_H__

#include "emulator.h"

extern int find_addr(addr_array_t *addr_list, unsigned long addr, unsigned long len);
extern int add_addr(addr_array_t *addr_list, unsigned long addr, unsigned long val, unsigned long len); 
extern void clear_addr_list(addr_array_t *addr_list);

#endif
