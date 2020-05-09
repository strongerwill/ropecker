#include <linux/string.h>
#include <linux/kernel.h>
#include "emulate_memory.h"

//addr_array_t addr_list;

int find_addr(addr_array_t* addr_list, unsigned long addr, unsigned long len)
{
	int i = 0;
	for(; i < addr_list->count; ++i)
	{
		// the query region has overlap with the saved region
		if((addr_list->addrs[i].addr <= addr) && ((addr_list->addrs[i].addr + addr_list->addrs[i].len) > addr))
		{
			return i;
		}
	}
	return -1;
}
int add_addr(addr_array_t *addr_list, unsigned long addr, unsigned long val, unsigned long len)
{
	if(addr_list->count >= MAX_ADDR_NUM){
		printk(KERN_ERR "emulation cache is overflow addr %08lx, count %ld\n", (ulong)&addr_list, addr_list->count);
		return -1;
	}
	addr_list->addrs[addr_list->count].addr = addr;	
	addr_list->addrs[addr_list->count].value = val;	
	addr_list->addrs[addr_list->count].len = len;	
	addr_list->count ++;
	return 0;
}

void clear_addr_list(addr_array_t* addr_list)
{
	//memset((void*)addr_list, 0, sizeof(*addr_list));
	addr_list->count = 0;
}
