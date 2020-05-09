#ifndef _BI_TABLE_
#define _BI_TABLE_
#include "types.h"

#define MAX_ENTRIES             512
typedef struct
{
    ULONG cs_start[MAX_ENTRIES];
    ULONG cs_end[MAX_ENTRIES];
    
    ULONG next_avail_idx;
} ADDR_TABLE, *PADDR_TABLE;

extern int table_search(PADDR_TABLE addr_table, ULONG addr, BOOL precise);
extern void table_insert(PADDR_TABLE addr_table, ULONG cs_start, ULONG cs_end);
extern void table_remove(PADDR_TABLE addr_table, ULONG cs_start);

// For Debug
extern void dump_table(PADDR_TABLE addr_table);

#endif
