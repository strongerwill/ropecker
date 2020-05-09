#include "bi_table.h"
#include "types.h"
#include "debug.h"
//~ #include <stdlib.h>
//~ #include <stdio.h>
//~ #include <string.h>
#include <linux/string.h>
#include <linux/kernel.h>

#define MAX_ENTRIES             512

int table_search(PADDR_TABLE addr_table, ULONG addr, BOOL precise)
{
    int low = 0;
    int high = addr_table->next_avail_idx;
    int mid = 0;
    
    while(low <= high)
    {
        mid = (low + high)/2;
        if (precise && (addr_table->cs_start[mid] == addr))
            return mid;
        if(!precise && (addr >= addr_table->cs_start[mid]) && (addr <= addr_table->cs_end[mid]))
            return mid;
        if (addr_table->cs_start[mid] > addr)
            high = mid - 1;
        else if (addr_table->cs_start[mid] < addr)
            low = mid + 1;
    }
    
    //the array does not contain the target
    return -1;
}

static int table_ins_pos(PADDR_TABLE addr_table, ULONG addr)
{
    int low = 0;
    int high = addr_table->next_avail_idx;
    int mid = 0;
    
    {
        if(addr_table->next_avail_idx !=0 && addr_table->cs_end[addr_table->next_avail_idx - 1] < addr)
            return addr_table->next_avail_idx;
        if(addr_table->next_avail_idx ==0)
            return 0;
        if(addr_table->cs_start[0] > addr)
            return 0;
    }
    
    while(low <= high)
    {
        mid = (low + high)/2;
        
        if((addr >= addr_table->cs_end[mid]) && (addr <= addr_table->cs_start[mid + 1]))
            return (mid+1);
        
        if (addr_table->cs_start[mid] > addr)
            high = mid - 1;
        else if (addr_table->cs_start[mid] < addr)
            low = mid + 1;
    }
    
    
    //the array does not contain the target
    return -1;
}

static BOOL inc_index(PADDR_TABLE addr_table, ULONG start_index)
{
    ULONG i = 0;
    
    if(addr_table->next_avail_idx > MAX_ENTRIES)
    {
        ROP_DB(printk("[inc_index] Table is full\n"));
        return FALSE;
    }
    
    addr_table->next_avail_idx++;
    for( i = addr_table->next_avail_idx; i > start_index ; i--)
    {
        addr_table->cs_end[i] = addr_table->cs_end[i - 1];
        addr_table->cs_start[i] = addr_table->cs_start[i - 1];
    }
    
    return TRUE;
}

static BOOL dec_index(PADDR_TABLE addr_table, ULONG start_index)
{
    ULONG i = 0;
    
    if(addr_table->next_avail_idx == 0)
    {
        ROP_DB(printk("[dec_index] Table is empty\n"));
        return FALSE;
    }
    
    addr_table->next_avail_idx--;
    for( i = start_index; i < addr_table->next_avail_idx; i++)
    {
        addr_table->cs_end[i] = addr_table->cs_end[i + 1];
        addr_table->cs_start[i] = addr_table->cs_start[i + 1];
    }
    
    return TRUE;
}

void table_insert(PADDR_TABLE addr_table, ULONG cs_start, ULONG cs_end)
{
    BOOL ret = FALSE;
    int idx = 0;
    
    if(cs_start > addr_table->cs_start[addr_table->next_avail_idx - 1])
    {
        addr_table->cs_start[addr_table->next_avail_idx] = cs_start;
        addr_table->cs_end[addr_table->next_avail_idx] = cs_end;
        addr_table->next_avail_idx++;
        return;
    }
    
    idx = table_ins_pos(addr_table, cs_start);
    
    if(idx != -1)
        ret = inc_index(addr_table, idx);
    
    if(ret)
    {
        addr_table->cs_end[idx] = cs_end;
        addr_table->cs_start[idx] = cs_start;
    }
}

void table_remove(PADDR_TABLE addr_table, ULONG cs_start)
{
    int idx = table_search(addr_table, cs_start, TRUE);
    
    if(idx != -1)
        dec_index(addr_table, idx);
    else
        ROP_DB(printk("[table_remove] Error cs_start is not found:0x%lX\n", cs_start));
}

void dump_table(PADDR_TABLE addr_table)
{
    int i= 0; 
    
    for ( i = 0; i< addr_table->next_avail_idx; i++)
    {
        ROP_DB(printk("[Idx:%d] Start Value:0x%lX, End Value:0x%lX\n", i, 
            addr_table->cs_start[i] , addr_table->cs_end[i]));
    }
}