//~ #define DDISTORM_LIGHT

#include "debug.h"
#include "stack_check.h"
#include "bi_table.h"
#include "./include/distorm.h"
#include "./include/mnemonics.h"
#include "data_struct.h"

#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/slab.h>// kmalloc

    #ifdef MICRO_BENCHMARK
		int quick_rop_checks = 0;
		int quick_gadget_checks = 0;
			
		int rop_payload_checks = -100;
		int payload_gadget_runs = 0;
        int read_db_runs = 0;
    #endif
        
static pid_t pid_list[MAX_PROCESS];
static PADDR_TABLE addr_tables[MAX_PROCESS];
static UINT next_pid_idx = 0;

static unsigned long rop_gadget_buf[MAX_INDIRECT_CALL + 1] = {0};

void init(pid_t pid)
{
    memset(pid_list, 0, MAX_PROCESS*sizeof(pid_t));
    memset(addr_tables, 0, MAX_PROCESS*sizeof(PADDR_TABLE));
    next_pid_idx = 0;
}

// Return -1 if not found
static int locate_addr_table(pid_t pid)
{
    int i=0;
        
    for(i=0;i < MAX_PROCESS; i++)
        if(pid == pid_list[i])
            return i;
        
    return -1;
}

static BOOL get_addr_table(pid_t pid, PADDR_TABLE* addr_table)
{
    int addr_table_idx = -1;
    
    addr_table_idx = locate_addr_table(pid);
    
    if(addr_table_idx!=-1)
    {
        *addr_table = addr_tables[addr_table_idx];
        return TRUE;
    }
    
    return FALSE;
}

static PADDR_TABLE pid_insert(ULONG pid)
{
    PADDR_TABLE addr_table = NULL;
    
    if(next_pid_idx < MAX_PROCESS)
    {
        //~ addr_table = vmalloc(1*sizeof(ADDR_TABLE));
        addr_table = kmalloc(1*sizeof(ADDR_TABLE), GFP_KERNEL);
        memset(addr_table, 0, 1*sizeof(ADDR_TABLE));
        pid_list[next_pid_idx] = pid;
        addr_tables[next_pid_idx] = addr_table;
        
        next_pid_idx++;
    }
    
    return addr_table;
}

static BOOL is_addr_in(pid_t pid, void* addr)
{
    PADDR_TABLE addr_table = NULL;
    BOOL ret = FALSE;
    
    ret = get_addr_table(pid, &addr_table);
    if(ret == TRUE)
    {
        // Found
        if(addr_table)
        {
            // Exist
            int idx;
            idx = table_search(addr_table, (ULONG)addr, FALSE);
            return (idx != -1);
        }
        else
        {
            ROP_DB(printk("[is_addr_in] Error addr_table is null\n"));
            return FALSE;
        }
    }
    else
    {
        ROP_DB(printk("[is_addr_in] Error addr_table is not found for pid:%d\n", pid));
        return FALSE;
    }
    
    // never reached
    return FALSE;
}

void register_cs(pid_t pid, void* lib_cs_start, void* lib_cs_end)
{
    PADDR_TABLE addr_table = NULL;
    BOOL ret = FALSE;
    
    ret = get_addr_table(pid, &addr_table);
    if(ret == FALSE)
    {
        // Not found, this is a new pid
        addr_table = pid_insert(pid);
    }
    
    // Here we must have the addr_table in hand.
    table_insert(addr_table, (ULONG)lib_cs_start, (ULONG)lib_cs_end);
}

void unregister_cs(pid_t pid, void* lib_cs_start)
{
    PADDR_TABLE addr_table = NULL;
    BOOL ret = FALSE;
    
    ret = get_addr_table(pid, &addr_table);
    if(ret == FALSE)
    {
        // Not found
        ROP_DB(printk("[unregister_cs] Error addr_table is not found\n"));
        return;
    }
    
    // Here we must have the addr_table in hand.
    table_remove(addr_table, (ULONG)lib_cs_start);
}

void finalize(pid_t pid)
{
    PADDR_TABLE addr_table = NULL;
    UINT remove_idx = 0;
    int idx = -1;
    
    idx = locate_addr_table(pid);
    if(idx == -1)
    {
         // Not found
        ROP_DB(printk("[finalize] Error addr_table is not found for pid:%d\n", pid));
        return;
    }
    
    addr_table = addr_tables[idx];
    //~ vfree(addr_table);
    kfree(addr_table);
    
    // Remove the entry -- overwrite this entry with the last entry in 
    // <pid_table>. But we need to clear this entry first for the case 
    // only 1 entry before removing
    remove_idx = --next_pid_idx;
    pid_list[idx] = 0;
    addr_tables[idx] = NULL;
    //~ addr_table->cs_start[idx] = addr_table->cs_start[remove_idx];
    //~ addr_table->cs_end[idx] = addr_table->cs_end[remove_idx];
}

// if MAX_INDIRECT_CALL is hit for the past MAX_NUM_INSPECT_ADDRS functions, 
// return TRUE, otherwise FALSE.
static BOOL inc_history(UINT* ind_calls, UINT idx)
{
    if(idx < MAX_NUM_INSPECT_ADDRS)
    {
        int i = 0;
        for (i = 0; i <= idx; i++)
        {
            ind_calls[i]++;
            if((ind_calls[i] >= MAX_INDIRECT_CALL) && (i != (idx % MAX_NUM_INSPECT_ADDRS)))
            {
                ROP_DB(printk("[1] Found ROP at index = %d\n", i));
                return TRUE;
            }
        }
    }
    else
    {
        int i = 0;
        for (i = 0; i < MAX_NUM_INSPECT_ADDRS; i++)
        {
            ind_calls[i]++;
            if((ind_calls[i] >= MAX_INDIRECT_CALL) && (i != (idx % MAX_NUM_INSPECT_ADDRS)))
            {
                if(i <= (idx % MAX_NUM_INSPECT_ADDRS))
                    ROP_DB(printk("[2] Found ROP at index = %d\n", idx - (idx % MAX_NUM_INSPECT_ADDRS) + i));
                else
                    ROP_DB(printk("[3] Found ROP at index = %d\n", (idx - (idx % MAX_NUM_INSPECT_ADDRS) + i - MAX_NUM_INSPECT_ADDRS)));
                return TRUE;
            }
        }
    }
    
    ind_calls[idx % MAX_NUM_INSPECT_ADDRS] = 1;
    return FALSE;
}

static _DInst result[CHECK_GADGET_INSTRS];
// Sometimes a gadget include add esp ** or pop;pop;pop, in this case, we 
// calculate how many inst we should skip in <jump_len>. If the <jump_len>
// is negative, the current "gadget" contains such code but it is not a valid
// gadget.
static BOOL online_check_gadget(UCHAR* code, UINT len, UINT decode_type, int* jump_len)
{
    _CodeInfo ci;
    _DecodeType dt = decode_type;
    //~ _DInst *result;
    
    unsigned int decoded_inst = 0;
    unsigned int max_inst = len;
    unsigned int i = 0;
    
    //~ result = vmalloc(CHECK_GADGET_INSTRS*sizeof(_DInst));
    *jump_len = 0;
        
    ci.codeOffset = 0;
    //~ ROP_DB(printk("Code:0x%08lx\n", (ULONG)code));
    ci.code = code;
    ci.codeLen = len;
    //~ ci.codeLen = ((((ULONG)code & 0xfff) + len) >= 0x1000) ? (0x1000 - 1 - ((ULONG)code & 0xfff)): len;
    ci.dt = dt;
    ci.features = DF_NONE;
        
    distorm_decompose(&ci, result, max_inst, &decoded_inst);
        
    for(i = 0; (i < decoded_inst) && (i < CHECK_GADGET_INSTRS); i++)
    {
        if(result[i].opcode == I_ADC ||
            (result[i].opcode == I_ADD))
        {
            _Operand *operand = result[i].ops;
            
            if (((operand[1].type == O_IMM) || 
                (operand[1].type == O_IMM1) ||
                (operand[1].type == O_IMM2)) && 
                ((operand[0].type == O_REG) && (operand[0].index == R_ESP)))
            {
                *jump_len = result[i].imm.dword;
            }
        }
        else if(result[i].opcode == I_POP)
        {
             _Operand *operand = result[i].ops;
            
            if (operand[0].type == O_REG)
            {
                *jump_len += sizeof(long);
            }
        }
         
        else if(result[i].opcode == I_IRET ||
        //~ if(result[i].opcode == I_IRET ||
            (result[i].opcode == I_RET) ||
            (result[i].opcode == I_RETF) ||
            (result[i].opcode == I_SYSRET))
        {
            //~ vfree(result);
            return TRUE;
        }
        else if((result[i].opcode == I_JA) ||
            (result[i].opcode == I_JAE) ||
            (result[i].opcode == I_JB) ||
            (result[i].opcode == I_JBE) ||
            (result[i].opcode == I_JCXZ) ||
            (result[i].opcode == I_JECXZ) ||
            (result[i].opcode == I_JG) ||
            (result[i].opcode == I_JGE) ||
            (result[i].opcode == I_JL) ||
            (result[i].opcode == I_JLE) ||
        
            (result[i].opcode == I_JMP) ||
            (result[i].opcode == I_JNS) ||
            (result[i].opcode == I_JNZ) ||
            (result[i].opcode == I_JMP_FAR) ||
            (result[i].opcode == I_JNO) ||
            (result[i].opcode == I_JNP) ||
            (result[i].opcode == I_JO) ||
            (result[i].opcode == I_JP) ||
            (result[i].opcode == I_JRCXZ) ||
            (result[i].opcode == I_JS) ||
        
            (result[i].opcode == I_JZ) ||
            (result[i].opcode == I_CALL) ||
            (result[i].opcode == I_CALL_FAR))
        {
            _Operand *operand = result[i].ops;
            int j = 0;
            
            for( j = 0; j < OPERANDS_NO; j++)
            {
                
                if((operand[j].type == O_REG) ||
                    (operand[j].type == O_SMEM) ||
                    (operand[j].type == O_MEM) ||
                    (operand[j].type == O_DISP))
                {
                    //~ vfree(result);
                    return TRUE;
                }
            }
        }
    }
    
    //~ vfree(result);
    
    *jump_len = 0 - *jump_len;
    return FALSE;
}

BOOL is_gadget(UCHAR* code)
{
    ULONG jump_len = 0;
    return online_check_gadget(code, CHECK_GADGET_BYTES, Decode32Bits, (int*)&jump_len);
}

#define SJMP_ALIGNED            1
#define IJMP_ALIGNED            2 //!
#define GOOD_CASE               0 //!
#define GAO_BU_DING             3 //!
#define NEED_ONLINE_ANALYSIS    4 // next esp >= [esp+4*12]
#define IJMP_ESP_ADD_4_1        5 // next esp = [esp+4*1]
#define IJMP_ESP_ADD_4_2        6
#define IJMP_ESP_ADD_4_3        7
#define IJMP_ESP_ADD_4_4        8
#define IJMP_ESP_ADD_4_5        9
#define IJMP_ESP_ADD_4_6        10
#define IJMP_ESP_ADD_4_7        11
#define IJMP_ESP_ADD_4_8        12
#define IJMP_ESP_ADD_4_9        13
#define IJMP_ESP_ADD_4_10        14
#define IJMP_ESP_ADD_4_11        15

// Check if the address points to a gadget according to the db
static BOOL db_check_gadget(pid_t pid, ULONG code, int* jump_len, BOOL* need_online_analysis)
{
    monitor_app_t *slot = NULL;
    mapping_element_t* ele = NULL; 
    
    slot = get_app_slot((ULONG)pid);
    ele = get_lib_mapping(slot, code);
    
    {
        ULONG exe_base_addr = (ULONG)ele->start;
        ULONG exe_code_size = (ULONG)ele->end - (ULONG)ele->start;
        ULONG exe_file_addr = (ULONG)code - exe_base_addr;
        
        if(exe_file_addr < exe_code_size)
        {
            char status_val = 0;
            
            status_val = get_status_val(ele, exe_file_addr);
            *jump_len = 0;
            
            switch(status_val)
            {
                case SJMP_ALIGNED:
                    return FALSE;
                
                case IJMP_ALIGNED:
                    return TRUE;
                
                case GOOD_CASE:
                    return FALSE;
                
                case GAO_BU_DING:
                    return FALSE;
                
                case NEED_ONLINE_ANALYSIS:
                    *need_online_analysis = TRUE;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_1:
                    *jump_len = 0;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_2:
                    *jump_len = 4*1;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_3:
                    *jump_len = 4*2;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_4:
                    *jump_len = 4*3;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_5:
                    *jump_len = 4*4;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_6:
                    *jump_len = 4*5;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_7:
                    *jump_len = 4*6;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_8:
                    *jump_len = 4*7;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_9:
                    *jump_len = 4*8;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_10:
                    *jump_len = 4*9;
                    return TRUE;
                
                case IJMP_ESP_ADD_4_11:
                    *jump_len = 4*10;
                    return TRUE;
                
                default:
                    break;
            }
        }
    }
    
    return FALSE;
}


// Return 1 if gadget found 
BOOL is_payload(pid_t pid, void* esp, void* orig_ebp, unsigned long* rop_buf)
{
    UINT ind_calls[MAX_NUM_INSPECT_ADDRS];
    ULONG* p = (ULONG*) esp;
    UINT idx = 0;
    int jump_len = 0;
    int rop_buf_idx = 0;
    
    #ifdef MICRO_BENCHMARK
		unsigned long long start = 0, end = 0;
	#endif
    
    // [Note] ROPT uses this counter to speed up the searching for payload. Otherwise 
    // ROPT always needs to check every integer in the stack from [esp, orig_ebp] to 
    // find possible gadgets.
    int num_already_checked = 0;
    
    rop_buf[MAX_INDIRECT_CALL] = 0; // Ensure the correct array ending
    
    memset(ind_calls, 0, MAX_NUM_INSPECT_ADDRS*sizeof(UINT));
    //~ ROP_DB(printk("Begin\n"));
    while( ((ULONG)p) <= ((ULONG)orig_ebp))
    {
        ULONG data = *p;
        
        // Records the number of checked stack values to speed up the stack check
        // process.
        num_already_checked++;
        
        //~ ROP_DB(printk("Examine ESP:0x%08lx\n", data));
        if(is_addr_in(pid, (void*)data))
        {
            UCHAR* user_code[CHECK_GADGET_BYTES] = {0};
            BOOL ret = FALSE;
            BOOL need_online_analysis = FALSE;
            
            #ifdef MICRO_BENCHMARK
            // For db_check_gadget();
                
            
                #ifdef USE_DB_CHECK_ONLY
                    start = __native_read_tsc();
                    ret = db_check_gadget(pid, data, &jump_len, &need_online_analysis);
                #endif
            
                #ifdef USE_ONLINE_CHECK_ONLY
                    copy_from_user(user_code, (void*)data, CHECK_GADGET_BYTES);
                    start = __native_read_tsc();
                    ret = online_check_gadget((UCHAR*)user_code, CHECK_GADGET_BYTES, Decode32Bits, (int*)&jump_len);
                #endif
            
                end = __native_read_tsc();
		
			payload_gadget_runs++;
			
                #ifdef USE_DB_CHECK_ONLY
                if(payload_gadget_runs <= MAX_MEASURES_PER_ITEM)
                    printk(KERN_ERR "[USE_DB_CHECK_ONLY] gadget_analysis_stack_check clockticks: %lld", (end - start));
                #endif 
                
                #ifdef USE_ONLINE_CHECK_ONLY
                if(payload_gadget_runs <= MAX_MEASURES_PER_ITEM)
                    printk(KERN_ERR "[USE_ONLINE_CHECK_ONLY] gadget_analysis_stack_check clockticks: %lld", (end - start));
                #endif 

            #endif
            
            #ifndef MICRO_BENCHMARK
            ret = db_check_gadget(pid, data, &jump_len, &need_online_analysis);
            if(ret == TRUE && need_online_analysis == TRUE)
            {
                copy_from_user(user_code, (void*)data, CHECK_GADGET_BYTES);
                ret = online_check_gadget((UCHAR*)user_code, CHECK_GADGET_BYTES, Decode32Bits, (int*)&jump_len);
            }
            #endif

            if(ret == TRUE)
            {
                // Found in some code segment
                BOOL dead_hit = FALSE;
                dead_hit = inc_history(ind_calls, idx);
                
                rop_gadget_buf[rop_buf_idx % MAX_INDIRECT_CALL] = data;
                
                if(dead_hit)
                {
                    int i = MAX_INDIRECT_CALL - 1;
                    
                    for(i = MAX_INDIRECT_CALL - 1; i >= 0; i--)
                    {
				
                        rop_buf[i] = rop_gadget_buf[(rop_buf_idx + i + 1) % MAX_INDIRECT_CALL];
                        ROP_DB(printk("[Superymk] rop_buf[%d]:0x%08lX\n", i,  rop_buf[i] ));
                    }
                    
                    ROP_DB(printk("[Superymk] The input esp is:0x%08lx \n", (ULONG)esp));
                    return TRUE;
                }
                
                rop_buf_idx++;
                
                if(num_already_checked >= MAX_NUM_INSPECT_ADDRS)
                {
                    // ROPT has already checked MAX_NUM_INSPECT_ADDRS values, we should stop
                    // checking more values in this interrupt event and report negative result.
                    ROP_DB(printk("[Superymk] Already checked %d stack values\n", num_already_checked));
                    return FALSE;
                }
                
                if(jump_len >= 0)
                {
                    //~ ROP_DB(printk("data:0x%08lx, jump_len:%d\n", data, jump_len));
                    p += (jump_len / sizeof(ULONG));
                }
            }
            else
            {
                // Not Found
                ind_calls[idx % MAX_NUM_INSPECT_ADDRS] = 0;
            }
                
        }
        else
        {
            // Not Found
            ind_calls[idx % MAX_NUM_INSPECT_ADDRS] = 0;
        }
        
        p++;
        idx++;
    }
    //~ ROP_DB(printk("Finish\n"));
    return FALSE;
}

//~ int main()
//~ {
    //~ // Testcase 1
    //~ {
        //~ pid_t pid1 = 1;
        //~ BOOL ret = FALSE;
        //~ ULONG stack[18] = {0x070072F7, 0x00010104, 0x070015BB, 0x00001000, 0x0700154D, 0x070015BB, 0x8FFE0300, 0x07007FB2, 0x070015BB, 0x070072F7,     0x070015BB, 0x070015BB, 0x070015BB, 0x0700154D, 0x070015BB, 0x070015BB, 0x07007FB2, 0x070015BB};
        //~ ULONG stack2[10] = {};
        //~ char gadget1[2]={0xFF, 0x21};//jmp [ecx]
        //~ char gadget2[2]={0xFF, 0xE0};//jmp eax
        //~ char gadget3[7]={0xff, 0x2c, 0x85, 0x02, 0x00, 0x00, 0x00}; //ff 2c 85 02 00 00 00    ljmp   *0x2(,%eax,4)
        //~ char gadget4[2]={0x74, 0x11};//4060fd:	74 11   je     406110 <__sprintf(printk_chk@plt+0x4920>
        //~ init(pid1);
        
        //~ register_cs(pid1, (void*)0x10000000, (void*)0x20000000);
        //~ register_cs(pid1, (void*)0x40000000, (void*)0x50000000);
        //~ register_cs(pid1, (void*)0x07000000, (void*)0x08000000);
            //~ register_cs(pid1, (void*)0xc7000000, (void*)0xc8000000);
            //~ register_cs(pid1, (void*)0xd7000000, (void*)0xd8000000);
            //~ register_cs(pid1, (void*)0xa7000000, (void*)0xa8000000);
            //~ register_cs(pid1, (void*)0xb7000000, (void*)0xb8000000);
            
        //~ {
            //~ {
                //~ PADDR_TABLE *t;
                
                //~ get_addr_table(pid1, t);
                //~ dump_table(*t);
            //~ }
            
            //~ ret = is_payload(pid1, (void*)stack, (void*)&stack[17]);
            //~ if (ret)
                //~ ROP_DB(printk("NB\n"));
        //~ }
        
        //~ unregister_cs(pid1, (void*)0x15000000);
        //~ unregister_cs(pid1, (void*)0x10000000);
        //~ unregister_cs(pid1, (void*)0xc7000000);
        //~ unregister_cs(pid1, (void*)0xd7000000);
        //~ unregister_cs(pid1, (void*)0x40000000);
        
        //~ if(is_gadget(gadget1, 2, Decode32Bits))
            //~ ROP_DB(printk("NB\n"));
        //~ if(is_gadget(gadget2, 2, Decode32Bits))
            //~ ROP_DB(printk("NB\n"));
        //~ if(is_gadget(gadget3, 7, Decode32Bits))
            //~ ROP_DB(printk("NB\n"));
        //~ if(!is_gadget(gadget4, 2, Decode32Bits))
            //~ ROP_DB(printk("NB\n"));
        
        //~ finalize(pid1);
    //~ }
    
    //~ // Testcase 2
    //~ {
        //~ pid_t pid1 = 1;
        //~ BOOL ret = FALSE;
        //~ ULONG stack[9] = {0x070015BB, 0x070015BB, 0x0804e3cc, 0x0804ec86, 0x8FFE0300, 0x080486fc, 0x0700154D , 0x8FFE0300, 0x08054020};
            
        //~ init(pid1);
        //~ register_cs(pid1, (void*)0x08048790, (void*)(0x08048790 + 0x660c));
        //~ register_cs(pid1, (void*)0x080486d0, (void*)(0x080486d0 + 0x0000002e));
        //~ register_cs(pid1, (void*)0x08048700, (void*)(0x08048700 + 0x00000090));

        //~ ret = is_payload(pid1, (void*)stack, (void*)&stack[8]);
        //~ if (ret)
            //~ ROP_DB(printk("Very NB!\n"));
        
        //~ unregister_cs(pid1, (void*)0x08048700);
        //~ unregister_cs(pid1, (void*)0x080486d0);
        //~ unregister_cs(pid1, (void*)0x08048790);
        //~ finalize(pid1);
    //~ }
    
    //~ return 0;
//~ }
