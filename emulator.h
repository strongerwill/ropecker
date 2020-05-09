#ifndef __EMULATOR_H__
#define __EMULATOR_H__

#include "include/xen.h"
#include "x86_emulate/x86_emulate.h"

struct emulate_memory
{
	unsigned long addr;
	unsigned long value;
	unsigned long len;
};

typedef struct emulate_memory emulate_mem_t;
typedef emulate_mem_t* emulate_mem_p;


struct addr_array
{
	unsigned long count;
#define MAX_ADDR_NUM		(1023)
	emulate_mem_t addrs[MAX_ADDR_NUM];
};

typedef struct addr_array addr_array_t;
extern addr_array_t addr_list;


struct rop_emulate_ctxt{
	struct x86_emulate_ctxt *ctxt;
	addr_array_t *addr_list;
};

extern void init_context(struct rop_emulate_ctxt **ctxt);
extern void free_context(struct rop_emulate_ctxt *ctxt);
extern void set_context(struct rop_emulate_ctxt *ctxt, struct pt_regs* orig_regs);
extern void clear_context(struct rop_emulate_ctxt * ctxt);

extern int x86_ins_emulate(struct rop_emulate_ctxt *ctxt);
#endif
