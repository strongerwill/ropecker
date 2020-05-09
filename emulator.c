#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module */
#include <linux/fs.h>
#include <linux/sched.h>	/* for current <the macro>	*/
#include <linux/version.h>
#include <asm/uaccess.h>	/* for get_user and put_user */

#include <linux/string.h>
#include <linux/slab.h>
#include "include/xen.h"

#define emu_cpu_has_amd_erratum(nr) 0

#include "x86_emulate/x86_emulate.h"
#include "emulate_memory.h"
#include "data_struct.h"

/* EFLAGS bit definitions. */
#define EFLG_OF (1<<11)
#define EFLG_DF (1<<10)
#define EFLG_SF (1<<7)
#define EFLG_ZF (1<<6)
#define EFLG_AF (1<<4)
#define EFLG_PF (1<<2)
#define EFLG_CF (1<<0)

static int read(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
	monitor_app_t *slot = get_app_slot(current->pid);
	addr_array_t* addr_list = slot->ctxt->addr_list;
	while(bytes)
	{
		int i = find_addr(addr_list, offset, bytes);
		if(i == -1)
		{
			copy_from_user(p_data, (void *)offset, bytes);
			break;
		} 
		else 
		{
			char* pos = (char*)&addr_list->addrs[i].value;
			int start_off = offset - addr_list->addrs[i].addr;
			int size = (start_off + bytes <= addr_list->addrs[i].len) ? (bytes) : (addr_list->addrs[i].len - start_off);
			bytes = bytes - size;
			offset = offset + size;
			memcpy(p_data, pos + start_off, size);
		}
	}
    return X86EMUL_OKAY;
}

static int write(
    unsigned int seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
	monitor_app_t *slot = get_app_slot(current->pid);
    if(add_addr(slot->ctxt->addr_list, offset, *(unsigned long*)p_data, bytes) == -1) return X86EMUL_UNHANDLEABLE;
    return X86EMUL_OKAY;
}

static int emu_cmpxchg(
    unsigned int seg,
    unsigned long offset,
    void *old,
    void *new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
	monitor_app_t *slot = get_app_slot(current->pid);
    if(add_addr(slot->ctxt->addr_list, offset, *(unsigned long*)new, bytes)) return X86EMUL_UNHANDLEABLE;
    return X86EMUL_OKAY;
}

static int emu_cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt)
{
    asm ("cpuid" : "+a" (*eax), "+c" (*ecx), "=d" (*edx), "=b" (*ebx));
    return X86EMUL_OKAY;
}

#define emu_cpu_has_mmx ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emu_cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 23)) != 0; \
})

#define emu_cpu_has_sse ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emu_cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 25)) != 0; \
})

#define emu_cpu_has_sse2 ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emu_cpuid(&eax, &ecx, &ecx, &edx, NULL); \
    (edx & (1U << 26)) != 0; \
})

static inline uint64_t xgetbv(uint32_t xcr)
{
    uint64_t res;

    asm ( ".byte 0x0f, 0x01, 0xd0" : "=A" (res) : "c" (xcr) );

    return res;
}

#define emu_cpu_has_avx ({ \
    unsigned int eax = 1, ecx = 0, edx; \
    emu_cpuid(&eax, &edx, &ecx, &edx, NULL); \
    if ( !(ecx & (1U << 27)) || ((xgetbv(0) & 6) != 6) ) \
        ecx = 0; \
    (ecx & (1U << 28)) != 0; \
})

int get_fpu(
    void (*exception_callback)(void *, struct cpu_user_regs *),
    void *exception_callback_arg,
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( type )
    {
    case X86EMUL_FPU_fpu:
        break;
    case X86EMUL_FPU_ymm:
        if ( emu_cpu_has_avx )
            break;
    case X86EMUL_FPU_xmm:
        if ( emu_cpu_has_sse )
            break;
    case X86EMUL_FPU_mmx:
        if ( emu_cpu_has_mmx )
            break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }
    return X86EMUL_OKAY;
}

static struct x86_emulate_ops emulops = {
    .read       = read,
    .insn_fetch = read,
    .write      = write,
    .cmpxchg    = emu_cmpxchg,
    .cpuid      = emu_cpuid,
    //.get_fpu    = get_fpu,
};

static inline void emulator_test(void)
{
    struct x86_emulate_ctxt ctxt;
    struct cpu_user_regs regs;
    int rc = -1, i = 0, ins_num = 11;
    unsigned int ip = 0;

    // generic setting for x86_32
    ctxt.regs = &regs;
    ctxt.force_writeback = 0;
    ctxt.addr_size = 32;
    ctxt.sp_size   = 32;

    ip = (ulong)emu_cpuid;
    regs.eflags = 0x200;
    regs.eip    = ip + 0x26;
    regs.ebp    = ip + 0x8;
    regs.edi    = regs.ebp - 0x10;
    regs.ecx    = regs.edi;
    regs.eax    = regs.ebp - 0xc;
    regs.edx    = 0xabcdefee;
    regs.esi    = 0;
    regs.esp    = ip;
    regs.ebx    = 0xaabbccdd;
// ebp f9959098 esp 00000000 eax f995908c, ebx aabbccdd, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590b6 rc -1
/*
   10088:       90                      nop
   10089:       90                      nop
   1008a:       90                      nop
   1008b:       90                      nop
   1008c:       90                      nop
   1008d:       90                      nop
   1008e:       90                      nop
   1008f:       90                      nop

00010090 <emu_cpuid>:
   10090:       55                      push   %ebp
   10091:       89 e5                   mov    %esp,%ebp
   10093:       83 ec 10                sub    $0x10,%esp
   10096:       89 5d f4                mov    %ebx,-0xc(%ebp)
   10099:       89 75 f8                mov    %esi,-0x8(%ebp)
   1009c:       89 7d fc                mov    %edi,-0x4(%ebp)
   1009f:       e8 fc ff ff ff          call   100a0 <emu_cpuid+0x10>
   100a4:       89 c6                   mov    %eax,%esi
   100a6:       89 cf                   mov    %ecx,%edi
   100a8:       8b 00                   mov    (%eax),%eax
   100aa:       8b 09                   mov    (%ecx),%ecx
   100ac:       89 55 f0                mov    %edx,-0x10(%ebp)
   100af:       0f a2                   cpuid  
   100b1:       89 06                   mov    %eax,(%esi)
   100b3:       8b 45 08                mov    0x8(%ebp),%eax
   100b6:       89 0f                   mov    %ecx,(%edi)
   100b8:       89 10                   mov    %edx,(%eax)
   100ba:       8b 45 f0                mov    -0x10(%ebp),%eax
   100bd:       89 18                   mov    %ebx,(%eax)
   100bf:       8b 5d f4                mov    -0xc(%ebp),%ebx
   100c2:       31 c0                   xor    %eax,%eax
   100c4:       8b 75 f8                mov    -0x8(%ebp),%esi
   100c7:       8b 7d fc                mov    -0x4(%ebp),%edi
   100ca:       89 ec                   mov    %ebp,%esp
   100cc:       5d                      pop    %ebp
   100cd:       c3                      ret    
*/
    printk(KERN_INFO "ebp %08x esp %08x eax %08x, ebx %08x, ecx %08x, edx %08x esi %08x edi %08x eip %08x rc %d\n", 
        regs.ebp, regs.esp, regs.eax, regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.eip, rc);
    for(; i < ins_num; ++i)
    {
        rc = x86_emulate(&ctxt, &emulops);
        printk(KERN_INFO "ebp %08x esp %08x eax %08x, ebx %08x, ecx %08x, edx %08x esi %08x edi %08x eip %08x rc %d\n", 
            regs.ebp, regs.esp, regs.eax, regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.eip, rc);
    } 
/*
[325908.382656] ebp f9959098 esp 00000000 eax f995908c, ebx aabbccdd, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590b6 rc -1
[325908.382660] ebp f9959098 esp 00000000 eax f995908c, ebx aabbccdd, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590b8 rc 0
[325908.382663] ebp f9959098 esp 00000000 eax f995908c, ebx aabbccdd, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590ba rc 0
[325908.382666] ebp f9959098 esp 00000000 eax f9959088, ebx aabbccdd, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590bd rc 0
[325908.382669] ebp f9959098 esp 00000000 eax f9959088, ebx aabbccdd, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590bf rc 0
[325908.382672] ebp f9959098 esp 00000000 eax f9959088, ebx abcdefee, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590c2 rc 0
[325908.382675] ebp f9959098 esp 00000000 eax 00000000, ebx abcdefee, ecx f9959088, edx abcdefee esi 00000000 edi f9959088 eip f99590c4 rc 0
[325908.382678] ebp f9959098 esp 00000000 eax 00000000, ebx abcdefee, ecx f9959088, edx abcdefee esi 83e58955 edi f9959088 eip f99590c7 rc 0
[325908.382681] ebp f9959098 esp 00000000 eax 00000000, ebx abcdefee, ecx f9959088, edx abcdefee esi 83e58955 edi 5d8910ec eip f99590ca rc 0
[325908.382684] ebp f9959098 esp f9959098 eax 00000000, ebx abcdefee, ecx f9959088, edx abcdefee esi 83e58955 edi 5d8910ec eip f99590cc rc 0
[325908.382687] ebp f87589f4 esp f995909c eax 00000000, ebx abcdefee, ecx f9959088, edx abcdefee esi 83e58955 edi 5d8910ec eip f99590cd rc 0
[325908.382690] ebp f87589f4 esp f99590a0 eax 00000000, ebx abcdefee, ecx f9959088, edx abcdefee esi 83e58955 edi 5d8910ec eip 3efc7d89 rc 0
*/
}

void _init_context(struct x86_emulate_ctxt **ctxt)
{
    *ctxt = (struct x86_emulate_ctxt*)kmalloc(sizeof(struct x86_emulate_ctxt), GFP_KERNEL);
    // generic setting for x86_32
    (*ctxt)->regs = (void*)kmalloc(sizeof(struct cpu_user_regs), GFP_KERNEL);
    (*ctxt)->force_writeback = 0;
    (*ctxt)->addr_size = 32;
    (*ctxt)->sp_size   = 32;
}

void init_context(struct rop_emulate_ctxt **ctxt)
{
    *ctxt = (struct rop_emulate_ctxt*)kmalloc(sizeof(struct rop_emulate_ctxt), GFP_KERNEL);
	_init_context(&(*ctxt)->ctxt);
    (*ctxt)->addr_list = (struct addr_array*)kmalloc(sizeof(struct addr_array), GFP_KERNEL);
	memset((*ctxt)->addr_list, 0, sizeof(struct addr_array));
}

void _free_context(struct x86_emulate_ctxt *ctxt)
{
    kfree(ctxt->regs);
    kfree(ctxt);
}

void free_context(struct rop_emulate_ctxt *ctxt)
{
	_free_context(ctxt->ctxt);
	kfree(ctxt->addr_list);
	kfree(ctxt);
}

void set_context(struct rop_emulate_ctxt *txt, struct pt_regs* orig_regs)
{
	struct x86_emulate_ctxt *ctxt = txt->ctxt;
    ctxt->regs->ebx = orig_regs->bx;
    ctxt->regs->ecx = orig_regs->cx;
    ctxt->regs->edx = orig_regs->dx;
    ctxt->regs->esi = orig_regs->si;
    ctxt->regs->edi = orig_regs->di;
    ctxt->regs->ebp = orig_regs->bp;
    ctxt->regs->eax = orig_regs->ax;
    ctxt->regs->ds = orig_regs->ds;
    ctxt->regs->es = orig_regs->es;
    ctxt->regs->fs = orig_regs->fs;
    ctxt->regs->gs = orig_regs->gs;
    ctxt->regs->error_code = orig_regs->orig_ax;
    ctxt->regs->eip = orig_regs->ip;
    ctxt->regs->cs = orig_regs->cs;
    ctxt->regs->eflags = orig_regs->flags;
    ctxt->regs->esp = orig_regs->sp;
    ctxt->regs->ss = orig_regs->ss;
}

void clear_context(struct rop_emulate_ctxt * ctxt)
{
    //memset(ctxt->ctxt->regs, 0, sizeof(struct cpu_user_regs));
	clear_addr_list(ctxt->addr_list);
}

int x86_ins_emulate(struct rop_emulate_ctxt *ctxt){
	return x86_emulate(ctxt->ctxt, &emulops);
}
