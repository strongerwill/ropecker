/*************************************************************************
  > File Name: kern_expirq.h
  > Author: Yueqiang Cheng
  > Mail: strongerwill@gmail.com 
  > Created Time: Sat 15 Sep 2012 04:09:40 PM EDT
 ************************************************************************/
#ifndef __ROP_GUARD_H_INC__
#define __ROP_GUARD_H_INC__

#include <asm/desc.h>		/* gate_desc struct, load/set_idt	*/
#include <linux/kprobes.h>  /* __kprobes, ...       */
#include <asm/traps.h>		/* dotraplinkage		*/
#include <linux/ftrace.h>	/* __irq_entry			*/
#include <asm/ptrace.h>		/* struct pt_regs		*/

#define PAGE_COPY_EXECV						(0x25LLU)
#define LD_NAME								"ld-2.15.so"
#define VDSO_NAME							"vdso"

// see the definition of the do_page_fault in the arch/x86/mm/fault.c
dotraplinkage void __kprobes pre_handle_exception ( struct pt_regs* regs, ulong error_code);
dotraplinkage void __kprobes post_handle_exception ( struct pt_regs* regs, ulong error_code);

// init and exit function for 
extern int pagefault_syscall_init(void);
extern void pagefault_syscall_exit(void);


extern long rop_check(ulong procid, struct pt_regs *regs); 
extern long rop_check1(ulong procid, struct pt_regs *regs); 
extern long rop_check2(ulong procid, struct pt_regs *regs); 

extern asmlinkage long rop_mprotect(ulong start, size_t len, ulong prot);
extern asmlinkage long rop_mmap2(ulong addr, ulong len, ulong prot, ulong flags, ulong fd, ulong pgoff);
extern asmlinkage long rop_munmap(ulong addr, ulong len);
extern asmlinkage long rop_execve(const char __user *name);
extern asmlinkage long rop_fork(struct pt_regs *regs);
extern asmlinkage long rop_clone(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *regs);
extern asmlinkage long rop_open(const char __user *name, int flags, int mode);
extern asmlinkage long rop_close(ulong fd);
extern asmlinkage long rop_exit_group(ulong error);

typedef asmlinkage long (*MPROTECT_FN)(ulong start, size_t len, ulong prot);
typedef asmlinkage long (*MMAP2_FN)(ulong addr, ulong len, ulong prot, ulong flags, ulong fd, ulong pgoff);
typedef asmlinkage long (*MUNMAP_FN)(ulong addr, ulong len);
typedef asmlinkage long (*EXECVE_FN)(const char __user *name);
typedef asmlinkage long (*CLONE_FN)(unsigned long flags, void *child_stack, void *ptid, void *ctid, struct pt_regs *regs);
typedef asmlinkage long (*OPEN_FN)(const char __user *name, int flags, int mode);
typedef asmlinkage long (*CLOSE_FN)(ulong fd);
typedef asmlinkage long (*EXIT_GROUP_FN)(ulong error);

extern ulong g_exp_irq_esp;
extern ulong g_error_code;

// the following three are heavily dependent on the system,
// we should modify them according to the infor in /proc/kallsyms
const static ulong orig_idt_table = (0xc1804000);			// the address of the IDT  
const static ulong orig_system_call = (0xc15a5748);		// the entry address of the int80 
const static ulong orig_sys_call_table = (0xc15b0000);		// the system call table
const static ulong orig_do_page_fault = 0xc15a8a80;		// the original page fault handler address
const static ulong orig_ret_from_exception = 0xc15a5710;// the original ret_from_exception address
const static ulong orig_sys_clone = 0xc10192f0;
const static ulong orig_sys_fork = 0xc1019270;

static inline ulong get_orig_system_call(const int index)
{
	return *((ulong*)(orig_sys_call_table + index * sizeof(int)));
}
static inline void kern_native_write_idt_entry(gate_desc *idt, int entry,
		const gate_desc *gate)
{
	memcpy(&idt[entry], gate, sizeof(*gate));
}

static inline void kern_pack_gate(gate_desc *gate, unsigned char type,
		unsigned long base, unsigned dpl, unsigned flags,
		unsigned short seg)
{
	gate->a = (seg << 16) | (base & 0xffff);
	gate->b = (base & 0xffff0000) |
		(((0x80 | type | (dpl << 5)) & 0xff) << 8);
}

static inline void kern_set_gate(int gate, unsigned type, void *addr,
		unsigned dpl, unsigned ist, unsigned seg)
{
	gate_desc s;
	kern_pack_gate(&s, type, (unsigned long)addr, dpl, ist, seg);
	kern_native_write_idt_entry((gate_desc*)orig_idt_table, gate, &s);
}

static inline void kern_set_new_gate(int gate, unsigned type, void *addr,
		unsigned dpl, unsigned ist, unsigned seg)
{
	kern_set_gate(gate, type, addr, dpl, ist, seg);
}

static inline void kern_set_system_trap_gate(unsigned int n, void *addr)
{
	kern_set_gate(n, GATE_TRAP, addr, 0x3, 0, __KERNEL_CS);
}

static inline void kern_restore_systemcall_gate ( void ) {
	kern_set_system_trap_gate(SYSCALL_VECTOR, (char*)orig_system_call);
}
static inline void kern_set_intr_gate(unsigned int n, void *addr)
{
	kern_set_new_gate(n, GATE_INTERRUPT, addr, 0x0, 0, __KERNEL_CS);
}
static inline void kern_set_system_intr_gate(unsigned int n, void *addr)
{
	kern_set_new_gate(n, GATE_INTERRUPT, addr, 0x3, 0, __KERNEL_CS);
}

static inline void kern_set_intr_gate_ist(unsigned int n, void *addr, unsigned int ist)
{
	kern_set_new_gate(n, GATE_INTERRUPT, addr, 0x0, ist, __KERNEL_CS);
}
static inline void kern_set_system_intr_gate_ist(unsigned int n, void *addr, unsigned int ist)
{
	kern_set_new_gate(n, GATE_INTERRUPT, addr, 0x3, ist, __KERNEL_CS);
}

// ---------- write to read-only memory with CR0-WP bit manipulation ---------//
/* From <asm/processor-flags.h> */
#define X86_CR0_WP 0x00010000
/* From <asm/system.h> */
static unsigned long __force_order;
static inline unsigned long readcr0(void) {
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}
static inline void writecr0(unsigned long val) {
	asm volatile("mov %0,%%cr0" : : "r" (val), "m" (__force_order));
}

#endif 
