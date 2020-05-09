/*************************************************************************
	> File Name: lbr.h
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Wed 05 Dec 2012 11:16:20 PM EST
 ************************************************************************/
#ifndef __LBR_H_INC__
#define __LBR_H_INC__

// on some machines, the 
//#define MSR_LASTBRANCH_0_FROM_IP			(0x040)
//#define MSR_LASTBRANCH_0_TO_IP			(0x060)
//#define MAX_BRANCH_NUM					(4)

#define MSR_LASTBRANCH_0_FROM_IP		(0x680)
#define MSR_LASTBRANCH_0_TO_IP			(0x6C0)
#define MAX_BRANCH_NUM					(16)
#define ROP_LBR_CHECKING_NUM			(7)

#define MSR_LBR_SELECT					(0x1C8)
#define MSR_LASTBRANCH_TOS				(0x1C9)
#define IA32_DEBUGCTL					(0x1D9)
#define MSR_LER_FROM_LIP				(0x1DD)
#define MSR_LER_TO_LIP					(0x1DE)

static inline void enable_lbr(void){
	ulong ctrl = -1;
	asm volatile("rdmsr \n":"=a"(ctrl):"c"(IA32_DEBUGCTL):"%edx");
	ctrl = (ctrl | 0x1);
	asm volatile("wrmsr \n"::"c"(IA32_DEBUGCTL), "a"(ctrl), "d"(0x0):"memory");
}

static inline void disable_lbr(void){
	ulong ctrl = -1;
	// disable lbr interception
	asm volatile("rdmsr \n":"=a"(ctrl):"c"(IA32_DEBUGCTL):"%edx");
	ctrl = (ctrl & (~0x1));
	asm volatile("wrmsr \n"::"c"(IA32_DEBUGCTL), "a"(ctrl), "d"(0x0):"memory");
}

static inline ulong get_lbr_position(void){
	ulong pos = -1;
	asm volatile("rdmsr \n":"=a"(pos):"c"(MSR_LASTBRANCH_TOS):"%edx");
	return pos;
}

static inline void lbr_userspace(void){
	ulong select = -1;
	asm volatile("rdmsr \n":"=a"(select):"c"(MSR_LBR_SELECT):"%edx");
	// do not capture kernel, and start to capture user space
	select = (select | 0x1);
	select = (select & (~0x2));
	asm volatile("wrmsr \n"::"c"(MSR_LBR_SELECT), "a"(select), "d"(0x0):"memory");
}

static inline void lbr_kernelspace(void){
	ulong select = -1;
	asm volatile("rdmsr \n":"=a"(select):"c"(MSR_LBR_SELECT):"%edx");
	// do not capture user space, and start to capture kernel space
	select = (select | 0x2);
	select = (select & (~0x1));
	asm volatile("wrmsr \n"::"c"(MSR_LBR_SELECT), "a"(select), "d"(0x0):"memory");
}

static inline void clear_lbr_select(void){
	ulong select = -1;
	asm volatile("rdmsr \n":"=a"(select):"c"(MSR_LBR_SELECT):"%edx");
	// clear setting
	select = (select & (~0x2));
	select = (select & (~0x1));
	asm volatile("wrmsr \n"::"c"(MSR_LBR_SELECT), "a"(select), "d"(0x0):"memory");
}

static inline void get_ip_pairs(ulong *fromip, ulong *toip, ulong start_pos, ulong num){
	int i = 0;
	for( ; i < num; i ++){
		asm volatile("rdmsr \n":"=a"(fromip[i]):"c"(MSR_LASTBRANCH_0_FROM_IP + ((start_pos + i) % MAX_BRANCH_NUM)):"%edx");
		asm volatile("rdmsr \n":"=a"(toip[i]):"c"(MSR_LASTBRANCH_0_TO_IP + ((start_pos + i) % MAX_BRANCH_NUM)):"%edx");
	}
}

#endif
