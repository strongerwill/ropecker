/*************************************************************************
	> File Name: payload_checking.h
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Sun 13 Jan 2013 01:44:09 PM EST
 ************************************************************************/

#ifndef __PAYLOAD_CHECKING_H__
#define __PAYLOAD_CHECKING_H__

#include <linux/types.h>

#define ALIGNED_NO_BRANCH					(0x0)	//0000
#define ALIGNED_SJMP						(0x1)	//0001
#define ALIGNED_RET							(0x2)	//0010
#define ALIGNED_IJMP						(0x3)	//0011
#define ALIGNED_STACK_PIVOT					(0x4)	//0100
#define ALIGNED_UNKNOWN_SIZE				(0x5)	//0101
#define UNALIGNED_INSTRUCTION				(0xF)
#define ROP_GADGET_CHAIN_LENGTH				(8)

extern void payload_checking_init(ulong procid);
extern void payload_checking_finalize(ulong procid);

extern void unregister_code_region(ulong procid, void* start);
extern void register_code_region(ulong procid, void* start, void* end);

extern long is_rop_payload(ulong procid, void* esp, void* orig_ebp, ulong* buf);
extern long check_is_gadget(unsigned char* code);
#endif
