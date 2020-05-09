//@Copyright: QiangGeQingFuFei.com

#ifndef _STACK_CHECK_H
#define _STACK_CHECK_H

#include "types.h"
//~ #include <stdlib.h>
//~ #include <stdio.h>
//~ #include <string.h>
#include <linux/string.h>

#define MAX_PROCESS             8

// If there is <MAX_INDIRECT_CALL> of indirect calls in any 
// of <MAX_NUM_INSPECT_ADDRS> addresses. There is ROP
#define MAX_NUM_INSPECT_ADDRS   10
#define MAX_INDIRECT_CALL       6

// We need <CHECK_GADGET_INSTRS> to avoid parse error in the 
// last instruction, due to the improperly set of 
// <CHECK_GADGET_BYTES>
#define CHECK_GADGET_BYTES  48
#define CHECK_GADGET_INSTRS  5

extern void init(pid_t pid);
extern void register_cs(pid_t pid, void* lib_cs_start, void* lib_cs_end);
extern void unregister_cs(pid_t pid, void* lib_cs_start);
extern void finalize(pid_t pid);

// Return 1 if gadget found, otherwise 0.
extern BOOL is_payload(pid_t pid, void* esp, void* orig_ebp, unsigned long* rop_buf);

extern BOOL is_gadget(UCHAR* code);

#endif

