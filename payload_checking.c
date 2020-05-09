/*************************************************************************
	> File Name: payload_checking.c
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Sun 13 Jan 2013 02:37:55 PM EST
 ************************************************************************/
#include "debug.h"
#include "payload_checking.h"
#include "stack_check.h"

void payload_checking_init(ulong procid){
	//init((pid_t)procid);
}

void payload_checking_finalize(ulong procid){
	//finalize((pid_t)procid);
}

void unregister_code_region(ulong procid, void* start){
	//unregister_cs((pid_t)procid, start);
}

void register_code_region(ulong procid, void* start, void* end){
	//register_cs((pid_t)procid, start, end);
}

long is_rop_payload(ulong procid, void* esp, void* orig_ebp, ulong* buf){
	long ret = 0;
	
	//ret = is_payload((pid_t)procid, esp, orig_ebp, buf);
	return ret;
}

long check_is_gadget(unsigned char* code)
{
	return is_gadget(code);
}
