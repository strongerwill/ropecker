/*************************************************************************
	> File Name: debug.h
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Thu 06 Dec 2012 03:59:31 PM EST
 ************************************************************************/

#ifndef __DEBUG_H_INC__
#define __DEBUG_H_INC__

#include <asm/msr.h>

#define ROP_DEBUG
#ifndef ROP_DEBUG
#define ROP_DB(x)
#else
#define ROP_DB(x) (x)
#endif

#define MICRO_BENCHMARK
//#define CHECK_LOAD_DB
#ifdef MICRO_BENCHMARK
	
	#define USE_DB_CHECK_ONLY
	#define USE_ONLINE_CHECK_ONLY
	#define MAX_MEASURES_PER_ITEM  100
	
	extern int quick_rop_checks;
	extern int quick_gadget_checks;
		
	extern int rop_payload_checks;
	extern int payload_gadget_runs;
	
	extern int read_db_runs;
#endif

#endif
