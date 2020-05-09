/*************************************************************************
	> File Name: branchdb.h
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Thu 06 Dec 2012 01:05:36 PM EST
 ************************************************************************/

#ifndef __BRANCHDB_H_INC__
#define __BRANCHDB_H_INC__

typedef struct _binary_buf binary_buf_t;
typedef binary_buf_t* binary_buf_p;

extern ulong read_odb(const char *name, binary_buf_p pdb_f);
extern void read_db(binary_buf_p odb, const char *name);
extern void free_db(char* odb);

typedef struct _code_region code_region_t;
typedef code_region_t* code_region_p;
extern ulong get_app_code_region(const char *filename, code_region_p region);
#endif
