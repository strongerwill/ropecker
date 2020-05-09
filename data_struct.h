/*************************************************************************
  > File Name: data_struct.h
  > Author: Yueqiang Cheng
  > Mail: strongerwill@gmail.com 
  > Created Time: Sat 15 Sep 2012 04:09:40 PM EDT
 ************************************************************************/
#ifndef __DATA_STRUCT_H_INC__
#define __DATA_STRUCT_H_INC__

#include <linux/types.h>	/* basic types						*/
#include <linux/string.h>	/* string related operations		*/
#include <linux/slab.h>		/* kmalloc							*/

#include "monwin.h"
#include "payload_checking.h"
#include "stack_check.h"
#include "include/xen.h"
#include "emulator.h"



struct gadget_unit{
	ulong start;
	ulong esp;
	ulong is_emulated;
};
typedef struct gadget_unit gadget_unit_t;
typedef gadget_unit_t* gadget_unit_p;

#define GADGET_CACHE_NUM			ROP_GADGET_CHAIN_LENGTH	
struct gadget_cache{
	gadget_unit_t gadgets[GADGET_CACHE_NUM];
	ulong index;
};
typedef struct gadget_cache gadget_cache_t;
typedef gadget_cache_t* gadget_cache_p;

#define MAX_APP_LIST_NUM			(40)

// the list contains all apps we plan to monitor
extern char* monitor_app_list[MAX_APP_LIST_NUM];

struct _mapping_element;
typedef struct _mapping_element mapping_element_t;

/**
 * each monitored app has its own describers
 * each monitored app has a dedicated table, which contains the memory base addresses of libraries
 **/
struct _monitor_app{
	char name[256];
	ulong procid;			/* current->pid value								*/
	ulong start_point;		/* the start point of the app						*/
#define MAPPING_TABLE_SIZE				(4096*2)
	mapping_element_t* mapping_table;
	ulong element_num;		/* the number of elements in mapping table			*/
#define PAIR_TABLE_SIZE					(4096*5)
	void* pair_table;		/* the {fd,name} table is for the mmap files		*/
#define MONITOR_DISABLED				(0)
#define MONITOR_START_POINT				(1)
#define MONITOR_RUNTIME					(1<<4)
#define MONITOR_MASK					(0XFFFFFFF0)
	ulong monitor_flag;		/* indicate if starts to monitor the app			*/
	monitor_win_t monwin;		/* monitor window									*/
	//struct x86_emulate_ctxt *ctxt;	/* context for emulation					*/
	struct rop_emulate_ctxt *ctxt;	/* context for emulation					*/
};
typedef struct _monitor_app monitor_app_t;
#define MAX_MONITOR_NUM				(256)
// all apps we are monitoring
extern monitor_app_t apps[MAX_MONITOR_NUM];


struct _pair_element{
	char name[48];
	ulong fd;
};
typedef struct _pair_element pair_element_t;
const static ulong MAX_PAIR_NUM = 64*5; /* PAIR_TABLE_SIZE/sizeof(pair_element_t)	*/

struct _code_region{
	ulong start;
	ulong end;
};
typedef struct _code_region code_region_t;
typedef code_region_t* code_region_p;

/**
 * for each loaded library/app, we record its start and end address
 * we still maintain a pointer to its corresponding DB
 * */
struct _mapping_element{
	ulong libid;	/* the id of the lib/app	*/
	ulong start;	/* the start address		*/
	ulong end;		/* the end address			*/
	void* db_des;	/* DB describer				*/
};

extern mapping_element_t* get_lib_mapping(monitor_app_t *slot, ulong fromip);
extern ulong is_direct_branch(mapping_element_t * ele, ulong offset);
extern ulong is_indirect_branch(mapping_element_t * ele, ulong offset);

extern char get_status_val(mapping_element_t * ele, ulong offset);
extern int set_status_val(mapping_element_t * ele, ulong offset, unsigned char val);

extern ulong is_monitor_app(const char *name);
extern void init_monitor_app_list(void);
extern monitor_app_t* start_to_monitor_app(const char *name, ulong procid);
extern void copy_mappings_from_parent(monitor_app_t* parent, monitor_app_t* child);
extern void install_db(mapping_element_t* ptr_app, const char* name);
extern mapping_element_t* insert_first_element(monitor_app_t* ptr_app, const char *filename);
extern mapping_element_t* insert_element(monitor_app_t* ptr_app, ulong addr, ulong len);
extern void remove_mapping_element(monitor_app_t *ptr_app, ulong addr, ulong len);

extern void save_pair(monitor_app_t *ptr_app, const char *filename, ulong fd);
extern void remove_pair(monitor_app_t *ptr_app, ulong fd);
extern char* get_filename_by_fd(monitor_app_t *ptr_app, ulong fd);

/**
 * the struct describes the binary buffer
 * since it can not represented as a string buffer
 * we have to record its size
 **/
struct _binary_buf{
	char* buf;				/* the content of the binary buffer	*/
	ulong size;				/* the size of the binary buffer	*/
};
typedef struct _binary_buf binary_buf_t;
typedef binary_buf_t* binary_buf_p;

struct _db_des{
	char name[48];			/* the lib/app name, without path	*/
	ulong libid;			/* the ID of lib/app 				*/
	binary_buf_t odb;		/* the direct DB					*/
	ulong refs;				/* the reference of the DB			*/
};
typedef struct _db_des db_des_t;
typedef db_des_t* db_des_p;
#define MAX_DB_NUM					(256)
extern db_des_t dbs[MAX_DB_NUM];

extern mapping_element_t* get_new_element_position(mapping_element_t * ptr_base, ulong addr);
extern mapping_element_t* remove_element(mapping_element_t* ptr_base, ulong addr);
/**
  * get the DB describes according the name of lib
  * if the DB des does not exsit, allocate it
  * update the reference
  * */
extern db_des_t* get_db_des(const char *name);
extern db_des_t* get_free_db_slot(void);

/**
 * release the corresponding lib
 * once the reference is 0, meaning there is no app using it
 * But we do not release the DB here
 * */
extern void put_db_des(db_des_t* db_des);
extern void put_all_dbs(monitor_app_t * slot);
/**
 * alloc/free lib DB by requirement
 * */
extern void load_db(db_des_t* db_des, const char *name);
extern void release_db(db_des_t* db_des);
extern void release_all_dbs(void);

static inline monitor_app_t* get_free_slot(void){
	int i = 0; 
	for(i = 0; i < MAX_MONITOR_NUM; i ++){
		if(apps[i].procid == 0){
			return &apps[i];
		}
	}
	return NULL;
}

static inline monitor_app_t* get_app_slot(ulong procid){
	int i = 0; 
	for(i = 0; i < MAX_MONITOR_NUM; i ++){
		if(apps[i].procid == procid){
			return &apps[i];
		}
	}
	return NULL;
}

static inline monitor_app_t* get_app_slot_by_name(const char *name){
	int i = 0; 
	for(i = 0; i < MAX_MONITOR_NUM; i ++){
		if(! strcmp(apps[i].name, name) ){
			return &apps[i];
		}
	}
	return NULL;
}

/**
 * accelarate the checking process (do not use string matching)
 **/
static inline ulong is_monitor_app_by_id (ulong id){
	return !!(ulong)get_app_slot(id);
}

static inline ulong is_monitor_app_by_name (const char *name){
	return !!(ulong)get_app_slot_by_name(name);
}

/**
 * init the monitoring app slot
 * allocate a new mapping table for the monitoring app
 **/
static inline void init_app_slot(monitor_app_t *ptr, const char *name, ulong procid){
			ptr->procid = procid;
			strcpy(ptr->name, name);
			ptr->mapping_table = kmalloc(MAPPING_TABLE_SIZE, GFP_KERNEL);
			memset(ptr->mapping_table, 0, MAPPING_TABLE_SIZE);
			ptr->pair_table = kmalloc(PAIR_TABLE_SIZE, GFP_KERNEL);
			memset(ptr->pair_table, 0, PAIR_TABLE_SIZE);
			create_monitor_window(&ptr->monwin);
			init_context(&ptr->ctxt);
}

/**
 * when the exit_group happens, we stop monitoring the app
 **/
static inline void free_app_slot(monitor_app_t *ptr){
			// finalize, to clear payload states and data structures
			payload_checking_finalize(ptr->procid);

			ptr->procid = 0;
			ptr->name[0] = '\0';
			kfree(ptr->mapping_table);
			kfree(ptr->pair_table);
			ptr->mapping_table = 0;
			// release the monitor window
			release_monitor_window(&ptr->monwin);
			free_context(ptr->ctxt);
			memset(ptr, 0, sizeof(monitor_app_t));
}

static inline void free_all_apps(void){
	int i = 0;
	for(i = 0; i < MAX_MONITOR_NUM; i ++){
		if(apps[i].procid != 0){
			free_app_slot(&apps[i]);
		}
	}
}
/**
 * a utility function
 * get the filename from the path
 **/
static inline char* get_name_from_path(const char* path){
	const char *ptr = path, *slash = path;
	while(*ptr){
		if(*ptr == '/') slash = ptr;
		ptr ++;
	}
	slash ++;
	// fix this to get the real file name
	return (char*)slash;
}

#endif 
