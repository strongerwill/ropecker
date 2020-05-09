/*************************************************************************
	> File Name: data_struct.c
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Thu 06 Dec 2012 03:44:00 PM EST
 ************************************************************************/

#include <linux/string.h>

#include "debug.h"
#include "data_struct.h"
#include "branchdb.h"

db_des_t dbs[MAX_DB_NUM];

/**
 * checking if the intercepted app is the one we want to monitor
 **/
ulong is_monitor_app(const char *name){
	ulong ret = 0, i = 0;
	for(i = 0; i < MAX_APP_LIST_NUM; i++){
		 /* search the application name in the monitor list
		  * we can also use exact matching
		  * if(!strcmp(name, monitor_app_list[i]))
		  * if(strstr(monitor_app_list[i], name))
		 */
		if(monitor_app_list[i] == NULL) break;
		// if the orig name is too long (the array struct->comm's len is 16)
		// thus, we can not use strcmp
		if(!strcmp(name, monitor_app_list[i])){
			ret = 1; break;
		}
		if(strlen(name) >= 15 && !strncmp(name, monitor_app_list[i], strlen(name))){
			ret = 1; break;
		}
	
	}
	return ret;
}

/**
 * start to monitor the app, meaning allocate a new monitor app
 * in the monitor_app list
 * we record the name and allocate a mapping table for the app
 **/
monitor_app_t* start_to_monitor_app(const char *name, ulong procid){
	monitor_app_t * ptr = get_free_slot();
	if(ptr == NULL){
		(printk(KERN_ERR "No monitor slot!\n"));
		return ptr;
	}
	printk(KERN_ERR "monitor app[%s], procid %08ld\n", name, procid);
	init_app_slot(ptr, name, procid);
	return ptr;
}

/**
 * copy the lib mappings from parent process
 **/
void copy_mappings_from_parent(monitor_app_t* parent, monitor_app_t* child){
	// copy all share library mappings
	memcpy(child->mapping_table, parent->mapping_table, sizeof(mapping_element_t) * parent->element_num);
	child->element_num = parent->element_num;
	// set start point
	child->start_point = parent->start_point;
	// copy recorded code pages
	memcpy(child->monwin.pages, parent->monwin.pages, parent->monwin.num * 4);
	child->monwin.num = parent->monwin.num;
	// enable monitor flag
	child->monitor_flag = parent->monitor_flag;
}

/**
 * get the corresponding lib
 **/
mapping_element_t* get_lib_mapping(monitor_app_t *slot, ulong fromip){
	mapping_element_t * array = (mapping_element_t*)slot->mapping_table;
	long first = 0, last = slot->element_num - 1, middle = (first + last) / 2;

	//printk(KERN_ERR "the element array size %ld, first %ld, middle %ld, last %ld, ip %08lx\n", slot->element_num, first, middle, last, fromip);
	while( first <= last ) {
		if ( array[middle].end < fromip ) first = middle + 1;    
		else if ( array[middle].start > fromip ) {
			last = middle - 1;
		} else if (array[middle].start <= fromip && array[middle].end >= fromip) {
			//printk(KERN_INFO "the lib[%s], start %08lx, end %08lx, IP %08lx\n", 
			//		((db_des_t*)(array[middle].db_des))->name, array[middle].start, array[middle].end, fromip);
			return &array[middle];
		}

		middle = (first + last) / 2;
	}
	//printk(KERN_INFO "Not found! %08lx may not be in code region\n", fromip);
	return NULL;
}

int set_status_val(mapping_element_t * ele, ulong offset, unsigned char val)
{
	db_des_t * des = ele->db_des;
	register ulong pos = (offset >> 1), mod = (offset & 0x01);
	unsigned char *ptr = 0;
	
	if(des->odb.size <= pos)
		return -1;
	
	if (des->odb.buf == NULL) 
		return -1;

	ptr = &(((db_des_t*)(ele->db_des))->odb.buf[pos]);
	// set upper value
	if(mod) *ptr = (*ptr & 0x0F) | (val << 4); 
	else *ptr = (*ptr & 0xF0) | (val & 0x0F);

	return 0;
}

char get_status_val(mapping_element_t * ele, ulong offset)
{
	db_des_t * des = ele->db_des;
	register ulong pos = (offset >> 1), mod = (offset & 0x01);
	unsigned char ch = 0;
	
	if(des->odb.size <= pos)
		return 0xF;
	
	if (des->odb.buf == NULL) 
		return 0xF;
	ch = (char)(((db_des_t*)(ele->db_des))->odb.buf[pos]) & (0xF << (mod << 2));
	return (ch >> (mod << 2));
}

ulong is_direct_branch(mapping_element_t * ele, ulong offset){
	ulong flag = 0;
	ulong status = get_status_val(ele, offset);
	if(status == 0x1) flag = 1;
	return flag;
}

ulong is_indirect_branch(mapping_element_t * ele, ulong offset){
	ulong flag = 0;
	ulong status = get_status_val(ele, offset);
	if(status == 0x2) flag = 1;
	return flag;
}

/**
 * the first one is the App itself
 * the element number is 1, the start address is fixed 0x08048000
 * the size of the app is stored in the DB files
 * see the format of the DB file
 **/
mapping_element_t* insert_first_element(monitor_app_t* ptr_app, const char *filename){
	mapping_element_t* ptr_ele = ptr_app->mapping_table;
	code_region_t region;
	ptr_app->element_num = 1;
	// currently the location of app is fixed
	get_app_code_region(filename, &region);
	ptr_ele->start = region.start;
	ptr_ele->end = region.end;
	// this number needs to get from a pre-processed file
	ptr_app->start_point = 0x0804a000;
	//printk(KERN_ERR "app region start %08lx, end %08lx\n", region.start, region.end);
	return ptr_ele;
}

static inline void print_mapping_table(mapping_element_t *base, ulong num){
	int i = 0;
	for(; i < num; i++){
		printk(KERN_INFO "the element[%d] start %08lx, end %08lx\n", i, base[i].start, base[i].end);
	}
}

/**
 * insert the mapping information for a lib
 * here we maintain the order of the start addr to facilitate the later search (binary sesearch)
 **/
mapping_element_t* insert_element(monitor_app_t* ptr_app, ulong addr, ulong len){
	mapping_element_t* ptr_base = ptr_app->mapping_table, *ptr_ele = NULL;
	//printk(KERN_INFO "the new element %08lx, len %08lx", addr, len);
	// get the position of the new element, and adjust the list
	ptr_ele = get_new_element_position(ptr_base, addr);
	ptr_app->element_num ++;
	// currently the location of app is fixed
	ptr_ele->start = addr;
	ptr_ele->end = ptr_ele->start + len;
	//print_mapping_table(ptr_base, ptr_app->element_num);
	return ptr_ele;
	
}

/**
 * move all elements from position ptr_ele backward
 **/
void move_backward(mapping_element_t * ptr_ele){
	mapping_element_t left = *ptr_ele, right;
	ptr_ele ++;
	right = *ptr_ele;
	do {
		*ptr_ele = left;
		left = right;
		ptr_ele ++;
		right = *ptr_ele;
	} while(left.start != 0);
}

/**
 * get the new element position, and adjust other elements
 **/
mapping_element_t* get_new_element_position(mapping_element_t * ptr_base, ulong addr){
	mapping_element_t *ptr_ele = ptr_base;
	// get the position, without using binary search here, since it is not frequently used
	while(ptr_ele->start != 0 && ptr_ele->start < addr){
		ptr_ele++;
	}
	// move the rest elements backward, keep the order constrains
	move_backward(ptr_ele);
	return ptr_ele;
}

/**
 * move all elements from position ptr_ele forward
 **/
void move_forward(mapping_element_t * ptr_ele){
	mapping_element_t *old = ptr_ele;
	ptr_ele ++;
	do{
		*old = *ptr_ele;
		old = ptr_ele;
		ptr_ele ++;
	}while(ptr_ele->start != 0);
	// remove the content of the last element
	old->start = old->end = 0;
	old->db_des = NULL;
}

/**
 * remove the element starting from the "addr"
 * and adjust other elements to enforce the order
 **/
mapping_element_t* remove_element(mapping_element_t* ptr_base, ulong addr){
	mapping_element_t *ptr_ele = ptr_base;
	while( !(ptr_ele->start <= addr && ptr_ele->end >= addr) ){
		// checking to break infinite loop
		if(ptr_ele->start == 0) {
			ptr_ele = NULL;
			break;
		}
		ptr_ele ++;
	}
	// move forward
	if(ptr_ele != NULL) move_forward(ptr_ele);
	return ptr_ele;
}
/**
 * remove the corresponding element according to the start addr
 * note that we should maintain the order feature
 **/
void remove_mapping_element(monitor_app_t *ptr_app, ulong addr, ulong len){
	mapping_element_t* ptr_base = ptr_app->mapping_table, *ptr_ele = NULL;
	// remove the element, and maintain the order
	ptr_ele = remove_element(ptr_base, addr);
	if(ptr_ele != NULL) ptr_app->element_num --;

}

/**
 * save the fd and its corresponding filename
 **/
void save_pair(monitor_app_t* ptr_app, const char *filename, ulong fd){
	int i = 0;
	pair_element_t *ptr = ptr_app->pair_table;
	for(; i < MAX_PAIR_NUM; i ++){
		if(ptr[i].fd == 0) {
			ptr[i].fd = fd;
			strcpy(ptr[i].name, filename);
			//printk(KERN_INFO "the filename %s, fd %08lx\n", ptr[i].name, fd);
			break;
		}
	}
}

/**
 * remove the pair according to the fd
 **/
void remove_pair(monitor_app_t *ptr_app, ulong fd){
	int i = 0;
	pair_element_t *ptr = ptr_app->pair_table;
	for(; i < MAX_PAIR_NUM; i ++){
		if(ptr[i].fd == fd) {
			ptr[i].fd = 0;
			memset(ptr[i].name, 0, sizeof(ptr[i].name));
			break;
		}
	}
}

/**
 * scan the pair (fd, filename) list, return the corresponding filename
 **/
char* get_filename_by_fd(monitor_app_t *ptr_app, ulong fd){
	int i = 0;
	pair_element_t *ptr = ptr_app->pair_table;
	for(; i < MAX_PAIR_NUM; i ++){
		if(ptr[i].fd == fd) {
			return ptr[i].name;
		}
	}
	return NULL;
}
/**
 * install direct DB and indirect DB of the intercepted app/lib
 * if the DB exists, we only update the reference number
 * if not, we read the DB file and update data strcture
 **/
void install_db(mapping_element_t* ptr_ele, const char* name){
	db_des_t* pdb_des = get_db_des(name); 
	if(pdb_des == NULL){
		pdb_des = get_free_db_slot();
		//printk(KERN_INFO "in install_db, load the db [%s] first time, pdb_des %08lx\n", name, (ulong)pdb_des);
		load_db(pdb_des, name);
	}
	// update mapping element table
	ptr_ele->db_des = pdb_des;
}

/**
 * currently, the monitor list is fixed
 **/
void init_monitor_app_list(void){
	monitor_app_list[0] = "ht";
	monitor_app_list[1] = "forkt";
	monitor_app_list[2] = "vuln";

	monitor_app_list[3] = "astar_base.ia64-gcc42";
	monitor_app_list[4] = "bzip2_base.ia64-gcc42";
	monitor_app_list[5] = "gcc_base.ia64-gcc42";
	monitor_app_list[6] = "gobmk_base.ia64-gcc42";
	monitor_app_list[7] = "h264ref_base.ia64-gcc42";
	monitor_app_list[8] = "hmmer_base.ia64-gcc42";
	monitor_app_list[9] = "libquantum_base.ia64-gcc42";
	monitor_app_list[10] = "mcf_base.ia64-gcc42";
	monitor_app_list[11] = "omnetpp_base.ia64-gcc42";
	monitor_app_list[12] = "perlbench_base.ia64-gcc42";
	monitor_app_list[13] = "sjeng_base.ia64-gcc42";
	monitor_app_list[14] = "specrand_base.ia64-gcc42";
	monitor_app_list[15] = "Xalan_base.ia64-gcc42";

	monitor_app_list[16] = "httpd-prefork";
	monitor_app_list[17] = "httpd-worker";
}

/**
 * scan the list from the beginning, and return the first empty slot
 **/
db_des_t* get_free_db_slot(void){
	ulong i = 0;
	for(i = 0; i < MAX_DB_NUM; i ++){
		if(!dbs[i].odb.size){
			//printk(KERN_ERR "GET AN EMPTY SLOT INDEX %ld\n", i);
			return &dbs[i];
		}
	}
	printk(KERN_ERR "CAN NOT GET AN EMPTY SLOT !!!\n");
	return NULL;
}

/**
 * scan the DB list, and return the matching one
 * update the reference number
 **/
db_des_t* get_db_des(const char *name){
	ulong i = 0;
	for(i = 0; i < MAX_DB_NUM; i ++){
		if(!strcmp(name, dbs[i].name)){
			dbs[i].refs ++;
			return &dbs[i];
		}
	}
	return NULL;
}

/**
 * decrease the reference number
 * when the reference is 0, we do not deallocate the DB
 * since we plan to cache the DB
 **/
void put_db_des(db_des_t* db_des){
	if(db_des != NULL && db_des->refs) db_des->refs --;
}

void put_all_dbs(monitor_app_t * slot){
	int i = 0;
	mapping_element_t *ele = slot->mapping_table;
	//printk(KERN_INFO "the element num %ld\n", slot->element_num);
	for(; i < slot->element_num; i++){
		put_db_des(ele[i].db_des);
	}
}
/**
 * read direct DB and indirect DB
 **/
void load_db(db_des_t* db_des, const char *name){
	
	#ifdef MICRO_BENCHMARK
	#ifdef CHECK_LOAD_DB
		unsigned long long start = 0, end = 0;
		start = __native_read_tsc();
	#endif
	#endif
	
	read_odb(name, &db_des->odb);
	// update db_des
	db_des->refs ++;
	strcpy(db_des->name, name);
	
	#ifdef MICRO_BENCHMARK
	#ifdef CHECK_LOAD_DB
	// For quickly_rop_checking();
		end = __native_read_tsc();
	
		read_db_runs++;
		
		if(read_db_runs <= MAX_MEASURES_PER_ITEM)
			printk(KERN_ERR "read_db clockticks: %lld", (end - start));
	#endif
	#endif
}

/**
 * we only release the DB according to the explicit request
 **/
void release_db(db_des_t* db_des){
	free_db(db_des->odb.buf);
	// update db_des
	db_des->odb.size = 0;
	db_des->odb.buf = NULL;
	db_des->refs = 0;
}

/**
 * release all DBs, which may be used in the module_headexit
 **/
void release_all_dbs(void){
	int i = 0; 
	for(; i < MAX_DB_NUM; i ++){
		release_db(&dbs[i]);
	}
}
