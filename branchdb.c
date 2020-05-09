/*************************************************************************
	> File Name: branchdb.c
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Thu 06 Dec 2012 01:08:02 PM EST
 ************************************************************************/

#include <linux/vmalloc.h>		/* vmalloc and vfree			*/
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "debug.h"
#include "data_struct.h"
#include "branchdb.h"

//const static char *directory = "/home/wqj/program/module/ROPProject/code/ndss_DB_gen/db_gen/";
//const static char *directory = "/home/wqj/program/module/ROPProject/code/ndss_DB_gen/db_gen/";
//const static char *directory = "/home/yunfeiyang/program/linux/ROPProject/code/ndss_DB_gen/db_gen/";
const static char *directory = "/home/yunfeiyang/rop/code/ndss_DB_gen/db_gen/";
//const static char *directory = "/home/superymk/rop/code/ROP_example/hteditor/DB/optDB/";
//const static char *directory = "/home/yunfeiyang/program/cmugroup/ROPProject/code/ROP_example/hteditor/DB/optDB/";
//const static char *directory = "/home/yunfeiyang/program/cmugroup/ROPProject/code/ROP_example/vuln/DB/";


static inline loff_t file_pos_read(struct file *file){
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos){
	file->f_pos = pos;
}

ulong read_file(const char* name, binary_buf_p pdb_f){
	mm_segment_t fs = get_fs();
	struct file *fd = 0;
	ulong size = 0;
	loff_t offset = 0; 

	// change fs
	set_fs(KERNEL_DS);

	fd = filp_open(name, O_RDONLY, 0644);
	if(IS_ERR(fd)) {
		printk(KERN_ERR "The file[%s] does not exist!\n", name);
		return 0;
	}
	vfs_read(fd, (char*)&size, 4, &offset);
	// change the size to char size, bitmap
	if(size == 0) return 0;
	size = size / 2 ;
	pdb_f->buf = vmalloc(size);
	memset(pdb_f->buf, 0, size);
	pdb_f->size = size;
	// for the old version, the format size, stream
	//file_pos_write(fd, offset);
	// for the new version, the format is size, start_addr, end_addr, stream, we need to skip the two addrs
	offset = 12;
	file_pos_write(fd, offset);
	vfs_read(fd, pdb_f->buf, size, &offset);
	filp_close(fd, NULL);

	// restore fs
	set_fs(fs);
	return size;
}

ulong read_odb(const char* name, binary_buf_p pdb_f){
	// read the db file according to the name
	char buf[256] = {0};
	char *pre_fix = "OVC/";
	char *pos_fix = ".ovc";
	ulong ret = 0;
	
	sprintf(buf, "%s%s%s%s", directory, pre_fix, name, pos_fix);
	ret = read_file(buf, pdb_f);
	return ret;
}

void read_db(binary_buf_p odb, const char *name){
	
	read_odb(name, odb);
	
	
}

void free_db(char* odb_buf){
	if(odb_buf) vfree(odb_buf);
}

ulong get_app_code_region(const char* filename, code_region_p region){
	// open the file (direct and indirect DB)
	mm_segment_t fs = get_fs();
	struct file *fd = 0;
	loff_t offset = 4; 
	char buf[256] = {0}, *pre_fix = "OVC/", *pos_fix = ".ovc";
	//char buf[256] = {0}, *pre_fix = "SIZE/", *pos_fix = ".size";
	sprintf(buf, "%s%s%s%s", directory, pre_fix, filename, pos_fix);

	// change fs
	set_fs(KERNEL_DS);

	fd = filp_open(buf, O_RDONLY, 0644);
	if(IS_ERR(fd)) return 0;
	region->start = 0x08049f60; region->end = 0x0814c1d5;
	file_pos_write(fd, offset);
	// read the first 4 bytes, the start addr 
	vfs_read(fd, (char*)&region->start, 4, &offset);
	// adjust the offset to read the next 4 bytes
	file_pos_write(fd, offset);
	// read next 4 bytes, the end addr
	vfs_read(fd, (char*)&region->end, 4, &offset);
	// change the size to char size, bitmap
	filp_close(fd, NULL);

	// restore fs
	set_fs(fs);
	return region->end - region->start;
}
