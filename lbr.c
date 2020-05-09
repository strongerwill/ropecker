/*************************************************************************
	> File Name: lbr.c
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Sat 17 Nov 2012 10:37:01 PM EST
 ************************************************************************/

#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module */
#include <linux/version.h>
#include <asm/uaccess.h>	/* for get_user and put_user */

#include "lbr.h"
/* 
 * Initialize the module - Register the character device 
 * The MSR position infor, see Page 2846 in the new Intel Specification
 */
static int __init lbr_module_init(void)
{
	ulong pos = -1;
	ulong i = 0;
	ulong fromip[16] = {0}, toip[16] = {0};

	enable_lbr();
	clear_lbr_select();

	printk(KERN_INFO "The position is %08lx\n", get_lbr_position());
	for(i = 0; i < 32; ++i){
		pos = get_lbr_position();
		get_ip_pairs(fromip, toip, pos, 1);
		printk(KERN_INFO "The index [%ld] position is %08lx, from %08lx -> %08lx\n", i, pos, fromip[0], toip[0]);
	}

	// test lbr_select
	lbr_userspace();
	for(i = 0; i < 32; ++i){
		pos = get_lbr_position();
		get_ip_pairs(fromip, toip, pos, 1);
		printk(KERN_INFO "The index [%ld] position is %08lx, from %08lx -> %08lx\n", i, pos, fromip[0], toip[0]);
	}
	printk(KERN_INFO " the lbr module init done!\n");

	return 0;
}

/* 
 * Cleanup - unregister the appropriate file from /proc 
 */
static void __exit lbr_module_exit(void)
{
	ulong pos = -1, i = 0;
	ulong fromip[16] = {0}, toip[16] = {0};

	printk(KERN_INFO "The position is %08lx\n", get_lbr_position());

	get_ip_pairs(fromip, toip, pos, 16);
	for(i = 0; i < 16; ++i){
		printk(KERN_INFO "The index [%ld]  from %08lx -> %08lx\n", i, fromip[i], toip[i]);
	}
	// clear lbr_select
	clear_lbr_select();

	// disable lbr interception
	disable_lbr();
}

/* Let the kernel know the calls for module init and exit */
module_init(lbr_module_init);
module_exit(lbr_module_exit);
MODULE_LICENSE("GPL");

