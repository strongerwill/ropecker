/*************************************************************************
	> File Name: monwin.h
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Fri 04 Jan 2013 08:12:46 AM EST
 ************************************************************************/


#ifndef __MONITOR_WINDOW_H_INC__
#define __MONITOR_WINDOW_H_INC__

#include <asm/pgtable.h>		/* page table related, PTE		*/
#include <linux/mm.h>			/* mm struct					*/
#include <linux/types.h>		/* types						*/

const static ulong KERNEL_SPACE_BOUNDARY = 0xc0000000;
const static ulong SMALL_PAGE_SIZE = 4096;


struct _monitor_win{
	ulong num;			/* the number of the code page	*/
#define MAX_CODE_PAGE_NUM	(4096*4)
	ulong *pages;		/* the code page list			*/
#define WINDOW_NUM			(1)
#define QUEUE_SIZE			(WINDOW_NUM+1)
	ulong window[QUEUE_SIZE];	/* the cycle array emulates the queue		*/
	ulong front;		/* the front of the queue		*/
	ulong rear;			/* the rear of the queue		*/
};
typedef struct _monitor_win monitor_win_t;
typedef monitor_win_t* monitor_win_p;

/**
 * the basic operations for the queue
 **/
extern void force_enqueue(monitor_win_p win, ulong addr);
extern void enqueue(monitor_win_p win, ulong addr);
extern void dequeue(monitor_win_p win, ulong *ptr);
extern int is_empty_queue(monitor_win_p win);
extern int is_full_queue(monitor_win_p win);
extern void print_queue(monitor_win_p win);
extern void free_queue(monitor_win_p win);
/**
 * create/release the list for the monitor window
 **/
extern void create_monitor_window(monitor_win_p win);
extern void release_monitor_window(monitor_win_p win);
/**
 * set/clear monitoring on a specific page
 **/
extern void set_nx_on_page(monitor_win_p win, ulong addr);
extern void clear_nx_on_page(monitor_win_p win, ulong addr);
/**
 * enable/disable the monitor window for a specific application
 **/
extern void enable_monitor_window(struct mm_struct *mm, monitor_win_p win);
extern void disable_monitor_window(monitor_win_p win);
/**
 * add/remove code page into/from the list
 **/
extern void record_code_page(monitor_win_p win, ulong base_addr);
extern void remove_code_page(monitor_win_p win, ulong base_addr);
extern int get_record_index(monitor_win_p win, ulong base_addr);

/**
 * get the PTE, return a pointer pointing to the PTE
 * note that the PTE pointer need to be released outside
 **/
extern pte_t* get_pte(struct mm_struct * mm, unsigned long address);

/**
 * release the PTE pointer
 **/
extern void free_pte(pte_t* pte);

/**
 * directly set PTE value
 **/
extern void set_pte_direct(pte_t *ptr, pteval_t value);
extern void set_exec(pte_t *pte);
extern void clear_exec(pte_t *pte);

/**
 * set the PTE value according to a virtual address
 * the set operation may failed since the PTE may not exist
 **/
extern ulong set_pte_value(struct mm_struct * mm, unsigned long address, pte_t * entry);

/**
 * get the PTE value according to a virtual address
 * the PTE value may be empty since the PTE may not exist
 **/
extern pteval_t get_pte_value(struct mm_struct * mm, unsigned long address);

/**
 * get the PTE of a given virtual address
 *
 * here we need to know who triggers (when and how) the kernel to set NX bit
 * I think execve is not a good point to intercept and parse the PT, since the PT has not been built well
 * */
extern void fast_get_pte(struct mm_struct * mm, unsigned long address, pte_t * entry);

/**
 * get the PTE of a virtual address
 **/
extern void follow_pte_4level(struct mm_struct * mm, unsigned long address, pte_t * entry);

#endif
