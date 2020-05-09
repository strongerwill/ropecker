/*************************************************************************
	> File Name: monwin.c
	> Author: strongerwill
	> Mail: strongerwill@gmail.com 
	> Created Time: Fri 04 Jan 2013 08:15:30 AM EST
 ************************************************************************/

#include <linux/highmem.h>		/* kmap_atomic					*/
#include <linux/slab.h>			/* kmalloc					*/
#include <linux/vmalloc.h>		/* vmalloc/vfree				*/
#include <linux/string.h>		/* memset					*/
#include "monwin.h"

/**
 * get the PTE, return a pointer pointing to the PTE
 * note that the PTE pointer need to be released outside
 **/
pte_t* get_pte(struct mm_struct * mm, unsigned long address)
{
	pgd_t * pgd = pgd_offset(mm, address);
	pud_t * pud = (pud_t*)pgd;
	if (!pgd_none(*pgd) && !pgd_bad(*pgd)) {
		pmd_t * pmd = pmd_offset(pud, address);
		if (pmd_none(*pmd)) return NULL;
		if (!pmd_bad(*pmd)) {
			return pte_offset_map(pmd, address);
		}
	}
	return NULL;
}

/**
 * release the PTE pointer
 **/
void free_pte(pte_t* pte){
	if(pte) pte_unmap(pte);
}

/**
 * directly set PTE value
 **/
void set_pte_direct(pte_t *ptr, pteval_t value){
	if(ptr != NULL) ptr->pte = value;
}

void set_exec(pte_t *pte){
	unsigned long long nx_mask = 0x8000000000000000;
	set_pte_direct(pte, pte_val(*pte) & (~nx_mask));
}

void clear_exec(pte_t *pte){
	unsigned long long nx_mask = 0x8000000000000000;
	set_pte_direct(pte, pte_val(*pte)|nx_mask);
}

/**
 * set the PTE value according to a virtual address
 * the set operation may failed since the PTE may not exist
 **/
ulong set_pte_value(struct mm_struct * mm, unsigned long address, pte_t * entry)
{
	pte_t * pte = get_pte(mm, address);
	if(pte != NULL){
		pte->pte = pte_val(*entry);
		free_pte(pte);
		return 1;
	}
	return 0;
}

/**
 * get the PTE value according to a virtual address
 * the PTE value may be empty since the PTE may not exist
 **/
pteval_t get_pte_value(struct mm_struct * mm, unsigned long address){
	pte_t * pte = get_pte(mm, address);
	pteval_t value = 0;
	if(pte != NULL){
		value = pte_val(*pte);
		free_pte(pte);
	}
	return value;
}

/**
 * get the PTE of a given virtual address
 *
 * here we need to know who triggers (when and how) the kernel to set NX bit
 * I think execve is not a good point to intercept and parse the PT, since the PT has not been built well
 * */
void fast_get_pte(struct mm_struct * mm, unsigned long address, pte_t * entry)
{
	pgd_t * pgd = pgd_offset(mm, address);
	pud_t * pud = (pud_t*)pgd;

	entry->pte = 0;
	if (!pgd_none(*pgd) && !pgd_bad(*pgd)) {
		pmd_t * pmd = pmd_offset(pud, address);

		if (pmd_none(*pmd)) return;
		if (!pmd_bad(*pmd)) {
			pte_t * pte = pte_offset_map(pmd, address);

			if (!pte_none(*pte)) {
				entry->pte = pte_val(*pte);
				printk("follow_pte() for %lx\n", address);
				printk(" pgd = %llx\n", pgd_val(*pgd));
				printk("   pmd = %llx\n", pmd_val(*pmd));
				printk("    pte = %llx\n", pte_val(*pte));
			}
			pte_unmap(pte);
		}
	}
}

/**
 * get the PTE of a virtual address
 **/
void follow_pte_4level(struct mm_struct * mm, unsigned long address, pte_t * entry)
{
	pgd_t * pgd = pgd_offset(mm, address);
	entry->pte = 0;
	if (!pgd_none(*pgd) && !pgd_bad(*pgd)) {
		pud_t * pud = pud_offset(pgd, address);
		if (pud_none(*pud)) return;
		if (!pud_bad(*pud)) {
			pmd_t * pmd = pmd_offset(pud, address);
			if (pmd_none(*pmd)) return;
			if (!pmd_bad(*pmd)) {
				pte_t * pte = pte_offset_map(pmd, address);
				if (!pte_none(*pte)) {
					entry->pte = pte_val(*pte);
					printk("follow_pte() for %lx\n", address);
					printk(" pgd = %llx\n", pgd_val(*pgd));
					printk("  pud = %llx\n", pud_val(*pud));
					printk("   pmd = %llx\n", pmd_val(*pmd));
					printk("    pte = %llx\n", pte_val(*pte));
				}
				pte_unmap(pte);
			}
		}
	}
}

/**
 * remove the code page record from the list
 * this function may never/rarely be called 
 * usually, the disable_monitor_window function will remove all code pages when the application exits
 **/
void remove_code_page(monitor_win_p win, ulong base_addr){
	int index = get_record_index(win, base_addr);
	if(index != -1){
		// remove the element by swappng with the last element
		win->pages[index] = win->pages[win->num - 1];
		win->pages[win->num -1] = 0;
		win->num --;
	} else {
		printk(KERN_ERR "the code page[%08lx] does not exist in the list\n", base_addr);
	}
}

/**
 * find if the code page is recorded
 * if found, return the index, otherwise, return -1
 **/
int get_record_index(monitor_win_p win, ulong base_addr){
	int index = -1, i = 0;
	for(; i < win->num; i++){
		if(win->pages[i] == base_addr) return i;
	}
	return index;
}
/**
 * record the page (i.e., the base address)
 **/
void record_code_page(monitor_win_p win, ulong base_addr){
	win->pages[win->num] = (base_addr & 0xfffff000);
	win->num ++;
}

/**
 * enable the monitor window on the specific application
 * all code pages are recorded and set non-executable
 **/
void enable_monitor_window(struct mm_struct *mm, monitor_win_p win){
	// mask for NX bit
	unsigned long long nx_mask = 0x8000000000000000;
	ulong addr = 0;

	for(addr = 0; addr < KERNEL_SPACE_BOUNDARY; addr += PAGE_SIZE){
		pte_t *pte = get_pte(mm, addr);
		// if the PTE entry exists, and the NX bit is not set
		if( pte != NULL ) {
			if(!pte_none(*pte) && (pte_val(*pte) & nx_mask) == 0 ){
				// record the addr (page) and set the page non-executable (set the NX bit)
				record_code_page(win, addr & 0xfffff000);
				set_pte_direct(pte, pte_val(*pte)|nx_mask);
			}
			free_pte(pte);
		}
	}
}

void disable_monitor_window(monitor_win_p win){
	int i = 0;
	for(; i < win->num; i++){
		clear_nx_on_page(win, win->pages[i]);
	}
	memset(win->pages, 0, win->num*4);
	win->num = 0;
	win->front = win->rear = 0;
	free_queue(win);
}
/**
 * create/release the list for the monitor window
 **/
void create_monitor_window(monitor_win_p win){
	win->pages = vmalloc(MAX_CODE_PAGE_NUM);
	memset(win->pages, 0, MAX_CODE_PAGE_NUM);
	win->num = 0;
	win->front = win->rear = 0;
}
void release_monitor_window(monitor_win_p win){
	disable_monitor_window(win);
	if(win->pages != NULL) vfree(win->pages);
	win->num = 0;
	win->front = win->rear = 0;
	free_queue(win);
}

/**
 * set/clear monitoring on a specific page
 **/
void set_nx_on_page(monitor_win_p win, ulong addr){
	pte_t *pte = get_pte(current->mm, addr);
	if(pte) {
		unsigned long long nx_mask = 0x8000000000000000;
		if(pte_val(*pte) == 0) {
			//printk(KERN_ERR "process[%s] pid %08d the addr is %08lx\n", current->comm, current->pid, addr);
			free_pte(pte);
			return;
		}
		set_pte_direct(pte, pte_val(*pte)|nx_mask);
		free_pte(pte);
	}
}

void clear_nx_on_page(monitor_win_p win, ulong addr){
	pte_t *pte = get_pte(current->mm, addr);
	if(pte) {
		unsigned long long nx_mask = 0x8000000000000000;
		if(pte_val(*pte) == 0) {
			//printk(KERN_ERR "process[%s] pid %08d the addr is %08lx\n", current->comm, current->pid, addr);
			free_pte(pte);
			return;
		}
		set_pte_direct(pte, pte_val(*pte) & (~nx_mask));
		free_pte(pte);
	}
}

/**
 * force to enqueue
 * if the queue is full, dequeue the first one, and enqueue
 * for the dequeued element, clear the executable right, free the mapping
 **/
void force_enqueue(monitor_win_p win, ulong addr){
	if(is_full_queue(win)) {
		ulong value = 0;
		dequeue(win, &value);
		// clear the executable right
		set_nx_on_page(win, value);
	}
	clear_nx_on_page(win, addr);
	win->window[win->rear] = addr;
	win->rear = (win->rear + 1) % QUEUE_SIZE;
}
/**
 * enqueue/dequeue for the monitor window
 **/
void enqueue(monitor_win_p win, ulong addr){
	if(is_full_queue(win)) return;
	win->window[win->rear] = addr;
	win->rear = (win->rear + 1) % QUEUE_SIZE;
}
void dequeue(monitor_win_p win, ulong *ptr){
	if(is_empty_queue(win)) return;
	*ptr = win->window[win->front];
	win->front = (win->front + 1) % QUEUE_SIZE;
}
/**
 * check the queue is empty/full
 **/
int is_empty_queue(monitor_win_p win){
	if(win->front == win->rear) return 1;
	return 0;
}
int is_full_queue(monitor_win_p win){
	if((win->rear + 1) % QUEUE_SIZE == win->front) return 1;
	return 0;
}
/**
 * print the queue
 **/
void print_queue(monitor_win_p win){
	int tail = win->front;
	while(tail != win->rear){
		printk(KERN_INFO "%08lx ", win->window[tail]);
		tail = (tail+1) % QUEUE_SIZE;
	}
	printk(KERN_INFO "\n");
}

/**
 * free all cached PTEs
 **/
void free_queue(monitor_win_p win){
}
