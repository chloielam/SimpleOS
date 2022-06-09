
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct {
	uint32_t proc;	// ID of process currently uses this page
	int index;	// Index of the page in the list of pages allocated
			// to the process.
	int next;	// The next page in the list. -1 if it is the last
			// page.
} _mem_stat [NUM_PAGES];

static pthread_mutex_t mem_lock;

void init_mem(void) {
	memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
	memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
	pthread_mutex_init(&mem_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr) {
	return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr) {
	return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr) {
	return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t * get_page_table(
		addr_t index, 	// Segment level index
		struct seg_table_t * seg_table) { // first level table
	
	/*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [seg_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

	int i;
	for (i = 0; i < seg_table->size; i++) {
		// Enter your code here
		if(seg_table->table[i].v_index == index) {
			return seg_table->table[i].pages;
		} // Check if the v_index is matched with index
	}
	return NULL;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
		addr_t virtual_addr, 	// Given virtual address
		addr_t * physical_addr, // Physical address to be returned
		struct pcb_t * proc) {  // Process uses given virtual address

	/* Offset of the virtual address */
	addr_t offset = get_offset(virtual_addr);
	/* The first layer index */
	addr_t first_lv = get_first_lv(virtual_addr);
	/* The second layer index */
	addr_t second_lv = get_second_lv(virtual_addr);
	
	/* Search in the first level */
	struct page_table_t * page_table = NULL;
	page_table = get_page_table(first_lv, proc->seg_table);
	if (page_table == NULL) {
		return 0;
	}

	int i;
	for (i = 0; i < page_table->size; i++) {
		if (page_table->table[i].v_index == second_lv) {
			/* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of page_table->table[i] to 
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */
			*physical_addr = (page_table->table[i].p_index << OFFSET_LEN) | offset;
			return 1;
		}
	}
	return 0;	
}

int checkEnoughPhyMem(int pageNum, addr_t * freePagesList) {
	int count = 0; 
	for(uint32_t i = 0; i < NUM_PAGES && count < pageNum; i++) {
		if(_mem_stat[i].proc == 0) {
			freePagesList[count] = i;
			count += 1; 
		} // Check if the frame slot is free then increase 'count' and update the freePagesList
	}
	if(count == pageNum) {
		return 1; // Enough virtual memory
	} else return 0; // Not enough free slots
}

int checkEnoughVirMem(int pageNum, struct pcb_t * proc) {
	uint32_t i = proc->bp;
	if((i + (pageNum * PAGE_SIZE)) < (NUM_PAGES * PAGE_SIZE)) return 1; 
	else return 0;
}

addr_t alloc_mem(uint32_t size, struct pcb_t * proc) {
	pthread_mutex_lock(&mem_lock);
	addr_t ret_mem = 0;
	/* TODO: Allocate [size] byte in the memory for the
	 * process [proc] and save the address of the first
	 * byte in the allocated memory region to [ret_mem].
	 * */

	uint32_t num_pages = (size % PAGE_SIZE) ? size / PAGE_SIZE + 1: size / PAGE_SIZE; // Number of pages we will use
	int mem_avail = 0; // We could allocate new memory region or not?

	/* First we must check if the amount of free memory in
	 * virtual address space and physical address space is
	 * large enough to represent the amount of required 
	 * memory. If so, set 1 to [mem_avail].
	 * Hint: check [proc] bit in each page of _mem_stat
	 * to know whether this page has been used by a process.
	 * For virtual memory space, check bp (break pointer).
	 * */
	
	addr_t freePagesList[num_pages]; // An array to store indexes of free physical pages in _mem_stat
	// Update 'mem_vail' if enough both physical and virtual memory
	mem_avail = checkEnoughPhyMem(num_pages, freePagesList) && checkEnoughVirMem(num_pages, proc);
	if (mem_avail) {
		/* We could allocate new memory region to the process */
		ret_mem = proc->bp;
		proc->bp += num_pages * PAGE_SIZE;
		/* Update status of physical pages which will be allocated
		 * to [proc] in _mem_stat. Tasks to do:
		 * 	- Update [proc], [index], and [next] field
		 * 	- Add entries to segment table page tables of [proc]
		 * 	  to ensure accesses to allocated memory slot is
		 * 	  valid. */
		
		// Update the physical pages will be used 
		for(uint32_t i = 0; i < num_pages; i++) {
			int order = freePagesList[i]; // Get the index of _mem_stat from the freePagesList updated by checkEnoughPhyMem
			_mem_stat[order].proc = proc->pid; // Update the pid
			_mem_stat[order].index = i; // Update the index
			if(i == num_pages - 1) _mem_stat[order].next = -1; // Update 'next' for the last page
			else _mem_stat[order].next = freePagesList[i + 1]; //Updats 'next' for other pages
		}

		// Update the segment table the page tables
		addr_t vPageAdd = ret_mem; // The virtual memory of the first byte need to allocate
		struct seg_table_t * segTable = proc->seg_table; 
		for(int i = 0; i < num_pages; i++) {
			addr_t segIndex = get_first_lv(vPageAdd);
			addr_t pageIndex = get_second_lv(vPageAdd);
			
			// Check if new Page Table should be allocated
			if(vPageAdd == 1024) { // No pages has been used yet
				segTable->size = 1; // Update Segment Table size
				segTable->table[0].v_index = segIndex; // Update the v_index of Segment Table
				segTable->table[0].pages = (struct page_table_t *)malloc(sizeof(struct page_table_t)); // Allocate memory for a new Page Table
				segTable->table[0].pages->size = 0; // Update the Page Table size
			} else if(segTable->table[segTable->size - 1].pages->size == 32) { // All previous Page Tables are fully used
				segTable->size += 1; // Update Segment Table size
				segTable->table[segTable->size - 1].v_index = segIndex; //Update the v_index of Segment Table
				segTable->table[segTable->size - 1].pages = (struct page_table_t *)malloc(sizeof(struct page_table_t)); // Allocate memory for a new Page Table
				segTable->table[segTable->size - 1].pages->size = 0; // Update the Page Table size
			}

			// Update the Page newly used
			struct page_table_t * pageTable = get_page_table(segTable->size - 1, segTable);
			pageTable->size += 1; // Update the Page Table size
			pageTable->table[pageTable->size - 1].v_index = pageIndex; // Update the Page v_index
			pageTable->table[pageTable->size - 1].p_index = freePagesList[i]; // Update the Page p_index
			vPageAdd += PAGE_SIZE; // Update the virtual memory
		}
	}
	
	pthread_mutex_unlock(&mem_lock);
	return ret_mem;
}

int free_mem(addr_t address, struct pcb_t * proc) {
	/*TODO: Release memor y region allocated by [proc]. The first byte of
	 * this region is indicated by [address]. Task to do:
	 * 	- Set flag [proc] of physical page use by the memory block
	 * 	  back to zero to indicate that it is free.
	 * 	- Remove unused entries in segment table and page tables of
	 * 	  the process [proc].
	 * 	- Remember to use lock to protect the memory from other
	 * 	  processes.  */
	pthread_mutex_lock(&mem_lock);

	struct seg_table_t * segTable = proc->seg_table;
	
	addr_t pAdd; // Physical Address to check if it needs be freed or not
	int totalDelPage = 1; // Number of pages need to be freed
	if(translate(address, &pAdd, proc)) {
		int pAddIndex = pAdd >> OFFSET_LEN; // Index of '_mem_stat'
		while(_mem_stat[pAddIndex].next != -1) { // check if no more pages need to be freed
			totalDelPage += 1; // Update 'totalDelPage'
			_mem_stat[pAddIndex].proc = 0; // Update the matched frame 'proc'
			_mem_stat[pAddIndex].index = 0; //Update the matched frame 'index'
			addr_t temp = _mem_stat[pAddIndex].next; // The next index to examine
			_mem_stat[pAddIndex].next = 0; //Update the matched frame 'next'
			pAddIndex = temp; // // Update pAddIndex to next index to examine
		}
		_mem_stat[pAddIndex].proc = 0; // Update the last frame 'proc'
		_mem_stat[pAddIndex].index = 0; // Update the last frame 'index'
		_mem_stat[pAddIndex].next = 0; // Update the last frame 'next'
	}


	//free the pages and shift other pages to create contiguous entries of Segment Table and Page Tables
	int addAfterFree = (address) + PAGE_SIZE * totalDelPage; //Virtual address of the first byte right after bytes need to be freed
	addr_t afterSegmentIndex = get_first_lv(addAfterFree); // Segment Table index of 'addAfterFree'
	addr_t afterPageIndex = get_second_lv(addAfterFree); // Page Table index of 'addAfterFree'
	addr_t firstSegmentIndex = get_first_lv(address); // Segment Table index of 'address'
	addr_t firstPageIndex = get_second_lv(address); // Page Table index of 'address'
	addr_t pcSegmentIndex = get_first_lv(proc->bp); // Segment Table index of breakpoint
	addr_t pcPageIndex = get_second_lv(proc->bp); // Segment Table index of breakpoint
	
	addr_t tempfs = firstSegmentIndex; // 'tempfs' indicates Segment Table index of 'address'
	addr_t tempfp = firstPageIndex; // 'tempfp' indicates Page Table index of 'address'
	addr_t tempas = afterSegmentIndex; // 'tempas' indicates Segment Table index of 'addAfterFree'
	addr_t tempap = afterPageIndex; // 'tempap' indicates Page Table index of 'addAfterFree'

	// The number of pages need to shifted
	int toShiftPageNum = 32 * (pcSegmentIndex - afterSegmentIndex) - afterPageIndex + pcPageIndex; 
	
	for(int i = 0; i < toShiftPageNum; i++) {
		if(tempap == 0) { // If the page after the last freed page is the last of a full Page Table
			tempap = 32; // Update 'tempap' to easily later access
			tempas -= 1; // Update 'tempas' to easily later access
		} 
		if(tempfp == 0) { // If first freed page is the last of a full Page Table
			tempfp = 32; // Update 'tempfp' to easily later access
			tempfs -= 1; // Update 'tempfs' to easily later access
		} 

		// Replace the 'p_index' of the first freed Page by 'p_index' of the page after freed to shift and free pages at the same time
		get_page_table(tempfs, segTable)->table[tempfp-1].p_index = get_page_table(tempas, segTable)->table[tempap-1].p_index;
		
		// Update the tempap and tempas after shifting one page to the next page need to be shifted
		if(tempap == 32) { // If the 'tempap' is the last page of a full Page Table
			tempap = 1; // Update the Page index to the next page to be shifted
			tempas += 1; // Update the Segment index to the next page to be shifted
		} else {
			tempap += 1; // If not only update the Page index to the next page to be replaced
		}  
		// Update the tempfp and tempfs after shifting one page to the next page to be replaced
		if(tempfp == 32) { // If the 'tempfp' is the last page of a full Page Table
			get_page_table(tempfs, segTable)->size = 32;
			tempfp = 1; // Update the Page index to the next page to be replaced
			tempfs += 1; // Update the Segment index to the next page to be replaced
		} else {
			tempfp += 1; // If not only update the Page index to the next page to be replaced
		}
	}
		
	if(tempfp != 1) { // If 'tempfp' is not the first page of a Page Table
		segTable->size = tempfs + 1; // Update the Segment Table size
		get_page_table(tempfs, segTable)->size = (tempfp == 0 || tempfs == 32) ? 32 : tempfp - 1; // Update the last Page Table size
	} else { // If 'tempfp' is the first page of a Page Table
		segTable->size = tempfs; // Update the Segment Table size
	}
	addr_t tempps = pcSegmentIndex;
	while(tempps > tempfs) {
		free(get_page_table(tempps, segTable));
		tempps -= 1;
	} // Free empty Segment Table
	if (addAfterFree < proc->bp) {
        for (int i = 0; i < 10; i++) {
            if (proc->regs[i] >= addAfterFree && proc->regs[i] != 1024) {
                proc->regs[i] -= totalDelPage * PAGE_SIZE;
            }
        }
    } // Update the resgisters' addresses

    //Updating the proccess's break pointer
    proc->bp -= totalDelPage * PAGE_SIZE;


	pthread_mutex_unlock(&mem_lock);
	return 0;
}

int read_mem(addr_t address, struct pcb_t * proc, BYTE * data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		*data = _ram[physical_addr];
		return 0;
	}else{
		return 1;
	}
}

int write_mem(addr_t address, struct pcb_t * proc, BYTE data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		_ram[physical_addr] = data;
		return 0;
	 }else {
		return 1;
	}
}

void dump(void) {
	int i;
	for (i = 0; i < NUM_PAGES; i++) {
		if (_mem_stat[i].proc != 0) {
			printf("%03d: ", i);
			printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
				i << OFFSET_LEN,
				((i + 1) << OFFSET_LEN) - 1,
				_mem_stat[i].proc,
				_mem_stat[i].index,
				_mem_stat[i].next
			);
			int j;
			for (	j = i << OFFSET_LEN;
				j < ((i+1) << OFFSET_LEN) - 1;
				j++) {
				
				if (_ram[j] != 0) {
					printf("\t%05x: %02x\n", j, _ram[j]);
				}
					
			}
		}
	}
}


