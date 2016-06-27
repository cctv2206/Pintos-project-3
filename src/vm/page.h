#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "vm/frame.h"

#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

#define MAX_STACK_SIZE (1 << 23)
#define STACK_INDICATOR 0xbfff7f80

// page types
#define PAGE_CODE 1
#define PAGE_IN_SWAP 2
#define PAGE_MMAP 3
#define PAGE_STACK 4
#define PAGE_FILE 5

struct s_page_table_entry
{
	// list
	struct list_elem elem;

	// for load_file_to_page_table
	struct file * file;
	off_t offset;
	void * upage;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;
	bool is_in_memory;

	struct thread * owner;

	size_t swap_index;

	// type
	uint8_t type;

	bool pinning;

};


void s_page_table_clear(struct thread*t);


struct s_page_table_entry * get_s_pt_entry(void * );
bool load_page_in_s_page_table(struct s_page_table_entry * );
bool load_page_from_swap (struct s_page_table_entry * );
struct s_page_table_entry * frame_table_entry_to_s_pt_entry(struct frame_table_entry * ); 

void s_page_table_entry_clear_by_file(struct file * );
bool grow_stack_one_page(void *);

void validate_sys_read_buffer(void *, unsigned );


#endif /* vm/page.h */