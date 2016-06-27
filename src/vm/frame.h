#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"

struct list frame_table_list;

struct lock frame_table_lock;

struct lock eviction_lock;

struct frame_table_entry {
	struct thread * owner;
	void * page;
	struct list_elem elem;
	int unused_count;
};

// only init once
static bool frame_initialization = false;

void frame_table_init (void);
void * frame_allocate (enum palloc_flags flags);
bool evict ();
struct frame_table_entry * frame_find_page(void * );
void clear_frame_with_owner (struct thread * );
struct frame_table_entry * choose_a_victim ();
struct frame_table_entry * choose_a_victim_random ();

#endif /* vm/frame.h */