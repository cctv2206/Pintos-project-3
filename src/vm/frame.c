#include "vm/frame.h"
#include <stdlib.h>

#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "vm/swap.h"


// frame table initialization
void frame_table_init (void)
{
	// only init once
	if (frame_initialization == true)
	{
		return;
	}
	frame_initialization = true;

	list_init(&frame_table_list);
	lock_init(&frame_table_lock);
	lock_init(&eviction_lock);
}



/*
Returns the new page directory, or a null pointer if memory
allocation fails.
*/
void *
frame_allocate (enum palloc_flags flag) {

	uint8_t * pd = palloc_get_page(flag);

	if (pd != NULL) { // palloc success

		// add a new frame table entry
		struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
		fte->page = pd;
		fte->owner = thread_current();

		if (!lock_held_by_current_thread(&frame_table_lock)) {
			lock_acquire(&frame_table_lock);
		}
		
		list_push_back(&frame_table_list, &fte->elem);
		lock_release(&frame_table_lock);

	} else { // palloc faild, need to evict a frame

		// try to evict a page
		bool evict_success = evict();

		if (evict_success) { // setup this new frame
			pd = palloc_get_page(flag);
			struct frame_table_entry *fte = malloc(sizeof(struct frame_table_entry));
			fte->page = pd;
			fte->owner = thread_current();
			if (!lock_held_by_current_thread(&frame_table_lock)) {
			lock_acquire(&frame_table_lock);
			}
			list_push_back(&frame_table_list, &fte->elem);
			lock_release(&frame_table_lock);
		} else {
			PANIC ("Frame could not be evicted!");
		}
		
	}
	return pd;
}

// free this frame
void frame_free_page(void * some_page)
{
	struct frame_table_entry * frame_to_free = frame_find_page(some_page);

	if (!lock_held_by_current_thread(&frame_table_lock)) {
		lock_acquire(&frame_table_lock);
	}
	if (frame_to_free != NULL) { // found the frame
		list_remove(&frame_to_free->elem);
		palloc_free_page(frame_to_free->page);
	}
	lock_release(&frame_table_lock);
}

// find the frame in frame list
struct frame_table_entry * 
frame_find_page(void * some_page)
{
	struct list_elem * e;

	for (e = list_begin(&frame_table_list); e != list_end(&frame_table_list);
			e = list_next(e))
	{
		struct frame_table_entry *fte = list_entry(e, struct frame_table_entry, elem);
		if (fte->page == some_page)
		{
			return fte;
		}
	}
	return NULL;
}


// evict a page
bool
evict() {

	bool eviction_success = false;

	// find the victim
	struct frame_table_entry * victim_frame;
	victim_frame = choose_a_victim();

	// locate the s_page_table_entry
	struct s_page_table_entry * victim_s_pt_entry = frame_table_entry_to_s_pt_entry(victim_frame);

	// make sure the victim is not pinning
	while (victim_s_pt_entry->pinning == true) {
		victim_frame = choose_a_victim();
		victim_s_pt_entry = frame_table_entry_to_s_pt_entry(victim_frame);
	}

	// make sure the victim is good
	if (victim_s_pt_entry == NULL) {
		PANIC("The frame is not mapped to any upage!");
	}

	victim_s_pt_entry->pinning = true;
	struct thread * owner_thread = victim_frame->owner;

	// swap out
	size_t index;

	index = swap_out_of_memory (victim_s_pt_entry->upage);

	// remove reference
	pagedir_clear_page(owner_thread->pagedir, victim_s_pt_entry->upage);

	// free the victim
	list_remove(&victim_frame->elem);
	palloc_free_page(victim_frame->page);

	// update the s_page_table
	victim_s_pt_entry->is_in_memory = false;
	victim_s_pt_entry->type = PAGE_IN_SWAP;
	victim_s_pt_entry->swap_index = index;
	victim_s_pt_entry->pinning = false;

	// success	
	return true;
}

/*
find the s_page_table_entry mapped with frame_table_entry
return the s_page_table_entry.
*/
struct s_page_table_entry *
frame_table_entry_to_s_pt_entry(struct frame_table_entry * ft_entry)
{
	struct s_page_table_entry * s_pt_entry;
	struct thread * owner_thread;

	owner_thread = ft_entry->owner;

	struct list * s_page_table = &owner_thread->s_page_table;

	struct list_elem * e;

	for (e = list_begin(s_page_table); e != list_end(s_page_table); e = list_next(e))
	{
		s_pt_entry = list_entry(e, struct s_page_table_entry, elem);
		uint32_t * kpage = pagedir_get_page(owner_thread->pagedir, s_pt_entry->upage);
		if (kpage == ft_entry->page)
		{
			return s_pt_entry;
		}
	}
	return NULL;
}


/*
Return a random frame in the frame list.
=== NOT USED IN THE FINAL VERSION ===
*/
struct frame_table_entry * 
choose_a_victim_random ()
{
	// random number
	int list_length = list_size(&frame_table_list);
	int r = random_ulong() % list_length;
	if (r < 0) {
		r = -r;
	}

	struct frame_table_entry * victim_frame;

	if (!lock_held_by_current_thread(&frame_table_lock)) {
		lock_acquire(&frame_table_lock);
	}

	struct list_elem * e;
	e = list_begin(&frame_table_list);
	while (r > 0) {
		e = list_next(e);
		r--;
	}

	victim_frame = list_entry(e, struct frame_table_entry, elem);

	lock_release(&frame_table_lock);
	return victim_frame;
}


/*
Frame eviction algorithm.
=== USED IN THE FINAL VERSION ===
*/
struct frame_table_entry * 
choose_a_victim()
{
	struct list_elem * e;
	struct frame_table_entry * victim_frame;

	int32_t most_unused_count = 0;
	bool have_candidate = true;
	bool page_is_accessed;
	struct thread * this_thread;

	lock_acquire (&frame_table_lock);

	for (e = list_front (&frame_table_list); e != list_end(&frame_table_list); e = list_next(e)) 
	{
		struct frame_table_entry * ft_entry  = list_entry(e, struct frame_table_entry, elem);

		this_thread = ft_entry->owner;
		
		struct s_page_table_entry * s_pt_entry = frame_table_entry_to_s_pt_entry(ft_entry);

		page_is_accessed = pagedir_is_accessed(this_thread->pagedir, s_pt_entry->upage);

	    if (page_is_accessed) 
	    {
			if (!have_candidate) 
			{
				ft_entry->unused_count = 0;
				break;
			}
	    }
	    else
	    {
	     	ft_entry->unused_count++;
	    }

	    ft_entry->unused_count++;

	    if (ft_entry->unused_count > most_unused_count)
	    {
	      victim_frame = ft_entry;
	      have_candidate = page_is_accessed;  
	      most_unused_count = ft_entry->unused_count;
	    }
	}

	victim_frame->unused_count = 0;
	lock_release(&frame_table_lock);

	return victim_frame;
}


// clear the frame of a thread
void clear_frame_with_owner(struct thread * t)
{
	struct list_elem *e = list_begin (&frame_table_list);
	while(e != list_end (&frame_table_list) && e != NULL)
	{
		struct frame_table_entry * fe = list_entry(e, struct frame_table_entry, elem);
		
		if(fe != NULL && fe->owner == t)
		{
			if (!lock_held_by_current_thread (&frame_table_lock)) 
			{
				lock_acquire(&frame_table_lock);
			}
			e = list_remove (e);
			palloc_free_page(fe->page);
			free(fe);
			lock_release(&frame_table_lock);
			if(e==NULL) break;
		}
		else if(e != NULL && e->next != NULL) 
		{
			e = list_next(e);
		}
		else 
		{
			break;
		}
	}
}

