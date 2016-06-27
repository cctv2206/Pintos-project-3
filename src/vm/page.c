#include "vm/page.h"

#include "userprog/process.h"
#include "userprog/syscall.h"

extern struct lock file_lock;

// clear s_page_table_entry of a file
void s_page_table_entry_clear_by_file(struct file * file)
{
	if (!lock_held_by_current_thread(&thread_current()->s_page_table_lock)) {
		lock_acquire(&thread_current()->s_page_table_lock);
	}
	struct thread * cur_thread = thread_current();
	struct list * s_page_table = &cur_thread->s_page_table;
	struct list_elem * e;
	for (e = list_begin(s_page_table); e != list_end(s_page_table);
			e = e)
		{
			struct s_page_table_entry * spte = list_entry(e, struct s_page_table_entry, elem);
			if(spte->file == file)
			{
				uint8_t * kpage = pagedir_get_page(thread_current()->pagedir, spte->upage);
				frame_free_page(kpage);
				free(kpage);
				e = list_remove(e);
				free(spte);
			}
			else e = list_next(e);
		}	 	
	lock_release(&thread_current()->s_page_table_lock);	
}

// clear the s_pt_entry and its resources
void s_page_table_entry_clear(struct s_page_table_entry * s_pt_entry)
{

	if (!lock_held_by_current_thread(&thread_current()->s_page_table_lock)) {
		lock_acquire(&thread_current()->s_page_table_lock);
	}
	list_remove (&s_pt_entry->elem);
	lock_release(&thread_current()->s_page_table_lock);

	uint8_t * kpage = pagedir_get_page(thread_current()->pagedir, s_pt_entry->upage);
	pagedir_clear_page (thread_current()->pagedir, s_pt_entry->upage);
	frame_free_page(kpage);
	free (s_pt_entry);
}

// return the s_page_table_entry of a upage
// return NULL if not find
struct s_page_table_entry * 
get_s_pt_entry(void * upage) 
{
	struct thread * cur_thread = thread_current();
	struct list * s_page_table = &cur_thread->s_page_table;

	upage = pg_round_down(upage);

	struct list_elem * e;

	for (e = list_begin(s_page_table); e != list_end(s_page_table);
			e = list_next(e))
	{
		struct s_page_table_entry * s_pt_entry = list_entry(e, struct s_page_table_entry, elem);
		if (s_pt_entry->upage == upage)
		{
			return s_pt_entry;
		}
	}
	return NULL;
}

// load this page
bool 
load_page_in_s_page_table(struct s_page_table_entry * s_pt_entry)
{
	s_pt_entry->pinning = true;

	bool load_success = false;

	enum palloc_flags flags = PAL_USER;
	if (s_pt_entry->read_bytes == 0) {
		flags |= PAL_ZERO;
	}

	uint8_t * new_frame = frame_allocate(flags);

	if (new_frame == NULL) {
		return false;
	}

	/* Load this page. */
	if (s_pt_entry->read_bytes != 0) {
		file_seek(s_pt_entry->file, s_pt_entry->offset);

		if (file_read (s_pt_entry->file, new_frame, s_pt_entry->read_bytes) != (int) s_pt_entry->read_bytes)
		{
		  	palloc_free_page (new_frame);
		  	return false; 
		}
		memset (new_frame + s_pt_entry->read_bytes, 0, s_pt_entry->zero_bytes);

	}

	/* Add the page to the process's address space. */
	if (!install_page (s_pt_entry->upage, new_frame, s_pt_entry->writable)) 
	{
	    palloc_free_page (new_frame);
	    return false; 
	}

	s_pt_entry->is_in_memory = true;
	s_pt_entry->pinning = false;

	return true;
}

// load this page from swap slot
bool
load_page_from_swap (struct s_page_table_entry * s_pt_entry)
{
	bool load_success = false;
	enum palloc_flags flags = PAL_USER;
	uint8_t * new_frame = frame_allocate(flags);

	if (new_frame == NULL) {
		return false;
	}
	
	/* Add the page to the process's address space. */
	if (!install_page (s_pt_entry->upage, new_frame, true)) 
	{
		frame_free_page(new_frame);
	    //palloc_free_page (new_frame);
	    return false; 
	}

	swap_into_memory (s_pt_entry->swap_index, s_pt_entry->upage);

	s_pt_entry->type = PAGE_FILE;

	s_pt_entry->is_in_memory = true;

	return true;
}


// load this page from mmap
bool
load_page_of_mmap (struct s_page_table_entry * s_pt_entry)
{
	bool load_success = false;
	enum palloc_flags flags = PAL_USER|PAL_ZERO;
	void * new_frame = frame_allocate(flags);

	if (new_frame == NULL) {
		return false;
	}

	/* Load this page. */
	file_seek(s_pt_entry->file, s_pt_entry->offset);
	
	if (file_read (s_pt_entry->file, new_frame, s_pt_entry->read_bytes) != (int) s_pt_entry->read_bytes)
    {
      	palloc_free_page (new_frame);
      	return false; 
    }
	memset (new_frame + s_pt_entry->read_bytes, 0, s_pt_entry->zero_bytes);

	/* Add the page to the process's address space. */
	if (!install_page (s_pt_entry->upage, new_frame, s_pt_entry->writable)) 
	{
	    palloc_free_page (new_frame);
	    return false; 
	}

	s_pt_entry->is_in_memory = true;

	return true;
}

// grow one page stack at *upage when needed
bool
grow_stack_one_page (void * upage) 
{

	if ( (size_t) (PHYS_BASE - pg_round_down(upage)) > MAX_STACK_SIZE) {
    	return false;
  	}

	struct s_page_table_entry * s_pt_entry = malloc(sizeof(struct s_page_table_entry));

	if (s_pt_entry == NULL) {
		return false;
	}

	// setup new entry
	s_pt_entry->upage = pg_round_down(upage);
	s_pt_entry->is_in_memory = true; // ???
	s_pt_entry->writable = true;
	s_pt_entry->owner = thread_current ();
	s_pt_entry->type = PAGE_STACK;
	s_pt_entry->pinning = false;

	uint8_t * new_frame = frame_allocate(PAL_USER);

	if (new_frame == NULL) {
		free(s_pt_entry);
		return false;
	}

	bool install_success = install_page(s_pt_entry->upage, new_frame, s_pt_entry->writable);
	if (install_success == false) 
	{
		free(s_pt_entry);
		free(new_frame);
		return false;
	}

	// add new entry to s_page_table
	struct list * s_page_table = &thread_current()->s_page_table;
	struct lock * s_page_table_lock = &thread_current()->s_page_table_lock;

	if (!lock_held_by_current_thread(&thread_current()->s_page_table_lock)) {
		lock_acquire(&thread_current()->s_page_table_lock);
	}
	list_push_back(s_page_table, &s_pt_entry->elem);
	lock_release(s_page_table_lock);

	return true;
}

// check whether the buffer and size is valid in syscall read
void validate_sys_read_buffer(void * buffer, unsigned size)
{
	if (buffer == NULL || !is_user_vaddr(buffer))
	{
		exit(-1);
	}

	if (buffer + size == NULL || !is_user_vaddr(buffer + size))
	{
		exit(-1);
	}

	if(get_s_pt_entry(buffer) == NULL)
	{
		if (buffer != STACK_INDICATOR) {
		  exit(-1);
		}    
	}
}

// check for stack access
bool
is_accessing_stack (void *ptr, uint32_t *esp)
{
  return  ((PHYS_BASE - pg_round_down (ptr)) <= MAX_STACK_SIZE && (uint32_t*)ptr >= (esp - 32));
}

// clear the s_page_table and reference of a thread
void
clear_s_page_table_of_cur_thread()
{
	struct list * s_page_table = &thread_current()->s_page_table;

	struct list_elem * e;
	for (e = list_begin(s_page_table); e != list_end(s_page_table); e = list_next(e))
	{
		struct s_page_table_entry * s_pt_entry = list_entry(e, struct s_page_table_entry, elem);
		
		frame_free_page(pagedir_get_page(thread_current()->pagedir, s_pt_entry->upage));
		pagedir_clear_page(thread_current()->pagedir, s_pt_entry->upage);

	}
}