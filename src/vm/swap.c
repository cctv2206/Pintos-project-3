#include "vm/swap.h"

//initialize swap slots list
void swap_init (void)
{
	// only swap once
	if (swap_initialization) {
		return;
	}
	swap_initialization = true;

	swap_block = block_get_role (BLOCK_SWAP);
	if (!swap_block)
	{
		return;
	}

	list_init(&swap_list);
	lock_init(&swap_lock);

	int i = 0;
	for(i; i<(block_size(swap_block) / SECTORS_PER_PAGE); i++)
	{
		struct swap_item * item  = malloc(sizeof(struct swap_item));
		item->available = true;
		item->index = i+1;
		if(item == NULL) return;
		list_push_back(&swap_list, &item->elem);
	}
	return;
}

//swap out to disk
size_t swap_out_of_memory (void * upage)
{
	swap_init ();
	
	if (swap_block == NULL || &swap_list == NULL)
	{
		return -1;
	}

	lock_acquire(&swap_lock); 
	struct list_elem * e = list_begin(&swap_list);
	
	int index;
	int i;
	for(e; e != list_end(&swap_list); e = list_next(e))
	{
		index++;
		struct swap_item * item = list_entry(e, struct swap_item, elem);
		if(item->available == true)
		{
			item->available = false;
			index = item->index;
			break;
		}
	}

	if(index == list_size(&swap_list)) 
	{
		lock_release(&swap_lock);
		return -1;
	}

	for (i = 0; i < SECTORS_PER_PAGE; i++) 
	{
		block_write (swap_block, index * SECTORS_PER_PAGE + i, (uint8_t *) upage + i * BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
	return index;
}




//get a swap_item by its index
struct swap_item * get_swap_item_at_index(size_t index)
{
	int i = 1;
	if(list_empty(&swap_list)) return NULL;
	struct list_elem * e = list_begin(&swap_list);
	struct swap_item * item;
	for(e; e != list_end(&swap_list); e = list_next(e))
	{
		item = list_entry(e, struct swap_item, elem);
		if(item->index == index)
		break;
	}
	return item;
}

// swap a page from swap slot into memory
void swap_into_memory (size_t used_index, void * upage)
{
	int i;
	lock_acquire(&swap_lock);
	struct swap_item * item = get_swap_item_at_index(used_index);
	
	if (item == NULL || item->available == true)
	{
		lock_release(&swap_lock);
		return;
	}

	item->available = true;

	for (i = 0; i < SECTORS_PER_PAGE; i++) 
	{
		block_read (swap_block, used_index * SECTORS_PER_PAGE + i, (uint8_t *) upage + i * BLOCK_SECTOR_SIZE);
	}
	lock_release(&swap_lock);
}


