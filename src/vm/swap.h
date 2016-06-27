#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include <list.h>

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

#define FREE_SWAP_SLOT 0
#define USED_SWAP_SLOT 1

#define UNAVAILABLE -100

struct lock swap_lock;

struct block * swap_block;


//swap list
struct list swap_list;

static bool swap_initialization = false;

//swap entry
struct swap_item {
	struct list_elem elem;
	bool available;
	size_t index;
};

void swap_init (void );
struct swap_item * get_swap_item_at_index( size_t );
size_t swap_out_of_memory (void *);
void swap_into_memory (size_t , void * );

#endif // vm/swap.h