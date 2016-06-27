#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"
#include <stdbool.h>
#include <stdint.h>


#define USER_VADDR_BOTTOM ((void *) 0x08048000)
#define STACK_HEURISTIC 32

struct lock file_lock;

void syscall_init (void);

#endif /* userprog/syscall.h */
