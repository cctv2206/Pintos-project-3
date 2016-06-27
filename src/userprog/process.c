#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
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


#include "vm/frame.h"
#include "vm/page.h"


const uint8_t *USER_STACK_VADDR = (uint8_t *) PHYS_BASE - PGSIZE;
static thread_func start_process NO_RETURN;
static bool load (struct args_struct *args, void (**eip) (void), void **esp);
static pid_t allocate_pid (void);
static void argument_tokenize (struct args_struct *args);
static bool push_args_to_stack (struct args_struct *args, void **esp);
static bool push_byte_to_stack (uint8_t val, void **esp);
static bool push_word_to_stack (uint32_t val, void **esp);
bool install_page (void *upage, void *kpage, bool writable);
struct process *get_child (pid_t pid);

/* Returns child of current thread with given PID or NULL If non exists. */
struct process *get_child (pid_t pid)
{
  struct list_elem *e;
  struct process *child;
  struct thread *cur = thread_current ();
  for (e = list_tail (&cur->children); e != list_head (&cur->children); e = list_prev (e))
    {
      child = list_entry (e, struct process, elem);
      if (child->pid == pid)
        return child;
    }
  return NULL;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *args) 
{
  struct args_struct *args_struct_ptr;
  tid_t tid = TID_ERROR;
  struct process *child;

  /* Make a copy of the arguments.
     Otherwise there's a race between the caller and load(). */
  args_struct_ptr = palloc_get_page (0);

  if (args_struct_ptr == NULL)
    return TID_ERROR;
  strlcpy (args_struct_ptr->args, args, ARGS_SIZE);

  /* Tokenize arguments. */
  argument_tokenize (args_struct_ptr);
  if (args_struct_ptr->argc == BAD_ARGS)
    {
      palloc_free_page (args_struct_ptr);
      return TID_ERROR;
    }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args_struct_ptr->argv[0], PRI_DEFAULT, start_process, args_struct_ptr);

  /* If a thread was created wait for process to begin or fail. */
  if (tid != TID_ERROR)
    {
      child = get_child ((pid_t) tid);
      sema_down (&child->sema);
      if (child->status == PROCESS_FAIL)
        {
          list_remove (&child->elem);
          free (child);
          return TID_ERROR;
        }
    }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *args_)
{
  struct args_struct *args = (struct args_struct *) args_;
  struct intr_frame if_;
  bool success = false;
  struct process *p;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (args, &if_.eip, &if_.esp);
  
  /* If successful signal waiting parent, else quit. */
  palloc_free_page (args);
  p = thread_current ()->proc;
  if (success)
    sema_up (&p->sema);
  else
    {
      p->status = PROCESS_FAIL;
      thread_exit ();
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  pid_t pid = (pid_t) child_tid;
  struct process *child;
  int exit;

  /* Find child process with matching PID. */
  child = get_child (pid);

  /* Return -1 immediately if no such child exists. */
  if (child == NULL)
    return -1;

  /* Wait for process to exit and return value. */
  sema_down (&child->sema);
  exit = child->exit;
  list_remove (&child->elem);
  free (child);
  return exit;
}

/* Free the current process's resources and signal its parent if it exists. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  struct process *p;
  struct process *child;
  struct file_descriptor *file_d;
  struct list_elem *e;
  uint32_t *pd;
  int exit;

  // clear mmap
  while (cur->map_id != 0) {
    munmap(cur->map_id);
  }


  /* Remove open file descriptors. */
  while (!list_empty (&cur->files))
  {
    e = list_pop_front (&cur->files);
    file_d = list_entry (e, struct file_descriptor, elem);
    file_close (file_d->file);
    free (file_d);
  }

  //clear tables!  
  clear_s_page_table_of_cur_thread();

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Let the children of the process that they're now orphaned so they
     will clean up when they exit. */
  for (e = list_end (&cur->children);e != list_begin (&cur->children);e = list_prev (e))
    {
      child = list_entry (e, struct process, elem);
      lock_acquire (&child->status_lock);
      if (child->status != PROCESS_RUN)
        free (child);
      else 
         child->status = PROCESS_ORPHAN;
      lock_release (&child->status_lock);
    }

  /* Signal that we've exited to a waiting parent if there is one else
     clean up our process information. Also print an exit message. */
  p = cur->proc;
  if (p != NULL)
    {
      lock_acquire (&p->status_lock);
      exit = p->exit;
      if (p->status == PROCESS_RUN) 
        p->status = PROCESS_DEAD;
      else
      if (p->status == PROCESS_ORPHAN)
        {
          free(p);
          p = NULL;
        }
      lock_release (&p->status_lock);
      if (p != NULL)
        sema_up (&p->sema);
      printf ("%s: exit(%d)\n", cur->name, exit);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool validate_segment (const struct Elf32_Phdr *, struct file *);

static bool load_file_to_page_table (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
static bool setup_stack_in_s_page_table(struct args_struct *args, void **esp);


/* Loads an ELF executable from ARGS into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct args_struct *args_struct_ptr, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  struct file_descriptor *file_d;
  off_t file_ofs;
  bool success = false;
  char *fn = args_struct_ptr->argv[0];
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();

  if (t->pagedir == NULL) 
    return success; // false
  process_activate ();

  /* Open executable file. */
  file = filesys_open (fn);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", fn);
      file_close (file);
      return success; 
    }
  else
    {
      file_deny_write (file);
      file_d = malloc (sizeof (struct file_descriptor));
      if (file_d == NULL)
        {
          file_close (file);
          return success;
        }
      file_d->file = file;
      file_d->fd = t->fd;
      t->fd = t->fd + 1;
      list_push_back (&t->files, &file_d->elem);
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", fn);
      return success;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        return success;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        return success;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          return success;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_file_to_page_table (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                return success;
            }
          else
            return success;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack_in_s_page_table (args_struct_ptr, esp))
    return success;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* If we reached here startup was successful. */
  return true;
}

// argument_tokenize is for parsing the filename into different tokens.
static void
argument_tokenize (struct args_struct *args_struct_ptr)
{
  int argc_value = 0;
  char *token, *save_ptr;
  char **arg_variable = args_struct_ptr->argv;
  for (token = strtok_r (args_struct_ptr->args, ARGS_DELI, &save_ptr); token != NULL; token = strtok_r (NULL, ARGS_DELI, &save_ptr))
    {
    //Check the count of the arguments cannot equal or larger than the THRESHOLD of the argument variables size
    //Return the argc_value to -1
      if (argc_value == ARGV_SIZE)
        {
          argc_value = BAD_ARGS;
          break;
        }
      arg_variable[argc_value++] = token;
    }
  //Return the argc with the arguments number, or -1 if the arguments are too many 
  args_struct_ptr->argc = argc_value;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}


/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_file_to_page_table (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);


  // create one s_page_table_entry for every loop until done
  while (read_bytes > 0 || zero_bytes > 0) {

    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct s_page_table_entry * s_pt_entry = malloc(sizeof(struct s_page_table_entry));
    
    if (s_pt_entry == NULL) {
      return false;
    }

    s_pt_entry->file = file;
    s_pt_entry->offset = ofs;
    s_pt_entry->upage = upage;
    s_pt_entry->read_bytes = page_read_bytes;
    s_pt_entry->zero_bytes = page_zero_bytes;
    s_pt_entry->writable = writable;
    s_pt_entry->is_in_memory = false;
    s_pt_entry->owner = thread_current();
    s_pt_entry->type = PAGE_CODE;
    s_pt_entry->pinning = false;

    struct list * s_page_table = &thread_current()->s_page_table;
    struct lock * s_page_table_lock = &thread_current()->s_page_table_lock;

    // add entry
    lock_acquire(s_page_table_lock);
    list_push_back(s_page_table, &s_pt_entry->elem);
    lock_release(s_page_table_lock);

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
    ofs += PGSIZE;
  } // end while

  file_seek (file, ofs);

  return true;
}

// setup the stack and push the args into the stack
static bool
setup_stack_in_s_page_table (struct args_struct *args_struct_ptr, void **esp) 
{
  void * upage = ((uint8_t *) PHYS_BASE) - PGSIZE;

  bool grow_stack_success = grow_stack_one_page(upage);

  if (grow_stack_success) 
  {
    *esp = PHYS_BASE;
  } else {
    return false;
  }

  // push argument into this stack
  bool push_args_success = push_args_to_stack(args_struct_ptr, esp);

  if (push_args_success == NULL)
  {
    return false;
  }

  return true;
}


/* Push arguments into the stack. */
static bool
push_args_to_stack (struct args_struct *args_struct_ptr, void **esp)
{
  char **argv;
  int argc, i, j;
  size_t len;

  /* Get arguments and argument count. */
  argv = args_struct_ptr->argv;
  argc = args_struct_ptr->argc;

  /* Place arguments into stack. */
  for (i = argc - 1; i >= 0; i--)
    {
      len = strlen (argv[i]);
      for (j = len; j >= 0; j--)
        if (!push_byte_to_stack ((uint8_t) argv[i][j], esp))
          return false;
      argv[i] = *esp;
    }

  /* Word align the stack. */
  for (i = (uintptr_t) *esp % sizeof (uint32_t); i > 0; i--)
    if (!push_byte_to_stack (NULL, esp))
      return false;
  
  /* Place pointers to arguments onto stack. */
  if (!push_word_to_stack (NULL, esp))
    return false;
  for (i = argc - 1; i >= 0; i--)
    if (!push_word_to_stack ((uint32_t) argv[i], esp))
      return false;
  argv = *esp;

  /* Place argv, argc and dummy return pointer ont stack. */
  return push_word_to_stack ((uint32_t) argv, esp) && push_word_to_stack ((uint32_t) argc, esp) && push_word_to_stack (NULL, esp);
}

/* Push a byte of data onto the stack. */
static bool
push_byte_to_stack (uint8_t val, void **esp)
{
  *esp -= sizeof(uint8_t);
  if (*esp < USER_STACK_VADDR)
    return false;
  *((uint8_t *) (*esp)) = val;
  return true;
}

/* Push a word of data onto the stack. */
static bool
push_word_to_stack (uint32_t val, void **esp)
{
  *esp -= sizeof(uint32_t);
  if (*esp < USER_STACK_VADDR)
    return false;
  *((uint32_t *) (*esp)) = val;
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

