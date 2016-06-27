#include "userprog/syscall.h"
#include "userprog/process.h"

#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
// #include <user/syscall.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#include "filesys/file.h"

#include "devices/shutdown.h"

// vm
#include "vm/page.h"


#define ARG0 (*(esp + 1))
#define ARG1 (*(esp + 2))
#define ARG2 (*(esp + 3))
#define ARG3 (*(esp + 4))
#define ARG4 (*(esp + 5))
#define ARG5 (*(esp + 6))


static void syscall_handler (struct intr_frame *);
bool add_to_mmap_file_list(struct s_page_table_entry * );


void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct file *get_file(int fd)
{
  struct list_elem *e;
  struct file_descriptor *file_d;
  struct thread *cur = thread_current();
  for (e = list_tail (&cur->files); e != list_head (&cur->files); e = list_prev (e))
    {
      file_d = list_entry (e, struct file_descriptor, elem);
      if (file_d->fd == fd) 
        return file_d->file;   
    }
  return NULL;
}

bool not_valid(const void *pointer)
{
  return (!is_user_vaddr(pointer) || pointer == NULL || pagedir_get_page (thread_current ()->pagedir, pointer) == NULL);
}

void 
halt (void)
{
  shutdown_power_off();
}


void 
exit (int status)
{	
  thread_current ()->proc->exit = status;
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  if (not_valid(cmd_line))
    exit (-1);
  return process_execute(cmd_line); 
}

int 
wait (pid_t pid)
{
  return process_wait (pid);
}

bool
create(const char *file, unsigned initial_size)
{
  if (not_valid(file))
    exit (-1);

  lock_acquire(&file_lock);
  bool result = filesys_create (file, initial_size);
  lock_release(&file_lock);
  return result;
}

bool
remove (const char *file)
{
  if (not_valid(file))
    exit (-1);

  lock_acquire(&file_lock);
  /* In case the file is opened. First check its existence. */
  struct file *f = filesys_open (file);
  bool result;
  if (f == NULL)
    result = false;
  else
    {
      file_close (f);
      result = filesys_remove (file);
    }
  lock_release(&file_lock);
  return result;
}

int 
open (const char *file)
{
  if (not_valid(file))
    exit (-1);

  lock_acquire(&file_lock);
  struct file_descriptor *file_d = malloc(sizeof(struct file_descriptor));
  struct file *f = filesys_open(file);
  struct thread *cur = thread_current();
  if (f == NULL)
    {
      lock_release(&file_lock);
      return -1;
    }
  file_d->file = f;
  file_d->fd = cur->fd;
  cur->fd = cur->fd + 1;
  list_push_back(&thread_current()->files,&file_d->elem);
  lock_release(&file_lock);
  return file_d->fd;
}

int
filesize (int fd)
{
  lock_acquire(&file_lock);
  struct file *file = get_file(fd);
  int result = file ? file_length(file) : -1;
  lock_release(&file_lock);
  return result;
}

int 
read (int fd, void *buffer, unsigned size, uint32_t *esp)
{
  if (fd == STDOUT_FILENO)
  {
    exit (-1);
  }

  // validate buffer and size
  validate_sys_read_buffer(buffer, size);

  lock_acquire(&file_lock);
  int count = 0, result = 0;

  void *buffer_rd = pg_round_down(buffer);
  void *buffer_page;

  unsigned readsize = (unsigned) (buffer_rd + PGSIZE - buffer);
  unsigned bytes_read = 0;
  bool read = true;

  for (buffer_page = buffer_rd; buffer_page <= buffer+size; buffer_page += PGSIZE){
      struct s_page_table_entry *spte = get_s_pt_entry(buffer_page);
      if (!spte) {
        grow_stack_one_page(buffer_page);
        count++;
      }
  }

  struct file *file = get_file(fd);

  if (file == NULL) {
    exit(-1);
  }

  if (fd == STDIN_FILENO)
  {
    while (count < size)
      {
        *((uint8_t *) (buffer + count)) = input_getc ();
        count++;
      }
    result = size;
  }
  else if (buffer_rd == USER_VADDR_BOTTOM) 
  {
      exit (-1);
  } 
  else if (size <= readsize)
  {

    result = file_read(file, buffer, size);
  }
  else 
 {
    while (read) 
    {
      bytes_read= file_read(file, buffer, readsize);
      
      //couldn't read all the bytes
      if(bytes_read != readsize) 
      {
        read = false;
      }

      size -= bytes_read;
    
      if(size == 0)
      { 
        read = false;
      } 
      else 
      {
        buffer += bytes_read;
        if (size >= PGSIZE) readsize = PGSIZE;
        else readsize = size;
      }
      
      result+=bytes_read;
    }
  }
  lock_release(&file_lock);

  return result;
}

int 
write (int fd, const void *buffer, unsigned size)
{
  if (not_valid(buffer) || not_valid(buffer+size) || fd == STDIN_FILENO)
  {
    exit (-1);
  }
  if (!lock_held_by_current_thread (&file_lock))
  {
    lock_acquire(&file_lock);
  }

  int result = 0;
  if (fd == STDOUT_FILENO)
  {
      putbuf (buffer, size);
      result = size;
  }
  else 
  {
    struct file * file = get_file(fd);
    result = file ? file_write(file, buffer, size) : -1;

    if(result == 0)
    {
      file_seek(file, 0);
      result = file_write(file, buffer, size);
    }
    
  }
  lock_release(&file_lock); 
  return result;
}

void 
seek (int fd, unsigned position)
{
  if (!lock_held_by_current_thread (&file_lock))
  {
    lock_acquire(&file_lock);
  }
  struct file *file = get_file(fd);
  if (file == NULL)
  {
    exit (-1);
  }
  file_seek(file,position);
  lock_release(&file_lock);
}

unsigned 
tell (int fd)
{
  lock_acquire(&file_lock);
  struct file *file = get_file(fd);
  int result = file ? file_tell(file) : 0;  
  lock_release(&file_lock);
  return result;
}

void 
close (int fd)
{
  lock_acquire(&file_lock);
  struct list_elem *e;
  struct file_descriptor *file_d;  
  struct thread *cur;
  cur = thread_current ();

  for (e = list_begin (&cur->files); e != list_tail (&cur->files); e = list_next (e))
  {
    file_d = list_entry (e, struct file_descriptor, elem);
    if (file_d->fd == fd)
    {
      //jxw remove mmap
      struct file* file = get_file(fd);
      struct list * s_page_table = &cur->s_page_table;
      struct list_elem * e;
      for(e = list_begin(s_page_table); e != list_end(s_page_table);
      e = list_next(e))
      {
        struct s_page_table_entry * spte = list_entry(e, struct s_page_table_entry, elem);
        if(spte->file == file)
        {
          load_page_of_mmap (spte);
        }
      }
      file_close (file_d->file);
      list_remove (&file_d->elem);
      free (file_d);
      break;
    }
  }
  lock_release(&file_lock);
}



mapid_t 
mmap (int fd, void * upage)
{
  //check if fd and uaddr legal
  if(fd == 0 || fd == 1 || upage == NULL) return -1;

  if((int) upage % PGSIZE != 0) return -1;

  if(!is_user_vaddr(upage)) return -1;

  lock_acquire(&file_lock);

  //check if file already opened
  struct file * f = get_file(fd);
  if (f == NULL) 
  {
    lock_release(&file_lock);
    return -1;
  }

  //check if file length legal
  off_t length_of_file = file_length (f);
  if (length_of_file <= 0) 
  {
    lock_release(&file_lock);
    return -1;
  }
  lock_release(&file_lock);

  //check if all pages not occupied
  int num_of_page = length_of_file / PGSIZE + 1;

  int i;
  for(i = 0; i < num_of_page; i++)
  {
    void * this_page = upage + PGSIZE * i;
    if(get_s_pt_entry(this_page) != NULL) 
    {
      return -1;
    }
  }

  //get current mapid
  thread_current()->map_id++;
  mapid_t id = thread_current()->map_id;

  off_t offset = 0;
  uint32_t read_bytes = length_of_file;

  while (read_bytes > 0)
  {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    struct s_page_table_entry * s_pt_entry = malloc(sizeof(struct s_page_table_entry));
    if (s_pt_entry == NULL) {
      return -1;
    }

    s_pt_entry->file = f;
    s_pt_entry->offset = offset;
    s_pt_entry->upage = upage;
    s_pt_entry->read_bytes = page_read_bytes;
    s_pt_entry->zero_bytes = page_zero_bytes;
    s_pt_entry->writable = true;
    s_pt_entry->type = PAGE_MMAP;
    s_pt_entry->is_in_memory = false;
    s_pt_entry->owner = thread_current();
    struct list * s_page_table = &thread_current()->s_page_table;
    struct lock * s_page_table_lock = &thread_current()->s_page_table_lock;

    // add entry
    lock_acquire(s_page_table_lock);
    list_push_back(s_page_table, &s_pt_entry->elem);
    lock_release(s_page_table_lock);

    if(add_to_mmap_file_list(s_pt_entry) == false)
    {
      //unmap
      munmap(id);
      return -1;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    upage += PGSIZE;
    offset += PGSIZE;
  }

  return id;
}

/*
Add a s_pt_entry into mmap_file_list
*/
bool 
add_to_mmap_file_list(struct s_page_table_entry * s_pt_entry)
{
  struct map_item * item = malloc(sizeof(struct map_item));
  if(item == NULL) return false;
  struct thread * t = thread_current();
  item->s_pt_entry = s_pt_entry;
  item->map_id = t->map_id;
  list_push_back(&t->mmap_file_list, &item->elem);
  return true;
}

void munmap(mapid_t mapping)
{

  if(mapping <= 0) return;

  struct list * map_list = &(thread_current()->mmap_file_list);
  struct list_elem * e = list_begin(map_list);

  for(e = list_begin(map_list); e != list_end(map_list); e = e)
  {
    struct map_item * item = list_entry(e, struct map_item, elem);

    if(item->map_id == mapping)
    {
      
      struct s_page_table_entry * s_pt_entry = item->s_pt_entry;
      file_seek(s_pt_entry->file, 0);

      if ( pagedir_is_dirty(thread_current()->pagedir, s_pt_entry->upage)) 
      {
        uint32_t bytes_written =  file_write_at(s_pt_entry->file, s_pt_entry->upage, s_pt_entry->read_bytes, s_pt_entry->offset);
      }

      s_page_table_entry_clear(s_pt_entry);

      e = list_remove(&item->elem);
      free(item);
    }
    else 
    {
      e = list_next(e);
    }

  }

  thread_current()->map_id--;
}


static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t *esp = f->esp;
  if (not_valid(esp))
    exit (-1);
  switch (*esp)
    {
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        if (not_valid(esp+1)) exit(-1);
        exit ((int) ARG0);
        break;
      case SYS_EXEC:
        f->eax = exec ((const char *) ARG0);
        break;
      case SYS_WAIT:
        f->eax = wait ((pid_t) ARG0);
        break;
      case SYS_CREATE:
        f->eax = create ((const char *) ARG0, (unsigned) ARG1);
        break;
      case SYS_REMOVE:
        f->eax = remove ((const char *) ARG0);
        break;
      case SYS_OPEN:
        f->eax = open ((const char *) ARG0);
        break;
      case SYS_FILESIZE:
        f->eax = filesize ((int) ARG0);
        break;
      case SYS_READ:
        f->eax = read ((int) ARG0, (void *) ARG1, (unsigned) ARG2 , *esp);
        break;
      case SYS_WRITE:
        f->eax = write ((int) ARG0, (void *) ARG1, (unsigned) ARG2);
        break;
      case SYS_SEEK:
        seek ((int) ARG0, (unsigned) ARG1);
        break;
      case SYS_TELL:
        f->eax = tell ((int) ARG0);
        break;
      case SYS_CLOSE:
        close ((int) ARG0);
        break;

      // vm
      case SYS_MMAP:
        f->eax = mmap ((int) ARG0, (void *) ARG1);
        break;
      case SYS_MUNMAP:
        munmap((mapid_t) ARG0);
        break;

      default:
        printf ("Invalid syscall!\n");
        thread_exit();
    }
}


