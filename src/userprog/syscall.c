#include "userprog/syscall.h"
#include <kernel/stdio.h>
#include <syscall-nr.h>
#include <debug.h>
#include <stddef.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define WRITE_MAX 256


static void syscall_handler (struct intr_frame *);
int get_int (int *esp);
char* get_char_ptr (char **esp);
void* get_void_ptr (void **esp);
void validate_void_ptr (const void *ptr);
struct file * validate_open_file (int fd);
void halt_wrapper (void);
void exit_wrapper (struct intr_frame *f);
void exec_wrapper (struct intr_frame *f);
void wait_wrapper (struct intr_frame *f);
void create_wrapper (struct intr_frame *f);
void remove_wrapper (struct intr_frame *f);
void open_wrapper (struct intr_frame *f);
void filesize_wrapper (struct intr_frame *f);
void read_wrapper (struct intr_frame *f);
void write_wrapper (struct intr_frame *f);
void seek_wrapper (struct intr_frame *f);
void tell_wrapper (struct intr_frame *f);
void close_wrapper (struct intr_frame *f);
void do_halt (void);
void do_exit (int status);
void do_exec (struct intr_frame *f, const char *cmd_line);
void do_wait (struct intr_frame *f, int pid);
void do_create (struct intr_frame *f, const char *file, unsigned initial_size);
void do_remove (struct intr_frame *f, const char *file);
void do_open (struct intr_frame *f, const char *file);
void do_filesize (struct intr_frame *f, int fd);
void do_read (struct intr_frame *f, int fd, void *buffer, unsigned size);
void do_write (struct intr_frame *f, int fd, const void *buffer, unsigned size);
void do_seek (int fd, unsigned position);
void do_tell (struct intr_frame *f, int fd);
void do_close (int fd);

static struct lock file_sync_lock;

void
syscall_init (void) 
{
  lock_init(&file_sync_lock);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  validate_void_ptr(f->esp);
  int sys_num = get_int((int *)f->esp);

	switch (sys_num) {
    case SYS_EXIT:
      exit_wrapper (f);
      break;

    case SYS_EXEC:
      exec_wrapper(f);
      break;

    case SYS_WAIT:
      wait_wrapper(f);
      break;

    case SYS_HALT:
      halt_wrapper ();
      break;

    case SYS_CREATE:
      create_wrapper (f);
      break;

    case SYS_REMOVE:
      remove_wrapper (f);
      break;

    case SYS_OPEN:
      open_wrapper (f);
      break;

    case SYS_FILESIZE:
      filesize_wrapper (f);
      break;

    case SYS_READ:
      read_wrapper (f);
      break;

    case SYS_WRITE:
      write_wrapper (f);
      break;

    case SYS_SEEK:
      seek_wrapper (f);
      break;

    case SYS_TELL:
      tell_wrapper (f);
      break;

    case SYS_CLOSE:
      close_wrapper (f);
      break;

    default:
      PANIC ("UNDEFINED SYSTEM CALL");
      break;
	}
}


int
get_int(int *esp)
{
  validate_void_ptr(esp+1);
  validate_void_ptr(esp+2);
  validate_void_ptr(esp+3);
  return *esp;
}

char*
get_char_ptr (char **esp)
{
  validate_void_ptr(esp+1);
  validate_void_ptr(esp+2);
  validate_void_ptr(esp+3);
  return *esp;
}

void*
get_void_ptr (void **esp)
{
  validate_void_ptr(esp+1);
  validate_void_ptr(esp+2);
  validate_void_ptr(esp+3);
  return *esp;
}

void
validate_void_ptr (const void *ptr)
{
  if (ptr == NULL || is_kernel_vaddr (ptr))
    do_exit (-1);
  
  void *temp_addr = pagedir_get_page(thread_current()->pagedir, ptr);
	if(temp_addr == NULL)
    do_exit (-1);
}

struct file *
validate_open_file (int fd)
{
  struct list_elem *e;
  struct thread *cur = thread_current ();

  for (e = list_begin (&cur->open_files); e != list_end (&cur->open_files);
       e = list_next (e))
  {
    struct open_file *file = list_entry (e, struct open_file, file_elem);
    if (file->fd == fd)
      return file->ptr;
  }

  return NULL;
}

void
halt_wrapper ()
{
  do_halt ();
}

void
exit_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int status = get_int ((int *) (f->esp+4));
  do_exit (status);
}

/*
// I tried to make it pid_t exec_wrapper(const char *cmd_line), but failed
int exec_wrapper(const char *cmd_line)
{
	char *file_name = (char*)malloc(strlen(cmd_line) + 1);
	strlcpy(file_name, cmd_line, strlen(cmd_line) + 1);
	  
  char *temp_ptr;
  file_name = strtok_r(file_name, " ", &temp_ptr);

  lock_acquire(&file_sync_lock);
  struct file *temp_file = filesys_open(file_name);
  if(temp_file == NULL)
  {
    lock_release(&file_sync_lock);
    return -1;
  }
  else
  {
    file_close(temp_file);
    lock_release(&file_sync_lock);
    return process_execute(cmd_line);
  }
}
 */

void
exec_wrapper (struct intr_frame *f)
{
  validate_void_ptr ((void *) (*((char **)(f->esp+4))));
  char *cmd_line = get_char_ptr((char **) (f->esp+4));
  do_exec (f, cmd_line);
}

void
wait_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int pid = get_int((int *) (f->esp+4));
  do_wait (f, pid);
}

void
create_wrapper (struct intr_frame *f)
{
  validate_void_ptr ((void *) (*((char **)(f->esp+4))));
  char *file_name = get_char_ptr ((char **) (f->esp+4));
  validate_void_ptr (f->esp+8);
  unsigned initial_size = (unsigned) get_int ((int *) (f->esp+8));
  do_create (f, file_name, initial_size);
}

void
remove_wrapper (struct intr_frame *f)
{
  validate_void_ptr ((void *) (*((char **)(f->esp+4))));
  char *file_name = get_char_ptr ((char **) (f->esp+4));
  do_remove (f, file_name);
}

void
open_wrapper (struct intr_frame *f)
{
  validate_void_ptr ((void *) (*((char **)(f->esp+4))));
  char *file_name = get_char_ptr ((char **) (f->esp+4));
  do_open (f, file_name);
}

void
filesize_wrapper (struct intr_frame *f)
{
  validate_void_ptr ((f->esp+4));
  int fd = get_int ((int *) (f->esp+4));
  do_filesize (f, fd);
}

void
read_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int fd = get_int ((int *) (f->esp+4));
  validate_void_ptr ((*((void **)(f->esp+8))));
  void *buffer = get_void_ptr ((void **) (f->esp+8));
  validate_void_ptr (f->esp+12);
  unsigned size = (unsigned) get_int ((int *) (f->esp+12));
  do_read (f, fd, buffer, size);
}

void
write_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int fd = get_int ((int *) (f->esp+4));
  validate_void_ptr ((*((void **)(f->esp+8))));
  void *buffer = get_void_ptr ((void **) (f->esp+8));
  validate_void_ptr (f->esp+12);
  unsigned size = (unsigned) get_int ((int *) (f->esp+12));
  do_write (f, fd, buffer, size);
}

void
seek_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int fd = get_int ((int *) (f->esp+4));
  validate_void_ptr (f->esp+8);
  unsigned position = (unsigned) get_int ((int *) (f->esp+8));
  do_seek (fd, position);
}

void
tell_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int fd = get_int ((int *) (f->esp+4));
  do_tell (f, fd);
}

void
close_wrapper (struct intr_frame *f)
{
  validate_void_ptr (f->esp+4);
  int fd = get_int ((int *) (f->esp+4));
  do_close (fd);
}

void
do_halt ()
{
  shutdown_power_off ();
}

void
do_exit (int status)
{
  struct thread *self = thread_current ();
  struct thread *parent = self->parent_thread;

  printf("%s: exit(%d)\n", self->name, status);

  lock_acquire (&file_sync_lock);
  file_close(self->executable_file);
  lock_release (&file_sync_lock);

  if (parent->waiting_on == self->tid)
  {
    parent->waiting_on = -1;
    parent->child_process_creation = false;
    parent->child_status = status;
    sema_up(&parent->wait_child);
    self->parent_thread = NULL;
  }
  thread_exit ();
}

void
do_exec (struct intr_frame *f, const char *cmd_line)
{
  validate_void_ptr((void *)cmd_line);
  validate_void_ptr((void *)(cmd_line+1));
  validate_void_ptr((void *)(cmd_line+2));
  validate_void_ptr((void *)(cmd_line+3));
  int res = process_execute (cmd_line);
  f->eax = (uint32_t) res;
}

void
do_wait (struct intr_frame *f, int pid)
{
  int res = process_wait (pid);
  f->eax = (uint32_t) res;
}

void
do_create (struct intr_frame *f, const char *file_name, unsigned initial_size)
{
  lock_acquire (&file_sync_lock);
  bool res = filesys_create (file_name, initial_size);
  lock_release (&file_sync_lock);
  f->eax = (uint32_t) res;
}

void
do_remove (struct intr_frame *f, const char *file_name)
{
  lock_acquire (&file_sync_lock);
  bool res = filesys_remove (file_name);
  lock_release (&file_sync_lock);
  f->eax = (uint32_t) res;
}

void
do_open (struct intr_frame *f, const char *file_name)
{
  lock_acquire (&file_sync_lock);
  struct file *res = filesys_open (file_name);
  lock_release (&file_sync_lock);
  if (res == NULL)
  {
    f->eax = (uint32_t) -1;
  }
  else
  {
    struct open_file *newly_opened_file;
    struct thread *cur = thread_current ();
    newly_opened_file = malloc(sizeof(struct open_file));
    newly_opened_file->fd = ++(cur->fd_last);
    newly_opened_file->ptr = res;
    list_push_back (&cur->open_files, &newly_opened_file->file_elem);
    f->eax = (uint32_t) newly_opened_file->fd;
  }

}

void
do_filesize (struct intr_frame *f, int fd)
{
  struct file *file = validate_open_file(fd);
  if (file == NULL)
  {
    f->eax = (uint32_t) -1;
  }
  else
  {
    lock_acquire (&file_sync_lock);
    int res = (int) file_length (file);
    lock_release (&file_sync_lock);
    f->eax = (uint32_t) res;
  }
}

void
do_read (struct intr_frame *f, int fd, void *buffer, unsigned size)
{
  if (fd == 0)
  {
    for (unsigned i = 0; i < size; i++)
    {
      validate_void_ptr (buffer);
      lock_acquire (&file_sync_lock);
      *((uint8_t *)buffer) = input_getc ();
      lock_release (&file_sync_lock);
      buffer += 1;
    }
    f->eax = (uint32_t) size;
  }
  else {
    struct file *file = validate_open_file(fd);

    if (file == NULL)
    {
      f->eax = (uint32_t) -1;
    }
    else
    {
      lock_acquire (&file_sync_lock);
      int res = (int) file_read (file, buffer, (off_t) size);
      lock_release (&file_sync_lock);
      f->eax = (uint32_t) res;
    }
  }
}

void
do_write (struct intr_frame *f, int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    validate_void_ptr (buffer);
    int res = size;
    while (size > WRITE_MAX)
    {
      lock_acquire( &file_sync_lock);
      putbuf (buffer, WRITE_MAX);
      lock_release (&file_sync_lock);
      buffer += WRITE_MAX;
      size -= WRITE_MAX;
      validate_void_ptr (buffer);
    }
    putbuf (buffer, size);
    f->eax = (uint32_t) res;
  }
  else {
    struct file *file = validate_open_file(fd);

    if (file == NULL)
    {
      f->eax = (uint32_t) -1;
    }
    else
    {
      lock_acquire( &file_sync_lock);
      int res = (int) file_write (file, buffer, (off_t) size);
      lock_release (&file_sync_lock);
      f->eax = (uint32_t) res;
    }
  }
}

void
do_seek (int fd, unsigned position)
{
  struct file *file = validate_open_file(fd);

  if (file != NULL)
  {
    lock_acquire( &file_sync_lock);
    file_seek (file, (off_t) position);
    lock_release (&file_sync_lock);
  }
}

void
do_tell (struct intr_frame *f, int fd)
{
  struct file *file = validate_open_file(fd);

  if (file == NULL)
  {
    f->eax = (uint32_t) -1;
  }
  else
  {
    lock_acquire( &file_sync_lock);
    unsigned res = (unsigned) file_tell (file);
    lock_release (&file_sync_lock);
    f->eax = (uint32_t) res;
  }
}

void
do_close (int fd)
{
  struct open_file *file = NULL;
  struct list_elem *e;
  struct thread *cur = thread_current ();

  for (e = list_begin (&cur->open_files); e != list_end (&cur->open_files);
       e = list_next (e))
  {
    file = list_entry (e, struct open_file, file_elem);
    if (file->fd == fd)
      list_remove (e);
  }


  if (file != NULL)
  {
    lock_acquire( &file_sync_lock);
    file_close (file->ptr);
    lock_release (&file_sync_lock);
    free (file);
  }
}

// /* System call numbers. */
// enum
// {
// /* Projects 2 and later. */
// SYS_HALT, /* Halt the operating system. */
// SYS_EXIT, /* Terminate this process. */
// SYS_EXEC, /* Start another process. */
// SYS_WAIT, /* Wait for a child process to die. */
// SYS_CREATE, /* Create a file. */
// SYS_REMOVE, /* Delete a file. */
// SYS_OPEN, /* Open a file. */
// SYS_FILESIZE, /* Obtain a file’s size. */
// SYS_READ, /* Read from a file. */
// SYS_WRITE, /* Write to a file. */
// SYS_SEEK, /* Change position in a file. */
// SYS_TELL, /* Report current position in a file. */
// SYS_CLOSE, /* Close a file. */
// };
