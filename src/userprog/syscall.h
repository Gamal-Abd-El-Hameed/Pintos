#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/synch.h"

struct open_file
{
    int fd;
    struct file *ptr;
    struct list_elem file_elem;
};

void syscall_init (void);

void do_exit (int status);

#endif /* userprog/syscall.h */