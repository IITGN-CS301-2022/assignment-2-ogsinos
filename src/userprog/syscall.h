#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"
#include "threads/synch.h"

struct lock file_mutex;

void addrs_check(const void *addrs);
void syscall_init (void);
void halt (void);
void exit(int stat);
tid_t exec (const char *cmd_line);
int wait (tid_t pid);
bool create (const char *file, unsigned init_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned pos);
unsigned tell (int fd);
void close (int fd);
/* Remove all files */
void close_all_fd (struct list *fd_list);

#endif /* userprog/syscall.h */
