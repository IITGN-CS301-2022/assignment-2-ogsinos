#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

void one_arg(struct intr_frame *intf, int syscall_num, void *args);
void two_arg(struct intr_frame *intf, int syscall_num, void *args);
void three_arg(struct intr_frame *intf, int syscall_num, void *args);
static void syscall_handler (struct intr_frame *intf);

void 
addrs_check(const void *addrs)
{
  if(!is_user_vaddr(addrs)) {
    // printf("fail\n");
    exit(-1);
  }
  void *check_page = pagedir_get_page(thread_current()->pagedir,addrs);
  if(check_page==NULL) exit(-1);
  // else printf("success\n");
}

void 
one_arg(struct intr_frame *intf, int syscall_num, void *args)
{
  int argv = *((int*)args);
  args += 4;
  // addrs_check((const void*)argv);
  switch (syscall_num)
  {
    case SYS_EXIT:
      exit(argv);
      break;
    case SYS_EXEC:
      addrs_check((const void*)argv);
      intf->eax = exec((const char*) argv);
      break;
    case SYS_WAIT:
      intf->eax = wait(argv);
      break;
    case SYS_REMOVE:
      addrs_check((const void*)argv);
      intf->eax = remove((const char*) argv);
      break;
    case SYS_OPEN:
      addrs_check((const void*)argv);
      intf->eax = open((const char*) argv);
      break;
    case SYS_FILESIZE:
      intf->eax = filesize(argv);
      break;
    case SYS_TELL:
      intf->eax = tell(argv);
      break;
    case SYS_CLOSE:
      close(argv);
      break;
    default:
      exit(-1);
      break;
  }
}

void 
two_arg(struct intr_frame *intf, int syscall_num, void *args)
{
  int argv = *((int*)args);
  args += 4;
  int argv1 = *((int*)args);
  args += 4;
  // addrs_check((const void*)argv);
  // addrs_check((const void*)argv1);
  switch (syscall_num)
  {
    case SYS_CREATE:
      addrs_check((const void*)argv);
      intf->eax = create((const char*)argv,(unsigned) argv1);
      break;
    case SYS_SEEK:
      seek(argv,(unsigned)argv1);
      break;
    default:
      exit(-1);
      break;
  }
}

void 
three_arg(struct intr_frame *intf, int syscall_num, void *args)
{
  int argv = *((int*)args);
  args += 4;
  int argv1 = *((int*)args);
  args += 4;
  int argv2 = *((int*)args);
  args += 4;
  // printf("%p %d\n",&argv,argv);
  // printf("%p %s\n",&argv1,(char *)argv1);
  // printf("%p %d\n",&argv2,argv2);
  // addrs_check((const void*)argv);
  addrs_check((const void*)argv1);
  void *temp = ((void*)argv1) + argv2;
  addrs_check((const void*)temp);
  // addrs_check((const void*)argv2);
  // addrs_check((const void*)0xc0000000);
  switch (syscall_num)
  {
    case SYS_WRITE:
      intf->eax = write(argv, (void*)argv1,(unsigned)argv2);
      // printf("yo1\n");
      break;
    case SYS_READ:
      intf->eax = read(argv, (void*)argv1,(unsigned)argv2);
      break;
    default:
      exit(-1);
      break;
  }
  // printf("yo2\n");
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_mutex);
}

static void
syscall_handler (struct intr_frame *intf) 
{
  // printf ("system call!\n");
  int syscall_num = 0;
  addrs_check((const void *)intf->esp);
  // printf("Syscall\n");

  void *args = intf->esp;
  syscall_num = *((int *)intf->esp);
  args += 4;
  //printf("%p %s\n",args,((char*)args));
  addrs_check((const void*)args);
  switch (syscall_num)
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT: case SYS_EXEC: case SYS_WAIT: case SYS_REMOVE: case SYS_OPEN: case SYS_FILESIZE: case SYS_TELL: case SYS_CLOSE:
      one_arg(intf,syscall_num,args);
      break;
    case SYS_CREATE: case SYS_SEEK:
      two_arg(intf,syscall_num,args);
      break;
    case SYS_WRITE: case SYS_READ:
      three_arg(intf,syscall_num,args);
      break;
    default:
      exit(-1);
      break;
  }
}

void
halt (void) 
{
  shutdown_power_off();
}

void
exit (int stat)
{
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, stat);

  struct child *baby = search_child(cur->tid, &(cur->parent->children_list));
  baby->exit_status = stat;
  if (stat == -1)
  {
    baby->cur_status = CHILD_KILLED;
  } 
  else 
  {
    baby->cur_status = CHILD_EXITED;
  }

  thread_exit();
}

tid_t
exec (const char *cmd_line)
{
  struct thread *cur = thread_current();
  tid_t pid = -1;
  pid = process_execute(cmd_line);

  struct child *baby = search_child(pid, &(cur->children_list));
  sema_down(&baby->child_thread->sema_load);

  if (!baby->loaded)
  {
    return -1;
  }
  else
  {
    return pid;
  }
}

int
wait (tid_t pid)
{
  return process_wait(pid);
}

bool
create (const char *file, unsigned init_size)
{
  lock_acquire(&file_mutex);
  bool val = filesys_create(file, init_size);
  lock_release(&file_mutex);
  return val;
}

bool 
remove (const char *file)
{
  lock_acquire(&file_mutex);
  bool val = filesys_remove(file);
  lock_release(&file_mutex);
  return val;
}

int 
open (const char *file)
{
  int val = -1;
  struct thread *cur = thread_current();
  // printf("OPEN\n");
  lock_acquire(&file_mutex);
  struct file *f_open = filesys_open(file);
  lock_release(&file_mutex);

  if (f_open)
  {
    // printf("ok\n");
    cur->fd_length ++;
    val = cur->fd_length;
    struct file_descriptor *fd_element = (struct file_descriptor *)malloc(sizeof(struct file_descriptor));
    fd_element->fd = val;
    fd_element->fd_file = f_open;
    list_push_back(&cur->fd_list, &fd_element->fd_elem);
  }
  // else 
  // {
  //   printf("not ok\n");
  // }
  // printf("%d\n",val);
  return val;
}

int 
filesize (int fd)
{
  struct file *f = search_fd(fd)->fd_file;
  lock_acquire(&file_mutex);
  int val = file_length(f);
  lock_release(&file_mutex);
  return val;
}

int 
read (int fd, void *buffer, unsigned size)
{
  int val = -1;
  if (fd == 0)
  {
    val = input_getc();
  }
  else if (fd > 0)
  {
    struct file_descriptor *fd_element = search_fd(fd);
    if (fd_element == NULL || buffer == NULL)
    {
      return -1;
    }

    struct file *f = fd_element->fd_file;
    lock_acquire(&file_mutex);
    val = file_read(f, buffer, size);
    lock_release(&file_mutex);

    if (val < (int)size && val != 0)
    {
      val = -1;
    }
  }

  return val;
}

int 
write (int fd, const void *buffer, unsigned size)
{
  uint8_t *buf = (uint8_t *)buffer;
  int val = -1;
  if (fd == 1)
  {
    putbuf((char *)buf, size);
    // printf("%d\n",size);
    return (int)size;
  }
  else{
    struct file_descriptor *fd_element = search_fd(fd);
    if (fd_element == NULL || buffer == NULL)
    {
      return -1;
    }

    struct file *f = fd_element->fd_file;
    lock_acquire(&file_mutex);
    val = file_write(f, buffer, size);
    lock_release(&file_mutex);
  }

  return val;
}

void 
seek (int fd, unsigned pos)
{
  struct file_descriptor *fd_element = search_fd(fd);
  if (fd_element == NULL) return;
  struct file* f = fd_element->fd_file;
  lock_acquire(&file_mutex);
  file_seek(f,pos);
  lock_release(&file_mutex);
}

unsigned
tell (int fd)
{
  struct file_descriptor *fd_element = search_fd(fd);
  if (fd_element == NULL) return -1;
  struct file* f = fd_element->fd_file;
  lock_acquire(&file_mutex);
  unsigned val = file_tell(f);
  lock_release(&file_mutex);
  return val;
}

void 
close (int fd)
{
  // printf("hello %d\n", fd);
  if (fd < 0) return;
  struct file_descriptor *fd_element = search_fd(fd);
  if (fd_element == NULL) return;
  struct file* f = fd_element->fd_file;
  lock_acquire(&file_mutex);
  file_close(f);
  lock_release(&file_mutex);
  list_remove(&fd_element->fd_elem);
}

void 
close_all_fd (struct list *fd_list)
{
  // printf("yo");
  struct list_elem *e;
  while (!list_empty(fd_list))
  {
    e = list_pop_front(fd_list);
    struct file_descriptor *fd_element = list_entry(e, struct file_descriptor, fd_elem);
    file_close(fd_element->fd_file);
    list_remove(e);
    free(fd_element);
  }
}
