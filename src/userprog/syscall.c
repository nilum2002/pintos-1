#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void validate_ptr (const void *ptr);
static int read_user_word (const void *uaddr);
static void validate_string (const char *str);
static void sys_halt (void);
static void sys_exit (int status);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
static int sys_exec (const char *cmd_line);
static int sys_wait (int pid);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Validates a user pointer - checks if it's in user space and mapped */
static void
validate_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr) || 
      pagedir_get_page (thread_current ()->pagedir, ptr) == NULL)
    {
      thread_current ()->exit_code = -1;
      thread_exit ();
    }
}

/* Validates and reads a 4-byte word from user memory */
static int
read_user_word (const void *uaddr)
{
  validate_ptr (uaddr);
  validate_ptr ((uint8_t *) uaddr + 3);  /* Check all 4 bytes */
  return *((int *) uaddr);
}

/* Validates a string in user memory */
static void
validate_string (const char *str)
{
  validate_ptr (str);
  while (*str != '\0')
    {
      str++;
      validate_ptr (str);
    }
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* Validate stack pointer */
  validate_ptr (f->esp);
  
  /* Read syscall number */
  int syscall_num = read_user_word (f->esp);
  int *args = (int *) f->esp;
  
  switch (syscall_num)
    {
    case SYS_HALT:
      sys_halt ();
      break;
      
    case SYS_EXIT:
      sys_exit (read_user_word (args + 1));
      break;
      
    case SYS_CREATE:
      f->eax = sys_create (
        (const char *) read_user_word (args + 1),
        (unsigned) read_user_word (args + 2)
      );
      break;
      
    case SYS_REMOVE:
      f->eax = sys_remove ((const char *) read_user_word (args + 1));
      break;
      
    case SYS_OPEN:
      f->eax = sys_open ((const char *) read_user_word (args + 1));
      break;
      
    case SYS_FILESIZE:
      f->eax = sys_filesize (read_user_word (args + 1));
      break;
      
    case SYS_READ:
      f->eax = sys_read (
        read_user_word (args + 1),
        (void *) read_user_word (args + 2),
        (unsigned) read_user_word (args + 3)
      );
      break;
      
    case SYS_WRITE:
      f->eax = sys_write (
        read_user_word (args + 1),
        (const void *) read_user_word (args + 2),
        (unsigned) read_user_word (args + 3)
      );
      break;
      
    case SYS_SEEK:
      sys_seek (
        read_user_word (args + 1),
        (unsigned) read_user_word (args + 2)
      );
      break;
      
    case SYS_TELL:
      f->eax = sys_tell (read_user_word (args + 1));
      break;
      
    case SYS_CLOSE:
      sys_close (read_user_word (args + 1));
      break;
      
    case SYS_EXEC:
      f->eax = sys_exec ((const char *) read_user_word (args + 1));
      break;
      
    case SYS_WAIT:
      f->eax = sys_wait (read_user_word (args + 1));
      break;
      
    default:
      thread_current ()->exit_code = -1;
      thread_exit ();
    }
}

/* System call implementations */

static void
sys_halt (void)
{
  shutdown_power_off ();
}

static void
sys_exit (int status)
{
  thread_current ()->exit_code = status;
  thread_exit ();
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  validate_ptr (buffer);
  if (size > 0)
    validate_ptr ((char *) buffer + size - 1);
  
  if (fd == 1) /* STDOUT_FILENO */
    {
      putbuf (buffer, size);
      return size;
    }
  
  if (fd < 2 || fd >= 128)
    return -1;
  
  struct file *f = thread_current ()->files[fd];
  if (f == NULL)
    return -1;
    
  return file_write (f, buffer, size);
}

static bool
sys_create (const char *file, unsigned initial_size)
{
  validate_string (file);
  return filesys_create (file, initial_size);
}

static bool
sys_remove (const char *file)
{
  validate_string (file);
  return filesys_remove (file);
}

static int
sys_open (const char *file)
{
  validate_string (file);
  
  struct file *f = filesys_open (file);
  if (f == NULL)
    return -1;
  
  /* Find free file descriptor */
  struct thread *cur = thread_current ();
  int fd;
  for (fd = 2; fd < 128; fd++)
    {
      if (cur->files[fd] == NULL)
        {
          cur->files[fd] = f;
          return fd;
        }
    }
  
  /* No free descriptors */
  file_close (f);
  return -1;
}

static int
sys_filesize (int fd)
{
  if (fd < 2 || fd >= 128)
    return -1;
  
  struct file *f = thread_current ()->files[fd];
  if (f == NULL)
    return -1;
    
  return file_length (f);
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  validate_ptr (buffer);
  if (size > 0)
    validate_ptr ((char *) buffer + size - 1);
  
  if (fd == 0) /* STDIN */
    {
      unsigned i;
      uint8_t *buf = buffer;
      for (i = 0; i < size; i++)
        buf[i] = input_getc ();
      return size;
    }
  
  if (fd < 2 || fd >= 128)
    return -1;
  
  struct file *f = thread_current ()->files[fd];
  if (f == NULL)
    return -1;
    
  return file_read (f, buffer, size);
}

static void
sys_seek (int fd, unsigned position)
{
  if (fd < 2 || fd >= 128)
    return;
    
  struct file *f = thread_current ()->files[fd];
  if (f != NULL)
    file_seek (f, position);
}

static unsigned
sys_tell (int fd)
{
  if (fd < 2 || fd >= 128)
    return 0;
    
  struct file *f = thread_current ()->files[fd];
  if (f == NULL)
    return 0;
    
  return file_tell (f);
}

static void
sys_close (int fd)
{
  if (fd < 2 || fd >= 128)
    return;
    
  struct thread *cur = thread_current ();
  struct file *f = cur->files[fd];
  if (f != NULL)
    {
      file_close (f);
      cur->files[fd] = NULL;
    }
}

static int
sys_exec (const char *cmd_line)
{
  validate_string (cmd_line);
  return process_execute (cmd_line);
}

static int
sys_wait (int pid)
{
  return process_wait (pid);
}
