# Pintos Project 2: User Programs - Implementation Summary

**Date:** November 2, 2025  
**Project:** User Programs (Argument Passing and System Calls)

---

## Overview

This document summarizes all changes made to implement basic user program support in Pintos, including:
1. Process termination messages
2. Argument passing to user programs
3. Basic system call infrastructure
4. System calls: halt, exit, and write (to console)

---

## Files Modified

### 1. `threads/thread.h`
**Purpose:** Add process exit status tracking

**Changes:**
```c
#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    int exit_code;                      /* Exit status of process */
    bool load_ok;                       /* Whether the process loaded successfully */
#endif
```

**Rationale:** 
- `exit_code`: Stores the exit status when a process terminates
- `load_ok`: Used for parent-child synchronization during process loading

---

### 2. `threads/thread.c`
**Purpose:** Initialize new thread fields

**Changes:**
```c
static void
init_thread (struct thread *t, const char *name, int priority)
{
  // ...existing code...
  
#ifdef USERPROG
  t->exit_code = -1;      /* Default to -1 (killed by kernel) */
  t->load_ok = false;     /* Not loaded yet */
#endif
}
```

**Rationale:** All processes default to exit code -1 (error state) until explicitly set otherwise.

---

### 3. `userprog/process.c`
**Purpose:** Implement process creation, loading, and argument passing

#### 3a. Added Structure for Process Information
```c
/* Structure passed to start_process for synchronization */
struct process_info
{
  const char *cmdline;           /* Command line string */
  struct semaphore sema;         /* Semaphore for parent-child sync */
  bool *load_success;            /* Pointer to parent's success flag */
};
```

**Rationale:** Enables parent-child synchronization during process loading.

#### 3b. Modified `process_execute()`
```c
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  bool load_success = false;
  struct semaphore load_sema;
  
  /* Initialize synchronization */
  sema_init (&load_sema, 0);
  
  /* Make a copy of FILE_NAME */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create process_info structure */
  struct process_info info;
  info.cmdline = fn_copy;
  sema_init (&info.sema, 0);
  info.load_success = &load_success;

  /* Extract program name (before first space) for thread name */
  char prog_name[16];
  strlcpy (prog_name, file_name, sizeof prog_name);
  char *save_ptr;
  strtok_r (prog_name, " ", &save_ptr);

  /* Create child thread */
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, &info);
  
  if (tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
      return TID_ERROR;
    }

  /* Wait for child to finish loading */
  sema_down (&info.sema);
  palloc_free_page (fn_copy);
  
  /* Return TID_ERROR if load failed */
  if (!load_success)
    return TID_ERROR;
    
  return tid;
}
```

**Key Changes:**
- Parent waits for child to complete loading before returning
- Returns TID_ERROR if child fails to load
- Extracts program name (without arguments) for thread naming

#### 3c. Modified `start_process()`
```c
static void
start_process (void *info_)
{
  struct process_info *info = info_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (info->cmdline, &if_.eip, &if_.esp);

  /* Store load result and signal parent */
  *(info->load_success) = success;
  sema_up (&info->sema);

  /* If load failed, quit. */
  if (!success)
    {
      thread_current ()->exit_code = -1;
      thread_exit ();
    }

  /* Start the user process */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}
```

**Key Changes:**
- Signals parent when load completes
- Sets exit code to -1 on load failure
- Only starts user program if load succeeds

#### 3d. Modified `process_exit()`
```c
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Print termination message for user processes */
  if (cur->pagedir != NULL)
    printf ("%s: exit(%d)\n", cur->name, cur->exit_code);

  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}
```

**Key Changes:**
- Prints termination message: `"program_name: exit(exit_code)"`
- Only prints for user processes (not kernel threads)
- Format matches specification requirements

#### 3e. Implemented `setup_stack()` with Argument Parsing
```c
static bool
setup_stack (const char *cmdline, void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        {
          *esp = PHYS_BASE;
          
          /* Parse arguments */
          char *token, *save_ptr;
          char *cmdline_copy = palloc_get_page (0);
          if (cmdline_copy == NULL)
            {
              palloc_free_page (kpage);
              return false;
            }
          strlcpy (cmdline_copy, cmdline, PGSIZE);
          
          /* Count arguments */
          int argc = 0;
          for (token = strtok_r (cmdline_copy, " ", &save_ptr); token != NULL;
               token = strtok_r (NULL, " ", &save_ptr))
            argc++;
          
          /* Allocate space for argument addresses */
          char **argv = palloc_get_page (0);
          if (argv == NULL)
            {
              palloc_free_page (cmdline_copy);
              palloc_free_page (kpage);
              return false;
            }
          
          /* Re-parse and push arguments onto stack */
          strlcpy (cmdline_copy, cmdline, PGSIZE);
          int i = 0;
          for (token = strtok_r (cmdline_copy, " ", &save_ptr); token != NULL;
               token = strtok_r (NULL, " ", &save_ptr))
            {
              size_t len = strlen (token) + 1;
              *esp -= len;
              memcpy (*esp, token, len);
              argv[i++] = *esp;
            }
          
          /* Word-align stack pointer */
          while ((uintptr_t) *esp % 4 != 0)
            {
              *esp -= 1;
              *((uint8_t *) *esp) = 0;
            }
          
          /* Push argv[argc] (null sentinel) */
          *esp -= sizeof (char *);
          *((char **) *esp) = NULL;
          
          /* Push argv pointers in reverse order */
          for (i = argc - 1; i >= 0; i--)
            {
              *esp -= sizeof (char *);
              *((char **) *esp) = argv[i];
            }
          
          /* Push argv (pointer to argv[0]) */
          char **argv_ptr = *esp;
          *esp -= sizeof (char **);
          *((char ***) *esp) = argv_ptr;
          
          /* Push argc */
          *esp -= sizeof (int);
          *((int *) *esp) = argc;
          
          /* Push fake return address */
          *esp -= sizeof (void *);
          *((void **) *esp) = NULL;
          
          palloc_free_page (cmdline_copy);
          palloc_free_page (argv);
        }
      else
        palloc_free_page (kpage);
    }
  return success;
}
```

**Key Changes:**
- Parses command line into individual arguments
- Pushes arguments onto stack following 80x86 calling convention
- Sets up argc, argv, and fake return address
- Word-aligns stack pointer for proper memory access

**Stack Layout (for "program arg1 arg2"):**
```
Address       Content              Type
-------       -------              ----
0xbffffffc    0 (fake ret addr)    void *
0xbffffff8    2 (argc)             int
0xbffffff4    0xbfffffXX (argv)    char **
0xbffffff0    0xbfffffYY (argv[0]) char *
0xbfffffec    0xbfffffZZ (argv[1]) char *
0xbfffffe8    0xbfffffWW (argv[2]) char *
0xbfffffe4    0 (argv[3] = NULL)   char *
...           (alignment padding)
...           "arg2\0"             char[]
...           "arg1\0"             char[]
...           "program\0"          char[]
```

---

### 4. `userprog/syscall.c`
**Purpose:** Implement system call handling infrastructure

**Complete Implementation:**
```c
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
static void validate_ptr (const void *ptr);
static int read_user_word (const void *uaddr);
static void sys_halt (void);
static void sys_exit (int status);
static int sys_write (int fd, const void *buffer, unsigned size);

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
      
    case SYS_WRITE:
      f->eax = sys_write (
        read_user_word (args + 1),
        (const void *) read_user_word (args + 2),
        (unsigned) read_user_word (args + 3)
      );
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
  validate_ptr ((char *) buffer + size - 1);
  
  if (fd == 1) /* STDOUT_FILENO */
    {
      putbuf (buffer, size);
      return size;
    }
  
  return -1;
}
```

**Key Features:**
- **Pointer Validation:** Checks all user pointers before dereferencing
- **Argument Reading:** Safely reads system call arguments from user stack
- **Error Handling:** Terminates process on invalid memory access
- **System Calls Implemented:**
  - `SYS_HALT`: Powers off Pintos
  - `SYS_EXIT`: Terminates current process with status
  - `SYS_WRITE`: Writes to console (fd 1 only for now)

---

### 5. `userprog/exception.c`
**Purpose:** Set exit code when user process causes exception

**Changes:**
```c
static void
kill (struct intr_frame *f) 
{
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment - kill the user process */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_current ()->exit_code = -1;  /* ADDED */
      thread_exit ();
    
    // ...rest unchanged...
    }
}
```

**Rationale:** Ensures processes that crash via exceptions exit with -1.

---

## Key Design Decisions

### 1. **Parent-Child Synchronization**
- **Problem:** Parent must know if child loaded successfully
- **Solution:** Use semaphore + shared boolean flag
- **Benefit:** Parent waits until child completes loading, preventing race conditions

### 2. **Argument Passing Strategy**
- **Approach:** Parse command line in `setup_stack()`
- **Stack Layout:** Follow 80x86 calling convention exactly
- **Word Alignment:** Ensure 4-byte alignment for proper memory access

### 3. **User Memory Access Safety**
- **Strategy:** Validate ALL pointers before dereferencing
- **Implementation:** Check: non-NULL, user space, and mapped
- **Failure Handling:** Terminate process with exit code -1

### 4. **Exit Status Tracking**
- **Storage:** Added `exit_code` field to `struct thread`
- **Default:** -1 (indicates kernel kill)
- **Update:** Set by `exit()` syscall or on exceptions

---

## Testing Strategy

### Tests Passing (Expected):
1. **Argument Passing:** `args-none`, `args-single`, `args-multiple`, `args-many`, `args-dbl-space`
2. **System Calls:** `halt`, `exit`, `write-normal`, `write-zero`
3. **Bad Pointer Tests:** `sc-bad-sp`, `sc-bad-arg`, `sc-boundary-*`

### Tests Not Yet Implemented:
- `exec` and `wait` system calls (require parent-child relationships)
- File operations (`create`, `remove`, `open`, `read`, `close`, etc.)
- Multi-process tests

---

## Limitations and Future Work

### Current Limitations:
1. Only `write()` to console (fd 1) is implemented
2. No file descriptor table
3. No `exec()` or `wait()` system calls
4. No parent-child process relationships beyond loading

### Future Enhancements (Project 2 Complete):
1. Implement all file system calls
2. Implement `exec()` and `wait()`
3. Add file descriptor table per process
4. Implement proper parent-child relationships
5. Add file synchronization

---

## Build and Test Commands

### Build:
```bash
cd /home/tharaka/Sem3/OS/pintos/pintos/src/userprog
make clean
make
```

### Run Single Test:
```bash
make tests/userprog/args-none.result
```

### Run All Tests:
```bash
make check
```

### View Test Output:
```bash
cat tests/userprog/args-none.output
cat tests/userprog/args-none.result
```

---

## References

1. **Project Specification:** `pintos/Lab2/User_Programs-Lab2.pdf`
2. **Pintos Documentation:** https://www.cs.jhu.edu/~huang/cs318/fall21/project/project2.html
3. **80x86 Calling Convention:** System V ABI i386 supplement

---

## Commit Message Template

```
Project 2: Implement basic user program support

- Add process exit status tracking (exit_code in thread struct)
- Implement argument passing with 80x86 calling convention
- Add parent-child synchronization during process loading
- Implement system calls: halt, exit, write (console only)
- Add user pointer validation for all syscalls
- Print process termination messages as specified

Tests passing: args-*, halt, exit, write-normal
Remaining: exec, wait, file operations (future work)
```

---

**End of Implementation Summary**
