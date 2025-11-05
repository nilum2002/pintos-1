#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "threads/malloc.h"
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

/* Child process structure for wait */
struct child_process
{
  tid_t tid;
  int exit_code;
  bool exited;
  struct list_elem elem;
};

/* Structure passed to start_process for synchronization */
struct process_info
{
  const char *cmdline;           /* Command line string */
  struct semaphore sema;         /* Semaphore for parent-child sync */
  bool *load_success;            /* Pointer to parent's success flag */
  tid_t tid;                     /* Thread ID of child */
};

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool setup_stack (const char *cmdline, void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *file_name) 
{
  char *copy;
  tid_t tid;
  bool load_success = false;
  struct semaphore sema;
  
  /* Initialize synchronization */
  sema_init (&sema, 0);

  /* Make a copy of FILE_NAME */
  copy = palloc_get_page (0);
  if (copy == NULL)
    return TID_ERROR;
  strlcpy (copy, file_name, PGSIZE);

  /* Create process_info structure */
  struct process_info info;
  info.cmdline = copy;
  sema_init (&info.sema, 0);
  info.load_success = &load_success;
  info.tid = TID_ERROR;

  /* Extract program name (before first space) for thread name */
  char prog_name[16];
  strlcpy (prog_name, file_name, sizeof prog_name);
  char *save_ptr;
  strtok_r (prog_name, " ", &save_ptr);

  /* Create child thread */
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, &info);
  info.tid = tid;
  
  if (tid == TID_ERROR)
    {
      palloc_free_page (copy);
      return TID_ERROR;
    }

  /* Wait for child to finish loading */
  sema_down (&info.sema);
  palloc_free_page (copy);
  
  /* Return TID_ERROR if load failed */
  if (!load_success)
    return TID_ERROR;
  
  /* Add child to parent's children list */
  struct child_process *child = malloc (sizeof (struct child_process));
  if (child != NULL)
    {
      child->tid = tid;
      child->exit_code = -1;
      child->exited = false;
      list_push_back (&thread_current ()->children, &child->elem);
    }
    
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */

static void
start_process (void *info_)
{
  struct process_info *info = info_;
  struct intr_frame if_;
  bool success;

  /* Set parent TID */
  thread_current ()->parent_tid = thread_current ()->tid;

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
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct child_process *child = NULL;
  
  /* Find child in children list */
  for (e = list_begin (&cur->children); e != list_end (&cur->children);
       e = list_next (e))
    {
      struct child_process *c = list_entry (e, struct child_process, elem);
      if (c->tid == child_tid)
        {
          child = c;
          break;
        }
    }
  
  /* Child not found or already waited on */
  if (child == NULL)
    return -1;
  
  /* Wait for child to exit if it hasn't yet */
  if (!child->exited)
    {
      /* Find the child thread and wait on its semaphore */
      struct thread *t = thread_get_by_tid (child_tid);
      if (t != NULL)
        sema_down (&t->wait_sema);
    }
  
  /* Get exit code and remove from children list */
  int exit_code = child->exit_code;
  list_remove (&child->elem);
  free (child);
  
  return exit_code;
}

/* Free the current process's resources. */

void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Print termination message for user processes */
  if (cur->pagedir != NULL)
    printf ("%s: exit(%d)\n", cur->name, cur->exit_code);

  /* Update parent's child list with exit code */
  struct thread *parent = thread_get_by_tid (cur->parent_tid);
  if (parent != NULL)
    {
      struct list_elem *e;
      for (e = list_begin (&parent->children); e != list_end (&parent->children);
           e = list_next (e))
        {
          struct child_process *child = list_entry (e, struct child_process, elem);
          if (child->tid == cur->tid)
            {
              child->exit_code = cur->exit_code;
              child->exited = true;
              break;
            }
        }
    }
  
  /* Signal parent that we're done */
  sema_up (&cur->wait_sema);
  
  /* Close all open files */
  int i;
  for (i = 2; i < 128; i++)
    {
      if (cur->files[i] != NULL)
        {
          file_close (cur->files[i]);
          cur->files[i] = NULL;
        }
    }

  /* Close executable file and re-enable writes */
  if (cur->executable != NULL)
    {
      file_close (cur->executable);
      cur->executable = NULL;
    }

  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
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
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char *prog_name = NULL;
  char *save_ptr;
  char *name_only;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Extract program name (before first space) */
  prog_name = palloc_get_page (0);
  if (prog_name == NULL)
    goto done;
  strlcpy (prog_name, file_name, PGSIZE);
  name_only = strtok_r (prog_name, " ", &save_ptr);
  
  /* If strtok_r returns NULL, file_name was empty or all spaces */
  if (name_only == NULL)
    goto done;

  /* Open executable file. */
  file = filesys_open (name_only);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
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
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
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
          goto done;
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
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (file_name, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (prog_name != NULL)
    palloc_free_page (prog_name);
    
  if (success)
    {
      /* Deny writes to executable */
      file_deny_write (file);
      thread_current ()->executable = file;
    }
  else
    {
      file_close (file);
    }
    
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

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
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */

/* Sets up the CPU for running user code in the current thread.
   This function is called on every context switch. */
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

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
