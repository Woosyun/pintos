#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* --- project 3.3 start --- */
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"


void validate (const void *ptr);
struct child_element* get_child(tid_t tid,struct list *mylist);
void fd_init(struct fd_element *file_d, int fd_, struct file *myfile_);
struct fd_element* get_fd(int fd);
bool check_pointer (void *ptr);

/*
static int get_user (char *uaddr);
bool check_args (void *ptr, int argc);
bool check_string (char *ptr);
*/
void halt (void);
int write (int fd, const void *buffer_, unsigned size);
int wait (tid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
tid_t exec (const char *cmdline);
void exit (int status);

void get_args_3(struct intr_frame *f, int choose, void *args);
void get_args_2(struct intr_frame *f, int choose, void *args);
void get_args_1(struct intr_frame *f, int choose, void *args);


/* --- project 3.3 end --- */

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init (&file_lock);//project 3.3
}
/* --- project 3.3 start --- */
void 
validate (const void *ptr)
{
	if (!is_user_vaddr (ptr))
		exit (-1);
	void *check = pagedir_get_page (thread_current ()->pagedir, ptr);
	if (check == NULL)
		exit (-1);
}

void get_args_1 (struct intr_frame *f, int choose, void *args)
{
	int argv = *((int *)args);
	args += 4;

	if (choose == SYS_EXIT)
		exit (argv);
	else if (choose == SYS_EXEC)
	{
		validate ((const void *)argv);
		f->eax = exec ((const char *)argv);
	}
	else if (choose == SYS_WAIT)
		f->eax = wait (argv);
	else if (choose == SYS_REMOVE)
	{
		validate ((const void *)argv);
		f->eax = remove ((const char *)argv);
	}
	else if (choose == SYS_OPEN)
	{
		validate ((const void *)argv);
		f->eax = open ((const char *)argv);
	}
	else if (choose == SYS_FILESIZE)
		f->eax = filesize (argv);
	else if (choose == SYS_TELL)
		f->eax = tell (argv);
	else if (choose == SYS_CLOSE)
		close (argv);
}

void 
get_args_2 (struct intr_frame *f, int choose, void *args)
{
	int argv = *((int *)args);
	args += 4;
	int argv_1 = *((int *)args);
	args += 4;

	if (choose == SYS_CREATE)
	{
		validate ((const void *) argv);
		f->eax = create ((const char *)argv, (unsigned)argv_1);
	}
	else if (choose == SYS_SEEK)
		seek (argv, (unsigned)argv_1);
}

void 
get_args_3 (struct intr_frame *f, int choose, void *args)
{
	int argv = *((int *)args);
	args += 4;
	int argv_1 = *((int *)args);
	args += 4;
	int argv_2 = *((int *)args);
	args += 4;

	validate ((const void *) argv_1);
	void *temp = ((void *)argv_1) + argv_2;
	validate ((const void *) temp);
	if (choose == SYS_WRITE)
		f->eax = write (argv, (void *)argv_1, (unsigned)argv_2);
	else
		f->eax = read (argv, (void *)argv_1, (unsigned) argv_2);
}
/*
bool 
check_args (void *ptr, int argc)
{
	int i;
	for (i=0; i<4*argc; i++)
	{
		if (!check_pointer (ptr+i))
			return false;
	}
	return true;
}
static int 
get_user (char *uaddr)
{
	if (!is_user_vaddr (uaddr))
		return -1;
	int re;
	asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (re) : "m" (*uaddr));
	return re;
}
bool 
check_string (char *ptr)
{
	int c = get_user (ptr);
	while (c != -1)
	{
		if (c == '\0')
			return true;
		ptr++;
		c = get_user (ptr);
	}
	return false;
}
bool
check_pointer (void *ptr)
{
	if (get_user (ptr) == -1)
		return false;
	return true;
}
*/
/* --- project 3.3 end --- */

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  //thread_exit ();
	/* --- project 3.3 start --- */
	void *args = f->esp;
	//validate syscall number?
	validate ((const void *)args);
	int syscall_number = *((int *)args);
	args += 4;
	//validate first arg
	validate ((const void *)args);
	/*if (!check_args (args, 1))
	{
		thread_exit();
		return;
	}
	*/
	//args += 4;

	switch (syscall_number)
	{
		case SYS_HALT:
			shutdown_power_off ();
			break;
		case SYS_EXIT:
			{
				/*if (!check_args (args + 4, 1))
				{
					exit (-1);
					break;
				}
				int status = *(int *)args;
				exit (status);*/
				get_args_1 (f, SYS_EXIT, args);
				break;
			}
		case SYS_EXEC:
			{
				/*if (!check_args (args + 4, 1) || !check_string (*(char **)(args + 4)))
				{
					exit (-1);
					break;
				}
				char *cmd_line = *(char **)(args + 4);
				struct thread *t = thread_current ();
				struct child_element *child = get_child (t->tid, &t->parent->child_list);
				sema_down (&child->real_child->sema_exec);
				tid_t pid = process_execute (cmd_line);
				if (child->loaded_success)
					f->eax = pid;
				else
					f->eax = -1;
					*/
				get_args_1 (f, SYS_EXEC, args);
				break;
			}
		case SYS_WAIT:
			{
				/*
				if (!check_args (args+4, 1))
				{
					exit (-1);
					break;
				}
				int pid = *(int *)(args+4);
				f->eax = process_wait (pid);
				*/
				get_args_1 (f, SYS_WAIT, args);
				break;
			}
		case SYS_CREATE:
			{
				/*
				if (!check_args (args+4, 2) || !check_string (*(char **)(args+4)))
				{
					exit (-1);
					break;
				}
				char *file = *(char **)(args + 4);
				unsigned size = *(unsigned *)(args + 8);
	
				lock_acquire (&file_lock);
				bool created = filesys_create (file, size);
				lock_release (&file_lock);

				f->eax = created;
				*/
				get_args_2 (f, SYS_CREATE, args);
				break;
			}
		case SYS_REMOVE:
			{
				/*
				if (!check_args (args + 4, 1) || !check_string (*(char **)(args + 4)))
				{
					exit (-1);
					break;
				}
				char *file = *(char **)(args + 4);

				lock_acquire (&file_lock);
				bool removed = filesys_remove (file);
				lock_release (&file_lock);

				f->eax = removed;
				*/
				get_args_1 (f, SYS_REMOVE, args);
				break;
			}
		case SYS_OPEN:
			{
				/*
				if (!check_args (args + 4, 1) || !check_string (*(char **)(args + 4)))
				{
					exit (-1);
					break;
				}
				char *file_name = *(char **)(args + 4);
	
				lock_acquire (&file_lock);
				struct file *file = filesys_open (file_name);
				lock_release (&file_lock);

				struct thread *t = thread_current ();

				f->eax = -1;
				if (file != NULL)
				{
					struct fd_element *fd_elem = (struct fd_element*)malloc (sizeof (struct fd_element));
					t->fd_size += 1;
					f->eax = t->fd_size;
					fd_elem->fd = t->fd_size;
					fd_elem->myfile = file;
					list_push_back (&t->fd_list, &fd_elem->element);
				}
				*/
				get_args_1 (f, SYS_OPEN, args);
				break;
			}
		case SYS_FILESIZE:
			{
				/*
				if (!check_args (args+4, 1))
				{
					exit(-1);
					break;
				}
				int fd = *(int *)(args + 4);
				struct file *file = get_fd (fd)->myfile;
				f->eax = -1;
				if (file != NULL)
				{
					lock_acquire (&file_lock);
					f->eax = file_length (file);
					lock_release (&file_lock);
				}
				*/
				get_args_1 (f, SYS_FILESIZE, args);
				break;
			}
		case SYS_READ:
			{
				/*
				if (!check_args (args + 4, 3))
				{
					exit (-1);
					break;
				}
				int fd = *(int *)(args + 4);
				char *buffer = *(char **)(args + 8);
				unsigned size = *(unsigned *)(args + 12);
				if (!check_pointer (buffer) || !check_pointer (buffer + size))
				{
					exit (-1);
					break;
				}

				int re = -1;
				if (fd > 0)
				{
					struct file *file = get_fd (fd)->myfile;
					f->eax = -1;
					if (file != NULL)
					{
						lock_acquire (&file_lock);
						re = file_read (file, buffer, size);
						lock_release (&file_lock);
						if (re < (int)size && re != 0)
							re = -1;
					}
				}
				else
				{
					unsigned i;
					for (i=0; i<size; i++)
						buffer[i] = input_getc ();
					f->eax = size;
				}
				*/
				get_args_3 (f, SYS_READ, args);
				break;
			}
		case SYS_WRITE:
			{
				/*
				if (!check_args (args + 4, 3))
				{
					exit (-1);
					break;
				}
				int fd = *(int *)(args + 4);
				char *buffer = *(char **)(args + 8);
				unsigned size = *(unsigned *)(args + 12);

				if (!check_pointer (buffer) || !check_pointer (buffer + size))
				{
					exit (-1);
					break;
				}

				if (fd == 1)
				{
					putbuf (buffer, size);
					f->eax = size;
				}
				else
				{
					struct file *file = get_fd (fd)->myfile;
					if (file == NULL)
					{
						f->eax = -1;
					}
					else
					{
						lock_acquire (&file_lock);
						f->eax = file_write (file, buffer, size);
						lock_release (&file_lock);
					}
				}
				*/
				get_args_3 (f, SYS_WRITE, args);
				break;
			}
		case SYS_SEEK:
			{
				/*
				if (!check_args (args + 4, 1))
				{
					exit (-1);
					break;
				}
				int fd = *(int *)(args + 4);
				unsigned pos = *(unsigned *)(args + 8);

				struct file *file = get_fd (fd)->myfile;
				if (file != NULL)
				{
					lock_acquire (&file_lock);
					file_seek (file, pos);
					lock_release (&file_lock);
				}
				*/
				get_args_2 (f, SYS_SEEK, args);
				break;
			}
		case SYS_TELL:
			{
				/*
				if (!check_args (args + 4, 1))
				{
					exit (-1);
					break;
				}
				int fd = *(int *)(args + 4);
				struct file *file = get_fd (fd)->myfile;
				f->eax = -1;
				if (file != NULL)
				{
					lock_acquire (&file_lock);
					f->eax = file_tell (file);
					lock_release (&file_lock);
				}
			*/
				get_args_1 (f, SYS_TELL, args);
				break;
			}
		case SYS_CLOSE:
			{
				/*
				if (!check_args (args + 4, 1))
				{
					exit (-1);
					break;
				}
				int fd = *(int *)(args + 4);
				struct file *file = get_fd (fd)->myfile;
				if (file != NULL)
				{
					lock_acquire (&file_lock);
					file_close (file);
					lock_release (&file_lock);
				}
				*/
				get_args_1 (f, SYS_CLOSE, args);
				break;
			}
	}
}

void
halt (void)
{
	shutdown_power_off ();
}
void
exit (int status)
{
	struct thread *cur = thread_current ();
	printf ("%s: exit(%d)\n", cur->name, status);

	//if (cur ->parent == NULL)
	//	return;

	struct child_element *child = get_child (cur->tid, &cur->parent->child_list);
	child->exit_status = status;
	if (status == -1)
		child->cur_status = WAS_KILLED;
	else
		child->cur_status = HAD_EXITED;

	remove_child (cur->tid, &cur->parent->child_list);
	free_children (&cur->child_list);
	cur->parent = NULL;

	lock_acquire (&file_lock);
	if (cur->exec_file != NULL)
	{
	file_allow_write (cur->exec_file);
	file_close (cur->exec_file);
	}
	close_all (&cur->fd_list);
	lock_release (&file_lock);
	
	sema_up (&cur->sema_wait);

	thread_exit ();
}

tid_t
exec (const char *cmd_line)
{
	struct thread* parent = thread_current();
	tid_t pid = -1;
	struct child_element *child = get_child(pid, &parent -> child_list);
	sema_down(&child -> real_child -> sema_exec);
	pid = process_execute(cmd_line);
	if(!child -> loaded_success)
		return -1;
	return pid;
}
int wait (tid_t pid)
{
	return process_wait (pid);
}
bool create (const char *file, unsigned initial_size)
{
	lock_acquire(&file_lock);
	bool ret = filesys_create(file, initial_size);
	lock_release(&file_lock);
	return ret;
}
bool remove (const char *file)
{
	lock_acquire(&file_lock);
	bool ret = filesys_remove(file);
	lock_release(&file_lock);
	return ret;
}
int open (const char *file)
{
	int ret = -1;
	lock_acquire(&file_lock);
	struct thread *cur = thread_current ();
	struct file * opened_file = filesys_open(file);
	lock_release(&file_lock);
	if(opened_file != NULL)
	{
		cur->fd_size = cur->fd_size + 1;
		ret = cur->fd_size;
		struct fd_element *file_d = (struct fd_element*) malloc(sizeof(struct fd_element));
		file_d->fd = ret;
		file_d->myfile = opened_file;
		list_push_back(&cur->fd_list, &file_d->element);
	}
	return ret;
}
int filesize (int fd)
{
	struct file *myfile = get_fd(fd)->myfile;
	lock_acquire(&file_lock);
	int ret = file_length(myfile);
	lock_release(&file_lock);
	return ret;
}
int read (int fd, void *buffer, unsigned size)
{
	int ret = -1;
	if(fd == 0)
	{
		ret = input_getc();
	}
	else if (fd > 0)
	{
		struct fd_element *fd_elem = get_fd(fd);
		if(fd_elem == NULL || buffer == NULL)
			return -1;
		struct file *myfile = fd_elem->myfile;
		lock_acquire(&file_lock);
		ret = file_read(myfile, buffer, size);
		lock_release(&file_lock);
		if(ret < (int)size && ret != 0)
		{
			ret = -1;
		}
	}
	return ret;
}
int write (int fd, const void *buffer_, unsigned size)
{
	uint8_t * buffer = (uint8_t *) buffer_;
	int ret = -1;
	if (fd == 1)
	{
		putbuf( (char *)buffer, size);
		ret = (int)size;
	}
	else
	{
		struct fd_element *fd_elem = get_fd (fd);
		if(fd_elem == NULL || buffer_ == NULL)
		{
			return -1;
		}
		struct file *myfile = fd_elem->myfile;

		lock_acquire(&file_lock);
		ret = file_write(myfile, buffer, size);
		lock_release(&file_lock);
	}

	return ret;
}
void seek (int fd, unsigned position)
{
	struct fd_element *fd_elem = get_fd(fd);
	if(fd_elem == NULL)
		return;
	struct file *myfile = fd_elem->myfile;
	lock_acquire(&file_lock);
	file_seek(myfile,position);
	lock_release(&file_lock);
}
unsigned tell (int fd)
{
	struct fd_element *fd_elem = get_fd(fd);
	if(fd_elem == NULL)
		return -1;
	struct file *myfile = fd_elem->myfile;
	lock_acquire(&file_lock);
	unsigned ret = file_tell(myfile);
	lock_release(&file_lock);
	return ret;
}
void close (int fd)
{
	struct fd_element *fd_elem = get_fd(fd);
	if(fd_elem == NULL)
		return;
	struct file *myfile = fd_elem->myfile;
	lock_acquire(&file_lock);
	file_close(myfile);
	lock_release(&file_lock);
}
void close_all(struct list *fd_list)
{
	struct list_elem *e;
	while(!list_empty(fd_list))
	{
		e = list_pop_front(fd_list);
		struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
		file_close(fd_elem->myfile);
		list_remove(e);
		free(fd_elem);
	}
}
struct fd_element*
get_fd(int fd)
{
	struct list *li = &thread_current ()->fd_list;
	struct list_elem *e;
	for (e = list_begin (li); e != list_end (li); e = list_next (e))
	{
		struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
		if(fd_elem->fd == fd)
			return fd_elem;
	}
	return NULL;
}
struct child_element*
get_child(tid_t tid, struct list *mylist)
{
	struct list_elem* e;
	for (e = list_begin (mylist); e != list_end (mylist); e = list_next (e))
	{
		struct child_element *child = list_entry (e, struct child_element, child_elem);
		if(child -> child_pid == tid)
		{
			return child;
		}
	}
	return NULL;
}
void
remove_child (tid_t tid, struct list *mylist)
{
	struct list_elem *e;
	for (e=list_begin (mylist); e!=list_end (mylist); e=list_next (e))
	{
		struct child_element *child = list_entry (e, struct child_element, child_elem);
		if (child->child_pid == tid)
		{
			list_remove (e);
			return;
		}
	}
}

/* --- project 3.3 end --- */
