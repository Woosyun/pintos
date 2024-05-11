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
	if (ptr == NULL || !is_user_vaddr (ptr))
		exit (-1);

	void *check = pagedir_get_page (thread_current ()->pagedir, ptr);
	if (check == NULL)
		exit (-1);
}
/* --- project 3.3 end --- */

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	/* --- project 3.3 start --- */
	void *args = f->esp;
	validate ((const void *)args);
	int syscall_number = *((int *)args);
	args += 4;
	validate ((const void *)args);

	switch (syscall_number)
	{
		case SYS_HALT:
			shutdown_power_off ();
			break;
		case SYS_EXIT:
			{
				int exit_status = *(int *)args;
				args += 4;
				exit (exit_status);
				break;
			}
		case SYS_EXEC:
			{
				const char *cmd_line = *(const char **)args;
				args += 4;
				validate ((const void *)cmd_line);

				f->eax = exec (cmd_line);
				break;
			}
		case SYS_WAIT:
			{
				tid_t pid = *(tid_t *)args;
				args += 4;

				f->eax = wait (pid);
				break;
			}
		case SYS_CREATE:
			{
				const char *file = *(const char **)args;
				args += 4;
				validate ((const void *)file);
				unsigned initial_size = *(unsigned *)args;
				args += 4;

				f->eax = create (file, initial_size);
				break;
			}
		case SYS_REMOVE:
			{
				const char *file = *(const char **)args;
				args += 4;
				validate ((const void *)file);

				f->eax = remove (file);
				break;
			}
		case SYS_OPEN:
			{
				const char *file = *(const char **)args;
				args += 4;
				validate ((const void *)file);

				f->eax = open (file);
				break;
			}
		case SYS_FILESIZE:
			{
				int fd = *(int *)args;
				args += 4;

				f->eax = filesize (fd);
				break;
			}
		case SYS_READ:
			{
				int fd = *(int *)args;
				args += 4;
				void *buffer = *(void **)args;
				args += 4;
				unsigned size = *(unsigned *)args;
				args += 4;
				validate ((const void *)buffer);
				f->eax = read (fd, buffer, size);
				break;
			}
		case SYS_WRITE:
			{
				int fd = *(int *)args;
				args += 4;
				void *buffer = *(void **)args;
				args += 4;
				unsigned size = *(unsigned *)args;
				args += 4;
				validate ((const void *)buffer);
				validate ((const void *)(buffer + size));

				f->eax = write (fd, buffer, size);
				break;
			}
		case SYS_SEEK:
			{
				int fd = *(int *)args;
				args += 4;
				unsigned position = *(unsigned *)args;
				args += 4;
				seek (fd, position);
				break;
			}
		case SYS_TELL:
			{
				int fd = *(int *)args;
				args += 4;

				f->eax = tell (fd);
				break;
			}
		case SYS_CLOSE:
			{
				int fd = *(int *)args;
				args += 4;

				close (fd);
				break;
			}
		default:
			exit (-1);
			break;
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

	struct list *child_list = &cur->parent->child_list;
	struct child_element *child = get_child (cur->tid, child_list);
	child->exit_status = status;
	if (status == -1)
		child->cur_status = WAS_KILLED;
	else
		child->cur_status = HAD_EXITED;

	if (cur->parent != NULL)
		remove_child (cur->tid, child_list);
	free_children (child_list);
	cur->parent = NULL;

	lock_acquire (&file_lock);
	if (cur->exec_file != NULL)
	{
		file_allow_write (cur->exec_file);
		file_close (cur->exec_file);
	}
	lock_release (&file_lock);

	close_all (&cur->fd_list);
	sema_up (&cur->sema_wait);
	thread_exit ();
}

tid_t
exec (const char *cmd_line)
{
	struct thread* parent = thread_current();

	tid_t pid = -1;
	pid = process_execute(cmd_line);
	struct child_element *child = get_child(pid, &parent -> child_list);

	sema_down(&child -> real_child -> sema_exec);

	if(!child -> loaded_success)
		return -1;
	return pid;
}
int 
wait (tid_t pid)
{
	return process_wait (pid);
}
bool 
create (const char *file, unsigned initial_size)
{
	if (initial_size == 0)//TODO: create-long
		exit (-1);
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
		exit (-1);//TODO: return ? exit ()?
	//	return;
	struct file *myfile = fd_elem->myfile;
	remove_fd (fd, &thread_current ()->fd_list);

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
remove_fd (int fd, struct list *fd_list)
{
	struct list_elem *e;
	for (e=list_begin (fd_list); e!=list_end (fd_list); e=list_next (e))
	{
		struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
		if (fd_elem->fd == fd)
		{
			list_remove (e);
			return;
		}
	}
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
