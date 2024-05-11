#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include "threads/thread.h"
#include <list.h>
#include "threads/synch.h"

void syscall_init (void);

/* --- project 3.3 start --- */
struct lock file_lock;
struct fd_element
{
	int fd;
	struct file *myfile;
	struct list_elem element;
};

void halt (void);
void exit (int);
tid_t exec (const char *);
int wait (tid_t);
bool create (const char *, unsigned);
bool remove (const char *);
int open (const char *);
int filesize (int);
int read (int, void *, unsigned);
int write (int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);
void close (int);
void close_all (struct list *);
struct child_element* get_child(tid_t,struct list *);
void remove_fd (int, struct list *);
void remove_child (tid_t, struct list *);
/* --- project 3.3 end --- */

#endif /* userprog/syscall.h */
