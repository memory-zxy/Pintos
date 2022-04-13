#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "list.h"
#include "filesys/directory.h"
struct proc_file {
	struct file* ptr;
	int fd;
	struct list_elem elem;
	struct dir *dir;
};
struct mmap_desc {
	int mid;
	struct file *file;
	void *addr;
	size_t size;
	struct list_elem elem;
};
void syscall_init (void);
void exit_proc(int status);
int exec_proc(char *file_name);
void check_addr_user(void *p);
bool sys_munmap(int mid);
#endif /* userprog/syscall.h */
