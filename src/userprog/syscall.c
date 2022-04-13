#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "list.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/string.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif



static struct proc_file* find_pfile(int fd) {
	// used to find the proc_file with fd
	struct list_elem *e;
  	struct proc_file *pf = NULL;
  	struct thread *t = thread_current();
  	for (e = list_begin(&t->files); e != list_end(&t->files); e = list_next(e)) {
  		pf = list_entry(e, struct proc_file, elem);
  		if (pf->fd == fd) return pf;
  	}
  	return NULL;
}

#ifdef VM
static struct mmap_desc *find_mmap(struct thread *t, int mid) {
	struct list_elem *e;
	struct mmap_desc *mmap_d = NULL;
	for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e = list_next(e)) {
		mmap_d = list_entry(e, struct mmap_desc, elem);
		if (mmap_d->mid == mid) return mmap_d;
	}
	return NULL;
}
bool sys_munmap(int mid) {
	struct thread *t = thread_current();
	struct mmap_desc *mmap_d = find_mmap(t, mid);
	if (mmap_d == NULL) return false;
	acquire_filesys_lock();
	size_t file_size = mmap_d->size;
	for (size_t offset = 0; offset < file_size; offset += PGSIZE) {
		void *addr = mmap_d->addr + offset;
		size_t bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
		page_table_mm_unmap(t->page_table, t->pagedir, addr, mmap_d->file, offset, bytes);	
	}
	list_remove(&mmap_d->elem);
	file_close(mmap_d->file);
	free(mmap_d);
	release_filesys_lock();
	return true;
}
void preload_and_pin_pages(const void *buffer, size_t size)
{
  struct hash *page_table = thread_current()->page_table;
  uint32_t *pagedir = thread_current()->pagedir;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    page_table_load (page_table, pagedir, upage);
    struct page *page = page_table_lookup(page_table, upage);
    if (page) vm_frame_pin(page->kpage);
  }
}

void unpin_preloaded_pages(const void *buffer, size_t size)
{
  struct hash *page_table = thread_current()->page_table;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
  	struct page *page = page_table_lookup(page_table, upage);
    if (page && page->status == ON_FRAME) vm_frame_pin(page->kpage);
  }
}
#endif

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void exit_proc(int status) {
	struct list_elem *e;
	struct child *c;
	// a little tricky... find parent's child 
	// because thread can't have a thread list
	for (e = list_begin(&thread_current()->parent->children);
	e != list_end(&thread_current()->parent->children); e = list_next(e)) {
		c = list_entry(e, struct child, elem_child);
		if (c->tid == thread_current()->tid) {
			c->used = true;
			c->exit_code = status;
		}
	}
	thread_current()->exit_code = status;
	if(thread_current()->parent && thread_current()->parent->wait_tid == thread_current()->tid) {
		// if its parent is waiting for it, wake up its parent
		sema_up(&thread_current()->parent->child_lock);
	}
	thread_exit();
}

int exec_proc(char *file_name) {
	acquire_filesys_lock(); // for task sync-read/write
	char * fn_cp = malloc (strlen(file_name)+1);
	strlcpy(fn_cp, file_name, strlen(file_name)+1);  
	char * save_ptr;
	fn_cp = strtok_r(fn_cp," ",&save_ptr);
	struct file* f = filesys_open (fn_cp);
	if (f == NULL) {
	  	release_filesys_lock();
	  	return -1;
	}
	else {
		file_close(f); // allow write f for task rox-child
		release_filesys_lock();
		return process_execute(file_name);
	}
}

void check_addr_user(void *p) {
	if (!is_user_vaddr(p)) {
		// kernel space
		exit_proc(-1);
		return;
	}
	if (p == NULL) {
		exit_proc(-1);
		return;
	}
#ifndef VM
	if (!pagedir_get_page(thread_current()->pagedir, p)) {
		// unmapped space
		exit_proc(-1);
		return;
	}
#endif
	// no unmap check, page_fault will deal with taht
}



static void
syscall_handler (struct intr_frame *f) 
{
  int *p = f->esp;
  check_addr_user(p+1); // for task sc-boundary-3(the first byte is valid, but...)
#ifdef VM  
  thread_current()->esp = p;
#endif
  switch (*p) {
  	case SYS_HALT: {
	  	shutdown_power_off();
	  	break;
	}
  	case SYS_EXIT: {
		check_addr_user(p+1);
		exit_proc(*(p+1));
		break;
	}
  	case SYS_EXEC: {
  		check_addr_user(p+1);
	  	check_addr_user(p+2); // exec-bound-2 
	  	check_addr_user((void*)*(p+1));
	  	check_addr_user((void*)(*(p+1)+1)); // exec-bound-3
	  	f->eax = exec_proc((char *)*(p+1));
	  	break;
	}
  	case SYS_WAIT: {
	  	check_addr_user(p+1);
	  	f->eax = process_wait(*(p+1));
	  	break;
	}
  	case SYS_CREATE: {
	  	check_addr_user(p+1);
	  	check_addr_user(p+2);
	  	check_addr_user((void*)*(p+1));
	  	acquire_filesys_lock();
	  	f->eax = filesys_create((void*)*(p+1),*(p+2), false);
	  	release_filesys_lock();
	  	break;
	}
  	case SYS_REMOVE: {
	  	check_addr_user(p+1);
	  	check_addr_user((void*)*(p+1));
	  	acquire_filesys_lock();
	  	f->eax = filesys_remove((void*)*(p+1));
		release_filesys_lock();
	  	break;
	}
  	case SYS_OPEN: {
	  	check_addr_user(p+1);
	  	check_addr_user((void*)*(p+1));
	  	acquire_filesys_lock(); // for task sync read/write
	  	struct file *fptr = filesys_open ((void*)*(p+1));
	  	if (fptr == NULL) f->eax = -1;
	  	else {
	  		struct proc_file *pfile = malloc(sizeof(struct proc_file));
	  		pfile->ptr = fptr;
	  		pfile->fd = thread_current()->fd_count++; // make sure the fd is different
	  	#ifdef FILESYS
	  		struct inode *inode = file_get_inode(fptr);
	  		if (inode && inode_is_directory(inode)) {
	  			pfile->dir = dir_open(inode_reopen(inode));
	  		}
	  		else pfile->dir = NULL;
	  	#endif
	  		ASSERT (pfile->fd >= 2); // 0,1 is stdin/stdout
	  		list_push_back (&thread_current()->files, &pfile->elem);
	  		f->eax = pfile->fd;
	  	}
	    release_filesys_lock();
	  	break;
	}
  	case SYS_FILESIZE: {
	  	check_addr_user(p+1);
	  	struct proc_file *pf = find_pfile(*(p+1));
	  	ASSERT (pf != NULL);
	  	acquire_filesys_lock();
	  	f->eax = file_length(pf->ptr);
	  	release_filesys_lock();
	  	break;
	}
  	case SYS_READ: {
	  	check_addr_user(p+1);
	  	check_addr_user(p+2);
	  	check_addr_user((void*)*(p+2));
	  	check_addr_user(p+3);
	#ifdef VM
	  	if ((uint32_t)(*(p+2)) - 0x08048000 < PGSIZE) {
	  		// write code 2
	  		exit_proc(-1);
	  		break;
	  	}
	#endif
	  	if (*(p+1) == 0) {
	  		// read from keyboard
	  		uint8_t *buffer = (uint8_t*)*(p+2); // ascii 0-255
	  		for (int i = 0; i < *(p+3); i++) buffer[i] = input_getc(); // read into buffer
	  		f->eax = *(p+3);
	  	}
	  	else {
	  		struct proc_file *pf = find_pfile(*(p+1));
	  		if (pf == NULL) f->eax = -1;
	  		else {
	  			acquire_filesys_lock();
	  		#ifdef VM
	  			preload_and_pin_pages(*(p+2),*(p+3));
	  		#endif
	  			f->eax = file_read(pf->ptr, (void*)*(p+2), *(p+3));
	  		#ifdef VM
	  			unpin_preloaded_pages(*(p+2),*(p+3));
	  		#endif
	  			release_filesys_lock();
	  		}
	  	}
	  	break;
	}
  	case SYS_WRITE: {
	  	check_addr_user(p+1);
	  	check_addr_user(p+2);
	  	check_addr_user((void*)*(p+2));
	  	check_addr_user(p+3);
	  	acquire_filesys_lock();
	  	if (*(p+1) == 1) {
	  		// write to the console
	  		putbuf((void*)*(p+2), *(p+3));
	  		f->eax = *(p+3);
	  	}
	  	else {
	  		struct proc_file *pf = find_pfile(*(p+1));
	  		if (pf == NULL) f->eax = -1;
	  		else {
	  			struct inode *inode = file_get_inode(pf->ptr);
	  			ASSERT(inode != NULL);
	  			if (inode_is_directory(inode)) f->eax = -1;
	  			else {
	  			#ifdef VM
	  				preload_and_pin_pages(*(p+2),*(p+3));
	  			#endif
	  				f->eax = file_write(pf->ptr,(void*)*(p+2),*(p+3));
	  			#ifdef VM
	  				unpin_preloaded_pages(*(p+2),*(p+3));
	  			#endif
	  			}
	  		}
	  	}
	  	release_filesys_lock();
	  	break;
	}
  	case SYS_SEEK: {
	  	check_addr_user(p+1);
	  	check_addr_user(p+2);
	  	struct proc_file *pf = find_pfile(*(p+1));
		ASSERT (pf != NULL);
		acquire_filesys_lock();
		file_seek(pf->ptr, *(p+2));
		release_filesys_lock();
	  	break;
	}
  	case SYS_TELL: {
	  	check_addr_user(p+1);
	  	struct proc_file *pf = find_pfile(*(p+1));
	  	acquire_filesys_lock();
	  	f->eax = file_tell(pf->ptr);
	  	release_filesys_lock();
	  	break;
	}
  	case SYS_CLOSE: {
	  	check_addr_user(p+1);
	  	struct proc_file *pf = NULL;
	  	struct list_elem *e;
	  	struct thread *t = thread_current();
	  	for (e = list_begin(&t->files); e != list_end(&t->files); e = list_next(e)) {
	  		pf = list_entry(e, struct proc_file, elem);
	  		if (pf->fd == *(p+1)) break;
	  	}
	  	if (pf == NULL) exit_proc(-1);
	  	acquire_filesys_lock();
	  	file_close(pf->ptr);
	  	if (pf->dir) dir_close(pf->dir);
	  	release_filesys_lock();
	  	list_remove(e);
	  	break;
	}
#ifdef VM
	case SYS_MMAP: {
		check_addr_user(p+1);
		check_addr_user(p+2);
		void *upage = (void*)*(p+2);
		acquire_filesys_lock();
		if (upage == NULL || pg_ofs(upage) || *(p+1) <= 1) goto FAIL;
		struct proc_file *pf = find_pfile(*(p+1));
		if (pf == NULL) goto FAIL;
		struct file *file = file_reopen(pf->ptr);
		if (file == NULL) goto FAIL;
		size_t file_size = file_length(file);
		if (file_size == 0) goto FAIL;
		struct thread *t = thread_current();
		// make sure lazy load
		for (size_t offset = 0; offset < file_size; offset += PGSIZE) {
			void *addr = upage + offset;
			if (page_table_lookup(t->page_table, addr)) goto FAIL;
		}

		// Now, map each page to filesystem
		for (size_t offset = 0; offset < file_size; offset += PGSIZE) {
			void *addr = upage + offset;
			size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
			size_t zero_bytes = PGSIZE - read_bytes;
			page_table_install_filesys(t->page_table, addr,
        		file, offset, read_bytes, zero_bytes, /*writable*/true);
		}
		int mid = t->mid_count++;
		struct mmap_desc *mmap_d = malloc(sizeof(struct mmap_desc));
		mmap_d->mid = mid;
		mmap_d->file = file;
		mmap_d->addr = upage;
		mmap_d->size = file_size;
		list_push_back(&t->mmap_list, &mmap_d->elem);
		f->eax = mid;
		release_filesys_lock();
		break;
		FAIL:
			f->eax = -1;
			release_filesys_lock();
		break;
	}
	case SYS_MUNMAP: {
		check_addr_user(p+1);
		sys_munmap(*(p+1));
		break;
	}
#endif
#ifdef FILESYS
	case SYS_CHDIR: {
		check_addr_user(p+1);
		check_addr_user((void*)*(p+1));
		acquire_filesys_lock();
		struct dir *dir = dir_open_path((char*)*(p+1));
		if (dir == NULL) f->eax = false;
		else {
			dir_close(thread_current()->cwd);
			thread_current()->cwd = dir;
			f->eax = true;
		}
		release_filesys_lock();
		break;
	}
	case SYS_MKDIR: {
		check_addr_user(p+1);
		check_addr_user((void*)*(p+1));
		acquire_filesys_lock();
		f->eax = filesys_create((char*)*(p+1), 0, true);
		release_filesys_lock();
		break;
	}
	case SYS_READDIR: {
		check_addr_user(p+1);
		check_addr_user(p+2);
		check_addr_user((void*)*(p+2));
		acquire_filesys_lock();
		struct proc_file *pf = find_pfile(*(p+1));
		if (pf == NULL) f->eax = false;
		else {
			struct inode *inode = file_get_inode(pf->ptr);
			if (inode == NULL || !inode_is_directory(inode)) f->eax = false;
			else {
				ASSERT (pf->dir != NULL);
				f->eax = dir_readdir(pf->dir, (char*)*(p+2));
			}
		}
		release_filesys_lock();
		break;
	}
	case SYS_ISDIR: {
		check_addr_user(p+1);
		acquire_filesys_lock();
		struct proc_file *pf = find_pfile(*(p+1));
		if (pf == NULL) f->eax = false;
		else {
			struct inode *inode = file_get_inode(pf->ptr);
			if (inode == NULL || !inode_is_directory(inode)) f->eax = false;
			else f->eax = true;
		}
		release_filesys_lock();
		break;
	}
	case SYS_INUMBER: {
		check_addr_user(p+1);
		acquire_filesys_lock();
		struct proc_file *pf = find_pfile(*(p+1));
		struct inode *inode = file_get_inode(pf->ptr);
		f->eax = inode_get_inumber(inode);
		release_filesys_lock();
		break;
	}
#endif
  	default: {
		printf("Default %d\n",*p);
	}
  }
}

