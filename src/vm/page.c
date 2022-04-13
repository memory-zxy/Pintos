#include <hash.h>
#include <string.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "filesys/file.h"

static unsigned
page_hash_func(const struct hash_elem *elem, void *aux UNUSED) {
  struct page *page = hash_entry(elem, struct page, helem);
  return hash_int( (int)page->upage );
}
static bool
page_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  struct page *page_a = hash_entry(a, struct page, helem);
  struct page *page_b = hash_entry(b, struct page, helem);
  return page_a->upage < page_b->upage;
}
static void
page_destroy_func(struct hash_elem *helem, void *aux UNUSED) {
  struct page *page = hash_entry(helem, struct page, helem);
  if (page->kpage != NULL) {
    ASSERT(page->status == ON_FRAME);
    frame_remove_page(page->kpage);
  }
  else if(page->status == ON_SWAP) {
      free_swap (page->swap_index);
  }
  free(page);
}
struct hash* page_table_init(void) {
  struct hash *page_table = malloc(sizeof(struct hash));
  hash_init(page_table, page_hash_func, page_less_func, NULL);
  return page_table;
}

bool page_table_install_frame(struct hash *page_table, void *upage, void *kpage) {
  struct page *page = malloc(sizeof(struct page));
  page->upage = upage;
  page->kpage = kpage;
  page->status = ON_FRAME;
  page->dirty = false;
  page->swap_index = -1;
  if (!hash_insert(page_table, &page->helem)) return true;
  else {
    // failed
    free(page);
    return false;
  }
}

bool page_table_install_zeropage(struct hash *page_table, void *upage) {
  struct page *page = malloc(sizeof(struct page));
  page->upage = upage;
  page->kpage = NULL;
  page->status = ALL_ZERO;
  page->dirty = false;
  if (!hash_insert(page_table, &page->helem)) return true;
  else {
    // failed
    free(page);
    return false;
  }
}

bool page_table_install_filesys (struct hash *page_table, void *upage,
    struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  struct page *page = (struct page *) malloc(sizeof(struct page));
  page->upage = upage;
  page->kpage = NULL;
  page->status = FROM_FILESYS;
  page->dirty = false;
  page->file = file;
  page->file_offset = offset;
  page->read_bytes = read_bytes;
  page->zero_bytes = zero_bytes;
  page->writable = writable;

  if (!hash_insert (page_table, &page->helem)) return true;
  // there is already an entry -- impossible state
  PANIC("Duplicated SUPT entry for filesys-page");
}

void page_table_destroy(struct hash *page_table) {
  hash_destroy(page_table, page_destroy_func);
  free(page_table);
}

struct page* page_table_lookup(struct hash *page_table, void *upage) {
  struct page tmp;
  tmp.upage = upage;
  struct hash_elem *helem = hash_find(page_table,&tmp.helem);
  if (helem == NULL) return NULL;
  return hash_entry(helem, struct page, helem);
}
static bool page_table_load_from_filesys(struct page *, void *);

bool
page_table_load(struct hash *page_table, uint32_t *pagedir, void *upage)
{
  /* see also userprog/exception.c */

  // 1. Check if the memory reference is valid
  struct page *page;
  page = page_table_lookup(page_table, upage);
  if(page == NULL) {
    return false;
  }

  if(page->status == ON_FRAME) {
    // already loaded
    return true;
  }

  // 2. Obtain a frame to store the page
  void *frame_page = frame_allocate(PAL_USER, upage);
  if(frame_page == NULL) {
    return false;
  }
  // 3. Fetch the data into the frame
  bool writable = true;
  switch (page->status)
  {
  case ALL_ZERO:
    memset (frame_page, 0, PGSIZE);
    break;

  case ON_FRAME:
    /* nothing to do */
    break;

  case ON_SWAP:
    // Swap in: load the data from the swap disc
    swap_in (page->swap_index, frame_page);
    break;

  case FROM_FILESYS:
    if( page_table_load_from_filesys(page, frame_page) == false) {
      free_frame(frame_page);
      return false;
    }

    writable = page->writable;
    break;

  default:
    PANIC ("unreachable state");
  }

  // 4. Point the page table entry for the faulting virtual address to the physical page.
  if(!pagedir_set_page (pagedir, upage, frame_page, writable)) {
    free_frame(frame_page);
    return false;
  }

  // Make SURE to mapped kpage is stored in the page.
  page->kpage = frame_page;
  page->status = ON_FRAME;
  vm_frame_unpin(frame_page); // can be evicted
  pagedir_set_dirty (pagedir, frame_page, false);
  return true;
}

static bool page_table_load_from_filesys(struct page *page, void *kpage)
{
  file_seek (page->file, page->file_offset);

  // read bytes from the file
  int n_read = file_read (page->file, kpage, page->read_bytes);
  if(n_read != (int)page->read_bytes)
    return false;

  // remain bytes are just zero
  ASSERT (page->read_bytes + page->zero_bytes == PGSIZE);
  memset (kpage + n_read, 0, page->zero_bytes);
  return true;
}




bool
page_table_mm_unmap(
    struct hash *page_table, uint32_t *pagedir,
    void *upage, struct file *f, off_t offset, size_t bytes)
{
  struct page *page = page_table_lookup(page_table, upage);
  if(page == NULL) {
    PANIC ("munmap - some page is missing; can't happen!");
  }

  // Pin the associated frame if loaded
  // otherwise, a page fault could occur while swapping in (reading the swap disk)
  if (page->status == ON_FRAME) {
    vm_frame_pin(page->kpage);  
  }


  // see also, page_table_load()
  switch (page->status)
  {
  case ON_FRAME:
    ASSERT (page->kpage != NULL);

    // Dirty frame handling (write into file)
    // Check if the upage or mapped frame is dirty. If so, write to file.
    bool is_dirty = page->dirty || pagedir_is_dirty(pagedir, page->upage) || pagedir_is_dirty(pagedir, page->kpage);
    if(is_dirty) {
      file_write_at (f, page->upage, bytes, offset);
    }

    // clear the page mapping, and release the frame
    free_frame (page->kpage);
    pagedir_clear_page (pagedir, page->upage);
    break;

  case ON_SWAP:
    {
      bool is_dirty = page->dirty || pagedir_is_dirty(pagedir, page->upage);
      if (is_dirty) {
        // load from swap, and write back to file
        void *tmp_page = palloc_get_page(0); // in the kernel
        swap_in (page->swap_index, tmp_page);
        file_write_at (f, tmp_page, PGSIZE, offset);
        palloc_free_page(tmp_page);
      }
      else {
        // just throw away the swap.
        free_swap (page->swap_index);
      }
    }
    break;

  case FROM_FILESYS:
    // do nothing.
    break;

  default:
    // Impossible, such as ALL_ZERO
    PANIC ("unreachable state");
  }

  // the supplemental page table entry is also removed.
  // so that the unmapped memory is unreachable. Later access will fault.
  hash_delete(page_table, &page->helem);
  return true;
}

