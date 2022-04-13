#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "devices/block.h"
#include "filesys/off_t.h"
#include "threads/synch.h"

enum page_status {
  ALL_ZERO,         // All zeros
  ON_FRAME,         // Actively in memory
  ON_SWAP,          // Swapped (on swap slot)
  FROM_FILESYS      // from filesystem (or executable)
};

struct page {
  void *kpage;
  void *upage;
  bool dirty;
  size_t swap_index;
  struct file *file;
  off_t file_offset;
  uint32_t read_bytes, zero_bytes;
  bool writable;
  enum page_status status;
  struct hash_elem helem;
};

struct hash* page_table_init(void);
void page_table_destroy(struct hash *page_table);
bool page_table_install_frame(struct hash *page_table, void *upage, void *kpage);
bool page_table_install_zeropage(struct hash *page_table, void *upage);
bool page_table_install_filesys (struct hash *page_table, void *upage,
    struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
struct page* page_table_lookup(struct hash *page_table, void *upage);
bool page_table_mm_unmap(struct hash *supt, uint32_t *pagedir,
    void *page, struct file *f, off_t offset, size_t bytes);
bool
page_table_load(struct hash *page_table, uint32_t *pagedir, void *upage);
#endif /* vm/page.h */
