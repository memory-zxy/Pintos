#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

struct hash frame_map;
struct list frame_list;
static struct lock frame_lock;
unsigned frame_hash_func(const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame *entry = hash_entry(elem, struct frame, helem);
  return hash_bytes( &entry->kpage, sizeof(entry->kpage));
}
bool frame_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct frame *a_entry = hash_entry(a, struct frame, helem);
  struct frame *b_entry = hash_entry(b, struct frame, helem);
  return a_entry->kpage < b_entry->kpage;
}

void frame_init() {
  lock_init (&frame_lock);
  hash_init(&frame_map, frame_hash_func,
  frame_less_func, NULL);
  list_init(&frame_list);
}

void* frame_allocate(enum palloc_flags flags, void *upage) {
  void *frame_page = palloc_get_page (PAL_USER | flags);
  if (frame_page == NULL) {
    // no frame, go evict
    struct frame *f_evict = pick_frame_to_evict(thread_current()->pagedir);
    ASSERT (f_evict != NULL);
    ASSERT (pg_ofs (f_evict->kpage) == 0);
    pagedir_clear_page(f_evict->t->pagedir, f_evict->upage);
      bool is_dirty = pagedir_is_dirty(f_evict->t->pagedir,f_evict->upage)
       || pagedir_is_dirty(f_evict->t->pagedir,f_evict->kpage);
    size_t swap_index = swap_out(f_evict->kpage);
    struct page *page = page_table_lookup(f_evict->t->page_table, f_evict->upage);
    ASSERT(page != NULL);
    page->status = ON_SWAP;
    page->kpage = NULL;
    page->swap_index = swap_index;
    page->dirty = page->dirty || is_dirty;
    free_frame(f_evict->kpage);
    frame_page = palloc_get_page (PAL_USER | flags);
    ASSERT(frame_page != NULL);
  } 
  struct frame *frame = malloc(sizeof(struct frame));
  if (frame == NULL) return NULL;
  frame->t = thread_current();
  frame->upage = upage;
  frame->kpage = frame_page;
  frame->pinned = true;
  hash_insert(&frame_map, &frame->helem);
  list_push_back (&frame_list, &frame->lelem);
  return frame_page;
}

void free_frame(void *kpage) {
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); // should be aligned

  struct frame tmp;
  tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(tmp.helem));
  if (h == NULL) PANIC ("no such page");
  struct frame *f = hash_entry(h, struct frame, helem);
  hash_delete(&frame_map, &f->helem);
  list_remove(&f->lelem);
  palloc_free_page(kpage);
  free(f);
}

void frame_remove_page(void *kpage) {
  struct frame tmp;
  tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(tmp.helem));
  if (h == NULL) PANIC ("no such page");
  struct frame *f = hash_entry(h, struct frame, helem);
  hash_delete(&frame_map, &f->helem);
  list_remove(&f->lelem);
  free(f);
}

struct frame *pick_frame_to_evict(uint32_t *pagedir) {
  int size = list_size(&frame_list);
  if (size == 0) {
    PANIC("Frame table is empty");
  }
  struct list_elem *e = list_begin(&frame_list);
  struct frame *f;
  for (int i = 0; i <= 2 * size; i++) {
    f = list_entry(e, struct frame, lelem);
    if (pagedir_is_accessed(pagedir, f->upage)) {
      // referenced before, pass
      pagedir_set_accessed(pagedir, f->upage, false);
          if (e != list_end(&frame_list)) e = list_next(e);
      else e = list_begin(&frame_list);
          continue;
    }
    else if (f->pinned) {
      if (e != list_end(&frame_list)) e = list_next(e);
      else e = list_begin(&frame_list);
      continue;
    }
    ASSERT (pg_ofs (f->kpage) == 0);
    return f;
  }
  PANIC("No frame to evict");     
}

void
vm_frame_unpin (void* kpage) {
  struct frame f_tmp;
  f_tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }

  struct frame *f = hash_entry(h, struct frame, helem);
  f->pinned = false;
}

void
vm_frame_pin (void* kpage) {
  struct frame f_tmp;
  f_tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }

  struct frame *f = hash_entry(h, struct frame, helem);
  f->pinned = true;
}