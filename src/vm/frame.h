#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <hash.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/palloc.h"

struct frame {
	struct thread *t;
	void *kpage; // frame page
	void *upage; // user page
	struct hash_elem helem;
	struct list_elem lelem;
	bool pinned; // if true, never evicted
};

void frame_init (void);
unsigned frame_hash_func(const struct hash_elem *elem,
	void *aux UNUSED);
bool frame_less_func(const struct hash_elem *a,
	const struct hash_elem *b, void *aux UNUSED);
void* frame_allocate(enum palloc_flags flags, void *upage);
struct frame *pick_frame_to_evict(uint32_t *pagedir);
void free_frame(void *kpage);
void frame_remove_page(void *kpage);
void vm_frame_pin (void* kpage);
void vm_frame_unpin (void* kpage);

#endif /* vm/frame.h */