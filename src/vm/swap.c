#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"

static struct block *swap_block;
static struct bitmap *swap_available;
static const size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;
static size_t swap_size;

void swap_init(void) {
  swap_block = block_get_role(BLOCK_SWAP);
  ASSERT(swap_block != NULL);
  swap_size = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_available = bitmap_create(swap_size);
  bitmap_set_all(swap_available, true);
}

size_t swap_out(void *kpage) {
  // find an available block
  size_t swap_index = bitmap_scan (swap_available, 0, 1, true);
  for (size_t i = 0; i < SECTORS_PER_PAGE; i++) {
    block_write(swap_block,
          /* sector number */  swap_index * SECTORS_PER_PAGE + i,
          /* target address */ kpage + (BLOCK_SECTOR_SIZE * i)
          );
  }
  bitmap_set(swap_available, swap_index, false);
  return swap_index;
}

void swap_in(size_t swap_index, void *kpage) {
  ASSERT(swap_index < swap_size);
  if (bitmap_test(swap_available, swap_index) == true) {
      // still available slot, error
      PANIC ("Error, invalid read access to unassigned swap block");
    }

    size_t i;
    for (i = 0; i < SECTORS_PER_PAGE; ++ i) {
      block_read (swap_block,
          /* sector number */  swap_index * SECTORS_PER_PAGE + i,
          /* target address */ kpage + (BLOCK_SECTOR_SIZE * i)
          );
    }

    bitmap_set(swap_available, swap_index, true);
}

void
free_swap (size_t swap_index)
{
  // check the swap region
  ASSERT (swap_index < swap_size);
  if (bitmap_test(swap_available, swap_index) == true) {
    PANIC ("Error, invalid free request to unassigned swap block");
  }
  bitmap_set(swap_available, swap_index, true);
}

