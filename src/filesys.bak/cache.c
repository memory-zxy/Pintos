#include <debug.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

#define CACHE_SIZE 64


static struct lock cache_lock;
static struct cache_entry cache[CACHE_SIZE];

void cache_init(void) {
	lock_init(&cache_lock);
	for (int i = 0; i < CACHE_SIZE; i++) {
		cache[i].used = false;
	}
}
static void cache_flush(struct cache_entry *entry) {
	// write dirty block to disk
	ASSERT (lock_held_by_current_thread(&cache_lock));
	ASSERT (entry->used == true);
	if (entry->dirty) {
		block_write (fs_device, entry->disk_sector, entry->buffer);
		entry->dirty = false;
	}
}
void cache_close(void) {
	lock_acquire(&cache_lock);
	for (int i = 0; i < CACHE_SIZE; i++) {
		if (cache[i].used) cache_flush(&cache[i]);
	}
	lock_release(&cache_lock);
} 
static struct cache_entry *cache_evict(void) {
	for (int i = 0;; i++) {
		i = i % CACHE_SIZE;
		if (!cache[i].used) return &cache[i];
		if (cache[i].reference) {
			cache[i].reference = false;
			continue;
		}
		cache_flush(&cache[i]);
		cache[i].used = false;
		return &cache[i];
	}
	PANIC ("no cache entry can be evicted");
}
static struct cache_entry *cache_lookup(block_sector_t sector) {
	for (int i = 0; i < CACHE_SIZE; i++) {
		if (cache[i].used && cache[i].disk_sector == sector) return &cache[i];
	}
	return NULL;
}
void cache_read(block_sector_t sector, void *addr) {
	lock_acquire(&cache_lock);
	struct cache_entry *entry = cache_lookup(sector);
	if (entry == NULL) {
		// cache miss, go evict
		entry = cache_evict();
		ASSERT(entry != NULL && entry->used == false);
		entry->used = true;
		entry->disk_sector = sector;
		entry->dirty = false;
		block_read(fs_device, sector, entry->buffer);
	}
	entry->reference = true;
	memcpy(addr, entry->buffer, BLOCK_SECTOR_SIZE);
	lock_release(&cache_lock);
}
void cache_write(block_sector_t sector, void *addr) {
	lock_acquire(&cache_lock);
	struct cache_entry *entry = cache_lookup(sector);
	if (entry == NULL) {
		// cache miss, go evict
		entry = cache_evict();
		ASSERT(entry != NULL && entry->used == false);
		entry->used = true;
		entry->disk_sector = sector;
		entry->dirty = false;
		block_read(fs_device, sector, entry->buffer);
	}
	entry->reference = true;
	entry->dirty = true;
	memcpy(entry->buffer, addr, BLOCK_SECTOR_SIZE);
	lock_release(&cache_lock);
}