#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "lib/stdbool.h"
#include "devices/block.h"

struct cache_entry {
	bool used;
	bool dirty;
	uint8_t buffer[BLOCK_SECTOR_SIZE];
	block_sector_t disk_sector;
	bool reference;
};

void cache_init(void);
void cache_close(void);
void cache_read(block_sector_t sector, void *addr);
void cache_write(block_sector_t sector, void *addr);

#endif