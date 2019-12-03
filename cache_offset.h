#ifndef CACHE_OFFSETS__H_
#define CACHE_OFFSETS__H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "parameters.h"

typedef struct offset_entry {
    TAILQ_ENTRY(offset_entry) entries;
    uint64_t addr;
    char name[];
} offset_entry_t;


TAILQ_HEAD(offset_cache, offset_entry);

/*
 * struct cache_blob {
 * 	size_t size;
 *  struct offset_cache cache;
 *  offset_entry_t entries[];
 * };
 */

void destroy_cache();

bool remove_offset(const char *name);

void set_offset(const char *name, uint64_t address);
uint64_t get_offset(const char *name);
bool has_offset(const char *name);

#endif