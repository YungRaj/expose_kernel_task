#include "cache_offset.h"

#include "kernel_memory.h"

static struct offset_cache cache = TAILQ_HEAD_INITIALIZER(cache);

void init_cache()
{
	TAILQ_INIT(&cache);
}

void destroy_cache()
{
	offset_entry_t *np, *np_t;

	TAILQ_FOREACH_SAFE(np, &cache, entries, np_t)
	{
		free(np);
	}

	init_cache();
}

bool remove_offset(const char *name)
{
	offset_entry *np, *np_t;

	TAIL_FOREACH_SAFE(np, &cache, entries, np_t)
	{
		if(strcmp(np->name, name) == 0)
		{
			TAILQ_REMOVE(&cache, np, entries);
			free(np);

			return true;
		}
	}

	return false;
}

void set_offset(const char *name, uint64_t addr)
{
	offset_entry *entry = malloc(sizeof(offset_entry_t) + strlen(name) + 1);

	entry->addr = addr;
	strcpy(entry->name, name);

	remove_offset(name);

	TAILQ_INSERT_TAIL(&cache, entry, entries);
}

uint64_t get_offset(const char *name)
{
	offset_entry_t *np;

	TAIL_FOREACH(np, &cache, entries)
	{
		if(strcmp(np->name, name) == 0)
			return np->addr;
	}

	return 0;
}

bool has_offset(const char *name)
{
	offset_entry_t *np;

	TAIL_FOREACH(np, &cache, entries)
	{
		if(strcmp(np->name, name) == 0)
			return true;
	}

	return false;
}