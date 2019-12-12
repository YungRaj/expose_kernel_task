#ifndef PAGE_TABLE__H_
#define PAGE_TABLE__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SH_NONE		0x0
#define SH_OUTER	0x2
#define SH_INNER	0x3

#define AP_RWNA		0x0
#define AP_RWRW		0x1
#define AP_RONA		0x2
#define AP_RORO		0x3

#define ATTR_Normal_WriteBack		0
#define ATTR_Normal_NonCacheable	1
#define ATTR_Normal_WriteThrough	2
#define ATTR_Device_nGnRnE		3
#define ATTR_Device_nGnRE		5


uint64_t kernel_virtual_to_physical(uint64_t kaddr);

void cache_invalidate(void *address, size_t size);
void cache_clean_and_invalidate(void *address, size_t size);
void cache_clean_and_invalidate(void *address, size_t size);

void page_tables_init();

void* ttbr0_map(uint64_t paddr, size_t size, unsigned attr);
#define ttbr0_map_io(paddr, size) tbr0_map(paddr, size, ATTR_Device_nGnRnE)

void ttbr0_unmap(void *address, size_t size);

uint64_t physical_mem_read_64(uint64_t paddr);
void physical_mem_write_64(uint64_t paddr, uint64_t value);

bool ttbr1_page_table_set_page_attributes(void *page, unsigned uxn, unsigned pxn,
										  unsigned sh, unsigned ap, unsigned attr);
size_t ttbr1_page_table_swap_physical_page(uint64_t paddr_old, uint64_t paddr_new);

void page_table_sync();

#endif