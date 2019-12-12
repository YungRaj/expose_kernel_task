#include "page_table.h"

// this code may end up not ever being used, but this is here to help me understand
// the underlying implementation of paging inside aarch64
// this is not for production, this example was used to create a small mapping inside el1

#define PAGE_SIZE 0x400

// Create an L0, L1, or L2 TTE entry for 48-bit OAs.
#define TTE_L012_48b(NSTable, APTable, XNTable, PXNTable, Ignored_58_52, OA, Ignored_11_2)	\
					(((uint64_t) (NSTable) << 63) | \
	 				((uint64_t) (APTable) << 61) | \
	 				((uint64_t) (XNTable) << 60) | \
	 				((uint64_t) (PXNTable) << 59) | \
	 				((uint64_t) (Ignored_58_52) << 52) | \
	 				((uint64_t) (OA)) | \
	 				((uint64_t) (Ignored_11_2) << 2) | \
	 				0b11)

// Create an L3 TTE entry for a 16k page.
#define TTE_L3_16k(Ignored_63, PBHA, Ignored_58_55, UXN, PXN, Contiguous, DBM, OA, \
					nG, AF, SH, AP, NS, AttrIdx) \
					(((uint64_t) (Ignored_63) << 63) | \
	 				((uint64_t) (PBHA) << 59) | \
	 				((uint64_t) (Ignored_58_55) << 55) | \
	 				((uint64_t) (UXN) << 54) | \
	 				((uint64_t) (PXN) << 53) | \
	 				((uint64_t) (Contiguous) << 52) | \
	 				((uint64_t) (DBM) << 51) | \
	 				((uint64_t) (OA)) | \
	 				((uint64_t) (nG) << 11) | \
					((uint64_t) (AF) << 10) | \
					((uint64_t) (SH) << 8) | \
					((uint64_t) (AP) << 6) | \
					((uint64_t) (NS) << 5) | \
					((uint64_t) (AttrIdx) << 2) | \
					0b11)

static const unsigned l1_size = 3;
static const unsigned l2_size = 11;
static const unsigned l3_size = 11;
static const unsigned pg_bits = 14;
static const unsigned phys_bits = 40;
static const uint64_t tt1_base = -(1uL << (l1_size + l2_size + l3_size + pg_bits));

static inline uint64_t bits64(uint64_t value, unsigned hi, unsigned lo, unsigned shift)
{
	return (((value << (63 - hi)) >> (63 - hi + lo)) << shift);
}

static inline uint64_t disable_interrupts()
{
	uint64_t daif;
	
	asm volatile("mrs %0, DAIF" : "=r"(daif));
	asm volatile("msr DAIFset, #0xf");

	return daif;
}

static inline void enable_interrupts(uint64_t daif)
{
	asm volatile("msr DAIF, %0" :: "r"(daif));
}

#define isb() asm volatile("isb")
#define dmb(_type) asm volatile("dmb " #_type)
#define dsb(_type) asm volatile("dsb " #_type)

// performs address translation
uint64_t kernel_virtual_to_physical(uint64_t kaddr)
{
	uint64_t daif, par_el1;

	daif = disable_interrupts();
	asm volatile("at s1e1r, %0" : : "r"(kaddr));
	isb();
	asm volatile("mrs %0, PAR_EL1" : "=r"(par_el1));
	enable_interrupts(daif);

	if(par_el1 & 0x1)
		return -1;

	return (bits64(par_el1, 47, 12, 12) | bits64(kaddr, 11, 0, 0));
}

// invalidates the cache
void cache_invalidate(void *address, size_t size)
{
	uint64_t cache_line_size = 64;

	// calculate an address to invalid a cache line for
	// start address -> end to invalidate all cache lines for address
	uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
	uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);

	for(uint64_t addr = start; addr < end; addr += cache_line_size)
		asm volatile("dc civac, %0" :: "r"(addr));

	dmb(sy);
}

void cache_clean_and_invalidate(void *address, size_t size)
{
	uint64_t cache_line_size = 64;

	// calculate an address to invalid a cache line for
	// start address -> end to invalidate all cache lines for address
	uint64_t start = ((uintptr_t) address) & ~(cache_line_size - 1);
	uint64_t end = ((uintptr_t) address + size + cache_line_size - 1) & ~(cache_line_size - 1);

	for (uint64_t addr = start; addr < end; addr += cache_line_size)
		asm volatile("dc civac, %0" : : "r"(addr));

	dmb(sy);
}

// ttbr0_el1 memory mapping
// normally the way to do this is ml_phys_read/write_data() inside the kernel
// this primitive allows us to map 0x1_0000_0000 to the physical page of our choosing
// once you obtain the kernel virtual address of this mapping, you can whatever you like

// it is easier to set up page tables for a direct virtual to physical in TTBR0, but a lot of
// memory ends up being used by the page table, (no leveled page mappings)

static const uint64_t map_base = 7uLL << (l2_size + l3_size + pg_bits);
static const uint64_t map_size = 1uLL << (l3_size + pg_bits);

// The L1 page table. Only 8 entries are used.
__attribute__((aligned(PAGE_SIZE)))
static uint8_t l1_page_table[PAGE_SIZE];

// The L2 page table. Only 1 entry is used.
__attribute__((aligned(PAGE_SIZE)))
static uint8_t l2_page_table[PAGE_SIZE];

// The L3 page table.
__attribute__((aligned(PAGE_SIZE)))
static uint8_t l3_page_table[PAGE_SIZE];

// Access the page tables via TTEs.
static uint64_t *const l1_ttes = (uint64_t *)l1_page_table;
static uint64_t *const l2_ttes = (uint64_t *)l2_page_table;
static uint64_t *const l3_ttes = (uint64_t *)l3_page_table;

// issue a data and instruction synchronization barrier
static inline void synchronize_page_table()
{
	dsb(sy);
	isb();
}

static uint64_t ttbr0_l3_index_to_vaddr(uint64_t l3_index)
{
	return map_base + l3_index * PAGE_SIZE;
}

void page_tables_init()
{
	static bool initialized = false;

	if(initialized)
		return;

	initialized = true;

	// get the physical address of the l1-l3 page tables
	uint64_t l1_table_phys = kernel_virtual_to_physical((uintptr_t) l1_page_table);
	uint64_t l2_table_phys = kernel_virtual_to_physical((uintptr_t) l2_page_table);
	uint64_t l3_table_phys = kernel_virtual_to_physical((uintptr_t) l3_page_table);

	uint64_t ttbr0_el1 = l1_table_phys;

	// initialize the base of the page table hierarchy
	uint64_t l1_index = (map_base >> (l2_size + l3_size + pg_bits));
	uint64_t l2_index = (map_base >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);

	// set the page table entry with the physical address of page tables
	l1_ttes[l1_index] = TTE_L012_48b(0, 0, 0, 0, 0, l2_table_phys, 0);
	l2_ttes[l2_index] = TTE_L012_48b(0, 0, 0, 0, 0, l3_table_phys, 0);
	
	// set the ttbr0_el1 value
	asm volatile("msr TTBR0_EL1, %0" : : "r"(ttbr0_el1));

	synchronize_page_table();
}

void* ttbr0_map(uint64_t paddr, size_t size, unsigned attr)
{
	paddr = bits64(paddr, 39, 14, 14);

	size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	// find contiguous empty l3 entries big enough to build mapping
	size_t l3_entry_count = PAGE_SIZE / sizeof(uint64_t);
	size_t l3_index = 0;
	size_t l3_count = 0;

	// skip first index, reserved for temporary fasting mappings
	for(size_t index = 1; index < l3_entry_count; index++)
	{
		if((l3_ttes[index] & 0x1) == 0)
		{
			// empty entry, add it to current one
			if(l3_count == 0)
				l3_index = index;

			l3_count ++;

			if(l3_count >= page_count)
				goto found;
		} else
			l3_count = 0;
	}

	return NULL;

found:
	// we found a contiguous set of l3 entries, map them
	for(size_t i = 0; i < l3_count; i++)
	{
		l3_ttes[l3_index + i] = TTE_L3_16k(0, 0, 0, 1, 0, 0, 0, paddr + PAGE_SIZE * i,
				1, 1, SH_OUTER, AP_RWNA, 0, attr);
	}

	// ensures writes to page table finished
	synchronize_page_table();

	// return address corresponding to this entry
	return (void*)ttbr0_l3_index_to_vaddr(l3_index);
}

void ttbr0_unmap(void *address, size_t size)
{
	uint64_t vaddr = ((uint64_t)address) & ~(PAGE_SIZE - 1);

	size_t page_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;

	// check address range
	if(!(map_base <= vaddr && vaddr + page_count * PAGE_SIZE <= map_base + map_size))
		return;

	// make sure writes to mapping are complete
	synchronize_page_table();
	// clear TTE's from L3
	uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);

	for(size_t i = 0; i < page_count; i++)
	{
		l3_ttes[l3_index + 0] = 0;
	}

	// make sure writes to page table finished
	synchronize_page_table();
	// invalidate old tlb buffer entries
	for(size_t i = 0; i < page_count; i++)
	{
		vaddr = ttbr0_l3_index_to_vaddr(l3_index + i);
		asm volatile("tlbi vaae1is, %0" : : "r"(vaddr >> 12));
	}
	// instruction sychronization barrier to make sure invalidation finished
	isb();
}

static void* ttbr0_fast_map(uint64_t paddr, unsigned attr)
{
	// finish writes to mapping
	synchronize_page_table();
	// add TTE to map page, sets UXN = 1, PXN = 0, SH = 10, and AP = 00.
	l3_ttes[0] = TTE_L3_16k(0, 0, 0, 1, 0, 0, 0, paddr, 1, 1, SH_OUTER, AP_RWNA, 0, attr);
	// synchronize to ensure new entry is in place
	synchronize_page_table();
	// invalid tlb buffer mapping
	uint64_t vaddr = ttbr0_l3_index_to_vaddr(0);
	asm volatile("tlbi vaae1is, %0" : : "r"(vaddr >> 12));
	// ensure invalidation of tlb buffer complete
	synchronize_page_table();
	// return virtual address
	return (void*)vaddr;
}

uint64_t physical_mem_read_64(uint64_t paddr)
{
	// map as device memory
	uint64_t offset = paddr & (PAGE_SIZE - 1);
	uint8_t *page = ttbr0_fast_map(paddr - offset, ATTR_Device_nGnRnE);
	return *(volatile uint64_t*)(page + offset);
}

void physical_mem_write_64(uint64_t paddr, uint64_t value)
{
	// map as device memory
	uint64_t offset = paddr & (PAGE_SIZE - 1);
	uint8_t *page = ttbr0_fast_map(paddr - offset, ATTR_Device_nGnRnE);
	*(volatile uint64_t*)(page + offset) = value;
}

// modify page tables

// read TTBR1_EL1
static inline uint64_t read_ttbr1_el1()
{
	uint64_t ttbr1_el1;

	asm volatile("mrs %0, TTBR1_EL1" : "=r"(ttbr1_el1));

	return ttbr1_el1;
}

// look up in the page table
static uint64_t aarch64_page_table_lookup(uint64_t ttb,
										  uint64_t vaddr,
										  uint64_t *p_l1_tte0, uint64_t *l1_tte0,
										  uint64_t *p_l2_tte0, uint64_t *l2_tte0,
										  uint64_t *p_l3_tte0, uint64_t *l3_tte0,
										  uint64_t *vaddr_next)
{
	if(vaddr < tt1_base)
	{
		if(vaddr_next)
			*vaddr_next = tt1_base;

		return -1;
	}

	const uint64_t tte_physaddr_mask = ((1uLL << phys_bits) - 1) & ~((1 << pg_bits) - 1);
	uint64_t l1_table = ttb;

	uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
	uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((vaddr >> l2_size) - 1);
	uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);

	uint64_t page_offset = vaddr & ((1 << pg_bits) - 1);
	uint64_t p_l1_tte = l1_table + 8 * l1_index;

	if(p_l1_tte0)
		*p_l1_tte0 = p_l1_tte;

	uint64_t l1_tte = physical_mem_read_64(p_l1_tte);

	if(l1_tte0)
		*l1_tte0 = l1_tte;

	if((l1_tte & 3) != 3)
	{
		if(vaddr_next)
		{
			uint64_t l1_span = 1uL << (l2_size + l3_size + pg_bits);
			*vaddr_next = (vaddr & ~(l1_span - 1)) + l1_span;
		}

		return -1;
	}

	uint64_t l2_table = l1_tte & tte_physaddr_mask;
	uint64_t p_l2_tte = l2_table + 8 * l2_index;
	
	if (p_l2_tte0)
		*p_l2_tte0 = p_l2_tte;


	uint64_t l2_tte = physical_mem_read_64(p_l2_tte);

	if(l2_tte0)
		*l2_tte0 = l2_tte;

	if((l2_tte & 3) != 3)
	{
		if(vaddr_next)
		{
			uint64_t l2_span = 1uL << (l3_size + pg_bits);
			*vaddr_next = (vaddr & ~(l2_span - 1)) + l2_span;
		}

		return -1;
	}

	uint64_t l3_table = l2_tte & tte_physaddr_mask;
	uint64_t p_l3_tte = l3_table + 8 * l3_index;
	
	if (p_l3_tte0)
		*p_l3_tte0 = p_l3_tte;

	uint64_t l3_tte = physical_mem_read_64(p_l3_tte);

	if(l3_tte0)
		*l3_tte0 = l3_tte;

	if(vaddr_next)
	{
		uint64_t l3_span = 1uL << (pg_bits);
		*vaddr_next = (vaddr & ~(l3_span - 1)) + l3_span;
	}

	if((l3_tte & 3) != 3)
		return -1;

	uint64_t frame = l3_tte & tte_physaddr_mask;
	return frame | page_offset;
}

bool ttbr1_page_table_set_page_attributes(void *page,
										  unsigned uxn, unsigned pxn, unsigned sh, unsigned ap, unsigned attr)
{
	uint64_t l3_tte_mask, new_bits, ttbr1_el1;
	
	l3_tte_mask = TTE_L3_16k(0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0x3, 0x3, 0, 0x7);
	new_bits = TTE_L3_16k(0, 0, 0, !!uxn, !!pxn, 0, 0, 0, 0, 0, sh, ap, 0, attr);
	ttbr1_el1 = read_ttbr1_el1();
	
	uint64_t p_l3_tte, l3_tte;

	uint64_t phys = aarch64_page_table_lookup(ttbr1_el1, (uint64_t) page,
			NULL, NULL, NULL, NULL, &p_l3_tte, &l3_tte, NULL);
	
	if (phys == -1)
		return false;

	uint64_t new_l3_tte = (l3_tte & ~l3_tte_mask) | new_bits;

	physical_mem_write_64(p_l3_tte, new_l3_tte);

	return true;
}

size_t ttbr1_page_table_swap_physical_page(uint64_t paddr_old, uint64_t paddr_new)
{
	uint64_t phys_mask, l3_tte_mask, new_bits, ttbr1_el1;
	page_table_sync();
	
	phys_mask = (1uL << phys_bits) - (1uL << pg_bits);
	
	l3_tte_mask = TTE_L3_16k(0, 0, 0, 0, 0, 0, 0, phys_mask, 0, 0, 0, 0, 0, 0);
	new_bits    = TTE_L3_16k(0, 0, 0, 0, 0, 0, 0, paddr_new, 0, 0, 0, 0, 0, 0);
	ttbr1_el1 = read_ttbr1_el1();
	
	uint64_t va = 0;
	size_t changed = 0;
	
	while(1)
	{
		uint64_t p_l3_tte, l3_tte, va_next;
		
		uint64_t phys = aarch64_page_table_lookup(ttbr1_el1, va,
				NULL, NULL, NULL, NULL, &p_l3_tte, &l3_tte, &va_next);

		if (phys == paddr_old)
		{
			uint64_t new_l3_tte = (l3_tte & ~l3_tte_mask) | new_bits;
			
			physical_mem_write_64(p_l3_tte, new_l3_tte);
			changed++;
		}
		
		va = va_next;
		
		if (va == 0)
			break;
	}

	asm volatile("tlbi vmalle1is");

	page_table_sync();

	return changed;
}

void
page_table_sync() {
	synchronize_page_table();
}

