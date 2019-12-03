#include "patchfinder.h"

#include "kernel_memory.h"
#include "tasks.h"
#include "slide.h"

#include "mach_vm.h"

#define UCHAR_MAX 255

static unsigned char * needle_haystack_memmem(const unsigned char *haystack, size_t hlen,
											  const unsigned char *needle, size_t nlen)
{
	size_t last, scan = 0;

	size_t bad_char_skip[UCHAR_MAX + 1];

	if(nlen <= 0 || !haystack || !needle)
		return NULL;

	for(scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
		bad_char_skip[scan] = nlen;
	
	last = nlen - 1;

	for(scan = 0; scan < last; scan = scan + 1)
		bad_char_skip[needle[scan]] = last - scan;

	while(hlen >= nlen)
	{
		for(scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
			if(scan == 0)
				return (void*) haystack;

		hlen -= bad_char_skip[haystack[last]];
		haystack += bad_char_skip[haystack[last]];
	}

	return NULL;
}

static mach_vm_address_t kern_entry_point = 0;
static mach_vm_address_t kerndumpbase = -1;

static mach_vm_address_t xnucore_base = 0;
static mach_vm_address_t xnucore_size = 0;
static mach_vm_address_t ppl_base = 0;
static mach_vm_address_t ppl_size = 0;
static mach_vm_address_t cstring_base = 0;
static mach_vm_address_t cstring_size = 0;
static mach_vm_address_t oslstring_base = 0;
static mach_vm_address_t oslstring_size = 0;
static mach_vm_address_t data_base = 0;
static mach_vm_address_t data_size = 0;
static mach_vm_address_t data_const_base = 0;
static mach_vm_address_t data_const_size = 0;
static mach_vm_address_t const_base = 0;
static mach_vm_address_t const_size = 0;

#define IS64(image) (*(uint8_t *)(image) & 1)

int init_kern()
{
	bool ok;

	uint8_t buf[0x4000];

	unsigned int i, j;

	const struct mach_header *hdr = (struct mach_header*) buf;
	const uint8_t *q;

	mach_vm_address_t min = -1;
	mach_vm_address_t max = 0;

	int is64 = false;

	ok = kernel_read(kernel_base, buf, sizeof(buf));

	if(!ok)
		return -1;

	if(IS64(buf))
		is64 = 4;

	q = buf + sizeof(struct mach_header) + is64;

	for(i = 0; i < hdr->ncmds; i++)
	{
		const struct load_command *cmd = (struct load_command*)q;

		if(cmd->cmd == LC_SEGMENT_64)
		{
			const struct segment_command_64 *seg = (struct segment_command_64*)q;

			if(min > seg->vmaddr && seg->vmsize > 0)
				min = seg->vmaddr;

			if(max < seg->vmaddr + seg->vmsize && seg->vmsize > 0)
				max = seg->vmaddr + seg->vmsize;

			if(!strcmp(seg->segname, "__TEXT"))
			{
				xnucore_base = seg->vmaddr;
				xnucore_size = seg->filesize;
			} else if (!strcmp(seg->segname, "__PPLTEXT")) {
				ppl_base = seg->vmaddr;
				ppl_size = seg->filesize;
            } else if (!strcmp(seg->segname, "__TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__cstring")) {
                        cstring_base = sec[j].addr;
                        cstring_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__os_log")) {
                        oslstring_base = sec[j].addr;
                        oslstring_size = sec[j].size;
                    } else if (!strcmp(sec[j].sectname, "__const")) {
                        const_base = sec[j].addr;
                        const_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__DATA_CONST")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__const")) {
                        data_const_base = sec[j].addr;
                        data_const_size = sec[j].size;
                    }
                }
            } else if (!strcmp(seg->segname, "__DATA")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__data")) {
                        data_base = sec[j].addr;
                        data_size = sec[j].size;
                    }
                }
            }
        } else if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint64_t x[29];	/* General purpose registers x0-x28 */
                uint64_t fp;	/* Frame pointer x29 */
                uint64_t lr;	/* Link register x30 */
                uint64_t sp;	/* Stack pointer x31 */
                uint64_t pc; 	/* Program counter */
                uint32_t cpsr;	/* Current program status register */
            } *thread = (void *)(ptr + 2);
            if (flavor == 6) {
                kern_entry_point = thread->pc;
            }
        }

		q = q + cmd->cmdsize;
	}

	kerndumpbase = min;

    xnucore_base -= kerndumpbase;
    cstring_base -= kerndumpbase;
    ppl_base -= kerndumpbase;
    oslstring_base -= kerndumpbase;
    data_const_base -= kerndumpbase;
    data_base -= kerndumpbase;
    const_base -= kerndumpbase;

    kernel_size = max - min;

    kernel = malloc(kernel_size);

    if(!kernel)
    	return -1;

    ok = kernel_read(kerndumpbase, kernel, kernel_size);

    if(!ok)
    {
    	fprintf(stderr, "could not read from kernel dump base %llu\n", kerndumpbase);

    	free(kernel);
    	kernel = NULL;
    	return -1;
    }

    kernel_mh = kernel + kernel_base - min;

    return 0;
}

static mach_vm_address_t xref64(const uint8_t *buf,
								mach_vm_address_t start,
								mach_vm_address_t end,
								mach_vm_address_t what)
{
	mach_vm_address_t i;

	uint64_t value[32];
	memset(value, 0, sizeof(value));

	end &= ~3;

	for(i = start & ~3; i < end; i += 4)
	{
		uint32_t op = *(uint32_t*)(buf + i);
		unsigned reg = op & 0x1F;

		if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
            continue;				// XXX should not XREF on its own?
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
            if (rn == 0x1f) {
                // ignore ADD Xn, SP
                value[reg] = 0;
                continue;
            }

            unsigned shift = (op >> 22) & 3;
            unsigned imm = (op >> 10) & 0xFFF;
            if (shift == 1) {
                imm <<= 12;
            } else {
                //assert(shift == 0);
                if (shift > 1) continue;
            }
            //printf("%llx: ADD X%d, X%d, 0x%x\n", i, reg, rn, imm);
            value[reg] = value[rn] + imm;
        } else if ((op & 0xF9C00000) == 0xF9400000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: LDR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[reg] = value[rn] + imm;	// XXX address, not actual value
        /*} else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value*/
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        } else if ((op & 0xFC000000) == 0x94000000) {
            // BL addr
            signed imm = (op & 0x3FFFFFF) << 2;
            if (op & 0x2000000) {
                imm |= 0xf << 28;
            }
            unsigned adr = (unsigned)(i + imm);
            if (adr == what) {
                return i;
            }
        }

        // Don't match SP as an offset
        if (value[reg] == what && reg != 0x1f) {
            return i;
        }
	}

	return 0;
}

mach_vm_address_t find_reference(mach_vm_address_t to, int n, enum text_bases text_base)
{
	mach_vm_address_t ref, end;

	mach_vm_address_t base = xnucore_base;
	size_t size = xnucore_size;

	switch(text_base)
	{
		case text_xnucore_base:
			break;
		case text_ppl_base:
			if(ppl_base != 0-kerndumpbase)
			{
				base = ppl_base;
				size = ppl_size;
			}

			break;
		default:
			fprintf(stdout, "Unknown base %d\n", text_base);

			return 0;

			break;
	}

	if(n <= 0)
		n = 1;

	end = base + size;

	to -= kerndumpbase;

	do
	{
		ref = xref64(kernel, base, end, to);

		if(!ref)
			return 0;

		base = ref + 4;
	} while(--n > 0);

	return ref + kerndumpbase;
}

mach_vm_address_t find_strref(const char *string, int n, enum string_bases string_base, bool full_match, bool ppl_base)
{
	uint8_t *str;

	mach_vm_address_t base;
	mach_vm_address_t size;

	enum text_bases text_base = ppl_base ? text_ppl_base : text_xnucore_base;

	switch(string_base)
	{
		case string_base_const:
			base = const_base;
			size = const_size;

			break;

		case string_base_data:
			base = data_base;
			size = data_size;
			
			break;

		case string_base_oslstring:
			base = oslstring_base;
			size = oslstring_size;
			
			break;

		case string_base_cstring:
		default:
			base = cstring_base;
			size = cstring_size;
			
			break;
	}

	mach_vm_address_t offset = 0;

	while((str = needle_haystack_memmem(kernel + base + offset, size - offset, (uint8_t*)string, strlen(string))))
	{
		if((str == kernel + base || *(str-1) == '\0') && (!full_match || strcmp((char*)str, string) == 0))
			break;

		offset = str - (kernel + base) + 1;
	}

	if(!str)
		return 0;

	return find_reference(str - kernel + kerndumpbase, n, text_base);
}


mach_vm_address_t find_symbol(const char *symbol)
{
	if(!symbol)
		return 0;

	unsigned i;
	const struct mach_header *hdr = kernel_mh;
	const uint8_t *q;
	
	int is64 = 0;

	if(IS64(hdr))
		is64 = 4;

	q = (uint8_t*)(hdr + 1) + is64;
	
	for(i = 0; i < hdr->ncmds; i++)
	{
		const struct load_command *cmd = (struct load_command*) q;

		if(cmd->cmd == LC_SYMTAB)
		{
			const struct symtab_command *sym = (struct symtab_command*) q;

			const char *stroff = (const char*) kernel_mh + sym->stroff;

			if(is64)
			{
				const struct nlist_64 *s = (struct nlist_64*) kernel_mh + sym->symoff;

				for(uint32_t k = 0; k < sym->nsyms; k++)
				{
					if(s[k].n_type & N_STAB)
						continue;

					if(s[k].n_value && (s[k].n_type & N_TYPE) != N_INDR)
					{
						if(!strcmp(symbol, stroff + s[k].n_un.n_strx))
							return s[k].n_value;
					}
				}
			}
		}

		q = q + cmd->cmdsize;
	}

	return 0;
}
