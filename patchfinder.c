#include "patchfinder.h"

#include "kernel_memory.h"
#include "tasks.h"
#include "slide.h"

#include "mach_vm.h"

#define UCHAR_MAX 255
#define INSN_RET  0xD65F03C0, 0xFFFFFFFF
#define INSN_CALL 0x94000000, 0xFC000000
#define INSN_B    0x14000000, 0xFC000000
#define INSN_CBZ  0x34000000, 0x7F000000
#define INSN_ADRP 0x90000000, 0x9F000000
#define INSN_STR8 0xF9000000 | 8, 0xFFC00000 | 0x1F
#define INSN_POPS 0xA9407BFD, 0xFFC07FFF

uint8_t *kernel = NULL;
size_t kernel_size = 0;

mach_vm_address_t kern_entry_point = 0;
mach_vm_address_t kerndumpbase = -1;

void *kernel_mh = NULL;

uint8_t* needle_haystack_memmem(const uint8_t *haystack, size_t hlen,
								 const uint8_t *needle, size_t nlen)
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

bool auth_ptrs = false;
bool monolithic_kernel = false;
static mach_vm_address_t xnucore_base = 0;
static mach_vm_address_t xnucore_size = 0;
static mach_vm_address_t ppl_base = 0;
static mach_vm_address_t ppl_size = 0;
static mach_vm_address_t prelink_base = 0;
static mach_vm_address_t prelink_size = 0;
static mach_vm_address_t cstring_base = 0;
static mach_vm_address_t cstring_size = 0;
static mach_vm_address_t pstring_base = 0;
static mach_vm_address_t pstring_size = 0;
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
			} else if (!strcmp(seg->segname, "__PPLDATA")) {
                auth_ptrs = true;
            } else if (!strcmp(seg->segname, "__PPLTEXT")) {
				ppl_base = seg->vmaddr;
				ppl_size = seg->filesize;
		    }  else if (!strcmp(seg->segname, "__PLK_TEXT_EXEC")) {
		        prelink_base = seg->vmaddr;
		        prelink_size = seg->filesize;
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
		    } else if (!strcmp(seg->segname, "__PRELINK_TEXT")) {
                const struct section_64 *sec = (struct section_64 *)(seg + 1);
                for (j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sec[j].sectname, "__text")) {
                        pstring_base = sec[j].addr;
                        pstring_size = sec[j].size;
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

	if(prelink_size == 0)
	{
        monolithic_kernel = true;
        prelink_base = xnucore_base;
        prelink_size = xnucore_size;
        pstring_base = cstring_base;
        pstring_size = cstring_size;
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

mach_vm_address_t step64(const uint8_t *buf,
						 mach_vm_address_t start,
						 size_t length,
						 uint32_t what,
						 uint32_t mask)
{
    mach_vm_address_t end = start + length;
    while (start < end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start += 4;
    }
    return 0;
}

mach_vm_address_t step64_back(const uint8_t *buf,
							  mach_vm_address_t start,
							  size_t length,
							  uint32_t what,
							  uint32_t mask)
{
    mach_vm_address_t end = start - length;
    while (start >= end) {
        uint32_t x = *(uint32_t *)(buf + start);
        if ((x & mask) == what) {
            return start;
        }
        start -= 4;
    }
    return 0;
}

mach_vm_address_t step_adrp_to_reg(const uint8_t *buf,
								   mach_vm_address_t start,
								   size_t length,
								   int reg)
{
    return step64(buf, start, length, 0x90000000 | (reg&0x1F), 0x9F00001F);
}

mach_vm_address_t xref64(const uint8_t *buf,
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

mach_vm_address_t bof64(const uint8_t *buf, mach_vm_address_t start, mach_vm_address_t where)
{
    for (; where >= start; where -= 4) {
        uint32_t op = *(uint32_t *)(buf + where);
        if ((op & 0xFFC003FF) == 0x910003FD) {
            unsigned delta = (op >> 10) & 0xFFF;
            //printf("0x%llx: ADD X29, SP, #0x%x\n", where + kerndumpbase, delta);
            if ((delta & 0xF) == 0) {
                mach_vm_address_t prev = where - ((delta >> 4) + 1) * 4;
                uint32_t au = *(uint32_t *)(buf + prev);
                //printf("0x%llx: (%llx & %llx) == %llx\n", prev + kerndumpbase, au, 0x3BC003E0, au & 0x3BC003E0);
                if ((au & 0x3BC003E0) == 0x298003E0) {
                    //printf("%x: STP x, y, [SP,#-imm]!\n", prev);
                    return prev;
                } else if ((au & 0x7F8003FF) == 0x510003FF) {
                    //printf("%x: SUB SP, SP, #imm\n", prev);
                    return prev;
                }
                for (mach_vm_address_t diff = 4; diff < delta/4+4; diff+=4) {
                    uint32_t ai = *(uint32_t *)(buf + where - diff);
                    // SUB SP, SP, #imm
                    //printf("0x%llx: (%llx & %llx) == %llx\n", where - diff + kerndumpbase, ai, 0x3BC003E0, ai & 0x3BC003E0);
                    if ((ai & 0x7F8003FF) == 0x510003FF) {
                        return where - diff;
                    }
                    // Not stp and not str
                    if (((ai & 0xFFC003E0) != 0xA90003E0) && (ai&0xFFC001F0) != 0xF90001E0) {
                        break;
                    }
                }
                // try something else
                while (where > start) {
                    where -= 4;
                    au = *(uint32_t *)(buf + where);
                    // SUB SP, SP, #imm
                    if ((au & 0xFFC003FF) == 0xD10003FF && ((au >> 10) & 0xFFF) == delta + 0x10) {
                        return where;
                    }
                    // STP x, y, [SP,#imm]
                    if ((au & 0xFFC003E0) != 0xA90003E0) {
                        where += 4;
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

mach_vm_address_t calc64(const uint8_t *buf, mach_vm_address_t start, mach_vm_address_t end, int which)
{
    mach_vm_address_t i;
    uint64_t value[32];

    memset(value, 0, sizeof(value));

    end &= ~3;
    for (i = start & ~3; i < end; i += 4) {
        uint32_t op = *(uint32_t *)(buf + i);
        unsigned reg = op & 0x1F;
        if ((op & 0x9F000000) == 0x90000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADRP X%d, 0x%llx\n", i, reg, ((long long)adr << 1) + (i & ~0xFFF));
            value[reg] = ((long long)adr << 1) + (i & ~0xFFF);
        /*} else if ((op & 0xFFE0FFE0) == 0xAA0003E0) {
            unsigned rd = op & 0x1F;
            unsigned rm = (op >> 16) & 0x1F;
            //printf("%llx: MOV X%d, X%d\n", i, rd, rm);
            value[rd] = value[rm];*/
        } else if ((op & 0xFF000000) == 0x91000000) {
            unsigned rn = (op >> 5) & 0x1F;
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
        } else if ((op & 0xF9C00000) == 0xF9000000) {
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 3;
            //printf("%llx: STR X%d, [X%d, 0x%x]\n", i, reg, rn, imm);
            if (!imm) continue;			// XXX not counted as true xref
            value[rn] = value[rn] + imm;	// XXX address, not actual value
        } else if ((op & 0x9F000000) == 0x10000000) {
            signed adr = ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8);
            //printf("%llx: ADR X%d, 0x%llx\n", i, reg, ((long long)adr >> 11) + i);
            value[reg] = ((long long)adr >> 11) + i;
        } else if ((op & 0xFF000000) == 0x58000000) {
            unsigned adr = (op & 0xFFFFE0) >> 3;
            //printf("%llx: LDR X%d, =0x%llx\n", i, reg, adr + i);
            value[reg] = adr + i;		// XXX address, not actual value
        } else if ((op & 0xF9C00000) == 0xb9400000) { // 32bit
            unsigned rn = (op >> 5) & 0x1F;
            unsigned imm = ((op >> 10) & 0xFFF) << 2;
            if (!imm) continue;            // XXX not counted as true xref
            value[reg] = value[rn] + imm;    // XXX address, not actual value
        }
    }
    return value[which];
}

mach_vm_address_t find_call64(const uint8_t *buf, mach_vm_address_t start, size_t length)
{
    return step64(buf, start, length, INSN_CALL);
}

mach_vm_address_t follow_call64(const uint8_t *buf, mach_vm_address_t call)
{
    long long w;
    w = *(uint32_t *)(buf + call) & 0x3FFFFFF;
    w <<= 64 - 26;
    w >>= 64 - 26 - 2;
    return call + w;
}

mach_vm_address_t follow_stub(const uint8_t *buf, mach_vm_address_t call)
{
    mach_vm_address_t stub = follow_call64(buf, call);
    if (!stub) return 0;

    if (monolithic_kernel) {
        return stub + kerndumpbase;
    }
    mach_vm_address_t target_function_offset = calc64(buf, stub, stub+4*3, 16);
    if (!target_function_offset) return 0;

    return *(mach_vm_address_t*)(buf + target_function_offset);
}

mach_vm_address_t follow_cbz(const uint8_t *buf, mach_vm_address_t cbz)
{
    return cbz + ((*(int *)(buf + cbz) & 0x3FFFFE0) << 10 >> 13);
}

mach_vm_address_t remove_pac(mach_vm_address_t addr)
{
    if (addr >= kerndumpbase) return addr;
    if (addr >> 56 == 0x80) {
        return (addr&0xffffffff) + kerndumpbase;
    }
    return addr |= 0xfffffff000000000;
}

#pragma GCC diagnostic pop

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

mach_vm_address_t find_str(const char *string)
{
    uint8_t *str = needle_haystack_memmem(kernel, kernel_size, (uint8_t *)string, strlen(string));
    
    if (!str) return 0;

    return str - kernel + kerndumpbase;
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

mach_vm_address_t find_paciza_pointer__l2tp_domain_module_start()
{
	uint64_t string = (uint64_t)needle_haystack_memmem(kernel + data_base, data_size, (const uint8_t *)"com.apple.driver.AppleSynopsysOTGDevice", strlen("com.apple.driver.AppleSynopsysOTGDevice")) - (uint64_t)kernel;
    
    if (!string) return 0;
    
    return string + kerndumpbase - 0x20;
}

mach_vm_address_t find_paciza_pointer__l2tp_domain_module_stop()
{
	uint64_t string = (uint64_t)needle_haystack_memmem(kernel + data_base, data_size, (const uint8_t *)"com.apple.driver.AppleSynopsysOTGDevice", strlen("com.apple.driver.AppleSynopsysOTGDevice")) - (uint64_t)kernel;
    
    if (!string) return 0;
    
    return string + kerndumpbase - 0x18;
}

mach_vm_address_t find_sysctl__net_ppp_l2tp()
{
	uint64_t ref = find_strref("L2TP domain init\n", 1, string_base_cstring, false, false);
    
    if (!ref) return 0;
    ref -= kerndumpbase;
    
    uint64_t addr = calc64(kernel, ref, ref + 32, 8);
    
    if (!addr) return 0;
    
    return addr + kerndumpbase;
}

mach_vm_address_t find_sysctl_unregister_oid()
{
	uint64_t ref = find_strref("L2TP domain terminate : PF_PPP domain does not exist...\n", 1, string_base_cstring, false, false);
    
    if (!ref) return 0;
    
    ref -= kerndumpbase;
    ref += 4;
    
    uint64_t addr = calc64(kernel, ref, ref + 28, 0);
    
    if (!addr) return 0;
    
    return addr + kerndumpbase;
}

mach_vm_address_t find_mov_x0_x4__br_x5()
{
	uint32_t bytes[] = {
        0xaa0403e0, // mov x0, x4
        0xd61f00a0  // br x5
    };
    
    uint64_t addr = (uint64_t)needle_haystack_memmem((uint8_t *)((uint64_t)kernel + xnucore_base), xnucore_size, (const uint8_t *)bytes, sizeof(bytes));
    
    if (!addr) return 0;
    
    return addr - (mach_vm_address_t)kernel + kerndumpbase;
}

mach_vm_address_t find_mov_x9_x0__br_x1()
{
	uint32_t bytes[] = {
        0xaa0003e9, // mov x9, x0
        0xd61f0020  // br x1
    };
    
    uint64_t addr = (uint64_t)needle_haystack_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) return 0;
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

mach_vm_address_t find_mov_x10_x3__br_x6()
{
	uint32_t bytes[] = {
        0xaa0303ea, // mov x10, x3
        0xd61f00c0  // br x6
    };
    
    uint64_t addr = (uint64_t)needle_haystack_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) return 0;
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

mach_vm_address_t find_kernel_forge_pacia_gadget()
{
	uint32_t bytes[] = {
        0xdac10149, // paci
        0xf9007849  // str x9, [x2, #240]
    };
    
    uint64_t addr = (uint64_t)needle_haystack_memmem((uint8_t *)((uint64_t)kernel + xnucore_base), xnucore_size, (const uint8_t *)bytes, sizeof(bytes));
    
    if (!addr) return 0;
    
    return addr - (mach_vm_address_t)kernel + kerndumpbase;
}

mach_vm_address_t find_kernel_forge_pacda_gadget()
{
	uint32_t bytes[] = {
        0xdac10949, // pacd x9
        0xf9007449  // str x9, [x2, #232]
    };
    
    uint64_t addr = (uint64_t)needle_haystack_memmem((unsigned char *)((uint64_t)kernel + xnucore_base), xnucore_size, (const unsigned char *)bytes, sizeof(bytes));
    
    if (!addr) return 0;
    
    return addr - (uint64_t)kernel + kerndumpbase;
}

mach_vm_address_t find_zone_map_ref()
{
	mach_vm_address_t ref = find_strref("\"Nothing being freed to the zone_map. start = end = %p\\n\"", 1, string_base_cstring, false, false);

	if(!ref)
		return 0;

	uint64_t val = kerndumpbase;

	ref -= val;
	// skip add & adrp for panic str
	ref -= 8;

	// adrp xX, #_zone_map@PAGE
	ref = step64_back(kernel, ref, 30, INSN_ADRP);

	if(!ref)
		return 0;

	uint32_t *insn = (uint32_t*)(kernel + ref);
	// get pc
	val += ((uint8_t*)(insn) - kernel) & ~0xfff;
	uint8_t xm = *insn & 0x1f;

	// he wrote this at 5am, not sure wtf is going on here lol
	val += (*insn << 9 & 0x1ffffc000) | (*insn >> 17 & 0x3000);

	// ldr x, [xX, #_zone_map@PAGEOFF]
	++insn;

	if(((*insn & 0xF9C00000) != 0xF9400000))
		return 0;

	// xd == xX, xn == xX
	if ((*insn & 0x1f) != xm || ((*insn >> 5) & 0x1f) != xm)
        return 0;

    val += ((*insn >> 10) & 0xFFF) << 3;

    return val;
}


mach_vm_address_t find_OSUnserializeXML()
{
	mach_vm_address_t ref = find_strref("OSUnserializeXML: %s near line %d\n", 1, string_base_cstring, false, false);

	if(!ref)
		return 0;

	ref -= kerndumpbase;

	uint64_t start = bof64(kernel, xnucore_base, ref);

	if(!start)
		return 0;

	if(monolithic_kernel)
	{
		ref = find_reference(start + kerndumpbase, 1, false);

		if(!ref) return 0;

		ref -= kerndumpbase;

		start = bof64(kernel, xnucore_base, ref);

		if(!start) return 0;
	}

	return start + kerndumpbase;
}

mach_vm_address_t find_gPhysBase()
{
	mach_vm_address_t ret, val;

	mach_vm_address_t ref = find_strref("\"pmap_map_high_window_bd: insufficient pages", 1, string_base_cstring, false, false);

	if(!ref) return 0;

	ref -= kerndumpbase;

	ret = step64(kernel, ref, 64, INSN_RET);

	if(!ret)
	{
		ref = step64(kernel, ref, 1024, INSN_RET);

		if(!ret) return 0;

		ret = step64(kernel, ref + 4, 64, INSN_RET);

		if(!ret) return 0;
	}

	val = calc64(kernel, ref, ret, 8);

	if(!val) return 0;

	return val + kerndumpbase;
}

mach_vm_address_t find_kernel_pmap()
{
	mach_vm_address_t call, bof, val;

	mach_vm_address_t ref = find_strref("\"pmap_map_bd\"", 1, string_base_cstring, false, false);

	if(!ref) return 0;

	ref -= kerndumpbase;

	call = step64_back(kernel, ref, 64, INSN_CALL);

	if(!call) return 0;

	bof = bof64(kernel, xnucore_base, call);

	if(!bof) return 0;

	val = calc64(kernel, bof, call, 2);

	if(!val) return 0;

	return val + kerndumpbase;
}

mach_vm_address_t find_trustcache()
{
	mach_vm_address_t ref;

    if (auth_ptrs)
    {
        mach_vm_address_t ref = find_strref("\"loadable trust cache buffer too small (%ld) for entries claimed (%d)\"", 1, string_base_cstring, false, true);
        if (!ref) return 0;
    
        ref -= kerndumpbase;

        mach_vm_address_t val = calc64(kernel, ref-32*4, ref-24*4, 8);
        if (!val) return 0;

        return val + kerndumpbase;
    }

    mach_vm_address_t call, func, val, adrp;
    int reg;
    uint32_t op;

   	ref = find_strref("%s: only allowed process can check the trust cache", 1, string_base_pstring, false, false); // Trying to find AppleMobileFileIntegrityUserClient::isCdhashInTrustCache
    
    if (!ref) return 0;
    ref -= kerndumpbase;

    call = step64_back(kernel, ref, 11 * 4, INSN_CALL);
    if (!call) return 0;

    func = follow_call64(kernel, call);
    if (!func) return 0;

    call = step64(kernel, func, 8 * 4, INSN_CALL);
    if (!call) return 0;

    func = follow_call64(kernel, call);
    if (!func) return 0;

    call = step64(kernel, func, 8 * 4, INSN_CALL);
    if (!call) return 0;

    call = step64(kernel, call + 4, 8 * 4, INSN_CALL);
    if (!call) return 0;

    func = follow_call64(kernel, call);
    if (!func) return 0;

    call = step64(kernel, func, 12 * 4, INSN_CALL);
    if (!call) return 0;

    val = calc64(kernel, call, call + 6 * 4, 21);
    if (!val) {
        func = follow_stub(kernel, call);
        if (!func) return 0;

        func -=  kerndumpbase;

        mach_vm_address_t movw = step64(kernel, func, 0x300, 0x52800280, 0xffffffe0);
        if (!movw) return 0;

        adrp = step64_back(kernel, movw, 0x10, INSN_ADRP);
        if (!adrp) return 0;

        op = *(uint32_t*)(kernel + adrp + 4);
        reg = op&0x1F;

        val = calc64(kernel, adrp, movw, reg);
        if (!val) return 0;
    }
    return val + kerndumpbase;
}

mach_vm_address_t find_amficache()
{
	mach_vm_address_t cbz, call, func, val;

	mach_vm_address_t ref = find_strref("amfi_prevent_old_entitled_platform_binaries", 1, string_base_pstring, false, false);

	if(!ref)
	{
		ref = find_strref("com.apple.MobileFileIntegrity", 1, string_base_pstring, false, false);
	
		ref -= kerndumpbase;

		call = step64(kernel, ref, 64, INSN_CALL);

		if(!call) return 0;

		call = step64(kernel, call + 4, 64, INSN_CALL);

		goto finish;
	}

	ref -= kerndumpbase;
    cbz = step64(kernel, ref, 32, INSN_CBZ);
    if (!cbz) return 0;

    call = step64(kernel, follow_cbz(kernel, cbz), 4, INSN_CALL);

finish:
	if (!call) return 0;

    func = follow_call64(kernel, call);
    
    if (!func) return 0;

    val = calc64(kernel, func, func + 16, 8);
    
    if (!val) {
        ref = find_strref("%s: only allowed process can check the trust cache", 1, string_base_pstring, false, false); // Trying to find AppleMobileFileIntegrityUserClient::isCdhashInTrustCache
        
        if (!ref) return 0;

        ref -= kerndumpbase;
        
        call = step64_back(kernel, ref, 11 * 4, INSN_CALL);
        if (!call) return 0;

        func = follow_call64(kernel, call);
        if (!func) return 0;
        
        call = step64(kernel, func, 8 * 4, INSN_CALL);
        if (!call) return 0;

        func = follow_call64(kernel, call);
        if (!func) return 0;

        call = step64(kernel, func, 8 * 4, INSN_CALL);
        if (!call) return 0;

        call = step64(kernel, call + 4, 8 * 4, INSN_CALL);
        if (!call) return 0;

        func = follow_call64(kernel, call);
        if (!func) return 0;

        call = step64(kernel, func, 12 * 4, INSN_CALL);
        if (!call) return 0;
        
        val = calc64(kernel, call, call + 6 * 4, 21);
    }
    return val + kerndumpbase;
}

mach_vm_address_t find_kern_proc()
{
	mach_vm_address_t ref = find_strref("\"returning child proc which is not cur_act\"", 1, string_base_cstring, false, false);

	if(!ref) return 0;

	ref -= kerndumpbase;

	mach_vm_address_t end;

	int reg = 0;

	if(monolithic_kernel)
	{
		mach_vm_address_t adrp = step64(kernel, ref, 20 * 4, INSN_ADRP);

		if(!adrp) return 0;

		uint32_t op = *(uint32_t*)(kernel + adrp + 4);

		reg = op & 0x1f;

		end = step64(kernel, adrp, 20 * 4, INSN_CALL);

		if(!end) return 0;
	} else 
	{
		reg = 19;

		end = step64(kernel, ref, 20 * 4, INSN_RET);

		if(!end) return 0;
	}

	mach_vm_address_t kernproc = calc64(kernel, ref, end, reg);

	if(!kernproc) return 0;

	return kernproc + kerndumpbase;
}

mach_vm_address_t find_allproc()
{
	mach_vm_address_t val, bof, str8;

	mach_vm_address_t ref = find_strref("\"pgrp_add : pgrp is dead adding process\"", 1, string_base_cstring, false, false);

	if(!ref) return 0;

	ref -= kerndumpbase;

	bof = bof64(kernel, xnucore_base, ref);

	if(!bof) return 0;

	str8 = step64_back(kernel, ref, ref - bof, INSN_STR8);

	if(!str8)
	{
		mach_vm_address_t ldp = step64(kernel, ref, 1024, INSN_POPS);

		if(!ldp) return 0;

		str8 = step64_back(kernel, ldp, ldp - bof, INSN_STR8);

		if(!str8) return 0;
	}

	val = calc64(kernel, bof, str8, 8);

	if(!val) return 0;

	return val + kerndumpbase;
}

mach_vm_address_t find_kernel_task()
{
	if(monolithic_kernel)
	{
		mach_vm_address_t str = find_strref("\"shouldn't be applying exception \"", 2, string_base_cstring, false, false);
		
		if(!str) return 0;

		str -= kerndumpbase;

		mach_vm_address_t call = step64_back(kernel, str, 0x10, INSN_CALL);

		if(!call) return 0;

		mach_vm_address_t task_suspend = follow_call64(kernel, call);

		if(!task_suspend) return 0;

		mach_vm_address_t adrp = step64(kernel, task_suspend, 20 * 4, INSN_ADRP);

		if(!adrp) return 0;

		mach_vm_address_t kern_task = calc64(kernel, adrp, adrp + 0x8, 8);

		if(!kern_task) return 0;

		return kern_task + kerndumpbase;
	}

	mach_vm_address_t term_str = find_strref("\"thread_terminate\"", 1, string_base_cstring, false, false);

	if(!term_str) return 0;

	term_str -= kerndumpbase;

	mach_vm_address_t thread_terminate = bof64(kernel, xnucore_base, term_str);

	if(!thread_terminate) return 0;

	mach_vm_address_t call_to_unk1 = step64(kernel, thread_terminate, 20 * 4, INSN_CALL);

	if(!call_to_unk1) return 0;

	mach_vm_address_t kern_task = calc64(kernel, thread_terminate, call_to_unk1, 9);

	if(!kern_task) return 0;

	return kern_task + kerndumpbase;
}

