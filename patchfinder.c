#include "patchfinder.h"

#include "kernel_memory.h"
#include "tasks.h"
#include "slide.h"

#include "mach_vm.h"

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
