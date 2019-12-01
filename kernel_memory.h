#ifndef KERNEL_MEMORY__H_
#define KERNEL_MEMORY__H_

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

mach_port_t kernel_task_port;

uint64_t kernel_vm_allocate(size_t size);

void kernel_vm_deallocate(uint64_t address, size_t size);
bool kernel_vm_protect(uint64_t address, size_t size, vm_prot_t prot);
void* kernel_vm_remap(uint64_t address, size_t size);
bool kernel_read(uint64_t address, void *data, size_t size);
bool kernel_write(uint64_t address, const void *data, size_t size);

uint8_t kernel_read8(uint64_t address);
uint16_t kernel_read16(uint64_t address);
uint32_t kernel_read32(uint64_t address);
uint64_t kernel_read64(uint64_t address);

bool kernel_write8(uint64_t address, uint8_t value);
bool kernel_write16(uint64_t address, uint16_t value);
bool kernel_write32(uint64_t address, uint32_t value);
bool kernel_write64(uint64_t address, uint64_t value);

bool kernel_ipc_port_lookup(uint64_t task, mach_port_name_t name, uint64_t *ipc_port, uint64_t *ipc_entry);

#endif