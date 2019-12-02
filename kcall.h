#ifndef K_CALL__H_
#define K_CALL__H_

#include "parameters.h"
#include "slide.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t SIZE(IOExternalTrap);

uint64_t ADDRESS(IOUserClient__vtable);
uint64_t ADDRESS(IORegistryEntry__getRegistryEntryID);

size_t OFFSET(IOExternalTrap, object);
size_t OFFSET(IOExternalTrap, function);
size_t OFFSET(IOExternalTrap, offset);

size_t OFFSET(IORegistryEntry, reserved);
size_t OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID);

uint32_t VTABLE_INDEX(IOUserClient, getExternalTrapForIndex);
uint32_t VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex);

bool kernel_call_init();
bool kernel_call_deinit();

uint32_t kernel_call_7(uint64_t function, size_t argument_count, ...);
uint32_t kernel_call_7v(uint64_t function, size_t argument_count, uint64_t arguments[]);

#endif