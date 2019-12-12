
#ifndef PARAMETERS__H_
#define PARAMETERS__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <dlfcn.h>

#include "cache_offsets.h"
#include "patchfinder.h"

#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

#define setoffset(offset, val) set_offset(#offset, val)
#define getoffset(offset) get_offset(#offset)

#define find_offset(x, symbol, critical) do { \
    if (!KERN_POINTER_VALID(getoffset(x))) { \
        setoffset(x, find_symbol(symbol != NULL ? symbol : "_" #x)); \
    } \
    if (!KERN_POINTER_VALID(getoffset(x))) { \
        mach_vm_address_t (*_find_ ##x)(void) = dlsym(RTLD_DEFAULT, "find_" #x); \
        if (_find_ ##x != NULL) { \
            setoffset(x, _find_ ##x()); \
        } \
    } \
    if (KERN_POINTER_VALID(getoffset(x))) { \
        setoffset(x, getoffset(x) + kernel_slide); \
    } else { \
    	fprintf(stdout, "Could not find offset for symbol %s\n", "_" #x); \
        exit(-1); \
    } \
} while (false)

#define PARAMETER_SHARED __attribute__((weak))

#define OFFSET(base_, object_)		_##base_##__##object_##__offset_

#define SIZE(object_)			_##object_##__size_

#define SLIDE(address)		(address == 0 ? 0 : address + kernel_slide)

#define ADDRESS(object_)		_##object_##__address_

#define STATIC_ADDRESS(object_)		_##object_##__static_address_

#define VTABLE_INDEX(class_, method_)	_##class_##_##method_##__vtable_index_

#define FIELD(object_, struct_, field_, type_)	\
	( *(type_ *) ( ((uint8_t *) object_) + OFFSET(struct_, field_) ) )

// A structure describing the PAC codes used as part of the context for signing and verifying
// virtual method pointers in a vtable.
struct vtable_pac_codes {
    size_t count;
    const uint16_t *codes;
};

// Generate the name for an offset in a virtual method table.
#define VTABLE_INDEX(class_, method_)   _##class_##_##method_##__vtable_index_

// Generate the name for a list of vtable PAC codes.
#define VTABLE_PAC_CODES(class_)    _##class_##__vtable_pac_codes_

// A helper macro for INIT_VTABLE_PAC_CODES().
#define VTABLE_PAC_CODES_DATA(class_)   _##class_##__vtable_pac_codes_data_

// Initialize a list of vtable PAC codes. In order to store the PAC code array in constant memory,
// we place it in a static variable. Consequently, this macro will produce name conflicts if used
// outside a function.
#define INIT_VTABLE_PAC_CODES(class_, ...)                      \
    static const uint16_t VTABLE_PAC_CODES_DATA(class_)[] = { __VA_ARGS__ };    \
    VTABLE_PAC_CODES(class_) = (struct vtable_pac_codes) {              \
        .count = sizeof(VTABLE_PAC_CODES_DATA(class_)) / sizeof(uint16_t),  \
        .codes = (const uint16_t *) VTABLE_PAC_CODES_DATA(class_),      \
    }

#endif