
#ifndef PARAMETERS__H_
#define PARAMETERS__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cache_offset.h"

#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

#define setoffset(offset, val) set_offset(#offset, val)
#define getoffset(offset) get_offset(#offset)

#define find_offset(x, symbol, critical) do { \
    if (!KERN_POINTER_VALID(getoffset(x))) { \
        setoffset(x, find_symbol(symbol != NULL ? symbol : "_" #x)); \
    } \
    if (!KERN_POINTER_VALID(getoffset(x))) { \
        kptr_t (*_find_ ##x)(void) = dlsym(RTLD_DEFAULT, "find_" #x); \
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

#endif