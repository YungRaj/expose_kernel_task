
#ifndef PARAMETERS__H_
#define PARAMETERS__H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// #include "platform.h"

#define PARAMETER_SHARED __attribute__((weak))

#define OFFSET(base_, object_)		_##base_##__##object_##__offset_

#define SIZE(object_)			_##object_##__size_

#define ADDRESS(object_)		_##object_##__address_

#define STATIC_ADDRESS(object_)		_##object_##__static_address_

#endif