#ifndef HSP4__H_
#define HSP4__H_

#include <mach/mach.h>

#include <stdbool.h>
#include <stdint.h>

#include "kernel_memory.h"
#include "slide.h"
#include "tasks.h"

#include "parameters.h"

bool perform_hsp4_patch(mach_port_t *port);


#endif