#ifndef PAC__H_
#define PAC__H_

#include <mach/mach.h>

#include <stdbool.h>
#include <stdint.h>

#include "parameters.h"

// The address of our kernel buffer.
uint64_t kernel_pacxa_buffer;

// The forged value PACIZA('mov x0, x4 ; br x5').
// uint64_t paciza__mov_x0_x4__br_x5;

#endif