#include "pac.h"

#include "kcall.h"

uint64_t get_kernel_buffer()
{
	return kernel_buffer + kernel_buffer_size - 0x1000;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static void init_kernel_pacxa_forging()
{
	kernel_pacxa_buffer = get_kernel_buffer();
}

#pragma GCC diagnostic pop