#ifndef SLIDE__H_
#define SLIDE__H_

#include <stdbool.h>
#include <stdint.h>

#include "parameters.h"

#ifdef KERNEL_SLIDE_EXTERN
#define extern KERNEL_SLIDE_EXTERN
#endif

#define PAGE_GRANULAR_ADDRESS (address / PAGE_SIZE) * PAGE_SIZE

uint64_t STATIC_ADDRESS(kernel_base);

extern uint64_t kernel_base;
extern uint64_t kernel_slide;

bool kernel_slide_init(void);
bool is_kernel_base(uint64_t base);
bool init_with_current_task();
bool kernel_slide_init_with_kernel_image_address(uint64_t address);

#undef extern
#endif