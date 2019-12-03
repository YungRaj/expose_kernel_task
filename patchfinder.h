#ifndef PATCHFINDER__H_
#define PATCHFINDER__H_

#include <mach/mach.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include "parameters.h"

uint8_t *kernel = NULL;
size_t kernel_size = 0;

void *kernel_mh = NULL;

int init_kern();
void term_kernel();

enum text_bases {
    text_xnucore_base = 0,
    text_prelink_base,
    text_ppl_base
};

enum string_bases {
    string_base_cstring = 0,
    string_base_oslstring,
    string_base_data,
    string_base_const
};

mach_vm_address_t find_symbol(const char *symbol);

#endif