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

mach_vm_address_t kern_entry_point = 0;
mach_vm_address_t kerndumpbase = -1;

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
    string_base_pstring,
    string_base_oslstring,
    string_base_data,
    string_base_const
};

uint8_t * needle_haystack_memmem(const uint8_t *haystack, size_t hlen,
								 const uint8_t *needle, size_t nlen);

mach_vm_address_t find_symbol(const char *symbol);

mach_vm_address_t find_paciza_pointer__l2tp_domain_module_start();
mach_vm_address_t find_paciza_pointer__l2tp_domain_module_stop();
mach_vm_address_t find_l2tp_domain_inited();
mach_vm_address_t find_sysctl__net_ppp_l2tp();
mach_vm_address_t find_sysctl_unregister_oid();
mach_vm_address_t find_mov_x0_x4__br_x5();
mach_vm_address_t find_mov_x9_x0__br_x1();
mach_vm_address_t find_mov_x10_x3__br_x6();
mach_vm_address_t find_kernel_forge_pacia_gadget();
mach_vm_address_t find_kernel_forge_pacda_gadget();

mach_vm_address_t find_paciza_pointer__l2tp_domain_module_start();
mach_vm_address_t find_paciza_pointer__l2tp_domain_module_stop();
mach_vm_address_t find_sysctl__net_ppp_l2tp();
mach_vm_address_t find_sysctl_unregister_oid();
mach_vm_address_t find_mov_x0_x4__br_x5();
mach_vm_address_t find_mov_x9_x0__br_x1();
mach_vm_address_t find_mov_x10_x3__br_x6();
mach_vm_address_t find_kernel_forge_pacia_gadget();
mach_vm_address_t find_kernel_forge_pacda_gadget();
mach_vm_address_t find_zone_map_ref();
mach_vm_address_t find_OSUnserializeXML();


#endif