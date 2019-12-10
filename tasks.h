#ifndef TASKS__H_
#define TASKS__H_

#include <mach/mach.h>

#include <stdbool.h>
#include <stdint.h>

#include "parameters.h"

#ifdef KERNEL_TASKS_EXTERN
#define extern KERNEL_TASKS_EXTERN
#endif

// Parameters for struct ipc_entry.
size_t SIZE(ipc_entry);
size_t OFFSET(ipc_entry, ie_object);

// Parameters for struct ipc_port.
size_t OFFSET(ipc_port, io_bits);
size_t OFFSET(ipc_port, io_references);
size_t OFFSET(ipc_port, ikmq_base);
size_t OFFSET(ipc_port, msg_count);
size_t OFFSET(ipc_port, ip_receiver);
size_t OFFSET(ipc_port, ip_kobject);
size_t OFFSET(ipc_port, ip_context);
size_t OFFSET(ipc_port, ip_srights);

// Parameters for struct ipc_space.
size_t OFFSET(ipc_space, is_table_size);
size_t OFFSET(ipc_space, is_table);

// Parameters for struct proc.
size_t OFFSET(proc, p_list_next);
size_t OFFSET(proc, task);
size_t OFFSET(proc, p_pid);

// Parameters for struct task.
size_t OFFSET(task, lck_mtx_type);
size_t OFFSET(task, ref_count);
size_t OFFSET(task, active);
size_t OFFSET(task, vm_map);
size_t OFFSET(task, next);
size_t OFFSET(task, prev);
size_t OFFSET(task, itk_space);
size_t OFFSET(task, bsd_info);

uint64_t ADDRESS(allproc);

uint64_t kernel_task;

uint64_t current_task;

bool kernel_tasks_init(void);
bool find_task(int pid, uint64_t *proc);
bool kernel_ipc_port_lookup(uint64_t task,
							mach_port_name_t port_name,
							uint64_t *ipc_port,
							uint64_t *ipc_entry);

uint64_t task_self_addr();

#undef extern
#endif