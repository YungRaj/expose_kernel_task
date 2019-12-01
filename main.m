#include <stdint.h>
#include <string.h>

#include <mach/mach.h>
#include <mach/host_priv.h>
#include <mach/kern_return.h>
#include <mach/mach_host.h>
#include <mach/mach_types.h>
#include <mach/port.h>
#include <mach/vm_types.h>

#include "kernel_memory.h"
#include "slide.h"
#include "tasks.h"

int main(int argc, char *argv[], char *envp[]) {
	bool ok;

	mach_port_t tfp0;

	kern_return_t kr = task_for_pid(mach_task_self(), 0, &tfp0);

	if(kr == KERN_SUCCESS)
	{
		printf("Got kernel task port!\n");
	} else {
		printf("tfp0 failure!\n");

		return -1;
	}

	kernel_task_port = tfp0;

	ok = kernel_slide_init();

	if(!ok)
	{
		fprintf(stderr, "%s failed!\n", "kernel_slide_init()");

		return -1;
	}

	ok = kernel_tasks_init();

	if(!ok)
	{
		fprintf(stderr, "%s failed!\n", "kernel_tasks_init()");

		return -1;
	}
	

	return 1;
}
