#include <stdint.h>
#include <string.h>

#include <mach/mach.h>
#include <mach/host_priv.h>
#include <mach/kern_return.h>
#include <mach/mach_host.h>
#include <mach/mach_types.h>
#include <mach/port.h>
#include <mach/vm_types.h>
#include <getopt.h>

#include "kernel_memory.h"
#include "slide.h"
#include "patchfinder.h"
#include "tasks.h"
#include "hsp4.h"

static mach_port_t tfp0;

static struct option options[] =
{
    {"gadgets",  required_argument, 0, 'g'},
    {"hsp4", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

int main(int argc, char *argv[], char *envp[]) {
	bool ok;
	kern_return_t kr;

	int c;
	bool hsp4;
	char *gadget_file = NULL;

	opterr = 0;

    do
    {
        int opt_index = 0;

        c = getopt_long(argc, argv, "g:h", options, &opt_index);

        if(c == -1)
            break;

        switch(c)
        {
            case 0:
                if(options[opt_index].flag != 0)
                    break;

                printf("option %s", options[opt_index].name);

                if(optarg)
                    printf(" with argument %s", optarg);

                printf("\n");

                break;
            case 'g':
              	gadget_file = optarg;

                break;

            case 'h':
            	hsp4 = true;

            	break;
        }

    } while(c != -1);

	kr = task_for_pid(mach_task_self(), 0, &tfp0);

	if(kr == KERN_SUCCESS)
	{
		printf("Got kernel task port!\n");
	} else {
		fprintf(stderr, "tfp0 failure!\n");

		return -1;
	}

	kernel_task_port = tfp0;

	ok = kernel_slide_init();

	if(!ok)
	{
		fprintf(stderr, "%s failed!\n", "kernel_slide_init()");

		return -1;
	}

	ok = patchfinder_init(gadget_file);

	if(!ok)
	{
		fprintf(stderr, "%s failed\n", "patchfinder_init()");

		return -1;
	}

	ok = kernel_tasks_init();

	if(!ok)
	{
		fprintf(stderr, "%s failed!\n", "kernel_tasks_init()");

		return -1;
	}

	mach_port_t fake_tfp0;

	if(hsp4)
	{
		ok = perform_hsp4_patch(&fake_tfp0);

		if(!ok)
		{
			fprintf(stderr, "%s failed!\n", "perform_hsp4_patch()");

			return -1;
		}
	}
	

	return 1;
}
