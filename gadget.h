#ifndef GADGET__H_
#define GADGET__H_

#include "patchfinder.h"

struct gadget
{
	struct gadget *next;
	struct gadget *prev;

	const char *name;

	size_t size;
	void *data;

	mach_vm_address_t address;
};

struct gadget *gadgets;

void find_gadgets(void *data, uint64_t address, size_t size);
bool construct_gadgets(char *filename);

#endif