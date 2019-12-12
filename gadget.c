#include "gadget.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

static int hexdigit(int ch) {
	if ('0' <= ch && ch <= '9')
		return ch - '0';
	else if ('A' <= ch && ch <= 'F')
		return ch - 'A' + 0xa;
	else if ('a' <= ch && ch <= 'f')
		return ch - 'a' + 0xa;
	return -1;
}

bool decode_gadget(struct gadget *gadget, char *string)
{
	char *colon = strchr(string, ':');

	if(!colon) return false;

	gadget->name = strndup(string, colon - string);

	string = colon + 1;

	size_t len = strlen(string);

	if(len == 0) return false;

	uint8_t *data = malloc(len / 2);
	gadget->data = data;

	const char *chr = string;

	size_t size = 0;

	while(1)
	{
		bool little_endian = (strncmp(chr, "0x", 2) == 0);

		if(little_endian)
			chr += 2;

		uint8_t *start = data;

		while(1)
		{
			if(*chr == 0 || *chr == ',') break;

			int byte_high = hexdigit(*chr++);

			if(*chr == 0 || *chr == ',') return false;

			int byte_low = hexdigit(*chr++);

			if(byte_high < 0 || byte_low < 0) return false;

			*data++ = (byte_high << 4) | byte_low;
		}

		size_t length = data - start;

		if(length == 0) return false;

		if(little_endian)
		{
			for(size_t i = 0; i < length/2; i++)
			{
				uint8_t tmp = start[i];

				start[i] = start[length - i - 1];
				start[length - i - 1] = tmp;
			}
		}

		size += length;

		if(*chr == ',')
			chr++;
		else
			break;
	}

	gadget->size = size;

	return true;
}

void find_gadgets(void *data, uint64_t address, size_t size)
{
	struct gadget *gadget;

	uint8_t *ins = data;
	uint8_t *end = ins + size;

	if(gadgets == NULL) return;

	for(; ins < end; ins++)
	{
		gadget = gadgets;

		while(gadget != NULL)
		{
			if(gadget->address != 0 || (end - ins) < gadget->size)
				continue;

			if(memcmp(gadget->data, ins, gadget->size) != 0)
				continue;

			gadget->address = address + (ins - (uint8_t*)data);

			gadget = gadget->next;
		}
	}
}

bool construct_gadgets(char *filename)
{
	FILE *fp;
	char *line;
	size_t len;
	size_t read;

	gadgets = NULL;

	if(filename == NULL)
		return true;

	fp = fopen(filename, "r");

	if(!fp)
	{
		fprintf(stderr, "Could not open gadgets file %s\n", filename);

		return false;
	}

	line = NULL;
	len = 0;

	struct gadget *curr = NULL;

	while((read = getline(&line, &len, fp)) != -1)
	{
		bool ok;
		struct gadget *gadget;

		gadget = malloc(sizeof(gadget));
		memset(gadget, 0x0, sizeof(struct gadget));

		ok = decode_gadget(gadget, line);

		if(ok)
		{
			if(!gadgets)
				gadgets = gadget;
			else
			{
				gadget->prev = curr;
				curr->next = gadget;
			}

			curr = gadget;
		} else
			free(gadget);
	}

	return true;
}