#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

#include <postgres.h>

#include "px.h"

/* PostgreSQL compat */

void *palloc( unsigned size)
{
	void *res = malloc(size);
	if (res == NULL) {
		px_debug("no mem");
		exit(1);
	}
	return res;
}

void *repalloc(void *ptr, unsigned size)
{
	void *res;
	res = realloc(ptr, size);
	if (res == NULL) {
		px_debug("no mem");
		exit(1);
	}
	return res;
}

void pfree(void *data)
{
	free(data);
}

