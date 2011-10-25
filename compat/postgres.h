#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define Assert(x)
#define pg_strcasecmp(a,b) strcasecmp(a,b)

#ifdef WIN32
#define PG_PRINTF_ATTRIBUTE gnu_printf
#else
#define PG_PRINTF_ATTRIBUTE printf
#endif

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

void *palloc(unsigned size);
void *repalloc(void *ptr, unsigned size);
void pfree(void *ptr);

