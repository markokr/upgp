#include <stdio.h>

#include "randtest.h"

#include "postgres.h"
#include "px.h"

int randtest(int rtype)
{
	int nbytes = 32*1024*1024;
	nbytes = 32;
	if (rtype == 0) {
		uint8_t buf[4];
		int err;
		while (nbytes > 0) {
			err = px_get_random_bytes(buf, sizeof(buf));
			if (err < 0) {
				printf("px_get_random_bytes failed: %d\n", err);
				return 1;
			}
			nbytes -= sizeof(buf);
		}

	} else {
		return -1;
	}
	return 0;
}

