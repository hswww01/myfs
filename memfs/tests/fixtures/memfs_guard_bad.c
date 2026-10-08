#include <stddef.h>

void bad_crt_heap_call(void) {
	void* p = malloc (16);
	(void)p;
}
