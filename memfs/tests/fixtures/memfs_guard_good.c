#include <stddef.h>

/*
 * malloc(calloc(realloc(free
 */
void good_mentions_only(void) {
	const char* s = "malloc(calloc(realloc(free";
	char c = 'm';
	// malloc(calloc(realloc(free
	(void)s;
	(void)c;
}
