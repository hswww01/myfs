#include "memfs_object.h"

#include "memfs_core.h"

#include <stdint.h>
#include <string.h>

MemfsNode* memfs_object_alloc_node(Memfs* fs) {
	MemfsNode* node;

	if (fs == NULL)
		return NULL;

	node = (MemfsNode*)memfs_allocator_alloc_node(&fs->allocator);

	return node;
}

void memfs_object_free_node(Memfs* fs, MemfsNode* node) {
	if (fs == NULL || node == NULL)
		return;

	memfs_allocator_free_node(&fs->allocator, node);
}

MemfsDir* memfs_object_alloc_dir(Memfs* fs) {
	MemfsDir* dir;

	if (fs == NULL)
		return NULL;

	dir = (MemfsDir*)memfs_allocator_alloc_dir(&fs->allocator);

	return dir;
}

void memfs_object_free_dir(Memfs* fs, MemfsDir* dir) {
	if (fs == NULL || dir == NULL)
		return;

	memfs_allocator_free_dir(&fs->allocator, dir);
}

wchar_t* memfs_object_dup_name(Memfs* fs, const wchar_t* name) {
	size_t chars;
	size_t bytes;
	wchar_t* copy;

	if (fs == NULL || name == NULL)
		return NULL;

	chars = wcslen(name) + 1U;
	if (chars > SIZE_MAX / sizeof(*copy))
		return NULL;

	bytes = chars * sizeof(*copy);
	copy = (wchar_t*)memfs_allocator_alloc_name(&fs->allocator, bytes);
	if (copy != NULL)
		memcpy(copy, name, bytes);

	return copy;
}

void memfs_object_free_name(Memfs* fs, wchar_t* name) {
	size_t chars;
	size_t bytes;

	if (fs == NULL || name == NULL)
		return;

	chars = wcslen(name) + 1U;
	if (chars > SIZE_MAX / sizeof(*name))
		return;

	bytes = chars * sizeof(*name);
	memfs_allocator_free_name(&fs->allocator, name, bytes);
}
