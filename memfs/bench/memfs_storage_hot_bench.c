#include "memfs_core.h"

#include <stdio.h>

enum {
	TINY_OPERATIONS = 1000000,
	SPARSE_GROUPS = 4096,
	SPARSE_ROUNDS = 7,
};

static double milliseconds(LARGE_INTEGER start, LARGE_INTEGER end,
	LARGE_INTEGER frequency) {
	return 1000.0 * (double)(end.QuadPart - start.QuadPart) /
		(double)frequency.QuadPart;
}

static bool tiny_hot_path(Memfs* fs, LARGE_INTEGER frequency) {
	MemfsNode* node = NULL;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t transferred;
	uint8_t value = 0;
	uint8_t output = 0;
	double write_ms;
	double read_ms;
	bool success = false;

	if (memfs_node_create(fs, fs->root, L"tiny-hot.bin", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK)
		return false;
	if (memfs_node_write(node, &value, 0, 1, false, false, &transferred) != MEMFS_OK)
		goto cleanup;
	QueryPerformanceCounter(&start);
	for (uint32_t i = 0; i < TINY_OPERATIONS; ++i) {
		value = (uint8_t)i;
		if (memfs_node_write(node, &value, 0, 1, false, false, &transferred) != MEMFS_OK ||
			transferred != 1)
			goto cleanup;
	}
	QueryPerformanceCounter(&end);
	write_ms = milliseconds(start, end, frequency);
	QueryPerformanceCounter(&start);
	for (uint32_t i = 0; i < TINY_OPERATIONS; ++i) {
		if (memfs_node_read(node, &output, 0, 1, &transferred) != MEMFS_OK ||
			transferred != 1 || output != value)
			goto cleanup;
	}
	QueryPerformanceCounter(&end);
	read_ms = milliseconds(start, end, frequency);
	if (node->file_size != 1 || node->allocation_size != 1 ||
		(uint64_t)fs->used_bytes != 1 || memfs_resident_bytes(fs) != 0 ||
		memfs_node_page_group_count(node) != 0)
		goto cleanup;
	printf("tiny operations=%u write_ms=%.3f read_ms=%.3f write_ns=%.3f read_ns=%.3f "
		"logical=1 resident=0 correctness=PASS\n", TINY_OPERATIONS,
		write_ms, read_ms, write_ms * 1000000.0 / TINY_OPERATIONS,
		read_ms * 1000000.0 / TINY_OPERATIONS);
	success = true;

cleanup:
	if (memfs_node_unlink(node) != MEMFS_OK)
		success = false;
	memfs_node_close(node);
	return success;
}

static bool sparse_trim_path(Memfs* fs, LARGE_INTEGER frequency) {
	MemfsNode* node = NULL;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats after;
	uint32_t transferred;
	uint8_t value = 0x5a;
	uint8_t output = 0;
	bool success = false;

	if (memfs_node_create(fs, fs->root, L"sparse-trim.bin", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK)
		return false;
	memfs_allocator_get_stats(&fs->allocator, &baseline);
	for (uint32_t round = 0; round < SPARSE_ROUNDS; ++round) {
		LARGE_INTEGER start;
		LARGE_INTEGER end;
		double trim_ms;
		for (uint32_t i = 0; i < SPARSE_GROUPS; ++i) {
			uint64_t offset = (uint64_t)i * MEMFS_PAGE_GROUP_BYTES;
			if (memfs_node_write(node, &value, offset, 1, false, false, &transferred) != MEMFS_OK ||
				transferred != 1)
				goto cleanup;
		}
		if (memfs_node_page_group_count(node) != SPARSE_GROUPS ||
			memfs_node_read(node, &output, (SPARSE_GROUPS - 1ULL) * MEMFS_PAGE_GROUP_BYTES,
				1, &transferred) != MEMFS_OK || transferred != 1 || output != value)
			goto cleanup;
		QueryPerformanceCounter(&start);
		if (memfs_node_set_file_size(node, 0) != MEMFS_OK)
			goto cleanup;
		QueryPerformanceCounter(&end);
		trim_ms = milliseconds(start, end, frequency);
		memfs_allocator_get_stats(&fs->allocator, &after);
		if (node->file_size != 0 || (uint64_t)fs->used_bytes != 0 ||
			memfs_resident_bytes(fs) != 0 || memfs_node_page_group_count(node) != 0 ||
			after.live_bytes != baseline.live_bytes ||
			after.live_objects != baseline.live_objects)
			goto cleanup;
		printf("sparse round=%u groups=%u trim_ms=%.3f logical=0 resident=0 "
			"group_count=0 allocator_live_restored=PASS correctness=PASS\n",
			round, SPARSE_GROUPS, trim_ms);
	}
	success = true;

cleanup:
	if (memfs_node_unlink(node) != MEMFS_OK)
		success = false;
	memfs_node_close(node);
	return success;
}

int main(void) {
	Memfs* fs = NULL;
	LARGE_INTEGER frequency;
	bool success;

	if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
		memfs_create(8ULL * 1024ULL * 1024ULL * 1024ULL, L"HOT-BENCH", &fs) != MEMFS_OK)
		return 1;
	success = tiny_hot_path(fs, frequency) && sparse_trim_path(fs, frequency);
	if ((uint64_t)fs->used_bytes != 0 || memfs_resident_bytes(fs) != 0)
		success = false;
	memfs_destroy(fs);
	printf("memfs_storage_hot_bench: %s\n", success ? "PASS" : "FAIL");
	return success ? 0 : 1;
}
