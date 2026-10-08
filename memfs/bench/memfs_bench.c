#include "memfs_core.h"

#include <Windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BENCH_SMALL_FILE_COUNT 100000U
#define BENCH_4KB_FILE_COUNT 10000U
#define BENCH_1MB_FILE_COUNT 100U
#define BENCH_RANDOM_REWRITE_COUNT 1000U
#define BENCH_COMPRESSION_PAGE_REWRITE_COUNT 200000U
#define BENCH_SPARSE_GROUP_COUNT 4096U
#define BENCH_SPARSE_GROUP_ROUNDS 16U
#define BENCH_NAME_HOT_COUNT 50000U
#define BENCH_NAME_HOT_ROUNDS 10U
#define BENCH_NAME_HOT_CHARS 40U
#define BENCH_SEQUENTIAL_READ_GROUPS 128U
#define BENCH_SEQUENTIAL_READ_ROUNDS 4U
#define BENCH_1MB_SIZE (1ULL * 1024ULL * 1024ULL)
#define BENCH_4KB_SIZE 4096U
#define BENCH_1B_SIZE 1U

typedef enum BenchMode {
	BENCH_MODE_COMPARE = 0,
	BENCH_MODE_PLAIN,
	BENCH_MODE_COMPRESSION,
	BENCH_MODE_ENCRYPTION,
	BENCH_MODE_COMBINED,
	BENCH_MODE_COMPRESSION_PAGE,
	BENCH_MODE_SPARSE_GROUPS,
	BENCH_MODE_NAME_HOT,
	BENCH_MODE_SEQUENTIAL_READ,
	BENCH_MODE_PRESSURE_POLICY
} BenchMode;

typedef struct BenchConfig {
	bool compression_enabled;
	bool encryption_enabled;
	int compression_level;
	uint8_t encryption_key[MEMFS_ENCRYPTION_KEY_SIZE];
	bool has_encryption_key;
} BenchConfig;

typedef struct BenchResult {
	const char* label;
	double create_seconds;
	double lookup_seconds;
	double miss_seconds;
	double delete_seconds;
	uint64_t used_after_create;
	uint64_t resident_after_create;
	uint64_t used_after_delete;
	uint64_t resident_after_delete;
} BenchResult;

static double seconds_between(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER frequency) {
	return (double)(end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
}

static uint64_t private_bytes(void) {
	PROCESS_MEMORY_COUNTERS_EX counters;

	ZeroMemory(&counters, sizeof(counters));
	if (!GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&counters, sizeof(counters))) {
		return 0;
	}

	return (uint64_t)counters.PrivateUsage;
}

static void print_rate(const char* label, uint32_t count, double seconds) {
	double rate = seconds > 0.0 ? (double)count / seconds : 0.0;
	printf("%-12s %10.3f s  %12.0f ops/s\n", label, seconds, rate);
}

static void print_fs_state(Memfs* fs, const char* label) {
	printf("%-12s used_bytes=%llu resident_bytes=%llu\n", label, (unsigned long long)fs->used_bytes,
		   (unsigned long long)fs->resident_bytes);
}
static void print_fs_state_full(Memfs* fs, const char* label) {
	MemfsAllocatorStats stats;

	memfs_allocator_get_stats(&fs->allocator, &stats);
	printf("%-12s used_bytes=%llu resident_bytes=%llu committed_bytes=%llu physical_bytes=%llu private_bytes=%llu "
		   "alloc_reserved_bytes=%llu alloc_live_bytes=%llu alloc_live_objects=%llu alloc_dedicated_committed_bytes=%llu\n",
		   label, (unsigned long long)fs->used_bytes, (unsigned long long)fs->resident_bytes,
		   (unsigned long long)memfs_committed_bytes(fs), (unsigned long long)memfs_physical_bytes(fs),
		   (unsigned long long)private_bytes(), (unsigned long long)stats.reserved_bytes,
		   (unsigned long long)stats.live_bytes, (unsigned long long)stats.live_objects,
		   (unsigned long long)stats.dedicated_committed_bytes);
}

static uint64_t bench_used_bytes(Memfs* fs) {
	return (uint64_t)fs->used_bytes;
}

static int bench_churn_high_water(Memfs* fs, LARGE_INTEGER frequency) {
	const uint32_t batch_count = 20000U;
	const uint32_t rounds = 3U;
	uint8_t one_byte = 0x5a;
	uint64_t peak_resident = 0;
	uint64_t peak_committed = 0;
	uint64_t after_delete_resident = 0;
	uint64_t after_delete_committed = 0;
	uint64_t after_delete_used = 0;
	uint64_t private_before;
	uint64_t private_after;
	uint32_t round;
	uint32_t i;
	wchar_t name[32];
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double create_seconds = 0.0;
	double delete_seconds = 0.0;
	int rc = 0;

	printf("\n[churn high-water]\n");
	printf("files/batch:      %u\n", batch_count);
	printf("rounds:           %u\n", rounds);
	printf("check:            after-delete resident/committed should not stay pinned near peak\n");

	private_before = private_bytes();
	for (round = 0; round < rounds; round++) {
		QueryPerformanceCounter(&start);
		for (i = 0; i < batch_count; i++) {
			MemfsNode* node = NULL;
			swprintf_s(name, _countof(name), L"ch%07u", i);
			if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
				rc = 1;
				break;
			}
			if (memfs_node_write(node, &one_byte, 0, BENCH_1B_SIZE, false, false, &(uint32_t){0}) != MEMFS_OK) {
				memfs_node_close(node);
				rc = 1;
				break;
			}
			memfs_node_close(node);
		}
		QueryPerformanceCounter(&end);
		if (rc != 0) {
			break;
		}
		create_seconds += seconds_between(start, end, frequency);
		if (fs->resident_bytes > (LONG64)peak_resident) {
			peak_resident = (uint64_t)fs->resident_bytes;
		}
		if (memfs_committed_bytes(fs) > peak_committed) {
			peak_committed = memfs_committed_bytes(fs);
		}

		QueryPerformanceCounter(&start);
		for (i = 0; i < batch_count; i++) {
			MemfsNode* node;
			swprintf_s(name, _countof(name), L"ch%07u", i);
			node = memfs_dir_lookup(fs->root, name);
			if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
				rc = 1;
				break;
			}
		}
		QueryPerformanceCounter(&end);
		if (rc != 0) {
			break;
		}
		delete_seconds += seconds_between(start, end, frequency);
	}
	private_after = private_bytes();
	after_delete_used = bench_used_bytes(fs);
	after_delete_resident = memfs_resident_bytes(fs);
	after_delete_committed = memfs_committed_bytes(fs);

	print_rate("create+1B", rounds * batch_count, create_seconds);
	print_rate("delete", rounds * batch_count, delete_seconds);
	printf("peak_resident:      %llu B\n", (unsigned long long)peak_resident);
	printf("after_delete_resident: %llu B\n", (unsigned long long)after_delete_resident);
	printf("peak_committed:     %llu B\n", (unsigned long long)peak_committed);
	printf("after_delete_committed: %llu B\n", (unsigned long long)after_delete_committed);
	printf("after_delete_used:  %llu B\n", (unsigned long long)after_delete_used);
	printf("private delta:      %llu B (%.2f MiB)\n", (unsigned long long)(private_after - private_before),
		   (double)(private_after - private_before) / (1024.0 * 1024.0));
	printf("high-water check:   %s\n",
		   (peak_resident == 0 || after_delete_resident < peak_resident * 3 / 4) &&
				   (peak_committed == 0 || after_delete_committed < peak_committed * 3 / 4)
			   ? "pass"
			   : "fail");
	print_fs_state_full(fs, "after-churn");

	return rc;
}

static int bench_random_rewrite_full(Memfs* fs, LARGE_INTEGER frequency) {
	const uint32_t file_count = 256U;
	const uint32_t rewrite_count = 2000U;
	const uint64_t file_size = 1ULL * 1024ULL * 1024ULL;
	uint8_t page[BENCH_4KB_SIZE];
	uint64_t used_before;
	uint64_t resident_before;
	uint64_t committed_before;
	uint64_t private_before;
	uint64_t used_after;
	uint64_t resident_after;
	uint64_t committed_after;
	uint64_t private_after;
	MemfsAllocatorStats alloc_before;
	MemfsAllocatorStats alloc_after;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double seed_seconds;
	double rewrite_seconds;
	uint32_t i;
	uint32_t r;
	wchar_t name[32];
	int rc = 0;

	memset(page, 0x5a, sizeof(page));
	printf("\n[random rewrite full]\n");
	printf("files:            %u\n", file_count);
	printf("rewrites:         %u\n", rewrite_count);
	printf("file size:        %llu B\n", (unsigned long long)file_size);

	used_before = bench_used_bytes(fs);
	resident_before = memfs_resident_bytes(fs);
	committed_before = memfs_committed_bytes(fs);
	private_before = private_bytes();
	memfs_allocator_get_stats(&fs->allocator, &alloc_before);

	QueryPerformanceCounter(&start);
	for (i = 0; i < file_count; i++) {
		MemfsNode* node = NULL;
		uint32_t written = 0;
		swprintf_s(name, _countof(name), L"rff%07u", i);
		if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
			rc = 1;
			break;
		}
		if (memfs_node_write(node, page, 0, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
			written != BENCH_4KB_SIZE) {
			memfs_node_close(node);
			rc = 1;
			break;
		}
		if (memfs_node_set_file_size(node, file_size) != MEMFS_OK) {
			memfs_node_close(node);
			rc = 1;
			break;
		}
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	seed_seconds = seconds_between(start, end, frequency);
	if (rc == 0) {
		QueryPerformanceCounter(&start);
		for (r = 0; r < rewrite_count; r++) {
			MemfsNode* node;
			uint32_t written = 0;
			uint64_t offset;
			uint32_t file_index = (uint32_t)((uint64_t)r * 2654435761ULL % file_count);
			swprintf_s(name, _countof(name), L"rff%07u", file_index);
			node = memfs_dir_lookup(fs->root, name);
			if (node == NULL) {
				rc = 1;
				break;
			}
			offset = ((uint64_t)r * 40503ULL) % (file_size / BENCH_4KB_SIZE) * BENCH_4KB_SIZE;
			if (memfs_node_write(node, page, offset, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
				written != BENCH_4KB_SIZE) {
				memfs_node_close(node);
				rc = 1;
				break;
			}
			memfs_node_close(node);
		}
		QueryPerformanceCounter(&end);
		rewrite_seconds = seconds_between(start, end, frequency);
	} else {
		rewrite_seconds = 0.0;
	}

	used_after = bench_used_bytes(fs);
	resident_after = memfs_resident_bytes(fs);
	committed_after = memfs_committed_bytes(fs);
	private_after = private_bytes();
	memfs_allocator_get_stats(&fs->allocator, &alloc_after);

	print_rate("seed", file_count, seed_seconds);
	print_rate("rewrite", rewrite_count, rewrite_seconds);
	printf("used delta:         %llu B\n", (unsigned long long)(used_after - used_before));
	printf("resident delta:     %llu B\n", (unsigned long long)(resident_after - resident_before));
	printf("committed delta:    %llu B\n", (unsigned long long)(committed_after - committed_before));
	printf("private delta:      %llu B (%.2f MiB)\n", (unsigned long long)(private_after - private_before),
		   (double)(private_after - private_before) / (1024.0 * 1024.0));
	printf("alloc committed delta=%llu B alloc live delta=%llu B alloc live_objects delta=%llu\n",
		   (unsigned long long)(alloc_after.committed_bytes - alloc_before.committed_bytes),
		   (unsigned long long)(alloc_after.live_bytes - alloc_before.live_bytes),
		   (unsigned long long)(alloc_after.live_objects - alloc_before.live_objects));
	print_fs_state_full(fs, "after-rewrite");

	for (i = 0; i < file_count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"rff%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
			rc = 1;
			break;
		}
	}
	print_fs_state_full(fs, "after-rewrite-delete");

	return rc;
}

static int bench_auto_capacity_status(LARGE_INTEGER frequency) {
	MemfsOptions options;
	Memfs* fs = NULL;
	uint8_t page[BENCH_4KB_SIZE];
	MemfsNode* node = NULL;
	uint32_t written = 0;
	uint64_t used_before;
	uint64_t resident_before;
	uint64_t committed_before;
	uint64_t private_before;
	uint64_t used_after;
	uint64_t resident_after;
	uint64_t committed_after;
	uint64_t private_after;
	MemfsAllocatorStats alloc_before;
	MemfsAllocatorStats alloc_after;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double write_seconds;
	int rc;

	memset(&options, 0, sizeof(options));
	options.capacity = 0;
	options.capacity_auto = true;
	options.volume_label = L"BENCH_AUTO";
	rc = memfs_create_ex(&options, &fs);
	if (rc != MEMFS_OK) {
		fprintf(stderr, "auto capacity create failed rc=%d\n", rc);
		return 1;
	}

	memset(page, 0x5a, sizeof(page));
	printf("\n[auto capacity status]\n");
	printf("capacity_auto:    true\n");
	printf("capacity:         %llu B\n", (unsigned long long)fs->capacity);
	printf("auto_allowance:   %llu B\n", (unsigned long long)memfs_auto_allowance_bytes(fs));
	printf("free_bytes:       %llu B\n", (unsigned long long)memfs_free_bytes(fs));
	print_fs_state_full(fs, "initial");

	used_before = bench_used_bytes(fs);
	resident_before = memfs_resident_bytes(fs);
	committed_before = memfs_committed_bytes(fs);
	private_before = private_bytes();
	memfs_allocator_get_stats(&fs->allocator, &alloc_before);

	QueryPerformanceCounter(&start);
	if (memfs_node_create(fs, fs->root, L"auto", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
		rc = 1;
	} else if (memfs_node_write(node, page, 0, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
			   written != BENCH_4KB_SIZE) {
		memfs_node_close(node);
		rc = 1;
	} else {
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	write_seconds = seconds_between(start, end, frequency);

	used_after = bench_used_bytes(fs);
	resident_after = memfs_resident_bytes(fs);
	committed_after = memfs_committed_bytes(fs);
	private_after = private_bytes();
	memfs_allocator_get_stats(&fs->allocator, &alloc_after);

	print_rate("create+4KB", 1, write_seconds);
	printf("auto_allowance:   %llu B\n", (unsigned long long)memfs_auto_allowance_bytes(fs));
	printf("free_bytes:       %llu B\n", (unsigned long long)memfs_free_bytes(fs));
	printf("used delta:         %llu B\n", (unsigned long long)(used_after - used_before));
	printf("resident delta:     %llu B\n", (unsigned long long)(resident_after - resident_before));
	printf("committed delta:    %llu B\n", (unsigned long long)(committed_after - committed_before));
	printf("private delta:      %llu B (%.2f MiB)\n", (unsigned long long)(private_after - private_before),
		   (double)(private_after - private_before) / (1024.0 * 1024.0));
	printf("alloc committed delta=%llu B alloc live delta=%llu B alloc live_objects delta=%llu\n",
		   (unsigned long long)(alloc_after.committed_bytes - alloc_before.committed_bytes),
		   (unsigned long long)(alloc_after.live_bytes - alloc_before.live_bytes),
		   (unsigned long long)(alloc_after.live_objects - alloc_before.live_objects));
	print_fs_state_full(fs, "after-write");

	if (rc == 0) {
		MemfsNode* found = memfs_dir_lookup(fs->root, L"auto");
		if (found == NULL || memfs_node_unlink(found) != MEMFS_OK) {
			rc = 1;
		}
	}
	print_fs_state_full(fs, "after-delete");

	memfs_destroy(fs);
	return rc;
}

static int fail(Memfs* fs, const char* message, uint32_t index) {
	fprintf(stderr, "%s at %u\n", message, index);
	memfs_destroy(fs);
	return 1;
}

static void print_config(const BenchConfig* config) {
	printf("compression:      %s level=%d\n", config->compression_enabled ? "enabled" : "disabled",
		   config->compression_level);
	printf("encryption:       %s\n", config->encryption_enabled ? "enabled" : "disabled");
}

static int create_fs(const BenchConfig* config, Memfs** out_fs) {
	MemfsOptions options;

	memset(&options, 0, sizeof(options));
	options.capacity = 4ULL * 1024ULL * 1024ULL * 1024ULL;
	options.volume_label = L"BENCH";
	options.compression_enabled = config->compression_enabled;
	options.compression_level = config->compression_level;
	options.encryption_enabled = config->encryption_enabled;
	if (config->has_encryption_key) {
		options.encryption_key = config->encryption_key;
		options.encryption_key_size = sizeof(config->encryption_key);
	}

	return memfs_create_ex(&options, out_fs);
}
static int bench_small_files(Memfs* fs, uint32_t count, LARGE_INTEGER frequency, BenchResult* result) {
	uint8_t one_byte = 0x5a;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t i;
	wchar_t name[32];

	printf("\n[small 1B create/delete]\n");
	printf("files:            %u\n", count);

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node = NULL;
		swprintf_s(name, _countof(name), L"small%07u", i);
		if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
			return fail(fs, "small create failed", i);
		}
		if (memfs_node_write(node, &one_byte, 0, BENCH_1B_SIZE, false, false, &(uint32_t){0}) != MEMFS_OK) {
			memfs_node_close(node);
			return fail(fs, "small write failed", i);
		}
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	result->create_seconds = seconds_between(start, end, frequency);
	print_rate("create+1B", count, result->create_seconds);
	result->used_after_create = (uint64_t)fs->used_bytes;
	result->resident_after_create = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-create");

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"small%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
			return fail(fs, "small delete failed", i);
		}
	}
	QueryPerformanceCounter(&end);
	result->delete_seconds = seconds_between(start, end, frequency);
	print_rate("delete", count, result->delete_seconds);
	result->used_after_delete = (uint64_t)fs->used_bytes;
	result->resident_after_delete = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-delete");

	return 0;
}
static int bench_4kb_files(Memfs* fs, uint32_t count, LARGE_INTEGER frequency, BenchResult* result) {
	uint8_t payload[BENCH_4KB_SIZE];
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t i;
	wchar_t name[32];

	memset(payload, 0x5a, sizeof(payload));

	printf("\n[4KB write]\n");
	printf("files:            %u\n", count);
	printf("bytes/file:       %u\n", BENCH_4KB_SIZE);

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node = NULL;
		uint32_t written = 0;
		swprintf_s(name, _countof(name), L"kb4%07u", i);
		if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
			return fail(fs, "4KB create failed", i);
		}
		if (memfs_node_write(node, payload, 0, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
			written != BENCH_4KB_SIZE) {
			memfs_node_close(node);
			return fail(fs, "4KB write failed", i);
		}
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	result->create_seconds = seconds_between(start, end, frequency);
	print_rate("create+4KB", count, result->create_seconds);
	result->used_after_create = (uint64_t)fs->used_bytes;
	result->resident_after_create = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-create");

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"kb4%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
			return fail(fs, "4KB delete failed", i);
		}
	}
	QueryPerformanceCounter(&end);
	result->delete_seconds = seconds_between(start, end, frequency);
	print_rate("delete", count, result->delete_seconds);
	result->used_after_delete = (uint64_t)fs->used_bytes;
	result->resident_after_delete = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-delete");

	return 0;
}
static int bench_1mb_sparse_write(Memfs* fs, uint32_t count, LARGE_INTEGER frequency, BenchResult* result) {
	uint8_t page[BENCH_4KB_SIZE];
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t i;
	wchar_t name[32];

	memset(page, 0x5a, sizeof(page));

	printf("\n[1MB sparse write]\n");
	printf("files:            %u\n", count);
	printf("bytes/file:       %llu\n", (unsigned long long)BENCH_1MB_SIZE);
	printf("write pattern:    4KB at offset 0 and 1MB-4KB\n");

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node = NULL;
		uint32_t written = 0;
		swprintf_s(name, _countof(name), L"mb1%07u", i);
		if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
			return fail(fs, "1MB create failed", i);
		}
		if (memfs_node_write(node, page, 0, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
			written != BENCH_4KB_SIZE) {
			memfs_node_close(node);
			return fail(fs, "1MB first write failed", i);
		}
		if (memfs_node_write(node, page, BENCH_1MB_SIZE - BENCH_4KB_SIZE, BENCH_4KB_SIZE, true, false, &written) !=
			MEMFS_OK ||
			written != BENCH_4KB_SIZE) {
			memfs_node_close(node);
			return fail(fs, "1MB tail write failed", i);
		}
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	result->create_seconds = seconds_between(start, end, frequency);
	print_rate("create+sparse", count, result->create_seconds);
	result->used_after_create = (uint64_t)fs->used_bytes;
	result->resident_after_create = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-create");

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"mb1%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
			return fail(fs, "1MB delete failed", i);
		}
	}
	QueryPerformanceCounter(&end);
	result->delete_seconds = seconds_between(start, end, frequency);
	print_rate("delete", count, result->delete_seconds);
	result->used_after_delete = (uint64_t)fs->used_bytes;
	result->resident_after_delete = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-delete");

	return 0;
}
static int bench_random_rewrite(Memfs* fs, uint32_t count, LARGE_INTEGER frequency, BenchResult* result) {
	uint8_t page[BENCH_4KB_SIZE];
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t i;
	wchar_t name[32];

	memset(page, 0x5a, sizeof(page));

	printf("\n[random rewrite]\n");
	printf("files:            %u\n", count);
	printf("rewrite size:     %u B\n", BENCH_4KB_SIZE);
	printf("file size:        %llu\n", (unsigned long long)BENCH_1MB_SIZE);

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node = NULL;
		uint32_t written = 0;
		uint64_t offset;
		swprintf_s(name, _countof(name), L"rw%07u", i);
		if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
			return fail(fs, "rewrite create failed", i);
		}
		if (memfs_node_write(node, page, 0, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
			written != BENCH_4KB_SIZE) {
			memfs_node_close(node);
			return fail(fs, "rewrite seed write failed", i);
		}
		if (memfs_node_set_file_size(node, BENCH_1MB_SIZE) != MEMFS_OK) {
			memfs_node_close(node);
			return fail(fs, "rewrite resize failed", i);
		}
		offset = ((uint64_t)i * 2654435761ULL) % (BENCH_1MB_SIZE / BENCH_4KB_SIZE) * BENCH_4KB_SIZE;
		if (memfs_node_write(node, page, offset, BENCH_4KB_SIZE, false, false, &written) != MEMFS_OK ||
			written != BENCH_4KB_SIZE) {
			memfs_node_close(node);
			return fail(fs, "rewrite random write failed", i);
		}
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	result->create_seconds = seconds_between(start, end, frequency);
	print_rate("create+rewrite", count, result->create_seconds);
	result->used_after_create = (uint64_t)fs->used_bytes;
	result->resident_after_create = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-create");

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"rw%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
			return fail(fs, "rewrite delete failed", i);
		}
	}
	QueryPerformanceCounter(&end);
	result->delete_seconds = seconds_between(start, end, frequency);
	print_rate("delete", count, result->delete_seconds);
	result->used_after_delete = (uint64_t)fs->used_bytes;
	result->resident_after_delete = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-delete");

	return 0;
}
static int bench_large_dir(Memfs* fs, uint32_t count, LARGE_INTEGER frequency, BenchResult* result) {
	uint8_t one_byte = 0x5a;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t i;
	wchar_t name[32];

	printf("\n[large dir create/lookup/delete]\n");
	printf("files:            %u\n", count);

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node = NULL;
		swprintf_s(name, _countof(name), L"ld%07u", i);
		if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
			return fail(fs, "large dir create failed", i);
		}
		if (memfs_node_write(node, &one_byte, 0, BENCH_1B_SIZE, false, false, &(uint32_t){0}) != MEMFS_OK) {
			memfs_node_close(node);
			return fail(fs, "large dir write failed", i);
		}
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	result->create_seconds = seconds_between(start, end, frequency);
	print_rate("create+1B", count, result->create_seconds);
	result->used_after_create = (uint64_t)fs->used_bytes;
	result->resident_after_create = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-create");


	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"ld%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL) {
			return fail(fs, "large dir lookup failed", i);
		}
	}
	QueryPerformanceCounter(&end);
	result->lookup_seconds = seconds_between(start, end, frequency);
	print_rate("lookup", count, result->lookup_seconds);

	QueryPerformanceCounter(&start);
	for (i = 0; i < count; i++) {
		MemfsNode* node;
		swprintf_s(name, _countof(name), L"ld%07u", i);
		node = memfs_dir_lookup(fs->root, name);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
			return fail(fs, "large dir delete failed", i);
		}
	}
	QueryPerformanceCounter(&end);
	result->delete_seconds = seconds_between(start, end, frequency);
	print_rate("delete", count, result->delete_seconds);
	result->used_after_delete = (uint64_t)fs->used_bytes;
	result->resident_after_delete = (uint64_t)fs->resident_bytes;
	print_fs_state(fs, "after-delete");

	return 0;
}
#define BENCH_SWEEP_FILE_COUNT 10000U
#define BENCH_HIGH_OFFSET_1GB (1ULL << 30)
#define BENCH_HIGH_OFFSET_64GB (64ULL << 30)
#define BENCH_HIGH_OFFSET_1GB_COUNT 1000U
#define BENCH_HIGH_OFFSET_64GB_COUNT 100U

static int bench_high_offset_sparse(Memfs* fs, LARGE_INTEGER frequency) {
	uint8_t page[BENCH_4KB_SIZE];
	uint64_t offsets[2] = {BENCH_HIGH_OFFSET_1GB, BENCH_HIGH_OFFSET_64GB};
	uint32_t counts[2] = {BENCH_HIGH_OFFSET_1GB_COUNT, BENCH_HIGH_OFFSET_64GB_COUNT};
	const char* labels[2] = {"1GiB", "64GiB"};
	uint32_t o;

	memset(page, 0x5a, sizeof(page));

	printf("\n[high offset sparse single-page write]\n");
	printf("pattern:          create file, write 4KB at logical offset, close, unlink\n");
	printf("expectation:      page_group_count=1 per file if high offset does not allocate dense intermediate tables\n");

	for (o = 0; o < 2; o++) {
		Memfs* target_fs = fs;
		Memfs* temp_fs = NULL;
		uint64_t offset = offsets[o];
		uint32_t count = counts[o];
		uint64_t private_before;
		uint64_t private_after;
		uint64_t used_before;
		uint64_t used_after;
		uint64_t resident_before;
		uint64_t resident_after;
		MemfsAllocatorStats alloc_before;
		MemfsAllocatorStats alloc_after;
		LARGE_INTEGER start;
		LARGE_INTEGER end;
		double create_seconds;
		uint32_t i;
		wchar_t name[32];
		uint32_t last_group_count = 0;
		uint32_t last_group_capacity = 0;
		uint64_t last_group_index = 0;
		uint64_t last_node_resident = 0;
		int rc = 0;

		if (o == 1) {
			MemfsOptions options;
			memset(&options, 0, sizeof(options));
			options.capacity = 128ULL * 1024ULL * 1024ULL * 1024ULL;
			options.volume_label = L"BENCH_HIGH_OFFSET";
			rc = memfs_create_ex(&options, &temp_fs);
			if (rc != MEMFS_OK) {
				fprintf(stderr, "high offset 64GiB temp fs create failed rc=%d\n", rc);
				return 1;
			}
			target_fs = temp_fs;
		}

		printf("\n[high offset %s]\n", labels[o]);
		printf("files:            %u\n", count);
		printf("logical offset:   %llu B\n", (unsigned long long)offset);
		printf("write size:       %u B\n", BENCH_4KB_SIZE);
		printf("capacity:         %llu B\n", (unsigned long long)target_fs->capacity);

		private_before = private_bytes();
		used_before = target_fs->used_bytes;
		resident_before = target_fs->resident_bytes;
		memfs_allocator_get_stats(&target_fs->allocator, &alloc_before);

		QueryPerformanceCounter(&start);
		for (i = 0; i < count; i++) {
			MemfsNode* node = NULL;
			uint32_t written = 0;
			MemfsResult write_rc;
			swprintf_s(name, _countof(name), L"ho%07u", i);
			if (memfs_node_create(target_fs, target_fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) !=
				MEMFS_OK) {
				rc = 1;
				break;
			}
			write_rc = memfs_node_write(node, page, offset, BENCH_4KB_SIZE, false, false, &written);
			if (write_rc != MEMFS_OK || written != BENCH_4KB_SIZE) {
				fprintf(stderr, "high offset %s write failed rc=%d written=%u\n", labels[o], write_rc, written);
				(void)memfs_node_unlink(node);
				memfs_node_close(node);
				rc = 1;
				break;
			}
			last_group_count = memfs_node_page_group_count(node);
			last_group_capacity = memfs_node_page_group_capacity(node);
			last_group_index = last_group_count > 0 ? memfs_node_page_group_index(node, 0) : 0;
			last_node_resident = memfs_node_resident_bytes(node);
			if (memfs_node_unlink(node) != MEMFS_OK) {
				memfs_node_close(node);
				rc = 1;
				break;
			}
			memfs_node_close(node);
		}
		QueryPerformanceCounter(&end);
		create_seconds = seconds_between(start, end, frequency);

		private_after = private_bytes();
		used_after = target_fs->used_bytes;
		resident_after = target_fs->resident_bytes;
		memfs_allocator_get_stats(&target_fs->allocator, &alloc_after);

		printf("%-20s %10.3f s  %12.0f ops/s\n", "create+write+delete", create_seconds,
			   create_seconds > 0.0 ? (double)count / create_seconds : 0.0);
		printf("last page_group_count=%u page_group_capacity=%u first_group_index=%llu node_resident=%llu B\n",
			   last_group_count, last_group_capacity, (unsigned long long)last_group_index,
			   (unsigned long long)last_node_resident);
		printf("after-lifecycle used_bytes=%llu resident_bytes=%llu\n", (unsigned long long)used_after,
			   (unsigned long long)resident_after);
		printf("used delta:         %llu B resident delta: %llu B\n",
			   (unsigned long long)(used_after - used_before),
			   (unsigned long long)(resident_after - resident_before));
		printf("private delta:      %llu B (%.2f MiB)\n", (unsigned long long)(private_after - private_before),
			   (double)(private_after - private_before) / (1024.0 * 1024.0));
		printf("alloc reserved delta=%llu B live delta=%llu B live_objects delta=%llu\n",
			   (unsigned long long)(alloc_after.reserved_bytes - alloc_before.reserved_bytes),
			   (unsigned long long)(alloc_after.live_bytes - alloc_before.live_bytes),
			   (unsigned long long)(alloc_after.live_objects - alloc_before.live_objects));

		if (temp_fs != NULL) {
			memfs_destroy(temp_fs);
		}
		if (rc != 0) {
			return rc;
		}
	}

	return 0;
}
static int bench_small_size_sweep(Memfs* fs, uint32_t count, LARGE_INTEGER frequency) {
	static const uint32_t sizes[6] = {0U, 1U, 8U, 9U, 64U, 4096U};
	uint8_t payload[BENCH_4KB_SIZE];
	uint32_t s;
	uint32_t i;
	wchar_t name[32];

	memset(payload, 0x5a, sizeof(payload));

	printf("\n[small size sweep]\n");
	printf("files:            %u\n", count);
	printf("%-8s %-8s %12s %18s %16s %24s %18s %20s %14s %16s\n", "size(B)", "files", "create_ops/s",
		   "private_delta(B)", "private/file(B)", "alloc_reserved_delta(B)", "alloc_live_delta(B)",
		   "alloc_live_obj_delta", "used/file(B)", "resident/file(B)");

	for (s = 0; s < 6; s++) {
		uint32_t size = sizes[s];
		uint64_t private_before;
		uint64_t private_after;
		uint64_t used_before;
		uint64_t used_after;
		uint64_t resident_before;
		uint64_t resident_after;
		MemfsAllocatorStats alloc_before;
		MemfsAllocatorStats alloc_after;
		LARGE_INTEGER start;
		LARGE_INTEGER end;
		double create_seconds;

		private_before = private_bytes();
		used_before = fs->used_bytes;
		resident_before = fs->resident_bytes;
		memfs_allocator_get_stats(&fs->allocator, &alloc_before);

		QueryPerformanceCounter(&start);
		for (i = 0; i < count; i++) {
			MemfsNode* node = NULL;
			swprintf_s(name, _countof(name), L"ss%07u", i);
			if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK) {
				return fail(fs, "sweep create failed", i);
			}
			if (size > 0) {
				uint32_t written = 0;
				if (memfs_node_write(node, payload, 0, size, false, false, &written) != MEMFS_OK ||
					written != size) {
					memfs_node_close(node);
					return fail(fs, "sweep write failed", i);
				}
			}
			memfs_node_close(node);
		}
		QueryPerformanceCounter(&end);
		create_seconds = seconds_between(start, end, frequency);

		private_after = private_bytes();
		used_after = fs->used_bytes;
		resident_after = fs->resident_bytes;
		memfs_allocator_get_stats(&fs->allocator, &alloc_after);

		printf("%-8u %-8u %12.0f %18llu %16.2f %24llu %18llu %20llu %14.2f %16.2f\n", size, count,
			   create_seconds > 0.0 ? (double)count / create_seconds : 0.0,
			   (unsigned long long)(private_after - private_before),
			   (double)(private_after - private_before) / (double)count,
			   (unsigned long long)(alloc_after.reserved_bytes - alloc_before.reserved_bytes),
			   (unsigned long long)(alloc_after.live_bytes - alloc_before.live_bytes),
			   (unsigned long long)(alloc_after.live_objects - alloc_before.live_objects),
			   (double)(used_after - used_before) / (double)count,
			   (double)(resident_after - resident_before) / (double)count);

		for (i = 0; i < count; i++) {
			MemfsNode* node;
			swprintf_s(name, _countof(name), L"ss%07u", i);
			node = memfs_dir_lookup(fs->root, name);
			if (node == NULL || memfs_node_unlink(node) != MEMFS_OK) {
				return fail(fs, "sweep delete failed", i);
			}
		}
		printf("size=%u after-delete used_bytes=%llu resident_bytes=%llu\n", size,
			   (unsigned long long)fs->used_bytes, (unsigned long long)fs->resident_bytes);
	}

	return 0;
}
#define BENCH_ALLOC_FRAGMENT_ROUNDS 8U
#define BENCH_ALLOC_FRAGMENT_OBJECTS 256U
#define BENCH_ALLOC_FRAGMENT_REFILL_OBJECTS (BENCH_ALLOC_FRAGMENT_OBJECTS / 2U)
#define BENCH_ALLOC_MIXED_COUNT 10U

static const size_t g_bench_alloc_mixed_sizes[BENCH_ALLOC_MIXED_COUNT] = {
	8U, 64U, 256U, 512U, 1024U, 4096U, 16384U, 32768U, 65536U, 262144U,
};

static void print_alloc_fragment_stats(const char* phase, uint32_t round, const MemfsAllocatorStats* stats) {
	uint64_t slab_reserved =
		stats->reserved_bytes >= stats->dedicated_reserved_bytes
			? stats->reserved_bytes - stats->dedicated_reserved_bytes
			: 0;

	printf("round=%u phase=%-12s live=%llu reserved=%llu slab_reserved=%llu area_cached=%llu committed=%llu physical=%llu slab_count=%u dedicated_count=%u\n",
		   round, phase,
		   (unsigned long long)stats->live_bytes,
		   (unsigned long long)stats->reserved_bytes,
		   (unsigned long long)slab_reserved,
		   (unsigned long long)stats->area_cached_bytes,
		   (unsigned long long)stats->committed_bytes,
		   (unsigned long long)stats->physical_bytes,
		   stats->slab_count, stats->dedicated_count);
}

static bool alloc_fragment_quiescent(
	const MemfsAllocatorStats* stats, const MemfsAllocatorStats* baseline) {
	return stats->live_objects == baseline->live_objects &&
		   stats->live_bytes == baseline->live_bytes &&
		   stats->physical_bytes == stats->committed_bytes &&
		   stats->slab_count == baseline->slab_count &&
		   stats->dedicated_count == baseline->dedicated_count &&
		   stats->dedicated_live_bytes == baseline->dedicated_live_bytes;
}

static bool alloc_fragment_back_to_baseline(
	const MemfsAllocatorStats* stats, const MemfsAllocatorStats* baseline) {
	return alloc_fragment_quiescent(stats, baseline) &&
		   stats->reserved_bytes == baseline->reserved_bytes &&
		   stats->committed_bytes == baseline->committed_bytes &&
		   stats->physical_bytes == baseline->physical_bytes &&
		   stats->dedicated_reserved_bytes == baseline->dedicated_reserved_bytes &&
		   stats->dedicated_committed_bytes == baseline->dedicated_committed_bytes &&
		   stats->area_cached_count == 0U &&
		   stats->area_cached_bytes == 0U;
}

static bool alloc_fragment_same_high_water(
	const MemfsAllocatorStats* stats, const MemfsAllocatorStats* first) {
	return stats->reserved_bytes == first->reserved_bytes &&
		   stats->committed_bytes == first->committed_bytes &&
		   stats->physical_bytes == first->physical_bytes &&
		   stats->slab_count == first->slab_count &&
		   stats->dedicated_count == first->dedicated_count;
}

static uint64_t alloc_fragment_slab_reserved(
	const MemfsAllocatorStats* stats) {
	return stats->reserved_bytes >= stats->dedicated_reserved_bytes
		? stats->reserved_bytes - stats->dedicated_reserved_bytes
		: 0;
}

static uint64_t alloc_fragment_slab_committed(
	const MemfsAllocatorStats* stats) {
	return stats->committed_bytes >= stats->dedicated_committed_bytes
		? stats->committed_bytes - stats->dedicated_committed_bytes
		: 0;
}

static bool alloc_fragment_same_slab_high_water(
	const MemfsAllocatorStats* stats, const MemfsAllocatorStats* first) {
	return alloc_fragment_slab_reserved(stats) ==
			   alloc_fragment_slab_reserved(first) &&
		   alloc_fragment_slab_committed(stats) ==
			   alloc_fragment_slab_committed(first) &&
		   stats->slab_count == first->slab_count;
}

static bool alloc_fragment_slab_back_to_baseline(
	const MemfsAllocatorStats* stats, const MemfsAllocatorStats* baseline) {
	return stats->live_objects == baseline->live_objects &&
		   stats->live_bytes == baseline->live_bytes &&
		   stats->slab_count == baseline->slab_count &&
		   alloc_fragment_slab_reserved(stats) ==
			   alloc_fragment_slab_reserved(baseline) &&
		   alloc_fragment_slab_committed(stats) ==
			   alloc_fragment_slab_committed(baseline) &&
		   stats->dedicated_count == baseline->dedicated_count &&
		   stats->dedicated_live_bytes == baseline->dedicated_live_bytes;
}

static int bench_allocator_fragmentation_reuse(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats full;
	MemfsAllocatorStats partial;
	MemfsAllocatorStats refilled;
	MemfsAllocatorStats released;
	MemfsAllocatorStats mixed_full;
	MemfsAllocatorStats mixed_released;
	MemfsAllocatorStats first_full = {0};
	MemfsAllocatorStats first_mixed_full = {0};
	void* blocks[BENCH_ALLOC_FRAGMENT_OBJECTS] = {0};
	void* refill[BENCH_ALLOC_FRAGMENT_REFILL_OBJECTS] = {0};
	void* mixed[BENCH_ALLOC_MIXED_COUNT] = {0};
	uint32_t round;
	uint32_t i;
	int rc = 0;

	memset(&allocator, 0, sizeof(allocator));
	if (!memfs_allocator_init(&allocator, 64U, 64U, 64U)) {
		fprintf(stderr, "allocator fragmentation init failed\n");
		return 1;
	}

	memfs_allocator_get_stats(&allocator, &baseline);
	printf("\n[allocator fragmentation/reuse]\n");
	printf("rounds:           %u\n", BENCH_ALLOC_FRAGMENT_ROUNDS);
	printf("512B objects:     %u (free/refill %u)\n", BENCH_ALLOC_FRAGMENT_OBJECTS,
		   BENCH_ALLOC_FRAGMENT_REFILL_OBJECTS);
	printf("mixed sizes:      8,64,256,512,1024,4096,16384,32768,65536,262144\n");
	printf("checks:           exact partial reuse, baseline reclaim, stable per-round high-water\n");
	print_alloc_fragment_stats("baseline", 0U, &baseline);

	for (round = 0; round < BENCH_ALLOC_FRAGMENT_ROUNDS; round++) {
		memset(blocks, 0, sizeof(blocks));
		memset(refill, 0, sizeof(refill));
		memset(mixed, 0, sizeof(mixed));

		for (i = 0; i < BENCH_ALLOC_FRAGMENT_OBJECTS; i++) {
			blocks[i] = memfs_allocator_alloc(&allocator, 512U);
			if (blocks[i] == NULL) {
				fprintf(stderr, "allocator 512B alloc failed round=%u index=%u\n", round, i);
				rc = 1;
				goto cleanup;
			}
			((uint8_t*)blocks[i])[0] = (uint8_t)(round + i);
		}

		memfs_allocator_get_stats(&allocator, &full);
		print_alloc_fragment_stats("512-full", round, &full);
		if (full.slab_count < 3U || full.physical_bytes != full.committed_bytes) {
			fprintf(stderr, "allocator 512B full-state invariant failed round=%u\n", round);
			rc = 1;
			goto cleanup;
		}
		if (round == 0U) {
			first_full = full;
		} else if (!alloc_fragment_same_slab_high_water(&full, &first_full)) {
			fprintf(stderr, "allocator 512B slab high-water drift round=%u\n", round);
			rc = 1;
			goto cleanup;
		}

		for (i = 0; i < BENCH_ALLOC_FRAGMENT_OBJECTS; i += 2U) {
			memfs_allocator_free(&allocator, blocks[i], 512U);
			blocks[i] = NULL;
		}
		memfs_allocator_get_stats(&allocator, &partial);
		print_alloc_fragment_stats("512-partial", round, &partial);

		for (i = 0; i < BENCH_ALLOC_FRAGMENT_REFILL_OBJECTS; i++) {
			refill[i] = memfs_allocator_alloc(&allocator, 512U);
			if (refill[i] == NULL) {
				fprintf(stderr, "allocator 512B refill failed round=%u index=%u\n", round, i);
				rc = 1;
				goto cleanup;
			}
			((uint8_t*)refill[i])[0] = (uint8_t)(round + i + 1U);
		}
		memfs_allocator_get_stats(&allocator, &refilled);
		print_alloc_fragment_stats("512-refill", round, &refilled);
		if (refilled.live_objects != full.live_objects ||
			refilled.live_bytes != full.live_bytes ||
			refilled.slab_count != full.slab_count ||
			refilled.reserved_bytes != full.reserved_bytes ||
			refilled.committed_bytes != full.committed_bytes ||
			refilled.physical_bytes != full.physical_bytes ||
			refilled.dedicated_count != full.dedicated_count) {
			fprintf(stderr, "allocator 512B partial refill grew/changed high-water round=%u\n", round);
			rc = 1;
			goto cleanup;
		}

		for (i = 0; i < BENCH_ALLOC_FRAGMENT_OBJECTS; i++) {
			if (blocks[i] != NULL) {
				memfs_allocator_free(&allocator, blocks[i], 512U);
				blocks[i] = NULL;
			}
		}
		for (i = 0; i < BENCH_ALLOC_FRAGMENT_REFILL_OBJECTS; i++) {
			if (refill[i] != NULL) {
				memfs_allocator_free(&allocator, refill[i], 512U);
				refill[i] = NULL;
			}
		}
		memfs_allocator_get_stats(&allocator, &released);
		print_alloc_fragment_stats("512-free", round, &released);
		if (!alloc_fragment_slab_back_to_baseline(&released, &baseline)) {
			fprintf(stderr, "allocator 512B free did not return slab state to baseline round=%u\n", round);
			rc = 1;
			goto cleanup;
		}

		for (i = 0; i < BENCH_ALLOC_MIXED_COUNT; i++) {
			size_t size = g_bench_alloc_mixed_sizes[i];
			size_t touch = size < 16U ? size : 16U;
			mixed[i] = memfs_allocator_alloc(&allocator, size);
			if (mixed[i] == NULL) {
				fprintf(stderr, "allocator mixed alloc failed round=%u index=%u size=%llu\n",
						round, i, (unsigned long long)size);
				rc = 1;
				goto cleanup;
			}
			memset(mixed[i], (int)(0x40U + i), touch);
		}
		memfs_allocator_get_stats(&allocator, &mixed_full);
		print_alloc_fragment_stats("mixed-full", round, &mixed_full);
		if (mixed_full.physical_bytes != mixed_full.committed_bytes) {
			fprintf(stderr, "allocator mixed physical/committed mismatch round=%u\n", round);
			rc = 1;
			goto cleanup;
		}
		if (round == 0U) {
			first_mixed_full = mixed_full;
		} else if (!alloc_fragment_same_high_water(&mixed_full, &first_mixed_full)) {
			fprintf(stderr, "allocator mixed high-water drift round=%u\n", round);
			rc = 1;
			goto cleanup;
		}

		for (i = 0; i < BENCH_ALLOC_MIXED_COUNT; i++) {
			if (mixed[i] != NULL) {
				memfs_allocator_free(&allocator, mixed[i], g_bench_alloc_mixed_sizes[i]);
				mixed[i] = NULL;
			}
		}
		memfs_allocator_get_stats(&allocator, &mixed_released);
		print_alloc_fragment_stats("mixed-free", round, &mixed_released);
		if (!alloc_fragment_quiescent(&mixed_released, &baseline)) {
			fprintf(stderr, "allocator mixed free left live allocations round=%u\n", round);
			rc = 1;
			goto cleanup;
		}
	}

	(void)memfs_allocator_scavenge(&allocator);
	memfs_allocator_get_stats(&allocator, &mixed_released);
	print_alloc_fragment_stats("scavenged", BENCH_ALLOC_FRAGMENT_ROUNDS, &mixed_released);
	if (!alloc_fragment_back_to_baseline(&mixed_released, &baseline)) {
		fprintf(stderr, "allocator scavenge did not return to baseline\n");
		rc = 1;
	}

cleanup:
	for (i = 0; i < BENCH_ALLOC_FRAGMENT_OBJECTS; i++) {
		if (blocks[i] != NULL) {
			memfs_allocator_free(&allocator, blocks[i], 512U);
			blocks[i] = NULL;
		}
	}
	for (i = 0; i < BENCH_ALLOC_FRAGMENT_REFILL_OBJECTS; i++) {
		if (refill[i] != NULL) {
			memfs_allocator_free(&allocator, refill[i], 512U);
			refill[i] = NULL;
		}
	}
	for (i = 0; i < BENCH_ALLOC_MIXED_COUNT; i++) {
		if (mixed[i] != NULL) {
			memfs_allocator_free(&allocator, mixed[i], g_bench_alloc_mixed_sizes[i]);
			mixed[i] = NULL;
		}
	}

	memfs_allocator_destroy(&allocator);
	printf("allocator fragmentation/reuse: %s\n", rc == 0 ? "pass" : "FAIL");
	return rc;
}



static int bench_pressure_policy(LARGE_INTEGER frequency) {
#if defined(NDEBUG)
	(void)frequency;
	fprintf(stderr, "--pressure-policy requires a Debug build with deterministic pressure hooks\n");
	return 2;
#else
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	MemfsAllocatorStats before;
	MemfsAllocatorStats after_soft;
	void* cached[4] = {0};
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double soft_seconds;
	uint32_t i;
	int rc = 1;

	options.capacity_auto = true;
	options.volume_label = L"PRESSBENCH";
	memfs_test_clear_system_available_bytes();

	if (memfs_create_ex(&options, &fs) != MEMFS_OK || fs == NULL)
		goto cleanup;
	if (memfs_node_create(fs, fs->root, L"pressure.bin", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) != MEMFS_OK || file == NULL)
		goto cleanup;

	for (i = 0; i < _countof(cached); i++) {
		cached[i] = memfs_allocator_alloc(&fs->allocator, 16U * 1024U);
		if (cached[i] == NULL)
			goto cleanup;
	}
	for (i = 0; i < _countof(cached); i++) {
		memfs_allocator_free(&fs->allocator, cached[i], 16U * 1024U);
		cached[i] = NULL;
	}

	memfs_allocator_get_stats(&fs->allocator, &before);
	fs->pressure_last_scavenge_tick = 0;
	memfs_test_set_system_available_bytes(320ULL * 1024ULL * 1024ULL);

	QueryPerformanceCounter(&start);
	if (memfs_node_set_file_size(file, 1U) != MEMFS_OK)
		goto cleanup;
	QueryPerformanceCounter(&end);
	soft_seconds = seconds_between(start, end, frequency);
	memfs_allocator_get_stats(&fs->allocator, &after_soft);

	printf("\n[adaptive pressure policy]\n");
	printf("soft_available=320MiB cached_before=%u/%lluB cached_after=%u/%lluB "
		   "scavenge_count=%llu latency_us=%.2f\n",
		   before.area_cached_count,
		   (unsigned long long)before.area_cached_bytes,
		   after_soft.area_cached_count,
		   (unsigned long long)after_soft.area_cached_bytes,
		   (unsigned long long)after_soft.scavenge_count,
		   soft_seconds * 1000000.0);

	if (before.area_cached_count == 0U ||
		after_soft.area_cached_count != 0U ||
		after_soft.area_cached_bytes != 0U)
		goto cleanup;

	fs->pressure_last_scavenge_tick = 0;
	memfs_test_set_system_available_bytes(128ULL * 1024ULL * 1024ULL);
	if (memfs_node_set_file_size(file, 2U) != MEMFS_ERR_NO_SPACE)
		goto cleanup;
	printf("hard_available=128MiB result=NO_SPACE file_size=%llu\n",
		   (unsigned long long)file->file_size);

	fs->pressure_last_scavenge_tick = 0;
	memfs_test_set_system_available_bytes(2ULL * 1024ULL * 1024ULL * 1024ULL);
	if (memfs_node_set_file_size(file, 2U) != MEMFS_OK)
		goto cleanup;
	printf("relief_available=2GiB result=OK file_size=%llu\n",
		   (unsigned long long)file->file_size);

	rc = 0;

cleanup:
	memfs_test_clear_system_available_bytes();
	for (i = 0; i < _countof(cached); i++) {
		if (cached[i] != NULL)
			memfs_allocator_free(&fs->allocator, cached[i], 16U * 1024U);
	}
	if (file != NULL) {
		(void)memfs_node_unlink(file);
		memfs_node_close(file);
	}
	if (fs != NULL)
		memfs_destroy(fs);
	return rc;
#endif
}

static int run_suite(const BenchConfig* config, const char* label, LARGE_INTEGER frequency, BenchResult* results) {
	Memfs* fs = NULL;
	uint64_t private_before;
	uint64_t private_after;
	MemfsAllocatorStats stats;
	int rc;

	printf("\n=== mode: %s ===\n", label);
	print_config(config);

	if (create_fs(config, &fs) != MEMFS_OK) {
		fprintf(stderr, "memfs_create_ex failed for %s\n", label);
		return 1;
	}

	printf("MemfsNode:          %zu B\n", sizeof(MemfsNode));
	printf("capacity:           %llu B\n", (unsigned long long)fs->capacity);
	print_fs_state(fs, "initial");

	private_before = private_bytes();

	rc = bench_small_size_sweep(fs, BENCH_SWEEP_FILE_COUNT, frequency);
	if (rc != 0) {
		return rc;
	}

	results[0].label = "small";
	rc = bench_small_files(fs, BENCH_SMALL_FILE_COUNT, frequency, &results[0]);
	if (rc != 0) {
		return rc;
	}

	results[1].label = "4kb";
	rc = bench_4kb_files(fs, BENCH_4KB_FILE_COUNT, frequency, &results[1]);
	if (rc != 0) {
		return rc;
	}

	results[2].label = "1mb";
	rc = bench_1mb_sparse_write(fs, BENCH_1MB_FILE_COUNT, frequency, &results[2]);
	if (rc != 0) {
		return rc;
	}

	results[3].label = "rewrite";
	rc = bench_random_rewrite(fs, BENCH_RANDOM_REWRITE_COUNT, frequency, &results[3]);
	if (rc != 0) {
		return rc;
	}

	{
		static const uint32_t large_dir_counts[4] = {128U, 256U, 512U, 4096U};
		static const char* large_dir_labels[4] = {"dir128", "dir256", "dir512", "dir4096"};
		uint32_t k;
		for (k = 0; k < 4; k++) {
			results[4 + k].label = large_dir_labels[k];
			rc = bench_large_dir(fs, large_dir_counts[k], frequency, &results[4 + k]);
			if (rc != 0) {
				return rc;
			}
		}
	}

	rc = bench_high_offset_sparse(fs, frequency);
	if (rc != 0) {
		return rc;
	}
	rc = bench_churn_high_water(fs, frequency);
	if (rc != 0) {
		return rc;
	}

	rc = bench_random_rewrite_full(fs, frequency);
	if (rc != 0) {
		return rc;
	}

	rc = bench_auto_capacity_status(frequency);
	if (rc != 0) {
		return rc;
	}

	rc = bench_allocator_fragmentation_reuse();
	if (rc != 0) {
		return rc;
	}

	private_after = private_bytes();
	memfs_allocator_get_stats(&fs->allocator, &stats);

	printf("\n[summary %s]\n", label);
	printf("private delta:      %.2f MiB\n", (double)(private_after - private_before) / (1024.0 * 1024.0));
	printf("allocator reserved: %.2f MiB\n", (double)stats.reserved_bytes / (1024.0 * 1024.0));
	printf("allocator live:     %llu objects / %.2f MiB\n", (unsigned long long)stats.live_objects,
		   (double)stats.live_bytes / (1024.0 * 1024.0));
	printf("allocator slabs:    %u\n", stats.slab_count);
	{
		uint64_t waste_bytes = stats.reserved_bytes > stats.live_bytes ? stats.reserved_bytes - stats.live_bytes : 0;
		double waste_percent = stats.reserved_bytes > 0 ? (double)waste_bytes * 100.0 / (double)stats.reserved_bytes : 0.0;
		printf("allocator reserved_bytes: %llu B\n", (unsigned long long)stats.reserved_bytes);
		printf("allocator live_bytes:     %llu B\n", (unsigned long long)stats.live_bytes);
		printf("allocator waste_bytes:    %llu B\n", (unsigned long long)waste_bytes);
		printf("allocator waste_percent:  %.2f%%\n", waste_percent);
	}
	print_fs_state(fs, "final");

	memfs_destroy(fs);
	return 0;
}
static void print_comparison(const BenchResult* plain, const BenchResult* compression, const BenchResult* encryption,
								const BenchResult* combined) {
	const BenchResult* modes[4];
	const char* names[4];
	uint32_t i;

	modes[0] = plain;
	names[0] = "plain";
	modes[1] = compression;
	names[1] = "compression";
	modes[2] = encryption;
	names[2] = "encryption";
	modes[3] = combined;
	names[3] = "combined";

	printf("\n[comparison]\n");
	printf("%-12s %-10s %12s %12s %12s %12s\n", "mode", "suite", "create_ops/s", "delete_ops/s", "used_after", "resident_after");
	for (i = 0; i < 8; i++) {
		uint32_t counts[8] = {BENCH_SMALL_FILE_COUNT, BENCH_4KB_FILE_COUNT, BENCH_1MB_FILE_COUNT, BENCH_RANDOM_REWRITE_COUNT,
							  128U, 256U, 512U, 4096U};
		uint32_t j;

		for (j = 0; j < 4; j++) {
			double create_ops = modes[j][i].create_seconds > 0.0 ? (double)counts[i] / modes[j][i].create_seconds : 0.0;
			double delete_ops = modes[j][i].delete_seconds > 0.0 ? (double)counts[i] / modes[j][i].delete_seconds : 0.0;

			printf("%-12s %-10s %12.0f %12.0f %12llu %12llu\n", names[j], modes[j][i].label, create_ops, delete_ops,
				   (unsigned long long)modes[j][i].used_after_create,
				   (unsigned long long)modes[j][i].resident_after_create);
		}
	}
}
static void print_comparison_csv(const BenchResult* plain, const BenchResult* compression, const BenchResult* encryption,
								  const BenchResult* combined) {
	const BenchResult* modes[4];
	const char* names[4];
	uint32_t i;
	uint32_t counts[8] = {BENCH_SMALL_FILE_COUNT, BENCH_4KB_FILE_COUNT, BENCH_1MB_FILE_COUNT, BENCH_RANDOM_REWRITE_COUNT,
						  128U, 256U, 512U, 4096U};

	modes[0] = plain;
	names[0] = "plain";
	modes[1] = compression;
	names[1] = "compression";
	modes[2] = encryption;
	names[2] = "encryption";
	modes[3] = combined;
	names[3] = "combined";

	printf("\n[comparison-csv]\n");
	printf("mode,suite,create_ops_per_s,delete_ops_per_s,used_after_create,resident_after_create\n");
	for (i = 0; i < 8; i++) {
		uint32_t j;
		for (j = 0; j < 4; j++) {
			double create_ops = modes[j][i].create_seconds > 0.0 ? (double)counts[i] / modes[j][i].create_seconds : 0.0;
			double delete_ops = modes[j][i].delete_seconds > 0.0 ? (double)counts[i] / modes[j][i].delete_seconds : 0.0;
			printf("%s,%s,%.0f,%.0f,%llu,%llu\n", names[j], modes[j][i].label, create_ops, delete_ops,
				   (unsigned long long)modes[j][i].used_after_create,
				   (unsigned long long)modes[j][i].resident_after_create);
		}
	}
}
static int bench_compression_page_rewrite(const BenchConfig* config, LARGE_INTEGER frequency) {
	Memfs* fs = NULL;
	MemfsNode* node = NULL;
	uint8_t page[BENCH_4KB_SIZE];
	uint8_t verify[BENCH_4KB_SIZE];
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint64_t private_before;
	uint64_t private_after;
	uint32_t written = 0;
	uint32_t read = 0;
	uint32_t i;
	double seconds;
	int rc = 1;

	if (create_fs(config, &fs) != MEMFS_OK || fs == NULL)
		return 1;

	if (memfs_node_create(fs, fs->root, L"compression-page.bin", false,
						  FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK || node == NULL)
		goto cleanup;

	private_before = private_bytes();
	memset(page, 0x5a, sizeof(page));
	if (memfs_node_write(node, page, 0, sizeof(page), false, false, &written) != MEMFS_OK ||
		written != sizeof(page))
		goto cleanup;

	QueryPerformanceCounter(&start);
	for (i = 0; i < BENCH_COMPRESSION_PAGE_REWRITE_COUNT; i++) {
		page[0] = (uint8_t)i;
		if (memfs_node_write(node, page, 0, sizeof(page), false, false, &written) != MEMFS_OK ||
			written != sizeof(page))
			goto cleanup;
	}
	QueryPerformanceCounter(&end);

	seconds = seconds_between(start, end, frequency);
	memset(verify, 0, sizeof(verify));
	if (memfs_node_read(node, verify, 0, sizeof(verify), &read) != MEMFS_OK ||
		read != sizeof(verify) || 0 != memcmp(page, verify, sizeof(page)))
		goto cleanup;

	private_after = private_bytes();
	printf("\n[compression 4KB page rewrite]\n");
	printf("rewrites:         %u\n", BENCH_COMPRESSION_PAGE_REWRITE_COUNT);
	printf("compression:      level=%d\n", config->compression_level);
	print_rate("rewrite4k", BENCH_COMPRESSION_PAGE_REWRITE_COUNT, seconds);
	printf("ns/op:            %.1f\n",
		   seconds > 0.0 ? seconds * 1000000000.0 / (double)BENCH_COMPRESSION_PAGE_REWRITE_COUNT : 0.0);
	printf("resident_bytes:   %llu\n", (unsigned long long)memfs_node_resident_bytes(node));
	printf("private_delta:    %lld B\n", (long long)(private_after - private_before));
	rc = 0;

cleanup:
	if (node != NULL) {
		(void)memfs_node_unlink(node);
		memfs_node_close(node);
	}
	if (fs != NULL)
		memfs_destroy(fs);
	return rc;
}

static int bench_sparse_single_page_groups(const BenchConfig* config, LARGE_INTEGER frequency) {
	Memfs* fs = NULL;
	MemfsNode* node = NULL;
	MemfsAllocatorStats before;
	MemfsAllocatorStats after;
	uint8_t page[BENCH_4KB_SIZE];
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t written = 0;
	uint32_t i;
	double seconds;
	int rc = 1;

	if (create_fs(config, &fs) != MEMFS_OK || fs == NULL)
		return 1;
	if (memfs_node_create(fs, fs->root, L"sparse-groups.bin", false,
						  FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK || node == NULL)
		goto cleanup;

	memset(page, 0x5a, sizeof(page));
	memfs_allocator_get_stats(&fs->allocator, &before);

	QueryPerformanceCounter(&start);
	for (uint32_t round = 0; round < BENCH_SPARSE_GROUP_ROUNDS; round++) {
		for (i = 0; i < BENCH_SPARSE_GROUP_COUNT; i++) {
			uint64_t offset = (uint64_t)i * MEMFS_PAGE_GROUP_BYTES;
			page[0] = (uint8_t)(i + round);
			if (memfs_node_write(node, page, offset, sizeof(page), false, false, &written) != MEMFS_OK ||
				written != sizeof(page))
				goto cleanup;
		}

		if (round + 1U != BENCH_SPARSE_GROUP_ROUNDS &&
			memfs_node_set_file_size(node, 0) != MEMFS_OK)
			goto cleanup;
	}
	QueryPerformanceCounter(&end);
	seconds = seconds_between(start, end, frequency);
	memfs_allocator_get_stats(&fs->allocator, &after);

	printf("\n[sparse single-page groups]\n");
	printf("groups:           %u\n", BENCH_SPARSE_GROUP_COUNT);
	printf("rounds:           %u\n", BENCH_SPARSE_GROUP_ROUNDS);
	printf("logical span:     %llu B\n",
		   (unsigned long long)((uint64_t)(BENCH_SPARSE_GROUP_COUNT - 1U) * MEMFS_PAGE_GROUP_BYTES + BENCH_4KB_SIZE));
	print_rate("write4k", BENCH_SPARSE_GROUP_COUNT * BENCH_SPARSE_GROUP_ROUNDS, seconds);
	printf("group_count:      %u\n", memfs_node_page_group_count(node));
	printf("live_objects_delta: %lld\n",
		   (long long)(after.live_objects - before.live_objects));
	printf("live_bytes_delta:   %lld B\n",
		   (long long)(after.live_bytes - before.live_bytes));
	printf("reserved_delta:     %lld B\n",
		   (long long)(after.reserved_bytes - before.reserved_bytes));
	printf("committed_delta:    %lld B\n",
		   (long long)(after.committed_bytes - before.committed_bytes));
	printf("resident_bytes:     %llu B\n",
		   (unsigned long long)memfs_node_resident_bytes(node));
	rc = 0;

cleanup:
	if (node != NULL) {
		(void)memfs_node_unlink(node);
		memfs_node_close(node);
	}
	if (fs != NULL)
		memfs_destroy(fs);
	return rc;
}

static int bench_sequential_sparse_read(const BenchConfig* config, LARGE_INTEGER frequency) {
	Memfs* fs = NULL;
	MemfsNode* node = NULL;
	uint8_t page[BENCH_4KB_SIZE];
	uint8_t* buffer = NULL;
	const uint64_t logical_size =
		(uint64_t)BENCH_SEQUENTIAL_READ_GROUPS * MEMFS_PAGE_GROUP_BYTES;
	const uint64_t page_lookups =
		(logical_size / MEMFS_PAGE_SIZE) * BENCH_SEQUENTIAL_READ_ROUNDS;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	uint32_t written = 0;
	uint32_t read = 0;
	uint32_t group;
	uint32_t round;
	double seconds;
	double mib_per_second;
	int rc = 1;

	if (logical_size > UINT32_MAX)
		return 1;

	if (create_fs(config, &fs) != MEMFS_OK || fs == NULL)
		return 1;

	if (memfs_node_create(fs, fs->root, L"sequential-read.bin", false,
						  FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK ||
		node == NULL)
		goto cleanup;

	memset(page, 0, sizeof(page));
	for (group = 0; group < BENCH_SEQUENTIAL_READ_GROUPS; group++) {
		uint64_t offset = (uint64_t)group * MEMFS_PAGE_GROUP_BYTES;
		page[0] = (uint8_t)(group + 1U);
		page[1] = (uint8_t)(group ^ 0x5aU);
		if (memfs_node_write(node, page, offset, sizeof(page), false, false,
							 &written) != MEMFS_OK ||
			written != sizeof(page))
			goto cleanup;
	}

	if (memfs_node_set_file_size(node, logical_size) != MEMFS_OK)
		goto cleanup;

	buffer = malloc((size_t)logical_size);
	if (buffer == NULL)
		goto cleanup;

	QueryPerformanceCounter(&start);
	for (round = 0; round < BENCH_SEQUENTIAL_READ_ROUNDS; round++) {
		read = 0;
		if (memfs_node_read(node, buffer, 0, (uint32_t)logical_size, &read) != MEMFS_OK ||
			read != (uint32_t)logical_size)
			goto cleanup;
	}
	QueryPerformanceCounter(&end);

	for (group = 0; group < BENCH_SEQUENTIAL_READ_GROUPS; group++) {
		uint64_t offset = (uint64_t)group * MEMFS_PAGE_GROUP_BYTES;
		if (buffer[offset] != (uint8_t)(group + 1U) ||
			buffer[offset + 1U] != (uint8_t)(group ^ 0x5aU))
			goto cleanup;
		if (buffer[offset + BENCH_4KB_SIZE] != 0)
			goto cleanup;
	}

	seconds = seconds_between(start, end, frequency);
	mib_per_second = seconds > 0.0
		? ((double)logical_size * BENCH_SEQUENTIAL_READ_ROUNDS /
		   (1024.0 * 1024.0)) / seconds
		: 0.0;

	printf("\n[sequential sparse paged read]\n");
	printf("groups:           %u\n", BENCH_SEQUENTIAL_READ_GROUPS);
	printf("logical size:     %llu B\n", (unsigned long long)logical_size);
	printf("resident bytes:   %llu B\n",
		   (unsigned long long)memfs_node_resident_bytes(node));
	printf("rounds:           %u\n", BENCH_SEQUENTIAL_READ_ROUNDS);
	printf("seconds:          %.6f\n", seconds);
	printf("MiB/s:            %.1f\n", mib_per_second);
	printf("ns/page lookup:   %.1f\n",
		   seconds > 0.0 ? seconds * 1000000000.0 / (double)page_lookups : 0.0);
	rc = 0;

cleanup:
	if (buffer != NULL)
		free(buffer);
	if (node != NULL) {
		(void)memfs_node_unlink(node);
		memfs_node_close(node);
	}
	if (fs != NULL)
		memfs_destroy(fs);
	return rc;
}

static int bench_name_hot_path(const BenchConfig* config, LARGE_INTEGER frequency) {
	typedef wchar_t NameSlot[BENCH_NAME_HOT_CHARS];
	Memfs* fs = NULL;
	NameSlot* canonical = NULL;
	NameSlot* lookup = NULL;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double create_seconds;
	double lookup_seconds;
	double miss_seconds;
	double delete_seconds;
	uint32_t i;
	uint32_t round;
	int rc = 1;

	if (create_fs(config, &fs) != MEMFS_OK || fs == NULL)
		return 1;

	canonical = malloc((size_t)BENCH_NAME_HOT_COUNT * sizeof(*canonical));
	lookup = malloc((size_t)BENCH_NAME_HOT_COUNT * sizeof(*lookup));
	if (canonical == NULL || lookup == NULL)
		goto cleanup;

	for (i = 0; i < BENCH_NAME_HOT_COUNT; i++) {
		swprintf_s(canonical[i], BENCH_NAME_HOT_CHARS,
				   L"some_MODULE_name_%05u.obj", i);
		swprintf_s(lookup[i], BENCH_NAME_HOT_CHARS,
				   L"SOME_module_NAME_%05u.OBJ", i);
	}

	QueryPerformanceCounter(&start);
	for (i = 0; i < BENCH_NAME_HOT_COUNT; i++) {
		MemfsNode* node = NULL;
		if (memfs_node_create(fs, fs->root, canonical[i], false,
							  FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) != MEMFS_OK ||
			node == NULL)
			goto cleanup;
		memfs_node_close(node);
	}
	QueryPerformanceCounter(&end);
	create_seconds = seconds_between(start, end, frequency);

	QueryPerformanceCounter(&start);
	for (round = 0; round < BENCH_NAME_HOT_ROUNDS; round++) {
		for (i = 0; i < BENCH_NAME_HOT_COUNT; i++) {
			uint32_t index = (uint32_t)(((uint64_t)i * 2654435761ULL +
										 (uint64_t)round * 2246822519ULL) %
										BENCH_NAME_HOT_COUNT);
			if (memfs_dir_lookup(fs->root, canonical[index]) == NULL)
				goto cleanup;
		}
	}
	QueryPerformanceCounter(&end);
	lookup_seconds = seconds_between(start, end, frequency);

	QueryPerformanceCounter(&start);
	for (round = 0; round < BENCH_NAME_HOT_ROUNDS; round++) {
		for (i = 0; i < BENCH_NAME_HOT_COUNT; i++) {
			if (memfs_dir_lookup(fs->root, lookup[i]) != NULL)
				goto cleanup;
		}
	}
	QueryPerformanceCounter(&end);
	miss_seconds = seconds_between(start, end, frequency);

	QueryPerformanceCounter(&start);
	for (i = 0; i < BENCH_NAME_HOT_COUNT; i++) {
		MemfsNode* node = memfs_dir_lookup(fs->root, canonical[i]);
		if (node == NULL || memfs_node_unlink(node) != MEMFS_OK)
			goto cleanup;
	}
	QueryPerformanceCounter(&end);
	delete_seconds = seconds_between(start, end, frequency);

	printf("\n[ASCII case-sensitive directory hot path]\n");
	printf("files:            %u\n", BENCH_NAME_HOT_COUNT);
	printf("lookup rounds:    %u\n", BENCH_NAME_HOT_ROUNDS);
	print_rate("create", BENCH_NAME_HOT_COUNT, create_seconds);
	print_rate("lookup", BENCH_NAME_HOT_COUNT * BENCH_NAME_HOT_ROUNDS, lookup_seconds);
	print_rate("case miss", BENCH_NAME_HOT_COUNT * BENCH_NAME_HOT_ROUNDS, miss_seconds);
	print_rate("delete", BENCH_NAME_HOT_COUNT, delete_seconds);
	printf("lookup ns/op:     %.1f\n",
		   lookup_seconds * 1000000000.0 /
			   (double)(BENCH_NAME_HOT_COUNT * BENCH_NAME_HOT_ROUNDS));
	rc = 0;

cleanup:
	if (canonical != NULL)
		free(canonical);
	if (lookup != NULL)
		free(lookup);
	if (fs != NULL)
		memfs_destroy(fs);
	return rc;
}

static int parse_args(int argc, char** argv, BenchConfig* plain, BenchConfig* compression, BenchConfig* encryption,
					  BenchConfig* combined, BenchMode* mode, bool* csv_enabled) {
	int i;

	*csv_enabled = false;
	memset(plain, 0, sizeof(*plain));
	memset(compression, 0, sizeof(*compression));
	memset(encryption, 0, sizeof(*encryption));
	memset(combined, 0, sizeof(*combined));

	plain->compression_level = 1;

	compression->compression_enabled = true;
	compression->compression_level = 1;

	encryption->encryption_enabled = true;
	encryption->compression_level = 1;

	combined->compression_enabled = true;
	combined->compression_level = 1;
	combined->encryption_enabled = true;

	*mode = BENCH_MODE_COMPARE;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--plain") == 0) {
			*mode = BENCH_MODE_PLAIN;
		} else if (strcmp(argv[i], "--compression") == 0) {
			*mode = BENCH_MODE_COMPRESSION;
		} else if (strcmp(argv[i], "--encryption") == 0) {
			*mode = BENCH_MODE_ENCRYPTION;
		} else if (strcmp(argv[i], "--combined") == 0) {
			*mode = BENCH_MODE_COMBINED;
		} else if (strcmp(argv[i], "--compression-page") == 0) {
			*mode = BENCH_MODE_COMPRESSION_PAGE;
		} else if (strcmp(argv[i], "--sparse-groups") == 0) {
			*mode = BENCH_MODE_SPARSE_GROUPS;
		} else if (strcmp(argv[i], "--name-hot") == 0) {
			*mode = BENCH_MODE_NAME_HOT;
		} else if (strcmp(argv[i], "--sequential-read") == 0) {
			*mode = BENCH_MODE_SEQUENTIAL_READ;
		} else if (strcmp(argv[i], "--pressure-policy") == 0) {
			*mode = BENCH_MODE_PRESSURE_POLICY;
		} else if (strcmp(argv[i], "--compare") == 0) {
			*mode = BENCH_MODE_COMPARE;
		} else if (strcmp(argv[i], "--csv") == 0) {
			*csv_enabled = true;
		} else if (strcmp(argv[i], "--compression-level") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "--compression-level requires a value\n");
				return 1;
			}
			compression->compression_level = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			printf("usage: memfs_bench [--compare | --plain | --compression | --encryption]\n");
			printf("  --compare            run plain, compression, encryption and print comparison (default)\n");
			printf("  --plain              run plain mode only\n");
			printf("  --compression        run compression mode only\n");
			printf("  --encryption         run encryption mode only\n");
			printf("  --combined           run compression+encryption combined mode only\n");
			printf("  --compression-page   run 200k repeated compressible 4KB page rewrites\n");
			printf("  --sparse-groups      write one 4KB page into each of 4096 distinct page groups\n");
			printf("  --name-hot           benchmark 50k ASCII names, exact hits and case-mismatch misses\n");
			printf("  --sequential-read    benchmark 128MiB sparse sequential read across 128 PageGroups\n");
			printf("  --pressure-policy    run deterministic auto-capacity pressure/scavenge benchmark (Debug)\n");
			printf("  --compression-level N set compression level for compression mode\n");
			printf("  --csv                append CSV comparison data after --compare table\n");
			return 2;
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			return 1;
		}
	}

	return 0;
}
/* repair: no code change required; verification-only task */
int main(int argc, char** argv) {
	LARGE_INTEGER frequency;
	BenchConfig plain;
	BenchConfig compression;
	BenchConfig encryption;
	BenchConfig combined;
	BenchResult plain_results[8];
	BenchResult compression_results[8];
	BenchResult encryption_results[8];
	BenchResult combined_results[8];
	BenchMode mode;
	bool csv_enabled = false;
	int rc;

	if (!QueryPerformanceFrequency(&frequency)) {
		fprintf(stderr, "QueryPerformanceFrequency failed\n");
		return 2;
	}

	rc = parse_args(argc, argv, &plain, &compression, &encryption, &combined, &mode, &csv_enabled);
	if (rc == 2)
		return 0;
	if (rc != 0)
		return rc;

	if (mode == BENCH_MODE_COMPARE) {
		rc = run_suite(&plain, "plain", frequency, plain_results);
		if (rc != 0) {
			return rc;
		}

		rc = run_suite(&compression, "compression", frequency, compression_results);
		if (rc != 0) {
			return rc;
		}

		rc = run_suite(&encryption, "encryption", frequency, encryption_results);
		if (rc != 0) {
			return rc;
		}

		rc = run_suite(&combined, "combined", frequency, combined_results);
		if (rc != 0) {
			return rc;
		}

		print_comparison(plain_results, compression_results, encryption_results, combined_results);
		if (csv_enabled) {
			print_comparison_csv(plain_results, compression_results, encryption_results, combined_results);
		}
	} else if (mode == BENCH_MODE_PLAIN) {
		rc = run_suite(&plain, "plain", frequency, plain_results);
	} else if (mode == BENCH_MODE_COMPRESSION) {
		rc = run_suite(&compression, "compression", frequency, compression_results);
	} else if (mode == BENCH_MODE_ENCRYPTION) {
		rc = run_suite(&encryption, "encryption", frequency, encryption_results);
	} else if (mode == BENCH_MODE_COMBINED) {
		rc = run_suite(&combined, "combined", frequency, combined_results);
	} else if (mode == BENCH_MODE_COMPRESSION_PAGE) {
		rc = bench_compression_page_rewrite(&compression, frequency);
	} else if (mode == BENCH_MODE_SPARSE_GROUPS) {
		rc = bench_sparse_single_page_groups(&plain, frequency);
	} else if (mode == BENCH_MODE_NAME_HOT) {
		rc = bench_name_hot_path(&plain, frequency);
	} else if (mode == BENCH_MODE_SEQUENTIAL_READ) {
		rc = bench_sequential_sparse_read(&plain, frequency);
	} else if (mode == BENCH_MODE_PRESSURE_POLICY) {
		rc = bench_pressure_policy(frequency);
	}

	return rc;
}
