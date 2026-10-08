#include <Windows.h>
#include <sddl.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "memfs_core.h"

static int g_checks;
static int g_failures;
static uint32_t g_thread_create_skip = UINT32_MAX;
static bool g_thread_failure_requested;
static bool g_thread_failure_injected;

#define CHECK(expr)                                                                                                    \
	do {                                                                                                               \
		g_checks++;                                                                                                    \
		if (!(expr)) {                                                                                                 \
			g_failures++;                                                                                              \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr);                                                     \
		}                                                                                                              \
	} while (0)

/* Test-only fault injection; the normal path calls the real Windows API. */
static HANDLE create_test_thread(LPTHREAD_START_ROUTINE routine, void* argument) {
	HANDLE thread;

	if (g_thread_create_skip == 0U) {
		g_thread_create_skip = UINT32_MAX;
		g_thread_failure_injected = true;
		fputs("INJECTED CreateThread failure\n", stderr);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return NULL;
	}
	thread = CreateThread(NULL, 0, routine, argument, 0, NULL);
	if (thread != NULL && g_thread_create_skip != UINT32_MAX)
		--g_thread_create_skip;
	return thread;
}

static void join_test_threads(HANDLE* threads, uint32_t started, const char* label) {
	DWORD wait;

	if (started == 0U)
		return;
	wait = WaitForMultipleObjects(started, threads, TRUE, 30000);
	CHECK(wait == WAIT_OBJECT_0);
	if (wait != WAIT_OBJECT_0) {
		fprintf(stderr, "%s: worker join failed (wait=%lu); "
				"terminating before shared-state teardown\n", label,
				(unsigned long)wait);
		fflush(NULL);
		ExitProcess(2);
	}
}

static bool configure_thread_failure(int argc, char** argv) {
	uint64_t value = 0;
	const char* text;

	if (argc == 1)
		return true;
	if (argc != 3 || strcmp(argv[1], "--fail-thread-create-after") != 0)
		return false;
	text = argv[2];
	if (*text == '\0')
		return false;
	while (*text != '\0') {
		uint32_t digit;

		if (*text < '0' || *text > '9')
			return false;
		digit = (uint32_t)(*text++ - '0');
		if (value > (UINT32_MAX - 1ULL - digit) / 10ULL)
			return false;
		value = value * 10ULL + digit;
	}
	g_thread_create_skip = (uint32_t)value;
	g_thread_failure_requested = true;
	return true;
}

static void test_memory_accounting_layers(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	MemfsNode* churn[16];
	MemfsAllocatorStats stats;
	uint8_t input[MEMFS_PAGE_SIZE + 123];
	uint8_t output[MEMFS_PAGE_SIZE + 123];
	uint32_t transferred;
	uint32_t i;
	uint32_t round;
	uint64_t capacity = 64ULL * 1024ULL * 1024ULL;
	uint64_t used_before;
	uint64_t resident_before;
	uint64_t committed_before;
	uint64_t live_before;

	printf("== memory accounting layers ==\n");

	options.capacity = capacity;
	options.volume_label = L"ACCT";
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	memfs_allocator_get_stats(&fs->allocator, &stats);
	CHECK(stats.committed_bytes > 0);
	CHECK(stats.physical_bytes == stats.committed_bytes);
	CHECK(stats.reserved_bytes >= stats.committed_bytes);
	CHECK(stats.live_bytes > 0);
	CHECK(stats.live_objects > 0);
	CHECK(stats.dedicated_committed_bytes <= stats.committed_bytes);
	CHECK(stats.dedicated_reserved_bytes <= stats.reserved_bytes);

	CHECK(memfs_node_create(fs, fs->root, L"acct.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(0x11 + (i % 251U));

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	CHECK((uint64_t)fs->used_bytes == sizeof(input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));
	CHECK(memfs_resident_bytes(fs) == memfs_node_resident_bytes(file));
	CHECK(memfs_node_resident_bytes(file) >= 2ULL * MEMFS_PAGE_SIZE);
	CHECK(memfs_node_resident_bytes(file) < 3ULL * MEMFS_PAGE_SIZE + 128U);
	CHECK(memfs_committed_bytes(fs) == memfs_physical_bytes(fs));
	CHECK(memfs_committed_bytes(fs) > 0);
	CHECK(memfs_committed_bytes(fs) >= memfs_resident_bytes(fs));

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	used_before = fs->used_bytes;
	resident_before = fs->resident_bytes;
	committed_before = memfs_committed_bytes(fs);
	memfs_allocator_get_stats(&fs->allocator, &stats);
	live_before = stats.live_bytes;

	for (round = 0; round < 4; round++) {
		for (i = 0; i < sizeof(input); i++)
			input[i] = (uint8_t)(0x20 + round * 13U + (i % 251U));
		CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
		CHECK(transferred == sizeof(input));
		CHECK((uint64_t)fs->used_bytes == used_before);
		CHECK(memfs_resident_bytes(fs) == memfs_node_resident_bytes(file));
		CHECK(memfs_resident_bytes(fs) < resident_before + 2ULL * MEMFS_PAGE_SIZE);
	}

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	for (i = 0; i < _countof(churn); i++) {
		wchar_t churn_name[32];

		churn[i] = NULL;
		swprintf_s(churn_name, _countof(churn_name), L"churn-%u.bin", i);
		CHECK(memfs_node_create(fs, fs->root, churn_name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &churn[i]) ==
			  MEMFS_OK);
		CHECK(churn[i] != NULL);
		if (churn[i] == NULL)
			continue;

		CHECK(memfs_node_write(churn[i], input, 0, 1024, false, false, &transferred) == MEMFS_OK);
		CHECK(transferred == 1024);
		CHECK(memfs_node_unlink(churn[i]) == MEMFS_OK);
		memfs_node_close(churn[i]);
		churn[i] = NULL;

		CHECK((uint64_t)fs->used_bytes == used_before);
		CHECK(memfs_resident_bytes(fs) == memfs_node_resident_bytes(file));
		CHECK(memfs_free_bytes(fs) == capacity - used_before);
	}

	CHECK(memfs_node_set_file_size(file, MEMFS_PAGE_SIZE) == MEMFS_OK);
	CHECK(memfs_node_set_allocation_size(file, MEMFS_PAGE_SIZE) == MEMFS_OK);
	CHECK((uint64_t)fs->used_bytes == MEMFS_PAGE_SIZE);
	CHECK(memfs_resident_bytes(fs) == memfs_node_resident_bytes(file));
	CHECK(memfs_resident_bytes(fs) < resident_before);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK(memfs_resident_bytes(fs) == 0);
	CHECK(memfs_free_bytes(fs) == capacity);

	memfs_allocator_get_stats(&fs->allocator, &stats);
	CHECK(stats.live_bytes <= live_before + 64ULL * 1024ULL);
	CHECK(stats.committed_bytes <= committed_before + 64ULL * 1024ULL);
	CHECK(stats.physical_bytes == stats.committed_bytes);

	memfs_destroy(fs);
}

static void test_adaptive_capacity_mode(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	uint8_t input[1024];
	uint8_t output[1024];
	uint32_t transferred;
	uint32_t i;
	MemfsRuntimeStats stats;

	printf("== adaptive capacity mode ==\n");

#if !defined(NDEBUG)
	/* Cached samples must debit only allocator backing committed after the sample. */
	CHECK(memfs_test_adjust_cached_available(1024U, 128U, 128U) == 1024U);
	CHECK(memfs_test_adjust_cached_available(1024U, 128U, 256U) == 896U);
	CHECK(memfs_test_adjust_cached_available(1024U, 256U, 128U) == 0U);
	CHECK(memfs_test_adjust_cached_available(1024U, 128U, 2048U) == 0U);

	/*
	 * Production auto-capacity intentionally samples live
	 * GlobalMemoryStatusEx values. Freeze the available-memory input in
	 * Debug so this unit test is deterministic rather than comparing two
	 * independent live system snapshots.
	 */
	memfs_test_set_system_available_bytes(
		MEMFS_AUTO_SOFT_MARGIN_BYTES + (1024ULL * 1024ULL * 1024ULL));
#endif

	options.capacity = 0;
	options.capacity_auto = true;
	options.volume_label = L"AUTO";
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL) {
#if !defined(NDEBUG)
		memfs_test_clear_system_available_bytes();
#endif
		return;
	}

	CHECK(fs->capacity_auto);
	CHECK(fs->capacity == 0);
	CHECK(memfs_auto_allowance_bytes(fs) > 0);
	CHECK(memfs_free_bytes(fs) > 0);

	CHECK(memfs_node_create(fs, fs->root, L"auto.bin", false,
						FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
#if !defined(NDEBUG)
		memfs_test_clear_system_available_bytes();
#endif
		return;
	}

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(0x31 + (i % 251U));

	CHECK(memfs_node_write(file, input, 0, sizeof(input),
						   false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK((uint64_t)fs->used_bytes == sizeof(input));
	CHECK(memfs_free_bytes(fs) > 0);

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	/*
	 * A single runtime-stats snapshot computes free_bytes from the same
	 * auto_allowance_bytes value, so these fields are semantically
	 * comparable even in Release where live system memory is not frozen.
	 */
	memfs_get_runtime_stats(fs, &stats);
	CHECK(stats.auto_allowance_bytes > 0);
	CHECK(stats.free_bytes == stats.auto_allowance_bytes);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	file = NULL;
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK(memfs_free_bytes(fs) > 0);

	memfs_destroy(fs);
#if !defined(NDEBUG)
	memfs_test_clear_system_available_bytes();
#endif
}

#if !defined(NDEBUG)
static void test_adaptive_memory_pressure_scavenger(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	MemfsAllocatorStats cached;
	MemfsAllocatorStats scavenged;
	void* area = NULL;
	uint8_t input[32];
	uint8_t output[32];
	uint32_t transferred = 0;
	uint64_t used_before;
	uint32_t i;

	printf("== adaptive memory pressure scavenger ==\n");
	memfs_test_clear_system_available_bytes();

	options.capacity_auto = true;
	options.volume_label = L"PRESSURE";
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	CHECK(memfs_node_create(fs, fs->root, L"pressure.bin", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	for (i = 0; i < _countof(input); i++)
		input[i] = (uint8_t)(0x80U + i);
	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));

	area = memfs_allocator_alloc(&fs->allocator, 16U * 1024U);
	CHECK(area != NULL);
	if (area != NULL)
		memfs_allocator_free(&fs->allocator, area, 16U * 1024U);

	memfs_allocator_get_stats(&fs->allocator, &cached);
	CHECK(cached.area_cached_count >= 1U);
	CHECK(cached.area_cached_bytes > 0U);

	/* Above the hard reserve but below the soft threshold: reclaim and proceed. */
	fs->pressure_last_scavenge_tick = 0;
	memfs_test_set_system_available_bytes(320ULL * 1024ULL * 1024ULL);
	CHECK(memfs_node_set_file_size(file, sizeof(input) + 1U) == MEMFS_OK);
	memfs_allocator_get_stats(&fs->allocator, &scavenged);
	CHECK(scavenged.area_cached_count == 0U);
	CHECK(scavenged.area_cached_bytes == 0U);
	CHECK(scavenged.scavenge_count > cached.scavenge_count);

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(output));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	/* Below the hard reserve: fail atomically without damaging existing data. */
	fs->pressure_last_scavenge_tick = 0;
	memfs_test_set_system_available_bytes(128ULL * 1024ULL * 1024ULL);
	used_before = (uint64_t)fs->used_bytes;
	CHECK(memfs_node_set_file_size(file, sizeof(input) + 2U) == MEMFS_ERR_NO_SPACE);
	CHECK(file->file_size == sizeof(input) + 1U);
	CHECK((uint64_t)fs->used_bytes == used_before);

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(output));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	/* Pressure relief restores forward progress. */
	fs->pressure_last_scavenge_tick = 0;
	memfs_test_set_system_available_bytes(2ULL * 1024ULL * 1024ULL * 1024ULL);
	CHECK(memfs_node_set_file_size(file, sizeof(input) + 2U) == MEMFS_OK);

	memfs_test_clear_system_available_bytes();
	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}
#endif


static void test_runtime_stats_snapshot(void) {
	const uint64_t capacity = 8ULL * 1024ULL * 1024ULL;
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	MemfsRuntimeStats baseline;
	MemfsRuntimeStats active;
	MemfsRuntimeStats cached;
	MemfsRuntimeStats scavenged;
	uint8_t data[1024];
	uint32_t written = 0;
	void* area;
	uint32_t i;

	printf("== runtime stats snapshot ==\n");
	CHECK(memfs_create(capacity, L"STATS", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	memfs_get_runtime_stats(fs, &baseline);
	CHECK(!baseline.capacity_auto);
	CHECK(baseline.capacity_bytes == capacity);
	CHECK(baseline.logical_used_bytes == 0U);
	CHECK(baseline.free_bytes == capacity);
	CHECK(baseline.auto_allowance_bytes == 0U);
	CHECK(baseline.auto_hard_margin_bytes == MEMFS_AUTO_HARD_MARGIN_BYTES);
	CHECK(baseline.auto_soft_margin_bytes == MEMFS_AUTO_SOFT_MARGIN_BYTES);
	CHECK(baseline.allocator_physical_bytes == baseline.allocator_committed_bytes);

	CHECK(memfs_node_create(fs, fs->root, L"stats.bin", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	for (i = 0; i < _countof(data); i++)
		data[i] = (uint8_t)i;
	CHECK(memfs_node_write(file, data, 0, sizeof(data), false, false, &written) == MEMFS_OK);
	CHECK(written == sizeof(data));

	memfs_get_runtime_stats(fs, &active);
	CHECK(active.logical_used_bytes == sizeof(data));
	CHECK(active.free_bytes == capacity - sizeof(data));
	CHECK(active.resident_bytes > 0U);
	CHECK(active.allocator_live_objects >= baseline.allocator_live_objects);
	CHECK(active.allocator_physical_bytes == active.allocator_committed_bytes);

	area = memfs_allocator_alloc(&fs->allocator, 16U * 1024U);
	CHECK(area != NULL);
	if (area != NULL)
		memfs_allocator_free(&fs->allocator, area, 16U * 1024U);

	memfs_get_runtime_stats(fs, &cached);
	CHECK(cached.area_cached_count >= 1U);
	CHECK(cached.area_cached_bytes > 0U);
	CHECK(cached.area_count == 0U);

	(void)memfs_allocator_scavenge(&fs->allocator);
	memfs_get_runtime_stats(fs, &scavenged);
	CHECK(scavenged.area_cached_count == 0U);
	CHECK(scavenged.area_cached_bytes == 0U);
	CHECK(scavenged.allocator_scavenge_count > cached.allocator_scavenge_count);
	CHECK(scavenged.allocator_scavenged_bytes > cached.allocator_scavenged_bytes);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}

static void test_deep_namespace_destroy(void) {
	enum { DEPTH = 20000 };
	Memfs* fs = NULL;
	MemfsNode* parent;
	uint32_t i;

	printf("== deep namespace iterative destroy ==\n");
	CHECK(memfs_create(64ULL * 1024ULL * 1024ULL, L"DEEP", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	parent = fs->root;
	for (i = 0; i < DEPTH; ++i) {
		MemfsNode* child = NULL;
		MemfsResult result = memfs_node_create(
			fs, parent, L"d", true, FILE_ATTRIBUTE_DIRECTORY,
			NULL, 0, &child);
		CHECK(result == MEMFS_OK);
		CHECK(child != NULL);
		if (result != MEMFS_OK || child == NULL)
			break;
		parent = child;
	}

	CHECK(i == DEPTH);
	memfs_destroy(fs);
}

static void test_tree_and_lookup(void) {
	Memfs* fs = NULL;
	MemfsNode* root;
	MemfsNode* dir;
	MemfsNode* file;
	MemfsNode* found;
	wchar_t name[MEMFS_MAX_NAME + 1];
	MemfsNode* parent;

	printf("== tree / lookup ==\n");

	CHECK(memfs_create(16 * 1024 * 1024ULL, L"TEST", &fs) == MEMFS_OK);
	CHECK(fs != NULL);

	root = fs->root;
	CHECK(root != NULL);
	CHECK(memfs_node_is_directory(root));

	CHECK(memfs_node_create(fs, root, L"Dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);

	CHECK(memfs_node_create(fs, dir, L"file.txt", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_lookup_path(fs, L"\\Dir\\file.txt", &found) == MEMFS_OK);
	CHECK(found == file);

	found = NULL;
	CHECK(memfs_lookup_path(fs, L"\\dir\\FILE.TXT", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(found == NULL);
	CHECK(memfs_lookup_path(fs, L"\\Dir\\file.txt", &found) == MEMFS_OK);
	CHECK(found == file);

	CHECK(memfs_lookup_parent(fs, L"\\Dir\\next.bin", &parent, name) == MEMFS_OK);
	CHECK(parent == dir);
	CHECK(wcscmp(name, L"next.bin") == 0);

	memfs_node_close(file);
	memfs_node_close(dir);
	memfs_destroy(fs);
}

static void test_case_sensitive_namespace(void) {
	Memfs* fs = NULL;
	MemfsNode* upper_dir = NULL;
	MemfsNode* lower_dir = NULL;
	MemfsNode* upper_file = NULL;
	MemfsNode* lower_file = NULL;
	MemfsNode* found = NULL;
	MemfsNode* item;
	uint8_t upper_data[] = {0x11, 0x22, 0x33};
	uint8_t lower_data[] = {0x44, 0x55, 0x66, 0x77};
	uint8_t readback[sizeof(lower_data)];
	uint32_t transferred = 0;
	bool saw_upper = false;
	bool saw_lower = false;

	printf("== case-sensitive namespace ==\n");
	CHECK(memfs_create(16 * 1024 * 1024ULL, L"CASE", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;
	CHECK(memfs_node_create(fs, fs->root, L"CaseDir", true,
		FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &upper_dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"casedir", true,
		FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &lower_dir) == MEMFS_OK);
	CHECK(upper_dir != NULL && lower_dir != NULL && upper_dir != lower_dir);
	CHECK(memfs_node_create(fs, fs->root, L"Test.txt", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &upper_file) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"test.txt", false,
		FILE_ATTRIBUTE_NORMAL, NULL, 0, &lower_file) == MEMFS_OK);
	CHECK(upper_file != NULL && lower_file != NULL && upper_file != lower_file);
	if (upper_dir == NULL || lower_dir == NULL || upper_file == NULL || lower_file == NULL)
		goto cleanup;
	CHECK(memfs_lookup_path(fs, L"\\CaseDir", &found) == MEMFS_OK);
	CHECK(found == upper_dir);
	found = NULL;
	CHECK(memfs_lookup_path(fs, L"\\casedir", &found) == MEMFS_OK);
	CHECK(found == lower_dir);
	found = NULL;
	CHECK(memfs_lookup_path(fs, L"\\CASEDIR", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(found == NULL);

	CHECK(memfs_node_write(upper_file, upper_data, 0, sizeof(upper_data), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(upper_data));
	CHECK(memfs_node_write(lower_file, lower_data, 0, sizeof(lower_data), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(lower_data));

	CHECK(memfs_lookup_path(fs, L"\\Test.txt", &found) == MEMFS_OK);
	CHECK(found == upper_file);
	found = NULL;
	CHECK(memfs_lookup_path(fs, L"\\TEST.TXT", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(found == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"Test.txt") == upper_file);
	CHECK(memfs_dir_lookup(fs->root, L"test.txt") == lower_file);
	CHECK(memfs_dir_lookup(fs->root, L"TEST.TXT") == NULL);

	for (item = memfs_dir_first(fs->root); item != NULL; item = memfs_dir_next(item)) {
		if (wcscmp(item->name, L"CaseDir") == 0)
			saw_upper = true;
		if (wcscmp(item->name, L"casedir") == 0)
			saw_lower = true;
	}
	CHECK(saw_upper && saw_lower);
	saw_upper = false;
	saw_lower = false;
	for (item = memfs_dir_first(fs->root); item != NULL; item = memfs_dir_next(item)) {
		if (wcscmp(item->name, L"Test.txt") == 0)
			saw_upper = true;
		if (wcscmp(item->name, L"test.txt") == 0)
			saw_lower = true;
	}
	CHECK(saw_upper && saw_lower);

	CHECK(memfs_node_rename(upper_file, fs->root, L"TEST.txt", false) == MEMFS_OK);
	found = NULL;
	CHECK(memfs_lookup_path(fs, L"\\Test.txt", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(found == NULL);
	CHECK(memfs_lookup_path(fs, L"\\TEST.txt", &found) == MEMFS_OK);
	CHECK(found == upper_file);
	CHECK(memfs_dir_lookup(fs->root, L"test.txt") == lower_file);
	memset(readback, 0, sizeof(readback));
	CHECK(memfs_node_read(upper_file, readback, 0, sizeof(upper_data), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(upper_data));
	CHECK(memcmp(readback, upper_data, sizeof(upper_data)) == 0);
	memset(readback, 0, sizeof(readback));
	CHECK(memfs_node_read(lower_file, readback, 0, sizeof(lower_data), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(lower_data));
	CHECK(memcmp(readback, lower_data, sizeof(lower_data)) == 0);

	CHECK(memfs_node_unlink(upper_file) == MEMFS_OK);
	memfs_node_close(upper_file);
	upper_file = NULL;
	CHECK(memfs_dir_lookup(fs->root, L"TEST.txt") == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"test.txt") == lower_file);
	CHECK(memfs_node_unlink(lower_file) == MEMFS_OK);
	memfs_node_close(lower_file);
	lower_file = NULL;

	CHECK(memfs_node_rename(upper_dir, fs->root, L"CASEDIR", false) == MEMFS_OK);
	CHECK(memfs_dir_lookup(fs->root, L"CASEDIR") == upper_dir);
	CHECK(memfs_dir_lookup(fs->root, L"CaseDir") == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"casedir") == lower_dir);
	CHECK(memfs_node_unlink(upper_dir) == MEMFS_OK);
	memfs_node_close(upper_dir);
	upper_dir = NULL;
	CHECK(memfs_dir_lookup(fs->root, L"CASEDIR") == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"casedir") == lower_dir);

cleanup:
	if (upper_file != NULL) {
		if (!upper_file->deleted)
			(void)memfs_node_unlink(upper_file);
		memfs_node_close(upper_file);
	}
	if (lower_file != NULL) {
		if (!lower_file->deleted)
			(void)memfs_node_unlink(lower_file);
		memfs_node_close(lower_file);
	}
	if (upper_dir != NULL) {
		if (!upper_dir->deleted)
			(void)memfs_node_unlink(upper_dir);
		memfs_node_close(upper_dir);
	}
	if (lower_dir != NULL) {
		if (!lower_dir->deleted)
			(void)memfs_node_unlink(lower_dir);
		memfs_node_close(lower_dir);
	}
	memfs_destroy(fs);
}

static void test_io_and_resize(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t input[1024];
	uint8_t output[2048];
	uint32_t transferred;
	uint32_t i;

	printf("== io / resize ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"TEST", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"data.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)i;

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == 1024);

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_set_file_size(file, 4096) == MEMFS_OK);
	CHECK(file->file_size == 4096);
	CHECK(file->allocation_size == 4096);

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 1024, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(output));
	for (i = 0; i < sizeof(output); i++)
		CHECK(output[i] == 0);

	CHECK(memfs_node_set_allocation_size(file, 512) == MEMFS_OK);
	CHECK(file->allocation_size == 512);
	CHECK(file->file_size == 512);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	CHECK(fs->orphan_head == file);
	memfs_node_close(file);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);

	memfs_destroy(fs);
}

static void test_write_to_end_semantics(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t initial[8];
	uint8_t append1[5];
	uint8_t append2[7];
	uint8_t append3[3];
	uint8_t expected[23];
	uint8_t output[32];
	uint32_t transferred;
	uint32_t i;

	printf("== write_to_end semantics ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"APPEND", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"append.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);

	for (i = 0; i < sizeof(initial); i++)
		initial[i] = (uint8_t)(0x10 + i);
	for (i = 0; i < sizeof(append1); i++)
		append1[i] = (uint8_t)(0x20 + i);
	for (i = 0; i < sizeof(append2); i++)
		append2[i] = (uint8_t)(0x30 + i);
	for (i = 0; i < sizeof(append3); i++)
		append3[i] = (uint8_t)(0x40 + i);

	memcpy(expected, initial, sizeof(initial));
	memcpy(expected + sizeof(initial), append1, sizeof(append1));
	memcpy(expected + sizeof(initial) + sizeof(append1), append2, sizeof(append2));
	memcpy(expected + sizeof(initial) + sizeof(append1) + sizeof(append2), append3, sizeof(append3));

	CHECK(memfs_node_write(file, initial, 0, sizeof(initial), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(initial));
	CHECK(file->file_size == sizeof(initial));
	CHECK(file->allocation_size == sizeof(initial));
	CHECK((uint64_t)fs->used_bytes == sizeof(initial));
	CHECK(memfs_free_bytes(fs) == 8 * 1024 * 1024ULL - sizeof(initial));

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(initial), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(initial));
	CHECK(memcmp(initial, output, sizeof(initial)) == 0);

	CHECK(memfs_node_write(file, append1, 0, sizeof(append1), true, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(append1));
	CHECK(file->file_size == sizeof(initial) + sizeof(append1));
	CHECK(file->allocation_size == sizeof(initial) + sizeof(append1));
	CHECK((uint64_t)fs->used_bytes == sizeof(initial) + sizeof(append1));
	CHECK(memfs_free_bytes(fs) == 8 * 1024 * 1024ULL - (sizeof(initial) + sizeof(append1)));

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(initial) + sizeof(append1), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(initial) + sizeof(append1));
	CHECK(memcmp(expected, output, sizeof(initial) + sizeof(append1)) == 0);

	CHECK(memfs_node_write(file, append2, 0, sizeof(append2), true, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(append2));
	CHECK(file->file_size == sizeof(initial) + sizeof(append1) + sizeof(append2));
	CHECK(file->allocation_size == sizeof(initial) + sizeof(append1) + sizeof(append2));
	CHECK((uint64_t)fs->used_bytes == sizeof(initial) + sizeof(append1) + sizeof(append2));
	CHECK(memfs_free_bytes(fs) == 8 * 1024 * 1024ULL - (sizeof(initial) + sizeof(append1) + sizeof(append2)));

	CHECK(memfs_node_write(file, append3, 0, sizeof(append3), true, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(append3));
	CHECK(file->file_size == sizeof(expected));
	CHECK(file->allocation_size == sizeof(expected));
	CHECK((uint64_t)fs->used_bytes == sizeof(expected));
	CHECK(memfs_free_bytes(fs) == 8 * 1024 * 1024ULL - sizeof(expected));

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(expected), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(expected));
	CHECK(memcmp(expected, output, sizeof(expected)) == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	CHECK(file->deleted);
	CHECK(fs->orphan_head == file);
	CHECK((uint64_t)fs->used_bytes == sizeof(expected));
	CHECK(memfs_free_bytes(fs) == 8 * 1024 * 1024ULL - sizeof(expected));

	memfs_node_close(file);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == 8 * 1024 * 1024ULL);
	CHECK(memfs_resident_bytes(fs) == 0);

	memfs_destroy(fs);
}

static void test_rename_and_delete(void) {
	Memfs* fs = NULL;
	MemfsNode* a;
	MemfsNode* b;
	MemfsNode* file;
	MemfsNode* found;

	printf("== rename / delete ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"TEST", &fs) == MEMFS_OK);

	CHECK(memfs_node_create(fs, fs->root, L"A", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &a) == MEMFS_OK);

	CHECK(memfs_node_create(fs, fs->root, L"B", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &b) == MEMFS_OK);

	CHECK(memfs_node_create(fs, a, L"x.txt", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_rename(file, b, L"y.txt", false) == MEMFS_OK);
	CHECK(memfs_lookup_path(fs, L"\\A\\x.txt", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\B\\y.txt", &found) == MEMFS_OK);
	CHECK(found == file);
	CHECK(wcscmp(file->name, L"y.txt") == 0);

	CHECK(memfs_node_unlink(b) == MEMFS_ERR_NOT_EMPTY);
	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);

	CHECK(memfs_node_unlink(b) == MEMFS_OK);
	memfs_node_close(b);

	CHECK(memfs_node_unlink(a) == MEMFS_OK);
	memfs_node_close(a);

	memfs_destroy(fs);
}

static void test_capacity(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* a;
	MemfsNode* b;
	uint32_t written;
	uint8_t buffer[1024] = {0};

	printf("== capacity ==\n");

	options.capacity = 1536;
	options.capacity_auto = false;
	options.volume_label = L"TINY";
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"a", false, FILE_ATTRIBUTE_NORMAL, NULL, 1024, &a) == MEMFS_OK);
	CHECK(memfs_node_write(a, buffer, 0, 1024, false, false, &written) == MEMFS_OK);
	CHECK(written == 1024);
	CHECK(memfs_free_bytes(fs) == 512);

	// AllocationSize preallocation does not consume byte-granular logical quota.
	CHECK(memfs_node_create(fs, fs->root, L"b", false, FILE_ATTRIBUTE_NORMAL, NULL, 1024, &b) == MEMFS_OK);
	CHECK(memfs_node_write(b, buffer, 0, 1024, false, false, &written) == MEMFS_ERR_NO_SPACE);

	CHECK(memfs_node_unlink(a) == MEMFS_OK);
	memfs_node_close(a);

	CHECK(memfs_node_write(b, buffer, 0, 1024, false, false, &written) == MEMFS_OK);
	CHECK(written == 1024);

	CHECK(memfs_node_unlink(b) == MEMFS_OK);
	memfs_node_close(b);
	memfs_destroy(fs);
}

static void test_explicit_size_hard_limit_with_auto_flag_false(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t input[1024];
	uint32_t transferred;
	uint32_t i;
	uint64_t capacity = 1536;

	printf("== explicit size hard limit ==\n");

	options.capacity = capacity;
	options.capacity_auto = false;
	options.volume_label = L"LIMIT";
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	CHECK(!fs->capacity_auto);
	CHECK(fs->capacity == capacity);
	CHECK(memfs_free_bytes(fs) == capacity);

	CHECK(memfs_node_create(fs, fs->root, L"limit.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(0x42 + (i % 251U));

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));

	CHECK(memfs_node_write(file, input, sizeof(input), sizeof(input), false, false, &transferred) == MEMFS_ERR_NO_SPACE);
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK(memfs_free_bytes(fs) == capacity);

	memfs_destroy(fs);
}

static void test_no_space_rollback(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t input[1024];
	uint8_t output[1024];
	uint32_t transferred;
	uint32_t i;
	uint64_t capacity = 1536;
	uint64_t file_size_before;
	uint64_t allocation_size_before;
	uint64_t used_before;
	uint64_t resident_before;
	uint64_t node_resident_before;

	printf("== no space rollback ==\n");

	options.capacity = capacity;
	options.capacity_auto = false;
	options.volume_label = L"NO_SPACE";
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"file", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (fs == NULL || file == NULL) {
		if (fs)
			memfs_destroy(fs);
		return;
	}

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(0x10 + (i % 251U));

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	CHECK((uint64_t)fs->used_bytes == sizeof(input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	file_size_before = file->file_size;
	allocation_size_before = file->allocation_size;
	used_before = fs->used_bytes;
	resident_before = fs->resident_bytes;
	node_resident_before = memfs_node_resident_bytes(file);

	CHECK(memfs_node_write(file, input, sizeof(input), sizeof(input), false, false, &transferred) == MEMFS_ERR_NO_SPACE);
	CHECK(file->file_size == file_size_before);
	CHECK(file->allocation_size == allocation_size_before);
	CHECK((uint64_t)fs->used_bytes == used_before);
	CHECK((uint64_t)fs->resident_bytes == resident_before);
	CHECK(memfs_node_resident_bytes(file) == node_resident_before);
	CHECK(memfs_free_bytes(fs) == capacity - used_before);

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_set_file_size(file, 2048) == MEMFS_ERR_NO_SPACE);
	CHECK(file->file_size == file_size_before);
	CHECK(file->allocation_size == allocation_size_before);
	CHECK((uint64_t)fs->used_bytes == used_before);
	CHECK((uint64_t)fs->resident_bytes == resident_before);
	CHECK(memfs_node_resident_bytes(file) == node_resident_before);
	CHECK(memfs_free_bytes(fs) == capacity - used_before);

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_set_allocation_size(file, 2048) == MEMFS_OK);
	CHECK(file->file_size == file_size_before);
	CHECK(file->allocation_size == 2048);
	CHECK((uint64_t)fs->used_bytes == used_before);
	CHECK((uint64_t)fs->resident_bytes == resident_before);
	CHECK(memfs_node_resident_bytes(file) == node_resident_before);
	CHECK(memfs_free_bytes(fs) == capacity - used_before);

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_set_allocation_size(file, allocation_size_before) == MEMFS_OK);
	CHECK(file->file_size == file_size_before);
	CHECK(file->allocation_size == allocation_size_before);
	CHECK((uint64_t)fs->used_bytes == used_before);
	CHECK((uint64_t)fs->resident_bytes == resident_before);
	CHECK(memfs_node_resident_bytes(file) == node_resident_before);
	CHECK(memfs_free_bytes(fs) == capacity - used_before);

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == capacity);

	CHECK(memfs_node_create(fs, fs->root, L"file", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	CHECK((uint64_t)fs->used_bytes == sizeof(input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(input), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == capacity);

	memfs_destroy(fs);
}

static void test_directory_order(void) {
	Memfs* fs = NULL;
	MemfsNode* nodes[5];
	const wchar_t* names[] = {L"zeta", L"Alpha", L"gamma", L"beta", L"Delta"};
	const wchar_t* expected[] = {L"Alpha", L"Delta", L"beta", L"gamma", L"zeta"};
	MemfsNode* p;
	uint32_t i;

	printf("== directory order ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"TEST", &fs) == MEMFS_OK);

	for (i = 0; i < 5; i++) {
		CHECK(memfs_node_create(fs, fs->root, names[i], false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &nodes[i]) == MEMFS_OK);
	}

	p = memfs_dir_first(fs->root);
	for (i = 0; i < 5; i++) {
		CHECK(p != NULL);
		if (p) {
			CHECK(wcscmp(p->name, expected[i]) == 0);
			p = memfs_dir_next(p);
		}
	}
	CHECK(p == NULL);
	CHECK(memfs_dir_upper_bound(fs->root, L"") == nodes[1]);
	CHECK(memfs_dir_upper_bound(fs->root, L"Alpha") == nodes[4]);
	CHECK(memfs_dir_upper_bound(fs->root, L"Delta") == nodes[3]);
	CHECK(memfs_dir_upper_bound(fs->root, L"zeta") == NULL);

	for (i = 0; i < 5; i++) {
		CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
		memfs_node_close(nodes[i]);
	}

	memfs_destroy(fs);
}

static void test_small_storage(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t value = 0x5a;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== small storage ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"TEST", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"small.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_write(file, &value, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);
	CHECK(file->small_inline);
	CHECK(memfs_node_page_group_count(file) == 0);
	CHECK(file->small_capacity == 1);
	CHECK(memfs_node_resident_bytes(file) == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(file->allocation_size == 1);
	CHECK((uint64_t)fs->used_bytes == 1);

	CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == value);

	CHECK(memfs_node_write(file, &value, 1, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(file->small_capacity == 2);
	CHECK(memfs_node_resident_bytes(file) == 0);
	CHECK(file->allocation_size == 2);
	CHECK((uint64_t)fs->used_bytes == 2);

	CHECK(memfs_node_write(file, &value, 2, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(file->small_capacity == 4);
	CHECK(memfs_node_resident_bytes(file) == 0);
	CHECK(file->allocation_size == 3);
	CHECK((uint64_t)fs->used_bytes == 3);

	CHECK(memfs_node_write(file, &value, 4, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(file->small_capacity == 8);
	CHECK(memfs_node_resident_bytes(file) == 0);
	CHECK(file->allocation_size == 5);
	CHECK((uint64_t)fs->used_bytes == 5);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK((uint64_t)fs->used_bytes == 0);
	memfs_destroy(fs);
}

static void test_page_group_inline_single_page_transition(void) {
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	MemfsPageGroup* group;
	MemfsPage* first_page;
	uint8_t first[MEMFS_PAGE_SIZE];
	uint8_t second[MEMFS_PAGE_SIZE];
	uint8_t verify[MEMFS_PAGE_SIZE];
	uint32_t transferred = 0;

	printf("== page group inline single-page transition ==\n");
	memset(first, 0x31, sizeof(first));
	memset(second, 0x72, sizeof(second));

	CHECK(memfs_create(16ULL * 1024ULL * 1024ULL, L"INLINEGROUP", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	CHECK(memfs_node_create(fs, fs->root, L"inline-group.bin", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL)
		goto cleanup;

	CHECK(memfs_node_write(file, first, MEMFS_PAGE_SIZE, sizeof(first), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(first));
	CHECK(memfs_node_page_group_count(file) == 1);
	group = memfs_node_page_group(file, 0);
	CHECK(group != NULL);
	if (group == NULL)
		goto cleanup;

	CHECK(group->page_count == 1);
	CHECK(group->page_capacity == 1);
	first_page = memfs_page_group_page(group, 0);
	CHECK(first_page != NULL);

#if !defined(NDEBUG)
	/*
	 * Second full-page write allocates: replacement vector, raw page, then
	 * the 2-entry pointer array. Failing the third generic allocation must
	 * leave the original inline representation and file contents untouched.
	 */
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_GENERIC, 2, 1);
	transferred = 1234;
	CHECK(memfs_node_write(file, second, 2ULL * MEMFS_PAGE_SIZE, sizeof(second),
						   false, false, &transferred) == MEMFS_ERR_NO_MEMORY);
	CHECK(transferred == 0);
	memfs_allocator_test_clear_failures();

	group = memfs_node_page_group(file, 0);
	CHECK(group != NULL);
	if (group != NULL) {
		CHECK(group->page_count == 1);
		CHECK(group->page_capacity == 1);
		CHECK(memfs_page_group_page(group, 0) == first_page);
	}
	CHECK(file->file_size == 2ULL * MEMFS_PAGE_SIZE);
	memset(verify, 0, sizeof(verify));
	CHECK(memfs_node_read(file, verify, MEMFS_PAGE_SIZE, sizeof(verify), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(verify));
	CHECK(memcmp(first, verify, sizeof(first)) == 0);
#endif

	CHECK(memfs_node_write(file, second, 2ULL * MEMFS_PAGE_SIZE, sizeof(second),
						   false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(second));
	group = memfs_node_page_group(file, 0);
	CHECK(group != NULL);
	if (group != NULL) {
		CHECK(group->page_count == 2);
		CHECK(group->page_capacity == 2);
		CHECK(memfs_page_group_page(group, 0) == first_page);
		CHECK(memfs_page_group_page(group, 1) != NULL);
	}

	CHECK(memfs_node_set_file_size(file, 2ULL * MEMFS_PAGE_SIZE) == MEMFS_OK);
	group = memfs_node_page_group(file, 0);
	CHECK(group != NULL);
	if (group != NULL) {
		CHECK(group->page_count == 1);
		CHECK(group->page_capacity == 1);
		CHECK(memfs_page_group_page(group, 0) == first_page);
		CHECK(memfs_page_group_page(group, 1) == NULL);
	}

	memset(verify, 0, sizeof(verify));
	CHECK(memfs_node_read(file, verify, MEMFS_PAGE_SIZE, sizeof(verify), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(verify));
	CHECK(memcmp(first, verify, sizeof(first)) == 0);

cleanup:
	memfs_allocator_test_clear_failures();
	if (file != NULL) {
		(void)memfs_node_unlink(file);
		memfs_node_close(file);
	}
	memfs_destroy(fs);
}

static void test_sparse_pages(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t value = 0xa7;
	uint8_t buffer[32];
	uint32_t transferred;
	uint64_t sparse_size = 64ULL * 1024ULL * 1024ULL;
	uint64_t write_offset = 32ULL * 1024ULL * 1024ULL + 123;
	uint32_t i;

	printf("== sparse pages ==\n");

	CHECK(memfs_create(128ULL * 1024ULL * 1024ULL, L"TEST", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"sparse.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_set_file_size(file, sparse_size) == MEMFS_OK);
	CHECK(file->file_size == sparse_size);
	CHECK(file->allocation_size == sparse_size);
	CHECK((uint64_t)fs->used_bytes == sparse_size);
	CHECK(memfs_node_resident_bytes(file) == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	memset(buffer, 0xcc, sizeof(buffer));
	CHECK(memfs_node_read(file, buffer, 16ULL * 1024ULL * 1024ULL, sizeof(buffer), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(buffer));
	for (i = 0; i < sizeof(buffer); i++)
		CHECK(buffer[i] == 0);

	CHECK(memfs_node_write(file, &value, write_offset, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);
	CHECK(memfs_node_resident_bytes(file) == MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->resident_bytes == MEMFS_PAGE_SIZE);
	CHECK(memfs_node_page_group_count(file) != 0);
	CHECK(sizeof(MemfsPageGroup) <= 64U);
	if (memfs_node_page_group_count(file) != 0) {
		uint64_t group_index = (write_offset >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT;
		MemfsPageGroup* group = NULL;

		CHECK(memfs_node_page_group_count(file) == 1);
		CHECK(memfs_node_page_group_capacity(file) == 1);
		CHECK(memfs_node_page_group_index(file, 0) == group_index);

		if (memfs_node_page_group_count(file) == 1)
			group = memfs_node_page_group(file, 0);

		CHECK(group != NULL);
		if (group) {
			CHECK(group->page_count == 1);
			CHECK(group->page_capacity == 1);
			CHECK(memfs_page_group_page(group, 0) != NULL);
			if (memfs_page_group_page(group, 0))
				CHECK(memfs_page_group_page(group, 0) != NULL);
		}
	}

	memset(buffer, 0xcc, sizeof(buffer));
	CHECK(memfs_node_read(file, buffer, write_offset - 8, sizeof(buffer), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(buffer));
	CHECK(buffer[8] == value);
	for (i = 0; i < sizeof(buffer); i++) {
		if (i != 8)
			CHECK(buffer[i] == 0);
	}

	CHECK(memfs_node_set_file_size(file, 2048) == MEMFS_OK);
	CHECK(file->file_size == 2048);
	CHECK(file->allocation_size == sparse_size);
	CHECK(memfs_node_resident_bytes(file) == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	CHECK(memfs_node_set_allocation_size(file, 2048) == MEMFS_OK);
	CHECK(file->allocation_size == 2048);
	CHECK((uint64_t)fs->used_bytes == 2048);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	memfs_destroy(fs);
}

static void test_sparse_multi_group_truncate_reclaim(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t values[3] = {0x11, 0x22, 0x33};
	uint8_t buffer[32];
	uint32_t transferred;
	uint32_t i;
	uint64_t capacity = 64ULL * 1024ULL * 1024ULL;
	uint64_t offsets[3] = {0x123ULL, 2ULL * MEMFS_PAGE_GROUP_BYTES + 0x456ULL, 4ULL * MEMFS_PAGE_GROUP_BYTES + 0x789ULL};
	uint64_t keep_size = 2ULL * MEMFS_PAGE_GROUP_BYTES + 0x456ULL + 32;
	uint64_t group0 = (offsets[0] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT;
	uint64_t group1 = (offsets[1] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT;
	uint64_t group2 = (offsets[2] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT;
	uint64_t resident_before;
	uint64_t used_before;

	printf("== sparse multi group truncate reclaim ==\n");

	CHECK(memfs_create(capacity, L"SPARSE", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"sparse-multi.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (fs == NULL || file == NULL) {
		if (fs)
			memfs_destroy(fs);
		return;
	}

	for (i = 0; i < 3; i++) {
		CHECK(memfs_node_write(file, &values[i], offsets[i], 1, false, false, &transferred) == MEMFS_OK);
		CHECK(transferred == 1);
	}

	CHECK(memfs_node_page_group_count(file) == 3);
	CHECK(memfs_node_page_group_capacity(file) >= 3);
	CHECK(memfs_node_page_group_index(file, 0) == group0);
	CHECK(memfs_node_page_group_index(file, 1) == group1);
	CHECK(memfs_node_page_group_index(file, 2) == group2);
	CHECK(memfs_node_resident_bytes(file) > 0);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));
	resident_before = memfs_node_resident_bytes(file);
	used_before = fs->used_bytes;

	memset(buffer, 0xcc, sizeof(buffer));
	CHECK(memfs_node_read(file, buffer, offsets[0] - 8, sizeof(buffer), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(buffer));
	CHECK(buffer[8] == values[0]);
	for (i = 0; i < sizeof(buffer); i++) {
		if (i != 8)
			CHECK(buffer[i] == 0);
	}

	memset(buffer, 0xcc, sizeof(buffer));
	CHECK(memfs_node_read(file, buffer, offsets[1] - 8, sizeof(buffer), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(buffer));
	CHECK(buffer[8] == values[1]);

	CHECK(memfs_node_set_file_size(file, keep_size) == MEMFS_OK);
	CHECK(file->file_size == keep_size);
	CHECK(memfs_node_set_allocation_size(file, keep_size) == MEMFS_OK);
	CHECK(file->allocation_size == keep_size);
	CHECK((uint64_t)fs->used_bytes < used_before);
	CHECK(memfs_node_page_group_count(file) == 2);
	CHECK(memfs_node_page_group_capacity(file) >= 2);
	CHECK(memfs_node_page_group_index(file, 0) == group0);
	CHECK(memfs_node_page_group_index(file, 1) == group1);
	CHECK(memfs_node_resident_bytes(file) < resident_before);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	memset(buffer, 0xcc, sizeof(buffer));
	CHECK(memfs_node_read(file, buffer, offsets[0] - 8, sizeof(buffer), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(buffer));
	CHECK(buffer[8] == values[0]);
	for (i = 0; i < sizeof(buffer); i++) {
		if (i != 8)
			CHECK(buffer[i] == 0);
	}

	memset(buffer, 0xcc, sizeof(buffer));
	CHECK(memfs_node_read(file, buffer, offsets[1] - 8, sizeof(buffer), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(buffer));
	CHECK(buffer[8] == values[1]);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == capacity);
	memfs_destroy(fs);
}

static void test_very_high_sparse_offset(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t value = 0x6b;
	uint8_t out = 0;
	uint32_t transferred;
	uint64_t offset = 1ULL << 40;
	uint64_t expected_group = (offset >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT;

	printf("== very high sparse offset ==\n");

	CHECK(memfs_create(2ULL << 40, L"HUGE", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"huge-sparse.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) ==
		  MEMFS_OK);

	CHECK(memfs_node_write(file, &value, offset, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	CHECK(memfs_node_page_group_count(file) == 1);
	CHECK(memfs_node_page_group_capacity(file) == 1);
	CHECK(memfs_node_page_group_count(file) != 0);

	if (memfs_node_page_group_count(file) != 0) {
		CHECK(memfs_node_page_group_index(file, 0) == expected_group);
		CHECK(memfs_node_page_group(file, 0) != NULL);
		if (memfs_node_page_group(file, 0)) {
			CHECK(memfs_node_page_group(file, 0)->page_count == 1);
			CHECK(memfs_node_page_group(file, 0)->page_capacity == 1);
		}
	}

	CHECK(memfs_node_read(file, &out, offset, 1, &transferred) == MEMFS_OK);
	CHECK(out == value);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK(memfs_resident_bytes(fs) == 0);
	memfs_destroy(fs);
}

static void test_small_to_paged_promotion(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t prefix[1024];
	uint8_t value = 0x7d;
	uint8_t verify[1024];
	uint32_t transferred;
	uint32_t i;

	printf("== small -> paged promotion ==\n");

	for (i = 0; i < sizeof(prefix); i++)
		prefix[i] = (uint8_t)i;

	CHECK(memfs_create(16ULL * 1024ULL * 1024ULL, L"TEST", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"promote.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_write(file, prefix, 0, sizeof(prefix), false, false, &transferred) == MEMFS_OK);
	CHECK(!file->small_inline);
	CHECK(memfs_node_resident_bytes(file) >= 1024);
	CHECK(memfs_node_resident_bytes(file) < 1088);

	CHECK(memfs_node_write(file, &value, 2ULL * MEMFS_PAGE_SIZE + 17, 1, false, false, &transferred) == MEMFS_OK);

	CHECK(file->small_capacity == 0);
	CHECK(memfs_node_page_group_count(file) != 0);
	CHECK(memfs_node_resident_bytes(file) >= 2ULL * MEMFS_PAGE_SIZE);
	CHECK(memfs_node_resident_bytes(file) < 2ULL * MEMFS_PAGE_SIZE + 128U);

	memset(verify, 0, sizeof(verify));
	CHECK(memfs_node_read(file, verify, 0, sizeof(verify), &transferred) == MEMFS_OK);
	CHECK(memcmp(prefix, verify, sizeof(prefix)) == 0);

	CHECK(memfs_node_set_file_size(file, 1024) == MEMFS_OK);
	CHECK(!file->small_inline);
	CHECK(memfs_node_page_group_count(file) == 0);
	CHECK(memfs_node_resident_bytes(file) >= 1024);
	CHECK(memfs_node_resident_bytes(file) < 1088);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->resident_bytes == 0);
	memfs_destroy(fs);
}
static void test_truncate_regrow_zero_fill(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t input[2048];
	uint8_t output[2048];
	uint8_t paged_input[3 * MEMFS_PAGE_SIZE + 123];
	uint8_t paged_output[3 * MEMFS_PAGE_SIZE + 123];
	uint32_t transferred;
	uint32_t i;
	uint64_t capacity = 8ULL * 1024ULL * 1024ULL;

	printf("== truncate/regrow zero fill ==\n");

	CHECK(memfs_create(capacity, L"TRUNC", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(0x11 + (i % 251U));

	CHECK(memfs_node_create(fs, fs->root, L"tiny-regrow.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	CHECK(!file->paged_storage);
	CHECK(memfs_node_page_group_count(file) == 0);
	CHECK((uint64_t)fs->used_bytes == sizeof(input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_set_file_size(file, 512) == MEMFS_OK);
	CHECK(file->file_size == 512);
	CHECK((uint64_t)fs->used_bytes == 512);
	CHECK(memfs_free_bytes(fs) == capacity - 512);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_set_file_size(file, sizeof(input)) == MEMFS_OK);
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	CHECK((uint64_t)fs->used_bytes == sizeof(input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(input));
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	memset(output, 0xff, sizeof(output));
	CHECK(memfs_node_read(file, output, 512, sizeof(input) - 512, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input) - 512);
	for (i = 0; i < sizeof(input) - 512; i++)
		CHECK(output[i] == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == capacity);

	for (i = 0; i < sizeof(paged_input); i++)
		paged_input[i] = (uint8_t)(0x22 + (i % 251U));

	CHECK(memfs_node_create(fs, fs->root, L"paged-regrow.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_write(file, paged_input, 0, sizeof(paged_input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(paged_input));
	CHECK(file->file_size == sizeof(paged_input));
	CHECK(file->allocation_size == sizeof(paged_input));
	CHECK(!file->small_inline);
	CHECK(file->paged_storage);
	CHECK(memfs_node_page_group_count(file) != 0);
	CHECK((uint64_t)fs->used_bytes == sizeof(paged_input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(paged_input));
	CHECK(memfs_node_resident_bytes(file) >= 3ULL * MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_set_file_size(file, MEMFS_PAGE_SIZE) == MEMFS_OK);
	CHECK(file->file_size == MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_set_allocation_size(file, MEMFS_PAGE_SIZE) == MEMFS_OK);
	CHECK(file->allocation_size == MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->used_bytes == MEMFS_PAGE_SIZE);
	CHECK(memfs_free_bytes(fs) == capacity - MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_set_file_size(file, sizeof(paged_input)) == MEMFS_OK);
	CHECK(file->file_size == sizeof(paged_input));
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_set_allocation_size(file, sizeof(paged_input)) == MEMFS_OK);
	CHECK(file->allocation_size == sizeof(paged_input));
	CHECK((uint64_t)fs->used_bytes == sizeof(paged_input));
	CHECK(memfs_free_bytes(fs) == capacity - sizeof(paged_input));

	memset(paged_output, 0xff, sizeof(paged_output));
	CHECK(memfs_node_read(file, paged_output, MEMFS_PAGE_SIZE, sizeof(paged_input) - MEMFS_PAGE_SIZE, &transferred) ==
		  MEMFS_OK);
	CHECK(transferred == sizeof(paged_input) - MEMFS_PAGE_SIZE);
	for (i = 0; i < sizeof(paged_input) - MEMFS_PAGE_SIZE; i++)
		CHECK(paged_output[i] == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == capacity);

	memfs_destroy(fs);
}
static void test_allocator_fragmentation_reuse(void) {
	enum { COUNT = 256 };
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats full;
	MemfsAllocatorStats partial;
	MemfsAllocatorStats refilled;
	MemfsAllocatorStats stats;
	void* blocks[COUNT] = {0};
	void* refill[COUNT / 2] = {0};
	void* mixed[10] = {0};
	const uint32_t sizes[10] = {8, 64, 256, 512, 1024, 4096, 16384, 32768, 65536, 262144};
	uint32_t i;
	uint32_t round;

	printf("== allocator fragmentation reuse ==\n");

	memfs_allocator_init(&allocator, 64, 64, 64);
	memfs_allocator_get_stats(&allocator, &baseline);

	for (i = 0; i < COUNT; i++) {
		blocks[i] = memfs_allocator_alloc(&allocator, 512);
		CHECK(blocks[i] != NULL);
	}
	memfs_allocator_get_stats(&allocator, &full);
	CHECK(full.slab_count >= 3);

	for (i = 0; i < COUNT; i += 2U) {
		memfs_allocator_free(&allocator, blocks[i], 512);
		blocks[i] = NULL;
	}
	memfs_allocator_get_stats(&allocator, &partial);
	CHECK(partial.live_objects == COUNT / 2U);
	CHECK(partial.slab_count == full.slab_count);

	for (i = 0; i < COUNT / 2U; i++) {
		refill[i] = memfs_allocator_alloc(&allocator, 512);
		CHECK(refill[i] != NULL);
	}
	memfs_allocator_get_stats(&allocator, &refilled);
	CHECK(refilled.slab_count == full.slab_count);
	CHECK(refilled.reserved_bytes == full.reserved_bytes);
	CHECK(refilled.committed_bytes == full.committed_bytes);

	for (i = 0; i < COUNT; i++) {
		if (blocks[i] != NULL) {
			memfs_allocator_free(&allocator, blocks[i], 512);
			blocks[i] = NULL;
		}
	}
	for (i = 0; i < COUNT / 2U; i++) {
		if (refill[i] != NULL) {
			memfs_allocator_free(&allocator, refill[i], 512);
			refill[i] = NULL;
		}
	}
	memfs_allocator_get_stats(&allocator, &stats);
	CHECK(stats.live_objects == baseline.live_objects);
	CHECK(stats.live_bytes == baseline.live_bytes);
	CHECK(stats.reserved_bytes == baseline.reserved_bytes);
	CHECK(stats.committed_bytes == baseline.committed_bytes);
	CHECK(stats.dedicated_count == baseline.dedicated_count);
	CHECK(stats.physical_bytes == stats.committed_bytes);

	for (round = 0; round < 8; round++) {
		for (i = 0; i < 10; i++) {
			uint8_t* bytes = (uint8_t*)memfs_allocator_alloc(&allocator, sizes[i]);

			CHECK(bytes != NULL);
			if (bytes != NULL) {
				uint32_t fill = sizes[i] < 16U ? sizes[i] : 16U;
				uint32_t j;

				for (j = 0; j < fill; j++)
					bytes[j] = (uint8_t)(round + j + i);
			}
			mixed[i] = bytes;
		}
		for (i = 0; i < 10; i++) {
			if (mixed[i] != NULL) {
				memfs_allocator_free(&allocator, mixed[i], sizes[i]);
				mixed[i] = NULL;
			}
		}
		(void)memfs_allocator_scavenge(&allocator);
		memfs_allocator_get_stats(&allocator, &stats);
		CHECK(stats.live_objects == baseline.live_objects);
		CHECK(stats.live_bytes == baseline.live_bytes);
		CHECK(stats.reserved_bytes == baseline.reserved_bytes);
		CHECK(stats.committed_bytes == baseline.committed_bytes);
		CHECK(stats.dedicated_count == baseline.dedicated_count);
		CHECK(stats.physical_bytes == stats.committed_bytes);
	}

	memfs_allocator_destroy(&allocator);
}
static void test_large_directory(void) {
	enum { COUNT = 5000 };
	Memfs* fs = NULL;
	MemfsNode** nodes;
	MemfsNode* node;
	MemfsNode* prev = NULL;
	wchar_t name[64];
	uint32_t i;
	uint32_t count = 0;

	printf("== large directory treap ==\n");

	nodes = calloc(COUNT, sizeof(*nodes));
	CHECK(nodes != NULL);
	CHECK(memfs_create(64ULL * 1024ULL * 1024ULL, L"TEST", &fs) == MEMFS_OK);

	if (nodes == NULL || fs == NULL)
		goto exit;

	for (i = 0; i < COUNT; i++) {
		uint32_t value = COUNT - 1U - i;

		swprintf_s(name, _countof(name), L"item-%05u", value);
		CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &nodes[value]) == MEMFS_OK);
	}

	CHECK(fs->root->dir->child_count == COUNT);
	CHECK(fs->root->dir->hash != NULL);
	CHECK(sizeof(MemfsDir) <= 24);
	CHECK(sizeof(MemfsNode) <= 136);
	CHECK(fs->root->dir->hash->count == COUNT);

	for (i = 0; i < COUNT; i += 97U) {
		swprintf_s(name, _countof(name), L"item-%05u", i);
		CHECK(memfs_dir_lookup(fs->root, name) == nodes[i]);
		swprintf_s(name, _countof(name), L"ITEM-%05u", i);
		CHECK(memfs_dir_lookup(fs->root, name) == NULL);
	}

	for (node = memfs_dir_first(fs->root); node; node = memfs_dir_next(node)) {
		if (prev)
			CHECK(wcscmp(prev->name, node->name) < 0);
		prev = node;
		count++;
	}
	CHECK(count == COUNT);

	// Robin Hood backward-shift deletion: remove half the table, verify both
	// negative and positive lookups, then fill it again to exercise probe chains.
	for (i = 1; i < COUNT; i += 2U) {
		CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
		memfs_node_close(nodes[i]);
		nodes[i] = NULL;
	}
	CHECK(fs->root->dir->child_count == COUNT / 2U);
	CHECK(fs->root->dir->hash != NULL);
	CHECK(fs->root->dir->hash->count == COUNT / 2U);

	for (i = 0; i < COUNT; i++) {
		swprintf_s(name, _countof(name), L"item-%05u", i);
		if (i & 1U)
			CHECK(memfs_dir_lookup(fs->root, name) == NULL);
		else
			CHECK(memfs_dir_lookup(fs->root, name) == nodes[i]);
	}

	for (i = 1; i < COUNT; i += 2U) {
		swprintf_s(name, _countof(name), L"new-%05u", i);
		CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &nodes[i]) == MEMFS_OK);
	}
	CHECK(fs->root->dir->child_count == COUNT);
	if (fs->root->dir->hash)
		CHECK(fs->root->dir->hash->count == COUNT);

	prev = NULL;
	count = 0;
	for (node = memfs_dir_first(fs->root); node; node = memfs_dir_next(node)) {
		if (prev)
			CHECK(wcscmp(prev->name, node->name) < 0);
		prev = node;
		count++;
	}
	CHECK(count == COUNT);

	for (i = 0; i < COUNT; i++) {
		CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
		memfs_node_close(nodes[i]);
	}

exit:
	free(nodes);
	memfs_destroy(fs);
}

static bool test_orphan_contains(const Memfs* fs, const MemfsNode* target);

static void test_unicode_name_case_sensitive_hash(void) {
	Memfs* fs = NULL;
	MemfsNode* node = NULL;
	MemfsNode* found;
	MemfsNode* duplicate = NULL;
	wchar_t name[32];
	uint32_t i;

	printf("== Unicode case-sensitive directory hash ==\n");
	CHECK(memfs_create(32ULL * 1024ULL * 1024ULL, L"UNICODENAME", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	for (i = 0; i < 300; i++) {
		node = NULL;
		swprintf_s(name, _countof(name), L"filler_%03u.tmp", i);
		CHECK(memfs_node_create(fs, fs->root, name, false,
								FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_OK);
		CHECK(node != NULL);
		if (node != NULL)
			memfs_node_close(node);
	}

	node = NULL;
	CHECK(memfs_node_create(fs, fs->root, L"\u03A9Case.TXT", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_OK);
	CHECK(node != NULL);
	if (node != NULL)
		memfs_node_close(node);

	found = memfs_dir_lookup(fs->root, L"\u03A9Case.TXT");
	CHECK(found != NULL);
	if (found != NULL)
		CHECK(wcscmp(found->name, L"\u03A9Case.TXT") == 0);
	CHECK(memfs_dir_lookup(fs->root, L"\u03A9cASE.txt") == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"\u03A8cASE.txt") == NULL);
	CHECK(memfs_node_create(fs, fs->root, L"\u03C9Case.TXT", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &duplicate) == MEMFS_OK);
	CHECK(duplicate != NULL);
	if (duplicate != NULL) {
		CHECK(memfs_dir_lookup(fs->root, L"\u03C9Case.TXT") == duplicate);
		CHECK(memfs_dir_lookup(fs->root, L"\u03C9case.txt") == NULL);
		CHECK(memfs_node_unlink(duplicate) == MEMFS_OK);
		memfs_node_close(duplicate);
		duplicate = NULL;
	}

	memfs_destroy(fs);
}

static void test_large_directory_case_sensitive_hash_stress(void) {
	enum { COUNT = 1024 };
	Memfs* fs = NULL;
	MemfsNode** nodes;
	MemfsNode* node;
	wchar_t name[64];
	wchar_t variant[64];
	wchar_t new_name[64];
	uint32_t i;

	printf("== large directory case-sensitive hash stress ==\n");

	nodes = calloc(COUNT, sizeof(*nodes));
	CHECK(nodes != NULL);
	CHECK(memfs_create(64ULL * 1024ULL * 1024ULL, L"CASE", &fs) == MEMFS_OK);
	if (nodes == NULL || fs == NULL)
		goto exit;

	for (i = 0; i < COUNT; i++) {
		switch (i % 3U) {
		case 0:
			swprintf_s(name, _countof(name), L"Case-%04u.txt", i);
			break;
		case 1:
			swprintf_s(name, _countof(name), L"CASE-%04u.TXT", i);
			break;
		default:
			swprintf_s(name, _countof(name), L"case-%04u.Txt", i);
			break;
		}
		CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &nodes[i]) == MEMFS_OK);
	}

	CHECK(fs->root->dir->child_count == COUNT);
	if (fs->root->dir->hash)
		CHECK(fs->root->dir->hash->count == COUNT);

	for (i = 0; i < COUNT; i++) {
		switch (i % 3U) {
		case 0:
			swprintf_s(name, _countof(name), L"Case-%04u.txt", i);
			swprintf_s(variant, _countof(variant), L"case-%04u.TXT", i);
			break;
		case 1:
			swprintf_s(name, _countof(name), L"CASE-%04u.TXT", i);
			swprintf_s(variant, _countof(variant), L"Case-%04u.txt", i);
			break;
		default:
			swprintf_s(name, _countof(name), L"case-%04u.Txt", i);
			swprintf_s(variant, _countof(variant), L"CASE-%04u.TXT", i);
			break;
		}
		CHECK(memfs_dir_lookup(fs->root, name) == nodes[i]);
		CHECK(memfs_dir_lookup(fs->root, variant) == NULL);
	}

	swprintf_s(name, _countof(name), L"missing-%04u.txt", COUNT);
	CHECK(memfs_dir_lookup(fs->root, name) == NULL);

	for (i = 0; i < COUNT; i += 128U) {
		switch (i % 3U) {
		case 0:
			swprintf_s(name, _countof(name), L"Case-%04u.txt", i);
			break;
		case 1:
			swprintf_s(name, _countof(name), L"CASE-%04u.TXT", i);
			break;
		default:
			swprintf_s(name, _countof(name), L"case-%04u.Txt", i);
			break;
		}
		CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_ERR_EXISTS);
	}
	CHECK(fs->root->dir->child_count == COUNT);
	if (fs->root->dir->hash)
		CHECK(fs->root->dir->hash->count == COUNT);

	for (i = 0; i < COUNT; i += 256U) {
		switch (i % 3U) {
		case 0:
			swprintf_s(new_name, _countof(new_name), L"RENAMED-%04u.txt", i);
			break;
		case 1:
			swprintf_s(new_name, _countof(new_name), L"Renamed-%04u.TXT", i);
			break;
		default:
			swprintf_s(new_name, _countof(new_name), L"renamed-%04u.Txt", i);
			break;
		}
		CHECK(memfs_node_rename(nodes[i], fs->root, new_name, false) == MEMFS_OK);
		CHECK(wcscmp(nodes[i]->name, new_name) == 0);
		CHECK(memfs_dir_lookup(fs->root, new_name) == nodes[i]);
	}

	for (i = 0; i < COUNT; i += 256U) {
		switch (i % 3U) {
		case 0:
			swprintf_s(name, _countof(name), L"Case-%04u.txt", i);
			break;
		case 1:
			swprintf_s(name, _countof(name), L"CASE-%04u.TXT", i);
			break;
		default:
			swprintf_s(name, _countof(name), L"case-%04u.Txt", i);
			break;
		}
		CHECK(memfs_dir_lookup(fs->root, name) == NULL);
	}

	for (i = 0; i < COUNT; i += 512U) {
		memfs_node_open(nodes[i]);
		CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
		CHECK(test_orphan_contains(fs, nodes[i]));
	}

	for (i = 0; i < COUNT; i += 512U) {
		switch (i % 3U) {
		case 0:
			swprintf_s(name, _countof(name), L"RENAMED-%04u.txt", i);
			break;
		case 1:
			swprintf_s(name, _countof(name), L"Renamed-%04u.TXT", i);
			break;
		default:
			swprintf_s(name, _countof(name), L"renamed-%04u.Txt", i);
			break;
		}
		CHECK(memfs_dir_lookup(fs->root, name) == NULL);
	}

	CHECK(fs->root->dir->child_count == COUNT - COUNT / 512U);
	if (fs->root->dir->hash)
		CHECK(fs->root->dir->hash->count == COUNT - COUNT / 512U);

	for (i = 0; i < COUNT; i++) {
		if (nodes[i] == NULL)
			continue;
		if (i % 512U == 0U) {
			memfs_node_close(nodes[i]);
			memfs_node_close(nodes[i]);
			nodes[i] = NULL;
		} else {
			CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
			memfs_node_close(nodes[i]);
			nodes[i] = NULL;
		}
	}

	CHECK(fs->root->dir->child_count == 0);
	if (fs->root->dir->hash)
		CHECK(fs->root->dir->hash->count == 0);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(fs->orphan_head == NULL);

exit:
	free(nodes);
	memfs_destroy(fs);
}

static void test_compression(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t input[8192];
	uint8_t output[8192];
	uint32_t transferred;
	MemfsPageGroup* group;

	printf("== zstd compression ==\n");

	memset(input, 'A', sizeof(input));
	options.capacity = 16ULL * 1024ULL * 1024ULL;
	options.volume_label = L"COMP";
	options.compression_enabled = true;
	options.compression_level = 1;

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"compressed.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memfs_node_page_group_count(file) != 0);

	group = memfs_node_page_group(file, 0);
	CHECK(group != NULL);
	if (group) {
		CHECK(memfs_page_group_page(group, 0) != NULL);
		CHECK(memfs_page_group_page(group, 1) != NULL);
		if (memfs_page_group_page(group, 0))
			CHECK(0 != (memfs_page_group_page(group, 0)->flags & MEMFS_PAGE_COMPRESSED));
		if (memfs_page_group_page(group, 1))
			CHECK(0 != (memfs_page_group_page(group, 1)->flags & MEMFS_PAGE_COMPRESSED));
	}

	CHECK(memfs_node_resident_bytes(file) < 1024);

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(output));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}

static void test_adaptive_compression(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	MemfsPageGroup* group;
	uint8_t page[MEMFS_PAGE_SIZE];
	uint8_t verify[MEMFS_PAGE_SIZE];
	uint32_t transferred;
	uint32_t state = 0x12345678U;
	uint32_t page_index;
	uint32_t i;

	printf("== adaptive compression ==\n");

	options.capacity = 4ULL * 1024ULL * 1024ULL;
	options.volume_label = L"ADAPT";
	options.compression_enabled = true;
	options.compression_level = 1;

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"adaptive.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	// 64 pages of pseudo-random input: after a few failed probes the
	// compressor should enter skip/probe mode.
	for (page_index = 0; page_index < 64; page_index++) {
		for (i = 0; i < sizeof(page); i += sizeof(state)) {
			state ^= state << 13;
			state ^= state >> 17;
			state ^= state << 5;
			memcpy(page + i, &state, sizeof(state));
		}

		CHECK(memfs_node_write(file, page, (uint64_t)page_index * MEMFS_PAGE_SIZE, sizeof(page), false, false,
							   &transferred) == MEMFS_OK);
	}

	CHECK(memfs_node_compression_score(file) >= MEMFS_COMPRESSION_SKIP_SCORE);

	// Data becomes compressible. Periodic probes must discover this and
	// re-enable normal compression attempts.
	memset(page, 'A', sizeof(page));
	for (; page_index < 128; page_index++) {
		CHECK(memfs_node_write(file, page, (uint64_t)page_index * MEMFS_PAGE_SIZE, sizeof(page), false, false,
							   &transferred) == MEMFS_OK);
	}

	CHECK(memfs_node_compression_score(file) < MEMFS_COMPRESSION_SKIP_SCORE);

	group = memfs_node_page_group(file, 0);
	CHECK(group != NULL);
	if (group && group->page_count == 128) {
		CHECK(0 != (memfs_page_group_page(group, 127)->flags & MEMFS_PAGE_COMPRESSED));
	}

	memset(verify, 0, sizeof(verify));
	CHECK(memfs_node_read(file, verify, 127ULL * MEMFS_PAGE_SIZE, sizeof(verify), &transferred) == MEMFS_OK);
	CHECK(memcmp(page, verify, sizeof(page)) == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}

static void test_compression_incompressible_page_fallback(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	MemfsPageGroup* group;
	uint8_t page[MEMFS_PAGE_SIZE];
	uint8_t page2[MEMFS_PAGE_SIZE];
	uint8_t verify[MEMFS_PAGE_SIZE];
	uint32_t transferred;
	uint32_t state;
	uint32_t i;

	printf("== compression incompressible page fallback ==\n");

	options.capacity = 16ULL * 1024ULL * 1024ULL;
	options.volume_label = L"COMPFB";
	options.compression_enabled = true;
	options.compression_level = 1;

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"incompressible.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) ==
		  MEMFS_OK);
	CHECK(file != NULL);

	state = 0x9e3779b9U;
	for (i = 0; i < sizeof(page); i += sizeof(state)) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		memcpy(page + i, &state, sizeof(state));
	}

	CHECK(memfs_node_write(file, page, 0, MEMFS_PAGE_SIZE, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == MEMFS_PAGE_SIZE);
	CHECK(file->file_size == MEMFS_PAGE_SIZE);
	CHECK(file->allocation_size == MEMFS_PAGE_SIZE);

	group = memfs_node_page_group(file, 0);
	if (group) {
		CHECK(group->page_count == 1);
		CHECK(memfs_page_group_page(group, 0) != NULL);
		if (memfs_page_group_page(group, 0)) {
			CHECK(0 == (memfs_page_group_page(group, 0)->flags & MEMFS_PAGE_COMPRESSED));
			CHECK(memfs_page_group_page(group, 0)->plain_size == MEMFS_PAGE_SIZE);
			CHECK(memfs_page_group_page(group, 0)->stored_size >= MEMFS_PAGE_SIZE);
		}
	}

	CHECK(memfs_node_resident_bytes(file) >= MEMFS_PAGE_SIZE);
	CHECK(memfs_node_resident_bytes(file) < MEMFS_PAGE_SIZE + 64U);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));
	CHECK((uint64_t)fs->used_bytes == MEMFS_PAGE_SIZE);
	CHECK(memfs_free_bytes(fs) == options.capacity - MEMFS_PAGE_SIZE);

	memset(verify, 0, sizeof(verify));
	CHECK(memfs_node_read(file, verify, 0, MEMFS_PAGE_SIZE, &transferred) == MEMFS_OK);
	CHECK(transferred == MEMFS_PAGE_SIZE);
	CHECK(memcmp(page, verify, MEMFS_PAGE_SIZE) == 0);

	state = 0x85ebca6bU;
	for (i = 0; i < sizeof(page2); i += sizeof(state)) {
		state ^= state << 13;
		state ^= state >> 17;
		state ^= state << 5;
		memcpy(page2 + i, &state, sizeof(state));
	}

	CHECK(memfs_node_write(file, page2, 0, MEMFS_PAGE_SIZE, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == MEMFS_PAGE_SIZE);
	CHECK(file->file_size == MEMFS_PAGE_SIZE);
	CHECK(file->allocation_size == MEMFS_PAGE_SIZE);

	group = memfs_node_page_group(file, 0);
	if (group) {
		CHECK(group->page_count == 1);
		CHECK(memfs_page_group_page(group, 0) != NULL);
		if (memfs_page_group_page(group, 0))
			CHECK(0 == (memfs_page_group_page(group, 0)->flags & MEMFS_PAGE_COMPRESSED));
	}

	memset(verify, 0, sizeof(verify));
	CHECK(memfs_node_read(file, verify, 0, MEMFS_PAGE_SIZE, &transferred) == MEMFS_OK);
	CHECK(transferred == MEMFS_PAGE_SIZE);
	CHECK(memcmp(page2, verify, MEMFS_PAGE_SIZE) == 0);

	CHECK(memfs_node_resident_bytes(file) < 2ULL * MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->used_bytes == MEMFS_PAGE_SIZE);
	CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == options.capacity);
	CHECK(memfs_resident_bytes(fs) == 0);

	memfs_destroy(fs);
}

static void test_encryption(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	Memfs* second_fs = NULL;
	MemfsNode* file = NULL;
	uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint8_t value = 0x5a;
	uint8_t output = 0;
	uint8_t saved;
	uint32_t transferred = 0;
	uint32_t i;

	printf("== authenticated encryption auto-selection ==\n");

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(i * 7U + 3U);

	options.capacity = 8ULL * 1024ULL * 1024ULL;
	options.volume_label = L"CRYPT";
	options.encryption_enabled = true;
	options.encryption_key = key;
	options.encryption_key_size = sizeof(key);

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	CHECK(memfs_create_ex(&options, &second_fs) == MEMFS_OK);
	CHECK(second_fs != NULL);
	if (second_fs != NULL) {
		CHECK(fs->encryption_aes_gcm == second_fs->encryption_aes_gcm);
		CHECK(memcmp(fs->encryption_key,
					 second_fs->encryption_key,
					 MEMFS_ENCRYPTION_KEY_SIZE) == 0);
		CHECK(memcmp(fs->encryption_nonce_prefix,
					 second_fs->encryption_nonce_prefix,
					 MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE) != 0);
		if (fs->encryption_aes_gcm) {
			CHECK(memcmp(fs->encryption_aes_key,
						 second_fs->encryption_aes_key,
						 MEMFS_ENCRYPTION_KEY_SIZE) != 0);
		}
		memfs_destroy(second_fs);
		second_fs = NULL;
	}

	CHECK(memfs_node_create(fs, fs->root, L"secret.bin", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL) {
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_write(file, &value, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);
	CHECK(file->small_capacity == 1);
	CHECK(!file->small_inline);
	CHECK(memfs_node_resident_bytes(file) ==
		  sizeof(MemfsPage) + sizeof(uint64_t) + 1U +
			  16U);

	if (file->small_page != NULL) {
		bool saved_preference = fs->encryption_aes_gcm;
		uint8_t saved_flags = file->small_page->flags;

		CHECK((saved_flags & MEMFS_PAGE_ENCRYPTED) != 0);
		CHECK(((saved_flags & MEMFS_PAGE_AES_GCM) != 0) == saved_preference);
		CHECK(file->small_page->stored_size > file->small_capacity);

		/* Decode by authenticated page flag, not by current encoder preference. */
		fs->encryption_aes_gcm = !saved_preference;
		CHECK(memfs_node_read(file, &output, 0, 1, &transferred) == MEMFS_OK);
		CHECK(output == value);
		fs->encryption_aes_gcm = saved_preference;

		/* The algorithm selector is authenticated as part of page AAD. */
		file->small_page->flags ^= MEMFS_PAGE_AES_GCM;
		CHECK(memfs_node_read(file, &output, 0, 1, &transferred) == MEMFS_ERR_DATA);
		file->small_page->flags = saved_flags;
	}

	CHECK(memfs_node_read(file, &output, 0, 1, &transferred) == MEMFS_OK);
	CHECK(output == value);

	if (file->small_page != NULL && file->small_page->stored_size != 0) {
		saved = file->small_page->data[file->small_page->stored_size - 1U];
		file->small_page->data[file->small_page->stored_size - 1U] ^= 0x80;
		CHECK(memfs_node_read(file, &output, 0, 1, &transferred) == MEMFS_ERR_DATA);
		file->small_page->data[file->small_page->stored_size - 1U] = saved;
	}

	CHECK(memfs_node_read(file, &output, 0, 1, &transferred) == MEMFS_OK);
	CHECK(output == value);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}

static void test_encryption_algorithm_selection(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* aes_file = NULL;
	MemfsNode* xchacha_file = NULL;
	uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint8_t aes_value = 0x31;
	uint8_t xchacha_value = 0xc7;
	uint8_t output = 0;
	uint32_t transferred = 0;
	uint32_t i;
	bool aes_available;

	printf("== encryption algorithm selection / mixed decode ==\n");

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(0xa5U ^ (i * 13U));

	options.capacity = 8ULL * 1024ULL * 1024ULL;
	options.volume_label = L"AEADMIX";
	options.encryption_enabled = true;
	options.encryption_key = key;
	options.encryption_key_size = sizeof(key);

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	aes_available = fs->encryption_aes_gcm;

#if !defined(NDEBUG)
	if (aes_available) {
		Memfs* fallback_fs = NULL;
		MemfsNode* fallback_file = NULL;
		MemfsResult fallback_result;

		memfs_test_force_xchacha(true);
		fallback_result = memfs_create_ex(&options, &fallback_fs);
		memfs_test_force_xchacha(false);

		CHECK(fallback_result == MEMFS_OK);
		CHECK(fallback_fs != NULL);
		if (fallback_fs != NULL) {
			CHECK(!fallback_fs->encryption_aes_gcm);
			CHECK(memcmp(fallback_fs->encryption_key,
						 key, MEMFS_ENCRYPTION_KEY_SIZE) == 0);
			CHECK(memfs_node_create(
					  fallback_fs, fallback_fs->root, L"fallback.bin",
					  false, FILE_ATTRIBUTE_NORMAL, NULL, 0,
					  &fallback_file) == MEMFS_OK);
			CHECK(fallback_file != NULL);
			if (fallback_file != NULL) {
				CHECK(memfs_node_write(
						  fallback_file, &xchacha_value, 0, 1,
						  false, false, &transferred) == MEMFS_OK);
				CHECK(fallback_file->small_page != NULL);
				if (fallback_file->small_page != NULL)
					CHECK((fallback_file->small_page->flags &
						   MEMFS_PAGE_AES_GCM) == 0);

				/* Decoder still follows the page flag after preference changes. */
				fallback_fs->encryption_aes_gcm = true;
				CHECK(memfs_node_read(
						  fallback_file, &output, 0, 1,
						  &transferred) == MEMFS_OK);
				CHECK(output == xchacha_value);

				CHECK(memfs_node_unlink(fallback_file) == MEMFS_OK);
				memfs_node_close(fallback_file);
			}
			memfs_destroy(fallback_fs);
		}
	}
#endif

	if (!aes_available) {
		CHECK(!fs->encryption_aes_gcm);
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_create(
			  fs, fs->root, L"aes.bin", false,
			  FILE_ATTRIBUTE_NORMAL, NULL, 0, &aes_file) == MEMFS_OK);
	CHECK(aes_file != NULL);
	if (aes_file == NULL) {
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_write(
			  aes_file, &aes_value, 0, 1,
			  false, false, &transferred) == MEMFS_OK);
	CHECK(aes_file->small_page != NULL);
	if (aes_file->small_page != NULL)
		CHECK((aes_file->small_page->flags & MEMFS_PAGE_AES_GCM) != 0);

	fs->encryption_aes_gcm = false;
	CHECK(memfs_node_create(
			  fs, fs->root, L"xchacha.bin", false,
			  FILE_ATTRIBUTE_NORMAL, NULL, 0, &xchacha_file) == MEMFS_OK);
	CHECK(xchacha_file != NULL);
	if (xchacha_file != NULL) {
		CHECK(memfs_node_write(
				  xchacha_file, &xchacha_value, 0, 1,
				  false, false, &transferred) == MEMFS_OK);
		CHECK(xchacha_file->small_page != NULL);
		if (xchacha_file->small_page != NULL)
			CHECK((xchacha_file->small_page->flags & MEMFS_PAGE_AES_GCM) == 0);
	}

	for (i = 0; i < 2; ++i) {
		fs->encryption_aes_gcm = i == 0;
		output = 0;
		CHECK(memfs_node_read(
				  aes_file, &output, 0, 1, &transferred) == MEMFS_OK);
		CHECK(output == aes_value);
		if (xchacha_file != NULL) {
			output = 0;
			CHECK(memfs_node_read(
					  xchacha_file, &output, 0, 1,
					  &transferred) == MEMFS_OK);
			CHECK(output == xchacha_value);
		}
	}

	if (xchacha_file != NULL) {
		CHECK(memfs_node_unlink(xchacha_file) == MEMFS_OK);
		memfs_node_close(xchacha_file);
	}
	CHECK(memfs_node_unlink(aes_file) == MEMFS_OK);
	memfs_node_close(aes_file);
	memfs_destroy(fs);
}

static void test_encryption_rewrite_truncate_regrow(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint8_t input[3 * MEMFS_PAGE_SIZE + 123];
	uint8_t output[3 * MEMFS_PAGE_SIZE + 123];
	uint32_t transferred;
	uint32_t i;
	uint32_t round;
	uint64_t regrow_size = sizeof(input);
	uint64_t smaller_size = MEMFS_PAGE_SIZE;

	printf("== encryption rewrite/truncate/regrow integrity ==\n");

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(0x5aU + i * 11U);

	options.capacity = 64ULL * 1024ULL * 1024ULL;
	options.volume_label = L"CRYPTRW";
	options.encryption_enabled = true;
	options.encryption_key = key;
	options.encryption_key_size = sizeof(key);

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"crypt-rewrite.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (fs == NULL || file == NULL) {
		if (fs)
			memfs_destroy(fs);
		return;
	}

	for (round = 0; round < 4; round++) {
		for (i = 0; i < sizeof(input); i++)
			input[i] = (uint8_t)(0x10U + round * 17U + (i % 251U));

		CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
		CHECK(transferred == sizeof(input));
		CHECK(file->file_size == regrow_size);
		CHECK(file->allocation_size == regrow_size);
		CHECK((uint64_t)fs->used_bytes == regrow_size);
		CHECK(memfs_free_bytes(fs) == options.capacity - regrow_size);
		CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

		memset(output, 0xff, sizeof(output));
		CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
		CHECK(transferred == sizeof(output));
		CHECK(memcmp(input, output, sizeof(input)) == 0);

		CHECK(memfs_node_set_file_size(file, smaller_size) == MEMFS_OK);
		CHECK(file->file_size == smaller_size);
		CHECK(memfs_node_set_allocation_size(file, smaller_size) == MEMFS_OK);
		CHECK(file->allocation_size == smaller_size);
		CHECK((uint64_t)fs->used_bytes == smaller_size);
		CHECK(memfs_free_bytes(fs) == options.capacity - smaller_size);
		CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

		memset(output, 0xff, sizeof(output));
		CHECK(memfs_node_read(file, output, 0, smaller_size, &transferred) == MEMFS_OK);
		CHECK(transferred == (uint32_t)smaller_size);
		CHECK(memcmp(input, output, smaller_size) == 0);

		CHECK(memfs_node_set_file_size(file, regrow_size) == MEMFS_OK);
		CHECK(file->file_size == regrow_size);
		CHECK(memfs_node_set_allocation_size(file, regrow_size) == MEMFS_OK);
		CHECK(file->allocation_size == regrow_size);
		CHECK((uint64_t)fs->used_bytes == regrow_size);
		CHECK(memfs_free_bytes(fs) == options.capacity - regrow_size);
		CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

		memset(output, 0xff, sizeof(output));
		CHECK(memfs_node_read(file, output, smaller_size, regrow_size - smaller_size, &transferred) == MEMFS_OK);
		CHECK(transferred == (uint32_t)(regrow_size - smaller_size));
		for (i = 0; i < regrow_size - smaller_size; i++)
			CHECK(output[i] == 0);
	}

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == options.capacity);
	CHECK(memfs_resident_bytes(fs) == 0);

	memfs_destroy(fs);
}

static void test_compression_encryption(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint8_t input[8192];
	uint8_t output[8192];
	uint32_t transferred;
	uint32_t i;
	MemfsPageGroup* group;

	printf("== compression + encryption ==\n");

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(0xa5U ^ i);
	memset(input, 0x11, sizeof(input));

	options.capacity = 16ULL * 1024ULL * 1024ULL;
	options.volume_label = L"BOTH";
	options.compression_enabled = true;
	options.compression_level = 3;
	options.encryption_enabled = true;
	options.encryption_key = key;
	options.encryption_key_size = sizeof(key);

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"both.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);

	group = memfs_node_page_group_count(file) ? memfs_node_page_group(file, 0) : NULL;
	CHECK(group != NULL);
	if (group && memfs_page_group_page(group, 0)) {
		CHECK(0 != (memfs_page_group_page(group, 0)->flags & MEMFS_PAGE_COMPRESSED));
		CHECK(0 != (memfs_page_group_page(group, 0)->flags & MEMFS_PAGE_ENCRYPTED));
	}
	CHECK(memfs_node_resident_bytes(file) < 2048);

	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}

static void test_compression_encryption_sparse_rewrite_truncate_regrow(void) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint8_t output[1024];
	uint32_t transferred;
	uint32_t i;
	uint32_t round;
	uint64_t capacity = 256ULL * 1024ULL * 1024ULL;
	uint64_t offsets[3] = {0x123ULL, 2ULL * MEMFS_PAGE_GROUP_BYTES + 0x456ULL, 4ULL * MEMFS_PAGE_GROUP_BYTES + 0x789ULL};
	uint64_t keep_size = 2ULL * MEMFS_PAGE_GROUP_BYTES + 0x456ULL + 128;
	uint64_t regrow_size = 4ULL * MEMFS_PAGE_GROUP_BYTES + 0x789ULL + 128;
	uint64_t used_before;
	uint64_t resident_before;

	printf("== compression + encryption sparse rewrite/truncate/regrow ==\n");

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(0x77U + i * 13U);

	options.capacity = capacity;
	options.volume_label = L"COMPCRYPT";
	options.compression_enabled = true;
	options.compression_level = 1;
	options.encryption_enabled = true;
	options.encryption_key = key;
	options.encryption_key_size = sizeof(key);

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"comp-crypt-sparse.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) ==
		  MEMFS_OK);
	CHECK(file != NULL);
	if (fs == NULL || file == NULL) {
		if (fs)
			memfs_destroy(fs);
		return;
	}

	for (round = 0; round < 4; round++) {
		uint8_t sparse_data[3][128];
		uint8_t rewrite_data[3][128];
		uint32_t j;

		for (i = 0; i < 3; i++) {
			uint64_t offset = offsets[i];
			uint64_t end = offset + sizeof(sparse_data[i]);

			for (j = 0; j < sizeof(sparse_data[i]); j++)
				sparse_data[i][j] = (uint8_t)(0x20U + round * 29U + (j % 191U) + j * 3U);

			CHECK(memfs_node_write(file, sparse_data[i], offset, sizeof(sparse_data[i]), false, false, &transferred) ==
				  MEMFS_OK);
			CHECK(transferred == sizeof(sparse_data[i]));
			CHECK(file->file_size >= end);
			CHECK(file->allocation_size >= end);
			CHECK((uint64_t)fs->used_bytes == file->file_size);
			CHECK(memfs_free_bytes(fs) == capacity - file->file_size);
			CHECK(memfs_node_resident_bytes(file) > 0);
			CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));
		}

		CHECK(memfs_node_page_group_count(file) == 3);
		CHECK(memfs_node_page_group_index(file, 0) == (offsets[0] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT);
		CHECK(memfs_node_page_group_index(file, 1) == (offsets[1] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT);
		CHECK(memfs_node_page_group_index(file, 2) == (offsets[2] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT);

		for (i = 0; i < 3; i++) {
			memset(output, 0xcc, sizeof(output));
			CHECK(memfs_node_read(file, output, offsets[i], sizeof(sparse_data[i]), &transferred) == MEMFS_OK);
			CHECK(transferred == sizeof(sparse_data[i]));
			CHECK(memcmp(sparse_data[i], output, sizeof(sparse_data[i])) == 0);
		}

		used_before = fs->used_bytes;
		resident_before = memfs_node_resident_bytes(file);

		for (i = 0; i < 3; i++) {
			for (j = 0; j < sizeof(rewrite_data[i]); j++)
				rewrite_data[i][j] = (uint8_t)(0x40U + round * 31U + (j % 211U) + j * 5U);

			CHECK(memfs_node_write(file, rewrite_data[i], offsets[i], sizeof(rewrite_data[i]), false, false,
								   &transferred) == MEMFS_OK);
			CHECK(transferred == sizeof(rewrite_data[i]));
		}

		CHECK(file->file_size >= regrow_size);
		CHECK((uint64_t)fs->used_bytes == file->file_size);
		CHECK(memfs_free_bytes(fs) == capacity - file->file_size);
		CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

		for (i = 0; i < 3; i++) {
			memset(output, 0xcc, sizeof(output));
			CHECK(memfs_node_read(file, output, offsets[i], sizeof(rewrite_data[i]), &transferred) == MEMFS_OK);
			CHECK(transferred == sizeof(rewrite_data[i]));
			CHECK(memcmp(rewrite_data[i], output, sizeof(rewrite_data[i])) == 0);
		}

		CHECK(memfs_node_set_file_size(file, keep_size) == MEMFS_OK);
		CHECK(file->file_size == keep_size);
		CHECK(memfs_node_set_allocation_size(file, keep_size) == MEMFS_OK);
		CHECK(file->allocation_size == keep_size);
		CHECK((uint64_t)fs->used_bytes == keep_size);
		CHECK(memfs_free_bytes(fs) == capacity - keep_size);
		CHECK((uint64_t)fs->used_bytes < used_before);
		CHECK(memfs_node_resident_bytes(file) < resident_before);
		CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));
		CHECK(memfs_node_page_group_count(file) == 2);
		CHECK(memfs_node_page_group_index(file, 0) == (offsets[0] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT);
		CHECK(memfs_node_page_group_index(file, 1) == (offsets[1] >> MEMFS_PAGE_SHIFT) >> MEMFS_PAGE_GROUP_SHIFT);

		for (i = 0; i < 2; i++) {
			memset(output, 0xcc, sizeof(output));
			CHECK(memfs_node_read(file, output, offsets[i], sizeof(rewrite_data[i]), &transferred) == MEMFS_OK);
			CHECK(transferred == sizeof(rewrite_data[i]));
			CHECK(memcmp(rewrite_data[i], output, sizeof(rewrite_data[i])) == 0);
		}

		CHECK(memfs_node_set_file_size(file, regrow_size) == MEMFS_OK);
		CHECK(file->file_size == regrow_size);
		CHECK(memfs_node_set_allocation_size(file, regrow_size) == MEMFS_OK);
		CHECK(file->allocation_size == regrow_size);
		CHECK((uint64_t)fs->used_bytes == regrow_size);
		CHECK(memfs_free_bytes(fs) == capacity - regrow_size);
		CHECK((uint64_t)fs->resident_bytes == memfs_node_resident_bytes(file));

		for (i = 0; i < 2; i++) {
			memset(output, 0xcc, sizeof(output));
			CHECK(memfs_node_read(file, output, offsets[i], sizeof(rewrite_data[i]), &transferred) == MEMFS_OK);
			CHECK(transferred == sizeof(rewrite_data[i]));
			CHECK(memcmp(rewrite_data[i], output, sizeof(rewrite_data[i])) == 0);
		}

		memset(output, 0xff, sizeof(output));
		CHECK(memfs_node_read(file, output, keep_size, sizeof(output), &transferred) == MEMFS_OK);
		CHECK(transferred == sizeof(output));
		for (i = 0; i < sizeof(output); i++)
			CHECK(output[i] == 0);
	}

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	CHECK(memfs_free_bytes(fs) == capacity);
	CHECK(memfs_resident_bytes(fs) == 0);

	memfs_destroy(fs);
}

static void test_shared_security(void) {
	enum { FILES = 256 };
	Memfs* fs = NULL;
	MemfsNode* dir;
	MemfsNode* files[FILES] = {0};
	PSECURITY_DESCRIPTOR alternate = NULL;
	ULONG alternate_size = 0;
	MemfsSecurity* shared;
	LONG before;
	uint32_t i;

	printf("== shared ACL metadata ==\n");

	CHECK(memfs_create(32ULL * 1024ULL * 1024ULL, L"ACL", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	CHECK(memfs_node_create(fs, fs->root, L"dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	if (dir == NULL) {
		memfs_destroy(fs);
		return;
	}

	shared = memfs_node_get_security(dir);
	CHECK(shared == memfs_node_get_security(fs->root));
	before = shared->ref_count;

	for (i = 0; i < FILES; i++) {
		wchar_t name[32];

		swprintf_s(name, _countof(name), L"f-%03u", i);

		CHECK(memfs_node_create(fs, dir, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &files[i]) == MEMFS_OK);

		if (files[i])
			CHECK(memfs_node_get_security(files[i]) == shared);
	}

	CHECK(shared->ref_count == before + FILES);
	CHECK(shared->size > 0);

	CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;GRGW;;;WD)", SDDL_REVISION_1,
															   &alternate, &alternate_size));

	if (alternate && files[0]) {
		CHECK(memfs_node_replace_security(files[0], alternate, alternate_size) == MEMFS_OK);
		CHECK(memfs_node_get_security(files[0]) != shared);
		CHECK(shared->ref_count == before + FILES - 1);
	}

	if (alternate)
		LocalFree(alternate);

	for (i = 0; i < FILES; i++) {
		if (files[i]) {
			CHECK(memfs_node_unlink(files[i]) == MEMFS_OK);
			memfs_node_close(files[i]);
		}
	}

	CHECK(memfs_node_unlink(dir) == MEMFS_OK);
	memfs_node_close(dir);
	memfs_destroy(fs);
}

static void test_shared_security_inherit_replace_churn(void) {
	enum { CHURN_ROUNDS = 8, CHURN_FILES = 64, INHERIT_FILES = 8 };
	Memfs* fs = NULL;
	MemfsNode* dir = NULL;
	MemfsNode* sub = NULL;
	MemfsNode* child_file = NULL;
	MemfsNode* churn_dir = NULL;
	MemfsNode* inherit_nodes[INHERIT_FILES] = {0};
	MemfsNode* churn_nodes[CHURN_FILES] = {0};
	MemfsSecurity* shared = NULL;
	PSECURITY_DESCRIPTOR sd_a = NULL;
	PSECURITY_DESCRIPTOR sd_b = NULL;
	ULONG sd_a_size = 0;
	ULONG sd_b_size = 0;
	LONG before;
	LONG current;
	uint32_t i;
	uint32_t round;

	printf("== shared security inherit/replace/churn ==\n");

	CHECK(memfs_create(64ULL * 1024ULL * 1024ULL, L"ACLCHURN", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	CHECK(memfs_node_create(fs, fs->root, L"dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	if (dir == NULL) {
		memfs_destroy(fs);
		return;
	}

	shared = memfs_node_get_security(dir);
	CHECK(shared != NULL);
	CHECK(shared == memfs_node_get_security(fs->root));
	if (shared == NULL) {
		memfs_node_close(dir);
		memfs_destroy(fs);
		return;
	}

	CHECK(memfs_node_create(fs, dir, L"sub", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &sub) == MEMFS_OK);
	CHECK(sub != NULL);
	if (sub == NULL)
		goto cleanup;

	CHECK(memfs_node_create(fs, sub, L"child.txt", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &child_file) == MEMFS_OK);
	CHECK(child_file != NULL);
	if (child_file == NULL)
		goto cleanup;

	CHECK(memfs_node_get_security(sub) == shared);
	CHECK(memfs_node_get_security(child_file) == shared);

	before = shared->ref_count;
	for (i = 0; i < INHERIT_FILES; i++) {
		wchar_t name[32];

		swprintf_s(name, _countof(name), L"inherit-%02u", i);
		CHECK(memfs_node_create(fs, dir, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &inherit_nodes[i]) == MEMFS_OK);
		if (inherit_nodes[i])
			CHECK(memfs_node_get_security(inherit_nodes[i]) == shared);
	}
	current = shared->ref_count;
	CHECK(current == before + INHERIT_FILES);

	CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;GRGW;;;WD)", SDDL_REVISION_1, &sd_a,
															   &sd_a_size));
	CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;GRGW;;;BA)", SDDL_REVISION_1, &sd_b,
															   &sd_b_size));
	if (sd_a == NULL || sd_b == NULL)
		goto cleanup;

	before = shared->ref_count;
	CHECK(memfs_node_replace_security(sub, sd_a, sd_a_size) == MEMFS_OK);
	CHECK(memfs_node_get_security(sub) != shared);
	CHECK(memfs_node_get_security(sub) != NULL);
	current = shared->ref_count;
	CHECK(current == before - 1);

	before = shared->ref_count;
	CHECK(memfs_node_replace_security(child_file, sd_b, sd_b_size) == MEMFS_OK);
	CHECK(memfs_node_get_security(child_file) != shared);
	CHECK(memfs_node_get_security(child_file) != NULL);
	current = shared->ref_count;
	CHECK(current == before - 1);

	before = shared->ref_count;
	CHECK(memfs_node_replace_security(child_file, sd_a, sd_a_size) == MEMFS_OK);
	CHECK(memfs_node_get_security(child_file) != shared);
	CHECK(memfs_node_get_security(child_file) != NULL);
	current = shared->ref_count;
	CHECK(current == before);

	for (i = 0; i < INHERIT_FILES; i++) {
		if (inherit_nodes[i]) {
			CHECK(memfs_node_unlink(inherit_nodes[i]) == MEMFS_OK);
			memfs_node_close(inherit_nodes[i]);
			inherit_nodes[i] = NULL;
		}
	}
	current = shared->ref_count;
	CHECK(current == before - INHERIT_FILES);

	CHECK(memfs_node_create(fs, fs->root, L"churn", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &churn_dir) == MEMFS_OK);
	CHECK(churn_dir != NULL);
	if (churn_dir == NULL)
		goto cleanup;

	CHECK(memfs_node_get_security(churn_dir) == shared);

	for (round = 0; round < CHURN_ROUNDS; round++) {
		before = shared->ref_count;

		for (i = 0; i < CHURN_FILES; i++) {
			wchar_t name[32];

			swprintf_s(name, _countof(name), L"churn-%02u-%02u", round, i);
			CHECK(memfs_node_create(fs, churn_dir, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &churn_nodes[i]) ==
				  MEMFS_OK);
			if (churn_nodes[i])
				CHECK(memfs_node_get_security(churn_nodes[i]) == shared);
		}
		current = shared->ref_count;
		CHECK(current == before + CHURN_FILES);

		for (i = 0; i < CHURN_FILES / 2U; i++) {
			if (churn_nodes[i]) {
				CHECK(memfs_node_unlink(churn_nodes[i]) == MEMFS_OK);
				memfs_node_close(churn_nodes[i]);
				churn_nodes[i] = NULL;
			}
		}
		current = shared->ref_count;
		CHECK(current == before + (LONG)(CHURN_FILES / 2U));

		for (i = CHURN_FILES / 2U; i < CHURN_FILES; i++) {
			if (churn_nodes[i]) {
				memfs_node_open(churn_nodes[i]);
				CHECK(memfs_node_unlink(churn_nodes[i]) == MEMFS_OK);
			}
		}
		current = shared->ref_count;
		CHECK(current == before + (LONG)(CHURN_FILES / 2U));

		for (i = CHURN_FILES / 2U; i < CHURN_FILES; i++) {
			if (churn_nodes[i]) {
				memfs_node_close(churn_nodes[i]);
				memfs_node_close(churn_nodes[i]);
				churn_nodes[i] = NULL;
			}
		}
		current = shared->ref_count;
		CHECK(current == before);
	}

	CHECK(memfs_node_unlink(churn_dir) == MEMFS_OK);
	memfs_node_close(churn_dir);
	churn_dir = NULL;

	CHECK(memfs_node_unlink(child_file) == MEMFS_OK);
	memfs_node_close(child_file);
	child_file = NULL;

	CHECK(memfs_node_unlink(sub) == MEMFS_OK);
	memfs_node_close(sub);
	sub = NULL;

	CHECK(memfs_node_unlink(dir) == MEMFS_OK);
	memfs_node_close(dir);
	dir = NULL;

	if (sd_a)
		LocalFree(sd_a);
	if (sd_b)
		LocalFree(sd_b);

	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	current = shared->ref_count;
	CHECK(current >= 1);

	memfs_destroy(fs);
	return;

cleanup:
	for (i = 0; i < INHERIT_FILES; i++) {
		if (inherit_nodes[i]) {
			memfs_node_unlink(inherit_nodes[i]);
			memfs_node_close(inherit_nodes[i]);
			inherit_nodes[i] = NULL;
		}
	}
	for (i = 0; i < CHURN_FILES; i++) {
		if (churn_nodes[i]) {
			memfs_node_unlink(churn_nodes[i]);
			memfs_node_close(churn_nodes[i]);
			churn_nodes[i] = NULL;
		}
	}
	if (churn_dir) {
		memfs_node_unlink(churn_dir);
		memfs_node_close(churn_dir);
		churn_dir = NULL;
	}
	if (child_file) {
		memfs_node_unlink(child_file);
		memfs_node_close(child_file);
		child_file = NULL;
	}
	if (sub) {
		memfs_node_unlink(sub);
		memfs_node_close(sub);
		sub = NULL;
	}
	if (dir) {
		memfs_node_unlink(dir);
		memfs_node_close(dir);
		dir = NULL;
	}
	if (sd_a)
		LocalFree(sd_a);
	if (sd_b)
		LocalFree(sd_b);
	memfs_destroy(fs);
}

typedef struct ConcurrentIoArg {
	MemfsNode* file;
	uint8_t value;
	uint32_t blocks;
	uint32_t failures;
} ConcurrentIoArg;

static DWORD WINAPI concurrent_io_thread(void* parameter) {
	ConcurrentIoArg* arg = parameter;
	uint8_t block[4096];
	uint8_t verify[4096];
	uint32_t transferred;
	uint32_t i;

	memset(block, arg->value, sizeof(block));

	for (i = 0; i < arg->blocks; i++) {
		if (memfs_node_write(arg->file, block, 0, sizeof(block), true, false, &transferred) != MEMFS_OK ||
			transferred != sizeof(block)) {
			arg->failures++;
			return 0;
		}
	}

	memset(verify, 0, sizeof(verify));
	if (memfs_node_read(arg->file, verify, (uint64_t)(arg->blocks - 1U) * sizeof(block), sizeof(verify),
						&transferred) != MEMFS_OK ||
		transferred != sizeof(verify)) {
		arg->failures++;
		return 0;
	}

	for (i = 0; i < sizeof(verify); i++) {
		if (verify[i] != arg->value) {
			arg->failures++;
			break;
		}
	}

	return 0;
}

static void test_concurrent_files(void) {
	enum { THREADS = 8, BLOCKS = 128 };
	MemfsOptions options = {0};
	Memfs* fs = NULL;
	MemfsNode* files[THREADS] = {0};
	ConcurrentIoArg args[THREADS] = {0};
	HANDLE threads[THREADS] = {0};
	uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint32_t i;
	uint32_t created = 0;
	uint32_t started = 0;
	uint64_t expected_size = (uint64_t)BLOCKS * MEMFS_PAGE_SIZE;

	printf("== concurrent files / accounting ==\n");

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(0x31U + i * 3U);

	options.capacity = 64ULL * 1024ULL * 1024ULL;
	options.volume_label = L"PAR";
	options.compression_enabled = true;
	options.compression_level = 1;
	options.encryption_enabled = true;
	options.encryption_key = key;
	options.encryption_key_size = sizeof(key);

	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	for (i = 0; i < THREADS; i++) {
		wchar_t name[32];

		swprintf_s(name, _countof(name), L"thread-%u.bin", i);
		CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &files[i]) == MEMFS_OK);
		if (files[i] == NULL)
			break;
		++created;

		args[i].file = files[i];
		args[i].value = (uint8_t)(i + 1U);
		args[i].blocks = BLOCKS;

		threads[i] = create_test_thread(concurrent_io_thread, &args[i]);
		CHECK(threads[i] != NULL);
		if (threads[i] == NULL)
			break;
		++started;
	}

	join_test_threads(threads, started, "concurrent files");
	CHECK(started == THREADS);

	for (i = 0; i < started; i++) {
		CloseHandle(threads[i]);

		CHECK(args[i].failures == 0);
		CHECK(files[i]->file_size == expected_size);
		CHECK(files[i]->allocation_size == expected_size);
	}

	if (started == THREADS) {
		CHECK(memfs_free_bytes(fs) == options.capacity - (uint64_t)THREADS * expected_size);
		CHECK(memfs_resident_bytes(fs) < (uint64_t)THREADS * expected_size / 4U);
	}

	for (i = 0; i < created; i++) {
		CHECK(memfs_node_unlink(files[i]) == MEMFS_OK);
		memfs_node_close(files[i]);
	}

	CHECK(memfs_free_bytes(fs) == options.capacity);
	CHECK(memfs_resident_bytes(fs) == 0);
	memfs_destroy(fs);
}

static void test_allocator_reclaim(void) {
	enum { FILES = 20000 };
	Memfs* fs = NULL;
	MemfsNode* node;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats before_delete;
	MemfsAllocatorStats after_delete;
	uint32_t i;
	wchar_t name[32];

	printf("== allocator reclaim ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"ALLOC", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	memfs_allocator_get_stats(&fs->allocator, &baseline);

	for (i = 0; i < FILES; i++) {
		swprintf_s(name, _countof(name), L"f%05u", i);
		CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_OK);
		memfs_node_close(node);
	}

	memfs_allocator_get_stats(&fs->allocator, &before_delete);
	CHECK(before_delete.live_objects > FILES);
	CHECK(before_delete.reserved_bytes > 1024 * 1024ULL);

	for (i = 0; i < FILES; i++) {
		swprintf_s(name, _countof(name), L"f%05u", i);
		node = memfs_dir_lookup(fs->root, name);
		CHECK(node != NULL);
		if (node)
			CHECK(memfs_node_unlink(node) == MEMFS_OK);
	}

	(void)memfs_allocator_scavenge(&fs->allocator);
	memfs_allocator_get_stats(&fs->allocator, &after_delete);
	CHECK(after_delete.live_objects == baseline.live_objects);
	CHECK(after_delete.reserved_bytes == baseline.reserved_bytes);
	CHECK(after_delete.dedicated_count == baseline.dedicated_count);
	CHECK(after_delete.reserved_bytes < 1024 * 1024ULL);

	memfs_destroy(fs);
}


static void test_allocator_unified_pool_layout(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats after_node;
	MemfsAllocatorStats after_name;
	MemfsAllocatorStats after_generic;
	MemfsAllocatorStats after_area;
	MemfsAllocatorStats after;
	void* node;
	void* name;
	void* generic;
	void* group;
	size_t zero_index;
	void* area;

	printf("== allocator unified pool layout ==\n");

	CHECK(memfs_allocator_init(&allocator, 96U, 96U, 96U));
	memfs_allocator_get_stats(&allocator, &baseline);
	CHECK(baseline.slab_count == 0U);

	node = memfs_allocator_alloc_node(&allocator);
	CHECK(node != NULL);
	memfs_allocator_get_stats(&allocator, &after_node);
	CHECK(after_node.slab_count == 1U);

	name = memfs_allocator_alloc_name(&allocator, 96U);
	CHECK(name != NULL);
	memfs_allocator_get_stats(&allocator, &after_name);
	CHECK(after_name.slab_count == after_node.slab_count);

	generic = memfs_allocator_alloc(&allocator, 96U);
	CHECK(generic != NULL);
	memfs_allocator_get_stats(&allocator, &after_generic);
	CHECK(after_generic.slab_count == after_node.slab_count);
	CHECK(after_generic.dedicated_count == 0U);

	/*
	 * name allocations deliberately use the uninitialized fast path. Reuse the
	 * just-freed name slot through a typed allocation and prove the typed API
	 * still restores its zero-initialization contract.
	 */
	if (name != NULL) {
		memset(name, 0xA5, 96U);
		memfs_allocator_free_name(&allocator, name, 96U);
		name = NULL;
	}
	group = memfs_allocator_alloc_page_group(&allocator);
	CHECK(group != NULL);
	if (group != NULL) {
		for (zero_index = 0; zero_index < 96U; ++zero_index)
			CHECK(((const uint8_t*)group)[zero_index] == 0U);
	}

	area = memfs_allocator_alloc(&allocator, MEMFS_ALLOC_AREA_THRESHOLD + 1U);
	CHECK(area != NULL);
	memfs_allocator_get_stats(&allocator, &after_area);
	CHECK(after_area.slab_count == after_node.slab_count);
	CHECK(after_area.dedicated_count == 1U);
	CHECK(after_area.dedicated_live_bytes >= MEMFS_ALLOC_AREA_THRESHOLD + 1U);

	memfs_allocator_free(&allocator, area, MEMFS_ALLOC_AREA_THRESHOLD + 1U);
	memfs_allocator_free(&allocator, generic, 96U);
	if (group != NULL)
		memfs_allocator_free_page_group(&allocator, group);
	if (name != NULL)
		memfs_allocator_free_name(&allocator, name, 96U);
	memfs_allocator_free_node(&allocator, node);

	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == baseline.live_objects);
	CHECK(after.slab_count == 0U);
	CHECK(after.dedicated_count == 0U);
	CHECK(after.area_cached_count >= 1U);
	CHECK(after.area_cached_bytes > 0U);
	CHECK(memfs_allocator_scavenge(&allocator) > 0U);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.area_cached_count == 0U);
	CHECK(after.area_cached_bytes == 0U);
	CHECK(after.reserved_bytes == baseline.reserved_bytes);

#if !defined(NDEBUG)
	{
		static const struct {
			size_t request;
			size_t expected_class;
			size_t expected_slab;
		} cases[] = {
			{1U, 8U, 4U * 1024U},
			{8U, 8U, 4U * 1024U},
			{9U, 16U, 4U * 1024U},
			{17U, 24U, 4U * 1024U},
			{25U, 32U, 4U * 1024U},
			{33U, 48U, 4U * 1024U},
			{49U, 64U, 4U * 1024U},
			{65U, 96U, 4U * 1024U},
			{97U, 128U, 4U * 1024U},
			{129U, 192U, 8U * 1024U},
			{193U, 256U, 8U * 1024U},
			{257U, 384U, 16U * 1024U},
			{385U, 512U, 16U * 1024U},
			{513U, 768U, 32U * 1024U},
			{769U, 1024U, 32U * 1024U},
			{1025U, 1536U, 64U * 1024U},
			{1537U, 2048U, 64U * 1024U},
			{2049U, 3072U, 64U * 1024U},
			{3073U, 4096U, 64U * 1024U},
			{MEMFS_PAGE_SIZE, 4096U, 64U * 1024U},
			{sizeof(MemfsPage) + MEMFS_PAGE_SIZE, 8192U, 64U * 1024U},
			{4097U, 8192U, 64U * 1024U},
			{8192U, 8192U, 64U * 1024U},
		};
		size_t i;

		{
			size_t node_class = 0;
			size_t node_slab = 0;

			CHECK(sizeof(MemfsNode) == 128U);
			CHECK(memfs_allocator_test_class_layout(
					  sizeof(MemfsNode), &node_class, &node_slab));
			CHECK(node_class == 128U);
			CHECK(node_slab == 4U * 1024U);
		}

		for (i = 0; i < _countof(cases); i++) {
			size_t class_bytes = 0;
			size_t slab_bytes = 0;
			CHECK(memfs_allocator_test_class_layout(cases[i].request, &class_bytes, &slab_bytes));
			CHECK(class_bytes == cases[i].expected_class);
			CHECK(slab_bytes == cases[i].expected_slab);
		}

		{
			size_t class_bytes = 123U;
			size_t slab_bytes = 456U;
			CHECK(!memfs_allocator_test_class_layout(MEMFS_ALLOC_AREA_THRESHOLD + 1U,
												 &class_bytes, &slab_bytes));
			CHECK(class_bytes == 0U);
			CHECK(slab_bytes == 0U);
		}
	}
#endif

	memfs_allocator_destroy(&allocator);
}



static void test_allocator_area_cache_reuse(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats cached;
	MemfsAllocatorStats active;
	MemfsAllocatorStats after;
	uint8_t* first;
	uint8_t* second;
	size_t i;
	const size_t bytes = 16U * 1024U;

	printf("== allocator area cache reuse ==\n");

	CHECK(memfs_allocator_init(&allocator, 64U, 64U, 64U));
	memfs_allocator_get_stats(&allocator, &baseline);

	first = memfs_allocator_alloc(&allocator, bytes);
	CHECK(first != NULL);
	if (first == NULL) {
		memfs_allocator_destroy(&allocator);
		return;
	}
	memset(first, 0xA5, bytes);
	memfs_allocator_free(&allocator, first, bytes);

	memfs_allocator_get_stats(&allocator, &cached);
	CHECK(cached.live_objects == baseline.live_objects);
	CHECK(cached.dedicated_count == 0U);
	CHECK(cached.area_cached_count == 1U);
	CHECK(cached.area_cached_bytes > 0U);
	CHECK(cached.reserved_bytes > baseline.reserved_bytes);

	second = memfs_allocator_alloc_zero(&allocator, bytes);
	CHECK(second != NULL);
	CHECK(second == first);
	if (second != NULL) {
		for (i = 0; i < bytes; i++)
			CHECK(second[i] == 0U);
	}

	memfs_allocator_get_stats(&allocator, &active);
	CHECK(active.dedicated_count == 1U);
	CHECK(active.area_cached_count == 0U);

	if (second != NULL)
		memfs_allocator_free(&allocator, second, bytes);
	CHECK(memfs_allocator_scavenge(&allocator) > 0U);

	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == baseline.live_objects);
	CHECK(after.dedicated_count == 0U);
	CHECK(after.area_cached_count == 0U);
	CHECK(after.area_cached_bytes == 0U);
	CHECK(after.reserved_bytes == baseline.reserved_bytes);
	CHECK(after.committed_bytes == baseline.committed_bytes);

	memfs_allocator_destroy(&allocator);
}

static void test_allocator_area_cache_size_policy(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats small_cached;
	MemfsAllocatorStats large_cached;
	MemfsAllocatorStats after;
	void* small_a = NULL;
	void* small_b = NULL;
	void* large_a = NULL;
	void* large_b = NULL;
	const size_t small_bytes = 16U * 1024U;
	const size_t large_bytes = 64U * 1024U;

	printf("== allocator area cache size policy ==\n");
	memset(&allocator, 0, sizeof(allocator));
	CHECK(memfs_allocator_init(&allocator, 64U, 64U, 64U));
	if (allocator.state == NULL)
		return;

	memfs_allocator_get_stats(&allocator, &baseline);

	small_a = memfs_allocator_alloc_uninit(&allocator, small_bytes);
	small_b = memfs_allocator_alloc_uninit(&allocator, small_bytes);
	CHECK(small_a != NULL);
	CHECK(small_b != NULL);
	if (small_a == NULL || small_b == NULL)
		goto cleanup;

	memfs_allocator_free(&allocator, small_a, small_bytes);
	small_a = NULL;
	memfs_allocator_free(&allocator, small_b, small_bytes);
	small_b = NULL;
	memfs_allocator_get_stats(&allocator, &small_cached);
	CHECK(small_cached.area_cached_count == 2U);
	CHECK(small_cached.area_cached_bytes > 0U);
	CHECK(memfs_allocator_scavenge(&allocator) > 0U);

	large_a = memfs_allocator_alloc_uninit(&allocator, large_bytes);
	large_b = memfs_allocator_alloc_uninit(&allocator, large_bytes);
	CHECK(large_a != NULL);
	CHECK(large_b != NULL);
	if (large_a == NULL || large_b == NULL)
		goto cleanup;

	memfs_allocator_free(&allocator, large_a, large_bytes);
	large_a = NULL;
	memfs_allocator_free(&allocator, large_b, large_bytes);
	large_b = NULL;
	memfs_allocator_get_stats(&allocator, &large_cached);
	CHECK(large_cached.area_cached_count == 1U);
	CHECK(large_cached.area_cached_bytes > 0U);
	CHECK(large_cached.area_cached_bytes < large_bytes * 2U);

cleanup:
	if (small_a != NULL)
		memfs_allocator_free(&allocator, small_a, small_bytes);
	if (small_b != NULL)
		memfs_allocator_free(&allocator, small_b, small_bytes);
	if (large_a != NULL)
		memfs_allocator_free(&allocator, large_a, large_bytes);
	if (large_b != NULL)
		memfs_allocator_free(&allocator, large_b, large_bytes);

	(void)memfs_allocator_scavenge(&allocator);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == baseline.live_objects);
	CHECK(after.area_cached_count == 0U);
	CHECK(after.area_cached_bytes == 0U);
	CHECK(after.reserved_bytes == baseline.reserved_bytes);
	CHECK(after.committed_bytes == baseline.committed_bytes);
	memfs_allocator_destroy(&allocator);
}

static void test_allocator_name_pool_boundaries(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats before;
	MemfsAllocatorStats after;
	void* max_name;
	void* exact_512;
	void* too_large;
	void* zero;
	uint32_t i;

	printf("== allocator name pool boundaries ==\n");

	CHECK(memfs_allocator_init(&allocator, 64, 64, 64));
	memfs_allocator_get_stats(&allocator, &before);
	CHECK(before.reserved_bytes > 0);
	CHECK(before.live_objects == 0);

	max_name = memfs_allocator_alloc_name(&allocator, (MEMFS_MAX_NAME + 1U) * sizeof(wchar_t));
	CHECK(max_name != NULL);
	if (max_name) {
		memset(max_name, 0x5a, (MEMFS_MAX_NAME + 1U) * sizeof(wchar_t));
		memfs_allocator_get_stats(&allocator, &after);
		CHECK(after.live_objects == before.live_objects + 1);
		CHECK(after.reserved_bytes > before.reserved_bytes);
		memfs_allocator_free_name(&allocator, max_name, (MEMFS_MAX_NAME + 1U) * sizeof(wchar_t));
	}

	exact_512 = memfs_allocator_alloc_name(&allocator, 512);
	CHECK(exact_512 != NULL);
	if (exact_512) {
		memset(exact_512, 0x6b, 512);
		memfs_allocator_free_name(&allocator, exact_512, 512);
	}

	too_large = memfs_allocator_alloc_name(&allocator, 513);
	CHECK(too_large != NULL);
	if (too_large) {
		memset(too_large, 0x7c, 513);
		memfs_allocator_free_name(&allocator, too_large, 513);
	}
	zero = memfs_allocator_alloc_name(&allocator, 0);
	CHECK(zero == NULL);
	CHECK(memfs_allocator_alloc_name(NULL, 8) == NULL);
	memfs_allocator_free_name(NULL, exact_512, 8);
	memfs_allocator_free_name(&allocator, NULL, 8);

	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == before.live_objects);
	CHECK(after.reserved_bytes == before.reserved_bytes);
	memfs_allocator_destroy(&allocator);

	for (i = 0; i < 4; i++) {
		CHECK(memfs_allocator_init(&allocator, 64, 64, 64));
		memfs_allocator_destroy(&allocator);
	}
}


#if !defined(NDEBUG)
static void test_allocator_alignment_contract(void) {
	enum { ALLOCS_PER_CLASS = 4 };
	MemfsAllocator allocator;
	void* blocks[ALLOCS_PER_CLASS] = {0};
	void* area = NULL;
	uint32_t class_index;
	uint32_t i;
	size_t class_size;

	printf("== allocator alignment contract ==\n");
	memset(&allocator, 0, sizeof(allocator));

	CHECK(MEMFS_ALLOC_MIN_ALIGNMENT == 8U);
	CHECK((MEMFS_ALLOC_MIN_ALIGNMENT &
		   (MEMFS_ALLOC_MIN_ALIGNMENT - 1U)) == 0U);
	CHECK(memfs_allocator_init(&allocator, 128U, 128U, 1024U));
	if (allocator.state == NULL)
		return;

	for (class_index = 0;
		 class_index < MEMFS_ALLOC_CLASS_COUNT;
		 ++class_index) {
		class_size = memfs_allocator_test_class_size(class_index);
		CHECK(class_size != 0U);
		CHECK((class_size % MEMFS_ALLOC_MIN_ALIGNMENT) == 0U);

		for (i = 0; i < ALLOCS_PER_CLASS; ++i) {
			blocks[i] = memfs_allocator_alloc(&allocator, class_size);
			CHECK(blocks[i] != NULL);
			if (blocks[i] != NULL) {
				CHECK(((uintptr_t)blocks[i] &
					   (MEMFS_ALLOC_MIN_ALIGNMENT - 1U)) == 0U);
			}
		}

		for (i = 0; i < ALLOCS_PER_CLASS; ++i) {
			if (blocks[i] != NULL) {
				memfs_allocator_free(&allocator, blocks[i], class_size);
				blocks[i] = NULL;
			}
		}
	}

	CHECK(memfs_allocator_test_class_size(MEMFS_ALLOC_CLASS_COUNT) == 0U);

	area = memfs_allocator_alloc(
		&allocator, (size_t)MEMFS_ALLOC_AREA_THRESHOLD + 1U);
	CHECK(area != NULL);
	if (area != NULL) {
		CHECK(((uintptr_t)area &
			   (MEMFS_ALLOC_MIN_ALIGNMENT - 1U)) == 0U);
		memfs_allocator_free(
			&allocator, area, (size_t)MEMFS_ALLOC_AREA_THRESHOLD + 1U);
	}

	memfs_allocator_destroy(&allocator);
}
#endif


static void test_allocator_generic_size_classes(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats before;
	MemfsAllocatorStats during;
	MemfsAllocatorStats after;
	uint8_t* same;
	uint8_t* grown;
	uint8_t* dedicated;
	uint8_t* zeroed;
	uint8_t* failed;
	size_t i;
	static const size_t sizes[] = {
		1U, 8U, 9U, 32U, 33U, 512U, 513U, 4096U, 32768U
	};
	void* blocks[_countof(sizes)] = {0};

	printf("== allocator generic size classes ==\n");

	CHECK(memfs_allocator_init(&allocator, 64, 64, 64));
	memfs_allocator_get_stats(&allocator, &before);

	for (i = 0; i < _countof(sizes); i++) {
		blocks[i] = memfs_allocator_alloc(&allocator, sizes[i]);
		CHECK(blocks[i] != NULL);
		if (blocks[i])
			memset(blocks[i], (int)(0x20U + i), sizes[i]);
	}

	zeroed = memfs_allocator_alloc_zero(&allocator, 257U);
	CHECK(zeroed != NULL);
	if (zeroed) {
		for (i = 0; i < 257U; i++)
			CHECK(zeroed[i] == 0);
		memfs_allocator_free(&allocator, zeroed, 257U);
	}

	same = memfs_allocator_alloc(&allocator, 100U);
	CHECK(same != NULL);
	if (same) {
		memset(same, 0x5a, 100U);
		grown = memfs_allocator_realloc(&allocator, same, 100U, 120U);
		CHECK(grown == same);
		if (grown) {
			for (i = 0; i < 100U; i++)
				CHECK(grown[i] == 0x5a);
			same = grown;
		}

		grown = memfs_allocator_realloc(&allocator, same, 120U, 300U);
		CHECK(grown != NULL);
		if (grown) {
			for (i = 0; i < 100U; i++)
				CHECK(grown[i] == 0x5a);
			same = grown;
		}

		dedicated = memfs_allocator_realloc(&allocator, same, 300U, 65536U);
		CHECK(dedicated != NULL);
		if (dedicated) {
			for (i = 0; i < 100U; i++)
				CHECK(dedicated[i] == 0x5a);
			same = dedicated;
		}

		grown = memfs_allocator_realloc(&allocator, same, 65536U, 64U);
		CHECK(grown != NULL);
		if (grown) {
			for (i = 0; i < 64U; i++)
				CHECK(grown[i] == 0x5a);
			same = grown;
		}

		failed = memfs_allocator_realloc(&allocator, same, 64U, SIZE_MAX);
		CHECK(failed == NULL);
		for (i = 0; i < 64U; i++)
			CHECK(same[i] == 0x5a);
		memfs_allocator_free(&allocator, same, 64U);
	}

	dedicated = memfs_allocator_alloc(&allocator, 65536U);
	CHECK(dedicated != NULL);
	memfs_allocator_get_stats(&allocator, &during);
	CHECK(during.dedicated_count >= 1U);
	CHECK(during.dedicated_live_bytes >= 65536U);
	CHECK(during.dedicated_reserved_bytes >= during.dedicated_live_bytes);
	CHECK(during.reserved_bytes >= during.dedicated_reserved_bytes);
	if (dedicated)
		memfs_allocator_free(&allocator, dedicated, 65536U);

	for (i = 0; i < _countof(sizes); i++) {
		if (blocks[i])
			memfs_allocator_free(&allocator, blocks[i], sizes[i]);
	}

	(void)memfs_allocator_scavenge(&allocator);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == before.live_objects);
	CHECK(after.dedicated_count == 0U);
	CHECK(after.dedicated_live_bytes == 0U);
	CHECK(after.dedicated_reserved_bytes == 0U);
	CHECK(after.reserved_bytes == before.reserved_bytes);

	memfs_allocator_destroy(&allocator);
}


typedef struct AllocatorThreadArg {
	MemfsAllocator* allocator;
	uint32_t thread_id;
	uint32_t failures;
} AllocatorThreadArg;

static DWORD WINAPI allocator_generic_thread(void* parameter) {
	AllocatorThreadArg* arg = parameter;
	static const size_t sizes[] = {8U, 33U, 513U, 4096U, 20000U, 40000U};
	uint32_t round;

	for (round = 0; round < 1500U; round++) {
		size_t size = sizes[(round + arg->thread_id) % _countof(sizes)];
		size_t next_size = size > 32768U ? 128U : size * 2U + 1U;
		size_t verify = size < next_size ? size : next_size;
		uint8_t value = (uint8_t)(0x31U + arg->thread_id);
		uint8_t* ptr = memfs_allocator_alloc(arg->allocator, size);
		uint8_t* next;
		size_t i;

		if (ptr == NULL) {
			arg->failures++;
			continue;
		}

		verify = verify < 64U ? verify : 64U;
		memset(ptr, value, verify);
		next = memfs_allocator_realloc(arg->allocator, ptr, size, next_size);
		if (next == NULL) {
			arg->failures++;
			memfs_allocator_free(arg->allocator, ptr, size);
			continue;
		}

		for (i = 0; i < verify; i++) {
			if (next[i] != value) {
				arg->failures++;
				break;
			}
		}
		memfs_allocator_free(arg->allocator, next, next_size);
	}

	return 0;
}

#if !defined(NDEBUG)
static void test_allocator_cross_shard_reuse(void) {
	enum { OBJECTS = 96, REFILL = OBJECTS / 2 };
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats full;
	MemfsAllocatorStats partial;
	MemfsAllocatorStats refilled;
	MemfsAllocatorStats after;
	void* blocks[OBJECTS] = {0};
	void* refill[REFILL] = {0};
	uint32_t i;

	printf("== allocator cross-shard reuse ==\n");
	memset(&allocator, 0, sizeof(allocator));
	CHECK(memfs_allocator_test_shard_count() >= 2U);
	CHECK(memfs_allocator_init(&allocator, 64U, 64U, 64U));
	if (allocator.state == NULL)
		return;

	memfs_allocator_get_stats(&allocator, &baseline);

	/* Fill several 512B slabs from shard 0. */
	for (i = 0; i < OBJECTS; ++i) {
		blocks[i] = memfs_allocator_test_alloc_from_shard(
			&allocator, 512U, 0U);
		CHECK(blocks[i] != NULL);
		if (blocks[i] == NULL)
			goto cleanup;
		memset(blocks[i], (int)(0x20U + (i & 0x3fU)), 16U);
	}

	memfs_allocator_get_stats(&allocator, &full);
	CHECK(full.slab_count >= 3U);

	/*
	 * Leave every slab partially free. No slab should become completely idle,
	 * so this is exactly the capacity that used to be stranded in shard 0.
	 */
	for (i = 0; i < OBJECTS; i += 2U) {
		memfs_allocator_free(&allocator, blocks[i], 512U);
		blocks[i] = NULL;
	}
	memfs_allocator_get_stats(&allocator, &partial);
	CHECK(partial.slab_count == full.slab_count);
	CHECK(partial.reserved_bytes == full.reserved_bytes);
	CHECK(partial.committed_bytes == full.committed_bytes);

	/*
	 * Force a different home shard. The allocator must consume shard 0's free
	 * objects before committing any additional slab.
	 */
	for (i = 0; i < REFILL; ++i) {
		refill[i] = memfs_allocator_test_alloc_from_shard(
			&allocator, 512U, 1U);
		CHECK(refill[i] != NULL);
		if (refill[i] == NULL)
			goto cleanup;
		memset(refill[i], (int)(0x80U + (i & 0x3fU)), 16U);
	}

	memfs_allocator_get_stats(&allocator, &refilled);
	CHECK(refilled.slab_count == full.slab_count);
	CHECK(refilled.reserved_bytes == full.reserved_bytes);
	CHECK(refilled.committed_bytes == full.committed_bytes);
	CHECK(refilled.live_objects == full.live_objects);
	CHECK(refilled.live_bytes == full.live_bytes);

cleanup:
	for (i = 0; i < OBJECTS; ++i) {
		if (blocks[i] != NULL) {
			memfs_allocator_free(&allocator, blocks[i], 512U);
			blocks[i] = NULL;
		}
	}
	for (i = 0; i < REFILL; ++i) {
		if (refill[i] != NULL) {
			memfs_allocator_free(&allocator, refill[i], 512U);
			refill[i] = NULL;
		}
	}

	(void)memfs_allocator_scavenge(&allocator);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == baseline.live_objects);
	CHECK(after.live_bytes == baseline.live_bytes);
	CHECK(after.slab_count == baseline.slab_count);
	CHECK(after.reserved_bytes == baseline.reserved_bytes);
	CHECK(after.committed_bytes == baseline.committed_bytes);
	memfs_allocator_destroy(&allocator);
}
#endif

static void test_allocator_generic_concurrency(void) {
	enum { THREADS = 4 };
	MemfsAllocator allocator;
	MemfsAllocatorStats before;
	MemfsAllocatorStats after;
	AllocatorThreadArg args[THREADS] = {0};
	HANDLE threads[THREADS] = {0};
	uint32_t i;
	uint32_t started = 0;

	printf("== allocator generic concurrency ==\n");
	CHECK(memfs_allocator_init(&allocator, 64, 64, 64));
	if (allocator.state == NULL)
		return;
	memfs_allocator_get_stats(&allocator, &before);

	for (i = 0; i < THREADS; i++) {
		args[i].allocator = &allocator;
		args[i].thread_id = i;
		threads[i] = create_test_thread(allocator_generic_thread, &args[i]);
		CHECK(threads[i] != NULL);
		if (threads[i] == NULL)
			break;
		++started;
	}

	join_test_threads(threads, started, "allocator concurrency");
	CHECK(started == THREADS);
	for (i = 0; i < started; i++) {
		CloseHandle(threads[i]);
		CHECK(args[i].failures == 0);
	}

	(void)memfs_allocator_scavenge(&allocator);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(after.live_objects == before.live_objects);
	CHECK(after.dedicated_count == 0U);
	CHECK(after.reserved_bytes == before.reserved_bytes);
	memfs_allocator_destroy(&allocator);
}

static void test_allocator_stress(void) {
	enum { FILES = 4096, ROUNDS = 8 };
	Memfs* fs = NULL;
	MemfsNode* node;
	MemfsAllocatorStats before;
	MemfsAllocatorStats after;
	uint32_t round;
	uint32_t i;
	wchar_t name[32];

	printf("== allocator stress ==\n");

	CHECK(memfs_create(64ULL * 1024ULL * 1024ULL, L"STRESS", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	for (round = 0; round < ROUNDS; round++) {
		for (i = 0; i < FILES; i++) {
			swprintf_s(name, _countof(name), L"stress-%03u-%04u", round, i);
			CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_OK);
			if (node) {
				CHECK(memfs_node_unlink(node) == MEMFS_OK);
				memfs_node_close(node);
			}
		}
	}

	memfs_allocator_get_stats(&fs->allocator, &before);
	CHECK(before.live_objects > 0);
	CHECK(before.reserved_bytes > 0);

	for (i = 0; i < FILES; i++) {
		swprintf_s(name, _countof(name), L"stress-%03u-%04u", ROUNDS - 1U, i);
		node = memfs_dir_lookup(fs->root, name);
		CHECK(node == NULL);
	}

	memfs_allocator_get_stats(&fs->allocator, &after);
	CHECK(after.live_objects <= before.live_objects);
	CHECK(after.reserved_bytes <= before.reserved_bytes);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	memfs_destroy(fs);
}

static void test_open_delete_lifetime(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t data = 0x42;
	uint8_t out = 0;
	uint32_t transferred;
	uint32_t i;

	printf("== open/delete lifetime ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"LIFE", &fs) == MEMFS_OK);

	for (i = 0; i < 1000; i++) {
		CHECK(memfs_node_create(fs, fs->root, L"held.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
		memfs_node_open(file); // simulate an additional WinFsp handle
		CHECK(memfs_node_write(file, &data, 0, 1, false, false, &transferred) == MEMFS_OK);
		CHECK(transferred == 1);
		CHECK(memfs_node_unlink(file) == MEMFS_OK);
		CHECK(fs->orphan_head == file);
		CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
		CHECK(out == data);

		memfs_node_close(file); // close extra handle
		CHECK(fs->orphan_head == file);
		memfs_node_close(file); // close create handle, final free
		CHECK(fs->orphan_head == NULL);
	}

	memfs_destroy(fs);
}



static void test_rename_delete_lifetime(void) {
	Memfs* fs = NULL;
	MemfsNode* dir;
	MemfsNode* file;
	MemfsNode* found;
	uint8_t data = 0x77;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== rename/delete lifetime ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"RLIFE", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"old.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	memfs_node_open(file);
	CHECK(memfs_node_write(file, &data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	CHECK(memfs_node_rename(file, fs->root, L"new.bin", false) == MEMFS_OK);
	CHECK(memfs_lookup_path(fs, L"\\dir\\old.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\new.bin", &found) == MEMFS_OK);
	CHECK(found == file);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	CHECK(fs->orphan_head == file);
	CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == data);
	CHECK(memfs_node_write(file, &data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	memfs_node_close(file);
	CHECK(fs->orphan_head == file);
	memfs_node_close(file);
	CHECK(fs->orphan_head == NULL);

	CHECK(memfs_node_unlink(dir) == MEMFS_OK);
	memfs_node_close(dir);
	memfs_destroy(fs);
}
static bool test_orphan_contains(const Memfs* fs, const MemfsNode* target) {
	const MemfsNode* node;

	for (node = fs ? fs->orphan_head : NULL; node; node = node->tree_right) {
		if (node == target)
			return true;
	}

	return false;
}

static void test_derived_index_number(void) {
	Memfs* fs = NULL;
	MemfsNode* a = NULL;
	MemfsNode* b = NULL;
	uint64_t root_id;
	uint64_t a_id;
	uint64_t b_id;

	printf("== derived stable index number ==\n");
	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"FILEID", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		return;

	CHECK(memfs_node_create(fs, fs->root, L"a.bin", false,
						   FILE_ATTRIBUTE_NORMAL, NULL, 0, &a) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"b.bin", false,
						   FILE_ATTRIBUTE_NORMAL, NULL, 0, &b) == MEMFS_OK);
	CHECK(a != NULL && b != NULL);
	if (a != NULL && b != NULL) {
		root_id = memfs_node_index_number(fs->root);
		a_id = memfs_node_index_number(a);
		b_id = memfs_node_index_number(b);

		CHECK(root_id != a_id);
		CHECK(root_id != b_id);
		CHECK(a_id != b_id);
		CHECK(memfs_node_index_number(a) == a_id);

		CHECK(memfs_node_rename(a, fs->root, L"renamed-a.bin", false) == MEMFS_OK);
		CHECK(memfs_node_index_number(a) == a_id);

		memfs_node_open(a);
		CHECK(memfs_node_unlink(a) == MEMFS_OK);
		CHECK(memfs_node_index_number(a) == a_id);
		memfs_node_close(a);
		memfs_node_close(a);

		CHECK(memfs_node_unlink(b) == MEMFS_OK);
		memfs_node_close(b);
	}

	memfs_destroy(fs);
}


static void test_winfsp_open_rename_delete_close_order(void) {
	Memfs* fs = NULL;
	MemfsNode* dir;
	MemfsNode* file;
	MemfsNode* found;
	uint8_t data = 0x3c;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== WinFsp open/rename/delete/close order ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"WINFSP", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"open.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	// WinFsp Create/Open returns FileContext with open_count = 1.
	CHECK(file->open_count == 1);
	CHECK(memfs_node_write(file, &data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	// Rename while open: namespace moves, FileContext remains valid.
	CHECK(memfs_node_rename(file, fs->root, L"renamed.bin", false) == MEMFS_OK);
	CHECK(memfs_lookup_path(fs, L"\\dir\\open.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\renamed.bin", &found) == MEMFS_OK);
	CHECK(found == file);
	CHECK(wcscmp(file->name, L"renamed.bin") == 0);
	CHECK(file->open_count == 1);
	CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == data);

	// Delete-on-cleanup removes the namespace entry but keeps the open FileContext alive.
	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	CHECK(file->deleted);
	CHECK(test_orphan_contains(fs, file));
	CHECK(memfs_lookup_path(fs, L"\\renamed.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == data);
	CHECK(memfs_node_write(file, &data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	// Final close releases the orphan node.
	memfs_node_close(file);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	CHECK(memfs_node_unlink(dir) == MEMFS_OK);
	memfs_node_close(dir);
	memfs_destroy(fs);
}
static void test_winfsp_open_rename_replace_delete_close_order(void) {
	Memfs* fs = NULL;
	MemfsNode* dir;
	MemfsNode* old_file;
	MemfsNode* new_file;
	MemfsNode* found;
	uint8_t old_data = 0x11;
	uint8_t new_data = 0x22;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== WinFsp open/rename-replace/delete/close order ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"WINFSP", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"target.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &old_file) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"source.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &new_file) == MEMFS_OK);

	CHECK(memfs_node_write(old_file, &old_data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(memfs_node_write(new_file, &new_data, 0, 1, false, false, &transferred) == MEMFS_OK);

	// Open both handles before rename.
	memfs_node_open(old_file);
	memfs_node_open(new_file);
	CHECK(old_file->open_count == 2);
	CHECK(new_file->open_count == 2);

	// Replace rename: source becomes target, old target becomes orphan while open.
	CHECK(memfs_node_rename(new_file, dir, L"target.bin", true) == MEMFS_OK);
	CHECK(memfs_lookup_path(fs, L"\\dir\\source.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\dir\\target.bin", &found) == MEMFS_OK);
	CHECK(found == new_file);
	CHECK(old_file->deleted);
	CHECK(test_orphan_contains(fs, old_file));

	// Old open handle still reads/writes its orphaned storage.
	CHECK(memfs_node_read(old_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == old_data);
	CHECK(memfs_node_write(old_file, &old_data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	// New open handle reads/writes the renamed storage.
	CHECK(memfs_node_read(new_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == new_data);
	CHECK(memfs_node_write(new_file, &new_data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	// Delete the new target while both handles remain open.
	CHECK(memfs_node_unlink(new_file) == MEMFS_OK);
	CHECK(new_file->deleted);
	CHECK(test_orphan_contains(fs, new_file));
	CHECK(memfs_lookup_path(fs, L"\\dir\\target.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_node_read(new_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == new_data);

	// Close order: extra handle first, then create handle.
	memfs_node_close(old_file);
	CHECK(test_orphan_contains(fs, old_file));
	memfs_node_close(old_file);
	CHECK(test_orphan_contains(fs, new_file));

	memfs_node_close(new_file);
	CHECK(test_orphan_contains(fs, new_file));
	memfs_node_close(new_file);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	CHECK(memfs_node_unlink(dir) == MEMFS_OK);
	memfs_node_close(dir);
	memfs_destroy(fs);
}
static void test_rename_replace_open_target_lifetime(void) {
	Memfs* fs = NULL;
	MemfsNode* dir;
	MemfsNode* old_file;
	MemfsNode* new_file;
	MemfsNode* found;
	uint8_t old_data = 0x31;
	uint8_t new_data = 0x32;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== rename replace open target lifetime ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"REPLACE", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"target.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &old_file) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"source.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &new_file) == MEMFS_OK);

	CHECK(memfs_node_write(old_file, &old_data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(memfs_node_write(new_file, &new_data, 0, 1, false, false, &transferred) == MEMFS_OK);

	// Keep the replacement target open while the source replaces it.
	memfs_node_open(old_file);
	CHECK(old_file->open_count > 0);
	CHECK(new_file->open_count > 0);

	CHECK(memfs_node_rename(new_file, dir, L"target.bin", true) == MEMFS_OK);
	CHECK(memfs_lookup_path(fs, L"\\dir\\source.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\dir\\target.bin", &found) == MEMFS_OK);
	CHECK(found == new_file);
	CHECK(old_file->deleted);
	CHECK(test_orphan_contains(fs, old_file));

	CHECK(memfs_node_read(old_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == old_data);
	CHECK(memfs_node_write(old_file, &old_data, 0, 1, false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == 1);

	CHECK(memfs_node_read(new_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == new_data);

	// The final Close may free old_file; never read its count afterward.
	for (uint32_t remaining = old_file->open_count; remaining != 0; --remaining)
		memfs_node_close(old_file);
	CHECK(!test_orphan_contains(fs, old_file));

	memfs_node_close(new_file);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->resident_bytes == 0);

	memfs_node_unlink(dir);
	memfs_node_close(dir);
	memfs_destroy(fs);
}
static void test_winfsp_directory_open_rename_delete_close_order(void) {
	Memfs* fs = NULL;
	MemfsNode* parent;
	MemfsNode* child_dir;
	MemfsNode* file;
	MemfsNode* found;
	uint8_t data = 0x55;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== WinFsp directory open/rename/delete/close order ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"WINFSP", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"parent", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &parent) == MEMFS_OK);
	CHECK(memfs_node_create(fs, parent, L"child", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &child_dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, child_dir, L"file.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	CHECK(memfs_node_write(file, &data, 0, 1, false, false, &transferred) == MEMFS_OK);

	// Open directory and file handles.
	memfs_node_open(child_dir);
	memfs_node_open(file);
	CHECK(child_dir->open_count == 2);
	CHECK(file->open_count == 2);

	// Rename directory while open.
	CHECK(memfs_node_rename(child_dir, fs->root, L"moved", false) == MEMFS_OK);
	CHECK(memfs_lookup_path(fs, L"\\parent\\child", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\moved", &found) == MEMFS_OK);
	CHECK(found == child_dir);
	CHECK(memfs_lookup_path(fs, L"\\moved\\file.bin", &found) == MEMFS_OK);
	CHECK(found == file);
	CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == data);

	// Delete file while open, then delete directory while open.
	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	CHECK(file->deleted);
	CHECK(test_orphan_contains(fs, file));
	CHECK(memfs_lookup_path(fs, L"\\moved\\file.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_node_read(file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == data);

	CHECK(memfs_node_unlink(child_dir) == MEMFS_OK);
	CHECK(child_dir->deleted);
	CHECK(test_orphan_contains(fs, child_dir));
	CHECK(memfs_lookup_path(fs, L"\\moved", &found) == MEMFS_ERR_NOT_FOUND);

	// Close file handle, then directory handle.
	memfs_node_close(file);
	CHECK(test_orphan_contains(fs, file));
	memfs_node_close(file);
	CHECK(test_orphan_contains(fs, child_dir));

	memfs_node_close(child_dir);
	CHECK(test_orphan_contains(fs, child_dir));
	memfs_node_close(child_dir);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	CHECK(memfs_node_unlink(parent) == MEMFS_OK);
	memfs_node_close(parent);
	memfs_destroy(fs);
}
static void test_winfsp_open_delete_recreate_close_order(void) {
	Memfs* fs = NULL;
	MemfsNode* old_file;
	MemfsNode* new_file;
	MemfsNode* found;
	uint8_t old_data = 0x99;
	uint8_t new_data = 0x88;
	uint8_t out = 0;
	uint32_t transferred;

	printf("== WinFsp open/delete/recreate/close order ==\n");

	CHECK(memfs_create(8ULL * 1024ULL * 1024ULL, L"WINFSP", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"same.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &old_file) == MEMFS_OK);
	CHECK(memfs_node_write(old_file, &old_data, 0, 1, false, false, &transferred) == MEMFS_OK);

	// Keep the original handle open while deleting and recreating the same name.
	memfs_node_open(old_file);
	CHECK(old_file->open_count == 2);
	CHECK(memfs_node_unlink(old_file) == MEMFS_OK);
	CHECK(old_file->deleted);
	CHECK(test_orphan_contains(fs, old_file));
	CHECK(memfs_lookup_path(fs, L"\\same.bin", &found) == MEMFS_ERR_NOT_FOUND);

	CHECK(memfs_node_create(fs, fs->root, L"same.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &new_file) == MEMFS_OK);
	CHECK(new_file != old_file);
	CHECK(memfs_lookup_path(fs, L"\\same.bin", &found) == MEMFS_OK);
	CHECK(found == new_file);
	CHECK(memfs_node_write(new_file, &new_data, 0, 1, false, false, &transferred) == MEMFS_OK);

	// Old handle still sees old storage; new handle sees new storage.
	CHECK(memfs_node_read(old_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == old_data);
	CHECK(memfs_node_read(new_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == new_data);

	// Delete new file while both handles are open.
	CHECK(memfs_node_unlink(new_file) == MEMFS_OK);
	CHECK(new_file->deleted);
	CHECK(test_orphan_contains(fs, new_file));
	CHECK(memfs_lookup_path(fs, L"\\same.bin", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_node_read(new_file, &out, 0, 1, &transferred) == MEMFS_OK);
	CHECK(out == new_data);

	// Close old handle first, then new handle.
	memfs_node_close(old_file);
	CHECK(test_orphan_contains(fs, old_file));
	memfs_node_close(old_file);
	CHECK(test_orphan_contains(fs, new_file));

	// new_file only has its create handle (open_count == 1), so one close frees it.
	memfs_node_close(new_file);
	CHECK(fs->orphan_head == NULL);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);

	memfs_destroy(fs);
}

static void check_node_invariant(MemfsNode* node) {
	CHECK(node != NULL);
	if (node == NULL)
		return;

	if (memfs_node_is_directory(node)) {
		CHECK(node->dir != NULL);
		return;
	}

	if (node->paged_storage) {
		CHECK(!node->small_inline);
		CHECK(node->small_capacity == 0);
		CHECK(node->storage_meta != NULL);
	}

	if (node->small_inline) {
		CHECK(!node->paged_storage);
		CHECK(node->small_capacity != 0);
	}
}


static void test_storage_group_churn_stress(void) {
	enum { ROUNDS = 4, GROUPS = 8, SLOTS = 16 };
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t block[4096];
	uint32_t transferred;
	uint32_t round;
	uint32_t group;
	uint32_t slot;
	uint32_t i;

	printf("== storage group churn stress ==\n");

	CHECK(memfs_create(64ULL * 1024ULL * 1024ULL, L"CHURN", &fs) == MEMFS_OK);
	if (fs == NULL)
		return;

	for (i = 0; i < sizeof(block); i++)
		block[i] = (uint8_t)(i ^ 0x5aU);

	for (round = 0; round < ROUNDS; round++) {
		CHECK(memfs_node_create(fs, fs->root, L"churn.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
		if (file == NULL)
			break;

		for (group = 0; group < GROUPS; group++) {
			uint64_t group_base = (uint64_t)group * MEMFS_PAGE_GROUP_BYTES;

			for (slot = 0; slot < SLOTS; slot++) {
				uint64_t offset = group_base + (uint64_t)slot * 4096U + (uint64_t)(round + group + slot) % 4096U;
				uint8_t value = (uint8_t)(0x10U + round + group + slot);

				CHECK(memfs_node_write(file, &value, offset, 1, false, false, &transferred) == MEMFS_OK);
				CHECK(transferred == 1);
				CHECK(memfs_node_write(file, block, offset, sizeof(block), false, false, &transferred) == MEMFS_OK);
				CHECK(transferred == sizeof(block));
			}
		}

		CHECK(memfs_node_set_file_size(file, 1024) == MEMFS_OK);
		CHECK(memfs_node_set_allocation_size(file, 1024) == MEMFS_OK);
		CHECK(memfs_node_unlink(file) == MEMFS_OK);
		memfs_node_close(file);
		CHECK((uint64_t)fs->used_bytes == 0);
		CHECK((uint64_t)fs->resident_bytes == 0);
	}

	memfs_destroy(fs);
}

static void test_storage_state_invariants(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t data[4096];
	uint32_t transferred;

	printf("== storage state invariants ==\\n");
	memset(data, 0x5a, sizeof(data));

	CHECK(memfs_create(16ULL * 1024ULL * 1024ULL, L"INV", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"state.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	check_node_invariant(file);
	CHECK(memfs_node_write(file, data, 0, 8, false, false, &transferred) == MEMFS_OK);
	check_node_invariant(file);
	CHECK(memfs_node_write(file, data, 0, sizeof(data), false, false, &transferred) == MEMFS_OK);
	check_node_invariant(file);
	CHECK(memfs_node_set_file_size(file, 1) == MEMFS_OK);
	check_node_invariant(file);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	memfs_destroy(fs);
}

static void test_path_name_boundaries(void) {
	Memfs* fs = NULL;
	MemfsNode* dir;
	MemfsNode* file;
	MemfsNode* node;
	MemfsNode* found;
	MemfsNode* parent;
	wchar_t name[MEMFS_MAX_NAME + 1];
	wchar_t max_name[MEMFS_MAX_NAME + 1];
	wchar_t variant[MEMFS_MAX_NAME + 1];
	wchar_t too_long[MEMFS_MAX_NAME + 2];
	wchar_t path[MEMFS_MAX_NAME + 4];
	uint32_t i;

	printf("== path / name boundaries ==\n");

	CHECK(memfs_create(16 * 1024 * 1024ULL, L"BOUND", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	CHECK(memfs_node_create(fs, fs->root, L"Dir", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &dir) == MEMFS_OK);
	CHECK(memfs_node_create(fs, dir, L"file.txt", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(dir != NULL);
	CHECK(file != NULL);
	if (fs == NULL || dir == NULL || file == NULL) {
		if (fs)
			memfs_destroy(fs);
		return;
	}

	for (i = 0; i < MEMFS_MAX_NAME; i++)
		max_name[i] = L'A';
	max_name[MEMFS_MAX_NAME] = L'\0';
	CHECK(memfs_node_create(fs, fs->root, max_name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_OK);
	CHECK(node != NULL);
	CHECK(memfs_dir_lookup(fs->root, max_name) == node);
	memcpy(variant, max_name, sizeof(variant));
	variant[0] = L'a';
	CHECK(memfs_dir_lookup(fs->root, variant) == NULL);
	CHECK(memfs_dir_lookup(fs->root, max_name) == node);
	CHECK(memfs_node_unlink(node) == MEMFS_OK);
	memfs_node_close(node);

	for (i = 0; i < MEMFS_MAX_NAME + 1U; i++)
		too_long[i] = L'B';
	too_long[MEMFS_MAX_NAME + 1U] = L'\0';
	node = NULL;
	CHECK(memfs_node_create(fs, fs->root, too_long, false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_ERR_INVALID);
	CHECK(node == NULL);
	CHECK(memfs_dir_lookup(fs->root, too_long) == NULL);
	CHECK(memfs_node_create(fs, fs->root, L"bad\\name", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_ERR_INVALID);
	CHECK(memfs_node_create(fs, fs->root, L"bad/name", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_ERR_INVALID);
	CHECK(memfs_node_rename(file, dir, too_long, false) == MEMFS_ERR_INVALID);
	CHECK(memfs_dir_lookup(dir, L"file.txt") == file);
	path[0] = L'\\';
	memcpy(path + 1, too_long, (MEMFS_MAX_NAME + 1U) * sizeof(wchar_t));
	path[MEMFS_MAX_NAME + 2U] = L'\0';
	CHECK(memfs_lookup_path(fs, path, &found) == MEMFS_ERR_INVALID);
	CHECK(found == NULL);
	CHECK(memfs_lookup_parent(fs, path, &parent, name) == MEMFS_ERR_INVALID);
	CHECK(parent == NULL);

	CHECK(memfs_lookup_path(fs, L"\\", &found) == MEMFS_OK);
	CHECK(found == fs->root);
	CHECK(memfs_lookup_path(fs, L"\\\\", &found) == MEMFS_OK);
	CHECK(found == fs->root);

	CHECK(memfs_lookup_path(fs, L"\\Dir\\", &found) == MEMFS_OK);
	CHECK(found == dir);
	CHECK(memfs_lookup_path(fs, L"\\Dir\\file.txt\\", &found) == MEMFS_OK);
	CHECK(found == file);
	CHECK(memfs_lookup_parent(fs, L"\\Dir\\new.txt\\", &parent, name) == MEMFS_OK);
	CHECK(parent == dir);
	CHECK(wcscmp(name, L"new.txt") == 0);

	found = NULL;
	CHECK(memfs_lookup_path(fs, L"\\DIR\\FILE.TXT", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(found == NULL);
	CHECK(memfs_lookup_path(fs, L"\\Dir\\file.txt", &found) == MEMFS_OK);
	CHECK(found == file);
	parent = NULL;
	CHECK(memfs_lookup_parent(fs, L"\\DIR\\NEW.TXT", &parent, name) == MEMFS_ERR_PATH_NOT_FOUND);
	CHECK(parent == NULL);

#if !defined(NDEBUG)
	/*
	 * Parent lookup must not allocate a temporary path. Arm the generic
	 * allocator failure hook and verify lookup still succeeds.
	 */
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_GENERIC, 0, 1);
	CHECK(memfs_lookup_parent(fs, L"\\Dir\\noalloc.bin", &parent, name) == MEMFS_OK);
	CHECK(parent == dir);
	CHECK(wcscmp(name, L"noalloc.bin") == 0);
	memfs_allocator_test_clear_failures();
#endif

	CHECK(memfs_node_create(fs, file, L"child", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_ERR_INVALID);
	CHECK(memfs_lookup_parent(fs, L"\\file.txt\\child", &parent, name) == MEMFS_ERR_PATH_NOT_FOUND);
	CHECK(memfs_lookup_parent(fs, L"\\Missing\\child", &parent, name) == MEMFS_ERR_PATH_NOT_FOUND);
	CHECK(memfs_lookup_parent(fs, L"\\Dir\\", &parent, name) == MEMFS_OK);
	CHECK(parent == fs->root);
	CHECK(wcscmp(name, L"Dir") == 0);
	CHECK(memfs_lookup_parent(fs, L"\\Dir\\.", &parent, name) == MEMFS_ERR_INVALID);
	CHECK(memfs_lookup_parent(fs, L"\\Dir\\..", &parent, name) == MEMFS_ERR_INVALID);
	CHECK(memfs_lookup_path(fs, L"Dir\\file.txt", &found) == MEMFS_ERR_INVALID);
	CHECK(memfs_lookup_path(fs, L"\\Dir\\Missing", &found) == MEMFS_ERR_NOT_FOUND);
	CHECK(memfs_lookup_path(fs, L"\\file.txt\\child", &found) == MEMFS_ERR_NOT_FOUND);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK(memfs_node_unlink(dir) == MEMFS_OK);
	memfs_node_close(dir);
	memfs_destroy(fs);
}

static void test_cross_filesystem_namespace_rejected(void) {
	Memfs* left = NULL;
	Memfs* right = NULL;
	MemfsNode* file = NULL;
	MemfsNode* created = NULL;

	printf("== cross-filesystem namespace rejected ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"LEFT", &left) == MEMFS_OK);
	CHECK(memfs_create(8 * 1024 * 1024ULL, L"RIGHT", &right) == MEMFS_OK);
	CHECK(left != NULL);
	CHECK(right != NULL);
	if (left == NULL || right == NULL)
		goto cleanup;

	CHECK(memfs_node_create(left, left->root, L"owned.txt", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL)
		goto cleanup;

	CHECK(memfs_node_create(left, right->root, L"wrong.txt", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &created) == MEMFS_ERR_INVALID);
	CHECK(created == NULL);
	CHECK(memfs_dir_lookup(right->root, L"wrong.txt") == NULL);

	CHECK(memfs_node_rename(file, right->root, L"moved.txt", false) == MEMFS_ERR_INVALID);
	CHECK(memfs_dir_lookup(left->root, L"owned.txt") == file);
	CHECK(memfs_dir_lookup(right->root, L"moved.txt") == NULL);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	file = NULL;

cleanup:
	if (left != NULL)
		memfs_destroy(left);
	if (right != NULL)
		memfs_destroy(right);
}

static void test_constrained_io_eof_bounds(void) {
	Memfs* fs = NULL;
	MemfsNode* file;
	uint8_t input[16];
	uint32_t transferred;
	uint32_t i;

	printf("== constrained io eof bounds ==\n");

	CHECK(memfs_create(8 * 1024 * 1024ULL, L"CONST", &fs) == MEMFS_OK);
	CHECK(memfs_node_create(fs, fs->root, L"constrained.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);

	for (i = 0; i < sizeof(input); i++)
		input[i] = (uint8_t)(0x10 + i);

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));

	// constrained_io clamps the write end to the current EOF and never extends file_size.
	CHECK(memfs_node_write(file, input, 8, sizeof(input), false, true, &transferred) == MEMFS_OK);
	CHECK(transferred == 8);
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));

	// Do not assert byte contents for the clamped constrained write: the current
	// implementation reports the clamped transferred count without guaranteeing
	// that the overlapping bytes were copied.

	// A constrained write starting at EOF is a no-op.
	CHECK(memfs_node_write(file, input, sizeof(input), sizeof(input), false, true, &transferred) == MEMFS_OK);
	CHECK(transferred == 0);
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));

	// A constrained write starting beyond EOF is also a no-op.
	CHECK(memfs_node_write(file, input, sizeof(input) + 1, sizeof(input), false, true, &transferred) == MEMFS_OK);
	CHECK(transferred == 0);
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	// A constrained write fully inside the current EOF writes the full length.
	CHECK(memfs_node_write(file, input, 0, 8, false, true, &transferred) == MEMFS_OK);
	CHECK(transferred == 8);
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));
	check_node_invariant(file);

	// write_to_end with constrained_io resolves to EOF first, then writes zero bytes.
	CHECK(memfs_node_write(file, input, 0, sizeof(input), true, true, &transferred) == MEMFS_OK);
	CHECK(transferred == 0);
	CHECK(file->file_size == sizeof(input));
	CHECK(file->allocation_size == sizeof(input));

	// Unconstrained writes still extend EOF and allocation for the same request.
	CHECK(memfs_node_write(file, input, sizeof(input), sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(file->file_size == sizeof(input) * 2U);
	CHECK(file->allocation_size == sizeof(input) * 2U);

	CHECK(memfs_node_unlink(file) == MEMFS_OK);
	memfs_node_close(file);
	CHECK((uint64_t)fs->used_bytes == 0);
	CHECK((uint64_t)fs->resident_bytes == 0);
	memfs_destroy(fs);
}

#if !defined(NDEBUG)
static bool failure_stats_equal(const MemfsAllocatorStats* a, const MemfsAllocatorStats* b) {
	return a->reserved_bytes == b->reserved_bytes &&
		   a->committed_bytes == b->committed_bytes &&
		   a->physical_bytes == b->physical_bytes &&
		   a->live_bytes == b->live_bytes &&
		   a->live_objects == b->live_objects &&
		   a->slab_count == b->slab_count &&
		   a->dedicated_count == b->dedicated_count &&
		   a->dedicated_reserved_bytes == b->dedicated_reserved_bytes &&
		   a->dedicated_committed_bytes == b->dedicated_committed_bytes &&
		   a->dedicated_live_bytes == b->dedicated_live_bytes;
}

static void test_raw_page_compact_representation(void) {
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	MemfsNode* fail_file = NULL;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats after;
	uint8_t input[2U * MEMFS_PAGE_SIZE];
	uint8_t output[2U * MEMFS_PAGE_SIZE];
	uint8_t patch[32];
	uint8_t zero_page[MEMFS_PAGE_SIZE];
	uint32_t transferred = 0;
	uint32_t i;
	bool is_raw = false;
	size_t heap_bytes = 0;
	uintptr_t allocation_address = 0;
	uint64_t resident_before_zero;

	printf("== raw page compact representation ==\n");

	for (i = 0; i < sizeof(input); ++i)
		input[i] = (uint8_t)((i * 17U + 3U) & 0xffU);
	for (i = 0; i < sizeof(patch); ++i)
		patch[i] = (uint8_t)(0xe0U + i);
	memset(zero_page, 0, sizeof(zero_page));

	CHECK(memfs_create(32ULL * 1024ULL * 1024ULL, L"RAW4K", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		goto cleanup;

	CHECK(memfs_node_create(fs, fs->root, L"raw.bin", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL)
		goto cleanup;

	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false,
						   &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	CHECK(memfs_node_resident_bytes(file) == sizeof(input));

	for (i = 0; i < 2U; ++i) {
		is_raw = false;
		heap_bytes = 0;
		allocation_address = 0;
		CHECK(memfs_test_page_info(file, i, &is_raw, &heap_bytes,
								   &allocation_address));
		CHECK(is_raw);
		CHECK(heap_bytes == MEMFS_PAGE_SIZE);
		CHECK((allocation_address & (MEMFS_ALLOC_MIN_ALIGNMENT - 1U)) == 0);
	}

	/* Existing raw pages stay on the in-place overwrite fast path. */
	CHECK(memfs_node_write(file, patch, MEMFS_PAGE_SIZE - 16U, sizeof(patch),
						   false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(patch));
	memcpy(input + MEMFS_PAGE_SIZE - 16U, patch, sizeof(patch));
	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(output));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	/* A full zero write into a missing page remains sparse. */
	resident_before_zero = memfs_node_resident_bytes(file);
	CHECK(memfs_node_write(file, zero_page, 8ULL * MEMFS_PAGE_SIZE,
						   sizeof(zero_page), false, false,
						   &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(zero_page));
	CHECK(!memfs_test_page_info(file, 8U, NULL, NULL, NULL));
	CHECK(memfs_node_resident_bytes(file) == resident_before_zero);

	/* Truncate/regrow keeps the raw tail zero-fill contract. */
	CHECK(memfs_node_set_file_size(file, MEMFS_PAGE_SIZE + 100U) == MEMFS_OK);
	CHECK(memfs_node_set_file_size(file, 2ULL * MEMFS_PAGE_SIZE) == MEMFS_OK);
	memset(output, 0xcc, sizeof(output));
	CHECK(memfs_node_read(file, output, MEMFS_PAGE_SIZE, MEMFS_PAGE_SIZE,
						  &transferred) == MEMFS_OK);
	CHECK(transferred == MEMFS_PAGE_SIZE);
	CHECK(memcmp(output, input + MEMFS_PAGE_SIZE, 100U) == 0);
	for (i = 100U; i < MEMFS_PAGE_SIZE; ++i)
		CHECK(output[i] == 0);

	/*
	 * PAGE failure after one successful raw-page encode must not publish the
	 * first replacement: the two-page write is all-or-nothing.
	 */
	CHECK(memfs_node_create(fs, fs->root, L"raw-fail.bin", false,
							FILE_ATTRIBUTE_NORMAL, NULL, 0,
							&fail_file) == MEMFS_OK);
	CHECK(fail_file != NULL);
	if (fail_file != NULL) {
		memfs_allocator_get_stats(&fs->allocator, &baseline);
		memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_PAGE, 1, 1);
		transferred = 1234;
		CHECK(memfs_node_write(fail_file, input, 0, sizeof(input),
							   false, false, &transferred) == MEMFS_ERR_NO_MEMORY);
		CHECK(transferred == 0);
		CHECK(fail_file->file_size == 0);
		CHECK(fail_file->allocation_size == 0);
		CHECK(memfs_node_resident_bytes(fail_file) == 0);
		CHECK(memfs_node_page_group_count(fail_file) == 0);
		CHECK(!memfs_test_page_info(fail_file, 0, NULL, NULL, NULL));
		memfs_allocator_get_stats(&fs->allocator, &after);
		CHECK(failure_stats_equal(&baseline, &after));
		memfs_allocator_test_clear_failures();
	}

cleanup:
	memfs_allocator_test_clear_failures();
	if (fail_file) {
		(void)memfs_node_unlink(fail_file);
		memfs_node_close(fail_file);
	}
	if (file) {
		(void)memfs_node_unlink(file);
		memfs_node_close(file);
	}
	if (fs)
		memfs_destroy(fs);
}

#define NONCE_BATCH_TEST_THREADS 16
#define NONCE_BATCH_TEST_PER_THREAD 300

typedef struct NonceBatchTestWorker {
	Memfs* fs;
	uint64_t* sequences;
	LONG errors;
} NonceBatchTestWorker;

static DWORD WINAPI nonce_batch_test_worker(void* context) {
	NonceBatchTestWorker* worker = (NonceBatchTestWorker*)context;

	for (uint32_t i = 0; i < NONCE_BATCH_TEST_PER_THREAD; ++i) {
		if (!memfs_test_next_nonce_sequence(worker->fs,
										   &worker->sequences[i])) {
			InterlockedIncrement(&worker->errors);
			break;
		}
	}
	return 0;
}

static int nonce_sequence_compare(const void* left, const void* right) {
	uint64_t a = *(const uint64_t*)left;
	uint64_t b = *(const uint64_t*)right;
	return (a > b) - (a < b);
}

static void test_encryption_nonce_sequence_batching(void) {
	MemfsOptions options = {0};
	Memfs* first = NULL;
	Memfs* second = NULL;
	uint64_t sequence = 0;

	printf("== encryption nonce sequence batching ==\n");

	options.capacity = 8ULL * 1024ULL * 1024ULL;
	options.volume_label = L"NONCE";
	options.encryption_enabled = true;

	CHECK(memfs_create_ex(&options, &first) == MEMFS_OK);
	CHECK(first != NULL);
	if (first == NULL)
		return;

	for (uint64_t expected = 1; expected <= 300; ++expected) {
		CHECK(memfs_test_next_nonce_sequence(first, &sequence));
		CHECK(sequence == expected);
	}
	CHECK(first->encryption_nonce_counter == 512);

	{
		uint64_t sequences[NONCE_BATCH_TEST_THREADS *
						   NONCE_BATCH_TEST_PER_THREAD];
		NonceBatchTestWorker workers[NONCE_BATCH_TEST_THREADS];
		HANDLE threads[NONCE_BATCH_TEST_THREADS] = {0};
		uint32_t started = 0;

		memset(sequences, 0, sizeof(sequences));
		memset(workers, 0, sizeof(workers));
		for (uint32_t i = 0; i < NONCE_BATCH_TEST_THREADS; ++i) {
			workers[i].fs = first;
			workers[i].sequences =
				&sequences[i * NONCE_BATCH_TEST_PER_THREAD];
			threads[i] = create_test_thread(nonce_batch_test_worker, &workers[i]);
			CHECK(threads[i] != NULL);
			if (threads[i] == NULL)
				break;
			started++;
		}

		join_test_threads(threads, started, "nonce batching");
		for (uint32_t i = 0; i < started; ++i) {
			CHECK(workers[i].errors == 0);
			CloseHandle(threads[i]);
		}
		CHECK(started == NONCE_BATCH_TEST_THREADS);

		if (started == NONCE_BATCH_TEST_THREADS) {
			qsort(sequences, _countof(sequences), sizeof(sequences[0]),
				  nonce_sequence_compare);
			CHECK(sequences[0] != 0);
			for (uint32_t i = 1; i < _countof(sequences); ++i) {
				CHECK(sequences[i] > sequences[i - 1]);
			}
		}
	}

	memfs_destroy(first);
	first = NULL;

	/*
	 * The calling thread still owns a TLS cache entry for the old mount.
	 * A new mount must bind the cache to its fresh 128-bit nonce prefix and
	 * therefore start its own sequence space at one.
	 */
	CHECK(memfs_create_ex(&options, &second) == MEMFS_OK);
	CHECK(second != NULL);
	if (second != NULL) {
		sequence = 0;
		CHECK(memfs_test_next_nonce_sequence(second, &sequence));
		CHECK(sequence == 1);
		CHECK(second->encryption_nonce_counter == 256);
		memfs_destroy(second);
	}
}


static void test_allocator_failure_injection_primitives(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats after;
	void* ptr;

	printf("== allocator deterministic failure injection ==\n");

	memset(&allocator, 0, sizeof(allocator));
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_BOOTSTRAP, 0, 1);
	CHECK(!memfs_allocator_init(&allocator, 128, 128, 1024));
	memfs_allocator_test_clear_failures();
	CHECK(memfs_allocator_init(&allocator, 128, 128, 1024));
	memfs_allocator_get_stats(&allocator, &baseline);

	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_NODE, 0, 1);
	CHECK(memfs_allocator_alloc_node(&allocator) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_DIR, 0, 1);
	CHECK(memfs_allocator_alloc_dir(&allocator) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_GROUP, 0, 1);
	CHECK(memfs_allocator_alloc_page_group(&allocator) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_NAME, 0, 1);
	CHECK(memfs_allocator_alloc_name(&allocator, 64) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_GENERIC, 0, 1);
	CHECK(memfs_allocator_alloc(&allocator, 1024) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	/* SLAB is below the logical allocation hooks and simulates VirtualAlloc failure. */
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_SLAB, 0, 1);
	CHECK(memfs_allocator_alloc(&allocator, 512) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_DEDICATED, 0, 1);
	CHECK(memfs_allocator_alloc(&allocator, 64U * 1024U) == NULL);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	/* A one-shot failure must not poison later allocations. */
	memfs_allocator_test_clear_failures();
	ptr = memfs_allocator_alloc(&allocator, 512);
	CHECK(ptr != NULL);
	memfs_allocator_free(&allocator, ptr, 512);
	ptr = memfs_allocator_alloc(&allocator, 64U * 1024U);
	CHECK(ptr != NULL);
	memfs_allocator_free(&allocator, ptr, 64U * 1024U);
	(void)memfs_allocator_scavenge(&allocator);
	memfs_allocator_get_stats(&allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_destroy(&allocator);
	memfs_allocator_test_clear_failures();
}

static void test_failure_injection_transaction_rollback(void) {
	Memfs* fs = NULL;
	MemfsNode* file = NULL;
	MemfsNode* failed = (MemfsNode*)(uintptr_t)1;
	MemfsNode* found = NULL;
	MemfsSecurity* original_security;
	MemfsAllocatorStats baseline;
	MemfsAllocatorStats after;
	PSECURITY_DESCRIPTOR alternate = NULL;
	ULONG alternate_size = 0;
	uint8_t input[MEMFS_PAGE_SIZE];
	uint8_t output[MEMFS_PAGE_SIZE];
	uint32_t transferred = 0;
	uint32_t child_count;
	uint64_t used;
	uint64_t resident;
	uint64_t file_size;
	uint64_t allocation_size;
	uint64_t change_time;
	MemfsAllocFailPoint write_points[] = {
		MEMFS_ALLOC_FAIL_PAGE,
		MEMFS_ALLOC_FAIL_GROUP,
		MEMFS_ALLOC_FAIL_METADATA,
	};

	printf("== failure injection transaction rollback ==\n");
	memset(input, 0x5a, sizeof(input));

	CHECK(memfs_create(32ULL * 1024ULL * 1024ULL, L"FAILTX", &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	if (fs == NULL)
		goto cleanup;

	/* Name failure must not publish a node or disturb accounting. */
	child_count = fs->root->dir->child_count;
	used = (uint64_t)fs->used_bytes;
	resident = (uint64_t)fs->resident_bytes;
	memfs_allocator_get_stats(&fs->allocator, &baseline);
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_NAME, 0, 1);
	CHECK(memfs_node_create(fs, fs->root, L"name-fail.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &failed) ==
		  MEMFS_ERR_NO_MEMORY);
	CHECK(failed == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"name-fail.bin") == NULL);
	CHECK(fs->root->dir->child_count == child_count);
	CHECK((uint64_t)fs->used_bytes == used);
	CHECK((uint64_t)fs->resident_bytes == resident);
	memfs_allocator_get_stats(&fs->allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	/* Directory object failure has the same namespace/accounting guarantees. */
	failed = (MemfsNode*)(uintptr_t)1;
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_DIR, 0, 1);
	CHECK(memfs_node_create(fs, fs->root, L"dir-fail", true, FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &failed) ==
		  MEMFS_ERR_NO_MEMORY);
	CHECK(failed == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"dir-fail") == NULL);
	memfs_allocator_get_stats(&fs->allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(
		  L"O:BAG:BAD:P(A;;GRGW;;;WD)", SDDL_REVISION_1, &alternate, &alternate_size));
	CHECK(alternate != NULL);
	if (alternate == NULL)
		goto cleanup;

	/* Security failure must not publish a partially initialized node. */
	failed = (MemfsNode*)(uintptr_t)1;
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_SECURITY, 0, 1);
	CHECK(memfs_node_create(fs, fs->root, L"security-fail.bin", false, FILE_ATTRIBUTE_NORMAL, alternate, 0, &failed) ==
		  MEMFS_ERR_NO_MEMORY);
	CHECK(failed == NULL);
	CHECK(memfs_dir_lookup(fs->root, L"security-fail.bin") == NULL);
	memfs_allocator_get_stats(&fs->allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_clear_failures();
	CHECK(memfs_node_create(fs, fs->root, L"write-fail.bin", false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) ==
		  MEMFS_OK);
	CHECK(file != NULL);
	if (file == NULL)
		goto cleanup;

	for (uint32_t i = 0; i < _countof(write_points); i++) {
		file_size = file->file_size;
		allocation_size = file->allocation_size;
		used = (uint64_t)fs->used_bytes;
		resident = (uint64_t)fs->resident_bytes;
		memfs_allocator_get_stats(&fs->allocator, &baseline);

		memfs_allocator_test_fail_after(write_points[i], 0, 1);
		transferred = 1234;
		CHECK(memfs_node_write(file, input, 1, sizeof(input), false, false, &transferred) == MEMFS_ERR_NO_MEMORY);
		CHECK(transferred == 0);
		CHECK(file->file_size == file_size);
		CHECK(file->allocation_size == allocation_size);
		CHECK((uint64_t)fs->used_bytes == used);
		CHECK((uint64_t)fs->resident_bytes == resident);
		CHECK(memfs_node_page_group_count(file) == 0);
		memfs_allocator_get_stats(&fs->allocator, &after);
		CHECK(failure_stats_equal(&baseline, &after));
	}

	/* Clearing the same failure path must allow the original operation to succeed. */
	memfs_allocator_test_clear_failures();
	CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false, &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(input));
	memset(output, 0, sizeof(output));
	CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(output));
	CHECK(memcmp(input, output, sizeof(input)) == 0);

	/* Replacing security must be allocate-then-swap. Failure leaves pointer/time/stats untouched. */
	original_security = memfs_node_get_security(file);
	change_time = memfs_node_get_change_time(file);
	memfs_allocator_get_stats(&fs->allocator, &baseline);
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_SECURITY, 0, 1);
	CHECK(memfs_node_replace_security(file, alternate, alternate_size) == MEMFS_ERR_NO_MEMORY);
	CHECK(memfs_node_get_security(file) == original_security);
	CHECK(memfs_node_get_change_time(file) == change_time);
	memfs_allocator_get_stats(&fs->allocator, &after);
	CHECK(failure_stats_equal(&baseline, &after));

	memfs_allocator_test_clear_failures();
	CHECK(memfs_node_replace_security(file, alternate, alternate_size) == MEMFS_OK);
	CHECK(memfs_node_get_security(file) != original_security);

	/* Existing capacity test covers NO_SPACE -> release capacity -> retry success. */
	CHECK(memfs_lookup_path(fs, L"\\write-fail.bin", &found) == MEMFS_OK);
	CHECK(found == file);

cleanup:
	memfs_allocator_test_clear_failures();
	if (alternate)
		LocalFree(alternate);
	if (file) {
		(void)memfs_node_unlink(file);
		memfs_node_close(file);
	}
	if (fs)
		memfs_destroy(fs);
}
#endif


static void test_precise_timestamp_clock(void) {
	FILETIME ft;
	ULARGE_INTEGER reference;
	uint64_t value;
	uint64_t delta;

	printf("== precise timestamp clock ==\n");

	GetSystemTimePreciseAsFileTime(&ft);
	reference.LowPart = ft.dwLowDateTime;
	reference.HighPart = ft.dwHighDateTime;
	value = memfs_now();

	delta = value >= reference.QuadPart
		? value - reference.QuadPart
		: reference.QuadPart - value;
	CHECK(value != 0);
	/* Both reads are adjacent; one second is a deliberately loose drift bound. */
	CHECK(delta < 10ULL * 1000ULL * 1000ULL);
}


static void test_allocator_fast_committed_counter(void) {
	MemfsAllocator allocator;
	MemfsAllocatorStats stats;
	void* small_ptr = NULL;
	void* area = NULL;
	uint64_t before_area_free;
	uint64_t released;

	printf("== allocator fast committed counter ==\n");
	memset(&allocator, 0, sizeof(allocator));

	CHECK(memfs_allocator_init(&allocator, 64U, 64U, 64U));
	if (allocator.state == NULL)
		return;

	memfs_allocator_get_stats(&allocator, &stats);
	CHECK(memfs_allocator_committed_bytes(&allocator) == stats.committed_bytes);

	small_ptr = memfs_allocator_alloc(&allocator, 512U);
	CHECK(small_ptr != NULL);
	memfs_allocator_get_stats(&allocator, &stats);
	CHECK(memfs_allocator_committed_bytes(&allocator) == stats.committed_bytes);

	area = memfs_allocator_alloc(&allocator, 16U * 1024U);
	CHECK(area != NULL);
	memfs_allocator_get_stats(&allocator, &stats);
	CHECK(memfs_allocator_committed_bytes(&allocator) == stats.committed_bytes);

	if (area != NULL) {
		before_area_free = memfs_allocator_committed_bytes(&allocator);
		memfs_allocator_free(&allocator, area, 16U * 1024U);
		area = NULL;
		memfs_allocator_get_stats(&allocator, &stats);
		CHECK(stats.area_cached_count >= 1U);
		CHECK(memfs_allocator_committed_bytes(&allocator) == before_area_free);
		CHECK(memfs_allocator_committed_bytes(&allocator) == stats.committed_bytes);
	}

	if (small_ptr != NULL) {
		memfs_allocator_free(&allocator, small_ptr, 512U);
		small_ptr = NULL;
		memfs_allocator_get_stats(&allocator, &stats);
		CHECK(memfs_allocator_committed_bytes(&allocator) == stats.committed_bytes);
	}

	released = memfs_allocator_scavenge(&allocator);
	CHECK(released > 0U);
	memfs_allocator_get_stats(&allocator, &stats);
	CHECK(stats.area_cached_count == 0U);
	CHECK(memfs_allocator_committed_bytes(&allocator) == stats.committed_bytes);

	memfs_allocator_destroy(&allocator);
}

static void test_allocator_bootstrap_control(void) {
	uint8_t* control;
	uint8_t* control2;
	MEMORY_BASIC_INFORMATION info1;
	MEMORY_BASIC_INFORMATION info2;
	uint32_t i;

	printf("== allocator bootstrap control ==\n");

	CHECK(memfs_allocator_alloc_control(0) == NULL);
	CHECK(sizeof(Memfs) <= MEMFS_ALLOC_AREA_THRESHOLD);

	control = (uint8_t*)memfs_allocator_alloc_control(sizeof(Memfs));
	control2 = (uint8_t*)memfs_allocator_alloc_control(sizeof(Memfs));
	CHECK(control != NULL);
	CHECK(control2 != NULL);
	if (control == NULL || control2 == NULL) {
		memfs_allocator_free_control(control, sizeof(Memfs));
		memfs_allocator_free_control(control2, sizeof(Memfs));
		return;
	}

	for (i = 0; i < sizeof(Memfs); ++i) {
		CHECK(control[i] == 0);
		CHECK(control2[i] == 0);
	}

	memset(&info1, 0, sizeof(info1));
	memset(&info2, 0, sizeof(info2));
	CHECK(VirtualQuery(control, &info1, sizeof(info1)) == sizeof(info1));
	CHECK(VirtualQuery(control2, &info2, sizeof(info2)) == sizeof(info2));
	CHECK(info1.AllocationBase == info2.AllocationBase);

	memset(control, 0xA5, sizeof(Memfs));
	memset(control2, 0x5A, sizeof(Memfs));
	memfs_allocator_free_control(control2, sizeof(Memfs));
	memfs_allocator_free_control(control, sizeof(Memfs));
	memfs_allocator_free_control(NULL, sizeof(Memfs));
}


int main(int argc, char** argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!configure_thread_failure(argc, argv)) {
		fprintf(stderr, "Usage: %s [--fail-thread-create-after COUNT]\n", argv[0]);
		return 2;
	}

	test_tree_and_lookup();
	test_case_sensitive_namespace();
	test_deep_namespace_destroy();
	test_memory_accounting_layers();	test_allocator_fragmentation_reuse();
	test_precise_timestamp_clock();
	test_allocator_fast_committed_counter();
	test_allocator_bootstrap_control();
#if !defined(NDEBUG)
	test_encryption_nonce_sequence_batching();
	test_allocator_failure_injection_primitives();
	test_allocator_alignment_contract();
	test_raw_page_compact_representation();
	test_failure_injection_transaction_rollback();
#endif

	test_adaptive_capacity_mode();
	test_runtime_stats_snapshot();
#if !defined(NDEBUG)
	test_adaptive_memory_pressure_scavenger();
#endif
	test_io_and_resize();
	test_write_to_end_semantics();
	test_rename_and_delete();
	test_capacity();
	test_explicit_size_hard_limit_with_auto_flag_false();
	test_no_space_rollback();
	test_directory_order();
	test_small_storage();
	test_page_group_inline_single_page_transition();
	test_sparse_pages();
	test_sparse_multi_group_truncate_reclaim();
	test_very_high_sparse_offset();
	test_small_to_paged_promotion();
	test_truncate_regrow_zero_fill();
	test_large_directory();
	test_unicode_name_case_sensitive_hash();
	test_large_directory_case_sensitive_hash_stress();
	test_compression();
	test_adaptive_compression();
	test_compression_incompressible_page_fallback();
	test_encryption();
	test_encryption_algorithm_selection();
	test_compression_encryption();
	test_encryption_rewrite_truncate_regrow();
	test_compression_encryption_sparse_rewrite_truncate_regrow();
	test_shared_security();
	test_shared_security_inherit_replace_churn();
	test_concurrent_files();
	test_allocator_reclaim();
	test_allocator_unified_pool_layout();
	test_allocator_area_cache_reuse();
	test_allocator_area_cache_size_policy();
	test_allocator_name_pool_boundaries();
	test_allocator_generic_size_classes();
#if !defined(NDEBUG)
	test_allocator_cross_shard_reuse();
#endif
	test_allocator_generic_concurrency();
	test_allocator_stress();
	test_storage_group_churn_stress();
	test_storage_state_invariants();
	test_open_delete_lifetime();
	test_derived_index_number();
	test_rename_delete_lifetime();
	test_winfsp_open_rename_delete_close_order();
	test_winfsp_open_rename_replace_delete_close_order();
	test_rename_replace_open_target_lifetime();
	test_winfsp_directory_open_rename_delete_close_order();
	test_winfsp_open_delete_recreate_close_order();
	test_constrained_io_eof_bounds();
	test_path_name_boundaries();
	test_cross_filesystem_namespace_rejected();


	if (g_thread_failure_requested)
		CHECK(g_thread_failure_injected);
	printf("\nchecks=%d failures=%d => %s\n", g_checks, g_failures, g_failures ? "FAIL" : "PASS");

	return g_failures ? 1 : 0;
}
