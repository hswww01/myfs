#include "scp_cache.h"

#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CHECK(condition) do { \
	if(!(condition)) { \
		fwprintf(stderr, L"FAIL: %hs:%d: %hs\n", __FILE__, __LINE__, #condition); \
		goto done; \
	} \
} while(0)

static bool make_test_directory(WCHAR directory[MAX_PATH])
{
	WCHAR executable[MAX_PATH];
	WCHAR *slash;
	GUID id;
	WCHAR guid[40];
	DWORD length = GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable));
	if(length == 0 || length >= ARRAYSIZE(executable))
		return false;
	slash = wcsrchr(executable, L'\\');
	if(slash == NULL || FAILED(CoCreateGuid(&id)) ||
		StringFromGUID2(&id, guid, ARRAYSIZE(guid)) == 0)
		return false;
	slash[1] = L'\0';
	if(swprintf_s(directory, MAX_PATH, L"%lsscp-cache-test-%ls", executable, guid) < 0)
		return false;
	return CreateDirectoryW(directory, NULL) != FALSE;
}

static bool write_test_file(PCWSTR path, const void *bytes, DWORD size)
{
	HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written = 0;
	bool result;
	if(file == INVALID_HANDLE_VALUE)
		return false;
	result = WriteFile(file, bytes, size, &written, NULL) && written == size;
	CloseHandle(file);
	return result;
}

static bool read_test_file(PCWSTR path, void *bytes, DWORD size)
{
	HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD read = 0;
	bool result;
	if(file == INVALID_HANDLE_VALUE)
		return false;
	result = ReadFile(file, bytes, size, &read, NULL) && read == size;
	CloseHandle(file);
	return result;
}

static void remove_test_directory(PCWSTR directory)
{
	WCHAR pattern[MAX_PATH];
	WIN32_FIND_DATAW data;
	HANDLE find;
	if(swprintf_s(pattern, ARRAYSIZE(pattern), L"%ls\\*", directory) < 0)
		return;
	find = FindFirstFileW(pattern, &data);
	if(find != INVALID_HANDLE_VALUE) {
		do {
			WCHAR path[MAX_PATH];
			if(wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
				continue;
			if(swprintf_s(path, ARRAYSIZE(path), L"%ls\\%ls", directory,
				data.cFileName) >= 0)
				DeleteFileW(path);
		} while(FindNextFileW(find, &data));
		FindClose(find);
	}
	RemoveDirectoryW(directory);
}

static WCHAR *test_wcsdup(PCWSTR source)
{
	size_t bytes = (wcslen(source) + 1u) * sizeof(WCHAR);
	WCHAR *copy = (WCHAR *)malloc(bytes);
	if(copy != NULL)
		memcpy(copy, source, bytes);
	return copy;
}

static SCPFS_REMOTE_STAT make_stat(uint64_t size)
{
	SCPFS_REMOTE_STAT value;
	memset(&value, 0, sizeof(value));
	value.type = SCPFS_REMOTE_FILE;
	value.mode = 0644;
	value.size = size;
	value.atime_ns = 100;
	value.mtime_ns = 200;
	value.device = 3;
	value.inode = 5;
	value.uid = 7;
	value.gid = 8;
	value.ctime_ns = 300;
	return value;
}

static void test_free_list(SCPFS_DIR_LIST *list)
{
	size_t index;
	for(index = 0; index < list->count; index++)
		free(list->entries[index].name);
	free(list->entries);
	memset(list, 0, sizeof(*list));
}

static bool same_stat(const SCPFS_REMOTE_STAT *left, const SCPFS_REMOTE_STAT *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

/* Exact-case stat/list, negative entries, list-populated child stats. */
static bool test_metadata(SCPFS_CACHE *cache)
{
	SCPFS_REMOTE_STAT value = make_stat(11);
	SCPFS_REMOTE_STAT output;
	SCPFS_DIR_LIST input, output_list;
	bool ok = false;
	memset(&input, 0, sizeof(input));
	memset(&output_list, 0, sizeof(output_list));
	CHECK(scp_cache_get_stat(cache, L"\\Case.txt", &output) == SCPFS_CACHE_MISS);
	scp_cache_put_stat(cache, L"\\Case.txt", &value, scp_cache_sequence(cache));
	CHECK(scp_cache_get_stat(cache, L"\\Case.txt", &output) == SCPFS_CACHE_PRESENT);
	CHECK(same_stat(&output, &value));
	CHECK(scp_cache_get_stat(cache, L"\\case.txt", &output) == SCPFS_CACHE_MISS);
	scp_cache_put_stat(cache, L"\\absent", NULL, scp_cache_sequence(cache));
	CHECK(scp_cache_get_stat(cache, L"\\absent", &output) == SCPFS_CACHE_ABSENT);
	/* A creation reported by the parent's watch drops the negative entry. */
	scp_cache_invalidate_path(cache, L"\\absent", SCPFS_CACHE_CHANGE_CONTENT);
	CHECK(scp_cache_get_stat(cache, L"\\absent", &output) == SCPFS_CACHE_MISS);

	input.entries = (SCPFS_DIR_ENTRY *)calloc(2, sizeof(*input.entries));
	CHECK(input.entries != NULL);
	input.count = 2;
	input.entries[0].name = test_wcsdup(L"Alpha");
	input.entries[0].name_length = 5;
	input.entries[0].stat = value;
	input.entries[1].name = test_wcsdup(L"beta");
	input.entries[1].name_length = 4;
	input.entries[1].stat = make_stat(22);
	CHECK(input.entries[0].name != NULL && input.entries[1].name != NULL);
	CHECK(!scp_cache_get_list(cache, L"\\Root", &output_list));
	scp_cache_put_list(cache, L"\\Root", &input, scp_cache_sequence(cache));
	CHECK(scp_cache_get_list(cache, L"\\Root", &output_list));
	CHECK(output_list.count == 2 && wcscmp(output_list.entries[0].name, L"Alpha") == 0 &&
		output_list.entries[1].stat.size == 22);
	test_free_list(&output_list);
	CHECK(!scp_cache_get_list(cache, L"\\root", &output_list));
	/* Listing a directory records each child's stat. */
	CHECK(scp_cache_get_stat(cache, L"\\Root\\beta", &output) == SCPFS_CACHE_PRESENT &&
		output.size == 22);
	/* A metadata change of one child keeps its siblings but drops the listing. */
	scp_cache_invalidate_path(cache, L"\\Root\\beta", SCPFS_CACHE_CHANGE_METADATA);
	CHECK(scp_cache_get_stat(cache, L"\\Root\\beta", &output) == SCPFS_CACHE_MISS);
	CHECK(scp_cache_get_stat(cache, L"\\Root\\Alpha", &output) == SCPFS_CACHE_PRESENT);
	CHECK(!scp_cache_get_list(cache, L"\\Root", &output_list));
	/* Unrelated paths survive any change. */
	CHECK(scp_cache_get_stat(cache, L"\\Case.txt", &output) == SCPFS_CACHE_PRESENT);
	/* A lost subtree drops everything below it, nothing beside it. */
	scp_cache_put_list(cache, L"\\Root", &input, scp_cache_sequence(cache));
	scp_cache_invalidate_path(cache, L"\\Root", SCPFS_CACHE_CHANGE_SUBTREE);
	CHECK(scp_cache_get_stat(cache, L"\\Root\\Alpha", &output) == SCPFS_CACHE_MISS);
	CHECK(!scp_cache_get_list(cache, L"\\Root", &output_list));
	CHECK(scp_cache_get_stat(cache, L"\\Case.txt", &output) == SCPFS_CACHE_PRESENT);
	ok = true;
done:
	test_free_list(&input);
	test_free_list(&output_list);
	return ok;
}

/* A put observed before a related invalidation must be dropped. */
static bool test_sequence_admission(SCPFS_CACHE *cache)
{
	SCPFS_REMOTE_STAT value = make_stat(33);
	SCPFS_REMOTE_STAT output;
	uint64_t observed;
	unsigned index;
	bool ok = false;
	observed = scp_cache_sequence(cache);
	scp_cache_invalidate_path(cache, L"\\seq\\file", SCPFS_CACHE_CHANGE_CONTENT);
	scp_cache_put_stat(cache, L"\\seq\\file", &value, observed);
	CHECK(scp_cache_get_stat(cache, L"\\seq\\file", &output) == SCPFS_CACHE_MISS);
	/* Ancestors and descendants are related too. */
	observed = scp_cache_sequence(cache);
	scp_cache_invalidate_path(cache, L"\\seq\\dir\\child", SCPFS_CACHE_CHANGE_METADATA);
	scp_cache_put_stat(cache, L"\\seq\\dir", &value, observed);
	CHECK(scp_cache_get_stat(cache, L"\\seq\\dir", &output) == SCPFS_CACHE_MISS);
	/* An unrelated change does not block admission. */
	observed = scp_cache_sequence(cache);
	scp_cache_invalidate_path(cache, L"\\elsewhere", SCPFS_CACHE_CHANGE_CONTENT);
	scp_cache_put_stat(cache, L"\\seq\\file", &value, observed);
	CHECK(scp_cache_get_stat(cache, L"\\seq\\file", &output) == SCPFS_CACHE_PRESENT);
	/* A sibling with a common name prefix is unrelated. */
	observed = scp_cache_sequence(cache);
	scp_cache_invalidate_path(cache, L"\\seq\\fil", SCPFS_CACHE_CHANGE_CONTENT);
	scp_cache_put_stat(cache, L"\\seq\\filex", &value, observed);
	CHECK(scp_cache_get_stat(cache, L"\\seq\\filex", &output) == SCPFS_CACHE_PRESENT);
	/* invalidate_all rejects everything observed before it. */
	observed = scp_cache_sequence(cache);
	scp_cache_invalidate_all(cache);
	scp_cache_put_stat(cache, L"\\late", &value, observed);
	CHECK(scp_cache_get_stat(cache, L"\\late", &output) == SCPFS_CACHE_MISS);
	/* Too many changes to remember: reject conservatively. */
	observed = scp_cache_sequence(cache);
	for(index = 0; index < 2000u; index++)
		scp_cache_invalidate_path(cache, L"\\other", SCPFS_CACHE_CHANGE_METADATA);
	scp_cache_put_stat(cache, L"\\late", &value, observed);
	CHECK(scp_cache_get_stat(cache, L"\\late", &output) == SCPFS_CACHE_MISS);
	scp_cache_put_stat(cache, L"\\late", &value, scp_cache_sequence(cache));
	CHECK(scp_cache_get_stat(cache, L"\\late", &output) == SCPFS_CACHE_PRESENT);
	ok = true;
done:
	return ok;
}

static bool test_payload(SCPFS_CACHE *cache, PCWSTR directory)
{
	static const char bytes[] = "payload-bytes";
	char copy[sizeof(bytes) - 1u];
	WCHAR source[MAX_PATH];
	WCHAR target[MAX_PATH];
	SCPFS_REMOTE_STAT provenance = make_stat(sizeof(bytes) - 1u);
	SCPFS_REMOTE_STAT changed;
	SCPFS_REMOTE_STAT atime_only;
	uint64_t observed;
	bool ok = false;
	CHECK(swprintf_s(source, MAX_PATH, L"%ls\\source.bin", directory) >= 0);
	CHECK(swprintf_s(target, MAX_PATH, L"%ls\\target.bin", directory) >= 0);
	CHECK(write_test_file(source, bytes, sizeof(bytes) - 1u));
	scp_cache_put_payload(cache, L"\\payload.bin", source, &provenance,
		scp_cache_sequence(cache));
	CHECK(scp_cache_copy_payload(cache, L"\\payload.bin", &provenance, target));
	CHECK(read_test_file(target, copy, sizeof(copy)) && memcmp(copy, bytes, sizeof(copy)) == 0);
	DeleteFileW(target);
	/* Access time and mode are not provenance; size/mtime/inode are. */
	atime_only = provenance;
	atime_only.atime_ns += 5;
	atime_only.mode = 0600;
	CHECK(scp_cache_copy_payload(cache, L"\\payload.bin", &atime_only, target));
	DeleteFileW(target);
	changed = provenance;
	changed.mtime_ns += 1;
	CHECK(!scp_cache_copy_payload(cache, L"\\payload.bin", &changed, target));
	CHECK(!scp_cache_copy_payload(cache, L"\\payload.bin", &provenance, target));
	/* Metadata changes keep bytes, content changes drop them. */
	scp_cache_put_payload(cache, L"\\payload.bin", source, &provenance,
		scp_cache_sequence(cache));
	scp_cache_invalidate_path(cache, L"\\payload.bin", SCPFS_CACHE_CHANGE_METADATA);
	CHECK(scp_cache_copy_payload(cache, L"\\payload.bin", &provenance, target));
	DeleteFileW(target);
	scp_cache_invalidate_path(cache, L"\\payload.bin", SCPFS_CACHE_CHANGE_CONTENT);
	CHECK(!scp_cache_copy_payload(cache, L"\\payload.bin", &provenance, target));
	/* A change during the transfer rejects the bytes. */
	observed = scp_cache_sequence(cache);
	scp_cache_invalidate_path(cache, L"\\payload.bin", SCPFS_CACHE_CHANGE_CONTENT);
	scp_cache_put_payload(cache, L"\\payload.bin", source, &provenance, observed);
	CHECK(!scp_cache_copy_payload(cache, L"\\payload.bin", &provenance, target));
	/* Size mismatch with the local file is never admitted. */
	changed = provenance;
	changed.size += 1;
	scp_cache_put_payload(cache, L"\\payload.bin", source, &changed,
		scp_cache_sequence(cache));
	CHECK(!scp_cache_copy_payload(cache, L"\\payload.bin", &changed, target));
	ok = true;
done:
	DeleteFileW(target);
	DeleteFileW(source);
	return ok;
}

static bool test_payload_limits(SCPFS_CACHE *cache, PCWSTR directory)
{
	WCHAR source_a[MAX_PATH];
	WCHAR source_b[MAX_PATH];
	WCHAR empty[MAX_PATH];
	WCHAR target[MAX_PATH];
	SCPFS_REMOTE_STAT stat = make_stat(700u * 1024u);
	SCPFS_REMOTE_STAT zero_stat = make_stat(0);
	char *large = (char *)calloc(1, 700u * 1024u);
	bool ok = false;
	CHECK(large != NULL);
	CHECK(swprintf_s(source_a, MAX_PATH, L"%ls\\large-a.bin", directory) >= 0);
	CHECK(swprintf_s(source_b, MAX_PATH, L"%ls\\large-b.bin", directory) >= 0);
	CHECK(swprintf_s(empty, MAX_PATH, L"%ls\\empty.bin", directory) >= 0);
	CHECK(swprintf_s(target, MAX_PATH, L"%ls\\limit-target.bin", directory) >= 0);
	CHECK(write_test_file(source_a, large, 700u * 1024u));
	CHECK(write_test_file(source_b, large, 700u * 1024u));
	CHECK(write_test_file(empty, "", 0));
	/* The 1 MiB budget holds one of the two; the older one is evicted. */
	scp_cache_put_payload(cache, L"\\large-a", source_a, &stat, scp_cache_sequence(cache));
	scp_cache_put_payload(cache, L"\\large-b", source_b, &stat, scp_cache_sequence(cache));
	CHECK(!scp_cache_copy_payload(cache, L"\\large-a", &stat, target));
	CHECK(scp_cache_copy_payload(cache, L"\\large-b", &stat, target));
	DeleteFileW(target);
	scp_cache_put_payload(cache, L"\\empty", empty, &zero_stat, scp_cache_sequence(cache));
	CHECK(scp_cache_copy_payload(cache, L"\\empty", &zero_stat, target));
	DeleteFileW(target);
	scp_cache_invalidate_all(cache);
	CHECK(!scp_cache_copy_payload(cache, L"\\large-b", &stat, target));
	ok = true;
done:
	free(large);
	DeleteFileW(target);
	DeleteFileW(source_a);
	DeleteFileW(source_b);
	DeleteFileW(empty);
	return ok;
}

static bool test_metadata_entry_bound(SCPFS_CACHE *cache)
{
	SCPFS_REMOTE_STAT value = make_stat(1);
	SCPFS_REMOTE_STAT output;
	WCHAR path[64];
	uint32_t index;
	bool ok = false;
	for(index = 0; index < SCPFS_CACHE_METADATA_LIMIT_ENTRIES + 8u; index++) {
		CHECK(swprintf_s(path, ARRAYSIZE(path), L"\\bound-%06u", index) >= 0);
		scp_cache_put_stat(cache, path, &value, scp_cache_sequence(cache));
	}
	CHECK(scp_cache_get_stat(cache, L"\\bound-000000", &output) == SCPFS_CACHE_MISS);
	CHECK(swprintf_s(path, ARRAYSIZE(path), L"\\bound-%06u",
		SCPFS_CACHE_METADATA_LIMIT_ENTRIES + 7u) >= 0);
	CHECK(scp_cache_get_stat(cache, path, &output) == SCPFS_CACHE_PRESENT);
	ok = true;
done:
	return ok;
}

static bool test_unlimited_cache(SCPFS_CACHE *cache, PCWSTR directory)
{
	WCHAR source[MAX_PATH];
	WCHAR target[MAX_PATH];
	SCPFS_REMOTE_STAT value = make_stat(4);
	SCPFS_REMOTE_STAT output;
	bool ok = false;
	CHECK(swprintf_s(source, MAX_PATH, L"%ls\\unlimited.bin", directory) >= 0);
	CHECK(swprintf_s(target, MAX_PATH, L"%ls\\unlimited-target.bin", directory) >= 0);
	CHECK(write_test_file(source, "1234", 4));
	scp_cache_put_stat(cache, L"\\unlimited-stat", &value, scp_cache_sequence(cache));
	CHECK(scp_cache_get_stat(cache, L"\\unlimited-stat", &output) == SCPFS_CACHE_PRESENT);
	scp_cache_put_payload(cache, L"\\unlimited.bin", source, &value, scp_cache_sequence(cache));
	CHECK(scp_cache_copy_payload(cache, L"\\unlimited.bin", &value, target));
	ok = true;
done:
	DeleteFileW(target);
	DeleteFileW(source);
	return ok;
}

int wmain(void)
{
	WCHAR directory[MAX_PATH];
	SCPFS_CACHE *cache = NULL;
	SCPFS_CACHE *unlimited = NULL;
	SCPFS_CACHE_COUNTERS counters;
	SCPFS_CACHE_COUNTERS unlimited_counters;
	bool passed = false;
	if(!make_test_directory(directory)) {
		fwprintf(stderr, L"FAIL: could not create isolated cache test directory (error %lu)\n",
			GetLastError());
		return 1;
	}
	if(!NT_SUCCESS(scp_cache_create(directory, 1, &cache)) || cache == NULL) {
		fwprintf(stderr, L"FAIL: scp_cache_create failed\n");
		goto done;
	}
	if(!test_metadata(cache)) {
		fwprintf(stderr, L"FAIL: metadata subtest\n");
		goto done;
	}
	if(!test_sequence_admission(cache)) {
		fwprintf(stderr, L"FAIL: sequence admission subtest\n");
		goto done;
	}
	if(!test_payload(cache, directory)) {
		fwprintf(stderr, L"FAIL: payload subtest\n");
		goto done;
	}
	if(!test_payload_limits(cache, directory)) {
		fwprintf(stderr, L"FAIL: payload limit subtest\n");
		goto done;
	}
	if(!test_metadata_entry_bound(cache)) {
		fwprintf(stderr, L"FAIL: metadata entry-bound subtest\n");
		goto done;
	}
	if(!NT_SUCCESS(scp_cache_create(directory, 0, &unlimited)) || unlimited == NULL)
		goto done;
	if(!test_unlimited_cache(unlimited, directory))
		goto done;
	scp_cache_get_counters(unlimited, &unlimited_counters);
	if(unlimited_counters.stat_hit == 0 || unlimited_counters.payload_hit == 0)
		goto done;
	scp_cache_get_counters(cache, &counters);
	if(counters.stat_hit == 0 || counters.list_hit == 0 || counters.payload_hit == 0 ||
		counters.evictions == 0 || counters.invalidations == 0 || counters.rejected_puts == 0)
		goto done;
	passed = true;
done:
	scp_cache_destroy(unlimited);
	scp_cache_destroy(cache);
	remove_test_directory(directory);
	if(!passed) {
		fwprintf(stderr, L"FAIL: cache module contract regression\n");
		return 1;
	}
	wprintf(L"PASS: metadata, negative entries, path-scoped invalidation, sequence admission, payload provenance, LRU and unlimited mode\n");
	return 0;
}
