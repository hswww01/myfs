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

static bool test_stat_list_epochs_and_failure(SCPFS_CACHE *cache)
{
	SCPFS_REMOTE_STAT value = make_stat(11);
	SCPFS_REMOTE_STAT output;
	SCPFS_DIR_LIST input, output_list;
	uint32_t fetches = 0;
	memset(&input, 0, sizeof(input));
	input.entries = (SCPFS_DIR_ENTRY *)calloc(1, sizeof(*input.entries));
	if(input.entries == NULL)
		return false;
	input.count = 1;
	input.entries[0].name = test_wcsdup(L"Alpha");
	input.entries[0].name_length = 5;
	input.entries[0].stat = value;
	if(input.entries[0].name == NULL)
		goto failed;

	/* Simulated exact-case stat miss/fetch, then hit with no fetch call. */
	if(scp_cache_get_stat(cache, L"\\Case.txt", 4, 9, &output))
		goto failed;
	fetches++;
	scp_cache_put_stat(cache, L"\\Case.txt", &value, 4, 9);
	if(!scp_cache_get_stat(cache, L"\\Case.txt", 4, 9, &output) ||
		fetches != 1 || output.inode != value.inode ||
		scp_cache_get_stat(cache, L"\\case.txt", 4, 9, &output))
		goto failed;
	if(scp_cache_get_stat(cache, L"\\Case.txt", 5, 9, &output))
		goto failed;

	/* A failed remote fetch is not published; the next success can be cached. */
	if(scp_cache_get_stat(cache, L"\\retry", 4, 9, &output))
		goto failed;
	fetches++; /* simulated failure; deliberately do not put */
	if(scp_cache_get_stat(cache, L"\\retry", 4, 9, &output))
		goto failed;
	fetches++;
	scp_cache_put_stat(cache, L"\\retry", &value, 4, 9);
	if(!scp_cache_get_stat(cache, L"\\retry", 4, 9, &output) || fetches != 3)
		goto failed;

	if(scp_cache_get_list(cache, L"\\Root", 4, 9, &output_list))
		goto failed;
	fetches++;
	scp_cache_put_list(cache, L"\\Root", &input, 4, 9);
	free(input.entries[0].name);
	input.entries[0].name = NULL;
	free(input.entries);
	input.entries = NULL;
	input.count = 0;
	memset(&output_list, 0, sizeof(output_list));
	if(!scp_cache_get_list(cache, L"\\Root", 4, 9, &output_list) ||
		output_list.count != 1 || wcscmp(output_list.entries[0].name, L"Alpha") != 0 ||
	fetches != 4) {
		if(output_list.entries != NULL) {
			free(output_list.entries[0].name);
			free(output_list.entries);
		}
		goto failed;
	}
	free(output_list.entries[0].name);
	free(output_list.entries);
	if(scp_cache_get_list(cache, L"\\root", 4, 9, &input))
		goto failed;
	fetches++;
	if(fetches != 5)
		goto failed;
	return true;
failed:
	if(input.entries != NULL) {
		if(input.count != 0)
			free(input.entries[0].name);
		free(input.entries);
	}
	return false;
}

static bool test_payload_copy_provenance_and_atime(SCPFS_CACHE *cache,
	PCWSTR directory)
{
	WCHAR source[MAX_PATH];
	WCHAR source2[MAX_PATH];
	SCPFS_REMOTE_STAT provenance = make_stat(4);
	SCPFS_REMOTE_STAT fresh;
	PCWSTR copied = NULL;
	uint64_t stored_metadata_epoch = 0;
	bool metadata_stale = false;
	char bytes[8] = { 0 };
	unsigned int iteration;
	DWORD handles_before = 0, handles_after = 0;
	if(swprintf_s(source, ARRAYSIZE(source), L"%ls\\source.bin", directory) < 0 ||
		swprintf_s(source2, ARRAYSIZE(source2), L"%ls\\source2.bin", directory) < 0 ||
		!write_test_file(source, "old!", 4) || !write_test_file(source2, "other", 5)) {
		fwprintf(stderr, L"payload subtest: fixture files could not be created\n");
		return false;
	}
	scp_cache_put_payload(cache, L"\\payload.bin", source, &provenance, 10, 20);
	if(!write_test_file(source, "new!", 4) ||
		!scp_cache_get_payload(cache, L"\\payload.bin", 10, 20, &copied,
			&fresh, &stored_metadata_epoch, &metadata_stale) ||
		metadata_stale || stored_metadata_epoch != 10 ||
		!read_test_file(copied, bytes, 4) || memcmp(bytes, "old!", 4) != 0) {
		fwprintf(stderr, L"payload subtest: copy isolation/initial candidate failed\n");
		return false;
	}
	scp_cache_record_payload_hit(cache);

	if(scp_cache_get_payload(cache, L"\\payload.bin", 10, 21, &copied,
		&fresh, &stored_metadata_epoch, &metadata_stale)) {
		fwprintf(stderr, L"payload subtest: content epoch did not evict candidate\n");
		return false;
	}
	if(!write_test_file(source, "old!", 4)) {
		fwprintf(stderr, L"payload subtest: could not restore immutable source fixture\n");
		return false;
	}
	scp_cache_put_payload(cache, L"\\payload.bin", source, &provenance, 10, 20);

	/* ATTRIB-only epoch keeps bytes but requires an exact fresh provenance check. */
	scp_cache_invalidate_metadata(cache);
	if(!scp_cache_get_payload(cache, L"\\payload.bin", 11, 20, &copied,
		&fresh, &stored_metadata_epoch, &metadata_stale) || !metadata_stale) {
		fwprintf(stderr, L"payload subtest: metadata epoch did not expose stale candidate\n");
		return false;
	}
	if(!scp_cache_validate_payload(cache, L"\\payload.bin", &provenance, 11) ||
		!scp_cache_get_payload(cache, L"\\payload.bin", 11, 20, &copied,
			&fresh, &stored_metadata_epoch, &metadata_stale) || metadata_stale) {
		fwprintf(stderr, L"payload subtest: matching fresh provenance was rejected\n");
		return false;
	}
	if(!read_test_file(copied, bytes, 4) || memcmp(bytes, "old!", 4) != 0)
	{
		fwprintf(stderr, L"payload subtest: validated cache copy changed\n");
		return false;
	}
	scp_cache_record_payload_hit(cache);
	/* A genuine access-time update changes the returned metadata while the
	 * same immutable bytes remain reusable after fresh provenance validation. */
	{
		SCPFS_REMOTE_STAT access_updated = provenance;
		access_updated.atime_ns += 1234;
		scp_cache_invalidate_metadata(cache);
		if(!scp_cache_validate_payload(cache, L"\\payload.bin", &access_updated, 12) ||
			!scp_cache_get_payload(cache, L"\\payload.bin", 12, 20, &copied,
				&fresh, &stored_metadata_epoch, &metadata_stale) || metadata_stale ||
			fresh.atime_ns != access_updated.atime_ns ||
			!read_test_file(copied, bytes, 4) || memcmp(bytes, "old!", 4) != 0) {
			fwprintf(stderr, L"payload subtest: access time refresh lost bytes or kept old metadata\n");
			return false;
		}
	}
	fresh = provenance;
	fresh.uid++;
	if(scp_cache_validate_payload(cache, L"\\payload.bin", &fresh, 11) ||
		scp_cache_get_payload(cache, L"\\payload.bin", 11, 20, &copied,
			&fresh, &stored_metadata_epoch, &metadata_stale)) {
		fwprintf(stderr, L"payload subtest: mismatched provenance remained reusable\n");
		return false;
	}
	scp_cache_record_payload_miss(cache);

	/* Repeat replacement/copy operations and ensure transient source handles close. */
	GetProcessHandleCount(GetCurrentProcess(), &handles_before);
	for(iteration = 0; iteration < 32; iteration++) {
		provenance = make_stat(5);
		scp_cache_put_payload(cache, L"\\replaced.bin", source2, &provenance, 1, 2);
		if(!scp_cache_get_payload(cache, L"\\replaced.bin", 1, 2, &copied,
			&fresh, &stored_metadata_epoch, &metadata_stale)) {
			fwprintf(stderr, L"payload subtest: replacement candidate missing\n");
			return false;
		}
		if(!read_test_file(copied, bytes, 5) || memcmp(bytes, "other", 5) != 0)
		{
			fwprintf(stderr, L"payload subtest: replacement copy differs\n");
			return false;
		}
		scp_cache_record_payload_hit(cache);
	}
	GetProcessHandleCount(GetCurrentProcess(), &handles_after);
	if(handles_before != 0 && handles_after > handles_before + 2u)
	{
		fwprintf(stderr, L"payload subtest: transient file handles grew %lu -> %lu\n",
			handles_before, handles_after);
		return false;
	}

	/* All provenance dimensions used by ATTRIB validation must reject a change. */
	provenance = make_stat(4);
	{
		unsigned int index;
		for(index = 0; index < 3u; index++) {
			SCPFS_REMOTE_STAT changed = make_stat(4);
			if(index == 0)
				changed.uid++;
			else if(index == 1)
				changed.gid++;
			else
				changed.ctime_ns++;
			scp_cache_put_payload(cache, L"\\provenance", source, &provenance, 3, 4);
			if(scp_cache_validate_payload(cache, L"\\provenance", &changed, 3) ||
				scp_cache_get_payload(cache, L"\\provenance", 3, 4, &copied,
					&fresh, &stored_metadata_epoch, &metadata_stale)) {
				fwprintf(stderr, L"payload subtest: UID/GID/ctime provenance field %u accepted\n", index);
				return false;
			}
		}
	}
	return true;
}

static bool test_payload_limits(SCPFS_CACHE *cache, PCWSTR directory)
{
	WCHAR source_a[MAX_PATH], source_b[MAX_PATH];
	char *block = (char *)malloc(700u * 1024u);
	SCPFS_REMOTE_STAT stat = make_stat(700u * 1024u);
	SCPFS_REMOTE_STAT output;
	PCWSTR path;
	uint64_t epoch;
	bool stale;
	if(block == NULL)
		return false;
	memset(block, 0x5a, 700u * 1024u);
	if(swprintf_s(source_a, ARRAYSIZE(source_a), L"%ls\\large-a.bin", directory) < 0 ||
		swprintf_s(source_b, ARRAYSIZE(source_b), L"%ls\\large-b.bin", directory) < 0 ||
		!write_test_file(source_a, block, 700u * 1024u) ||
		!write_test_file(source_b, block, 700u * 1024u)) {
		free(block);
		return false;
	}
	free(block);
	scp_cache_put_payload(cache, L"\\large-a", source_a, &stat, 1, 1);
	scp_cache_put_payload(cache, L"\\large-b", source_b, &stat, 1, 1);
	if(scp_cache_get_payload(cache, L"\\large-a", 1, 1, &path,
		&output, &epoch, &stale))
		return false;
	if(!scp_cache_get_payload(cache, L"\\large-b", 1, 1, &path,
		&output, &epoch, &stale))
		return false;
	{
		WCHAR empty[MAX_PATH];
		SCPFS_REMOTE_STAT zero_stat = make_stat(0);
		if(swprintf_s(empty, ARRAYSIZE(empty), L"%ls\\empty.bin", directory) < 0 ||
			!write_test_file(empty, "", 0))
			return false;
		scp_cache_put_payload(cache, L"\\empty", empty, &zero_stat, 1, 1);
		if(!scp_cache_get_payload(cache, L"\\empty", 1, 1, &path,
			&output, &epoch, &stale) || output.size != 0)
			return false;
	}
	scp_cache_invalidate_all(cache);
	return !scp_cache_get_payload(cache, L"\\large-b", 1, 1, &path,
		&output, &epoch, &stale);
}

static bool test_metadata_entry_bound(SCPFS_CACHE *cache)
{
	WCHAR path[48];
	SCPFS_REMOTE_STAT value = make_stat(1), output;
	unsigned int index;
	for(index = 0; index < SCPFS_CACHE_METADATA_LIMIT_ENTRIES + 8u; index++) {
		if(swprintf_s(path, ARRAYSIZE(path), L"\\bound-%04u", index) < 0)
			return false;
		scp_cache_put_stat(cache, path, &value, 1, 1);
	}
	if(scp_cache_get_stat(cache, L"\\bound-0000", 1, 1, &output) ||
		!scp_cache_get_stat(cache, L"\\bound-4103", 1, 1, &output))
		return false;
	return true;
}

static bool test_unlimited_cache(SCPFS_CACHE *cache, PCWSTR directory)
{
	const DWORD payload_size = 1024u * 1024u + 17u;
	WCHAR source[MAX_PATH];
	char *payload = (char *)malloc(payload_size);
	SCPFS_REMOTE_STAT value = make_stat(payload_size), output;
	PCWSTR cached_path = NULL;
	uint64_t metadata_epoch = 0;
	bool metadata_stale = false;
	LARGE_INTEGER copied_size;
	WIN32_FILE_ATTRIBUTE_DATA attributes;
	if(payload == NULL)
		return false;
	memset(payload, 0xa7, payload_size);
	if(swprintf_s(source, ARRAYSIZE(source), L"%ls\\unlimited.bin", directory) < 0 ||
		!write_test_file(source, payload, payload_size)) {
		free(payload);
		return false;
	}
	free(payload);
	if(scp_cache_get_stat(cache, L"\\unlimited-stat", 7, 8, &output))
		return false;
	scp_cache_put_stat(cache, L"\\unlimited-stat", &value, 7, 8);
	if(!scp_cache_get_stat(cache, L"\\unlimited-stat", 7, 8, &output) ||
		output.size != payload_size)
		return false;
	scp_cache_put_payload(cache, L"\\unlimited.bin", source, &value, 7, 8);
	if(!scp_cache_get_payload(cache, L"\\unlimited.bin", 7, 8, &cached_path,
		&output, &metadata_epoch, &metadata_stale) || metadata_stale ||
		!GetFileAttributesExW(cached_path, GetFileExInfoStandard, &attributes))
		return false;
	copied_size.HighPart = attributes.nFileSizeHigh;
	copied_size.LowPart = attributes.nFileSizeLow;
	if(copied_size.QuadPart != payload_size)
		return false;
	scp_cache_record_payload_hit(cache);
	return true;
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
	if(!test_stat_list_epochs_and_failure(cache)) {
		fwprintf(stderr, L"FAIL: exact-case stat/list or miss-retry subtest\n");
		goto done;
	}
	if(!test_payload_copy_provenance_and_atime(cache, directory)) {
		fwprintf(stderr, L"FAIL: payload copy/provenance/handle subtest\n");
		goto done;
	}
	if(!test_payload_limits(cache, directory)) {
		fwprintf(stderr, L"FAIL: payload LRU/zero-length subtest\n");
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
		counters.evictions == 0 || counters.invalidations == 0)
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
	wprintf(L"PASS: exact-case metadata, retry, copied payload, provenance, epochs, LRU, zero-length entries and unlimited 0 mode\n");
	return 0;
}
