#include "scp_cache.h"

#include <ntstatus.h>
#include <objbase.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>


typedef enum SCPFS_CACHE_KIND {
	SCPFS_CACHE_STAT,
	SCPFS_CACHE_LIST,
	SCPFS_CACHE_PAYLOAD
} SCPFS_CACHE_KIND;

typedef struct SCPFS_CACHE_ENTRY {
	struct SCPFS_CACHE_ENTRY *previous;
	struct SCPFS_CACHE_ENTRY *next;
	SCPFS_CACHE_KIND kind;
	WCHAR *path;
	size_t metadata_bytes;
	uint64_t metadata_epoch;
	uint64_t content_epoch;
	union {
		SCPFS_REMOTE_STAT stat;
		SCPFS_DIR_LIST list;
		struct {
			WCHAR *path;
			SCPFS_REMOTE_STAT provenance;
			size_t size;
	} payload;
	} value;
} SCPFS_CACHE_ENTRY;

struct SCPFS_CACHE {
	WCHAR *session_directory;
	SCPFS_CACHE_ENTRY *most_recent;
	SCPFS_CACHE_ENTRY *least_recent;
	size_t metadata_bytes;
	uint32_t metadata_entries;
	uint64_t payload_max_bytes;
	uint64_t payload_bytes;
	uint32_t filename_counter;
	SCPFS_CACHE_COUNTERS counters;
};

static WCHAR *scp_cache_wcsdup(PCWSTR text)
{
	size_t length;
	WCHAR *copy;
	if (text == NULL)
		return NULL;
	length = wcslen(text);
	if (length > SIZE_MAX / sizeof(WCHAR) - 1u)
		return NULL;
	copy = (WCHAR *)malloc((length + 1u) * sizeof(WCHAR));
	if (copy != NULL)
		memcpy(copy, text, (length + 1u) * sizeof(WCHAR));
	return copy;
}

static bool scp_cache_path(SCPFS_CACHE *cache, PCWSTR leaf, WCHAR **path_out)
{
	size_t directory_length;
	size_t leaf_length;
	WCHAR *path;
	if (cache == NULL || leaf == NULL || path_out == NULL)
		return false;
	*path_out = NULL;
	directory_length = wcslen(cache->session_directory);
	leaf_length = wcslen(leaf);
	if (directory_length > SIZE_MAX - leaf_length - 2u ||
		(directory_length + leaf_length + 2u) > SIZE_MAX / sizeof(WCHAR))
		return false;
	path = (WCHAR *)malloc((directory_length + leaf_length + 2u) * sizeof(WCHAR));
	if (path == NULL)
		return false;
	memcpy(path, cache->session_directory, directory_length * sizeof(WCHAR));
	if (directory_length != 0 && cache->session_directory[directory_length - 1u] != L'\\')
		path[directory_length++] = L'\\';
	memcpy(path + directory_length, leaf, (leaf_length + 1u) * sizeof(WCHAR));
	*path_out = path;
	return true;
}

static void scp_cache_free_list(SCPFS_DIR_LIST *list)
{
	size_t index;
	if (list == NULL)
		return;
	for (index = 0; index < list->count; index++)
		free(list->entries[index].name);
	free(list->entries);
	memset(list, 0, sizeof(*list));
}

static bool scp_cache_clone_list(const SCPFS_DIR_LIST *source,
	SCPFS_DIR_LIST *destination)
{
	size_t index;
	memset(destination, 0, sizeof(*destination));
	if (source->count == 0)
		return true;
	if (source->entries == NULL ||
		source->count > SIZE_MAX / sizeof(*destination->entries))
		return false;
	destination->entries = (SCPFS_DIR_ENTRY *)calloc(source->count,
		sizeof(*destination->entries));
	if (destination->entries == NULL)
		return false;
	for (index = 0; index < source->count; index++) {
		destination->entries[index] = source->entries[index];
		destination->entries[index].name = scp_cache_wcsdup(source->entries[index].name);
		if (destination->entries[index].name == NULL) {
			destination->count = index;
			scp_cache_free_list(destination);
			return false;
		}
		destination->count++;
	}
	return true;
}

static bool scp_cache_list_size(const SCPFS_DIR_LIST *list, size_t *bytes_out)
{
	size_t bytes = sizeof(*list);
	size_t index;
	if (list->count != 0 && list->entries == NULL)
		return false;
	if (list->count > (SIZE_MAX - bytes) / sizeof(*list->entries))
		return false;
	bytes += list->count * sizeof(*list->entries);
	for (index = 0; index < list->count; index++) {
		size_t name_bytes;
		if (list->entries[index].name == NULL ||
			list->entries[index].name_length > (SIZE_MAX / sizeof(WCHAR)) - 1u)
			return false;
		name_bytes = (list->entries[index].name_length + 1u) * sizeof(WCHAR);
		if (bytes > SIZE_MAX - name_bytes)
			return false;
		bytes += name_bytes;
	}
	*bytes_out = bytes;
	return true;
}

static SCPFS_CACHE_ENTRY *scp_cache_find(SCPFS_CACHE *cache,
	SCPFS_CACHE_KIND kind, PCWSTR path)
{
	SCPFS_CACHE_ENTRY *entry;
	for (entry = cache->most_recent; entry != NULL; entry = entry->next) {
		if (entry->kind == kind && wcscmp(entry->path, path) == 0)
			return entry;
	}
	return NULL;
}

static void scp_cache_unlink(SCPFS_CACHE *cache, SCPFS_CACHE_ENTRY *entry)
{
	if (entry->previous != NULL)
		entry->previous->next = entry->next;
	else
		cache->most_recent = entry->next;
	if (entry->next != NULL)
		entry->next->previous = entry->previous;
	else
		cache->least_recent = entry->previous;
	entry->previous = NULL;
	entry->next = NULL;
}

static void scp_cache_link_recent(SCPFS_CACHE *cache, SCPFS_CACHE_ENTRY *entry)
{
	entry->previous = NULL;
	entry->next = cache->most_recent;
	if (cache->most_recent != NULL)
		cache->most_recent->previous = entry;
	else
		cache->least_recent = entry;
	cache->most_recent = entry;
}

static void scp_cache_touch(SCPFS_CACHE *cache, SCPFS_CACHE_ENTRY *entry)
{
	if (cache->most_recent == entry)
		return;
	scp_cache_unlink(cache, entry);
	scp_cache_link_recent(cache, entry);
}

static void scp_cache_remove_entry(SCPFS_CACHE *cache,
	SCPFS_CACHE_ENTRY *entry, bool eviction)
{
	scp_cache_unlink(cache, entry);
	if (entry->kind == SCPFS_CACHE_PAYLOAD) {
		if (cache->payload_bytes >= entry->value.payload.size)
			cache->payload_bytes -= entry->value.payload.size;
		else
			cache->payload_bytes = 0;
		if (entry->value.payload.path != NULL) {
			SetFileAttributesW(entry->value.payload.path, FILE_ATTRIBUTE_NORMAL);
			DeleteFileW(entry->value.payload.path);
			free(entry->value.payload.path);
		}
		if (cache->metadata_bytes >= entry->metadata_bytes)
			cache->metadata_bytes -= entry->metadata_bytes;
		else
			cache->metadata_bytes = 0;
		if (cache->metadata_entries != 0)
			cache->metadata_entries--;
	} else {
		if (cache->metadata_bytes >= entry->metadata_bytes)
			cache->metadata_bytes -= entry->metadata_bytes;
		else
			cache->metadata_bytes = 0;
		if (cache->metadata_entries != 0)
			cache->metadata_entries--;
		if (entry->kind == SCPFS_CACHE_LIST)
			scp_cache_free_list(&entry->value.list);
	}
	free(entry->path);
	free(entry);
	if (eviction)
		cache->counters.evictions++;
}

static void scp_cache_remove_key(SCPFS_CACHE *cache,
	SCPFS_CACHE_KIND kind, PCWSTR path, bool eviction)
{
	SCPFS_CACHE_ENTRY *entry = scp_cache_find(cache, kind, path);
	if (entry != NULL)
		scp_cache_remove_entry(cache, entry, eviction);
}

static void scp_cache_trim_metadata(SCPFS_CACHE *cache)
{
	SCPFS_CACHE_ENTRY *entry;
	while (cache->metadata_bytes > SCPFS_CACHE_METADATA_LIMIT_BYTES ||
		cache->metadata_entries > SCPFS_CACHE_METADATA_LIMIT_ENTRIES) {
		entry = cache->least_recent;
		if (entry == NULL)
			break;
		scp_cache_remove_entry(cache, entry, true);
	}
}

static void scp_cache_trim_payload(SCPFS_CACHE *cache)
{
	SCPFS_CACHE_ENTRY *entry;
	while (cache->payload_bytes > cache->payload_max_bytes) {
		for (entry = cache->least_recent; entry != NULL; entry = entry->previous) {
			if (entry->kind == SCPFS_CACHE_PAYLOAD)
				break;
		}
		if (entry == NULL)
			break;
		scp_cache_remove_entry(cache, entry, true);
	}
}

static bool scp_cache_reserve_metadata(SCPFS_CACHE *cache, size_t bytes)
{
	SCPFS_CACHE_ENTRY *entry;
	if (bytes > SCPFS_CACHE_METADATA_LIMIT_BYTES)
		return false;
	while (cache->metadata_bytes > SCPFS_CACHE_METADATA_LIMIT_BYTES - bytes ||
		cache->metadata_entries >= SCPFS_CACHE_METADATA_LIMIT_ENTRIES) {
		entry = cache->least_recent;
		if (entry == NULL)
			return false;
		scp_cache_remove_entry(cache, entry, true);
	}
	return true;
}

static bool scp_cache_reserve_payload(SCPFS_CACHE *cache, uint64_t bytes)
{
	SCPFS_CACHE_ENTRY *entry;
	if (bytes > cache->payload_max_bytes)
		return false;
	while (cache->payload_bytes > cache->payload_max_bytes - bytes) {
		for (entry = cache->least_recent; entry != NULL; entry = entry->previous) {
			if (entry->kind == SCPFS_CACHE_PAYLOAD)
				break;
		}
		if (entry == NULL)
			return false;
		scp_cache_remove_entry(cache, entry, true);
	}
	return true;
}

NTSTATUS scp_cache_create(PCWSTR session_directory, uint32_t max_payload_mib,
	SCPFS_CACHE **cache_out)
{
	SCPFS_CACHE *cache;
	DWORD attributes;
	if (cache_out == NULL || session_directory == NULL || max_payload_mib > 16384u)
		return STATUS_INVALID_PARAMETER;
	*cache_out = NULL;
	attributes = GetFileAttributesW(session_directory);
	if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY))
		return STATUS_OBJECT_PATH_NOT_FOUND;
	cache = (SCPFS_CACHE *)calloc(1, sizeof(*cache));
	if (cache == NULL)
		return STATUS_NO_MEMORY;
	cache->session_directory = scp_cache_wcsdup(session_directory);
	if (cache->session_directory == NULL) {
		free(cache);
		return STATUS_NO_MEMORY;
	}
	cache->payload_max_bytes = max_payload_mib == 0 ? UINT64_MAX :
		(uint64_t)max_payload_mib * 1024u * 1024u;
	*cache_out = cache;
	return STATUS_SUCCESS;
}

void scp_cache_destroy(SCPFS_CACHE *cache)
{
	if (cache == NULL)
		return;
	while (cache->most_recent != NULL)
		scp_cache_remove_entry(cache, cache->most_recent, false);
	free(cache->session_directory);
	free(cache);
}

bool scp_cache_get_stat(SCPFS_CACHE *cache, PCWSTR path,
	uint64_t metadata_epoch, uint64_t content_epoch,
	SCPFS_REMOTE_STAT *stat_out)
{
	SCPFS_CACHE_ENTRY *entry;
	if (cache == NULL || path == NULL || stat_out == NULL)
		return false;
	entry = scp_cache_find(cache, SCPFS_CACHE_STAT, path);
	if (entry != NULL && (entry->metadata_epoch != metadata_epoch ||
		entry->content_epoch != content_epoch)) {
		scp_cache_remove_entry(cache, entry, true);
		entry = NULL;
	}
	if (entry == NULL) {
		cache->counters.stat_miss++;
		return false;
	}
	*stat_out = entry->value.stat;
	cache->counters.stat_hit++;
	scp_cache_touch(cache, entry);
	return true;
}

void scp_cache_put_stat(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, uint64_t metadata_epoch,
	uint64_t content_epoch)
{
	SCPFS_CACHE_ENTRY *entry;
	size_t path_bytes;
	if (cache == NULL || path == NULL || stat == NULL)
		return;
	if (wcslen(path) > SIZE_MAX / sizeof(WCHAR) - 1u)
		return;
	path_bytes = (wcslen(path) + 1u) * sizeof(WCHAR);
	if (path_bytes > SIZE_MAX - sizeof(*entry))
		return;
	scp_cache_remove_key(cache, SCPFS_CACHE_STAT, path, false);
	entry = (SCPFS_CACHE_ENTRY *)calloc(1, sizeof(*entry));
	if (entry == NULL)
		return;
	entry->path = scp_cache_wcsdup(path);
	if (entry->path == NULL) {
		free(entry);
		return;
	}
	entry->kind = SCPFS_CACHE_STAT;
	entry->metadata_epoch = metadata_epoch;
	entry->content_epoch = content_epoch;
	entry->value.stat = *stat;
	entry->metadata_bytes = sizeof(*entry) + path_bytes;
	cache->metadata_bytes += entry->metadata_bytes;
	cache->metadata_entries++;
	scp_cache_link_recent(cache, entry);
	scp_cache_trim_metadata(cache);
}

bool scp_cache_get_list(SCPFS_CACHE *cache, PCWSTR path,
	uint64_t metadata_epoch, uint64_t content_epoch,
	SCPFS_DIR_LIST *list_out)
{
	SCPFS_CACHE_ENTRY *entry;
	if (cache == NULL || path == NULL || list_out == NULL)
		return false;
	memset(list_out, 0, sizeof(*list_out));
	entry = scp_cache_find(cache, SCPFS_CACHE_LIST, path);
	if (entry != NULL && (entry->metadata_epoch != metadata_epoch ||
		entry->content_epoch != content_epoch)) {
		scp_cache_remove_entry(cache, entry, true);
		entry = NULL;
	}
	if (entry == NULL || !scp_cache_clone_list(&entry->value.list, list_out)) {
		cache->counters.list_miss++;
		return false;
	}
	cache->counters.list_hit++;
	scp_cache_touch(cache, entry);
	return true;
}

void scp_cache_put_list(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_DIR_LIST *list, uint64_t metadata_epoch,
	uint64_t content_epoch)
{
	SCPFS_CACHE_ENTRY *entry;
	size_t path_bytes;
	size_t list_bytes;
	if (cache == NULL || path == NULL || list == NULL)
		return;
	if (wcslen(path) > SIZE_MAX / sizeof(WCHAR) - 1u ||
		!scp_cache_list_size(list, &list_bytes))
		return;
	path_bytes = (wcslen(path) + 1u) * sizeof(WCHAR);
	if (list_bytes > SIZE_MAX - sizeof(*entry) ||
		path_bytes > SIZE_MAX - sizeof(*entry) - list_bytes)
		return;
	if (sizeof(*entry) + list_bytes + path_bytes > SCPFS_CACHE_METADATA_LIMIT_BYTES)
		return;
	scp_cache_remove_key(cache, SCPFS_CACHE_LIST, path, false);
	entry = (SCPFS_CACHE_ENTRY *)calloc(1, sizeof(*entry));
	if (entry == NULL)
		return;
	entry->path = scp_cache_wcsdup(path);
	if (entry->path == NULL || !scp_cache_clone_list(list, &entry->value.list)) {
		free(entry->path);
		scp_cache_free_list(&entry->value.list);
		free(entry);
		return;
	}
	entry->kind = SCPFS_CACHE_LIST;
	entry->metadata_epoch = metadata_epoch;
	entry->content_epoch = content_epoch;
	entry->metadata_bytes = sizeof(*entry) + path_bytes + list_bytes;
	cache->metadata_bytes += entry->metadata_bytes;
	cache->metadata_entries++;
	scp_cache_link_recent(cache, entry);
	scp_cache_trim_metadata(cache);
}

bool scp_cache_get_payload(SCPFS_CACHE *cache, PCWSTR path,
	uint64_t metadata_epoch, uint64_t content_epoch,
	PCWSTR *payload_path_out,
	SCPFS_REMOTE_STAT *provenance_out, uint64_t *metadata_epoch_out,
	bool *metadata_stale_out)
{
	SCPFS_CACHE_ENTRY *entry;
	if (payload_path_out != NULL)
		*payload_path_out = NULL;
	if (metadata_stale_out != NULL)
		*metadata_stale_out = false;
	if (cache == NULL || path == NULL ||
		payload_path_out == NULL || provenance_out == NULL ||
		metadata_epoch_out == NULL || metadata_stale_out == NULL)
		return false;
	entry = scp_cache_find(cache, SCPFS_CACHE_PAYLOAD, path);
	if (entry != NULL && entry->content_epoch != content_epoch) {
		scp_cache_remove_entry(cache, entry, true);
		entry = NULL;
	}
	if (entry == NULL) {
		cache->counters.payload_miss++;
		return false;
	}
	*payload_path_out = entry->value.payload.path;
	*provenance_out = entry->value.payload.provenance;
	*metadata_epoch_out = entry->metadata_epoch;
	*metadata_stale_out = entry->metadata_epoch != metadata_epoch;
	scp_cache_touch(cache, entry);
	return true;
}

static bool scp_cache_same_payload_provenance(const SCPFS_REMOTE_STAT *left,
	const SCPFS_REMOTE_STAT *right)
{
	return left->type == right->type && left->device == right->device &&
		left->inode == right->inode && left->size == right->size &&
		left->mtime_ns == right->mtime_ns && left->mode == right->mode &&
		left->uid == right->uid && left->gid == right->gid &&
		left->ctime_ns == right->ctime_ns;
}

bool scp_cache_validate_payload(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *fresh_stat, uint64_t metadata_epoch)
{
	SCPFS_CACHE_ENTRY *entry;
	if (cache == NULL || path == NULL || fresh_stat == NULL)
		return false;
	entry = scp_cache_find(cache, SCPFS_CACHE_PAYLOAD, path);
	if (entry == NULL)
		return false;
	if (!scp_cache_same_payload_provenance(&entry->value.payload.provenance,
		fresh_stat)) {
		scp_cache_remove_entry(cache, entry, true);
		return false;
	}
	entry->metadata_epoch = metadata_epoch;
	entry->value.payload.provenance = *fresh_stat;
	scp_cache_touch(cache, entry);
	return true;
}

void scp_cache_put_payload(SCPFS_CACHE *cache, PCWSTR path,
	PCWSTR source_path, const SCPFS_REMOTE_STAT *provenance,
	uint64_t metadata_epoch, uint64_t content_epoch)
{
	SCPFS_CACHE_ENTRY *entry;
	WCHAR leaf[64];
	WCHAR *cache_path = NULL;
	LARGE_INTEGER size;
	unsigned int attempt;
	HANDLE source;
	size_t key_bytes;
	size_t payload_path_bytes;
	size_t entry_metadata_bytes;
	if (cache == NULL || path == NULL ||
		source_path == NULL || provenance == NULL ||
		provenance->size > cache->payload_max_bytes || provenance->size > SIZE_MAX)
		return;
	source = CreateFileW(source_path, FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (source == INVALID_HANDLE_VALUE) {
		return;
	}
	size.QuadPart = -1;
	if (!GetFileSizeEx(source, &size) || size.QuadPart < 0 ||
		(uint64_t)size.QuadPart != provenance->size) {
		CloseHandle(source);
		return;
	}
	CloseHandle(source);
	scp_cache_remove_key(cache, SCPFS_CACHE_PAYLOAD, path, false);
	for (attempt = 0; attempt < 16u; attempt++) {
		GUID guid;
		WCHAR guid_text[40];
		if (FAILED(CoCreateGuid(&guid)) ||
			StringFromGUID2(&guid, guid_text, _countof(guid_text)) == 0)
			return;
		if (swprintf_s(leaf, _countof(leaf), L"read-%s.cache", guid_text) < 0 ||
			!scp_cache_path(cache, leaf, &cache_path))
			return;
		break;
	}
	if (cache_path == NULL)
		return;
	if (wcslen(path) > SIZE_MAX / sizeof(WCHAR) - 1u ||
		wcslen(cache_path) > SIZE_MAX / sizeof(WCHAR) - 1u) {
		free(cache_path);
		return;
	}
	key_bytes = (wcslen(path) + 1u) * sizeof(WCHAR);
	payload_path_bytes = (wcslen(cache_path) + 1u) * sizeof(WCHAR);
	if (key_bytes > SIZE_MAX - sizeof(*entry) ||
		payload_path_bytes > SIZE_MAX - sizeof(*entry) - key_bytes) {
		free(cache_path);
		return;
	}
	entry_metadata_bytes = sizeof(*entry) + key_bytes + payload_path_bytes;
	if (!scp_cache_reserve_metadata(cache, entry_metadata_bytes) ||
		!scp_cache_reserve_payload(cache, provenance->size)) {
		free(cache_path);
		return;
	}
	entry = (SCPFS_CACHE_ENTRY *)calloc(1, sizeof(*entry));
	if (entry == NULL) {
		free(cache_path);
		return;
	}
	entry->path = scp_cache_wcsdup(path);
	if (entry->path == NULL) {
		free(cache_path);
		free(entry);
		return;
	}
	/* Reserve both quotas before copying so a full cache directory never
	 * transiently exceeds the configured payload bound. */
	if (!CopyFileW(source_path, cache_path, TRUE)) {
		SetFileAttributesW(cache_path, FILE_ATTRIBUTE_NORMAL);
		DeleteFileW(cache_path);
		free(entry->path);
		free(cache_path);
		free(entry);
		return;
	}
	entry->kind = SCPFS_CACHE_PAYLOAD;
	entry->metadata_epoch = metadata_epoch;
	entry->content_epoch = content_epoch;
	entry->value.payload.path = cache_path;
	entry->value.payload.provenance = *provenance;
	entry->value.payload.size = (size_t)provenance->size;
	entry->metadata_bytes = entry_metadata_bytes;
	cache->payload_bytes += provenance->size;
	cache->metadata_bytes += entry->metadata_bytes;
	cache->metadata_entries++;
	scp_cache_link_recent(cache, entry);
	scp_cache_trim_metadata(cache);
	scp_cache_trim_payload(cache);
}

void scp_cache_evict_payload(SCPFS_CACHE *cache, PCWSTR path)
{
	if (cache != NULL && path != NULL)
		scp_cache_remove_key(cache, SCPFS_CACHE_PAYLOAD, path, true);
}

void scp_cache_invalidate_metadata(SCPFS_CACHE *cache)
{
	SCPFS_CACHE_ENTRY *entry = cache != NULL ? cache->most_recent : NULL;
	if (cache == NULL)
		return;
	cache->counters.invalidations++;
	while (entry != NULL) {
		SCPFS_CACHE_ENTRY *next = entry->next;
		if (entry->kind != SCPFS_CACHE_PAYLOAD)
			scp_cache_remove_entry(cache, entry, false);
		entry = next;
	}
}

void scp_cache_invalidate_all(SCPFS_CACHE *cache)
{
	if (cache == NULL)
		return;
	cache->counters.invalidations++;
	while (cache->most_recent != NULL)
		scp_cache_remove_entry(cache, cache->most_recent, false);
}

void scp_cache_record_monitor_bypass(SCPFS_CACHE *cache)
{
	if (cache != NULL)
		cache->counters.monitor_bypass++;
}

void scp_cache_record_payload_hit(SCPFS_CACHE *cache)
{
	if (cache != NULL)
		cache->counters.payload_hit++;
}

void scp_cache_record_payload_miss(SCPFS_CACHE *cache)
{
	if (cache != NULL)
		cache->counters.payload_miss++;
}

void scp_cache_get_counters(const SCPFS_CACHE *cache,
	SCPFS_CACHE_COUNTERS *counters_out)
{
	if (counters_out == NULL)
		return;
	if (cache != NULL)
		*counters_out = cache->counters;
	else
		memset(counters_out, 0, sizeof(*counters_out));
}
