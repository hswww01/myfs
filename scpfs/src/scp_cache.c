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
	struct SCPFS_CACHE_ENTRY *bucket_next;
	uint32_t hash;
	SCPFS_CACHE_KIND kind;
	WCHAR *path;
	size_t metadata_bytes;
	union {
		struct {
			bool absent;
			SCPFS_REMOTE_STAT stat;
		} stat;
		SCPFS_DIR_LIST list;
		struct {
			WCHAR *path;
			SCPFS_REMOTE_STAT provenance;
			uint64_t size;
		} payload;
	} value;
} SCPFS_CACHE_ENTRY;

/* Power of two; the metadata limit keeps chains short. */
#define SCPFS_CACHE_BUCKETS 65536u
/* Recent invalidations remembered for put admission. */
#define SCPFS_CACHE_RING 1024u
#define SCPFS_CACHE_COPY_CHUNK (1024u * 1024u)

typedef struct SCPFS_CACHE_CHANGE {
	uint64_t sequence;
	WCHAR *path;
} SCPFS_CACHE_CHANGE;

struct SCPFS_CACHE {
	SRWLOCK lock;
	WCHAR *session_directory;
	SCPFS_CACHE_ENTRY **buckets;
	SCPFS_CACHE_ENTRY *most_recent;
	SCPFS_CACHE_ENTRY *least_recent;
	size_t metadata_bytes;
	uint32_t metadata_entries;
	uint64_t payload_max_bytes;
	uint64_t payload_bytes;
	uint64_t sequence;
	/* Puts observed before floor predate an invalidate_all. */
	uint64_t floor;
	SCPFS_CACHE_CHANGE ring[SCPFS_CACHE_RING];
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

/* True when ancestor is path itself or one of its ancestor directories. */
static bool scp_cache_is_ancestor(PCWSTR ancestor, PCWSTR path)
{
	size_t length = wcslen(ancestor);
	if (length == 1u && ancestor[0] == L'\\')
		return true;
	return wcsncmp(ancestor, path, length) == 0 &&
		(path[length] == L'\0' || path[length] == L'\\');
}

static bool scp_cache_related(PCWSTR left, PCWSTR right)
{
	return scp_cache_is_ancestor(left, right) || scp_cache_is_ancestor(right, left);
}

/* Returns the parent of path in buffer, or NULL for the root. */
static WCHAR *scp_cache_parent(PCWSTR path)
{
	PCWSTR separator = wcsrchr(path, L'\\');
	size_t length;
	WCHAR *parent;
	if (separator == NULL || (separator == path && path[1] == L'\0'))
		return NULL;
	length = separator == path ? 1u : (size_t)(separator - path);
	parent = (WCHAR *)malloc((length + 1u) * sizeof(WCHAR));
	if (parent == NULL)
		return NULL;
	memcpy(parent, path, length * sizeof(WCHAR));
	parent[length] = L'\0';
	return parent;
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

static uint32_t scp_cache_hash(SCPFS_CACHE_KIND kind, PCWSTR path)
{
	uint32_t hash = 2166136261u ^ (uint32_t)kind;
	for (; *path != L'\0'; ++path)
		hash = (hash ^ (uint32_t)*path) * 16777619u;
	return hash;
}

static SCPFS_CACHE_ENTRY *scp_cache_find(SCPFS_CACHE *cache,
	SCPFS_CACHE_KIND kind, PCWSTR path)
{
	uint32_t hash = scp_cache_hash(kind, path);
	SCPFS_CACHE_ENTRY *entry;
	for (entry = cache->buckets[hash & (SCPFS_CACHE_BUCKETS - 1u)]; entry != NULL;
		entry = entry->bucket_next) {
		if (entry->hash == hash && entry->kind == kind && wcscmp(entry->path, path) == 0)
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
	SCPFS_CACHE_ENTRY **link = &cache->buckets[entry->hash & (SCPFS_CACHE_BUCKETS - 1u)];
	while (*link != NULL && *link != entry)
		link = &(*link)->bucket_next;
	if (*link == entry)
		*link = entry->bucket_next;
	scp_cache_unlink(cache, entry);
	if (entry->kind == SCPFS_CACHE_PAYLOAD) {
		cache->payload_bytes -= entry->value.payload.size <= cache->payload_bytes ?
			entry->value.payload.size : cache->payload_bytes;
		if (entry->value.payload.path != NULL) {
			SetFileAttributesW(entry->value.payload.path, FILE_ATTRIBUTE_NORMAL);
			DeleteFileW(entry->value.payload.path);
			free(entry->value.payload.path);
		}
	} else if (entry->kind == SCPFS_CACHE_LIST) {
		scp_cache_free_list(&entry->value.list);
	}
	cache->metadata_bytes -= entry->metadata_bytes <= cache->metadata_bytes ?
		entry->metadata_bytes : cache->metadata_bytes;
	if (cache->metadata_entries != 0)
		cache->metadata_entries--;
	free(entry->path);
	free(entry);
	if (eviction)
		cache->counters.evictions++;
}

static void scp_cache_remove_key(SCPFS_CACHE *cache,
	SCPFS_CACHE_KIND kind, PCWSTR path)
{
	SCPFS_CACHE_ENTRY *entry = scp_cache_find(cache, kind, path);
	if (entry != NULL)
		scp_cache_remove_entry(cache, entry, false);
}

/* Makes room for one more entry of the given size; false if it never fits. */
static bool scp_cache_reserve_metadata(SCPFS_CACHE *cache, size_t bytes)
{
	if (bytes > SCPFS_CACHE_METADATA_LIMIT_BYTES)
		return false;
	while (cache->metadata_bytes > SCPFS_CACHE_METADATA_LIMIT_BYTES - bytes ||
		cache->metadata_entries >= SCPFS_CACHE_METADATA_LIMIT_ENTRIES) {
		if (cache->least_recent == NULL)
			return false;
		scp_cache_remove_entry(cache, cache->least_recent, true);
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

/* Allocates, indexes and accounts a new entry for (kind, path), replacing
 * any previous one. extra_bytes is the value's own heap footprint. */
static SCPFS_CACHE_ENTRY *scp_cache_new_entry(SCPFS_CACHE *cache,
	SCPFS_CACHE_KIND kind, PCWSTR path, size_t extra_bytes)
{
	SCPFS_CACHE_ENTRY *entry;
	SCPFS_CACHE_ENTRY **bucket;
	size_t path_length = wcslen(path);
	size_t bytes;
	if (path_length > SIZE_MAX / sizeof(WCHAR) - 1u)
		return NULL;
	bytes = sizeof(*entry) + (path_length + 1u) * sizeof(WCHAR);
	if (extra_bytes > SIZE_MAX - bytes)
		return NULL;
	bytes += extra_bytes;
	scp_cache_remove_key(cache, kind, path);
	if (!scp_cache_reserve_metadata(cache, bytes))
		return NULL;
	entry = (SCPFS_CACHE_ENTRY *)calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;
	entry->path = scp_cache_wcsdup(path);
	if (entry->path == NULL) {
		free(entry);
		return NULL;
	}
	entry->kind = kind;
	entry->metadata_bytes = bytes;
	entry->hash = scp_cache_hash(kind, path);
	bucket = &cache->buckets[entry->hash & (SCPFS_CACHE_BUCKETS - 1u)];
	entry->bucket_next = *bucket;
	*bucket = entry;
	scp_cache_link_recent(cache, entry);
	cache->metadata_bytes += bytes;
	cache->metadata_entries++;
	return entry;
}

/* Lock held. A put is admissible unless a related path changed after it was observed. */
static bool scp_cache_admissible(SCPFS_CACHE *cache, PCWSTR path, uint64_t sequence)
{
	uint64_t change;
	if (sequence < cache->floor || sequence > cache->sequence ||
		cache->sequence - sequence >= SCPFS_CACHE_RING)
		goto reject;
	for (change = sequence + 1u; change <= cache->sequence; change++) {
		const SCPFS_CACHE_CHANGE *slot = &cache->ring[change % SCPFS_CACHE_RING];
		if (slot->sequence != change || slot->path == NULL ||
			scp_cache_related(slot->path, path))
			goto reject;
	}
	return true;
reject:
	cache->counters.rejected_puts++;
	return false;
}

static void scp_cache_record_change(SCPFS_CACHE *cache, PCWSTR path)
{
	SCPFS_CACHE_CHANGE *slot;
	cache->sequence++;
	slot = &cache->ring[cache->sequence % SCPFS_CACHE_RING];
	free(slot->path);
	slot->sequence = cache->sequence;
	slot->path = scp_cache_wcsdup(path);
	if (slot->path == NULL)
		cache->floor = cache->sequence;
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
	InitializeSRWLock(&cache->lock);
	cache->buckets = (SCPFS_CACHE_ENTRY **)calloc(SCPFS_CACHE_BUCKETS,
		sizeof(*cache->buckets));
	cache->session_directory = scp_cache_wcsdup(session_directory);
	if (cache->buckets == NULL || cache->session_directory == NULL) {
		free(cache->buckets);
		free(cache->session_directory);
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
	size_t index;
	if (cache == NULL)
		return;
	while (cache->most_recent != NULL)
		scp_cache_remove_entry(cache, cache->most_recent, false);
	for (index = 0; index < SCPFS_CACHE_RING; index++)
		free(cache->ring[index].path);
	free(cache->buckets);
	free(cache->session_directory);
	free(cache);
}

uint64_t scp_cache_sequence(SCPFS_CACHE *cache)
{
	uint64_t sequence;
	if (cache == NULL)
		return 0;
	AcquireSRWLockExclusive(&cache->lock);
	sequence = cache->sequence;
	ReleaseSRWLockExclusive(&cache->lock);
	return sequence;
}

SCPFS_CACHE_LOOKUP scp_cache_get_stat(SCPFS_CACHE *cache, PCWSTR path,
	SCPFS_REMOTE_STAT *stat_out)
{
	SCPFS_CACHE_ENTRY *entry;
	SCPFS_CACHE_LOOKUP result = SCPFS_CACHE_MISS;
	if (cache == NULL || path == NULL || stat_out == NULL)
		return SCPFS_CACHE_MISS;
	AcquireSRWLockExclusive(&cache->lock);
	entry = scp_cache_find(cache, SCPFS_CACHE_STAT, path);
	if (entry == NULL) {
		cache->counters.stat_miss++;
	} else {
		cache->counters.stat_hit++;
		scp_cache_touch(cache, entry);
		if (entry->value.stat.absent) {
			result = SCPFS_CACHE_ABSENT;
		} else {
			*stat_out = entry->value.stat.stat;
			result = SCPFS_CACHE_PRESENT;
		}
	}
	ReleaseSRWLockExclusive(&cache->lock);
	return result;
}

static void scp_cache_put_stat_locked(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat)
{
	SCPFS_CACHE_ENTRY *entry = scp_cache_new_entry(cache, SCPFS_CACHE_STAT, path, 0);
	if (entry == NULL)
		return;
	entry->value.stat.absent = stat == NULL;
	if (stat != NULL)
		entry->value.stat.stat = *stat;
}

void scp_cache_put_stat(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, uint64_t sequence)
{
	if (cache == NULL || path == NULL)
		return;
	AcquireSRWLockExclusive(&cache->lock);
	if (scp_cache_admissible(cache, path, sequence))
		scp_cache_put_stat_locked(cache, path, stat);
	ReleaseSRWLockExclusive(&cache->lock);
}

bool scp_cache_get_list(SCPFS_CACHE *cache, PCWSTR path,
	SCPFS_DIR_LIST *list_out)
{
	SCPFS_CACHE_ENTRY *entry;
	bool hit = false;
	if (cache == NULL || path == NULL || list_out == NULL)
		return false;
	memset(list_out, 0, sizeof(*list_out));
	AcquireSRWLockExclusive(&cache->lock);
	entry = scp_cache_find(cache, SCPFS_CACHE_LIST, path);
	if (entry != NULL && scp_cache_clone_list(&entry->value.list, list_out)) {
		hit = true;
		cache->counters.list_hit++;
		scp_cache_touch(cache, entry);
	} else {
		cache->counters.list_miss++;
	}
	ReleaseSRWLockExclusive(&cache->lock);
	return hit;
}

void scp_cache_put_list(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_DIR_LIST *list, uint64_t sequence)
{
	SCPFS_CACHE_ENTRY *entry;
	size_t list_bytes;
	size_t path_length;
	size_t index;
	WCHAR *child;
	if (cache == NULL || path == NULL || list == NULL ||
		!scp_cache_list_size(list, &list_bytes))
		return;
	path_length = wcslen(path);
	AcquireSRWLockExclusive(&cache->lock);
	if (!scp_cache_admissible(cache, path, sequence))
		goto done;
	/* Child stats first, so the listing itself is the most recent entry. */
	for (index = 0; index < list->count; index++) {
		const SCPFS_DIR_ENTRY *item = &list->entries[index];
		size_t bytes = (path_length + item->name_length + 2u) * sizeof(WCHAR);
		child = (WCHAR *)malloc(bytes);
		if (child == NULL)
			continue;
		memcpy(child, path, path_length * sizeof(WCHAR));
		{
			size_t used = path_length;
			if (used == 0 || child[used - 1u] != L'\\')
				child[used++] = L'\\';
			memcpy(child + used, item->name, item->name_length * sizeof(WCHAR));
			child[used + item->name_length] = L'\0';
		}
		scp_cache_put_stat_locked(cache, child, &item->stat);
		free(child);
	}
	entry = scp_cache_new_entry(cache, SCPFS_CACHE_LIST, path, list_bytes);
	if (entry != NULL && !scp_cache_clone_list(list, &entry->value.list))
		scp_cache_remove_entry(cache, entry, false);
done:
	ReleaseSRWLockExclusive(&cache->lock);
}

static bool scp_cache_same_payload(const SCPFS_REMOTE_STAT *left,
	const SCPFS_REMOTE_STAT *right)
{
	return left->type == right->type && left->device == right->device &&
		left->inode == right->inode && left->size == right->size &&
		left->mtime_ns == right->mtime_ns;
}

static bool scp_cache_copy_handle(HANDLE source, PCWSTR destination)
{
	HANDLE target;
	BYTE *buffer;
	bool ok = false;
	target = CreateFileW(destination, GENERIC_WRITE, 0, NULL, CREATE_NEW,
		FILE_ATTRIBUTE_TEMPORARY, NULL);
	if (target == INVALID_HANDLE_VALUE)
		return false;
	buffer = (BYTE *)malloc(SCPFS_CACHE_COPY_CHUNK);
	if (buffer != NULL) {
		for (;;) {
			DWORD read = 0;
			DWORD written = 0;
			if (!ReadFile(source, buffer, SCPFS_CACHE_COPY_CHUNK, &read, NULL))
				break;
			if (read == 0) {
				ok = true;
				break;
			}
			if (!WriteFile(target, buffer, read, &written, NULL) || written != read)
				break;
		}
		free(buffer);
	}
	CloseHandle(target);
	if (!ok)
		DeleteFileW(destination);
	return ok;
}

bool scp_cache_copy_payload(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *expected, PCWSTR destination)
{
	SCPFS_CACHE_ENTRY *entry;
	HANDLE source = INVALID_HANDLE_VALUE;
	bool copied;
	if (cache == NULL || path == NULL || expected == NULL || destination == NULL)
		return false;
	AcquireSRWLockExclusive(&cache->lock);
	entry = scp_cache_find(cache, SCPFS_CACHE_PAYLOAD, path);
	if (entry != NULL && !scp_cache_same_payload(&entry->value.payload.provenance,
		expected)) {
		scp_cache_remove_entry(cache, entry, true);
		entry = NULL;
	}
	if (entry != NULL) {
		/* Share delete: an invalidation may unlink the file mid-copy. */
		source = CreateFileW(entry->value.payload.path, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
			FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (source == INVALID_HANDLE_VALUE)
			scp_cache_remove_entry(cache, entry, true);
		else
			scp_cache_touch(cache, entry);
	}
	if (source == INVALID_HANDLE_VALUE)
		cache->counters.payload_miss++;
	ReleaseSRWLockExclusive(&cache->lock);
	if (source == INVALID_HANDLE_VALUE)
		return false;
	copied = scp_cache_copy_handle(source, destination);
	CloseHandle(source);
	AcquireSRWLockExclusive(&cache->lock);
	if (copied)
		cache->counters.payload_hit++;
	else
		cache->counters.payload_miss++;
	ReleaseSRWLockExclusive(&cache->lock);
	return copied;
}

void scp_cache_put_payload(SCPFS_CACHE *cache, PCWSTR path,
	PCWSTR source_path, const SCPFS_REMOTE_STAT *provenance, uint64_t sequence)
{
	SCPFS_CACHE_ENTRY *entry;
	WCHAR leaf[64];
	GUID guid;
	WCHAR guid_text[40];
	WCHAR *cache_path;
	size_t directory_length;
	size_t cache_path_bytes;
	LARGE_INTEGER size;
	HANDLE source;
	bool admitted = false;
	if (cache == NULL || path == NULL || source_path == NULL || provenance == NULL ||
		provenance->type != SCPFS_REMOTE_FILE ||
		provenance->size > cache->payload_max_bytes)
		return;
	if (FAILED(CoCreateGuid(&guid)) ||
		StringFromGUID2(&guid, guid_text, _countof(guid_text)) == 0 ||
		swprintf_s(leaf, _countof(leaf), L"read-%s.cache", guid_text) < 0)
		return;
	directory_length = wcslen(cache->session_directory);
	cache_path_bytes = (directory_length + wcslen(leaf) + 2u) * sizeof(WCHAR);
	cache_path = (WCHAR *)malloc(cache_path_bytes);
	if (cache_path == NULL)
		return;
	memcpy(cache_path, cache->session_directory, directory_length * sizeof(WCHAR));
	if (directory_length != 0 && cache_path[directory_length - 1u] != L'\\')
		cache_path[directory_length++] = L'\\';
	wcscpy_s(cache_path + directory_length,
		cache_path_bytes / sizeof(WCHAR) - directory_length, leaf);
	/* Copy outside the lock; the monitor must never wait on disk I/O. */
	source = CreateFileW(source_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (source == INVALID_HANDLE_VALUE) {
		free(cache_path);
		return;
	}
	if (!GetFileSizeEx(source, &size) || size.QuadPart < 0 ||
		(uint64_t)size.QuadPart != provenance->size ||
		!scp_cache_copy_handle(source, cache_path)) {
		CloseHandle(source);
		free(cache_path);
		return;
	}
	CloseHandle(source);
	AcquireSRWLockExclusive(&cache->lock);
	if (scp_cache_admissible(cache, path, sequence)) {
		scp_cache_remove_key(cache, SCPFS_CACHE_PAYLOAD, path);
		if (scp_cache_reserve_payload(cache, provenance->size)) {
			entry = scp_cache_new_entry(cache, SCPFS_CACHE_PAYLOAD, path,
				cache_path_bytes);
			if (entry != NULL) {
				entry->value.payload.path = cache_path;
				entry->value.payload.provenance = *provenance;
				entry->value.payload.size = provenance->size;
				cache->payload_bytes += provenance->size;
				admitted = true;
			}
		}
	}
	ReleaseSRWLockExclusive(&cache->lock);
	if (!admitted) {
		SetFileAttributesW(cache_path, FILE_ATTRIBUTE_NORMAL);
		DeleteFileW(cache_path);
		free(cache_path);
	}
}

void scp_cache_invalidate_path(SCPFS_CACHE *cache, PCWSTR path, unsigned kind)
{
	WCHAR *parent;
	if (cache == NULL || path == NULL)
		return;
	AcquireSRWLockExclusive(&cache->lock);
	cache->counters.invalidations++;
	scp_cache_record_change(cache, path);
	scp_cache_remove_key(cache, SCPFS_CACHE_STAT, path);
	parent = scp_cache_parent(path);
	if (parent != NULL)
		scp_cache_remove_key(cache, SCPFS_CACHE_LIST, parent);
	if (kind & (SCPFS_CACHE_CHANGE_CONTENT | SCPFS_CACHE_CHANGE_SUBTREE)) {
		scp_cache_remove_key(cache, SCPFS_CACHE_LIST, path);
		scp_cache_remove_key(cache, SCPFS_CACHE_PAYLOAD, path);
		if (parent != NULL) {
			/* The parent's mtime moved, and with it the grandparent listing. */
			WCHAR *grandparent = scp_cache_parent(parent);
			scp_cache_remove_key(cache, SCPFS_CACHE_STAT, parent);
			if (grandparent != NULL)
				scp_cache_remove_key(cache, SCPFS_CACHE_LIST, grandparent);
			free(grandparent);
		}
	}
	if (kind & SCPFS_CACHE_CHANGE_SUBTREE) {
		SCPFS_CACHE_ENTRY *entry = cache->most_recent;
		while (entry != NULL) {
			SCPFS_CACHE_ENTRY *next = entry->next;
			if (scp_cache_is_ancestor(path, entry->path))
				scp_cache_remove_entry(cache, entry, false);
			entry = next;
		}
	}
	free(parent);
	ReleaseSRWLockExclusive(&cache->lock);
}

void scp_cache_invalidate_all(SCPFS_CACHE *cache)
{
	if (cache == NULL)
		return;
	AcquireSRWLockExclusive(&cache->lock);
	cache->counters.invalidations++;
	cache->sequence++;
	cache->floor = cache->sequence;
	while (cache->most_recent != NULL)
		scp_cache_remove_entry(cache, cache->most_recent, false);
	ReleaseSRWLockExclusive(&cache->lock);
}

void scp_cache_get_counters(SCPFS_CACHE *cache,
	SCPFS_CACHE_COUNTERS *counters_out)
{
	if (counters_out == NULL)
		return;
	memset(counters_out, 0, sizeof(*counters_out));
	if (cache == NULL)
		return;
	AcquireSRWLockExclusive(&cache->lock);
	*counters_out = cache->counters;
	ReleaseSRWLockExclusive(&cache->lock);
}
