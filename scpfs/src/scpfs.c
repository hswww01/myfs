/*
 * WinFsp callback and lifecycle adapter for SCPFS.
 * The callback table and dispatcher lifecycle follow the WinFsp adapter
 * structure used by D:\work\memfs\src\memfs_winfsp.c; this file is a new
 * SCP/cache implementation and does not include memfs storage code.
 */
#include "scpfs.h"
#include "scpfs_driver.h"
#include "scp_cache.h"
#include "scp_watch.h"
#include <ntstatus.h>
#include "fs_frontend.h"

#include <bcrypt.h>
#include <winfsp/winfsp.h>

#include <objbase.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define SCPFS_MAX_PATH_CHARS 32760U
#define SCPFS_MAX_COMPONENT_CHARS 255U
#define SCPFS_SECTOR_SIZE 4096U
#define SCPFS_DEFAULT_CACHE_ROOT L"scpfs"
#define SCPFS_MAX_COMMAND_TIMEOUT_MS 540000U


typedef struct SCPFS_HANDLE SCPFS_HANDLE;

typedef struct SCPFS_CACHE_DIAGNOSTICS {
	uint64_t cold_attempt;
	uint64_t cold_unavailable;
	uint64_t cold_watch_unhealthy;
	uint64_t cold_ensure_failed;
	uint64_t cold_barrier_failed;
	uint64_t cold_pre_content_changed;
	uint64_t cold_post_barrier_failed;
	uint64_t cold_post_unhealthy;
	uint64_t cold_post_content_changed;
	uint64_t cold_stat_failed;
	uint64_t cold_verify_barrier_failed;
	uint64_t cold_verify_unhealthy;
	uint64_t cold_verify_content_changed;
	uint64_t cold_verify_metadata_changed;
	uint64_t cold_provenance_mismatch;
	uint64_t cold_atime_mismatch;
	uint64_t cold_put_attempt;
	uint64_t warm_candidate;
	uint64_t warm_metadata_stale;
	uint64_t warm_watch_unhealthy;
	uint64_t warm_ensure_failed;
	uint64_t warm_barrier_failed;
	uint64_t warm_stat_failed;
	uint64_t warm_verify_barrier_failed;
	uint64_t warm_verify_unhealthy;
	uint64_t warm_content_changed;
	uint64_t warm_metadata_changed;
	uint64_t warm_provenance_mismatch;
	uint64_t warm_copy_failed;
	uint32_t provenance_mismatch_mask;
} SCPFS_CACHE_DIAGNOSTICS;

#define SCPFS_CACHE_DIAG(instance, counter) \
	(void)InterlockedIncrement64((volatile LONG64 *)&(instance)->cache_diagnostics.counter)

struct SCPFS_HANDLE {
	SCPFS_HANDLE *previous;
	SCPFS_HANDLE *next;
	struct SCPFS *owner;
	WCHAR *remote_path;
	WCHAR *cache_path;
	HANDLE cache_file;
	SCPFS_REMOTE_STAT snapshot;
	SCPFS_REMOTE_STAT current;
	uint64_t file_size;
	uint64_t index_number;
	uint32_t mode;
	int64_t pending_atime_ns;
	int64_t pending_mtime_ns;
	bool remote_exists;
	bool directory;
	bool metadata_only;
	bool stale_namespace;
	bool cleaned_up;
	bool modified_after_cleanup;
	bool dirty;
	bool mode_dirty;
	bool atime_dirty;
	bool mtime_dirty;
	bool deleted;
	bool delete_failed;
	bool inbox_attempted;
	bool inbox_recovery_pending;
	bool inbox_input_consumed;
	bool inbox_completed;
	bool inbox_outcome_unknown;
	bool inbox_output_published;
	int inbox_exit_code;
	WCHAR *inbox_claim_path;
	WCHAR *inbox_failure_stage;
	/* WinFsp directory buffer holding this handle's enumeration snapshot. */
	PVOID dir_buffer;
};

struct SCPFS {
	FSP_FILE_SYSTEM *file_system;
	FSF_WINFSP *frontend;
	SCPFS_BACKEND *backend;
	SCPFS_CACHE *read_cache;
	SCPFS_WATCH *watch;
	SCPFS_WATCH_STATE observed_watch;
	bool observed_watch_valid;
	SCPFS_HANDLE *handles;
	SRWLOCK lock;
	volatile LONG dispatcher_stop_reason;
	bool dispatcher_started;
	WCHAR *cache_directory;
	WCHAR *remote_host;
	WCHAR *remote_root;
	uint32_t command_timeout_ms;
	uint32_t read_cache_max_mib;
	PSECURITY_DESCRIPTOR default_security;
	DWORD default_security_size;
	WCHAR volume_label[32];
	uint16_t volume_label_bytes;
	/* Remote statfs sample; Explorer refuses copies onto a volume reporting 0 free. */
	uint64_t volume_total_bytes;
	uint64_t volume_free_bytes;
	ULONGLONG volume_sample_tick;
	volatile LONG cache_counter;
	SCPFS_CACHE_DIAGNOSTICS cache_diagnostics;
};

enum {
	SCPFS_DISPATCHER_ACTIVE = 0,
	SCPFS_DISPATCHER_STOPPED_NORMALLY = 1,
	SCPFS_DISPATCHER_STOPPED_ABNORMALLY = 2
};

typedef BOOLEAN(NTAPI *SCPFS_NAME_MATCH_FN)(
	PUNICODE_STRING, PUNICODE_STRING, BOOLEAN, PWCH);
static INIT_ONCE g_scpfs_name_match_once = INIT_ONCE_STATIC_INIT;
static SCPFS_NAME_MATCH_FN g_scpfs_name_match_fn;

static BOOL CALLBACK scpfs_name_match_initialize(
	PINIT_ONCE once, PVOID parameter, PVOID *context)
{
	HMODULE ntdll;
	(void)once;
	(void)parameter;
	(void)context;
	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll != NULL)
		g_scpfs_name_match_fn = (SCPFS_NAME_MATCH_FN)GetProcAddress(
			ntdll, "RtlIsNameInUnUpcasedExpression");
	return TRUE;
}

static NTSTATUS scpfs_map_win32_error(DWORD error)
{
	switch (error) {
	case ERROR_SUCCESS:
		return STATUS_SUCCESS;
	case ERROR_FILE_NOT_FOUND:
		return STATUS_OBJECT_NAME_NOT_FOUND;
	case ERROR_PATH_NOT_FOUND:
		return STATUS_OBJECT_PATH_NOT_FOUND;
	case ERROR_ALREADY_EXISTS:
	case ERROR_FILE_EXISTS:
		return STATUS_OBJECT_NAME_COLLISION;
	case ERROR_ACCESS_DENIED:
	case ERROR_SHARING_VIOLATION:
		return error == ERROR_SHARING_VIOLATION ? STATUS_SHARING_VIOLATION : STATUS_ACCESS_DENIED;
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return STATUS_INSUFFICIENT_RESOURCES;
	case ERROR_DISK_FULL:
		return STATUS_DISK_FULL;
	case ERROR_INVALID_NAME:
	case ERROR_INVALID_PARAMETER:
		return STATUS_INVALID_PARAMETER;
	case ERROR_DIRECTORY:
		return STATUS_NOT_A_DIRECTORY;
	default:
		return STATUS_UNSUCCESSFUL;
	}
}

static NTSTATUS scpfs_map_backend_not_found(NTSTATUS status)
{
	if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND ||
		status == STATUS_NO_SUCH_FILE)
		return status;
	return status;
}

static void scpfs_log_failure(SCPFS_HANDLE *handle, PCWSTR operation,
	NTSTATUS status, PCWSTR recovery_path)
{
	SCPFS *instance = handle != NULL ? handle->owner : NULL;
	WCHAR *message;
	char *message_utf8;
	size_t capacity;
	int length;
	int utf8_length;
	DWORD written;
	HANDLE stderr_handle;
	PCWSTR remote_path = handle != NULL ? handle->remote_path : L"(unknown)";
	PCWSTR recovery = recovery_path != NULL ? recovery_path : L"(unavailable)";
	PCWSTR stage = handle != NULL && handle->inbox_failure_stage != NULL ?
		handle->inbox_failure_stage : L"(none)";

	capacity = wcslen(remote_path) + wcslen(recovery) + wcslen(stage) + 512;
	if (instance != NULL) {
		if (instance->remote_host != NULL)
			capacity += wcslen(instance->remote_host);
		if (instance->remote_root != NULL)
			capacity += wcslen(instance->remote_root);
	}
	if (capacity > SIZE_MAX / sizeof(WCHAR))
		return;
	message = (WCHAR *)malloc(capacity * sizeof(WCHAR));
	if (message == NULL)
		return;
	length = swprintf_s(message, capacity,
		L"SCPFS: %s failed for %s on %s:%s (status 0x%08lX, stage=%s); cache/recovery: %s\r\n",
		operation != NULL ? operation : L"operation", remote_path,
		instance != NULL && instance->remote_host != NULL ? instance->remote_host : L"?",
		instance != NULL && instance->remote_root != NULL ? instance->remote_root : L"?",
		(unsigned long)status, stage, recovery);
	if (length >= 0) {
		OutputDebugStringW(message);
		utf8_length = WideCharToMultiByte(CP_UTF8, 0, message, length,
			NULL, 0, NULL, NULL);
		if (utf8_length > 0) {
			message_utf8 = (char *)malloc((size_t)utf8_length);
			if (message_utf8 != NULL && WideCharToMultiByte(CP_UTF8, 0,
				message, length, message_utf8, utf8_length, NULL, NULL) == utf8_length) {
			stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
			if (stderr_handle != NULL && stderr_handle != INVALID_HANDLE_VALUE)
				WriteFile(stderr_handle, message_utf8, (DWORD)utf8_length, &written, NULL);
			}
			free(message_utf8);
		}
	}
	free(message);
}

static void scpfs_log_open_failure(SCPFS *instance, PCWSTR path,
	PCWSTR operation, NTSTATUS status)
{
	SCPFS_HANDLE log_handle;
	memset(&log_handle, 0, sizeof(log_handle));
	log_handle.owner = instance;
	log_handle.remote_path = (WCHAR *)path;
	scpfs_log_failure(&log_handle, operation, status, NULL);
}

static void scpfs_log_message(PCWSTR message)
{
	int message_chars;
	int utf8_length;
	char *message_utf8;
	DWORD written;
	HANDLE stderr_handle;
	if (message == NULL)
		return;
	OutputDebugStringW(message);
	message_chars = (int)wcslen(message);
	utf8_length = WideCharToMultiByte(CP_UTF8, 0, message, message_chars,
		NULL, 0, NULL, NULL);
	if (utf8_length <= 0)
		return;
	message_utf8 = (char *)malloc((size_t)utf8_length);
	if (message_utf8 == NULL)
		return;
	if (WideCharToMultiByte(CP_UTF8, 0, message, message_chars,
		message_utf8, utf8_length, NULL, NULL) == utf8_length) {
		stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
		if (stderr_handle != NULL && stderr_handle != INVALID_HANDLE_VALUE)
			WriteFile(stderr_handle, message_utf8, (DWORD)utf8_length, &written, NULL);
	}
	free(message_utf8);
}

static void scpfs_log_command_exit(const SCPFS_HANDLE *handle, int exit_code)
{
	const SCPFS *instance;
	const WCHAR *host;
	const WCHAR *root;
	const WCHAR *path;
	const WCHAR *claim;
	WCHAR *message;
	size_t capacity;
	int length;
	if (handle == NULL || (instance = handle->owner) == NULL)
		return;
	host = instance->remote_host != NULL ? instance->remote_host : L"?";
	root = instance->remote_root != NULL ? instance->remote_root : L"?";
	path = handle->remote_path != NULL ? handle->remote_path : L"?";
	claim = handle->inbox_claim_path != NULL ? handle->inbox_claim_path : L"(none)";
	capacity = wcslen(host) + wcslen(root) + wcslen(path) + wcslen(claim) + 192;
	if (capacity > SIZE_MAX / sizeof(WCHAR))
		return;
	message = (WCHAR *)malloc(capacity * sizeof(WCHAR));
	if (message == NULL)
		return;
	length = swprintf_s(message, capacity,
		L"SCPFS: remote command completed with exit code %d for %s on %s:%s; claim=%s\r\n",
		exit_code, path, host, root, claim);
	if (length >= 0)
		scpfs_log_message(message);
	free(message);
}

static WCHAR *scpfs_wcsdup(PCWSTR value)
{
	size_t count;
	WCHAR *copy;

	if (value == NULL)
		return NULL;
	count = wcslen(value) + 1;
	if (count > SIZE_MAX / sizeof(WCHAR))
		return NULL;
	copy = (WCHAR *)malloc(count * sizeof(WCHAR));
	if (copy != NULL)
		memcpy(copy, value, count * sizeof(WCHAR));
	return copy;
}

static SCPFS *scpfs_from_file_system(FSP_FILE_SYSTEM *file_system)
{
	return (SCPFS *)fs_frontend_backend_context(file_system);
}

static bool scpfs_is_root_path(PCWSTR path)
{
	return path != NULL && path[0] == L'\\' && path[1] == L'\0';
}

static bool scpfs_is_inbox_command_path(PCWSTR path)
{
	PCWSTR leaf;
	if (path == NULL)
		return false;
	leaf = wcsrchr(path, L'\\');
	leaf = leaf != NULL ? leaf + 1 : path;
	return wcscmp(leaf, L".in.txt") == 0;
}

static bool scpfs_is_device_component(PCWSTR component, size_t length)
{
	WCHAR base[8];
	size_t base_length = 0;
	size_t i;

	while (base_length < length && component[base_length] != L'.')
		base_length++;
	if (base_length == 0 || base_length >= _countof(base))
		return false;
	for (i = 0; i < base_length; i++) {
		WCHAR c = component[i];
		if (c >= L'a' && c <= L'z')
			c = (WCHAR)(c - L'a' + L'A');
		base[i] = c;
	}
	base[base_length] = L'\0';
	if (wcscmp(base, L"CON") == 0 || wcscmp(base, L"PRN") == 0 ||
		wcscmp(base, L"AUX") == 0 || wcscmp(base, L"NUL") == 0)
		return true;
	return base_length == 4 &&
		((memcmp(base, L"COM", 3 * sizeof(WCHAR)) == 0) ||
		 (memcmp(base, L"LPT", 3 * sizeof(WCHAR)) == 0)) &&
		base[3] >= L'1' && base[3] <= L'9';
}

static bool scpfs_valid_component(PCWSTR component, size_t length)
{
	size_t i;

	if (length == 0 || length > SCPFS_MAX_COMPONENT_CHARS ||
		(component[0] == L'.' && (length == 1 || (length == 2 && component[1] == L'.'))))
		return false;
	if (component[length - 1] == L'.' || component[length - 1] == L' ' ||
		scpfs_is_device_component(component, length))
		return false;
	for (i = 0; i < length; i++) {
		WCHAR c = component[i];
		if (c < 0x20 || c == L'/' || c == L'\\' || c == L':' || c == L'*' ||
			c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|')
			return false;
		if (c >= 0xD800 && c <= 0xDBFF) {
			if (i + 1 >= length || component[i + 1] < 0xDC00 || component[i + 1] > 0xDFFF)
				return false;
			i++;
		} else if (c >= 0xDC00 && c <= 0xDFFF) {
			return false;
		}
	}
	return true;
}

static bool scpfs_valid_path(PCWSTR path, bool allow_root)
{
	size_t total;
	size_t start;
	size_t i;

	if (path == NULL || path[0] != L'\\')
		return false;
	total = wcslen(path);
	if (total > SCPFS_MAX_PATH_CHARS)
		return false;
	if (total == 1)
		return allow_root;
	start = 1;
	for (i = 1; i <= total; i++) {
		if (path[i] == L'\\' || path[i] == L'\0') {
			if (!scpfs_valid_component(path + start, i - start))
				return false;
			start = i + 1;
		}
	}
	return true;
}

static bool scpfs_valid_name(PCWSTR name, size_t length)
{
	return scpfs_valid_component(name, length);
}

static bool scpfs_join_path(PCWSTR parent, PCWSTR name, size_t name_length,
	WCHAR **path_out)
{
	size_t parent_length;
	size_t total;
	WCHAR *path;

	if (path_out == NULL || !scpfs_valid_name(name, name_length))
		return false;
	*path_out = NULL;
	parent_length = wcslen(parent);
	if (parent_length > SCPFS_MAX_PATH_CHARS ||
		name_length > SCPFS_MAX_PATH_CHARS - parent_length - 1)
		return false;
	total = parent_length + name_length + (scpfs_is_root_path(parent) ? 0 : 1);
	path = (WCHAR *)malloc((total + 1) * sizeof(WCHAR));
	if (path == NULL)
		return false;
	memcpy(path, parent, parent_length * sizeof(WCHAR));
	if (!scpfs_is_root_path(parent))
		path[parent_length++] = L'\\';
	memcpy(path + parent_length, name, name_length * sizeof(WCHAR));
	path[parent_length + name_length] = L'\0';
	if (!scpfs_valid_path(path, false)) {
		free(path);
		return false;
	}
	*path_out = path;
	return true;
}

static bool scpfs_path_equal(PCWSTR left, PCWSTR right)
{
	return left != NULL && right != NULL && wcscmp(left, right) == 0;
}

static bool scpfs_path_is_descendant(PCWSTR path, PCWSTR parent)
{
	size_t parent_length;

	if (path == NULL || parent == NULL || scpfs_is_root_path(parent))
		return path != NULL && parent != NULL && scpfs_is_root_path(parent) && !scpfs_is_root_path(path);
	parent_length = wcslen(parent);
	return wcsncmp(path, parent, parent_length) == 0 && path[parent_length] == L'\\';
}

static WCHAR *scpfs_parent_path(PCWSTR path)
{
	const WCHAR *separator;
	size_t length;
	WCHAR *parent;

	if (path == NULL || scpfs_is_root_path(path))
		return NULL;
	separator = wcsrchr(path, L'\\');
	if (separator == NULL || separator == path)
		return scpfs_wcsdup(L"\\");
	length = (size_t)(separator - path);
	parent = (WCHAR *)malloc((length + 1) * sizeof(WCHAR));
	if (parent != NULL) {
		memcpy(parent, path, length * sizeof(WCHAR));
		parent[length] = L'\0';
	}
	return parent;
}

static uint64_t scpfs_unix_ns_to_filetime(int64_t unix_ns)
{
	const uint64_t epoch = UINT64_C(116444736000000000);
	uint64_t ticks;

	if (unix_ns < 0) {
		uint64_t before = (uint64_t)(-(unix_ns + 1)) + 1;
		uint64_t delta = before / 100;
		return delta > epoch ? 0 : epoch - delta;
	}
	ticks = (uint64_t)unix_ns / 100;
	return UINT64_MAX - epoch < ticks ? UINT64_MAX : epoch + ticks;
}

static int64_t scpfs_filetime_to_unix_ns(uint64_t filetime)
{
	const uint64_t epoch = UINT64_C(116444736000000000);
	uint64_t delta;
	uint64_t ns;

	if (filetime >= epoch) {
		delta = filetime - epoch;
		if (delta > (uint64_t)INT64_MAX / 100)
			return INT64_MAX;
		return (int64_t)(delta * 100);
	}
	delta = epoch - filetime;
	if (delta > (uint64_t)INT64_MAX / 100)
		return INT64_MIN;
	ns = delta * 100;
	return -(int64_t)ns;
}

static uint32_t scpfs_attributes(PCWSTR path, const SCPFS_REMOTE_STAT *stat)
{
	uint32_t attributes = FILE_ATTRIBUTE_ARCHIVE;
	PCWSTR leaf = wcsrchr(path, L'\\');

	if (stat->type == SCPFS_REMOTE_DIRECTORY) {
		attributes = FILE_ATTRIBUTE_DIRECTORY;
	} else {
		if (leaf != NULL && leaf[1] == L'.')
			attributes |= FILE_ATTRIBUTE_HIDDEN;
		if ((stat->mode & 0222U) == 0)
			attributes |= FILE_ATTRIBUTE_READONLY;
		if (attributes == 0)
			attributes = FILE_ATTRIBUTE_NORMAL;
	}
	return attributes;
}

static uint64_t scpfs_index_number(PCWSTR path, const SCPFS_REMOTE_STAT *stat)
{
	uint64_t value = stat->device ^ UINT64_C(1469598103934665603);
	size_t i;
	value ^= stat->inode;
	value *= UINT64_C(1099511628211);
	if (stat->device == 0 && stat->inode == 0 && path != NULL) {
		value = UINT64_C(1469598103934665603);
		for (i = 0; path[i] != L'\0'; i++) {
			value ^= (uint16_t)path[i];
			value *= UINT64_C(1099511628211);
		}
	}
	return value != 0 ? value : 1;
}

static void scpfs_fill_file_info(const SCPFS_HANDLE *handle, FSP_FSCTL_FILE_INFO *info)
{
	uint64_t stamp = scpfs_unix_ns_to_filetime(handle->current.mtime_ns);
	uint64_t access_stamp = scpfs_unix_ns_to_filetime(handle->current.atime_ns);
	uint64_t allocation = handle->directory ? 0 :
		((handle->file_size + SCPFS_SECTOR_SIZE - 1) / SCPFS_SECTOR_SIZE) * SCPFS_SECTOR_SIZE;

	memset(info, 0, sizeof(*info));
	info->FileAttributes = scpfs_attributes(handle->remote_path, &handle->current);
	info->AllocationSize = allocation;
	info->FileSize = handle->directory ? 0 : handle->file_size;
	info->CreationTime = stamp;
	info->LastAccessTime = access_stamp;
	info->LastWriteTime = stamp;
	info->ChangeTime = stamp;
	info->IndexNumber = handle->index_number != 0 ? handle->index_number :
		scpfs_index_number(handle->remote_path, &handle->current);
}

static bool scpfs_is_remote_object_supported(const SCPFS_REMOTE_STAT *stat)
{
	return stat != NULL &&
		(stat->type == SCPFS_REMOTE_FILE || stat->type == SCPFS_REMOTE_DIRECTORY) &&
		(stat->type != SCPFS_REMOTE_FILE || stat->size <= INT64_MAX);
}

static NTSTATUS scpfs_stat_path(SCPFS *instance, PCWSTR path, SCPFS_REMOTE_STAT *stat)
{
	NTSTATUS status;
	if (!scpfs_valid_path(path, true))
		return STATUS_OBJECT_NAME_INVALID;
	status = scp_backend_stat(instance->backend, path, stat);
	if (!NT_SUCCESS(status))
		return scpfs_map_backend_not_found(status);
	if (!scpfs_is_remote_object_supported(stat))
		return STATUS_ACCESS_DENIED;
	return STATUS_SUCCESS;
}

static bool scpfs_cacheable_path(PCWSTR path)
{
	PCWSTR leaf;
	if (path == NULL)
		return false;
	leaf = wcsrchr(path, L'\\');
	leaf = leaf != NULL ? leaf + 1 : path;
	return wcscmp(leaf, L".in.txt") != 0 && wcscmp(leaf, L".out.txt") != 0;
}

/* Called with instance->lock held. A failed/lost monitor invalidates all clean
 * entries and makes this read bypass the cache until coverage is healthy again. */
static bool scpfs_cache_watch_state(SCPFS *instance, SCPFS_WATCH_STATE *state)
{
	if (state != NULL)
		memset(state, 0, sizeof(*state));
	if (instance == NULL || instance->read_cache == NULL || instance->watch == NULL) {
		if (instance != NULL)
			scp_cache_record_monitor_bypass(instance->read_cache);
		return false;
	}
	scp_watch_snapshot(instance->watch, state);
	if (!state->healthy) {
		if (!instance->observed_watch_valid || instance->observed_watch.healthy)
			scp_cache_invalidate_all(instance->read_cache);
		instance->observed_watch = *state;
		instance->observed_watch_valid = true;
		scp_cache_record_monitor_bypass(instance->read_cache);
		return false;
	}
	if (!instance->observed_watch_valid || !instance->observed_watch.healthy) {
		scp_cache_invalidate_all(instance->read_cache);
		instance->observed_watch_valid = true;
	} else if (instance->observed_watch.content_epoch != state->content_epoch) {
		scp_cache_invalidate_all(instance->read_cache);
	} else if (instance->observed_watch.metadata_epoch != state->metadata_epoch) {
		scp_cache_invalidate_metadata(instance->read_cache);
	}
	instance->observed_watch = *state;
	return true;
}

static bool scpfs_watch_same_generation(const SCPFS_WATCH_STATE *left,
	const SCPFS_WATCH_STATE *right)
{
	return left->healthy && right->healthy &&
		left->metadata_epoch == right->metadata_epoch &&
		left->content_epoch == right->content_epoch;
}

static uint32_t scpfs_cache_stat_provenance_mismatch_mask(
	const SCPFS_REMOTE_STAT *left, const SCPFS_REMOTE_STAT *right)
{
	uint32_t mismatch = 0;
	if (left->type != right->type) mismatch |= 1u << 0;
	if (left->device != right->device) mismatch |= 1u << 1;
	if (left->inode != right->inode) mismatch |= 1u << 2;
	if (left->size != right->size) mismatch |= 1u << 3;
	if (left->mtime_ns != right->mtime_ns) mismatch |= 1u << 4;
	if (left->mode != right->mode) mismatch |= 1u << 5;
	if (left->uid != right->uid) mismatch |= 1u << 6;
	if (left->gid != right->gid) mismatch |= 1u << 7;
	if (left->ctime_ns != right->ctime_ns) mismatch |= 1u << 8;
	return mismatch;
}

static void scpfs_cache_invalidate_all(SCPFS *instance)
{
	if (instance != NULL && instance->read_cache != NULL)
		scp_cache_invalidate_all(instance->read_cache);
}

/* Cache only read-side stat callbacks. Mutation preflight and writeback continue
 * to call scpfs_stat_path/scp_backend_stat directly. */
static NTSTATUS scpfs_read_stat(SCPFS *instance, PCWSTR path,
	SCPFS_REMOTE_STAT *stat)
{
	SCPFS_WATCH_STATE before;
	SCPFS_WATCH_STATE after;
	SCPFS_REMOTE_STAT discovery;
	NTSTATUS status;
	if (!scpfs_valid_path(path, true))
		return STATUS_OBJECT_NAME_INVALID;
	if (instance == NULL || instance->read_cache == NULL ||
		!scpfs_cacheable_path(path))
		return scpfs_stat_path(instance, path, stat);
	if (scpfs_cache_watch_state(instance, &before) &&
		scp_cache_get_stat(instance->read_cache, path,
			before.metadata_epoch, before.content_epoch, stat))
		return STATUS_SUCCESS;

	/* Discover the object kind, establish file/directory coverage, then fetch
	 * again inside one acknowledged generation before admitting metadata. */
	status = scpfs_stat_path(instance, path, &discovery);
	if (!NT_SUCCESS(status))
		return status;
	scp_watch_snapshot(instance->watch, &before);
	if (!before.healthy || !scpfs_cache_watch_state(instance, &before)) {
		*stat = discovery;
		return STATUS_SUCCESS;
	}
	if (!scp_watch_ensure(instance->watch, path,
		discovery.type == SCPFS_REMOTE_DIRECTORY) ||
		!scp_watch_barrier(instance->watch)) {
		*stat = discovery;
		return STATUS_SUCCESS;
	}
	scp_watch_snapshot(instance->watch, &after);
	(void)scpfs_cache_watch_state(instance, &after);
	if (!after.healthy) {
		*stat = discovery;
		return STATUS_SUCCESS;
	}
	if (before.content_epoch != after.content_epoch)
		return scpfs_stat_path(instance, path, stat);
	before = after;
	status = scpfs_stat_path(instance, path, stat);
	if (!NT_SUCCESS(status))
		return status;
	if (!scp_watch_barrier(instance->watch)) {
		(void)scpfs_cache_watch_state(instance, &after);
		return STATUS_SUCCESS;
	}
	scp_watch_snapshot(instance->watch, &after);
	if (scpfs_watch_same_generation(&before, &after) &&
		scpfs_cacheable_path(path))
		scp_cache_put_stat(instance->read_cache, path, stat,
			after.metadata_epoch, after.content_epoch);
	(void)scpfs_cache_watch_state(instance, &after);
	return STATUS_SUCCESS;
}

static bool scpfs_list_has_inbox_entry(const SCPFS_DIR_LIST *list)
{
	size_t index;
	for (index = 0; list != NULL && index < list->count; index++) {
		PCWSTR name = list->entries[index].name;
		if (name != NULL && (wcscmp(name, L".in.txt") == 0 ||
			wcscmp(name, L".out.txt") == 0))
			return true;
	}
	return false;
}

static int __cdecl scpfs_compare_dir_entry(const void *left, const void *right);

/* Called with instance->lock held. A list is admitted only after every child
 * has acknowledged its own file/directory watch coverage. */
static NTSTATUS scpfs_read_list(SCPFS *instance, PCWSTR path,
	SCPFS_DIR_LIST *list)
{
	SCPFS_WATCH_STATE before;
	SCPFS_WATCH_STATE after;
	NTSTATUS status;
	size_t index;
	bool can_cache = false;
	memset(list, 0, sizeof(*list));
	if (instance->read_cache != NULL && scpfs_cacheable_path(path) &&
		scpfs_cache_watch_state(instance, &before) &&
		scp_cache_get_list(instance->read_cache, path,
			before.metadata_epoch, before.content_epoch, list))
		return STATUS_SUCCESS;
	if (instance->read_cache != NULL && scpfs_cacheable_path(path)) {
		SCPFS_WATCH_STATE before_ensure;
		scp_watch_snapshot(instance->watch, &before_ensure);
		if (before_ensure.healthy &&
			scpfs_cache_watch_state(instance, &before_ensure) &&
			scp_watch_ensure(instance->watch, path, true) &&
			scp_watch_barrier(instance->watch)) {
			scp_watch_snapshot(instance->watch, &before);
			(void)scpfs_cache_watch_state(instance, &before);
			can_cache = before.healthy &&
				before.content_epoch == before_ensure.content_epoch;
		}
	}
	status = scp_backend_list(instance->backend, path, list);
	if (!NT_SUCCESS(status))
		return status;
	if (list->count > 1)
		qsort(list->entries, list->count, sizeof(list->entries[0]), scpfs_compare_dir_entry);
	if (can_cache && scpfs_list_has_inbox_entry(list))
		can_cache = false;
	if (can_cache) {
		for (index = 0; index < list->count; index++) {
			WCHAR *child_path = NULL;
			SCPFS_DIR_ENTRY *entry = &list->entries[index];
			if (!scpfs_valid_name(entry->name, entry->name_length) ||
				!scpfs_is_remote_object_supported(&entry->stat) ||
				!scpfs_cacheable_path(entry->name) ||
				!scpfs_join_path(path, entry->name, entry->name_length, &child_path)) {
				can_cache = false;
				free(child_path);
				break;
			}
			if (!scp_watch_ensure(instance->watch, child_path,
				entry->stat.type == SCPFS_REMOTE_DIRECTORY))
				can_cache = false;
			free(child_path);
			if (!can_cache)
				break;
		}
	}
	if (can_cache && scp_watch_barrier(instance->watch)) {
		SCPFS_DIR_LIST verified;
		memset(&verified, 0, sizeof(verified));
		/* Child watches may have taken time to install. Fetch the list again
		 * after coverage so the returned/admitted snapshot is from afterward. */
		status = scp_backend_list(instance->backend, path, &verified);
		if (!NT_SUCCESS(status)) {
			scp_backend_free_list(&verified);
			scp_backend_free_list(list);
			return status;
		}
		if (verified.count > 1)
			qsort(verified.entries, verified.count, sizeof(verified.entries[0]),
				scpfs_compare_dir_entry);
		scp_backend_free_list(list);
		*list = verified;
		if (scp_watch_barrier(instance->watch)) {
			scp_watch_snapshot(instance->watch, &after);
			if (scpfs_watch_same_generation(&before, &after) &&
				!scpfs_list_has_inbox_entry(list))
				scp_cache_put_list(instance->read_cache, path, list,
					after.metadata_epoch, after.content_epoch);
		} else {
			memset(&after, 0, sizeof(after));
		}
		(void)scpfs_cache_watch_state(instance, &after);
	} else if (instance->read_cache != NULL) {
		(void)scpfs_cache_watch_state(instance, &after);
	}
	return STATUS_SUCCESS;
}

static bool scpfs_handle_is_active(const SCPFS_HANDLE *handle)
{
	if (handle->deleted)
		return handle->inbox_recovery_pending || handle->inbox_outcome_unknown;
	if (handle->delete_failed || handle->inbox_recovery_pending ||
		handle->inbox_outcome_unknown)
		return true;
	if (handle->metadata_only)
		return handle->modified_after_cleanup || handle->dirty || handle->mode_dirty ||
			handle->atime_dirty || handle->mtime_dirty;
	return !handle->cleaned_up || handle->modified_after_cleanup || handle->dirty ||
		handle->mode_dirty || handle->atime_dirty || handle->mtime_dirty;
}

static bool scpfs_metadata_handle_is_clean(const SCPFS_HANDLE *handle)
{
	return handle->metadata_only && !handle->deleted && !handle->dirty &&
		!handle->mode_dirty && !handle->atime_dirty && !handle->mtime_dirty &&
		!handle->modified_after_cleanup &&
		!handle->delete_failed && !handle->inbox_recovery_pending &&
		!handle->inbox_outcome_unknown;
}

static void scpfs_mark_metadata_handles_stale(SCPFS *instance, PCWSTR path,
	bool include_descendants, const SCPFS_HANDLE *ignore)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (handle == ignore || !scpfs_metadata_handle_is_clean(handle))
			continue;
		if (scpfs_path_equal(handle->remote_path, path) ||
			(include_descendants && scpfs_path_is_descendant(handle->remote_path, path)))
			handle->stale_namespace = true;
	}
}

static bool scpfs_has_open_regular_path(SCPFS *instance, PCWSTR path)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (!handle->directory && scpfs_handle_is_active(handle) &&
			scpfs_path_equal(handle->remote_path, path))
			return true;
	}
	return false;
}

static void scpfs_mark_modified(SCPFS_HANDLE *handle)
{
	if (handle->cleaned_up)
		handle->modified_after_cleanup = true;
}

static bool scpfs_has_open_path(SCPFS *instance, PCWSTR path)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (scpfs_handle_is_active(handle) && scpfs_path_equal(handle->remote_path, path))
			return true;
	}
	return false;
}

static bool scpfs_has_other_open_path(SCPFS *instance, PCWSTR path,
	const SCPFS_HANDLE *ignore)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (handle != ignore && scpfs_handle_is_active(handle) &&
			scpfs_path_equal(handle->remote_path, path))
			return true;
	}
	return false;
}

static bool scpfs_has_other_open_payload_path(SCPFS *instance, PCWSTR path,
	const SCPFS_HANDLE *ignore)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (handle != ignore && !handle->metadata_only &&
		scpfs_handle_is_active(handle) && scpfs_path_equal(handle->remote_path, path))
			return true;
	}
	return false;
}

static bool scpfs_has_open_descendant(SCPFS *instance, PCWSTR path,
	const SCPFS_HANDLE *ignore)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (handle != ignore && scpfs_handle_is_active(handle) &&
			scpfs_path_is_descendant(handle->remote_path, path))
			return true;
	}
	return false;
}

static void scpfs_link_handle(SCPFS *instance, SCPFS_HANDLE *handle)
{
	handle->next = instance->handles;
	if (instance->handles != NULL)
		instance->handles->previous = handle;
	instance->handles = handle;
}

static void scpfs_unlink_handle(SCPFS *instance, SCPFS_HANDLE *handle)
{
	if (handle->previous != NULL)
		handle->previous->next = handle->next;
	else
		instance->handles = handle->next;
	if (handle->next != NULL)
		handle->next->previous = handle->previous;
	handle->previous = NULL;
	handle->next = NULL;
}

static SCPFS_HANDLE *scpfs_find_registered_handle(SCPFS *instance,
	const void *file_context)
{
	SCPFS_HANDLE *handle;
	for (handle = instance->handles; handle != NULL; handle = handle->next) {
		if (handle == file_context)
			return handle;
	}
	return NULL;
}

static bool scpfs_make_cache_file_name(SCPFS *instance, WCHAR **path_out)
{
	LONG counter;
	WCHAR leaf[64];
	size_t root_length;
	WCHAR *path;

	if (path_out == NULL)
		return false;
	*path_out = NULL;
	root_length = wcslen(instance->cache_directory);
	for (;;) {
		counter = InterlockedIncrement(&instance->cache_counter);
		if (swprintf_s(leaf, _countof(leaf), L"\\file-%08lx.cache", (unsigned long)counter) < 0)
			return false;
		path = (WCHAR *)malloc((root_length + wcslen(leaf) + 1) * sizeof(WCHAR));
		if (path == NULL)
			return false;
		wcscpy_s(path, root_length + wcslen(leaf) + 1, instance->cache_directory);
		wcscat_s(path, root_length + wcslen(leaf) + 1, leaf);
		if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
			DWORD error = GetLastError();
			if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
				*path_out = path;
				return true;
			}
		}
		free(path);
		if ((uint32_t)counter == UINT32_MAX)
			return false;
	}
}

static NTSTATUS scpfs_create_local_cache_file(SCPFS *instance,
	SCPFS_HANDLE *handle)
{
	DWORD error;
	if (!scpfs_make_cache_file_name(instance, &handle->cache_path))
		return STATUS_INSUFFICIENT_RESOURCES;
	handle->cache_file = CreateFileW(handle->cache_path,
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
		FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (handle->cache_file == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		handle->cache_file = NULL;
		free(handle->cache_path);
		handle->cache_path = NULL;
		return scpfs_map_win32_error(error);
	}
	return STATUS_SUCCESS;
}

static SCPFS_HANDLE *scpfs_allocate_handle(SCPFS *instance, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, bool remote_exists)
{
	SCPFS_HANDLE *handle;
	handle = (SCPFS_HANDLE *)calloc(1, sizeof(*handle));
	if (handle == NULL)
		return NULL;
	handle->remote_path = scpfs_wcsdup(path);
	if (handle->remote_path == NULL) {
		free(handle);
		return NULL;
	}
	handle->owner = instance;
	handle->cache_file = NULL;
	handle->remote_exists = remote_exists;
	if (stat != NULL) {
		handle->snapshot = *stat;
		handle->current = *stat;
		handle->mode = stat->mode & 07777U;
		handle->directory = stat->type == SCPFS_REMOTE_DIRECTORY;
		handle->file_size = stat->size;
	} else {
		handle->current.type = SCPFS_REMOTE_FILE;
		handle->current.mode = 0666U;
		handle->mode = 0666U;
		handle->directory = false;
	}
	handle->inbox_exit_code = -1;
	/* Keep a stable file identifier for this open handle across atomic writeback. */
	handle->index_number = scpfs_index_number(path, &handle->current);
	return handle;
}

static void scpfs_dispose_handle(SCPFS_HANDLE *handle, bool remove_clean_cache)
{
	if (handle == NULL)
		return;
	if (handle->cache_file != NULL && handle->cache_file != INVALID_HANDLE_VALUE)
		CloseHandle(handle->cache_file);
	if (remove_clean_cache && handle->cache_path != NULL)
		DeleteFileW(handle->cache_path);
	FspFileSystemDeleteDirectoryBuffer(&handle->dir_buffer);
	free(handle->cache_path);
	free(handle->remote_path);
	free(handle->inbox_claim_path);
	free(handle->inbox_failure_stage);
	free(handle);
}

static int64_t scpfs_now_unix_ns(void)
{
	FILETIME file_time;
	ULARGE_INTEGER ticks;
	const uint64_t epoch = UINT64_C(116444736000000000);

	GetSystemTimeAsFileTime(&file_time);
	ticks.LowPart = file_time.dwLowDateTime;
	ticks.HighPart = file_time.dwHighDateTime;
	if (ticks.QuadPart < epoch)
		return 0;
	if (ticks.QuadPart - epoch > (uint64_t)INT64_MAX / 100)
		return INT64_MAX;
	return (int64_t)((ticks.QuadPart - epoch) * 100);
}

static void scpfs_write_recovery_manifest(SCPFS_HANDLE *handle,
	PCWSTR operation, NTSTATUS status)
{
	SCPFS *instance;
	WCHAR manifest_path[SCPFS_MAX_PATH_CHARS + 64];
	WCHAR *record;
	WCHAR expected[256];
	size_t record_chars;
	size_t capacity;
	DWORD written;
	HANDLE file;
	LARGE_INTEGER file_size;
	int length;

	if (handle == NULL || (instance = handle->owner) == NULL ||
		instance->cache_directory == NULL)
		return;
	if (swprintf_s(manifest_path, _countof(manifest_path), L"%s\\recovery.manifest.txt",
		instance->cache_directory) < 0) {
		scpfs_log_failure(handle, operation, status, NULL);
		return;
	}
	scpfs_log_failure(handle, operation, status, manifest_path);
	if (handle->remote_exists) {
		if (swprintf_s(expected, _countof(expected),
			L"exists size=%llu mtime_ns=%lld mode=%04o dev=%llu ino=%llu",
			(unsigned long long)handle->snapshot.size,
			(long long)handle->snapshot.mtime_ns,
			handle->snapshot.mode & 07777U,
			(unsigned long long)handle->snapshot.device,
			(unsigned long long)handle->snapshot.inode) < 0)
			return;
	} else {
		wcscpy_s(expected, _countof(expected), L"must-remain-absent");
	}
	capacity = wcslen(handle->remote_path) +
		(handle->cache_path != NULL ? wcslen(handle->cache_path) : 0) +
		(handle->inbox_claim_path != NULL ? wcslen(handle->inbox_claim_path) : 0) +
		(handle->inbox_failure_stage != NULL ? wcslen(handle->inbox_failure_stage) : 0) + 800;
	capacity += (instance->remote_host != NULL ? wcslen(instance->remote_host) : 0) +
		(instance->remote_root != NULL ? wcslen(instance->remote_root) : 0);
	if (capacity > SIZE_MAX / sizeof(WCHAR))
		return;
	record = (WCHAR *)malloc(capacity * sizeof(WCHAR));
	if (record == NULL)
		return;
	length = swprintf_s(record, capacity,
		L"Operation: %s\r\nRemoteHost: %s\r\nConfiguredRoot: %s\r\nRemotePath: %s\r\nCachePath: %s\r\nExpected: %s\r\nExpectedAtimeNs: %lld\r\nPendingAtimeNs: %lld (dirty=%u)\r\nCommandAttempted: %u\r\nCommandInputConsumed: %u\r\nCommandCompleted: %u\r\nCommandOutcomeUnknown: %u\r\nCommandOutputPublished: %u\r\nCommandExitCode: %d\r\nCommandFailureStage: %s\r\nCommandClaimPath: %s\r\nStatus: 0x%08lX\r\n\r\n",
		operation != NULL ? operation : L"commit",
		instance->remote_host != NULL ? instance->remote_host : L"(unknown)",
		instance->remote_root != NULL ? instance->remote_root : L"(unknown)",
		handle->remote_path,
		handle->cache_path != NULL ? handle->cache_path : L"(none)",
		expected,
		(long long)handle->snapshot.atime_ns,
		(long long)(handle->atime_dirty ? handle->pending_atime_ns : handle->current.atime_ns),
		handle->atime_dirty ? 1U : 0U,
		handle->inbox_attempted ? 1U : 0U,
		handle->inbox_input_consumed ? 1U : 0U,
		handle->inbox_completed ? 1U : 0U,
		handle->inbox_outcome_unknown ? 1U : 0U,
		handle->inbox_output_published ? 1U : 0U,
		handle->inbox_exit_code,
		handle->inbox_failure_stage != NULL ? handle->inbox_failure_stage : L"(none)",
		handle->inbox_claim_path != NULL ? handle->inbox_claim_path : L"(none)",
		(unsigned long)status);
	if (length < 0) {
		free(record);
		return;
	}
	record_chars = (size_t)length;
	file = CreateFileW(manifest_path, FILE_APPEND_DATA | FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		free(record);
		return;
	}
	if (GetFileSizeEx(file, &file_size) && file_size.QuadPart == 0) {
		static const WCHAR bom = 0xFEFF;
		WriteFile(file, &bom, sizeof(bom), &written, NULL);
	}
	WriteFile(file, record, (DWORD)(record_chars * sizeof(WCHAR)), &written, NULL);
	CloseHandle(file);
	free(record);
}

static NTSTATUS scpfs_commit_handle(SCPFS_HANDLE *handle, PCWSTR operation)
{
	SCPFS *instance;
	SCPFS_REMOTE_STAT updated;
	NTSTATUS status;
	bool commit_payload;
	bool update_metadata;

	if (handle == NULL || (instance = handle->owner) == NULL)
		return STATUS_INVALID_PARAMETER;
	if (handle->deleted)
		return STATUS_SUCCESS;
	if (handle->delete_failed)
		return STATUS_DELETE_PENDING;
	commit_payload = !handle->directory && handle->dirty;
	update_metadata = handle->mode_dirty || handle->atime_dirty || handle->mtime_dirty;
	if (!commit_payload && !update_metadata)
		return STATUS_SUCCESS;
	scpfs_cache_invalidate_all(instance);
	if (commit_payload) {
		if (handle->cache_file == NULL) {
			status = STATUS_INVALID_HANDLE;
			scpfs_write_recovery_manifest(handle, operation, status);
			return status;
		}
		if (!FlushFileBuffers(handle->cache_file)) {
			status = scpfs_map_win32_error(GetLastError());
			scpfs_write_recovery_manifest(handle, operation, status);
			return status;
		}
		status = scp_backend_upload_atomic(instance->backend,
			handle->remote_path, handle->cache_path,
			handle->remote_exists ? &handle->snapshot : NULL, &updated);
		if (!NT_SUCCESS(status)) {
			scpfs_write_recovery_manifest(handle, operation, status);
			return status;
		}
		handle->snapshot = updated;
		handle->current = updated;
		handle->remote_exists = true;
		handle->dirty = false;
		handle->file_size = updated.size;
		if (!handle->mode_dirty)
			handle->mode = updated.mode & 07777U;
		else
			handle->current.mode = handle->mode;
	}
	if (update_metadata) {
		status = scp_backend_setmeta(instance->backend, handle->remote_path,
			handle->mode,
			handle->atime_dirty ? handle->pending_atime_ns : handle->current.atime_ns,
			handle->mtime_dirty ? handle->pending_mtime_ns : handle->current.mtime_ns,
			handle->mode_dirty, handle->atime_dirty, handle->mtime_dirty);
		if (!NT_SUCCESS(status)) {
			scpfs_write_recovery_manifest(handle, operation, status);
			return status;
		}
		if (handle->mode_dirty) {
			handle->snapshot.mode = handle->mode;
			handle->current.mode = handle->mode;
		}
		if (handle->atime_dirty) {
			handle->snapshot.atime_ns = handle->pending_atime_ns;
			handle->current.atime_ns = handle->pending_atime_ns;
		}
		if (handle->mtime_dirty) {
			handle->snapshot.mtime_ns = handle->pending_mtime_ns;
			handle->current.mtime_ns = handle->pending_mtime_ns;
		}
		handle->mode_dirty = false;
		handle->atime_dirty = false;
		handle->mtime_dirty = false;
		status = scpfs_stat_path(instance, handle->remote_path, &updated);
		if (!NT_SUCCESS(status)) {
			scpfs_write_recovery_manifest(handle, operation, status);
			return status;
		}
		handle->snapshot = updated;
		handle->current = updated;
		handle->remote_exists = true;
		handle->mode = updated.mode & 07777U;
		handle->file_size = handle->directory ? 0 : updated.size;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS scpfs_execute_inbox_after_commit(SCPFS_HANDLE *handle,
	PCWSTR operation)
{
	SCPFS_INBOX_RESULT result;
	NTSTATUS status;
	NTSTATUS recovery_status;
	bool completed_successfully;
	if (handle == NULL || handle->owner == NULL)
		return STATUS_INVALID_PARAMETER;
	if (handle->directory || handle->deleted || handle->delete_failed ||
		!scpfs_is_inbox_command_path(handle->remote_path) || handle->inbox_attempted)
		return STATUS_SUCCESS;
	scpfs_cache_invalidate_all(handle->owner);
	if (scpfs_has_other_open_path(handle->owner, handle->remote_path, handle)) {
		if (handle->metadata_only && scpfs_has_other_open_payload_path(
			handle->owner, handle->remote_path, handle))
			return STATUS_SUCCESS;
		handle->inbox_attempted = true;
		handle->inbox_recovery_pending = true;
		free(handle->inbox_failure_stage);
		handle->inbox_failure_stage = scpfs_wcsdup(L"not launched: active path context");
		scpfs_write_recovery_manifest(handle, operation, STATUS_SHARING_VIOLATION);
		return STATUS_SHARING_VIOLATION;
	}
	memset(&result, 0, sizeof(result));
	result.exit_code = -1;
	/* Mark before dispatch so a timeout or lost reply is never blindly retried. */
	handle->inbox_attempted = true;
	status = scp_backend_execute_inbox(handle->owner->backend,
		handle->remote_path, handle->owner->command_timeout_ms, &result);
	scpfs_cache_invalidate_all(handle->owner);
	if ((status == STATUS_OBJECT_NAME_NOT_FOUND ||
		status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_NO_SUCH_FILE) &&
		!result.input_consumed && !result.outcome_unknown) {
		/* Another client may have removed/claimed it before this close arrived. */
		scp_backend_free_inbox_result(&result);
		return STATUS_SUCCESS;
	}
	handle->inbox_input_consumed = result.input_consumed;
	handle->inbox_completed = result.completed;
	handle->inbox_outcome_unknown = result.outcome_unknown;
	handle->inbox_output_published = result.output_published;
	handle->inbox_exit_code = result.exit_code;
	if (result.claim_path != NULL) {
		WCHAR *claim_copy = scpfs_wcsdup(result.claim_path);
		if (claim_copy != NULL) {
			free(handle->inbox_claim_path);
			handle->inbox_claim_path = claim_copy;
		} else {
			scpfs_log_failure(handle, L"copy command claim path",
				STATUS_INSUFFICIENT_RESOURCES, result.claim_path);
		}
	}
	if (result.failure_stage != NULL) {
		WCHAR *stage_copy = scpfs_wcsdup(result.failure_stage);
		if (stage_copy != NULL) {
			free(handle->inbox_failure_stage);
			handle->inbox_failure_stage = stage_copy;
		}
	}
	if (result.input_consumed) {
		scpfs_mark_metadata_handles_stale(handle->owner, handle->remote_path,
			handle->directory, handle);
		handle->deleted = true;
		handle->remote_exists = false;
		handle->dirty = false;
		handle->mode_dirty = false;
		handle->atime_dirty = false;
		handle->mtime_dirty = false;
	}
	completed_successfully = NT_SUCCESS(status) && result.input_consumed &&
		result.completed && !result.outcome_unknown && result.output_published &&
		result.claim_path == NULL && result.failure_stage == NULL;
	if (completed_successfully) {
		handle->inbox_recovery_pending = false;
		if (result.exit_code != 0)
			scpfs_log_command_exit(handle, result.exit_code);
		scp_backend_free_inbox_result(&result);
		return STATUS_SUCCESS;
	}
	handle->inbox_recovery_pending = true;
	recovery_status = NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
	scpfs_write_recovery_manifest(handle,
		operation != NULL ? operation : L"command inbox", recovery_status);
	scp_backend_free_inbox_result(&result);
	return recovery_status;
}

static NTSTATUS scpfs_open_existing(SCPFS *instance, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, bool enforce_single_file_handle,
	bool metadata_only, SCPFS_HANDLE **handle_out)
{
	SCPFS_HANDLE *handle;
	SCPFS_HANDLE *active_handle;
	NTSTATUS status;
	bool downloaded = false;

	if (handle_out == NULL)
		return STATUS_INVALID_PARAMETER;
	*handle_out = NULL;
	if (stat->type == SCPFS_REMOTE_FILE && enforce_single_file_handle &&
		scpfs_has_open_regular_path(instance, path)) {
		for (active_handle = instance->handles; active_handle != NULL;
			active_handle = active_handle->next) {
			WCHAR operation[192];
			if (active_handle->directory || active_handle->deleted ||
				!scpfs_path_equal(active_handle->remote_path, path) ||
				(active_handle->cleaned_up && !active_handle->modified_after_cleanup &&
				 !active_handle->dirty && !active_handle->mode_dirty &&
				 !active_handle->atime_dirty && !active_handle->mtime_dirty))
				continue;
			(void)swprintf_s(operation, _countof(operation),
				L"open blocked by active handle context=%p (cleaned_up=%u dirty=%u mode_dirty=%u atime_dirty=%u mtime_dirty=%u)",
				(void *)active_handle,
				active_handle->cleaned_up ? 1U : 0U,
				active_handle->dirty ? 1U : 0U,
				active_handle->mode_dirty ? 1U : 0U,
				active_handle->atime_dirty ? 1U : 0U,
				active_handle->mtime_dirty ? 1U : 0U);
			scpfs_log_open_failure(instance, active_handle->remote_path,
				operation, STATUS_SHARING_VIOLATION);
		}
		return STATUS_SHARING_VIOLATION;
	}
	handle = scpfs_allocate_handle(instance, path, stat, true);
	if (handle == NULL) {
		scpfs_log_open_failure(instance, path, L"allocate open handle", STATUS_INSUFFICIENT_RESOURCES);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	handle->metadata_only = metadata_only && !handle->directory;
	if (!handle->directory && !handle->metadata_only) {
		PCWSTR cached_payload = NULL;
		SCPFS_REMOTE_STAT cached_provenance;
		SCPFS_REMOTE_STAT fresh_stat;
		uint64_t payload_metadata_epoch = 0;
		bool metadata_stale = false;
		bool cache_hit = false;
		bool payload_candidate = false;
		bool download_cacheable = false;
		SCPFS_WATCH_STATE before;
		SCPFS_WATCH_STATE after;
		if (!scpfs_make_cache_file_name(instance, &handle->cache_path)) {
			scpfs_log_failure(handle, L"allocate cache path", STATUS_INSUFFICIENT_RESOURCES, NULL);
			scpfs_dispose_handle(handle, false);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		if (instance->read_cache != NULL && scpfs_cacheable_path(path) &&
			scpfs_cache_watch_state(instance, &before) &&
			scp_cache_get_payload(instance->read_cache, path,
				before.metadata_epoch, before.content_epoch, &cached_payload,
				&cached_provenance, &payload_metadata_epoch, &metadata_stale)) {
			payload_candidate = true;
			SCPFS_CACHE_DIAG(instance, warm_candidate);
			if (payload_metadata_epoch != before.metadata_epoch)
				metadata_stale = true;
			if (metadata_stale)
				SCPFS_CACHE_DIAG(instance, warm_metadata_stale);
			bool provenance_valid = !metadata_stale;
			if (metadata_stale) {
				SCPFS_WATCH_STATE before_ensure;
				bool coverage_ready;
				/* ATTRIB retains immutable bytes only after a fresh complete
				 * provenance stat and a monitor barrier agree. */
				provenance_valid = false;
				scp_watch_snapshot(instance->watch, &before_ensure);
				if (!before_ensure.healthy ||
					before_ensure.content_epoch != before.content_epoch) {
					if (!before_ensure.healthy)
						SCPFS_CACHE_DIAG(instance, warm_watch_unhealthy);
					else
						SCPFS_CACHE_DIAG(instance, warm_content_changed);
					(void)scpfs_cache_watch_state(instance, &before_ensure);
					coverage_ready = false;
				} else {
					(void)scpfs_cache_watch_state(instance, &before_ensure);
					if (!scp_watch_ensure(instance->watch, path, false)) {
						SCPFS_CACHE_DIAG(instance, warm_ensure_failed);
						coverage_ready = false;
					} else if (!scp_watch_barrier(instance->watch)) {
						SCPFS_CACHE_DIAG(instance, warm_barrier_failed);
						coverage_ready = false;
					} else {
						coverage_ready = true;
					}
				}
				if (coverage_ready) {
					scp_watch_snapshot(instance->watch, &before);
					(void)scpfs_cache_watch_state(instance, &before);
					if (!before.healthy) {
						SCPFS_CACHE_DIAG(instance, warm_watch_unhealthy);
						coverage_ready = false;
					} else if (before.content_epoch != before_ensure.content_epoch) {
						SCPFS_CACHE_DIAG(instance, warm_content_changed);
						coverage_ready = false;
					}
				}
				status = coverage_ready ? scpfs_stat_path(instance, path, &fresh_stat) :
					STATUS_UNSUCCESSFUL;
				if (coverage_ready && !NT_SUCCESS(status)) {
					SCPFS_CACHE_DIAG(instance, warm_stat_failed);
				} else if (coverage_ready && !scp_watch_barrier(instance->watch)) {
					SCPFS_CACHE_DIAG(instance, warm_verify_barrier_failed);
				} else if (coverage_ready) {
					scp_watch_snapshot(instance->watch, &after);
					if (!scpfs_watch_same_generation(&before, &after)) {
						if (!after.healthy)
							SCPFS_CACHE_DIAG(instance, warm_verify_unhealthy);
						else if (before.content_epoch != after.content_epoch)
							SCPFS_CACHE_DIAG(instance, warm_content_changed);
						else if (before.metadata_epoch != after.metadata_epoch)
							SCPFS_CACHE_DIAG(instance, warm_metadata_changed);
						(void)scpfs_cache_watch_state(instance, &after);
					} else {
						bool provenance_matches = scp_cache_validate_payload(
							instance->read_cache, path, &fresh_stat,
							after.metadata_epoch);
						(void)scpfs_cache_watch_state(instance, &after);
						if (provenance_matches)
							provenance_valid = scp_cache_get_payload(
								instance->read_cache, path, after.metadata_epoch,
								after.content_epoch, &cached_payload,
								&cached_provenance, &payload_metadata_epoch,
								&metadata_stale) && !metadata_stale;
						else {
							SCPFS_CACHE_DIAG(instance, warm_provenance_mismatch);
							(void)InterlockedOr(
								(volatile LONG *)&instance->cache_diagnostics.provenance_mismatch_mask,
								(LONG)scpfs_cache_stat_provenance_mismatch_mask(
									&cached_provenance, &fresh_stat));
						}
					}
			}
			if (!provenance_valid)
					(void)scp_cache_evict_payload(instance->read_cache, path);
			}
			if (provenance_valid) {
				if (CopyFileW(cached_payload, handle->cache_path, TRUE)) {
					cache_hit = true;
					scp_cache_record_payload_hit(instance->read_cache);
					handle->current = cached_provenance;
					if (metadata_stale)
						handle->current = fresh_stat;
				} else {
					SCPFS_CACHE_DIAG(instance, warm_copy_failed);
					SetFileAttributesW(handle->cache_path, FILE_ATTRIBUTE_NORMAL);
					DeleteFileW(handle->cache_path);
				}
			}
		}
		if (!cache_hit) {
			if (payload_candidate)
				scp_cache_record_payload_miss(instance->read_cache);
			/* Establish the file and all ancestor coverage immediately before
			 * the network transfer; content events reset subscriptions. */
			if (instance->read_cache != NULL && scpfs_cacheable_path(path)) {
				SCPFS_WATCH_STATE before_ensure;
				scp_watch_snapshot(instance->watch, &before_ensure);
				SCPFS_CACHE_DIAG(instance, cold_attempt);
				if (!before_ensure.healthy) {
					SCPFS_CACHE_DIAG(instance, cold_watch_unhealthy);
				} else if (!scpfs_cache_watch_state(instance, &before_ensure)) {
					SCPFS_CACHE_DIAG(instance, cold_watch_unhealthy);
				} else if (!scp_watch_ensure(instance->watch, path, false)) {
					SCPFS_CACHE_DIAG(instance, cold_ensure_failed);
				} else if (!scp_watch_barrier(instance->watch)) {
					SCPFS_CACHE_DIAG(instance, cold_barrier_failed);
				} else {
					scp_watch_snapshot(instance->watch, &before);
					(void)scpfs_cache_watch_state(instance, &before);
					download_cacheable = before.healthy &&
						before.content_epoch == before_ensure.content_epoch;
					if (!before.healthy)
						SCPFS_CACHE_DIAG(instance, cold_watch_unhealthy);
					else if (before.content_epoch != before_ensure.content_epoch)
						SCPFS_CACHE_DIAG(instance, cold_pre_content_changed);
				}
			} else {
				SCPFS_CACHE_DIAG(instance, cold_unavailable);
			}
			status = scp_backend_download(instance->backend, path,
				handle->cache_path, &handle->current);
			if (!NT_SUCCESS(status)) {
				scpfs_log_failure(handle, L"download file cache", status, NULL);
				scpfs_dispose_handle(handle, true);
				return status;
			}
			downloaded = true;
		}
		if (downloaded && download_cacheable) {
			if (!scp_watch_barrier(instance->watch)) {
				SCPFS_CACHE_DIAG(instance, cold_post_barrier_failed);
			} else {
				scp_watch_snapshot(instance->watch, &after);
				/* Backend download's final stat is after restoring atime. A second
				 * stat confirms no chmod, replacement, or other metadata change was
				 * folded into this generation before admitting the byte copy. */
				if (!after.healthy) {
					SCPFS_CACHE_DIAG(instance, cold_post_unhealthy);
				} else if (before.content_epoch != after.content_epoch) {
					SCPFS_CACHE_DIAG(instance, cold_post_content_changed);
				} else {
					status = scpfs_stat_path(instance, path, &fresh_stat);
					if (!NT_SUCCESS(status)) {
						SCPFS_CACHE_DIAG(instance, cold_stat_failed);
					} else if (!scp_watch_barrier(instance->watch)) {
						SCPFS_CACHE_DIAG(instance, cold_verify_barrier_failed);
					} else {
						SCPFS_WATCH_STATE verified;
						bool same_generation;
						bool same_stat;
						uint32_t provenance_mismatch;
						scp_watch_snapshot(instance->watch, &verified);
						same_generation = scpfs_watch_same_generation(&after, &verified);
						if (!verified.healthy) {
							SCPFS_CACHE_DIAG(instance, cold_verify_unhealthy);
						} else if (verified.content_epoch != after.content_epoch) {
							SCPFS_CACHE_DIAG(instance, cold_verify_content_changed);
						} else if (verified.metadata_epoch != after.metadata_epoch) {
							SCPFS_CACHE_DIAG(instance, cold_verify_metadata_changed);
						}
						provenance_mismatch =
							scpfs_cache_stat_provenance_mismatch_mask(
								&handle->current, &fresh_stat);
						same_stat = provenance_mismatch == 0 &&
							handle->current.atime_ns == fresh_stat.atime_ns;
						if (same_generation && same_stat) {
							SCPFS_CACHE_DIAG(instance, cold_put_attempt);
							scp_cache_put_payload(instance->read_cache, path,
								handle->cache_path, &handle->current,
								verified.metadata_epoch, verified.content_epoch);
						} else if (same_generation) {
							if (provenance_mismatch != 0) {
								SCPFS_CACHE_DIAG(instance, cold_provenance_mismatch);
								(void)InterlockedOr(
									(volatile LONG *)&instance->cache_diagnostics.provenance_mismatch_mask,
									(LONG)provenance_mismatch);
							}
							if (handle->current.atime_ns != fresh_stat.atime_ns) {
								SCPFS_CACHE_DIAG(instance, cold_atime_mismatch);
								(void)InterlockedOr(
									(volatile LONG *)&instance->cache_diagnostics.provenance_mismatch_mask,
									(LONG)(1u << 9));
							}
						}
						(void)scpfs_cache_watch_state(instance, &verified);
					}
				}
			}
		}
		handle->snapshot = handle->current;
		handle->file_size = handle->current.size;
		handle->cache_file = CreateFileW(handle->cache_path,
			GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_RANDOM_ACCESS, NULL);
		if (handle->cache_file == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			status = scpfs_map_win32_error(error);
			scpfs_log_failure(handle, L"open downloaded cache", status, NULL);
			handle->cache_file = NULL;
			scpfs_dispose_handle(handle, true);
			return status;
		}
	}
	*handle_out = handle;
	return STATUS_SUCCESS;
}

static bool scpfs_is_name_in_pattern(PCWSTR pattern, PCWSTR name)
{
	UNICODE_STRING expression;
	UNICODE_STRING candidate;
	size_t pattern_length;
	size_t name_length;

	if (pattern == NULL || *pattern == L'\0')
		return true;
	if (name == NULL)
		return false;
	if (!InitOnceExecuteOnce(&g_scpfs_name_match_once,
		scpfs_name_match_initialize, NULL, NULL))
		return true;
	if (g_scpfs_name_match_fn == NULL)
		return true;
	pattern_length = wcslen(pattern);
	name_length = wcslen(name);
	if (pattern_length > USHRT_MAX / sizeof(WCHAR) || name_length > USHRT_MAX / sizeof(WCHAR))
		return true;
	expression.Length = (USHORT)(pattern_length * sizeof(WCHAR));
	expression.MaximumLength = expression.Length;
	expression.Buffer = (PWSTR)pattern;
	candidate.Length = (USHORT)(name_length * sizeof(WCHAR));
	candidate.MaximumLength = candidate.Length;
	candidate.Buffer = (PWSTR)name;
	return g_scpfs_name_match_fn(&expression, &candidate, FALSE, NULL) != FALSE;
}

static int __cdecl scpfs_compare_dir_entry(const void *left, const void *right)
{
	const SCPFS_DIR_ENTRY *a = (const SCPFS_DIR_ENTRY *)left;
	const SCPFS_DIR_ENTRY *b = (const SCPFS_DIR_ENTRY *)right;
	int result = CompareStringOrdinal(a->name, (int)a->name_length,
		b->name, (int)b->name_length, FALSE);
	if (result == CSTR_LESS_THAN)
		return -1;
	if (result == CSTR_GREATER_THAN)
		return 1;
	return 0;
}

typedef union SCPFS_DIR_INFO_STORAGE {
	FSP_FSCTL_DIR_INFO info;
	uint8_t bytes[sizeof(FSP_FSCTL_DIR_INFO) +
		(SCPFS_MAX_COMPONENT_CHARS + 1U) * sizeof(WCHAR)];
} SCPFS_DIR_INFO_STORAGE;

static FSP_FSCTL_DIR_INFO *scpfs_build_dir_info(PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, PCWSTR name, SCPFS_DIR_INFO_STORAGE *storage)
{
	FSP_FSCTL_DIR_INFO *info = &storage->info;
	SCPFS_HANDLE temp;
	size_t name_chars = wcslen(name);
	size_t name_bytes = name_chars * sizeof(WCHAR);

	if (name_chars > SCPFS_MAX_COMPONENT_CHARS)
		return NULL;
	memset(&temp, 0, sizeof(temp));
	temp.remote_path = (WCHAR *)path;
	temp.current = *stat;
	temp.directory = stat->type == SCPFS_REMOTE_DIRECTORY;
	temp.file_size = stat->size;
	memset(storage, 0, sizeof(*storage));
	info->Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + name_bytes);
	scpfs_fill_file_info(&temp, &info->FileInfo);
	if (name_bytes != 0)
		memcpy(info->FileNameBuf, name, name_bytes);
	return info;
}

/* Adds one entry to the handle's enumeration snapshot. */
static NTSTATUS scpfs_fill_dir_entry(SCPFS_HANDLE *directory, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, PCWSTR name)
{
	SCPFS_DIR_INFO_STORAGE storage;
	FSP_FSCTL_DIR_INFO *info = scpfs_build_dir_info(path, stat, name, &storage);
	NTSTATUS status = STATUS_SUCCESS;

	if (info == NULL)
		return STATUS_SUCCESS;
	if (!FspFileSystemFillDirectoryBuffer(&directory->dir_buffer, info, &status))
		return status;
	return STATUS_SUCCESS;
}

static NTSTATUS scpfs_fs_get_volume_info(FSP_FILE_SYSTEM *file_system,
	FSP_FSCTL_VOLUME_INFO *volume_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	if (instance == NULL || volume_info == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	memset(volume_info, 0, sizeof(*volume_info));
	/* Volume info is queried constantly; refresh the remote sample at most
	 * every 30 seconds and keep the last good one if a refresh fails. */
	if (instance->volume_sample_tick == 0 ||
		GetTickCount64() - instance->volume_sample_tick >= 30000) {
		uint64_t total = 0, available = 0;
		if (NT_SUCCESS(scp_backend_statfs(instance->backend, &total, &available))) {
			instance->volume_total_bytes = total;
			instance->volume_free_bytes = available;
		}
		instance->volume_sample_tick = GetTickCount64();
	}
	volume_info->TotalSize = instance->volume_total_bytes;
	volume_info->FreeSize = instance->volume_free_bytes;
	volume_info->VolumeLabelLength = instance->volume_label_bytes;
	memcpy(volume_info->VolumeLabel, instance->volume_label,
		instance->volume_label_bytes);
	ReleaseSRWLockExclusive(&instance->lock);
	return STATUS_SUCCESS;
}

static NTSTATUS scpfs_fs_set_volume_label(FSP_FILE_SYSTEM *file_system,
	PWSTR volume_label, FSP_FSCTL_VOLUME_INFO *volume_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	size_t chars;
	if (instance == NULL || volume_label == NULL || volume_info == NULL)
		return STATUS_INVALID_PARAMETER;
	chars = wcslen(volume_label);
	if (chars > 31)
		return STATUS_INVALID_VOLUME_LABEL;
	AcquireSRWLockExclusive(&instance->lock);
	memset(instance->volume_label, 0, sizeof(instance->volume_label));
	memcpy(instance->volume_label, volume_label, chars * sizeof(WCHAR));
	instance->volume_label_bytes = (uint16_t)(chars * sizeof(WCHAR));
	ReleaseSRWLockExclusive(&instance->lock);
	return scpfs_fs_get_volume_info(file_system, volume_info);
}

static NTSTATUS scpfs_fs_get_security_by_name(FSP_FILE_SYSTEM *file_system,
	PWSTR file_name, PUINT32 file_attributes,
	PSECURITY_DESCRIPTOR security_descriptor, SIZE_T *security_descriptor_size)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_REMOTE_STAT stat;
	NTSTATUS status;
	(void)security_descriptor;
	if (instance == NULL || file_name == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	status = scpfs_read_stat(instance, file_name, &stat);
	if (NT_SUCCESS(status) && file_attributes != NULL)
		*file_attributes = scpfs_attributes(file_name, &stat);
	/* PersistentAcls is disabled; return one session-wide default descriptor. */
	if (NT_SUCCESS(status) && security_descriptor_size != NULL) {
		if (instance->default_security_size > *security_descriptor_size) {
			*security_descriptor_size = instance->default_security_size;
			status = STATUS_BUFFER_OVERFLOW;
		} else {
			*security_descriptor_size = instance->default_security_size;
			if (security_descriptor != NULL)
				memcpy(security_descriptor, instance->default_security,
					instance->default_security_size);
		}
	}
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_create(FSP_FILE_SYSTEM *file_system,
	PWSTR file_name, UINT32 create_options, UINT32 granted_access,
	UINT32 file_attributes, PSECURITY_DESCRIPTOR security_descriptor,
	UINT64 allocation_size, PVOID *file_context,
	FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_REMOTE_STAT parent_stat;
	SCPFS_REMOTE_STAT target_stat;
	SCPFS_HANDLE *handle = NULL;
	WCHAR *parent_path = NULL;
	NTSTATUS status;
	bool directory;
	(void)granted_access;
	(void)security_descriptor;
	(void)allocation_size;

	if (instance == NULL || file_name == NULL || file_context == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	*file_context = NULL;
	if (!scpfs_valid_path(file_name, false))
		return STATUS_OBJECT_NAME_INVALID;
	AcquireSRWLockExclusive(&instance->lock);
	parent_path = scpfs_parent_path(file_name);
	if (parent_path == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	status = scpfs_stat_path(instance, parent_path, &parent_stat);
	if (!NT_SUCCESS(status))
		goto done;
	if (parent_stat.type != SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_NOT_A_DIRECTORY;
		goto done;
	}
	if (scpfs_has_open_path(instance, file_name)) {
		status = STATUS_OBJECT_NAME_COLLISION;
		goto done;
	}
	status = scp_backend_stat(instance->backend, file_name, &target_stat);
	if (NT_SUCCESS(status)) {
		status = STATUS_OBJECT_NAME_COLLISION;
		goto done;
	}
	if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND &&
		status != STATUS_NO_SUCH_FILE)
		goto done;

	directory = (create_options & FILE_DIRECTORY_FILE) != 0;
	scpfs_cache_invalidate_all(instance);
	if (directory) {
		SCPFS_REMOTE_STAT created_stat;
		status = scp_backend_mkdir(instance->backend, file_name, 0777U);
		if (!NT_SUCCESS(status))
			goto done;
		status = scpfs_stat_path(instance, file_name, &created_stat);
		if (!NT_SUCCESS(status)) {
			(void)scp_backend_remove(instance->backend, file_name, true);
			goto done;
		}
		handle = scpfs_allocate_handle(instance, file_name, &created_stat, true);
		if (handle == NULL) {
			(void)scp_backend_remove(instance->backend, file_name, true);
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
	} else {
		SCPFS_REMOTE_STAT empty_stat;
		memset(&empty_stat, 0, sizeof(empty_stat));
		empty_stat.type = SCPFS_REMOTE_FILE;
		empty_stat.mode = (file_attributes & FILE_ATTRIBUTE_READONLY) ? 0444U : 0666U;
		empty_stat.atime_ns = scpfs_now_unix_ns();
		empty_stat.mtime_ns = scpfs_now_unix_ns();
		handle = scpfs_allocate_handle(instance, file_name, &empty_stat, false);
		if (handle == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		status = scpfs_create_local_cache_file(instance, handle);
		if (!NT_SUCCESS(status)) {
			scpfs_dispose_handle(handle, false);
			handle = NULL;
			goto done;
		}
		handle->dirty = true;
		/* Preserve the remote umask-filtered mode unless readonly was requested. */
		handle->mode_dirty = (file_attributes & FILE_ATTRIBUTE_READONLY) != 0;
	}
	scpfs_link_handle(instance, handle);
	*file_context = handle;
	scpfs_fill_file_info(handle, file_info);
	status = STATUS_SUCCESS;

done:
	free(parent_path);
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_open(FSP_FILE_SYSTEM *file_system,
	PWSTR file_name, UINT32 create_options, UINT32 granted_access,
	PVOID *file_context, FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_REMOTE_STAT stat;
	SCPFS_HANDLE *handle = NULL;
	NTSTATUS status;

	if (instance == NULL || file_name == NULL || file_context == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	*file_context = NULL;
	if (!scpfs_valid_path(file_name, true))
		return STATUS_OBJECT_NAME_INVALID;
	AcquireSRWLockExclusive(&instance->lock);
	status = scpfs_read_stat(instance, file_name, &stat);
	if (!NT_SUCCESS(status)) {
		if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND &&
			status != STATUS_NO_SUCH_FILE)
			scpfs_log_open_failure(instance, file_name, L"stat before open", status);
		goto done;
	}
	if ((create_options & FILE_DIRECTORY_FILE) && stat.type != SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_NOT_A_DIRECTORY;
		goto done;
	}
	if ((create_options & FILE_NON_DIRECTORY_FILE) && stat.type == SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_FILE_IS_A_DIRECTORY;
		goto done;
	}
	{
		const UINT32 payload_access = FILE_READ_DATA | FILE_WRITE_DATA |
			FILE_APPEND_DATA | FILE_EXECUTE;
		bool metadata_only = stat.type == SCPFS_REMOTE_FILE &&
			(granted_access & payload_access) == 0;
		status = scpfs_open_existing(instance, file_name, &stat, true,
			metadata_only, &handle);
	}
	if (!NT_SUCCESS(status))
		goto done;
	scpfs_link_handle(instance, handle);
	*file_context = handle;
	scpfs_fill_file_info(handle, file_info);

done:
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_overwrite(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, UINT32 file_attributes,
	BOOLEAN replace_file_attributes, UINT64 allocation_size,
	FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	LARGE_INTEGER zero;
	(void)allocation_size;

	if (instance == NULL || handle == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance || handle->deleted) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_INVALID_HANDLE;
	}
	if (handle->directory) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_FILE_IS_A_DIRECTORY;
	}
	if (handle->cache_file == NULL) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_ACCESS_DENIED;
	}
	zero.QuadPart = 0;
	if (!SetFilePointerEx(handle->cache_file, zero, NULL, FILE_BEGIN) ||
		!SetEndOfFile(handle->cache_file)) {
		NTSTATUS status = scpfs_map_win32_error(GetLastError());
		ReleaseSRWLockExclusive(&instance->lock);
		return status;
	}
	scpfs_cache_invalidate_all(instance);
	handle->file_size = 0;
	handle->current.size = 0;
	handle->dirty = true;
	scpfs_mark_modified(handle);
	if (replace_file_attributes && (file_attributes & FILE_ATTRIBUTE_READONLY)) {
		handle->mode &= ~0222U;
		handle->mode_dirty = true;
		scpfs_mark_modified(handle);
	}
	handle->current.mode = handle->mode;
	scpfs_fill_file_info(handle, file_info);
	ReleaseSRWLockExclusive(&instance->lock);
	return STATUS_SUCCESS;
}

static VOID scpfs_fs_cleanup(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PWSTR file_name, ULONG flags)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle;
	SCPFS_HANDLE *registered_handle;
	NTSTATUS status;

	if (instance == NULL || file_context == NULL)
		return;
	AcquireSRWLockExclusive(&instance->lock);
	registered_handle = scpfs_find_registered_handle(instance, file_context);
	if (registered_handle == NULL || registered_handle->owner != instance ||
		registered_handle->deleted) {
		if (registered_handle == NULL)
			scpfs_log_open_failure(instance,
				file_name != NULL ? file_name : L"(unknown)",
				L"Cleanup received unregistered context", STATUS_INVALID_HANDLE);
		ReleaseSRWLockExclusive(&instance->lock);
		return;
	}
	handle = registered_handle;
	if (handle->stale_namespace) {
		handle->cleaned_up = true;
		handle->modified_after_cleanup = false;
		ReleaseSRWLockExclusive(&instance->lock);
		return;
	}
	if (flags & FspCleanupDelete) {
		if (scpfs_has_other_open_path(instance, handle->remote_path, handle) ||
			(handle->directory && scpfs_has_open_descendant(instance, handle->remote_path, handle))) {
			status = STATUS_SHARING_VIOLATION;
			handle->delete_failed = true;
			scpfs_log_failure(handle, L"CleanupDelete blocked by active handles", status, NULL);
			scpfs_write_recovery_manifest(handle, L"delete", status);
			ReleaseSRWLockExclusive(&instance->lock);
			return;
		}
		if (handle->remote_exists) {
			scpfs_cache_invalidate_all(instance);
			status = scp_backend_remove(instance->backend,
				handle->remote_path, handle->directory);
			if (!NT_SUCCESS(status)) {
				scpfs_log_failure(handle, L"CleanupDelete remote remove", status, NULL);
				handle->delete_failed = true;
				scpfs_write_recovery_manifest(handle, L"delete", status);
				ReleaseSRWLockExclusive(&instance->lock);
				return;
			}
		scpfs_mark_metadata_handles_stale(instance, handle->remote_path,
			handle->directory, handle);
		}
		handle->deleted = true;
		handle->delete_failed = false;
		handle->dirty = false;
		handle->mode_dirty = false;
		handle->atime_dirty = false;
		handle->mtime_dirty = false;
		handle->cleaned_up = true;
		handle->modified_after_cleanup = false;
	} else {
		/*
		 * FspCleanupSetLastWriteTime is WinFsp's automatic post-write hint, not
		 * an explicit SetFileTime request. Existing-file payload commits preserve
		 * remote snapshot times; explicit SetBasicInfo times are tracked above.
		 */
		if (handle->delete_failed)
			status = STATUS_DELETE_PENDING;
		else
			status = scpfs_commit_handle(handle, L"cleanup");
		if (!NT_SUCCESS(status)) {
			OutputDebugStringW(L"SCPFS: cleanup writeback failed; cached data retained.\n");
		} else {
			/* Cleanup is WinFsp's last-user-handle-close event; Close may be delayed. */
			status = scpfs_execute_inbox_after_commit(handle, L"cleanup command");
			if (!NT_SUCCESS(status))
				OutputDebugStringW(L"SCPFS: inbox command requires recovery; cache retained.\n");
		}
		handle->cleaned_up = true;
		handle->modified_after_cleanup = false;
	}
	ReleaseSRWLockExclusive(&instance->lock);
}

static VOID scpfs_fs_close(FSP_FILE_SYSTEM *file_system, PVOID file_context)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle;
	bool keep_cache;

	if (instance == NULL || file_context == NULL)
		return;
	AcquireSRWLockExclusive(&instance->lock);
	handle = scpfs_find_registered_handle(instance, file_context);
	if (handle == NULL || handle->owner != instance) {
		if (handle == NULL)
			scpfs_log_open_failure(instance, L"(unregistered)",
				L"Close received unregistered context", STATUS_INVALID_HANDLE);
		ReleaseSRWLockExclusive(&instance->lock);
		return;
	}
	if (!handle->stale_namespace && !handle->deleted && !handle->delete_failed) {
		NTSTATUS status = STATUS_SUCCESS;
		bool close_trigger = !handle->cleaned_up && !handle->directory &&
			scpfs_is_inbox_command_path(handle->remote_path) && !handle->inbox_attempted;
		bool close_writeback = !handle->cleaned_up || handle->modified_after_cleanup;
		if (close_trigger) {
			status = scpfs_commit_handle(handle, L"close");
			if (NT_SUCCESS(status))
				status = scpfs_execute_inbox_after_commit(handle, L"close command");
		} else if (close_writeback &&
			(handle->dirty || handle->mode_dirty || handle->atime_dirty || handle->mtime_dirty)) {
			status = scpfs_commit_handle(handle, L"close");
		}
		if (!NT_SUCCESS(status))
			OutputDebugStringW(L"SCPFS: close writeback/command failed; cached data retained.\n");
	}
	scpfs_unlink_handle(instance, handle);
	keep_cache = !handle->stale_namespace &&
		(handle->inbox_recovery_pending || (!handle->deleted &&
			(handle->dirty || handle->mode_dirty || handle->atime_dirty || handle->mtime_dirty)));
	ReleaseSRWLockExclusive(&instance->lock);
	scpfs_dispose_handle(handle, !keep_cache);
}

static NTSTATUS scpfs_fs_read(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PVOID buffer, UINT64 offset, ULONG length,
	PULONG bytes_transferred)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	LARGE_INTEGER position;
	DWORD bytes_read = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (instance == NULL || handle == NULL || (buffer == NULL && length != 0) ||
		bytes_transferred == NULL)
		return STATUS_INVALID_PARAMETER;
	*bytes_transferred = 0;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}
	if (handle->directory) {
		status = STATUS_FILE_IS_A_DIRECTORY;
		goto done;
	}
	if (handle->cache_file == NULL) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if (offset > INT64_MAX) {
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}
	if (length == 0)
		goto done;
	if (offset >= handle->file_size) {
		status = STATUS_END_OF_FILE;
		goto done;
	}
	position.QuadPart = (LONGLONG)offset;
	if (!SetFilePointerEx(handle->cache_file, position, NULL, FILE_BEGIN)) {
		status = scpfs_map_win32_error(GetLastError());
		goto done;
	}
	if (!ReadFile(handle->cache_file, buffer, length, &bytes_read, NULL)) {
		status = scpfs_map_win32_error(GetLastError());
		goto done;
	}
	*bytes_transferred = bytes_read;
	done:
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_write(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PVOID buffer, UINT64 offset, ULONG length,
	BOOLEAN write_to_end_of_file, BOOLEAN constrained_io,
	PULONG bytes_transferred, FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	LARGE_INTEGER position;
	DWORD bytes_written = 0;
	int64_t target;
	NTSTATUS status = STATUS_SUCCESS;

	if (instance == NULL || handle == NULL || (buffer == NULL && length != 0) ||
		bytes_transferred == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	*bytes_transferred = 0;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}
	if (handle->directory) {
		status = STATUS_FILE_IS_A_DIRECTORY;
		goto done;
	}
	if (handle->cache_file == NULL) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if (write_to_end_of_file) {
		if (handle->file_size > INT64_MAX) {
			status = STATUS_INVALID_PARAMETER;
			goto done;
		}
		target = (int64_t)handle->file_size;
	} else {
		if (offset > INT64_MAX || (uint64_t)length > (uint64_t)INT64_MAX - offset) {
			status = STATUS_INVALID_PARAMETER;
			goto done;
		}
		target = (int64_t)offset;
	}
	if (constrained_io && ((uint64_t)target > handle->file_size ||
		(uint64_t)length > handle->file_size - (uint64_t)target))
		goto done;
	position.QuadPart = target;
	if (!SetFilePointerEx(handle->cache_file, position, NULL, FILE_BEGIN)) {
		status = scpfs_map_win32_error(GetLastError());
		goto done;
	}
	if (!WriteFile(handle->cache_file, buffer, length, &bytes_written, NULL)) {
		status = scpfs_map_win32_error(GetLastError());
		goto done;
	}
	/* Local cache writes do not change the remote until commit; only this
	 * path's entries can disagree with the open handle meanwhile. */
	if (bytes_written != 0 && instance->read_cache != NULL)
		scp_cache_invalidate_path(instance->read_cache, handle->remote_path);
	{
		LARGE_INTEGER size;
		if (!GetFileSizeEx(handle->cache_file, &size) || size.QuadPart < 0) {
			status = scpfs_map_win32_error(GetLastError());
			goto done;
		}
		handle->file_size = (uint64_t)size.QuadPart;
	}
	handle->current.size = handle->file_size;
	handle->dirty = true;
	scpfs_mark_modified(handle);
	*bytes_transferred = bytes_written;
	scpfs_fill_file_info(handle, file_info);
	done:
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_flush(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	NTSTATUS first_error = STATUS_SUCCESS;

	if (instance == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle != NULL) {
		if (handle->owner != instance) {
			first_error = STATUS_INVALID_HANDLE;
		} else {
			first_error = scpfs_commit_handle(handle, L"flush");
			if (NT_SUCCESS(first_error) && file_info != NULL)
				scpfs_fill_file_info(handle, file_info);
		}
	} else {
		SCPFS_HANDLE *item;
		for (item = instance->handles; item != NULL; item = item->next) {
			NTSTATUS status = scpfs_commit_handle(item, L"volume-flush");
			if (!NT_SUCCESS(status) && NT_SUCCESS(first_error))
				first_error = status;
		}
	}
	ReleaseSRWLockExclusive(&instance->lock);
	return first_error;
}

static NTSTATUS scpfs_fs_get_file_info(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	if (instance == NULL || handle == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_INVALID_HANDLE;
	}
	if (!handle->directory && handle->cache_file != NULL) {
		LARGE_INTEGER size;
		if (GetFileSizeEx(handle->cache_file, &size) && size.QuadPart >= 0) {
			handle->file_size = (uint64_t)size.QuadPart;
			handle->current.size = handle->file_size;
		}
	}
	scpfs_fill_file_info(handle, file_info);
	ReleaseSRWLockExclusive(&instance->lock);
	return STATUS_SUCCESS;
}

static NTSTATUS scpfs_fs_set_basic_info(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, UINT32 file_attributes,
	UINT64 creation_time, UINT64 last_access_time, UINT64 last_write_time,
	UINT64 change_time, FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	(void)creation_time;
	(void)change_time;
	if (instance == NULL || handle == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance || handle->deleted) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_INVALID_HANDLE;
	}
	if (handle->stale_namespace) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_FILE_DELETED;
	}
	if (handle->metadata_only &&
		scpfs_has_other_open_payload_path(instance, handle->remote_path, handle)) {
		ReleaseSRWLockExclusive(&instance->lock);
		return STATUS_SHARING_VIOLATION;
	}
	if (file_attributes != INVALID_FILE_ATTRIBUTES || last_access_time != 0 ||
		last_write_time != 0)
		scpfs_cache_invalidate_all(instance);
	if (file_attributes != INVALID_FILE_ATTRIBUTES) {
		if (file_attributes & FILE_ATTRIBUTE_READONLY)
			handle->mode &= ~0222U;
		else
			handle->mode |= 0200U;
		handle->current.mode = handle->mode;
		handle->mode_dirty = true;
		scpfs_mark_modified(handle);
	}
	if (last_access_time != 0) {
		handle->pending_atime_ns = scpfs_filetime_to_unix_ns(last_access_time);
		handle->current.atime_ns = handle->pending_atime_ns;
		handle->atime_dirty = true;
		scpfs_mark_modified(handle);
	}
	if (last_write_time != 0) {
		handle->pending_mtime_ns = scpfs_filetime_to_unix_ns(last_write_time);
		handle->current.mtime_ns = handle->pending_mtime_ns;
		handle->mtime_dirty = true;
		scpfs_mark_modified(handle);
	}
	if (handle->metadata_only) {
		NTSTATUS status = scpfs_commit_handle(handle, L"metadata-only SetBasicInfo");
		if (!NT_SUCCESS(status)) {
			ReleaseSRWLockExclusive(&instance->lock);
			return status;
		}
		if (handle->cleaned_up && !handle->dirty && !handle->mode_dirty &&
			!handle->atime_dirty && !handle->mtime_dirty)
			handle->modified_after_cleanup = false;
	}
	scpfs_fill_file_info(handle, file_info);
	ReleaseSRWLockExclusive(&instance->lock);
	return STATUS_SUCCESS;
}

static NTSTATUS scpfs_fs_set_file_size(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, UINT64 new_size, BOOLEAN set_allocation_size,
	FSP_FSCTL_FILE_INFO *file_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	LARGE_INTEGER position;
	NTSTATUS status = STATUS_SUCCESS;
	if (instance == NULL || handle == NULL || file_info == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}
	if (handle->directory) {
		status = STATUS_FILE_IS_A_DIRECTORY;
		goto done;
	}
	if (handle->cache_file == NULL) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if (new_size > INT64_MAX) {
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}
	if (set_allocation_size)
		goto fill;
	position.QuadPart = (LONGLONG)new_size;
	if (!SetFilePointerEx(handle->cache_file, position, NULL, FILE_BEGIN) ||
		!SetEndOfFile(handle->cache_file)) {
		status = scpfs_map_win32_error(GetLastError());
		goto done;
	}
	if (instance->read_cache != NULL)
		scp_cache_invalidate_path(instance->read_cache, handle->remote_path);
	handle->file_size = new_size;
	handle->current.size = new_size;
	handle->dirty = true;
	scpfs_mark_modified(handle);
fill:
	scpfs_fill_file_info(handle, file_info);
done:
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_can_delete(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PWSTR file_name)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	NTSTATUS status = STATUS_SUCCESS;
	if (instance == NULL || handle == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (handle->owner != instance || handle->deleted) {
		status = STATUS_INVALID_HANDLE;
	} else if (handle->stale_namespace) {
		status = STATUS_FILE_DELETED;
	} else if (scpfs_is_root_path(handle->remote_path)) {
		status = STATUS_ACCESS_DENIED;
	} else if (scpfs_has_other_open_path(instance, handle->remote_path, handle) ||
		(handle->directory && scpfs_has_open_descendant(instance, handle->remote_path, handle))) {
		status = STATUS_SHARING_VIOLATION;
	} else if (handle->directory) {
		SCPFS_DIR_LIST list;
		memset(&list, 0, sizeof(list));
		status = scp_backend_list(instance->backend, handle->remote_path, &list);
		if (NT_SUCCESS(status) && list.count != 0)
			status = STATUS_DIRECTORY_NOT_EMPTY;
		scp_backend_free_list(&list);
	}
	if (!NT_SUCCESS(status))
		scpfs_log_open_failure(instance,
			file_name != NULL ? file_name : handle->remote_path,
			L"CanDelete callback", status);
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static void scpfs_log_rename_failure(SCPFS *instance, SCPFS_HANDLE *handle,
	PCWSTR target_path, PCWSTR stage, NTSTATUS status)
{
	PCWSTR log_path;
	WCHAR *operation;
	size_t capacity;
	int length;
	bool owner_matches = handle != NULL && instance != NULL && handle->owner == instance;
	if (instance == NULL) {
		SCPFS_HANDLE log_handle;
		memset(&log_handle, 0, sizeof(log_handle));
		log_handle.remote_path = (WCHAR *)(target_path != NULL ? target_path : L"(unknown)");
		scpfs_log_failure(&log_handle, L"rename with invalid filesystem context", status, NULL);
		return;
	}
	log_path = owner_matches && handle->remote_path != NULL ? handle->remote_path :
		(target_path != NULL ? target_path : L"(unknown)");
	capacity = (target_path != NULL ? wcslen(target_path) : 0) + 320;
	if (capacity > SIZE_MAX / sizeof(WCHAR))
		return;
	operation = (WCHAR *)malloc(capacity * sizeof(WCHAR));
	if (operation == NULL)
		return;
	length = swprintf_s(operation, capacity,
		L"rename stage=%s context=%p owner_match=%u deleted=%u cleaned_up=%u dirty=%u inbox_attempted=%u target=%s",
		stage != NULL ? stage : L"unknown", (void *)handle,
		owner_matches ? 1U : 0U,
		owner_matches && handle->deleted ? 1U : 0U,
		owner_matches && handle->cleaned_up ? 1U : 0U,
		owner_matches && handle->dirty ? 1U : 0U,
		owner_matches && handle->inbox_attempted ? 1U : 0U,
		target_path != NULL ? target_path : L"(null)");
	if (length >= 0)
		scpfs_log_open_failure(instance, log_path, operation, status);
	free(operation);
}

static NTSTATUS scpfs_fs_rename(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PWSTR file_name, PWSTR new_file_name,
	BOOLEAN replace_if_exists)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *handle = (SCPFS_HANDLE *)file_context;
	SCPFS_REMOTE_STAT destination_stat;
	SCPFS_REMOTE_STAT parent_stat;
	WCHAR *parent_path = NULL;
	WCHAR *new_path_copy = NULL;
	NTSTATUS status;
	PCWSTR stage = L"validate callback arguments";
	bool destination_exists = false;
	bool command_target = false;
	(void)file_name;

	if (instance == NULL || handle == NULL || new_file_name == NULL) {
		scpfs_log_rename_failure(instance, handle, new_file_name, stage,
			STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}
	stage = L"validate target path";
	if (!scpfs_valid_path(new_file_name, false)) {
		scpfs_log_rename_failure(instance, handle, new_file_name, stage,
			STATUS_OBJECT_NAME_INVALID);
		return STATUS_OBJECT_NAME_INVALID;
	}
	AcquireSRWLockExclusive(&instance->lock);
	stage = L"validate file context";
	if (handle->owner != instance || handle->deleted) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}
	if (handle->stale_namespace) {
		status = STATUS_FILE_DELETED;
		goto done;
	}
	command_target = !handle->directory && scpfs_is_inbox_command_path(new_file_name);
	stage = L"reject root rename";
	if (scpfs_is_root_path(handle->remote_path)) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	stage = L"validate source handles";
	if (scpfs_has_other_open_path(instance, handle->remote_path, handle) ||
		(handle->directory &&
		 (scpfs_path_is_descendant(new_file_name, handle->remote_path) ||
		  scpfs_has_open_descendant(instance, handle->remote_path, handle)))) {
		status = STATUS_SHARING_VIOLATION;
		goto done;
	}
	if (scpfs_path_equal(handle->remote_path, new_file_name)) {
		stage = L"same-path inbox commit";
		status = command_target ? scpfs_commit_handle(handle, L"rename inbox commit") : STATUS_SUCCESS;
		if (NT_SUCCESS(status) && command_target) {
			stage = L"same-path inbox execute";
			status = scpfs_execute_inbox_after_commit(handle, L"rename command");
		}
		goto done;
	}
	stage = L"allocate parent path";
	parent_path = scpfs_parent_path(new_file_name);
	if (parent_path == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	stage = L"stat destination parent";
	status = scpfs_stat_path(instance, parent_path, &parent_stat);
	if (!NT_SUCCESS(status))
		goto done;
	if (parent_stat.type != SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_NOT_A_DIRECTORY;
		goto done;
	}
	stage = L"allocate renamed path";
	new_path_copy = scpfs_wcsdup(new_file_name);
	if (new_path_copy == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	stage = L"stat rename destination";
	status = scpfs_stat_path(instance, new_file_name, &destination_stat);
	if (NT_SUCCESS(status)) {
		destination_exists = true;
		if (!replace_if_exists) {
			status = STATUS_OBJECT_NAME_COLLISION;
			goto done;
		}
		if (!handle->remote_exists) {
			/* Keep replacement semantics explicit until the new file is published. */
			status = STATUS_NOT_SUPPORTED;
			goto done;
		}
		if (scpfs_has_open_path(instance, new_file_name) ||
			(handle->directory && scpfs_has_open_descendant(instance, new_file_name, NULL))) {
			status = STATUS_SHARING_VIOLATION;
			goto done;
		}
		if ((handle->directory && destination_stat.type != SCPFS_REMOTE_DIRECTORY) ||
			(!handle->directory && destination_stat.type != SCPFS_REMOTE_FILE)) {
			status = handle->directory ? STATUS_NOT_A_DIRECTORY : STATUS_FILE_IS_A_DIRECTORY;
			goto done;
		}
	} else if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
		status == STATUS_OBJECT_PATH_NOT_FOUND || status == STATUS_NO_SUCH_FILE) {
		status = STATUS_SUCCESS;
	} else {
		goto done;
	}
	if (command_target) {
		stage = L"pre-rename inbox commit";
		status = scpfs_commit_handle(handle, L"rename inbox commit");
		if (!NT_SUCCESS(status))
			goto done;
	}
	if (handle->remote_exists) {
		stage = L"remote rename";
		scpfs_cache_invalidate_all(instance);
		status = scp_backend_rename(instance->backend, handle->remote_path,
			new_file_name, destination_exists && replace_if_exists);
		if (!NT_SUCCESS(status))
			goto done;
		scpfs_mark_metadata_handles_stale(instance, handle->remote_path,
			handle->directory, handle);
		if (destination_exists && replace_if_exists)
			scpfs_mark_metadata_handles_stale(instance, new_file_name,
				destination_stat.type == SCPFS_REMOTE_DIRECTORY, handle);
	}
	free(handle->remote_path);
	handle->remote_path = new_path_copy;
	new_path_copy = NULL;
	status = STATUS_SUCCESS;
	if (command_target) {
		stage = L"post-rename inbox execute";
		status = scpfs_execute_inbox_after_commit(handle, L"rename command");
	}

done:
	if (!NT_SUCCESS(status))
		scpfs_log_rename_failure(instance, handle, new_file_name, stage, status);
	free(new_path_copy);
	free(parent_path);
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

/* Called with instance->lock held and the directory buffer acquired. */
static NTSTATUS scpfs_fill_directory_snapshot(SCPFS *instance,
	SCPFS_HANDLE *directory, PCWSTR pattern)
{
	SCPFS_DIR_LIST list;
	SCPFS_REMOTE_STAT parent_stat;
	WCHAR *parent_path = NULL;
	NTSTATUS status;
	size_t i;

	memset(&list, 0, sizeof(list));
	/* scpfs_read_list returns entries already sorted by ordinal name. */
	status = scpfs_read_list(instance, directory->remote_path, &list);
	if (!NT_SUCCESS(status))
		goto done;
	if (!scpfs_is_root_path(directory->remote_path)) {
		if (scpfs_is_name_in_pattern(pattern, L".")) {
			status = scpfs_fill_dir_entry(directory, directory->remote_path,
				&directory->current, L".");
			if (!NT_SUCCESS(status))
				goto done;
		}
		parent_path = scpfs_parent_path(directory->remote_path);
		if (parent_path == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		status = scpfs_read_stat(instance, parent_path, &parent_stat);
		if (!NT_SUCCESS(status))
			goto done;
		if (scpfs_is_name_in_pattern(pattern, L"..")) {
			status = scpfs_fill_dir_entry(directory, parent_path, &parent_stat, L"..");
			if (!NT_SUCCESS(status))
				goto done;
		}
	}
	for (i = 0; i < list.count; i++) {
		SCPFS_DIR_ENTRY *entry = &list.entries[i];
		WCHAR *entry_path = NULL;
		if (!scpfs_valid_name(entry->name, entry->name_length) ||
			!scpfs_is_remote_object_supported(&entry->stat) ||
			!scpfs_is_name_in_pattern(pattern, entry->name))
			continue;
		if (!scpfs_join_path(directory->remote_path, entry->name,
			entry->name_length, &entry_path))
			continue;
		status = scpfs_fill_dir_entry(directory, entry_path, &entry->stat, entry->name);
		free(entry_path);
		if (!NT_SUCCESS(status))
			goto done;
	}
	status = STATUS_SUCCESS;
done:
	free(parent_path);
	scp_backend_free_list(&list);
	return status;
}

static NTSTATUS scpfs_fs_read_directory(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PWSTR pattern, PWSTR marker,
	PVOID buffer, ULONG length, PULONG bytes_transferred)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *directory = (SCPFS_HANDLE *)file_context;
	NTSTATUS status = STATUS_SUCCESS;

	if (instance == NULL || directory == NULL || bytes_transferred == NULL)
		return STATUS_INVALID_PARAMETER;
	*bytes_transferred = 0;
	if (buffer == NULL && length != 0)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (directory->owner != instance || directory->deleted) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}
	if (!directory->directory) {
		status = STATUS_NOT_A_DIRECTORY;
		goto done;
	}
	/*
	 * Snapshot the listing once per enumeration (marker == NULL) and serve
	 * continuation pages from it. Re-listing per page cost a remote find for
	 * every buffer of a large directory, and could skip or repeat entries
	 * that changed between pages.
	 */
	if (FspFileSystemAcquireDirectoryBuffer(&directory->dir_buffer,
		marker == NULL, &status)) {
		status = scpfs_fill_directory_snapshot(instance, directory, pattern);
		FspFileSystemReleaseDirectoryBuffer(&directory->dir_buffer);
	}
	if (!NT_SUCCESS(status))
		goto done;
	FspFileSystemReadDirectoryBuffer(&directory->dir_buffer, marker,
		buffer, length, bytes_transferred);
	status = STATUS_SUCCESS;
done:
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static NTSTATUS scpfs_fs_get_dir_info_by_name(FSP_FILE_SYSTEM *file_system,
	PVOID file_context, PWSTR file_name, FSP_FSCTL_DIR_INFO *dir_info)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	SCPFS_HANDLE *directory = (SCPFS_HANDLE *)file_context;
	SCPFS_REMOTE_STAT stat;
	WCHAR *path = NULL;
	PCWSTR output_name = file_name;
	NTSTATUS status;
	size_t name_chars;
	size_t name_bytes;

	if (instance == NULL || directory == NULL || file_name == NULL || dir_info == NULL)
		return STATUS_INVALID_PARAMETER;
	AcquireSRWLockExclusive(&instance->lock);
	if (directory->owner != instance || directory->deleted) {
		status = STATUS_INVALID_HANDLE;
		goto done;
	}
	if (!directory->directory) {
		status = STATUS_NOT_A_DIRECTORY;
		goto done;
	}
	if (wcscmp(file_name, L".") == 0) {
		path = scpfs_wcsdup(directory->remote_path);
	} else if (wcscmp(file_name, L"..") == 0) {
		path = scpfs_parent_path(directory->remote_path);
		if (path == NULL && scpfs_is_root_path(directory->remote_path))
			path = scpfs_wcsdup(L"\\");
	} else if (scpfs_valid_name(file_name, wcslen(file_name))) {
		if (!scpfs_join_path(directory->remote_path, file_name,
			wcslen(file_name), &path)) {
			status = STATUS_OBJECT_NAME_INVALID;
			goto done;
		}
	} else {
		status = STATUS_OBJECT_NAME_INVALID;
		goto done;
	}
	if (path == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	status = scpfs_read_stat(instance, path, &stat);
	if (!NT_SUCCESS(status))
		goto done;
	if (!scpfs_is_remote_object_supported(&stat)) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	name_chars = wcslen(output_name);
	if (name_chars > SCPFS_MAX_COMPONENT_CHARS) {
		status = STATUS_OBJECT_NAME_INVALID;
		goto done;
	}
	name_bytes = name_chars * sizeof(WCHAR);
	memset(dir_info, 0, sizeof(*dir_info) + name_bytes);
	dir_info->Size = (UINT16)(sizeof(*dir_info) + name_bytes);
	{
		SCPFS_HANDLE temporary;
		memset(&temporary, 0, sizeof(temporary));
		temporary.remote_path = path;
		temporary.current = stat;
		temporary.directory = stat.type == SCPFS_REMOTE_DIRECTORY;
		temporary.file_size = stat.size;
		scpfs_fill_file_info(&temporary, &dir_info->FileInfo);
	}
	if (name_bytes != 0)
		memcpy(dir_info->FileNameBuf, output_name, name_bytes);
	status = STATUS_SUCCESS;

done:
	free(path);
	ReleaseSRWLockExclusive(&instance->lock);
	return status;
}

static VOID NTAPI scpfs_fs_dispatcher_stopped(FSP_FILE_SYSTEM *file_system,
	BOOLEAN normally)
{
	SCPFS *instance = scpfs_from_file_system(file_system);
	if (instance == NULL)
		return;
	InterlockedExchange(&instance->dispatcher_stop_reason,
		normally ? SCPFS_DISPATCHER_STOPPED_NORMALLY : SCPFS_DISPATCHER_STOPPED_ABNORMALLY);
}

static const FSP_FILE_SYSTEM_INTERFACE g_scpfs_interface = {
	.GetVolumeInfo = scpfs_fs_get_volume_info,
	.SetVolumeLabel = scpfs_fs_set_volume_label,
	.GetSecurityByName = scpfs_fs_get_security_by_name,
	.Create = scpfs_fs_create,
	.Open = scpfs_fs_open,
	.Overwrite = scpfs_fs_overwrite,
	.Cleanup = scpfs_fs_cleanup,
	.Close = scpfs_fs_close,
	.Read = scpfs_fs_read,
	.Write = scpfs_fs_write,
	.Flush = scpfs_fs_flush,
	.GetFileInfo = scpfs_fs_get_file_info,
	.SetBasicInfo = scpfs_fs_set_basic_info,
	.SetFileSize = scpfs_fs_set_file_size,
	.CanDelete = scpfs_fs_can_delete,
	.Rename = scpfs_fs_rename,
	.ReadDirectory = scpfs_fs_read_directory,
	.GetDirInfoByName = scpfs_fs_get_dir_info_by_name,
	.DispatcherStopped = scpfs_fs_dispatcher_stopped,
};

static bool scpfs_append_path(PCWSTR left, PCWSTR right, WCHAR **out)
{
	size_t left_length;
	size_t right_length;
	bool needs_separator;
	WCHAR *result;

	if (left == NULL || right == NULL || out == NULL)
		return false;
	*out = NULL;
	left_length = wcslen(left);
	right_length = wcslen(right);
	needs_separator = left_length != 0 && left[left_length - 1] != L'\\' && left[left_length - 1] != L'/';
	if (left_length + right_length + (needs_separator ? 1 : 0) + 1 > SCPFS_MAX_PATH_CHARS)
		return false;
	result = (WCHAR *)malloc((left_length + right_length + 2) * sizeof(WCHAR));
	if (result == NULL)
		return false;
	memcpy(result, left, left_length * sizeof(WCHAR));
	if (needs_separator)
		result[left_length++] = L'\\';
	memcpy(result + left_length, right, (right_length + 1) * sizeof(WCHAR));
	*out = result;
	return true;
}

/*
 * Returns an absolute "\\?\" form of path. Cache payloads live several levels
 * below %TMP% with GUID names, so an ordinary %TMP% of ~120 characters already
 * pushed read-*.cache past MAX_PATH and silently disabled the read cache.
 */
static WCHAR *scpfs_long_path(PCWSTR path)
{
	DWORD required, written;
	WCHAR *full, *result;
	size_t length, prefix_length;
	PCWSTR prefix, tail;

	if (path == NULL || path[0] == L'\0')
		return NULL;
	if (wcsncmp(path, L"\\\\?\\", 4) == 0)
		return scpfs_wcsdup(path);
	required = GetFullPathNameW(path, 0, NULL, NULL);
	if (required == 0)
		return NULL;
	full = (WCHAR *)malloc((size_t)required * sizeof(WCHAR));
	if (full == NULL)
		return NULL;
	written = GetFullPathNameW(path, required, full, NULL);
	if (written == 0 || written >= required) {
		free(full);
		return NULL;
	}
	if (full[0] == L'\\' && full[1] == L'\\') {
		prefix = L"\\\\?\\UNC\\";
		tail = full + 2;
	} else {
		prefix = L"\\\\?\\";
		tail = full;
	}
	prefix_length = wcslen(prefix);
	length = prefix_length + wcslen(tail);
	result = (WCHAR *)malloc((length + 1) * sizeof(WCHAR));
	if (result != NULL) {
		memcpy(result, prefix, prefix_length * sizeof(WCHAR));
		memcpy(result + prefix_length, tail, (wcslen(tail) + 1) * sizeof(WCHAR));
	}
	free(full);
	return result;
}

static NTSTATUS scpfs_prepare_cache_directory(PCWSTR requested_parent,
	WCHAR **session_directory_out)
{
	WCHAR temp_buffer[SCPFS_MAX_PATH_CHARS + 1];
	WCHAR *base = NULL;
	WCHAR *scpfs_root = NULL;
	WCHAR *session_path = NULL;
	DWORD temp_length;
	DWORD attributes;
	NTSTATUS status = STATUS_SUCCESS;
	unsigned int attempt;

	if (session_directory_out == NULL)
		return STATUS_INVALID_PARAMETER;
	*session_directory_out = NULL;
	if (requested_parent != NULL) {
		base = scpfs_long_path(requested_parent);
		if (base == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;
		attributes = GetFileAttributesW(base);
		if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			status = attributes == INVALID_FILE_ATTRIBUTES
				? scpfs_map_win32_error(GetLastError()) : STATUS_NOT_A_DIRECTORY;
			goto done;
		}
	} else {
		temp_length = GetEnvironmentVariableW(L"TMP", temp_buffer,
			_countof(temp_buffer));
		if (temp_length == 0 || temp_length >= _countof(temp_buffer)) {
			temp_length = GetTempPathW(_countof(temp_buffer), temp_buffer);
			if (temp_length == 0 || temp_length >= _countof(temp_buffer)) {
				status = scpfs_map_win32_error(GetLastError());
				goto done;
			}
		} else {
			temp_buffer[temp_length] = L'\0';
		}
		base = scpfs_long_path(temp_buffer);
		if (base == NULL || !scpfs_append_path(base, SCPFS_DEFAULT_CACHE_ROOT, &scpfs_root)) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		free(base);
		base = NULL;
		if (!CreateDirectoryW(scpfs_root, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
			status = scpfs_map_win32_error(GetLastError());
			goto done;
		}
		attributes = GetFileAttributesW(scpfs_root);
		if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			status = STATUS_NOT_A_DIRECTORY;
			goto done;
		}
		base = scpfs_root;
		scpfs_root = NULL;
	}
	for (attempt = 0; attempt < 32; attempt++) {
		GUID guid;
		WCHAR guid_text[40];
		WCHAR leaf[64];
		HRESULT hr = CoCreateGuid(&guid);
		if (FAILED(hr) || StringFromGUID2(&guid, guid_text, _countof(guid_text)) == 0) {
			status = STATUS_UNSUCCESSFUL;
			goto done;
		}
		if (swprintf_s(leaf, _countof(leaf), L"session-%s", guid_text) < 0 ||
			!scpfs_append_path(base, leaf, &session_path)) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		if (CreateDirectoryW(session_path, NULL)) {
			*session_directory_out = session_path;
			session_path = NULL;
			goto done;
		}
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			status = scpfs_map_win32_error(GetLastError());
			goto done;
		}
		free(session_path);
		session_path = NULL;
	}
	status = STATUS_OBJECT_NAME_COLLISION;

done:
	free(base);
	free(scpfs_root);
	free(session_path);
	return status;
}

static bool scpfs_directory_contains_files(PCWSTR directory)
{
	WCHAR *pattern = NULL;
	WIN32_FIND_DATAW find_data;
	HANDLE find_handle;
	bool contains = false;

	if (!scpfs_append_path(directory, L"*", &pattern))
		return true;
	find_handle = FindFirstFileW(pattern, &find_data);
	free(pattern);
	if (find_handle == INVALID_HANDLE_VALUE)
		return true;
	do {
		if (wcscmp(find_data.cFileName, L".") != 0 &&
			wcscmp(find_data.cFileName, L"..") != 0) {
			contains = true;
			break;
		}
	} while (FindNextFileW(find_handle, &find_data));
	FindClose(find_handle);
	return contains;
}

static NTSTATUS scpfs_create_default_security_descriptor(PCWSTR authorized_user_sid,
	PSECURITY_DESCRIPTOR *descriptor_out, DWORD *descriptor_size_out)
{
	HANDLE token = NULL;
	PTOKEN_USER token_user = NULL;
	WCHAR *user_sid = NULL;
	WCHAR *authorized_sid = NULL;
	WCHAR *sddl = NULL;
	PSID authorized_sid_value = NULL;
	BYTE system_sid_storage[SECURITY_MAX_SID_SIZE];
	DWORD system_sid_size = sizeof(system_sid_storage);
	PSID system_sid = system_sid_storage;
	PCWSTR user_ace_sid = NULL;
	PCWSTR authorized_ace_sid = NULL;
	DWORD required = 0;
	size_t sddl_capacity;
	NTSTATUS status = STATUS_ACCESS_DENIED;
	if (descriptor_out == NULL || descriptor_size_out == NULL)
		return STATUS_INVALID_PARAMETER;
	*descriptor_out = NULL;
	*descriptor_size_out = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		goto done;
	(void)GetTokenInformation(token, TokenUser, NULL, 0, &required);
	if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto done;
	token_user = (PTOKEN_USER)malloc(required);
	if (token_user == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	if (!GetTokenInformation(token, TokenUser, token_user, required, &required))
		goto done;
	if (!ConvertSidToStringSidW(token_user->User.Sid, &user_sid))
		goto done;
	if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid, &system_sid_size))
		goto done;
	if (authorized_user_sid != NULL) {
		if (authorized_user_sid[0] == L'\0') {
			status = STATUS_INVALID_PARAMETER;
			goto done;
		}
		if (!ConvertStringSidToSidW(authorized_user_sid, &authorized_sid_value)) {
			status = GetLastError() == ERROR_NOT_ENOUGH_MEMORY ?
				STATUS_INSUFFICIENT_RESOURCES : STATUS_INVALID_PARAMETER;
			goto done;
		}
		if (!IsValidSid(authorized_sid_value) ||
			!ConvertSidToStringSidW(authorized_sid_value, &authorized_sid)) {
			status = IsValidSid(authorized_sid_value) ?
				STATUS_ACCESS_DENIED : STATUS_INVALID_PARAMETER;
			goto done;
		}
	}
	/* SID text is bounded by the Windows SID format; keep all sizing arithmetic explicit. */
	{
		size_t user_chars = wcslen(user_sid);
		size_t authorized_chars = authorized_sid != NULL ? wcslen(authorized_sid) : 0;
		if (user_chars > 512 || authorized_chars > 512) {
			status = STATUS_INVALID_PARAMETER;
			goto done;
		}
		sddl_capacity = user_chars * 3u + authorized_chars + 96u;
	}
	sddl = (WCHAR *)malloc(sddl_capacity * sizeof(WCHAR));
	if (sddl == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	/* Preserve launch-user access; SYSTEM and the explicitly authorized user inherit to children. */
	if (!EqualSid(token_user->User.Sid, system_sid))
		user_ace_sid = user_sid;
	if (authorized_sid != NULL &&
		!EqualSid(authorized_sid_value, system_sid) &&
		!EqualSid(authorized_sid_value, token_user->User.Sid))
		authorized_ace_sid = authorized_sid;
	if (swprintf_s(sddl, sddl_capacity, L"O:%sG:%sD:P(A;OICI;FA;;;SY)",
		user_sid, user_sid) < 0)
		goto done;
	if (user_ace_sid != NULL) {
		if (swprintf_s(sddl + wcslen(sddl), sddl_capacity - wcslen(sddl),
			L"(A;OICI;FA;;;%s)", user_ace_sid) < 0)
			goto done;
	}
	if (authorized_ace_sid != NULL) {
		if (swprintf_s(sddl + wcslen(sddl), sddl_capacity - wcslen(sddl),
			L"(A;OICI;FA;;;%s)", authorized_ace_sid) < 0)
			goto done;
	}
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
		SDDL_REVISION_1, descriptor_out, descriptor_size_out))
		goto done;
	status = STATUS_SUCCESS;
done:
	if (sddl != NULL)
		free(sddl);
	if (authorized_sid != NULL)
		LocalFree(authorized_sid);
	if (authorized_sid_value != NULL)
		LocalFree(authorized_sid_value);
	if (user_sid != NULL)
		LocalFree(user_sid);
	free(token_user);
	if (token != NULL)
		CloseHandle(token);
	return status;
}

static NTSTATUS scpfs_resolve_create_failure(void *backend_context,
	NTSTATUS first_create_status, BOOL *retry_create, DWORD *win32_detail_out)
{
	DWORD driver_error;
	(void)backend_context;
	if (retry_create != NULL)
		*retry_create = FALSE;
	if (win32_detail_out != NULL)
		*win32_detail_out = ERROR_SUCCESS;
	if (first_create_status != STATUS_NO_SUCH_DEVICE &&
		first_create_status != STATUS_DRIVER_UNABLE_TO_LOAD)
		return first_create_status;
	driver_error = scpfs_winfsp_install_embedded_driver();
	if (driver_error == ERROR_SUCCESS ||
		driver_error == ERROR_SERVICE_ALREADY_RUNNING) {
		if (retry_create != NULL)
			*retry_create = TRUE;
		return STATUS_SUCCESS;
	}
	if (win32_detail_out != NULL)
		*win32_detail_out = driver_error;
	fprintf(stderr,
		"SCPFS: WinFsp driver start failed with Win32 error %lu after FspFileSystemCreate NTSTATUS 0x%08lX; original status preserved.\n",
		(unsigned long)driver_error, (unsigned long)first_create_status);
	return first_create_status;
}

NTSTATUS scpfs_create(const SCPFS_OPTIONS *options, SCPFS **instance_out)
{
	SCPFS *instance = NULL;
	SCPFS_REMOTE_STAT root_stat;
	FSP_FSCTL_VOLUME_PARAMS volume_params;
	FSF_WINFSP_CONFIG frontend_config;
	DWORD frontend_win32_detail = ERROR_SUCCESS;
	NTSTATUS status;
	LARGE_INTEGER counter;
	SCPFS_BACKEND_OPTIONS monitor_options;
	WCHAR *monitor_root = NULL;

	if (options == NULL || instance_out == NULL || options->backend.host == NULL ||
		options->backend.username == NULL || options->backend.remote_root == NULL ||
		options->backend.known_hosts_file == NULL || options->backend.identity_file == NULL ||
		options->command_timeout_ms > SCPFS_MAX_COMMAND_TIMEOUT_MS ||
		options->read_cache_max_mib > 16384U)
		return STATUS_INVALID_PARAMETER;
	*instance_out = NULL;
	instance = (SCPFS *)calloc(1, sizeof(*instance));
	if (instance == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	InitializeSRWLock(&instance->lock);
	instance->dispatcher_stop_reason = SCPFS_DISPATCHER_ACTIVE;
	instance->volume_label[0] = L'S';
	instance->volume_label[1] = L'C';
	instance->volume_label[2] = L'P';
	instance->volume_label[3] = L'F';
	instance->volume_label[4] = L'S';
	instance->volume_label_bytes = 5 * sizeof(WCHAR);
	instance->command_timeout_ms = options->command_timeout_ms != 0 ?
		options->command_timeout_ms : 30000U;
	instance->read_cache_max_mib = options->read_cache_max_mib;
	status = scpfs_create_default_security_descriptor(options->authorized_user_sid,
		&instance->default_security, &instance->default_security_size);
	if (!NT_SUCCESS(status))
		goto fail;
	QueryPerformanceCounter(&counter);
	instance->cache_counter = (LONG)(counter.LowPart & 0x3fffffff);

	status = scp_backend_connect(&options->backend, &instance->backend);
	if (!NT_SUCCESS(status))
		goto fail;
	status = scp_backend_stat(instance->backend, L"\\", &root_stat);
	if (!NT_SUCCESS(status))
		goto fail;
	if (root_stat.type != SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_NOT_A_DIRECTORY;
		goto fail;
	}
	status = scpfs_prepare_cache_directory(options->cache_directory,
		&instance->cache_directory);
	if (!NT_SUCCESS(status))
		goto fail;
	if (NT_SUCCESS(scp_cache_create(instance->cache_directory,
		instance->read_cache_max_mib, &instance->read_cache))) {
		/* Change notifications are required for reuse. Startup failure is
		 * deliberately cache-off and does not change mount availability. */
		monitor_root = scp_backend_dup_remote_root(instance->backend);
		if (monitor_root != NULL) {
			monitor_options = options->backend;
			monitor_options.remote_root = monitor_root;
			if (!NT_SUCCESS(scp_watch_start(&monitor_options, &instance->watch)))
				instance->watch = NULL;
			free(monitor_root);
			monitor_root = NULL;
		}
	}
	instance->remote_host = scpfs_wcsdup(options->backend.host);
	instance->remote_root = scpfs_wcsdup(options->backend.remote_root);
	if (instance->remote_host == NULL || instance->remote_root == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto fail;
	}
	memset(&volume_params, 0, sizeof(volume_params));
	volume_params.Version = sizeof(volume_params);
	volume_params.SectorSize = SCPFS_SECTOR_SIZE;
	volume_params.SectorsPerAllocationUnit = 1;
	/* The WinFsp FSD measures components in WCHARs despite fsctl.h's "bytes". */
	volume_params.MaxComponentLength = SCPFS_MAX_COMPONENT_CHARS;
	volume_params.VolumeCreationTime = scpfs_unix_ns_to_filetime(scpfs_now_unix_ns());
	volume_params.VolumeSerialNumber = (uint32_t)(GetTickCount64() & 0xffffffffU);
	volume_params.FileInfoTimeout = 0;
	volume_params.CaseSensitiveSearch = 1;
	volume_params.CasePreservedNames = 1;
	volume_params.UnicodeOnDisk = 1;
	volume_params.PersistentAcls = 0;
	/*
	 * SCPFS_HANDLE is a per-open descriptor: it owns a cache HANDLE, snapshot,
	 * and cleanup/command state. WinFsp's default FileContext is a file-node
	 * identity that must stay stable while any reference to the name is open,
	 * which is incompatible with allocating and retiring one SCPFS_HANDLE per
	 * Open/Create. Use UserContext2 so callbacks receive the descriptor returned
	 * by each successful Open/Create instead.
	 */
	volume_params.UmFileContextIsUserContext2 = 1;
	/* Cleanup represents the last user close and must run for clean/read-only inboxes too. */
	volume_params.PostCleanupWhenModifiedOnly = 0;
	volume_params.IrpTimeout = FspFsctlIrpTimeoutMaximum;
	volume_params.PassQueryDirectoryFileName = 1;
	volume_params.PassQueryDirectoryPattern = 1;
	volume_params.PostDispositionWhenNecessaryOnly = 1;
	volume_params.SupportsPosixUnlinkRename = 0;
	wcscpy_s(volume_params.FileSystemName,
		_countof(volume_params.FileSystemName), L"SCPFS");
	memset(&frontend_config, 0, sizeof(frontend_config));
	frontend_config.struct_size = sizeof(frontend_config);
	frontend_config.abi_version = FS_FRONTEND_ABI_VERSION;
	frontend_config.operation_table_size = sizeof(g_scpfs_interface);
	frontend_config.backend_context = instance;
	frontend_config.operations = &g_scpfs_interface;
	frontend_config.volume_params = volume_params;
	frontend_config.resolve_create_failure = scpfs_resolve_create_failure;
	status = fsf_winfsp_create(&frontend_config, &instance->frontend,
		&frontend_win32_detail);
	if (!NT_SUCCESS(status))
	{
		if (frontend_win32_detail != ERROR_SUCCESS)
			fprintf(stderr, "SCPFS: WinFsp frontend creation failed with NTSTATUS 0x%08lX and Win32 error %lu.\n",
				(unsigned long)status, (unsigned long)frontend_win32_detail);
		goto fail;
	}
	instance->file_system = fsf_winfsp_object(instance->frontend);
	if (instance->file_system == NULL) {
		status = STATUS_INTERNAL_ERROR;
		goto fail;
	}
	FspFileSystemSetOperationGuardStrategy(instance->file_system,
		FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE);
	*instance_out = instance;
	return STATUS_SUCCESS;

fail:
	if (instance != NULL) {
		if (instance->watch != NULL)
			scp_watch_stop(instance->watch);
		if (instance->read_cache != NULL)
			scp_cache_destroy(instance->read_cache);
		if (instance->frontend != NULL)
			fsf_winfsp_destroy(instance->frontend);
		if (instance->backend != NULL)
			scp_backend_disconnect(instance->backend);
		if (instance->default_security != NULL)
			LocalFree(instance->default_security);
		if (instance->cache_directory != NULL)
			RemoveDirectoryW(instance->cache_directory);
		free(monitor_root);
		free(instance->cache_directory);
		free(instance->remote_host);
		free(instance->remote_root);
		free(instance);
	}
	return status;
}

PCWSTR scpfs_cache_directory(const SCPFS *instance)
{
	return instance != NULL ? instance->cache_directory : NULL;
}

NTSTATUS scpfs_mount(SCPFS *instance, PCWSTR mount_point)
{
	if (instance == NULL || instance->frontend == NULL || mount_point == NULL)
		return STATUS_INVALID_PARAMETER;
	return fsf_winfsp_mount(instance->frontend, mount_point);
}

NTSTATUS scpfs_start(SCPFS *instance, uint32_t dispatcher_thread_count)
{
	NTSTATUS status;
	if (instance == NULL || instance->frontend == NULL)
		return STATUS_INVALID_PARAMETER;
	/*
	 * Keep cleanup and the following open/rename callback in IOQ order. WinFsp
	 * posts clean Cleanup requests best-effort; multiple dispatcher workers can
	 * dequeue Cleanup and Open together and race for the adapter's serialization
	 * lock, making a just-closed clean handle look active to the next callback.
	 * SCPFS already serializes its backend/cache callbacks, so extra workers do
	 * not provide useful backend parallelism.
	 */
	if (dispatcher_thread_count > 1)
		return STATUS_INVALID_PARAMETER;
	if (dispatcher_thread_count == 0)
		dispatcher_thread_count = 1;
	InterlockedExchange(&instance->dispatcher_stop_reason, SCPFS_DISPATCHER_ACTIVE);
	status = fsf_winfsp_start(instance->frontend, dispatcher_thread_count);
	if (NT_SUCCESS(status))
		instance->dispatcher_started = true;
	return status;
}

HANDLE scpfs_dispatcher_stopped_event(SCPFS *instance)
{
	return instance != NULL ? fsf_winfsp_stopped_event(instance->frontend) : NULL;
}

bool scpfs_dispatcher_stopped_normally(const SCPFS *instance)
{
	return instance != NULL && fsf_winfsp_dispatcher_stopped_normally(instance->frontend);
}

NTSTATUS scpfs_dispatcher_result(const SCPFS *instance)
{
	return instance != NULL ? fsf_winfsp_dispatcher_result(instance->frontend) :
		STATUS_INVALID_PARAMETER;
}

HANDLE scpfs_backend_failure_event(SCPFS *instance)
{
	return instance != NULL ? scp_backend_failure_event(instance->backend) : NULL;
}

NTSTATUS scpfs_backend_failure_status(const SCPFS *instance)
{
	return instance != NULL ? scp_backend_failure_status(instance->backend) :
		STATUS_INVALID_PARAMETER;
}

void scpfs_stop(SCPFS *instance)
{
	if (instance != NULL && instance->frontend != NULL && instance->dispatcher_started)
		fsf_winfsp_stop(instance->frontend);
}

void scpfs_destroy(SCPFS *instance)
{
	SCPFS_HANDLE *handle;
	bool cache_has_files;
	SCPFS_CACHE_COUNTERS cache_counters;
	if (instance == NULL)
		return;
	if (instance->frontend != NULL) {
		fsf_winfsp_destroy(instance->frontend);
		instance->frontend = NULL;
		instance->file_system = NULL;
	}
	/* The monitor owns its SSH session and may wait on a request. Join it only
	 * after WinFsp dispatch is stopped, and always outside the adapter lock. */
	if (instance->watch != NULL) {
		scp_watch_stop(instance->watch);
		instance->watch = NULL;
	}
	AcquireSRWLockExclusive(&instance->lock);
	while ((handle = instance->handles) != NULL) {
		if (!handle->deleted && !handle->inbox_recovery_pending &&
			(handle->dirty || handle->mode_dirty || handle->atime_dirty || handle->mtime_dirty))
			(void)scpfs_commit_handle(handle, L"shutdown");
		scpfs_unlink_handle(instance, handle);
		{
			bool keep_cache = handle->inbox_recovery_pending || (!handle->deleted &&
				(handle->dirty || handle->mode_dirty || handle->atime_dirty || handle->mtime_dirty));
			scpfs_dispose_handle(handle, !keep_cache);
		}
	}
	ReleaseSRWLockExclusive(&instance->lock);
	if (instance->read_cache != NULL) {
		scp_cache_get_counters(instance->read_cache, &cache_counters);
		fwprintf(stderr,
			L"SCPFS cache stats: stat_hit=%llu stat_miss=%llu list_hit=%llu list_miss=%llu payload_hit=%llu payload_miss=%llu evictions=%llu invalidations=%llu monitor_bypass=%llu\n",
			(unsigned long long)cache_counters.stat_hit,
			(unsigned long long)cache_counters.stat_miss,
			(unsigned long long)cache_counters.list_hit,
			(unsigned long long)cache_counters.list_miss,
			(unsigned long long)cache_counters.payload_hit,
			(unsigned long long)cache_counters.payload_miss,
			(unsigned long long)cache_counters.evictions,
			(unsigned long long)cache_counters.invalidations,
			(unsigned long long)cache_counters.monitor_bypass);
		fflush(stderr);
		scp_cache_destroy(instance->read_cache);
		instance->read_cache = NULL;
	}
	fwprintf(stderr,
		L"SCPFS cache admission diag: cold_attempt=%llu cold_unavailable=%llu cold_watch_unhealthy=%llu cold_ensure_failed=%llu cold_barrier_failed=%llu cold_pre_content_changed=%llu cold_post_barrier_failed=%llu cold_post_unhealthy=%llu cold_post_content_changed=%llu cold_stat_failed=%llu cold_verify_barrier_failed=%llu cold_verify_unhealthy=%llu cold_verify_content_changed=%llu cold_verify_metadata_changed=%llu cold_provenance_mismatch=%llu cold_atime_mismatch=%llu cold_put_attempt=%llu warm_candidate=%llu warm_metadata_stale=%llu warm_watch_unhealthy=%llu warm_ensure_failed=%llu warm_barrier_failed=%llu warm_stat_failed=%llu warm_verify_barrier_failed=%llu warm_verify_unhealthy=%llu warm_content_changed=%llu warm_metadata_changed=%llu warm_provenance_mismatch=%llu warm_copy_failed=%llu provenance_mask=0x%03X\n",
		(unsigned long long)instance->cache_diagnostics.cold_attempt,
		(unsigned long long)instance->cache_diagnostics.cold_unavailable,
		(unsigned long long)instance->cache_diagnostics.cold_watch_unhealthy,
		(unsigned long long)instance->cache_diagnostics.cold_ensure_failed,
		(unsigned long long)instance->cache_diagnostics.cold_barrier_failed,
		(unsigned long long)instance->cache_diagnostics.cold_pre_content_changed,
		(unsigned long long)instance->cache_diagnostics.cold_post_barrier_failed,
		(unsigned long long)instance->cache_diagnostics.cold_post_unhealthy,
		(unsigned long long)instance->cache_diagnostics.cold_post_content_changed,
		(unsigned long long)instance->cache_diagnostics.cold_stat_failed,
		(unsigned long long)instance->cache_diagnostics.cold_verify_barrier_failed,
		(unsigned long long)instance->cache_diagnostics.cold_verify_unhealthy,
		(unsigned long long)instance->cache_diagnostics.cold_verify_content_changed,
		(unsigned long long)instance->cache_diagnostics.cold_verify_metadata_changed,
		(unsigned long long)instance->cache_diagnostics.cold_provenance_mismatch,
		(unsigned long long)instance->cache_diagnostics.cold_atime_mismatch,
		(unsigned long long)instance->cache_diagnostics.cold_put_attempt,
		(unsigned long long)instance->cache_diagnostics.warm_candidate,
		(unsigned long long)instance->cache_diagnostics.warm_metadata_stale,
		(unsigned long long)instance->cache_diagnostics.warm_watch_unhealthy,
		(unsigned long long)instance->cache_diagnostics.warm_ensure_failed,
		(unsigned long long)instance->cache_diagnostics.warm_barrier_failed,
		(unsigned long long)instance->cache_diagnostics.warm_stat_failed,
		(unsigned long long)instance->cache_diagnostics.warm_verify_barrier_failed,
		(unsigned long long)instance->cache_diagnostics.warm_verify_unhealthy,
		(unsigned long long)instance->cache_diagnostics.warm_content_changed,
		(unsigned long long)instance->cache_diagnostics.warm_metadata_changed,
		(unsigned long long)instance->cache_diagnostics.warm_provenance_mismatch,
		(unsigned long long)instance->cache_diagnostics.warm_copy_failed,
		(unsigned int)instance->cache_diagnostics.provenance_mismatch_mask);
	fflush(stderr);
	if (instance->backend != NULL)
		scp_backend_disconnect(instance->backend);
	if (instance->default_security != NULL)
		LocalFree(instance->default_security);
	cache_has_files = instance->cache_directory != NULL &&
		scpfs_directory_contains_files(instance->cache_directory);
	if (!cache_has_files && instance->cache_directory != NULL)
		RemoveDirectoryW(instance->cache_directory);
	free(instance->cache_directory);
	free(instance->remote_host);
	free(instance->remote_root);
	free(instance);
}





