#include "scp_watch.h"
#include "scpfs_watch_embedded.h"

#include <ntstatus.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define SCPFS_WATCH_REQUEST_TIMEOUT_MS 15000u
#define SCPFS_WATCH_LIST_TIMEOUT_MS 120000u
#define SCPFS_WATCH_HEARTBEAT_MS 5000u
#define SCPFS_WATCH_RECONNECT_DELAY_MS 500u
#define SCPFS_WATCH_RECONNECT_MAX_DELAY_MS 30000u
#define SCPFS_WATCH_MAX_LINE 16384u
#define SCPFS_WATCH_READ_CHUNK 65536u
#define SCPFS_WATCH_MAX_QUEUED 256u
#define SCPFS_WATCH_MAX_ENTRIES 1000000u
/* Larger files use an SCP channel so one transfer never stalls the stream. */
#define SCPFS_WATCH_MAX_READ (8u * 1024u * 1024u)
#define SCPFS_WATCH_MAX_WRITE (8u * 1024u * 1024u)

typedef enum SCPFS_WATCH_REQUEST_KIND {
	SCPFS_WATCH_BARRIER,
	SCPFS_WATCH_STAT,
	SCPFS_WATCH_LIST,
	SCPFS_WATCH_STATFS,
	SCPFS_WATCH_READ,
	/* Mutations: once sent, a lost reply leaves the outcome unknown. */
	SCPFS_WATCH_WRITE,
	SCPFS_WATCH_SETMETA,
	SCPFS_WATCH_MKDIR,
	SCPFS_WATCH_REMOVE,
	SCPFS_WATCH_RENAME
} SCPFS_WATCH_REQUEST_KIND;

/* Wire letters, indexed by SCPFS_WATCH_REQUEST_KIND. */
static const char scp_watch_ops[] = "BSLFRPMKXN";

static bool
scp_watch_is_mutation(SCPFS_WATCH_REQUEST_KIND kind)
{
	return kind >= SCPFS_WATCH_WRITE;
}

typedef struct SCPFS_WATCH_REQUEST {
	struct SCPFS_WATCH_REQUEST *next;
	SCPFS_WATCH_REQUEST_KIND kind;
	uint64_t id;
	char *path;
	/* NULL for internal heartbeats, which nobody waits for. */
	HANDLE completed;
	ULONGLONG deadline;
	bool done;
	bool abandoned;
	/* Results, valid once done. */
	NTSTATUS status;
	bool cacheable;
	uint64_t sequence;
	SCPFS_REMOTE_STAT stat;
	SCPFS_DIR_LIST list;
	size_t list_remaining;
	size_t list_capacity;
	uint64_t total_bytes;
	uint64_t available_bytes;
	/* READ: size limit sent, then the content received after "D size". */
	uint64_t limit;
	char *data;
	size_t data_size;
	size_t data_received;
	bool data_pending;
	/* Mutations: text after the path (leading space), then raw bytes (WRITE). */
	char *args;
	char *payload;
	size_t payload_size;
} SCPFS_WATCH_REQUEST;

struct SCPFS_WATCH {
	CRITICAL_SECTION lock;
	HANDLE stop_event;
	HANDLE wake_event;
	HANDLE thread;
	SCPFS_CACHE *cache;
	SCPFS_BACKEND_OPTIONS options;
	WCHAR *host;
	WCHAR *username;
	WCHAR *remote_root;
	WCHAR *known_hosts_file;
	WCHAR *identity_file;
	WCHAR *identity_passphrase;
	SCPFS_WATCH_REQUEST *queue_head;
	SCPFS_WATCH_REQUEST *queue_tail;
	size_t queued;
	bool healthy;
	bool stopping;
	uint64_t next_request_id;
	/* Signaled while healthy (manual reset). */
	HANDLE healthy_event;
	/* Canonical root of the main connection, hex of its UTF-8; root_known is
	 * signaled once it is set. The helper's resolved root must match. */
	char *expected_root_hex;
	HANDLE root_known;
	/* Owned by the monitor thread. */
	SCPFS_WATCH_REQUEST *inflight_head;
	SCPFS_WATCH_REQUEST *inflight_tail;
	char *pending;
	size_t pending_length;
};

static WCHAR *
scp_watch_wcsdup(PCWSTR value)
{
	size_t count;
	WCHAR *copy;
	if(!value)
		return NULL;
	count = wcslen(value) + 1u;
	if(count > SIZE_MAX / sizeof(WCHAR))
		return NULL;
	copy = (WCHAR *)malloc(count * sizeof(WCHAR));
	if(copy)
		memcpy(copy, value, count * sizeof(WCHAR));
	return copy;
}

/* WinFsp path ("\\a\\b") to the helper's virtual path ("/a/b"). */
static char *
scp_watch_utf8_path(PCWSTR value)
{
	int length;
	char *result;
	int index;
	if(!value || value[0] != L'\\')
		return NULL;
	length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
		NULL, 0, NULL, NULL);
	if(length <= 0 || (size_t)length > (SCPFS_WATCH_MAX_LINE - 64u) / 2u)
		return NULL;
	result = (char *)malloc((size_t)length);
	if(!result)
		return NULL;
	if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
		result, length, NULL, NULL) != length) {
		free(result);
		return NULL;
	}
	for(index = 0; index < length - 1; index++) {
		if(result[index] == '\\')
			result[index] = '/';
		else if(result[index] == '/' || result[index] == '\n' || result[index] == '\r') {
			free(result);
			return NULL;
		}
	}
	return result;
}

static int
scp_watch_hex_value(char value)
{
	if(value >= '0' && value <= '9')
		return value - '0';
	if(value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	return -1;
}

/* Decodes hex in place-independent storage; returns byte count or -1. */
static int
scp_watch_unhex(const char *text, size_t text_length, char *out, size_t capacity)
{
	size_t index;
	if(text_length % 2u || text_length / 2u > capacity)
		return -1;
	for(index = 0; index < text_length; index += 2u) {
		int high = scp_watch_hex_value(text[index]);
		int low = scp_watch_hex_value(text[index + 1u]);
		if(high < 0 || low < 0)
			return -1;
		out[index / 2u] = (char)(high * 16 + low);
	}
	return (int)(text_length / 2u);
}

/* Helper virtual path bytes to a WinFsp path. NULL when not valid UTF-8. */
static WCHAR *
scp_watch_wide_path(const char *bytes, int length)
{
	int required;
	WCHAR *result;
	int index;
	if(length <= 0 || bytes[0] != '/')
		return NULL;
	required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, length,
		NULL, 0);
	if(required <= 0)
		return NULL;
	result = (WCHAR *)malloc(((size_t)required + 1u) * sizeof(WCHAR));
	if(!result)
		return NULL;
	if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, length,
		result, required) != required) {
		free(result);
		return NULL;
	}
	result[required] = L'\0';
	for(index = 0; index < required; index++) {
		if(result[index] == L'/')
			result[index] = L'\\';
	}
	return result;
}

/* Applies one C/M/T event line to the cache. */
static void
scp_watch_apply_event(SCPFS_WATCH *watch, char kind, const char *hex, size_t hex_length)
{
	char bytes[SCPFS_WATCH_MAX_LINE / 2u];
	unsigned flags = kind == 'M' ? SCPFS_CACHE_CHANGE_METADATA :
		kind == 'T' ? SCPFS_CACHE_CHANGE_SUBTREE : SCPFS_CACHE_CHANGE_CONTENT;
	int length = scp_watch_unhex(hex, hex_length, bytes, sizeof(bytes));
	WCHAR *path;
	if(length <= 0) {
		scp_cache_invalidate_all(watch->cache);
		return;
	}
	path = scp_watch_wide_path(bytes, length);
	while(!path && length > 1) {
		/* A name Windows cannot see: its parent's listing and stat still changed. */
		while(length > 1 && bytes[length - 1] != '/')
			length--;
		if(length > 1)
			length--;
		flags = SCPFS_CACHE_CHANGE_CONTENT;
		path = scp_watch_wide_path(bytes, length);
	}
	if(!path) {
		scp_cache_invalidate_all(watch->cache);
		return;
	}
	scp_cache_invalidate_path(watch->cache, path, flags);
	free(path);
}

static void
scp_watch_free_request(SCPFS_WATCH_REQUEST *request)
{
	if(!request)
		return;
	if(request->completed)
		CloseHandle(request->completed);
	scp_backend_free_list(&request->list);
	free(request->data);
	free(request->args);
	free(request->payload);
	free(request->path);
	free(request);
}

/* Publishes a result. Thread owns the request until done is set under lock. */
static void
scp_watch_finish(SCPFS_WATCH *watch, SCPFS_WATCH_REQUEST *request, NTSTATUS status)
{
	bool abandoned;
	request->status = status;
	if(!NT_SUCCESS(status)) {
		scp_backend_free_list(&request->list);
		free(request->data);
		request->data = NULL;
	}
	EnterCriticalSection(&watch->lock);
	request->done = true;
	abandoned = request->abandoned || !request->completed;
	if(!abandoned)
		SetEvent(request->completed);
	LeaveCriticalSection(&watch->lock);
	if(abandoned)
		scp_watch_free_request(request);
}

static void
scp_watch_fail_all(SCPFS_WATCH *watch)
{
	SCPFS_WATCH_REQUEST *request;
	while((request = watch->inflight_head) != NULL) {
		watch->inflight_head = request->next;
		/* A sent mutation may have happened; never let the caller redo it. */
		scp_watch_finish(watch, request, scp_watch_is_mutation(request->kind) ?
			STATUS_CONNECTION_DISCONNECTED : STATUS_NOT_SUPPORTED);
	}
	watch->inflight_tail = NULL;
	for(;;) {
		EnterCriticalSection(&watch->lock);
		request = watch->queue_head;
		if(request) {
			watch->queue_head = request->next;
			watch->queued--;
		}
		if(!watch->queue_head)
			watch->queue_tail = NULL;
		LeaveCriticalSection(&watch->lock);
		if(!request)
			break;
		scp_watch_finish(watch, request, STATUS_NOT_SUPPORTED);
	}
}

static void
scp_watch_set_healthy(SCPFS_WATCH *watch, bool healthy)
{
	EnterCriticalSection(&watch->lock);
	watch->healthy = healthy;
	if(healthy)
		SetEvent(watch->healthy_event);
	else
		ResetEvent(watch->healthy_event);
	LeaveCriticalSection(&watch->lock);
	/* Changes may have been missed either way: start from an empty cache. */
	scp_cache_invalidate_all(watch->cache);
}

static bool
scp_watch_format_request(const SCPFS_WATCH_REQUEST *request, char *wire,
	size_t capacity, size_t *length_out)
{
	static const char hex[] = "0123456789abcdef";
	int prefix = _snprintf_s(wire, capacity, _TRUNCATE, "%c %llu",
		scp_watch_ops[request->kind], (unsigned long long)request->id);
	size_t used;
	size_t index;
	if(prefix < 0)
		return false;
	used = (size_t)prefix;
	if(request->path) {
		if(used + 2u + strlen(request->path) * 2u >= capacity)
			return false;
		wire[used++] = ' ';
		for(index = 0; request->path[index] != '\0'; index++) {
			unsigned char value = (unsigned char)request->path[index];
			wire[used++] = hex[value >> 4];
			wire[used++] = hex[value & 15u];
		}
	}
	if(request->kind == SCPFS_WATCH_READ) {
		int suffix = _snprintf_s(wire + used, capacity - used, _TRUNCATE, " %llu",
			(unsigned long long)request->limit);
		if(suffix < 0 || used + (size_t)suffix + 1u >= capacity)
			return false;
		used += (size_t)suffix;
	}
	if(request->args) {
		size_t length = strlen(request->args);
		if(used + length + 1u >= capacity)
			return false;
		memcpy(wire + used, request->args, length);
		used += length;
	}
	wire[used++] = '\n';
	if(request->payload_size) {
		if(used + request->payload_size > capacity)
			return false;
		memcpy(wire + used, request->payload, request->payload_size);
		used += request->payload_size;
	}
	*length_out = used;
	return true;
}

/* Moves queued requests in flight and writes them in one batch. */
static bool
scp_watch_send_queued(SCPFS_WATCH *watch, SCPFS_WATCH_STREAM *stream)
{
	SCPFS_WATCH_REQUEST *batch;
	SCPFS_WATCH_REQUEST *request;
	char *wire;
	size_t used = 0;
	size_t capacity = 0;
	bool ok = true;
	EnterCriticalSection(&watch->lock);
	batch = watch->queue_head;
	watch->queue_head = watch->queue_tail = NULL;
	watch->queued = 0;
	LeaveCriticalSection(&watch->lock);
	if(!batch)
		return true;
	for(request = batch; request; request = request->next)
		capacity += SCPFS_WATCH_MAX_LINE + request->payload_size;
	wire = (char *)malloc(capacity);
	while((request = batch) != NULL) {
		size_t length;
		batch = request->next;
		request->next = NULL;
		if(!wire || !scp_watch_format_request(request, wire + used,
			capacity - used, &length)) {
			scp_watch_finish(watch, request, STATUS_NOT_SUPPORTED);
			continue;
		}
		used += length;
		request->deadline = GetTickCount64() + (request->kind == SCPFS_WATCH_LIST ||
			request->kind == SCPFS_WATCH_READ || request->kind == SCPFS_WATCH_WRITE ?
			SCPFS_WATCH_LIST_TIMEOUT_MS : SCPFS_WATCH_REQUEST_TIMEOUT_MS);
		if(watch->inflight_tail)
			watch->inflight_tail->next = request;
		else
			watch->inflight_head = request;
		watch->inflight_tail = request;
	}
	if(used)
		ok = NT_SUCCESS(scp_backend_watch_stream_write(stream, wire, used));
	free(wire);
	return ok;
}

static bool
scp_watch_next_token(const char **cursor, const char *end, const char **token,
	size_t *length)
{
	const char *start = *cursor;
	const char *stop = start;
	while(stop < end && *stop != ' ')
		stop++;
	if(stop == start)
		return false;
	*token = start;
	*length = (size_t)(stop - start);
	*cursor = stop < end ? stop + 1 : stop;
	return true;
}

static bool
scp_watch_parse_u64(const char *text, size_t length, unsigned base, uint64_t *value)
{
	char local[32];
	char *end;
	if(length == 0 || length >= sizeof(local) || text[0] == '-' || text[0] == '+')
		return false;
	memcpy(local, text, length);
	local[length] = '\0';
	errno = 0;
	*value = _strtoui64(local, &end, (int)base);
	return errno == 0 && *end == '\0';
}

static bool
scp_watch_parse_i64(const char *text, size_t length, int64_t *value)
{
	char local[32];
	char *end;
	if(length == 0 || length >= sizeof(local))
		return false;
	memcpy(local, text, length);
	local[length] = '\0';
	errno = 0;
	*value = _strtoi64(local, &end, 10);
	return errno == 0 && *end == '\0';
}

/* "type mode size atime mtime dev ino uid gid ctime" */
static bool
scp_watch_parse_stat(const char **cursor, const char *end, SCPFS_REMOTE_STAT *stat)
{
	const char *token;
	size_t length;
	uint64_t mode;
	memset(stat, 0, sizeof(*stat));
	if(!scp_watch_next_token(cursor, end, &token, &length) || length != 1u)
		return false;
	switch(token[0]) {
	case 'f': stat->type = SCPFS_REMOTE_FILE; break;
	case 'd': stat->type = SCPFS_REMOTE_DIRECTORY; break;
	case 'l': stat->type = SCPFS_REMOTE_SYMLINK; break;
	case 'o': stat->type = SCPFS_REMOTE_OTHER; break;
	default: return false;
	}
	if(!scp_watch_next_token(cursor, end, &token, &length) ||
		!scp_watch_parse_u64(token, length, 8u, &mode) || mode > 07777u)
		return false;
	stat->mode = (uint32_t)mode;
	return scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_u64(token, length, 10u, &stat->size) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_i64(token, length, &stat->atime_ns) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_i64(token, length, &stat->mtime_ns) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_u64(token, length, 10u, &stat->device) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_u64(token, length, 10u, &stat->inode) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_u64(token, length, 10u, &stat->uid) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_u64(token, length, 10u, &stat->gid) &&
		scp_watch_next_token(cursor, end, &token, &length) &&
		scp_watch_parse_i64(token, length, &stat->ctime_ns) &&
		*cursor == end;
}

/* One "hexname <stat>" line of a listing. */
static bool
scp_watch_parse_entry(SCPFS_WATCH_REQUEST *request, const char *line, size_t length)
{
	const char *cursor = line;
	const char *end = line + length;
	const char *token;
	size_t token_length;
	char name[512];
	int name_length;
	SCPFS_DIR_ENTRY entry;
	memset(&entry, 0, sizeof(entry));
	if(!scp_watch_next_token(&cursor, end, &token, &token_length))
		return false;
	name_length = scp_watch_unhex(token, token_length, name, sizeof(name));
	if(name_length <= 0 || !scp_watch_parse_stat(&cursor, end, &entry.stat))
		return false;
	{
		NTSTATUS status = scp_backend_decode_name(name, (size_t)name_length,
			&entry.name, &entry.name_length);
		if(status == STATUS_OBJECT_NAME_INVALID)
			return true;
		if(!NT_SUCCESS(status))
			return false;
	}
	if(request->list.count == request->list_capacity) {
		size_t next = request->list_capacity ? request->list_capacity * 2u : 64u;
		SCPFS_DIR_ENTRY *entries = (SCPFS_DIR_ENTRY *)realloc(request->list.entries,
			next * sizeof(*entries));
		if(!entries) {
			free(entry.name);
			return false;
		}
		request->list.entries = entries;
		request->list_capacity = next;
	}
	request->list.entries[request->list.count++] = entry;
	return true;
}

static void
scp_watch_complete_head(SCPFS_WATCH *watch, NTSTATUS status)
{
	SCPFS_WATCH_REQUEST *head = watch->inflight_head;
	watch->inflight_head = head->next;
	if(!watch->inflight_head)
		watch->inflight_tail = NULL;
	head->next = NULL;
	scp_watch_finish(watch, head, status);
}

/* Handles "A id ..." for the oldest request in flight. The helper answers in
 * order, so anything else is a protocol error. */
static bool
scp_watch_handle_reply(SCPFS_WATCH *watch, const char *line, size_t length)
{
	SCPFS_WATCH_REQUEST *request = watch->inflight_head;
	const char *cursor = line + 2;
	const char *end = line + length;
	const char *token;
	size_t token_length;
	uint64_t id;
	NTSTATUS status = STATUS_NOT_SUPPORTED;
	if(!request || !scp_watch_next_token(&cursor, end, &token, &token_length) ||
		!scp_watch_parse_u64(token, token_length, 10u, &id) || id != request->id ||
		!scp_watch_next_token(&cursor, end, &token, &token_length))
		return false;
	/* Events read before this line have been applied; later ones follow it. */
	request->sequence = scp_cache_sequence(watch->cache);
	if(token_length == 2u && memcmp(token, "OK", 2u) == 0) {
		if(request->kind != SCPFS_WATCH_BARRIER && request->kind != SCPFS_WATCH_REMOVE &&
			request->kind != SCPFS_WATCH_RENAME)
			return false;
		status = STATUS_SUCCESS;
	} else if(token_length != 1u) {
		return false;
	} else if(token[0] == 'U') {
		status = STATUS_NOT_SUPPORTED;
	} else if(token[0] == 'N') {
		if(request->kind != SCPFS_WATCH_STAT)
			return false;
		request->cacheable = true;
		status = STATUS_OBJECT_NAME_NOT_FOUND;
	} else if(token[0] == 'E') {
		static const struct {
			const char *reason;
			NTSTATUS status;
		} reasons[] = {
			{ "noent", STATUS_OBJECT_NAME_NOT_FOUND },
			{ "notdir", STATUS_NOT_A_DIRECTORY },
			{ "access", STATUS_ACCESS_DENIED },
			{ "exists", STATUS_OBJECT_NAME_COLLISION },
			{ "notempty", STATUS_DIRECTORY_NOT_EMPTY },
			{ "isdir", STATUS_FILE_IS_A_DIRECTORY },
			{ "conflict", STATUS_FILE_LOCK_CONFLICT },
			{ "reparse", STATUS_REPARSE_POINT_ENCOUNTERED },
			{ "nospace", STATUS_DISK_FULL },
			{ "readonly", STATUS_MEDIA_WRITE_PROTECTED },
			{ "xdev", STATUS_NOT_SAME_DEVICE },
			{ "invalid", STATUS_INVALID_PARAMETER },
		};
		size_t index;
		if(!scp_watch_next_token(&cursor, end, &token, &token_length))
			return false;
		/* "error": reads retry on the backend; a mutation reports failure. */
		status = scp_watch_is_mutation(request->kind) ? STATUS_UNSUCCESSFUL :
			STATUS_NOT_SUPPORTED;
		for(index = 0; index < ARRAYSIZE(reasons); index++) {
			if(strlen(reasons[index].reason) == token_length &&
				memcmp(reasons[index].reason, token, token_length) == 0)
				status = reasons[index].status;
		}
	} else if(token[0] == 'S') {
		if((request->kind != SCPFS_WATCH_STAT && request->kind != SCPFS_WATCH_WRITE &&
			request->kind != SCPFS_WATCH_SETMETA && request->kind != SCPFS_WATCH_MKDIR) ||
			!scp_watch_parse_stat(&cursor, end, &request->stat))
			return false;
		request->cacheable = request->kind == SCPFS_WATCH_STAT;
		status = STATUS_SUCCESS;
	} else if(token[0] == 'F') {
		if(request->kind != SCPFS_WATCH_STATFS ||
			!scp_watch_next_token(&cursor, end, &token, &token_length) ||
			!scp_watch_parse_u64(token, token_length, 10u, &request->total_bytes) ||
			!scp_watch_next_token(&cursor, end, &token, &token_length) ||
			!scp_watch_parse_u64(token, token_length, 10u, &request->available_bytes))
			return false;
		status = STATUS_SUCCESS;
	} else if(token[0] == 'D') {
		uint64_t size;
		if(request->kind != SCPFS_WATCH_READ ||
			!scp_watch_next_token(&cursor, end, &token, &token_length) ||
			!scp_watch_parse_u64(token, token_length, 10u, &size) ||
			size > request->limit ||
			!scp_watch_parse_stat(&cursor, end, &request->stat) ||
			request->stat.size != size)
			return false;
		request->cacheable = true;
		if(size != 0) {
			/* Raw content bytes follow; the request completes after the last one. */
			request->data = (char *)malloc((size_t)size);
			if(!request->data)
				return false;
			request->data_size = (size_t)size;
			request->data_pending = true;
			return true;
		}
		status = STATUS_SUCCESS;
	} else if(token[0] == 'L') {
		uint64_t count;
		if(request->kind != SCPFS_WATCH_LIST ||
			!scp_watch_next_token(&cursor, end, &token, &token_length) ||
			!scp_watch_parse_u64(token, token_length, 10u, &count))
			return false;
		if(count != 0) {
			/* Entry lines follow; the request completes after the last one. */
			request->list_remaining = (size_t)count;
			return true;
		}
		status = STATUS_SUCCESS;
	} else {
		return false;
	}
	scp_watch_complete_head(watch, status);
	return true;
}

static bool
scp_watch_handle_line(SCPFS_WATCH *watch, const char *line, size_t length)
{
	SCPFS_WATCH_REQUEST *head = watch->inflight_head;
	if(head && head->list_remaining) {
		if(!scp_watch_parse_entry(head, line, length))
			return false;
		if(--head->list_remaining == 0)
			scp_watch_complete_head(watch, head->list.count > SCPFS_WATCH_MAX_ENTRIES ?
				STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS);
		return true;
	}
	if(length >= 2u && line[1] == ' ') {
		switch(line[0]) {
		case 'A':
			return scp_watch_handle_reply(watch, line, length);
		case 'C':
		case 'M':
		case 'T':
			scp_watch_apply_event(watch, line[0], line + 2, length - 2u);
			return true;
		default:
			return false;
		}
	}
	if(length == 1u && line[0] == 'R') {
		scp_cache_invalidate_all(watch->cache);
		return true;
	}
	return false;
}

/* Consumes every complete line, and any raw content a read reply announced. */
static bool
scp_watch_process_pending(SCPFS_WATCH *watch)
{
	size_t start = 0;
	bool ok = true;
	while(start < watch->pending_length) {
		SCPFS_WATCH_REQUEST *head = watch->inflight_head;
		const char *line = watch->pending + start;
		const char *newline;
		if(head && head->data_pending) {
			size_t take = watch->pending_length - start;
			if(take > head->data_size - head->data_received)
				take = head->data_size - head->data_received;
			memcpy(head->data + head->data_received, line, take);
			head->data_received += take;
			start += take;
			if(head->data_received == head->data_size) {
				head->data_pending = false;
				scp_watch_complete_head(watch, STATUS_SUCCESS);
			}
			continue;
		}
		newline = (const char *)memchr(line, '\n', watch->pending_length - start);
		if(!newline)
			break;
		if(newline == line ||
			!scp_watch_handle_line(watch, line, (size_t)(newline - line))) {
			ok = false;
			break;
		}
		start = (size_t)(newline - watch->pending) + 1u;
	}
	if(start) {
		memmove(watch->pending, watch->pending + start, watch->pending_length - start);
		watch->pending_length -= start;
	}
	return ok && watch->pending_length <= SCPFS_WATCH_MAX_LINE;
}

static bool
scp_watch_read_some(SCPFS_WATCH *watch, SCPFS_WATCH_STREAM *stream)
{
	size_t received = 0;
	NTSTATUS status = scp_backend_watch_stream_read(stream,
		watch->pending + watch->pending_length,
		SCPFS_WATCH_MAX_LINE + SCPFS_WATCH_READ_CHUNK - watch->pending_length,
		&received);
	if(status == STATUS_IO_TIMEOUT)
		return true;
	if(!NT_SUCCESS(status) || received == 0)
		return false;
	watch->pending_length += received;
	return true;
}

static bool
scp_watch_read_greeting(SCPFS_WATCH *watch, SCPFS_WATCH_STREAM *stream)
{
	static const char prefix[] = "G SCPFS-WATCH 2 ";
	ULONGLONG deadline = GetTickCount64() + SCPFS_WATCH_REQUEST_TIMEOUT_MS;
	const char *newline = NULL;
	HANDLE waits[2];
	size_t length;
	bool matches;
	watch->pending_length = 0;
	while(!newline) {
		if(GetTickCount64() >= deadline || !scp_watch_read_some(watch, stream))
			return false;
		newline = (const char *)memchr(watch->pending, '\n', watch->pending_length);
	}
	length = (size_t)(newline - watch->pending);
	if(length <= sizeof(prefix) - 1u ||
		memcmp(watch->pending, prefix, sizeof(prefix) - 1u) != 0)
		return false;
	/* The helper may start before the main connection has resolved the root. */
	waits[0] = watch->root_known;
	waits[1] = watch->stop_event;
	if(WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0)
		return false;
	EnterCriticalSection(&watch->lock);
	matches = watch->expected_root_hex &&
		strlen(watch->expected_root_hex) == length - (sizeof(prefix) - 1u) &&
		memcmp(watch->expected_root_hex, watch->pending + sizeof(prefix) - 1u,
			length - (sizeof(prefix) - 1u)) == 0;
	LeaveCriticalSection(&watch->lock);
	if(!matches)
		return false;
	watch->pending_length -= length + 1u;
	memmove(watch->pending, newline + 1, watch->pending_length);
	return true;
}

static SCPFS_WATCH_REQUEST *
scp_watch_new_request(SCPFS_WATCH_REQUEST_KIND kind)
{
	SCPFS_WATCH_REQUEST *request =
		(SCPFS_WATCH_REQUEST *)calloc(1, sizeof(*request));
	if(request)
		request->kind = kind;
	return request;
}

/* Runs one connected session until it fails or stop is requested. */
static void
scp_watch_session(SCPFS_WATCH *watch, SCPFS_WATCH_STREAM *stream)
{
	ULONGLONG next_heartbeat = GetTickCount64() + SCPFS_WATCH_HEARTBEAT_MS;
	for(;;) {
		ULONGLONG now;
		DWORD wait_ms;
		bool readable = false;
		if(WaitForSingleObject(watch->stop_event, 0) == WAIT_OBJECT_0)
			return;
		if(!scp_watch_send_queued(watch, stream) ||
			!scp_watch_process_pending(watch))
			return;
		now = GetTickCount64();
		if(watch->inflight_head) {
			if(now >= watch->inflight_head->deadline)
				return;
			wait_ms = (DWORD)(watch->inflight_head->deadline - now);
			next_heartbeat = now + SCPFS_WATCH_HEARTBEAT_MS;
		} else if(now >= next_heartbeat) {
			SCPFS_WATCH_REQUEST *heartbeat = scp_watch_new_request(SCPFS_WATCH_BARRIER);
			if(!heartbeat)
				return;
			EnterCriticalSection(&watch->lock);
			heartbeat->id = ++watch->next_request_id;
			heartbeat->next = watch->queue_head;
			watch->queue_head = heartbeat;
			if(!watch->queue_tail)
				watch->queue_tail = heartbeat;
			watch->queued++;
			LeaveCriticalSection(&watch->lock);
			next_heartbeat = now + SCPFS_WATCH_HEARTBEAT_MS;
			continue;
		} else {
			wait_ms = (DWORD)(next_heartbeat - now);
		}
		if(!NT_SUCCESS(scp_backend_watch_stream_wait(stream, watch->wake_event,
			watch->stop_event, wait_ms, &readable)))
			return;
		if(readable && !scp_watch_read_some(watch, stream))
			return;
	}
}

static DWORD WINAPI
scp_watch_thread(void *parameter)
{
	SCPFS_WATCH *watch = (SCPFS_WATCH *)parameter;
	DWORD delay = SCPFS_WATCH_RECONNECT_DELAY_MS;
	while(WaitForSingleObject(watch->stop_event, 0) != WAIT_OBJECT_0) {
		SCPFS_WATCH_STREAM *stream = NULL;
		if(NT_SUCCESS(scp_backend_watch_stream_open(&watch->options,
			SCPFS_WATCH_HELPER_SOURCE, SCPFS_WATCH_HELPER_SOURCE_LENGTH,
			&stream))) {
			if(scp_watch_read_greeting(watch, stream)) {
				ULONGLONG started = GetTickCount64();
				scp_watch_set_healthy(watch, true);
				scp_watch_session(watch, stream);
				scp_watch_set_healthy(watch, false);
				if(GetTickCount64() - started > SCPFS_WATCH_RECONNECT_MAX_DELAY_MS)
					delay = SCPFS_WATCH_RECONNECT_DELAY_MS;
			}
			scp_backend_watch_stream_close(stream);
		}
		scp_watch_fail_all(watch);
		watch->pending_length = 0;
		/* Back off, so a server without python3/inotify is not hammered. */
		if(WaitForSingleObject(watch->stop_event, delay) == WAIT_OBJECT_0)
			break;
		delay = delay * 2u > SCPFS_WATCH_RECONNECT_MAX_DELAY_MS ?
			SCPFS_WATCH_RECONNECT_MAX_DELAY_MS : delay * 2u;
	}
	scp_watch_fail_all(watch);
	return 0;
}

/* Allocates a request for path (NULL for none); NULL on failure. */
static SCPFS_WATCH_REQUEST *
scp_watch_prepare(SCPFS_WATCH_REQUEST_KIND kind, PCWSTR path)
{
	SCPFS_WATCH_REQUEST *request = scp_watch_new_request(kind);
	if(!request)
		return NULL;
	request->completed = CreateEventW(NULL, TRUE, FALSE, NULL);
	if(!request->completed || (path && (request->path = scp_watch_utf8_path(path)) == NULL)) {
		scp_watch_free_request(request);
		return NULL;
	}
	return request;
}

/* Queues a prepared request (consumed) and waits for it. On completion the
 * caller owns *out. Unanswered reads report STATUS_NOT_SUPPORTED so callers
 * use the backend; an unanswered mutation may have happened and reports
 * STATUS_IO_TIMEOUT instead. */
static NTSTATUS
scp_watch_submit_prepared(SCPFS_WATCH *watch, SCPFS_WATCH_REQUEST *request,
	SCPFS_WATCH_REQUEST **out)
{
	SCPFS_WATCH_REQUEST_KIND kind = request->kind;
	DWORD timeout = kind == SCPFS_WATCH_LIST || kind == SCPFS_WATCH_READ ||
		kind == SCPFS_WATCH_WRITE ? SCPFS_WATCH_LIST_TIMEOUT_MS :
		SCPFS_WATCH_REQUEST_TIMEOUT_MS;
	ULONGLONG started = GetTickCount64();
	WCHAR trace[4];
	bool done;
	*out = NULL;
	EnterCriticalSection(&watch->lock);
	if(watch->stopping || !watch->healthy || watch->queued >= SCPFS_WATCH_MAX_QUEUED) {
		LeaveCriticalSection(&watch->lock);
		scp_watch_free_request(request);
		return STATUS_NOT_SUPPORTED;
	}
	request->id = ++watch->next_request_id;
	if(watch->queue_tail)
		watch->queue_tail->next = request;
	else
		watch->queue_head = request;
	watch->queue_tail = request;
	watch->queued++;
	LeaveCriticalSection(&watch->lock);
	SetEvent(watch->wake_event);
	/* The monitor fails every request on its own deadline; this is a backstop. */
	(void)WaitForSingleObject(request->completed, timeout + 5000u);
	if(GetEnvironmentVariableW(L"SCPFS_TRACE", trace, ARRAYSIZE(trace)) != 0)
		fwprintf(stderr, L"SCPFS trace: %5llu ms watch %c %hs\n",
			GetTickCount64() - started, (WCHAR)scp_watch_ops[kind],
			request->path ? request->path : "");
	EnterCriticalSection(&watch->lock);
	done = request->done;
	if(!done)
		request->abandoned = true;
	LeaveCriticalSection(&watch->lock);
	if(!done)
		return scp_watch_is_mutation(kind) ? STATUS_IO_TIMEOUT : STATUS_NOT_SUPPORTED;
	*out = request;
	return request->status;
}

static NTSTATUS
scp_watch_submit(SCPFS_WATCH *watch, SCPFS_WATCH_REQUEST_KIND kind,
	PCWSTR path, uint64_t limit, SCPFS_WATCH_REQUEST **out)
{
	SCPFS_WATCH_REQUEST *request;
	*out = NULL;
	if(!watch || (request = scp_watch_prepare(kind, path)) == NULL)
		return STATUS_NOT_SUPPORTED;
	request->limit = limit;
	return scp_watch_submit_prepared(watch, request, out);
}

/* Submits a mutation whose arguments follow the path; returns its status and
 * the reply stat when stat_out is given. */
static NTSTATUS
scp_watch_mutate(SCPFS_WATCH *watch, SCPFS_WATCH_REQUEST_KIND kind, PCWSTR path,
	const char *args, char *payload, size_t payload_size,
	SCPFS_REMOTE_STAT *stat_out)
{
	SCPFS_WATCH_REQUEST *request;
	NTSTATUS status;
	if(!watch || (request = scp_watch_prepare(kind, path)) == NULL ||
		(request->args = _strdup(args)) == NULL) {
		if(watch && request)
			scp_watch_free_request(request);
		free(payload);
		return STATUS_NOT_SUPPORTED;
	}
	if(strlen(request->path) * 2u + strlen(args) + 64u > SCPFS_WATCH_MAX_LINE) {
		scp_watch_free_request(request);
		free(payload);
		return STATUS_NOT_SUPPORTED;
	}
	request->payload = payload;
	request->payload_size = payload_size;
	status = scp_watch_submit_prepared(watch, request, &request);
	if(request) {
		if(NT_SUCCESS(status) && stat_out)
			*stat_out = request->stat;
		scp_watch_free_request(request);
	}
	return status;
}

NTSTATUS
scp_watch_write(SCPFS_WATCH *watch, PCWSTR path, PCWSTR local_path,
	const SCPFS_REMOTE_STAT *expected, int64_t atime_ns, int64_t mtime_ns,
	SCPFS_REMOTE_STAT *stat_out)
{
	char args[192];
	char *payload = NULL;
	LARGE_INTEGER size;
	DWORD read = 0;
	HANDLE file;
	if(!watch)
		return STATUS_NOT_SUPPORTED;
	file = CreateFileW(local_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(file == INVALID_HANDLE_VALUE)
		return STATUS_NOT_SUPPORTED;
	if(!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
		size.QuadPart > SCPFS_WATCH_MAX_WRITE ||
		(size.QuadPart && ((payload = (char *)malloc((size_t)size.QuadPart)) == NULL ||
			!ReadFile(file, payload, (DWORD)size.QuadPart, &read, NULL) ||
			read != (DWORD)size.QuadPart))) {
		CloseHandle(file);
		free(payload);
		return STATUS_NOT_SUPPORTED;
	}
	CloseHandle(file);
	if(expected)
		(void)_snprintf_s(args, sizeof(args), _TRUNCATE,
			" %llu %llu:%llu:%llu:%lld:%u %lld %lld", (unsigned long long)size.QuadPart,
			(unsigned long long)expected->device, (unsigned long long)expected->inode,
			(unsigned long long)expected->size, (long long)expected->mtime_ns,
			(unsigned)(expected->mode & 07777u), (long long)atime_ns, (long long)mtime_ns);
	else
		(void)_snprintf_s(args, sizeof(args), _TRUNCATE, " %llu - %lld %lld",
			(unsigned long long)size.QuadPart, (long long)atime_ns, (long long)mtime_ns);
	return scp_watch_mutate(watch, SCPFS_WATCH_WRITE, path, args, payload,
		(size_t)size.QuadPart, stat_out);
}

NTSTATUS
scp_watch_setmeta(SCPFS_WATCH *watch, PCWSTR path, uint32_t mode, int64_t atime_ns,
	int64_t mtime_ns, bool set_mode, bool set_atime, bool set_mtime,
	SCPFS_REMOTE_STAT *stat_out)
{
	char args[96];
	(void)_snprintf_s(args, sizeof(args), _TRUNCATE, " %u %o %lld %lld",
		(set_mode ? 1u : 0u) | (set_atime ? 2u : 0u) | (set_mtime ? 4u : 0u),
		(unsigned)(mode & 07777u), (long long)atime_ns, (long long)mtime_ns);
	return scp_watch_mutate(watch, SCPFS_WATCH_SETMETA, path, args, NULL, 0, stat_out);
}

NTSTATUS
scp_watch_mkdir(SCPFS_WATCH *watch, PCWSTR path, uint32_t mode,
	SCPFS_REMOTE_STAT *stat_out)
{
	char args[16];
	(void)_snprintf_s(args, sizeof(args), _TRUNCATE, " %o", (unsigned)(mode & 07777u));
	return scp_watch_mutate(watch, SCPFS_WATCH_MKDIR, path, args, NULL, 0, stat_out);
}

NTSTATUS
scp_watch_remove(SCPFS_WATCH *watch, PCWSTR path, bool directory)
{
	return scp_watch_mutate(watch, SCPFS_WATCH_REMOVE, path,
		directory ? " D" : " F", NULL, 0, NULL);
}

NTSTATUS
scp_watch_rename(SCPFS_WATCH *watch, PCWSTR old_path, PCWSTR new_path,
	bool replace_existing)
{
	static const char hex[] = "0123456789abcdef";
	char *target = scp_watch_utf8_path(new_path);
	char *args;
	size_t length;
	size_t index;
	NTSTATUS status;
	if(!target)
		return STATUS_NOT_SUPPORTED;
	length = strlen(target);
	args = (char *)malloc(length * 2u + 4u);
	if(!args) {
		free(target);
		return STATUS_NOT_SUPPORTED;
	}
	args[0] = ' ';
	for(index = 0; index < length; index++) {
		args[1u + index * 2u] = hex[(unsigned char)target[index] >> 4];
		args[2u + index * 2u] = hex[(unsigned char)target[index] & 15u];
	}
	args[1u + length * 2u] = ' ';
	args[2u + length * 2u] = replace_existing ? '1' : '0';
	args[3u + length * 2u] = '\0';
	free(target);
	status = scp_watch_mutate(watch, SCPFS_WATCH_RENAME, old_path, args, NULL, 0, NULL);
	free(args);
	return status;
}

NTSTATUS
scp_watch_stat(SCPFS_WATCH *watch, PCWSTR path, SCPFS_REMOTE_STAT *stat_out,
	bool *cacheable, uint64_t *sequence)
{
	SCPFS_WATCH_REQUEST *request;
	NTSTATUS status;
	*cacheable = false;
	*sequence = 0;
	status = scp_watch_submit(watch, SCPFS_WATCH_STAT, path, 0, &request);
	if(request) {
		if(NT_SUCCESS(status))
			*stat_out = request->stat;
		*cacheable = request->cacheable;
		*sequence = request->sequence;
		scp_watch_free_request(request);
	}
	return status;
}

NTSTATUS
scp_watch_list(SCPFS_WATCH *watch, PCWSTR path, SCPFS_DIR_LIST *list_out,
	uint64_t *sequence)
{
	SCPFS_WATCH_REQUEST *request;
	NTSTATUS status;
	memset(list_out, 0, sizeof(*list_out));
	*sequence = 0;
	status = scp_watch_submit(watch, SCPFS_WATCH_LIST, path, 0, &request);
	if(request) {
		if(NT_SUCCESS(status)) {
			*list_out = request->list;
			memset(&request->list, 0, sizeof(request->list));
		}
		*sequence = request->sequence;
		scp_watch_free_request(request);
	}
	return status;
}

NTSTATUS
scp_watch_read(SCPFS_WATCH *watch, PCWSTR path, uint64_t limit,
	PCWSTR destination, SCPFS_REMOTE_STAT *stat_out, uint64_t *sequence)
{
	SCPFS_WATCH_REQUEST *request;
	NTSTATUS status;
	*sequence = 0;
	if(limit > SCPFS_WATCH_MAX_READ)
		limit = SCPFS_WATCH_MAX_READ;
	status = scp_watch_submit(watch, SCPFS_WATCH_READ, path, limit, &request);
	if(!request)
		return status;
	if(NT_SUCCESS(status)) {
		HANDLE file = CreateFileW(destination, GENERIC_WRITE, 0, NULL, CREATE_NEW,
			FILE_ATTRIBUTE_TEMPORARY, NULL);
		DWORD written = 0;
		if(file == INVALID_HANDLE_VALUE) {
			status = STATUS_NOT_SUPPORTED;
		} else {
			if(request->data_size != 0 && (!WriteFile(file, request->data,
				(DWORD)request->data_size, &written, NULL) ||
				written != request->data_size))
				status = STATUS_NOT_SUPPORTED;
			CloseHandle(file);
			if(!NT_SUCCESS(status))
				DeleteFileW(destination);
		}
		if(NT_SUCCESS(status)) {
			*stat_out = request->stat;
			*sequence = request->sequence;
		}
	}
	scp_watch_free_request(request);
	return status;
}

NTSTATUS
scp_watch_statfs(SCPFS_WATCH *watch, uint64_t *total_bytes,
	uint64_t *available_bytes)
{
	SCPFS_WATCH_REQUEST *request;
	NTSTATUS status = scp_watch_submit(watch, SCPFS_WATCH_STATFS, NULL, 0, &request);
	if(request) {
		if(NT_SUCCESS(status)) {
			*total_bytes = request->total_bytes;
			*available_bytes = request->available_bytes;
		}
		scp_watch_free_request(request);
	}
	return status;
}

void
scp_watch_expect_root(SCPFS_WATCH *watch, PCWSTR canonical_root)
{
	static const char hex[] = "0123456789abcdef";
	char *utf8;
	char *text = NULL;
	int length;
	int index;
	if(!watch || !canonical_root)
		return;
	length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, canonical_root, -1,
		NULL, 0, NULL, NULL);
	utf8 = length > 0 ? (char *)malloc((size_t)length) : NULL;
	if(utf8 && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, canonical_root, -1,
		utf8, length, NULL, NULL) == length &&
		(text = (char *)malloc((size_t)length * 2u)) != NULL) {
		for(index = 0; index < length - 1; index++) {
			text[index * 2] = hex[(unsigned char)utf8[index] >> 4];
			text[index * 2 + 1] = hex[(unsigned char)utf8[index] & 15u];
		}
		text[(length - 1) * 2] = '\0';
	}
	free(utf8);
	EnterCriticalSection(&watch->lock);
	free(watch->expected_root_hex);
	/* NULL (conversion failure) never matches, so the cache stays off. */
	watch->expected_root_hex = text;
	LeaveCriticalSection(&watch->lock);
	SetEvent(watch->root_known);
}

bool
scp_watch_wait_healthy(SCPFS_WATCH *watch, DWORD timeout_ms)
{
	return watch && WaitForSingleObject(watch->healthy_event, timeout_ms) == WAIT_OBJECT_0;
}

bool
scp_watch_healthy(SCPFS_WATCH *watch)
{
	bool healthy;
	if(!watch)
		return false;
	EnterCriticalSection(&watch->lock);
	healthy = watch->healthy;
	LeaveCriticalSection(&watch->lock);
	return healthy;
}

static void
scp_watch_free(SCPFS_WATCH *watch)
{
	if(!watch)
		return;
	if(watch->identity_passphrase) {
		SecureZeroMemory(watch->identity_passphrase,
			wcslen(watch->identity_passphrase) * sizeof(WCHAR));
	}
	free(watch->host);
	free(watch->username);
	free(watch->remote_root);
	free(watch->known_hosts_file);
	free(watch->identity_file);
	free(watch->identity_passphrase);
	free(watch->pending);
	free(watch->expected_root_hex);
	if(watch->healthy_event)
		CloseHandle(watch->healthy_event);
	if(watch->root_known)
		CloseHandle(watch->root_known);
	if(watch->wake_event)
		CloseHandle(watch->wake_event);
	if(watch->stop_event)
		CloseHandle(watch->stop_event);
	DeleteCriticalSection(&watch->lock);
	free(watch);
}

NTSTATUS
scp_watch_start(const SCPFS_BACKEND_OPTIONS *options, SCPFS_CACHE *cache,
	SCPFS_WATCH **watch_out)
{
	SCPFS_WATCH *watch;
	if(!options || !cache || !watch_out || !options->host || !options->username ||
		!options->remote_root || !options->known_hosts_file ||
		!options->identity_file)
		return STATUS_INVALID_PARAMETER;
	*watch_out = NULL;
	watch = (SCPFS_WATCH *)calloc(1, sizeof(*watch));
	if(!watch)
		return STATUS_NO_MEMORY;
	InitializeCriticalSection(&watch->lock);
	watch->cache = cache;
	watch->host = scp_watch_wcsdup(options->host);
	watch->username = scp_watch_wcsdup(options->username);
	watch->remote_root = scp_watch_wcsdup(options->remote_root);
	watch->known_hosts_file = scp_watch_wcsdup(options->known_hosts_file);
	watch->identity_file = scp_watch_wcsdup(options->identity_file);
	watch->identity_passphrase = scp_watch_wcsdup(
		options->identity_passphrase ? options->identity_passphrase : L"");
	watch->pending = (char *)malloc(SCPFS_WATCH_MAX_LINE + SCPFS_WATCH_READ_CHUNK);
	if(!watch->host || !watch->username || !watch->remote_root ||
		!watch->known_hosts_file || !watch->identity_file ||
		!watch->identity_passphrase || !watch->pending) {
		scp_watch_free(watch);
		return STATUS_NO_MEMORY;
	}
	watch->options = *options;
	watch->options.host = watch->host;
	watch->options.username = watch->username;
	watch->options.remote_root = watch->remote_root;
	watch->options.known_hosts_file = watch->known_hosts_file;
	watch->options.identity_file = watch->identity_file;
	watch->options.identity_passphrase = watch->identity_passphrase;
	watch->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch->wake_event = CreateEventW(NULL, FALSE, FALSE, NULL);
	watch->healthy_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	watch->root_known = CreateEventW(NULL, TRUE, FALSE, NULL);
	if(!watch->stop_event || !watch->wake_event || !watch->healthy_event ||
		!watch->root_known) {
		scp_watch_free(watch);
		return STATUS_NO_MEMORY;
	}
	watch->thread = CreateThread(NULL, 0, scp_watch_thread, watch, 0, NULL);
	if(!watch->thread) {
		scp_watch_free(watch);
		return STATUS_NO_MEMORY;
	}
	*watch_out = watch;
	return STATUS_SUCCESS;
}

void
scp_watch_stop(SCPFS_WATCH *watch)
{
	if(!watch)
		return;
	EnterCriticalSection(&watch->lock);
	watch->stopping = true;
	LeaveCriticalSection(&watch->lock);
	SetEvent(watch->stop_event);
	SetEvent(watch->wake_event);
	WaitForSingleObject(watch->thread, INFINITE);
	CloseHandle(watch->thread);
	scp_watch_free(watch);
}
