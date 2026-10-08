#include "scp_watch.h"
#include "scpfs_watch_embedded.h"

#include <ntstatus.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define SCPFS_WATCH_IO_TIMEOUT_MS 25u
#define SCPFS_WATCH_REQUEST_TIMEOUT_MS 5000u
#define SCPFS_WATCH_HEARTBEAT_MS 2000u
#define SCPFS_WATCH_RECONNECT_DELAY_MS 500u
#define SCPFS_WATCH_MAX_LINE 16384u
#define SCPFS_WATCH_MAX_QUEUED 64u

typedef enum SCPFS_WATCH_LINE_RESULT {
	SCPFS_WATCH_LINE_ERROR = -1,
	SCPFS_WATCH_LINE_TIMEOUT = 0,
	SCPFS_WATCH_LINE_READY = 1
} SCPFS_WATCH_LINE_RESULT;

typedef enum SCPFS_WATCH_REQUEST_KIND {
	SCPFS_WATCH_REQUEST_ENSURE,
	SCPFS_WATCH_REQUEST_BARRIER
} SCPFS_WATCH_REQUEST_KIND;

typedef struct SCPFS_WATCH_REQUEST {
	struct SCPFS_WATCH_REQUEST *next;
	SCPFS_WATCH_REQUEST_KIND kind;
	uint64_t id;
	char *path;
	bool directory;
	HANDLE completed;
	volatile LONG references;
	volatile LONG abandoned;
	bool result;
} SCPFS_WATCH_REQUEST;

typedef struct SCPFS_WATCH_SUBSCRIPTION {
	struct SCPFS_WATCH_SUBSCRIPTION *next;
	char *path;
	bool directory;
} SCPFS_WATCH_SUBSCRIPTION;

struct SCPFS_WATCH {
	CRITICAL_SECTION lock;
	HANDLE stop_event;
	HANDLE wake_event;
	HANDLE thread;
	SCPFS_BACKEND_OPTIONS options;
	WCHAR *host;
	WCHAR *username;
	WCHAR *remote_root;
	WCHAR *known_hosts_file;
	WCHAR *identity_file;
	WCHAR *identity_passphrase;
	SCPFS_WATCH_REQUEST *request_head;
	SCPFS_WATCH_REQUEST *request_tail;
	size_t request_count;
	SCPFS_WATCH_SUBSCRIPTION *subscriptions;
	bool healthy;
	bool stopping;
	uint64_t metadata_epoch;
	uint64_t content_epoch;
	uint64_t next_request_id;
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
	if(length <= 0 || (size_t)length > (SCPFS_WATCH_MAX_LINE - 32u) / 2u)
		return NULL;
	result = (char *)malloc((size_t)length);
	if(!result)
		return NULL;
	if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1,
		result, length, NULL, NULL) != length) {
		free(result);
		return NULL;
	}
	result[0] = '/';
	for(index = 1; index < length - 1; index++) {
		if(result[index] == '\\')
			result[index] = '/';
		if(result[index] == '\0' || result[index] == '\n' || result[index] == '\r') {
			free(result);
			return NULL;
		}
	}
	{
		char *component = result + 1;
		while(*component) {
			char *end = strchr(component, '/');
			if(!end)
				end = component + strlen(component);
			if((end - component == 1 && component[0] == '.') ||
				(end - component == 2 && component[0] == '.' && component[1] == '.')) {
				free(result);
				return NULL;
			}
			component = *end ? end + 1 : end;
		}
	}
	return result;
}

static void
scp_watch_request_release(SCPFS_WATCH_REQUEST *request)
{
	if(InterlockedDecrement(&request->references) == 0) {
		if(request->completed)
			CloseHandle(request->completed);
		free(request->path);
		free(request);
	}
}

static void
scp_watch_complete_request(SCPFS_WATCH_REQUEST *request, bool result)
{
	request->result = result;
	SetEvent(request->completed);
	scp_watch_request_release(request);
}

static SCPFS_WATCH_REQUEST *
scp_watch_pop_request(SCPFS_WATCH *watch)
{
	SCPFS_WATCH_REQUEST *request;
	EnterCriticalSection(&watch->lock);
	request = watch->request_head;
	if(request) {
		watch->request_head = request->next;
		if(watch->request_count != 0)
			watch->request_count--;
		if(!watch->request_head)
			watch->request_tail = NULL;
		request->next = NULL;
	}
	LeaveCriticalSection(&watch->lock);
	return request;
}

static void
scp_watch_fail_queued(SCPFS_WATCH *watch)
{
	SCPFS_WATCH_REQUEST *request;
	while((request = scp_watch_pop_request(watch)) != NULL)
		scp_watch_complete_request(request, false);
}

static void
scp_watch_clear_subscriptions(SCPFS_WATCH *watch)
{
	SCPFS_WATCH_SUBSCRIPTION *item;
	while((item = watch->subscriptions) != NULL) {
		watch->subscriptions = item->next;
		free(item->path);
		free(item);
	}
}

static void
scp_watch_mark_unhealthy(SCPFS_WATCH *watch)
{
	EnterCriticalSection(&watch->lock);
	if(watch->healthy) {
		watch->healthy = false;
		watch->metadata_epoch++;
		watch->content_epoch++;
	}
	LeaveCriticalSection(&watch->lock);
	scp_watch_clear_subscriptions(watch);
}

static void
scp_watch_mark_healthy(SCPFS_WATCH *watch)
{
	EnterCriticalSection(&watch->lock);
	watch->metadata_epoch++;
	watch->content_epoch++;
	watch->healthy = true;
	LeaveCriticalSection(&watch->lock);
}

static void
scp_watch_note_event(SCPFS_WATCH *watch, unsigned mask)
{
	EnterCriticalSection(&watch->lock);
	if(mask & 1u) {
		watch->content_epoch++;
		watch->metadata_epoch++;
		scp_watch_clear_subscriptions(watch);
	} else if(mask & 2u) {
		watch->metadata_epoch++;
	} else {
		watch->healthy = false;
		watch->content_epoch++;
		watch->metadata_epoch++;
		scp_watch_clear_subscriptions(watch);
	}
	LeaveCriticalSection(&watch->lock);
}

static bool
scp_watch_subscribed(SCPFS_WATCH *watch, const char *path, bool directory)
{
	SCPFS_WATCH_SUBSCRIPTION *item;
	for(item = watch->subscriptions; item; item = item->next) {
		if(item->directory == directory && strcmp(item->path, path) == 0)
			return true;
	}
	return false;
}

static bool
scp_watch_add_subscription(SCPFS_WATCH *watch, const char *path, bool directory)
{
	SCPFS_WATCH_SUBSCRIPTION *item;
	if(scp_watch_subscribed(watch, path, directory))
		return true;
	item = (SCPFS_WATCH_SUBSCRIPTION *)calloc(1, sizeof(*item));
	if(!item)
		return false;
	item->path = _strdup(path);
	if(!item->path) {
		free(item);
		return false;
	}
	item->directory = directory;
	item->next = watch->subscriptions;
	watch->subscriptions = item;
	return true;
}

static bool
scp_watch_write_line(SCPFS_WATCH_STREAM *stream, const char *line)
{
	return NT_SUCCESS(scp_backend_watch_stream_write(stream, line, strlen(line)));
}

static SCPFS_WATCH_LINE_RESULT
scp_watch_read_line(SCPFS_WATCH_STREAM *stream, char *pending,
	size_t *pending_length, char *line, size_t line_capacity, DWORD timeout_ms)
{
	ULONGLONG deadline = GetTickCount64() + timeout_ms;
	for(;;) {
		size_t index;
		for(index = 0; index < *pending_length; index++) {
			if(pending[index] == '\n') {
				size_t length = index;
			size_t character;
				if(length == 0 || length + 1u > line_capacity)
					return SCPFS_WATCH_LINE_ERROR;
				for(character = 0; character < length; character++) {
					unsigned char value = (unsigned char)pending[character];
					if(value < 0x20u || value > 0x7eu)
						return SCPFS_WATCH_LINE_ERROR;
				}
				memcpy(line, pending, length);
				line[length] = '\0';
				memmove(pending, pending + index + 1u,
					*pending_length - index - 1u);
				*pending_length -= index + 1u;
				return SCPFS_WATCH_LINE_READY;
			}
		}
		if(*pending_length >= SCPFS_WATCH_MAX_LINE ||
			GetTickCount64() >= deadline)
			return *pending_length >= SCPFS_WATCH_MAX_LINE ?
				SCPFS_WATCH_LINE_ERROR : SCPFS_WATCH_LINE_TIMEOUT;
		{
			char buffer[2048];
			size_t received = 0;
			NTSTATUS status = scp_backend_watch_stream_read(stream, buffer,
				sizeof(buffer), &received);
			if(status == STATUS_IO_TIMEOUT)
				continue;
			if(!NT_SUCCESS(status))
				return SCPFS_WATCH_LINE_ERROR;
			if(received == 0 || received > SCPFS_WATCH_MAX_LINE - *pending_length)
				return SCPFS_WATCH_LINE_ERROR;
			memcpy(pending + *pending_length, buffer, received);
			*pending_length += received;
		}
	}
}

static bool
scp_watch_parse_ack(SCPFS_WATCH *watch, const char *line, uint64_t id,
	bool *accepted)
{
	char expected[48];
	char *end;
	unsigned long mask;
	if(line[0] == 'E' && line[1] == ' ') {
		mask = strtoul(line + 2, &end, 16);
		if(end != line + 2 && *end == '\0' &&
			(mask == 1ul || mask == 2ul || mask == 3ul)) {
			scp_watch_note_event(watch, (unsigned)mask);
			return true;
		}
		return false;
	}
	_snprintf_s(expected, sizeof(expected), _TRUNCATE, "A %llu OK",
		(unsigned long long)id);
	if(strcmp(line, expected) == 0) {
		*accepted = true;
		return true;
	}
	_snprintf_s(expected, sizeof(expected), _TRUNCATE, "A %llu UNSUPPORTED",
		(unsigned long long)id);
	if(strcmp(line, expected) == 0) {
		*accepted = false;
		return true;
	}
	_snprintf_s(expected, sizeof(expected), _TRUNCATE, "A %llu ERROR",
		(unsigned long long)id);
	if(strcmp(line, expected) == 0) {
		*accepted = false;
		return true;
	}
	return false;
}

static bool
scp_watch_exchange(SCPFS_WATCH *watch,
	SCPFS_WATCH_STREAM *stream, char *pending, size_t *pending_length,
	SCPFS_WATCH_REQUEST *request)
{
	char wire[ SCPFS_WATCH_MAX_LINE + 64u ];
	char line[SCPFS_WATCH_MAX_LINE + 1u];
	size_t used = 0;
	size_t index;
	bool accepted = false;
	uint64_t starting_content_epoch;
	ULONGLONG deadline = GetTickCount64() + SCPFS_WATCH_REQUEST_TIMEOUT_MS;
	EnterCriticalSection(&watch->lock);
	starting_content_epoch = watch->content_epoch;
	LeaveCriticalSection(&watch->lock);
	if(request->kind == SCPFS_WATCH_REQUEST_BARRIER) {
		_snprintf_s(wire, sizeof(wire), _TRUNCATE, "B %llu\n",
			(unsigned long long)request->id);
	} else {
		int prefix = _snprintf_s(wire, sizeof(wire), _TRUNCATE, "W %llu %c ",
			(unsigned long long)request->id, request->directory ? 'D' : 'F');
		static const char hex[] = "0123456789abcdef";
		if(prefix < 0 || (size_t)prefix + strlen(request->path) * 2u + 1u >= sizeof(wire))
			return false;
		used = (size_t)prefix;
		for(index = 0; request->path[index] != '\0'; index++) {
			unsigned char value = (unsigned char)request->path[index];
			wire[used++] = hex[value >> 4];
			wire[used++] = hex[value & 15u];
		}
		wire[used++] = '\n';
		wire[used] = '\0';
	}
	if(!scp_watch_write_line(stream, wire))
		return false;
	while(GetTickCount64() < deadline) {
		SCPFS_WATCH_LINE_RESULT line_result = scp_watch_read_line(stream,
			pending, pending_length, line, sizeof(line),
			(DWORD)(deadline - GetTickCount64()));
		if(line_result == SCPFS_WATCH_LINE_ERROR)
			return false;
		if(line_result == SCPFS_WATCH_LINE_TIMEOUT)
			continue;
		if(line[0] == 'X' && line[1] == ' ')
			return false;
		if(!scp_watch_parse_ack(watch, line, request->id, &accepted))
			return false;
		if(line[0] == 'A') {
			request->result = accepted;
			if(accepted && request->kind == SCPFS_WATCH_REQUEST_ENSURE) {
				bool same_generation;
				EnterCriticalSection(&watch->lock);
				same_generation = watch->healthy &&
					starting_content_epoch == watch->content_epoch;
				LeaveCriticalSection(&watch->lock);
				request->result = same_generation &&
					scp_watch_add_subscription(watch,
						request->path, request->directory);
			}
			return true;
		}
	}
	return false;
}

static bool
scp_watch_read_greeting(SCPFS_WATCH_STREAM *stream, char *pending,
	size_t *pending_length)
{
	char line[SCPFS_WATCH_MAX_LINE + 1u];
	return scp_watch_read_line(stream, pending, pending_length, line,
		sizeof(line), SCPFS_WATCH_REQUEST_TIMEOUT_MS) == SCPFS_WATCH_LINE_READY &&
		strcmp(line, "G SCPFS-WATCH 1") == 0;
}

static DWORD WINAPI
scp_watch_thread(void *parameter)
{
	SCPFS_WATCH *watch = (SCPFS_WATCH *)parameter;
	for(;;) {
		SCPFS_WATCH_STREAM *stream = NULL;
		char pending[SCPFS_WATCH_MAX_LINE + 1u];
		size_t pending_length = 0;
		ULONGLONG next_heartbeat;
		if(WaitForSingleObject(watch->stop_event, 0) == WAIT_OBJECT_0)
			break;
		if(!NT_SUCCESS(scp_backend_watch_stream_open(&watch->options,
			SCPFS_WATCH_HELPER_SOURCE, SCPFS_WATCH_HELPER_SOURCE_LENGTH,
			&stream))) {
			scp_watch_mark_unhealthy(watch);
			scp_watch_fail_queued(watch);
			WaitForSingleObject(watch->stop_event, SCPFS_WATCH_RECONNECT_DELAY_MS);
			continue;
		}
		if(!scp_watch_read_greeting(stream, pending, &pending_length)) {
			scp_watch_mark_unhealthy(watch);
			scp_backend_watch_stream_close(stream);
			scp_watch_fail_queued(watch);
			WaitForSingleObject(watch->stop_event, SCPFS_WATCH_RECONNECT_DELAY_MS);
			continue;
		}
		scp_watch_clear_subscriptions(watch);
		scp_watch_mark_healthy(watch);
		next_heartbeat = GetTickCount64() + SCPFS_WATCH_HEARTBEAT_MS;
		while(WaitForSingleObject(watch->stop_event, 0) != WAIT_OBJECT_0) {
			SCPFS_WATCH_REQUEST *request = scp_watch_pop_request(watch);
			bool healthy = true;
			if(request) {
				if(InterlockedCompareExchange(&request->abandoned, 0, 0)) {
					scp_watch_complete_request(request, false);
					continue;
				}
				if(request->kind == SCPFS_WATCH_REQUEST_ENSURE &&
					scp_watch_subscribed(watch, request->path, request->directory)) {
					request->result = true;
				} else {
					healthy = scp_watch_exchange(watch, stream, pending,
						&pending_length, request);
				}
				scp_watch_complete_request(request, healthy && request->result);
				if(!healthy)
					break;
				next_heartbeat = GetTickCount64() + SCPFS_WATCH_HEARTBEAT_MS;
				continue;
			}
			if(GetTickCount64() >= next_heartbeat) {
				SCPFS_WATCH_REQUEST heartbeat;
				memset(&heartbeat, 0, sizeof(heartbeat));
				heartbeat.kind = SCPFS_WATCH_REQUEST_BARRIER;
				EnterCriticalSection(&watch->lock);
				heartbeat.id = ++watch->next_request_id;
				LeaveCriticalSection(&watch->lock);
				if(!scp_watch_exchange(watch, stream, pending,
					&pending_length, &heartbeat) || !heartbeat.result) {
					break;
				}
				next_heartbeat = GetTickCount64() + SCPFS_WATCH_HEARTBEAT_MS;
				continue;
			}
			{
				char line[SCPFS_WATCH_MAX_LINE + 1u];
				SCPFS_WATCH_LINE_RESULT line_result;
				/* Sleep until monitor data, a queued request, stop or the next
				 * heartbeat. A blocking 25 ms read here delayed every queued
				 * ensure/barrier by up to 25 ms. */
				if(memchr(pending, '\n', pending_length) == NULL) {
					bool readable = false;
					ULONGLONG now = GetTickCount64();
					DWORD wait_ms = next_heartbeat > now ?
						(DWORD)(next_heartbeat - now) : 0;
					if(!NT_SUCCESS(scp_backend_watch_stream_wait(stream,
						watch->wake_event, watch->stop_event, wait_ms, &readable)))
						break;
					if(!readable)
						continue;
				}
				line_result = scp_watch_read_line(
					stream, pending, &pending_length, line, sizeof(line),
					SCPFS_WATCH_IO_TIMEOUT_MS);
				if(line_result == SCPFS_WATCH_LINE_ERROR)
					break;
				if(line_result == SCPFS_WATCH_LINE_READY) {
					bool ignored = false;
					if(line[0] == 'X' && line[1] == ' ')
						break;
					if(!scp_watch_parse_ack(watch, line, UINT64_MAX, &ignored))
						break;
					if(line[0] != 'E')
						break;
				}
				(void)WaitForSingleObject(watch->wake_event, 0);
			}
		}
		scp_watch_mark_unhealthy(watch);
		scp_backend_watch_stream_close(stream);
		scp_watch_fail_queued(watch);
		if(WaitForSingleObject(watch->stop_event,
			SCPFS_WATCH_RECONNECT_DELAY_MS) == WAIT_OBJECT_0)
			break;
	}
	scp_watch_mark_unhealthy(watch);
	scp_watch_fail_queued(watch);
	return 0;
}

static bool
scp_watch_submit(SCPFS_WATCH *watch, SCPFS_WATCH_REQUEST_KIND kind,
	PCWSTR path, bool directory)
{
	SCPFS_WATCH_REQUEST *request;
	DWORD wait_result;
	if(!watch)
		return false;
	request = (SCPFS_WATCH_REQUEST *)calloc(1, sizeof(*request));
	if(!request)
		return false;
	request->completed = CreateEventW(NULL, TRUE, FALSE, NULL);
	request->references = 2;
	request->kind = kind;
	request->directory = directory;
	if(!request->completed || (kind == SCPFS_WATCH_REQUEST_ENSURE &&
		(request->path = scp_watch_utf8_path(path)) == NULL)) {
		request->references = 1;
		scp_watch_request_release(request);
		return false;
	}
	EnterCriticalSection(&watch->lock);
	if(watch->stopping) {
		LeaveCriticalSection(&watch->lock);
		scp_watch_request_release(request);
		scp_watch_request_release(request);
		return false;
	}
	if(watch->request_count >= SCPFS_WATCH_MAX_QUEUED) {
		LeaveCriticalSection(&watch->lock);
		scp_watch_request_release(request);
		scp_watch_request_release(request);
		return false;
	}
	request->id = ++watch->next_request_id;
	if(watch->request_tail)
		watch->request_tail->next = request;
	else
		watch->request_head = request;
	watch->request_tail = request;
	watch->request_count++;
	LeaveCriticalSection(&watch->lock);
	SetEvent(watch->wake_event);
	wait_result = WaitForSingleObject(request->completed,
		SCPFS_WATCH_REQUEST_TIMEOUT_MS);
	{
		bool result = wait_result == WAIT_OBJECT_0 && request->result;
		if(wait_result != WAIT_OBJECT_0)
			InterlockedExchange(&request->abandoned, 1);
		scp_watch_request_release(request);
		return result;
	}
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
	if(watch->wake_event)
		CloseHandle(watch->wake_event);
	if(watch->stop_event)
		CloseHandle(watch->stop_event);
	DeleteCriticalSection(&watch->lock);
	free(watch);
}

NTSTATUS
scp_watch_start(const SCPFS_BACKEND_OPTIONS *options, SCPFS_WATCH **watch_out)
{
	SCPFS_WATCH *watch;
	if(!options || !watch_out || !options->host || !options->username ||
		!options->remote_root || !options->known_hosts_file ||
		!options->identity_file)
		return STATUS_INVALID_PARAMETER;
	*watch_out = NULL;
	watch = (SCPFS_WATCH *)calloc(1, sizeof(*watch));
	if(!watch)
		return STATUS_NO_MEMORY;
	InitializeCriticalSection(&watch->lock);
	watch->host = scp_watch_wcsdup(options->host);
	watch->username = scp_watch_wcsdup(options->username);
	watch->remote_root = scp_watch_wcsdup(options->remote_root);
	watch->known_hosts_file = scp_watch_wcsdup(options->known_hosts_file);
	watch->identity_file = scp_watch_wcsdup(options->identity_file);
	watch->identity_passphrase = scp_watch_wcsdup(
		options->identity_passphrase ? options->identity_passphrase : L"");
	if(!watch->host || !watch->username || !watch->remote_root ||
		!watch->known_hosts_file || !watch->identity_file ||
		!watch->identity_passphrase) {
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
	if(!watch->stop_event || !watch->wake_event) {
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

bool
scp_watch_ensure(SCPFS_WATCH *watch, PCWSTR path, bool directory)
{
	return scp_watch_submit(watch, SCPFS_WATCH_REQUEST_ENSURE, path, directory);
}

bool
scp_watch_barrier(SCPFS_WATCH *watch)
{
	return scp_watch_submit(watch, SCPFS_WATCH_REQUEST_BARRIER, NULL, false);
}

void
scp_watch_snapshot(SCPFS_WATCH *watch, SCPFS_WATCH_STATE *state_out)
{
	if(!state_out)
		return;
	memset(state_out, 0, sizeof(*state_out));
	if(!watch)
		return;
	EnterCriticalSection(&watch->lock);
	state_out->healthy = watch->healthy;
	state_out->metadata_epoch = watch->metadata_epoch;
	state_out->content_epoch = watch->content_epoch;
	LeaveCriticalSection(&watch->lock);
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
	scp_watch_clear_subscriptions(watch);
	scp_watch_free(watch);
}
