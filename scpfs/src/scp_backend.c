#include "scp_backend.h"

#include <bcrypt.h>
#include <libssh2.h>
#include <openssl/crypto.h>
#include <winfsp/winfsp.h>
#include <ws2tcpip.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <netioapi.h>
#include <windns.h>

#pragma comment(lib, "bcrypt.lib")

#define SCPFS_DEFAULT_TIMEOUT_MS 15000u
#define SCPFS_MAX_KNOWN_HOSTS_BYTES (16u * 1024u * 1024u)
#define SCPFS_MAX_PRIVATE_KEY_BYTES (16u * 1024u * 1024u)
#define SCPFS_MAX_COMMAND_BYTES (1024u * 1024u)
#define SCPFS_WATCH_READ_TIMEOUT_MS 25u
#define SCPFS_MAX_STAT_OUTPUT 4096u
#define SCPFS_MAX_LIST_OUTPUT (64u * 1024u * 1024u)
#define SCPFS_MAX_DIRECTORY_ENTRIES 1000000u
#define SCPFS_IO_BUFFER_SIZE (64u * 1024u)
#define SCPFS_TEMP_ATTEMPTS 8u
#define SCPFS_INBOX_DEFAULT_TIMEOUT_MS 30000u
#define SCPFS_INBOX_TIMEOUT_GRACE_MS 32000u
#define SCPFS_INBOX_MAX_INPUT_BYTES (1024u * 1024u)
#define SCPFS_INBOX_MAX_OUTPUT_BYTES (8u * 1024u * 1024u)
#define SCPFS_INBOX_CAPTURE_BYTES (SCPFS_INBOX_MAX_OUTPUT_BYTES + 1u)

typedef struct SCPFS_BUFFER {
	char *data;
	size_t length;
	size_t capacity;
} SCPFS_BUFFER;

struct SCPFS_BACKEND {
	SOCKET socket;
	LIBSSH2_SESSION *session;
	CRITICAL_SECTION mutex;
	bool mutex_initialized;
	volatile LONG broken;
	volatile LONG failure_status;
	HANDLE failure_event;
	uint32_t timeout_ms;
	char *host;
	char *username;
	char *remote_root;
};

struct SCPFS_WATCH_STREAM {
	SCPFS_BACKEND *backend;
	LIBSSH2_CHANNEL *channel;
};

static INIT_ONCE g_network_once = INIT_ONCE_STATIC_INIT;
static NTSTATUS g_network_status = STATUS_UNSUCCESSFUL;

static BOOL CALLBACK
scpfs_initialize_network(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
	WSADATA data;
	int wsa_result;
	int ssh_result;
	(void)once;
	(void)parameter;
	(void)context;

	/*
	 * Disable environment-driven OpenSSL configuration before libssh2 or any
	 * crypto operation can initialize the default library context. This build
	 * uses only the statically linked built-in providers.
	 */
	if(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
		g_network_status = STATUS_UNSUCCESSFUL;
		return TRUE;
	}
	wsa_result = WSAStartup(MAKEWORD(2, 2), &data);
	if(wsa_result != 0) {
		g_network_status = STATUS_UNSUCCESSFUL;
		return TRUE;
	}
	ssh_result = libssh2_init(0);
	if(ssh_result != 0) {
		g_network_status = STATUS_UNSUCCESSFUL;
		return TRUE;
	}
	g_network_status = STATUS_SUCCESS;
	return TRUE;
}

static bool
scpfs_add_size(size_t left, size_t right, size_t *result)
{
	if(left > SIZE_MAX - right)
		return false;
	*result = left + right;
	return true;
}

static bool
scpfs_buffer_reserve(SCPFS_BUFFER *buffer, size_t extra)
{
	size_t wanted;
	size_t capacity;
	char *resized;
	if(!scpfs_add_size(buffer->length, extra, &wanted))
		return false;
	if(wanted <= buffer->capacity)
		return true;
	capacity = buffer->capacity ? buffer->capacity : 128u;
	while(capacity < wanted) {
		if(capacity > SIZE_MAX / 2u) {
			capacity = wanted;
			break;
		}
		capacity *= 2u;
	}
	resized = (char *)realloc(buffer->data, capacity);
	if(!resized)
		return false;
	buffer->data = resized;
	buffer->capacity = capacity;
	return true;
}

static bool
scpfs_buffer_append(SCPFS_BUFFER *buffer, const void *data, size_t length)
{
	if(!scpfs_buffer_reserve(buffer, length))
		return false;
	if(length)
		memcpy(buffer->data + buffer->length, data, length);
	buffer->length += length;
	return true;
}

static bool
scpfs_buffer_append_text(SCPFS_BUFFER *buffer, const char *text)
{
	return scpfs_buffer_append(buffer, text, strlen(text));
}

static char *
scpfs_buffer_take_string(SCPFS_BUFFER *buffer)
{
	char *result;
	if(!scpfs_buffer_reserve(buffer, 1u))
		return NULL;
	buffer->data[buffer->length] = '\0';
	result = buffer->data;
	buffer->data = NULL;
	buffer->length = 0;
	buffer->capacity = 0;
	return result;
}

static void
scpfs_buffer_free(SCPFS_BUFFER *buffer)
{
	free(buffer->data);
	buffer->data = NULL;
	buffer->length = 0;
	buffer->capacity = 0;
}

static NTSTATUS
scpfs_wide_to_utf8(PCWSTR input, char **output, size_t *output_length)
{
	int required;
	int written;
	char *converted;
	if(!input || !output)
		return STATUS_INVALID_PARAMETER;
	*output = NULL;
	if(output_length)
		*output_length = 0;
	required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1,
		NULL, 0, NULL, NULL);
	if(required <= 0)
		return STATUS_OBJECT_NAME_INVALID;
	converted = (char *)malloc((size_t)required);
	if(!converted)
		return STATUS_NO_MEMORY;
	written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1,
		converted, required, NULL, NULL);
	if(written != required) {
		free(converted);
		return STATUS_OBJECT_NAME_INVALID;
	}
	*output = converted;
	if(output_length)
		*output_length = (size_t)required - 1u;
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_utf8_to_wide_n(const char *input, size_t input_length,
	WCHAR **output, size_t *output_length)
{
	int required;
	int written;
	WCHAR *converted;
	if(!input || !output || input_length > (size_t)INT_MAX)
		return STATUS_INVALID_PARAMETER;
	*output = NULL;
	if(output_length)
		*output_length = 0;
	required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input,
		(int)input_length, NULL, 0);
	if(required <= 0)
		return STATUS_OBJECT_NAME_INVALID;
	converted = (WCHAR *)malloc(((size_t)required + 1u) * sizeof(WCHAR));
	if(!converted)
		return STATUS_NO_MEMORY;
	written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input,
		(int)input_length, converted, required);
	if(written != required) {
		free(converted);
		return STATUS_OBJECT_NAME_INVALID;
	}
	converted[required] = L'\0';
	*output = converted;
	if(output_length)
		*output_length = (size_t)required;
	return STATUS_SUCCESS;
}

static bool
scpfs_ascii_equal_ci(const WCHAR *left, size_t left_length, const WCHAR *right)
{
	size_t index;
	if(wcslen(right) != left_length)
		return false;
	for(index = 0; index < left_length; index++) {
		WCHAR a = left[index];
		WCHAR b = right[index];
		if(a >= L'a' && a <= L'z')
			a = (WCHAR)(a - L'a' + L'A');
		if(b >= L'a' && b <= L'z')
			b = (WCHAR)(b - L'a' + L'A');
		if(a != b)
			return false;
	}
	return true;
}

static bool
scpfs_is_reserved_windows_name(const WCHAR *component, size_t length)
{
	size_t stem_length = 0;
	while(stem_length < length && component[stem_length] != L'.')
		stem_length++;
	while(stem_length && (component[stem_length - 1u] == L' ' ||
		component[stem_length - 1u] == L'.'))
		stem_length--;
	if(scpfs_ascii_equal_ci(component, stem_length, L"CON") ||
		scpfs_ascii_equal_ci(component, stem_length, L"PRN") ||
		scpfs_ascii_equal_ci(component, stem_length, L"AUX") ||
		scpfs_ascii_equal_ci(component, stem_length, L"NUL"))
		return true;
	if(stem_length == 4u && component[3] >= L'1' && component[3] <= L'9' &&
		(scpfs_ascii_equal_ci(component, 3u, L"COM") ||
		 scpfs_ascii_equal_ci(component, 3u, L"LPT")))
		return true;
	if(stem_length == 4u &&
		(component[3] == 0x00b9 || component[3] == 0x00b2 ||
		 component[3] == 0x00b3) &&
		(scpfs_ascii_equal_ci(component, 3u, L"COM") ||
		 scpfs_ascii_equal_ci(component, 3u, L"LPT")))
		return true;
	return false;
}

static bool
scpfs_is_windows_component(PCWSTR component, size_t length)
{
	size_t index;
	char *utf8 = NULL;
	size_t utf8_length = 0;
	NTSTATUS status;
	if(length == 0 || (length == 1u && component[0] == L'.') ||
		(length == 2u && component[0] == L'.' && component[1] == L'.'))
		return false;
	if(component[length - 1u] == L'.' || component[length - 1u] == L' ')
		return false;
	for(index = 0; index < length; index++) {
		WCHAR ch = component[index];
		if(ch < 0x20 || (ch >= 0x7f && ch <= 0x9f) || ch == L'<' ||
			ch == L'>' || ch == L':' || ch == L'"' || ch == L'/' ||
			ch == L'\\' || ch == L'|' || ch == L'?' || ch == L'*')
			return false;
	}
	if(scpfs_is_reserved_windows_name(component, length))
		return false;
	{
		WCHAR *copy = (WCHAR *)malloc((length + 1u) * sizeof(WCHAR));
		if(!copy)
			return false;
		memcpy(copy, component, length * sizeof(WCHAR));
		copy[length] = L'\0';
		status = scpfs_wide_to_utf8(copy, &utf8, &utf8_length);
		free(copy);
	}
	if(!NT_SUCCESS(status))
		return false;
	free(utf8);
	return utf8_length <= 255u;
}

/* Quote one UTF-8 shell word for both Bourne shells and csh-family shells.
 * The apostrophe and exclamation handling follows libssh2 1.11.1 src/scp.c. */
static char *
scpfs_shell_quote(const char *input)
{
	enum { QUOTE_UNQUOTED, QUOTE_SINGLE, QUOTE_DOUBLE } state = QUOTE_UNQUOTED;
	size_t input_length;
	size_t capacity;
	size_t source;
	size_t target = 0;
	char *quoted;
	if(!input)
		return NULL;
	input_length = strlen(input);
	if(input_length > (SIZE_MAX - 3u) / 3u)
		return NULL;
	capacity = input_length * 3u + 3u;
	quoted = (char *)malloc(capacity);
	if(!quoted)
		return NULL;
	if(input_length == 0) {
		quoted[target++] = '\'';
		quoted[target++] = '\'';
		quoted[target] = '\0';
		return quoted;
	}
	for(source = 0; source < input_length; source++) {
		unsigned char ch = (unsigned char)input[source];
		if(ch == '\'') {
			if(state == QUOTE_UNQUOTED)
				quoted[target++] = '"';
			else if(state == QUOTE_SINGLE) {
				quoted[target++] = '\'';
				quoted[target++] = '"';
			}
			quoted[target++] = '\'';
			state = QUOTE_DOUBLE;
		}
		else if(ch == '!') {
			if(state == QUOTE_SINGLE)
				quoted[target++] = '\'';
			else if(state == QUOTE_DOUBLE)
				quoted[target++] = '"';
			quoted[target++] = '\\';
			quoted[target++] = '!';
			state = QUOTE_UNQUOTED;
		}
		else {
			if(state == QUOTE_UNQUOTED)
				quoted[target++] = '\'';
			else if(state == QUOTE_DOUBLE) {
				quoted[target++] = '"';
				quoted[target++] = '\'';
			}
			quoted[target++] = (char)ch;
			state = QUOTE_SINGLE;
		}
	}
	if(state == QUOTE_SINGLE)
		quoted[target++] = '\'';
	else if(state == QUOTE_DOUBLE)
		quoted[target++] = '"';
	quoted[target] = '\0';
	return quoted;
}

static bool
scpfs_append_shell_word(SCPFS_BUFFER *buffer, const char *word)
{
	char *quoted = scpfs_shell_quote(word);
	bool result;
	if(!quoted)
		return false;
	result = scpfs_buffer_append_text(buffer, quoted);
	free(quoted);
	return result;
}

static NTSTATUS
scpfs_normalize_remote_root(PCWSTR root, char **root_out)
{
	char *utf8 = NULL;
	size_t length = 0;
	SCPFS_BUFFER normalized = { 0 };
	size_t index = 0;
	NTSTATUS status;
	if(!root || !root_out)
		return STATUS_INVALID_PARAMETER;
	*root_out = NULL;
	status = scpfs_wide_to_utf8(root, &utf8, &length);
	if(!NT_SUCCESS(status))
		return status;
	if(length == 0 || utf8[0] != '/') {
		free(utf8);
		return STATUS_INVALID_PARAMETER;
	}
	if(!scpfs_buffer_append_text(&normalized, "/")) {
		free(utf8);
		return STATUS_NO_MEMORY;
	}
	while(index < length) {
		size_t start;
		size_t component_length;
		while(index < length && utf8[index] == '/')
			index++;
		start = index;
		while(index < length && utf8[index] != '/') {
			unsigned char ch = (unsigned char)utf8[index];
			if(ch < 0x20u || ch == 0x7fu) {
				status = STATUS_INVALID_PARAMETER;
				goto done;
			}
			index++;
		}
		component_length = index - start;
		if(component_length == 0)
			continue;
		if((component_length == 1u && utf8[start] == '.') ||
			(component_length == 2u && utf8[start] == '.' &&
			 utf8[start + 1u] == '.')) {
			status = STATUS_INVALID_PARAMETER;
			goto done;
		}
		if(normalized.length > 1u &&
			!scpfs_buffer_append_text(&normalized, "/")) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		if(!scpfs_buffer_append(&normalized, utf8 + start,
			component_length)) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
	}
	*root_out = scpfs_buffer_take_string(&normalized);
	status = *root_out ? STATUS_SUCCESS : STATUS_NO_MEMORY;
done:
	free(utf8);
	scpfs_buffer_free(&normalized);
	return status;
}

static NTSTATUS
scpfs_path_to_remote(SCPFS_BACKEND *backend, PCWSTR path, char **remote_out)
{
	SCPFS_BUFFER remote = { 0 };
	size_t index = 0;
	NTSTATUS status = STATUS_SUCCESS;
	if(!backend || !path || !remote_out)
		return STATUS_INVALID_PARAMETER;
	*remote_out = NULL;
	if(path[0] != L'\\' && path[0] != L'/')
		return STATUS_INVALID_PARAMETER;
	if(!scpfs_buffer_append_text(&remote, backend->remote_root))
		return STATUS_NO_MEMORY;
	while(path[index]) {
		size_t start;
		char *part = NULL;
		size_t part_length = 0;
		while(path[index] == L'\\' || path[index] == L'/')
			index++;
		if(!path[index])
			break;
		start = index;
		while(path[index] && path[index] != L'\\' && path[index] != L'/')
			index++;
		if(!scpfs_is_windows_component(path + start, index - start)) {
			status = STATUS_OBJECT_NAME_INVALID;
			goto done;
		}
		{
			WCHAR *component = (WCHAR *)malloc((index - start + 1u) * sizeof(WCHAR));
			if(!component) {
				status = STATUS_NO_MEMORY;
				goto done;
			}
			memcpy(component, path + start, (index - start) * sizeof(WCHAR));
			component[index - start] = L'\0';
			status = scpfs_wide_to_utf8(component, &part, &part_length);
			free(component);
		}
		if(!NT_SUCCESS(status))
			goto done;
		if(remote.length == 0 || remote.data[remote.length - 1u] != '/') {
			if(!scpfs_buffer_append_text(&remote, "/")) {
				free(part);
				status = STATUS_NO_MEMORY;
				goto done;
			}
		}
		if(!scpfs_buffer_append(&remote, part, part_length)) {
			free(part);
			status = STATUS_NO_MEMORY;
			goto done;
		}
		free(part);
		if(remote.length > 8192u) {
			status = STATUS_NAME_TOO_LONG;
			goto done;
		}
	}
	*remote_out = scpfs_buffer_take_string(&remote);
	if(!*remote_out)
		status = STATUS_NO_MEMORY;
done:
	scpfs_buffer_free(&remote);
	return status;
}

static bool
scpfs_path_is_root(const SCPFS_BACKEND *backend, const char *path)
{
	return strcmp(backend->remote_root, path) == 0;
}

static bool
scpfs_path_is_below_root(const SCPFS_BACKEND *backend, const char *path)
{
	size_t root_length = strlen(backend->remote_root);
	if(strncmp(backend->remote_root, path, root_length) != 0)
		return false;
	if(path[root_length] == '\0')
		return true;
	return root_length == 1u || path[root_length] == '/';
}

static NTSTATUS
scpfs_parent_path(const SCPFS_BACKEND *backend, const char *path,
	char **parent_out)
{
	const char *slash;
	size_t root_length;
	size_t parent_length;
	char *parent;
	if(!scpfs_path_is_below_root(backend, path))
		return STATUS_ACCESS_DENIED;
	if(scpfs_path_is_root(backend, path)) {
		parent = _strdup(path);
		if(!parent)
			return STATUS_NO_MEMORY;
		*parent_out = parent;
		return STATUS_SUCCESS;
	}
	root_length = strlen(backend->remote_root);
	slash = strrchr(path, '/');
	if(!slash)
		return STATUS_ACCESS_DENIED;
	if(root_length == 1u && slash == path) {
		parent = _strdup("/");
		if(!parent)
			return STATUS_NO_MEMORY;
		*parent_out = parent;
		return STATUS_SUCCESS;
	}
	if(slash < path + root_length)
		return STATUS_ACCESS_DENIED;
	parent_length = (size_t)(slash - path);
	if(parent_length < root_length)
		return STATUS_ACCESS_DENIED;
	parent = (char *)malloc(parent_length + 1u);
	if(!parent)
		return STATUS_NO_MEMORY;
	memcpy(parent, path, parent_length);
	parent[parent_length] = '\0';
	*parent_out = parent;
	return STATUS_SUCCESS;
}

static bool
scpfs_contains_text(const char *data, size_t length, const char *needle)
{
	size_t needle_length = strlen(needle);
	size_t index;
	if(needle_length == 0 || needle_length > length)
		return false;
	for(index = 0; index + needle_length <= length; index++) {
		if(memcmp(data + index, needle, needle_length) == 0)
			return true;
	}
	return false;
}

static NTSTATUS
scpfs_map_remote_error(const char *output, size_t output_length)
{
	if(scpfs_contains_text(output, output_length, "No such file or directory") ||
		scpfs_contains_text(output, output_length, "cannot stat"))
		return STATUS_OBJECT_NAME_NOT_FOUND;
	if(scpfs_contains_text(output, output_length, "File exists"))
		return STATUS_OBJECT_NAME_COLLISION;
	if(scpfs_contains_text(output, output_length, "Permission denied") ||
		scpfs_contains_text(output, output_length, "Operation not permitted"))
		return STATUS_ACCESS_DENIED;
	if(scpfs_contains_text(output, output_length, "Directory not empty"))
		return STATUS_DIRECTORY_NOT_EMPTY;
	if(scpfs_contains_text(output, output_length, "Not a directory"))
		return STATUS_NOT_A_DIRECTORY;
	if(scpfs_contains_text(output, output_length, "Is a directory"))
		return STATUS_FILE_IS_A_DIRECTORY;
	if(scpfs_contains_text(output, output_length, "No space left on device"))
		return STATUS_DISK_FULL;
	if(scpfs_contains_text(output, output_length, "Read-only file system"))
		return STATUS_MEDIA_WRITE_PROTECTED;
	if(scpfs_contains_text(output, output_length, "Cross-device link"))
		return STATUS_NOT_SAME_DEVICE;
	if(scpfs_contains_text(output, output_length, "Invalid argument"))
		return STATUS_INVALID_PARAMETER;
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
scpfs_map_libssh2_error(int error)
{
	if(error == LIBSSH2_ERROR_TIMEOUT || error == LIBSSH2_ERROR_SOCKET_TIMEOUT)
		return STATUS_IO_TIMEOUT;
	if(error == LIBSSH2_ERROR_AUTHENTICATION_FAILED ||
		error == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED ||
		error == LIBSSH2_ERROR_KEYFILE_AUTH_FAILED)
		return STATUS_LOGON_FAILURE;
	if(error == LIBSSH2_ERROR_ALLOC)
		return STATUS_NO_MEMORY;
	if(error == LIBSSH2_ERROR_SCP_PROTOCOL)
		return STATUS_DATA_ERROR;
	return STATUS_UNSUCCESSFUL;
}

static void
scpfs_poison_backend(SCPFS_BACKEND *backend, NTSTATUS status)
{
	if(!backend)
		return;
	if(InterlockedCompareExchange(&backend->broken, 1, 0) == 0) {
		InterlockedExchange(&backend->failure_status, status);
		if(backend->failure_event)
			SetEvent(backend->failure_event);
	}
	if(backend->socket != INVALID_SOCKET)
		shutdown(backend->socket, SD_BOTH);
}

static NTSTATUS
scpfs_execute_locked(SCPFS_BACKEND *backend, const char *command,
	size_t max_output, char **output, size_t *output_length, int *exit_status)
{
	static const char status_prefix[] = "\036SCPFS_RC:";
	SCPFS_BUFFER full_command = { 0 };
	SCPFS_BUFFER result = { 0 };
	LIBSSH2_CHANNEL *channel = NULL;
	char io_buffer[SCPFS_IO_BUFFER_SIZE];
	ssize_t read_count;
	int rc;
	int transport_exit_status;
	size_t digits_start;
	size_t digits_end;
	size_t trailer_start;
	size_t prefix_length = sizeof(status_prefix) - 1u;
	unsigned int remote_exit_status = 0;
	NTSTATUS status = STATUS_SUCCESS;
	if(output)
		*output = NULL;
	if(output_length)
		*output_length = 0;
	if(exit_status)
		*exit_status = -1;
	if(!backend || !command || !output || !output_length || !exit_status)
		return STATUS_INVALID_PARAMETER;
	if(backend->broken || !backend->session)
		return STATUS_CONNECTION_DISCONNECTED;
	if(strlen(command) > SCPFS_MAX_COMMAND_BYTES)
		return STATUS_NAME_TOO_LONG;
	/* Ignore SSH extended data so sshd diagnostics cannot corrupt NUL-framed
	 * stdout or fill the channel window. Redirect only the remote utility's
	 * own stderr into its result stream for NTSTATUS mapping, then append an
	 * out-of-band sentinel carrying the command's exit status. */
	if(!scpfs_buffer_append_text(&full_command,
		"LC_ALL=C; export LC_ALL; { ") ||
		!scpfs_buffer_append_text(&full_command, command) ||
		!scpfs_buffer_append_text(&full_command,
			"; } 2>&1; scpfs_rc=$?; printf '\\036SCPFS_RC:%d\\037' \"$scpfs_rc\"")) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	if(full_command.length > SCPFS_MAX_COMMAND_BYTES) {
		status = STATUS_NAME_TOO_LONG;
		goto done;
	}
	channel = libssh2_channel_open_session(backend->session);
	if(!channel) {
		status = scpfs_map_libssh2_error(libssh2_session_last_errno(backend->session));
		scpfs_poison_backend(backend, status);
		goto done;
	}
	rc = libssh2_channel_handle_extended_data2(channel,
		LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		goto done;
	}
	rc = libssh2_channel_process_startup(channel, "exec", 4u,
		full_command.data, (unsigned int)full_command.length);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		goto done;
	}
	while(!libssh2_channel_eof(channel)) {
		read_count = libssh2_channel_read(channel, io_buffer, sizeof(io_buffer));
		if(read_count > 0) {
			if(result.length > max_output + 32u ||
				(size_t)read_count > max_output + 32u - result.length) {
				status = STATUS_BUFFER_OVERFLOW;
				scpfs_poison_backend(backend, status);
				goto done;
			}
			if(!scpfs_buffer_append(&result, io_buffer, (size_t)read_count)) {
				status = STATUS_NO_MEMORY;
				scpfs_poison_backend(backend, status);
				goto done;
			}
		}
		else if(read_count == 0) {
			if(libssh2_channel_eof(channel))
				break;
			/* In blocking mode a zero read without EOF is not progress. */
			status = STATUS_DATA_ERROR;
			scpfs_poison_backend(backend, status);
			goto done;
		}
		else {
			status = scpfs_map_libssh2_error((int)read_count);
			scpfs_poison_backend(backend, status);
			goto done;
		}
	}
	rc = libssh2_channel_close(channel);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		goto done;
	}
	rc = libssh2_channel_wait_closed(channel);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		goto done;
	}
	/* libssh2 1.11.1 exposes get_exit_status but no has_exit_status query.
	 * wait_closed completes receipt of the server's channel close/exit status. */
	transport_exit_status = libssh2_channel_get_exit_status(channel);
	if(transport_exit_status != 0 || result.length < prefix_length + 2u ||
		(unsigned char)result.data[result.length - 1u] != 0x1fu) {
		status = STATUS_DATA_ERROR;
		scpfs_poison_backend(backend, status);
		goto done;
	}
	digits_end = result.length - 1u;
	digits_start = digits_end;
	while(digits_start > 0 && result.data[digits_start - 1u] >= '0' &&
		result.data[digits_start - 1u] <= '9')
		digits_start--;
	if(digits_start == digits_end || digits_end - digits_start > 3u ||
		digits_start < prefix_length ||
		memcmp(result.data + digits_start - prefix_length, status_prefix,
			prefix_length) != 0) {
		status = STATUS_DATA_ERROR;
		scpfs_poison_backend(backend, status);
		goto done;
	}
	trailer_start = digits_start - prefix_length;
	if(trailer_start > max_output) {
		status = STATUS_BUFFER_OVERFLOW;
		scpfs_poison_backend(backend, status);
		goto done;
	}
	while(digits_start < digits_end) {
		remote_exit_status = remote_exit_status * 10u +
			(unsigned int)(result.data[digits_start++] - '0');
	}
	if(remote_exit_status > 255u) {
		status = STATUS_DATA_ERROR;
		scpfs_poison_backend(backend, status);
		goto done;
	}
	result.length = trailer_start;
	*exit_status = (int)remote_exit_status;
	if(!scpfs_buffer_reserve(&result, 1u)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	result.data[result.length] = '\0';
	*output = result.data;
	*output_length = result.length;
	result.data = NULL;
done:
	if(channel)
		(void)libssh2_channel_free(channel);
	if(!*output && NT_SUCCESS(status)) {
		*output = (char *)malloc(1u);
		if(!*output)
			status = STATUS_NO_MEMORY;
		else
			(*output)[0] = '\0';
	}
	scpfs_buffer_free(&full_command);
	scpfs_buffer_free(&result);
	return status;
}

static NTSTATUS
scpfs_run_command_locked(SCPFS_BACKEND *backend, const char *command,
	size_t max_output, char **output, size_t *output_length)
{
	int exit_status = -1;
	NTSTATUS status = scpfs_execute_locked(backend, command, max_output,
		output, output_length, &exit_status);
	if(!NT_SUCCESS(status))
		return status;
	if(exit_status != 0) {
		status = scpfs_map_remote_error(*output, *output_length);
		free(*output);
		*output = NULL;
		*output_length = 0;
		return status;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_validate_parent_locked(SCPFS_BACKEND *backend, const char *path)
{
	char *parent = NULL;
	SCPFS_BUFFER command = { 0 };
	char *output = NULL;
	size_t output_length = 0;
	NTSTATUS status;
	if(scpfs_path_is_root(backend, path))
		return STATUS_SUCCESS;
	status = scpfs_parent_path(backend, path, &parent);
	if(!NT_SUCCESS(status))
		return status;
	if(!scpfs_buffer_append_text(&command, "realpath -e -z -- ") ||
		!scpfs_append_shell_word(&command, parent)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	if(!scpfs_buffer_reserve(&command, 1u)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	command.data[command.length] = '\0';
	status = scpfs_run_command_locked(backend, command.data,
		SCPFS_MAX_STAT_OUTPUT, &output, &output_length);
	if(!NT_SUCCESS(status))
		goto done;
	if(output_length != strlen(parent) + 1u ||
		memcmp(output, parent, strlen(parent)) != 0 ||
		output[output_length - 1u] != '\0') {
		status = STATUS_REPARSE_POINT_ENCOUNTERED;
		goto done;
	}
	status = STATUS_SUCCESS;
done:
	free(parent);
	free(output);
	scpfs_buffer_free(&command);
	return status;
}

static bool
scpfs_parse_u64(const char *text, size_t length, unsigned int base,
	uint64_t *value_out)
{
	char local[64];
	char *end = NULL;
	unsigned long long value;
	if(length == 0 || length >= sizeof(local))
		return false;
	memcpy(local, text, length);
	local[length] = '\0';
	if(local[0] == '-' || local[0] == '+')
		return false;
	errno = 0;
	value = _strtoui64(local, &end, (int)base);
	if(errno || !end || *end != '\0')
		return false;
	*value_out = (uint64_t)value;
	return true;
}

static bool
scpfs_parse_i64(const char *text, size_t length, int64_t *value_out)
{
	char local[64];
	char *end = NULL;
	long long value;
	if(length == 0 || length >= sizeof(local))
		return false;
	memcpy(local, text, length);
	local[length] = '\0';
	errno = 0;
	value = _strtoi64(local, &end, 10);
	if(errno || !end || *end != '\0')
		return false;
	*value_out = (int64_t)value;
	return true;
}

static bool
scpfs_parse_find_time(const char *text, size_t length, int64_t *mtime_ns_out)
{
	size_t index = 0;
	bool negative = false;
	uint64_t seconds = 0;
	uint32_t fraction = 0;
	size_t fraction_digits = 0;
	uint64_t absolute_ns;
	if(length == 0)
		return false;
	if(text[index] == '-') {
		negative = true;
		index++;
	}
	else if(text[index] == '+') {
		index++;
	}
	if(index == length)
		return false;
	while(index < length && text[index] >= '0' && text[index] <= '9') {
		unsigned int digit = (unsigned int)(text[index] - '0');
		if(seconds > (UINT64_MAX - digit) / 10u)
			return false;
		seconds = seconds * 10u + digit;
		index++;
	}
	if(index < length && text[index] == '.') {
		index++;
		while(index < length && text[index] >= '0' && text[index] <= '9') {
			if(fraction_digits < 9u)
				fraction = fraction * 10u + (uint32_t)(text[index] - '0');
			fraction_digits++;
			index++;
		}
	}
	if(index != length)
		return false;
	while(fraction_digits < 9u) {
		fraction *= 10u;
		fraction_digits++;
	}
	if(seconds > (uint64_t)INT64_MAX / 1000000000u)
		return false;
	absolute_ns = seconds * 1000000000u + fraction;
	if(absolute_ns > (uint64_t)INT64_MAX + (negative ? 1u : 0u))
		return false;
	if(negative) {
		if(absolute_ns == (uint64_t)INT64_MAX + 1u)
			*mtime_ns_out = INT64_MIN;
		else
			*mtime_ns_out = -(int64_t)absolute_ns;
	}
	else {
		*mtime_ns_out = (int64_t)absolute_ns;
	}
	return true;
}

static bool
scpfs_parse_stat_time(const char *seconds_text, size_t seconds_length,
	const char *formatted_text, size_t formatted_length, int64_t *time_ns_out)
{
	int64_t seconds;
	int64_t nanoseconds;
	uint32_t fraction = 0;
	size_t index;
	size_t digits = 0;
	const char *dot = NULL;
	const char *end = formatted_text + formatted_length;
	if(!scpfs_parse_i64(seconds_text, seconds_length, &seconds))
		return false;
	for(index = 0; index < formatted_length; index++) {
		if(formatted_text[index] == '.')
			dot = formatted_text + index + 1u;
	}
	if(dot) {
		while(dot + digits < end && dot[digits] >= '0' &&
			dot[digits] <= '9') {
			if(digits < 9u)
				fraction = fraction * 10u +
					(uint32_t)(dot[digits] - '0');
			digits++;
		}
	}
	while(digits < 9u) {
		fraction *= 10u;
		digits++;
	}
	if(seconds > INT64_MAX / 1000000000LL ||
		seconds < INT64_MIN / 1000000000LL)
		return false;
	nanoseconds = seconds * 1000000000LL;
	if(nanoseconds > INT64_MAX - (int64_t)fraction)
		return false;
	*time_ns_out = nanoseconds + (int64_t)fraction;
	return true;
}

static bool
scpfs_parse_stat_type(const char *text, size_t length, SCPFS_REMOTE_TYPE *type)
{
	if((length == 12u && memcmp(text, "regular file", 12u) == 0) ||
		(length == 18u && memcmp(text, "regular empty file", 18u) == 0))
		*type = SCPFS_REMOTE_FILE;
	else if(length == 9u && memcmp(text, "directory", 9u) == 0)
		*type = SCPFS_REMOTE_DIRECTORY;
	else if(length == 13u && memcmp(text, "symbolic link", 13u) == 0)
		*type = SCPFS_REMOTE_SYMLINK;
	else
		*type = SCPFS_REMOTE_OTHER;
	return true;
}

static SCPFS_REMOTE_TYPE
scpfs_find_type(char value)
{
	switch(value) {
	case 'f': return SCPFS_REMOTE_FILE;
	case 'd': return SCPFS_REMOTE_DIRECTORY;
	case 'l': return SCPFS_REMOTE_SYMLINK;
	default: return SCPFS_REMOTE_OTHER;
	}
}

static NTSTATUS
scpfs_stat_locked(SCPFS_BACKEND *backend, const char *path,
	SCPFS_REMOTE_STAT *stat_out)
{
	SCPFS_BUFFER command = { 0 };
	char *output = NULL;
	size_t output_length = 0;
	const char *fields[13];
	size_t lengths[13];
	size_t field_count = 0;
	size_t field_start = 0;
	size_t index;
	uint64_t value;
	NTSTATUS status;
	if(!stat_out)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_validate_parent_locked(backend, path);
	if(!NT_SUCCESS(status))
		return status;
	if(!scpfs_buffer_append_text(&command,
		"stat --printf='%F\\0%s\\0%X\\0%x\\0%Y\\0%y\\0%a\\0%d\\0%i\\0%u\\0%g\\0%Z\\0%z\\0' -- ") ||
		!scpfs_append_shell_word(&command, path) ||
		!scpfs_buffer_reserve(&command, 1u)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	command.data[command.length] = '\0';
	status = scpfs_run_command_locked(backend, command.data,
		SCPFS_MAX_STAT_OUTPUT, &output, &output_length);
	if(!NT_SUCCESS(status))
		goto done;
	for(index = 0; index < output_length; index++) {
		if(output[index] == '\0') {
			if(field_count >= 13u) {
				status = STATUS_DATA_ERROR;
				goto done;
			}
			fields[field_count] = output + field_start;
			lengths[field_count] = index - field_start;
			field_count++;
			field_start = index + 1u;
		}
	}
	if(field_count != 13u || field_start != output_length) {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	memset(stat_out, 0, sizeof(*stat_out));
	scpfs_parse_stat_type(fields[0], lengths[0], &stat_out->type);
	if(!scpfs_parse_u64(fields[1], lengths[1], 10u, &stat_out->size) ||
		!scpfs_parse_stat_time(fields[2], lengths[2], fields[3], lengths[3],
			&stat_out->atime_ns) ||
		!scpfs_parse_stat_time(fields[4], lengths[4], fields[5], lengths[5],
			&stat_out->mtime_ns) ||
		!scpfs_parse_u64(fields[6], lengths[6], 8u, &value)) {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	stat_out->mode = (uint32_t)value;
	if(!scpfs_parse_u64(fields[7], lengths[7], 10u, &stat_out->device) ||
		!scpfs_parse_u64(fields[8], lengths[8], 10u, &stat_out->inode) ||
		!scpfs_parse_u64(fields[9], lengths[9], 10u, &stat_out->uid) ||
		!scpfs_parse_u64(fields[10], lengths[10], 10u, &stat_out->gid) ||
		!scpfs_parse_stat_time(fields[11], lengths[11], fields[12], lengths[12],
			&stat_out->ctime_ns)) {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	status = STATUS_SUCCESS;
done:
	free(output);
	scpfs_buffer_free(&command);
	return status;
}

static bool
scpfs_parse_find_entry(const char *const fields[11], const size_t lengths[11],
	SCPFS_DIR_ENTRY *entry)
{
	uint64_t value;
	if(lengths[1] != 1u)
		return false;
	if(!scpfs_parse_u64(fields[2], lengths[2], 8u, &value))
		return false;
	entry->stat.mode = (uint32_t)value;
	if(!scpfs_parse_u64(fields[3], lengths[3], 10u, &entry->stat.size) ||
		!scpfs_parse_find_time(fields[4], lengths[4], &entry->stat.atime_ns) ||
		!scpfs_parse_find_time(fields[5], lengths[5], &entry->stat.mtime_ns) ||
		!scpfs_parse_u64(fields[6], lengths[6], 10u, &entry->stat.device) ||
		!scpfs_parse_u64(fields[7], lengths[7], 10u, &entry->stat.inode) ||
		!scpfs_parse_u64(fields[8], lengths[8], 10u, &entry->stat.uid) ||
		!scpfs_parse_u64(fields[9], lengths[9], 10u, &entry->stat.gid) ||
		!scpfs_parse_find_time(fields[10], lengths[10], &entry->stat.ctime_ns))
		return false;
	entry->stat.type = scpfs_find_type(fields[1][0]);
	return true;
}

static NTSTATUS
scpfs_list_locked(SCPFS_BACKEND *backend, const char *path,
	SCPFS_DIR_LIST *list_out)
{
	SCPFS_REMOTE_STAT directory_stat;
	SCPFS_BUFFER command = { 0 };
	char *output = NULL;
	size_t output_length = 0;
	size_t cursor = 0;
	size_t capacity = 0;
	NTSTATUS status;
	if(!list_out)
		return STATUS_INVALID_PARAMETER;
	memset(list_out, 0, sizeof(*list_out));
	status = scpfs_stat_locked(backend, path, &directory_stat);
	if(!NT_SUCCESS(status))
		return status;
	if(directory_stat.type != SCPFS_REMOTE_DIRECTORY)
		return directory_stat.type == SCPFS_REMOTE_SYMLINK ?
			STATUS_REPARSE_POINT_ENCOUNTERED : STATUS_NOT_A_DIRECTORY;
	if(!scpfs_buffer_append_text(&command,
		"find -P -- ") || !scpfs_append_shell_word(&command, path) ||
		!scpfs_buffer_append_text(&command,
			" -mindepth 1 -maxdepth 1 -printf '%f\\0%y\\0%m\\0%s\\0%A@\\0%T@\\0%D\\0%i\\0%U\\0%G\\0%C@\\0'") ||
		!scpfs_buffer_reserve(&command, 1u)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	command.data[command.length] = '\0';
	status = scpfs_run_command_locked(backend, command.data,
		SCPFS_MAX_LIST_OUTPUT, &output, &output_length);
	if(!NT_SUCCESS(status))
		goto done;
	while(cursor < output_length) {
		const char *fields[11];
		size_t lengths[11];
		size_t field_index;
		size_t field_start = cursor;
		SCPFS_DIR_ENTRY entry;
		bool valid_name = true;
		memset(&entry, 0, sizeof(entry));
		for(field_index = 0; field_index < 11u; field_index++) {
			while(cursor < output_length && output[cursor] != '\0')
				cursor++;
			if(cursor == output_length) {
				status = STATUS_DATA_ERROR;
				goto done;
			}
			fields[field_index] = output + field_start;
			lengths[field_index] = cursor - field_start;
			cursor++;
			field_start = cursor;
		}
		if(lengths[0] == 0 || lengths[0] > 255u) {
			valid_name = false;
		}
		else {
			WCHAR *name = NULL;
			size_t name_length = 0;
			status = scpfs_utf8_to_wide_n(fields[0], lengths[0],
				&name, &name_length);
			if(!NT_SUCCESS(status)) {
				/* A POSIX byte name Windows cannot represent is invisible through
				 * this namespace and must never be reinterpreted or truncated. */
				valid_name = false;
				status = STATUS_SUCCESS;
			}
			else if(!scpfs_is_windows_component(name, name_length)) {
				valid_name = false;
				free(name);
			}
			else {
				entry.name = name;
				entry.name_length = name_length;
			}
		}
		if(!valid_name)
			continue;
		if(!scpfs_parse_find_entry(fields, lengths, &entry)) {
			free(entry.name);
			status = STATUS_DATA_ERROR;
			goto done;
		}
		if(list_out->count >= SCPFS_MAX_DIRECTORY_ENTRIES) {
			free(entry.name);
			status = STATUS_BUFFER_OVERFLOW;
			goto done;
		}
		if(list_out->count == capacity) {
			/* Geometric growth; one realloc per entry was quadratic. */
			size_t next = capacity ? capacity * 2u : 64u;
			SCPFS_DIR_ENTRY *entries;
			if(next > SCPFS_MAX_DIRECTORY_ENTRIES)
				next = SCPFS_MAX_DIRECTORY_ENTRIES;
			entries = (SCPFS_DIR_ENTRY *)realloc(list_out->entries,
				next * sizeof(SCPFS_DIR_ENTRY));
			if(!entries) {
				free(entry.name);
				status = STATUS_NO_MEMORY;
				goto done;
			}
			list_out->entries = entries;
			capacity = next;
		}
		list_out->entries[list_out->count++] = entry;
	}
	status = STATUS_SUCCESS;
done:
	if(!NT_SUCCESS(status))
		scp_backend_free_list(list_out);
	free(output);
	scpfs_buffer_free(&command);
	return status;
}

static NTSTATUS
scpfs_parse_remote_root_command(SCPFS_BACKEND *backend)
{
	SCPFS_BUFFER command = { 0 };
	char *output = NULL;
	size_t output_length = 0;
	char *canonical = NULL;
	SCPFS_REMOTE_STAT stat;
	NTSTATUS status;
	if(!scpfs_buffer_append_text(&command, "realpath -e -z -- ") ||
		!scpfs_append_shell_word(&command, backend->remote_root) ||
		!scpfs_buffer_reserve(&command, 1u)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	command.data[command.length] = '\0';
	status = scpfs_run_command_locked(backend, command.data,
		SCPFS_MAX_STAT_OUTPUT, &output, &output_length);
	if(!NT_SUCCESS(status))
		goto done;
	if(output_length < 2u || output[output_length - 1u] != '\0' ||
		output[0] != '/') {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	canonical = (char *)malloc(output_length);
	if(!canonical) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	memcpy(canonical, output, output_length - 1u);
	canonical[output_length - 1u] = '\0';
	free(backend->remote_root);
	backend->remote_root = canonical;
	canonical = NULL;
	status = scpfs_stat_locked(backend, backend->remote_root, &stat);
	if(NT_SUCCESS(status) && stat.type != SCPFS_REMOTE_DIRECTORY)
		status = STATUS_NOT_A_DIRECTORY;
done:
	free(canonical);
	free(output);
	scpfs_buffer_free(&command);
	return status;
}

static NTSTATUS
scpfs_append_resolved_address(struct addrinfo **head, struct addrinfo **tail,
	int family, const void *address, uint16_t port)
{
	struct addrinfo *entry;
	if(family != AF_INET && family != AF_INET6)
		return STATUS_INVALID_PARAMETER;
	entry = (struct addrinfo *)calloc(1, sizeof(*entry));
	if(!entry)
		return STATUS_NO_MEMORY;
	entry->ai_addrlen = family == AF_INET ? sizeof(struct sockaddr_in) :
		sizeof(struct sockaddr_in6);
	entry->ai_addr = (struct sockaddr *)calloc(1, entry->ai_addrlen);
	if(!entry->ai_addr) {
		free(entry);
		return STATUS_NO_MEMORY;
	}
	entry->ai_family = family;
	entry->ai_socktype = SOCK_STREAM;
	entry->ai_protocol = IPPROTO_TCP;
	if(family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)entry->ai_addr;
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons(port);
		memcpy(&ipv4->sin_addr, address, sizeof(ipv4->sin_addr));
	} else {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)entry->ai_addr;
		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = htons(port);
		memcpy(&ipv6->sin6_addr, address, sizeof(ipv6->sin6_addr));
	}
	if(*tail)
		(*tail)->ai_next = entry;
	else
		*head = entry;
	*tail = entry;
	return STATUS_SUCCESS;
}

static bool
scpfs_parse_ipv6_literal(const char *host, struct in6_addr *address,
	ULONG *scope_id)
{
	const char *zone = strrchr(host, '%');
	char address_text[INET6_ADDRSTRLEN];
	char *end;
	unsigned long numeric_scope;
	*scope_id = 0;
	if(!zone)
		return InetPtonA(AF_INET6, host, address) == 1;
	if(zone == host || zone[1] == '\0' || (size_t)(zone - host) >= sizeof(address_text))
		return false;
	memcpy(address_text, host, (size_t)(zone - host));
	address_text[zone - host] = '\0';
	if(InetPtonA(AF_INET6, address_text, address) != 1)
		return false;
	errno = 0;
	numeric_scope = strtoul(zone + 1, &end, 10);
	if(errno == 0 && *end == '\0' && numeric_scope <= ULONG_MAX) {
		*scope_id = (ULONG)numeric_scope;
		return true;
	}
	*scope_id = if_nametoindex(zone + 1);
	return *scope_id != 0;
}

static void
scpfs_free_resolved_addresses(struct addrinfo *addresses)
{
	while(addresses) {
		struct addrinfo *next = addresses->ai_next;
		free(addresses->ai_addr);
		free(addresses->ai_canonname);
		free(addresses);
		addresses = next;
	}
}

typedef struct SCPFS_DNS_QUERY {
	volatile LONG references;
	volatile LONG completed;
	HANDLE completed_event;
	WCHAR *query_name;
	DNS_QUERY_REQUEST request;
	DNS_QUERY_RESULT result;
	DNS_QUERY_CANCEL cancel;
} SCPFS_DNS_QUERY;

static void
scpfs_dns_query_release(SCPFS_DNS_QUERY *query)
{
	if(InterlockedDecrement(&query->references) == 0) {
		if(query->result.pQueryRecords)
			DnsRecordListFree(query->result.pQueryRecords, DnsFreeRecordList);
		if(query->completed_event)
			CloseHandle(query->completed_event);
		free(query->query_name);
		free(query);
	}
}

static VOID WINAPI
scpfs_dns_query_completed(PVOID context, PDNS_QUERY_RESULT result)
{
	SCPFS_DNS_QUERY *query = (SCPFS_DNS_QUERY *)context;
	(void)result;
	InterlockedExchange(&query->completed, 1);
	SetEvent(query->completed_event);
	/* The callback reference keeps all DNS-owned state alive until this point. */
	scpfs_dns_query_release(query);
}

static NTSTATUS
scpfs_start_dns_query(PCWSTR name, WORD type, SCPFS_DNS_QUERY **query_out,
	BOOL *pending_out)
{
	SCPFS_DNS_QUERY *query;
	DNS_STATUS dns_status;
	*query_out = NULL;
	*pending_out = FALSE;
	query = (SCPFS_DNS_QUERY *)calloc(1, sizeof(*query));
	if(!query)
		return STATUS_NO_MEMORY;
	query->references = 2; /* caller plus a possible asynchronous callback */
	query->query_name = _wcsdup(name);
	query->completed_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if(!query->query_name || !query->completed_event) {
		BOOL event_created = query->completed_event != NULL;
		if(query->completed_event)
			CloseHandle(query->completed_event);
		free(query->query_name);
		free(query);
		return event_created ? STATUS_NO_MEMORY : STATUS_INSUFFICIENT_RESOURCES;
	}
	query->result.Version = DNS_QUERY_RESULTS_VERSION1;
	ZeroMemory(&query->request, sizeof(query->request));
	query->request.Version = DNS_QUERY_REQUEST_VERSION1;
	query->request.QueryName = query->query_name;
	query->request.QueryType = type;
	query->request.QueryOptions = DNS_QUERY_STANDARD;
	query->request.pQueryCompletionCallback = scpfs_dns_query_completed;
	query->request.pQueryContext = query;
	dns_status = DnsQueryEx(&query->request, &query->result, &query->cancel);
	if(dns_status == DNS_REQUEST_PENDING) {
		*pending_out = TRUE;
	} else {
		InterlockedExchange(&query->completed, 1);
		SetEvent(query->completed_event);
		/* Synchronous completion does not invoke the callback. */
		scpfs_dns_query_release(query);
	}
	*query_out = query;
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_append_dns_records(SCPFS_DNS_QUERY *query, struct addrinfo **head,
	struct addrinfo **tail, uint16_t port, size_t *count)
{
	DNS_RECORD *record;
	if(query->result.QueryStatus != ERROR_SUCCESS ||
		query->result.pQueryRecords == NULL)
		return STATUS_SUCCESS;
	for(record = query->result.pQueryRecords; record; record = record->pNext) {
		NTSTATUS status;
		if(*count >= 256u)
			break;
		if(record->wType == DNS_TYPE_A) {
			status = scpfs_append_resolved_address(head, tail, AF_INET,
				&record->Data.A.IpAddress, port);
		} else if(record->wType == DNS_TYPE_AAAA) {
			status = scpfs_append_resolved_address(head, tail, AF_INET6,
				record->Data.AAAA.Ip6Address.IP6Byte, port);
		} else {
			continue;
		}
		if(!NT_SUCCESS(status))
			return status;
		++*count;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_resolve_addresses(const char *host, uint16_t port, uint64_t deadline,
	struct addrinfo **addresses_out)
{
	struct in_addr ipv4;
	struct in6_addr ipv6;
	ULONG ipv6_scope_id;
	struct addrinfo *head = NULL, *tail = NULL;
	WCHAR *wide_host = NULL;
	SCPFS_DNS_QUERY *queries[2] = { NULL, NULL };
	BOOL pending[2] = { FALSE, FALSE };
	WORD types[2] = { DNS_TYPE_A, DNS_TYPE_AAAA };
	NTSTATUS status;
	BOOL timed_out = FALSE;
	BOOL wait_failed = FALSE;
	int index;
	size_t count = 0;
	*addresses_out = NULL;
	if(InetPtonA(AF_INET, host, &ipv4) == 1) {
		status = scpfs_append_resolved_address(&head, &tail, AF_INET,
			&ipv4, port);
		if(NT_SUCCESS(status))
			*addresses_out = head;
		return status;
	}
	if(scpfs_parse_ipv6_literal(host, &ipv6, &ipv6_scope_id)) {
		status = scpfs_append_resolved_address(&head, &tail, AF_INET6,
			&ipv6, port);
		if(NT_SUCCESS(status)) {
			((struct sockaddr_in6 *)tail->ai_addr)->sin6_scope_id = ipv6_scope_id;
			*addresses_out = head;
		}
		return status;
	}
	status = scpfs_utf8_to_wide_n(host, strlen(host), &wide_host, NULL);
	if(!NT_SUCCESS(status))
		return status;
	for(index = 0; index < 2; ++index) {
		status = scpfs_start_dns_query(wide_host, types[index],
			&queries[index], &pending[index]);
		if(!NT_SUCCESS(status))
			break;
	}
	free(wide_host);
	wide_host = NULL;
	if(index != 2 && queries[0] == NULL && queries[1] == NULL)
		return status;
	for(;;) {
		HANDLE events[2];
		DWORD wait_ms;
		uint64_t now;
		BOOL all_completed = TRUE;
		DWORD wait_result;
		DWORD event_count = 0;
		for(index = 0; index < 2; ++index) {
			if(queries[index] &&
				InterlockedCompareExchange(&queries[index]->completed, 0, 0) == 0) {
				all_completed = FALSE;
				events[event_count] = queries[index]->completed_event;
				++event_count;
			}
		}
		if(all_completed)
			break;
		now = GetTickCount64();
		if(now >= deadline) {
			timed_out = TRUE;
			break;
		}
		wait_ms = (DWORD)((deadline - now) > MAXDWORD ? MAXDWORD : deadline - now);
		wait_result = WaitForMultipleObjects(event_count, events, FALSE, wait_ms);
		if(wait_result == WAIT_TIMEOUT) {
			timed_out = TRUE;
			break;
		}
		if(wait_result == WAIT_FAILED) {
			wait_failed = TRUE;
			break;
		}
	}
	if(timed_out || wait_failed) {
		for(index = 0; index < 2; ++index) {
			if(pending[index] && queries[index] &&
				InterlockedCompareExchange(&queries[index]->completed, 0, 0) == 0)
				(void)DnsCancelQuery(&queries[index]->cancel);
		}
	}
	for(index = 0; index < 2; ++index) {
		if(queries[index] &&
			InterlockedCompareExchange(&queries[index]->completed, 0, 0) != 0) {
			status = scpfs_append_dns_records(queries[index], &head, &tail,
				port, &count);
			if(!NT_SUCCESS(status))
				goto done;
		}
	}
	if(head) {
		*addresses_out = head;
		head = NULL;
		status = STATUS_SUCCESS;
		goto done;
	}
	status = timed_out ? STATUS_IO_TIMEOUT :
		(wait_failed ? STATUS_UNSUCCESSFUL : STATUS_BAD_NETWORK_PATH);
done:
	scpfs_free_resolved_addresses(head);
	for(index = 0; index < 2; ++index)
		if(queries[index])
			scpfs_dns_query_release(queries[index]);
	return status;
}

static NTSTATUS
scpfs_open_tcp_socket(const char *host, uint16_t port, uint32_t timeout_ms,
	SOCKET *socket_out)
{
	struct addrinfo *addresses = NULL;
	struct addrinfo *address;
	uint64_t deadline = GetTickCount64() + timeout_ms;
	SOCKET connected = INVALID_SOCKET;
	NTSTATUS resolve_status = scpfs_resolve_addresses(host, port, deadline,
		&addresses);
	if(!NT_SUCCESS(resolve_status))
		return resolve_status;
	for(address = addresses; address; address = address->ai_next) {
		unsigned long nonblocking = 1;
		int connect_result;
		SOCKET candidate;
		if(GetTickCount64() >= deadline)
			break;
		candidate = socket(address->ai_family, address->ai_socktype,
			address->ai_protocol);
		if(candidate == INVALID_SOCKET)
			continue;
		if(ioctlsocket(candidate, FIONBIO, &nonblocking) != 0) {
			closesocket(candidate);
			continue;
		}
		if(GetTickCount64() >= deadline) {
			closesocket(candidate);
			break;
		}
		connect_result = connect(candidate, address->ai_addr,
			(int)address->ai_addrlen);
		if(connect_result != 0) {
			int error = WSAGetLastError();
			if(error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
				error == WSAEINVAL) {
				fd_set write_set;
				fd_set error_set;
				struct timeval timeout;
				uint64_t now = GetTickCount64();
				uint64_t remaining = deadline > now ? deadline - now : 0u;
				int select_result;
				if(remaining == 0u) {
					closesocket(candidate);
					break;
				}
				FD_ZERO(&write_set);
				FD_ZERO(&error_set);
				FD_SET(candidate, &write_set);
				FD_SET(candidate, &error_set);
				timeout.tv_sec = (long)(remaining / 1000u);
				timeout.tv_usec = (long)((remaining % 1000u) * 1000u);
				select_result = select(0, NULL, &write_set, &error_set, &timeout);
				if(select_result > 0) {
					int socket_error = 0;
					int socket_error_length = sizeof(socket_error);
					if(getsockopt(candidate, SOL_SOCKET, SO_ERROR,
						(char *)&socket_error, &socket_error_length) == 0 &&
						socket_error == 0)
						connect_result = 0;
				}
				else if(select_result == 0) {
					closesocket(candidate);
					break;
				}
			}
		}
		if(connect_result == 0) {
			if(GetTickCount64() >= deadline) {
				closesocket(candidate);
				break;
			}
			nonblocking = 0;
			if(ioctlsocket(candidate, FIONBIO, &nonblocking) == 0) {
				DWORD socket_timeout = timeout_ms;
				int tcp_nodelay = 1;
				if(setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO,
					(const char *)&socket_timeout, sizeof(socket_timeout)) == 0 &&
					setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO,
					(const char *)&socket_timeout, sizeof(socket_timeout)) == 0) {
					if(GetTickCount64() < deadline) {
						(void)setsockopt(candidate, IPPROTO_TCP, TCP_NODELAY,
							(const char *)&tcp_nodelay, sizeof(tcp_nodelay));
						connected = candidate;
						break;
					}
				}
			}
		}
		closesocket(candidate);
	}
	scpfs_free_resolved_addresses(addresses);
	if(connected == INVALID_SOCKET) {
		if(GetTickCount64() >= deadline)
			return STATUS_IO_TIMEOUT;
		return STATUS_BAD_NETWORK_PATH;
	}
	*socket_out = connected;
	return STATUS_SUCCESS;
}

static bool
scpfs_read_local_file(PCWSTR path, size_t max_bytes, unsigned char **data_out,
	size_t *length_out)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	LARGE_INTEGER size = { 0 };
	unsigned char *data = NULL;
	size_t remaining;
	size_t offset = 0;
	bool result = false;
	*data_out = NULL;
	*length_out = 0;
	file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
		FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file == INVALID_HANDLE_VALUE)
		return false;
	if(!GetFileSizeEx(file, &size) || size.QuadPart < 0 ||
		(uint64_t)size.QuadPart > max_bytes)
		goto done;
	if((uint64_t)size.QuadPart > SIZE_MAX)
		goto done;
	data = (unsigned char *)malloc((size_t)size.QuadPart + 1u);
	if(!data)
		goto done;
	remaining = (size_t)size.QuadPart;
	while(remaining) {
		DWORD chunk = (DWORD)(remaining > UINT32_MAX ? UINT32_MAX : remaining);
		DWORD read_bytes = 0;
		if(!ReadFile(file, data + offset, chunk, &read_bytes, NULL) ||
			read_bytes == 0)
			goto done;
		offset += read_bytes;
		remaining -= read_bytes;
	}
	data[offset] = 0;
	*data_out = data;
	*length_out = offset;
	data = NULL;
	result = true;
done:
	if(data) {
		SecureZeroMemory(data, (size_t)(size.QuadPart >= 0 ? size.QuadPart : 0));
		free(data);
	}
	CloseHandle(file);
	return result;
}

static int
scpfs_host_key_mask(int host_key_type)
{
	switch(host_key_type) {
	case LIBSSH2_HOSTKEY_TYPE_RSA: return LIBSSH2_KNOWNHOST_KEY_SSHRSA;
	case LIBSSH2_HOSTKEY_TYPE_DSS: return LIBSSH2_KNOWNHOST_KEY_SSHDSS;
	case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: return LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
	case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: return LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
	case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: return LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
	case LIBSSH2_HOSTKEY_TYPE_ED25519: return LIBSSH2_KNOWNHOST_KEY_ED25519;
	default: return 0;
	}
}

static NTSTATUS
scpfs_load_known_hosts(PCWSTR path, LIBSSH2_KNOWNHOSTS *known_hosts)
{
	unsigned char *contents = NULL;
	size_t contents_length = 0;
	size_t cursor = 0;
	size_t entries = 0;
	if(!scpfs_read_local_file(path, SCPFS_MAX_KNOWN_HOSTS_BYTES,
		&contents, &contents_length))
		return STATUS_ACCESS_DENIED;
	while(cursor < contents_length) {
		size_t start = cursor;
		size_t length;
		int rc;
		while(cursor < contents_length && contents[cursor] != '\n')
			cursor++;
		length = cursor - start;
		if(cursor < contents_length)
			cursor++;
		if(length && contents[start + length - 1u] == '\r')
			length--;
		while(length && (contents[start] == ' ' || contents[start] == '\t')) {
			start++;
			length--;
		}
		if(length == 0 || contents[start] == '#')
			continue;
		{
			unsigned char delimiter = contents[start + length];
			/* libssh2 inspects the byte after the supplied span for LF. */
			contents[start + length] = '\0';
			rc = libssh2_knownhost_readline(known_hosts,
				(const char *)contents + start, length,
				LIBSSH2_KNOWNHOST_FILE_OPENSSH);
			contents[start + length] = delimiter;
		}
		if(rc != 0) {
			SecureZeroMemory(contents, contents_length);
			free(contents);
			return STATUS_INVALID_PARAMETER;
		}
		entries++;
	}
	SecureZeroMemory(contents, contents_length);
	free(contents);
	return entries ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

static NTSTATUS
scpfs_verify_host_key(SCPFS_BACKEND *backend, PCWSTR known_hosts_file,
	uint16_t port)
{
	LIBSSH2_KNOWNHOSTS *known_hosts = NULL;
	const char *key;
	size_t key_length = 0;
	int key_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
	int key_mask;
	int check_result;
	NTSTATUS status;
	known_hosts = libssh2_knownhost_init(backend->session);
	if(!known_hosts)
		return STATUS_NO_MEMORY;
	status = scpfs_load_known_hosts(known_hosts_file, known_hosts);
	if(!NT_SUCCESS(status))
		goto done;
	key = libssh2_session_hostkey(backend->session, &key_length, &key_type);
	key_mask = scpfs_host_key_mask(key_type);
	if(!key || key_length == 0 || key_mask == 0) {
		status = STATUS_TRUST_FAILURE;
		goto done;
	}
	check_result = libssh2_knownhost_checkp(known_hosts, backend->host,
		(int)port, key, key_length,
		LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW |
		key_mask, NULL);
	if(check_result != LIBSSH2_KNOWNHOST_CHECK_MATCH)
		status = STATUS_TRUST_FAILURE;
	done:
	libssh2_knownhost_free(known_hosts);
	return status;
}

NTSTATUS
scp_backend_connect(const SCPFS_BACKEND_OPTIONS *options,
	SCPFS_BACKEND **backend_out)
{
	SCPFS_BACKEND *backend = NULL;
	char *identity_passphrase = NULL;
	unsigned char *private_key = NULL;
	size_t private_key_length = 0;
	uint16_t port;
	NTSTATUS status;
	int rc;
	if(!backend_out || !options || !options->host || !options->username ||
		!options->remote_root || !options->known_hosts_file ||
		!options->identity_file) {
		return STATUS_INVALID_PARAMETER;
	}
	*backend_out = NULL;
	if(!InitOnceExecuteOnce(&g_network_once, scpfs_initialize_network,
		NULL, NULL) || !NT_SUCCESS(g_network_status))
		return g_network_status;
	backend = (SCPFS_BACKEND *)calloc(1, sizeof(*backend));
	if(!backend)
		return STATUS_NO_MEMORY;
	backend->socket = INVALID_SOCKET;
	InitializeCriticalSection(&backend->mutex);
	backend->mutex_initialized = true;
	backend->failure_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if(!backend->failure_event) {
		status = FspNtStatusFromWin32(GetLastError());
		goto failed;
	}
	backend->timeout_ms = options->timeout_ms ? options->timeout_ms :
		SCPFS_DEFAULT_TIMEOUT_MS;
	status = scpfs_wide_to_utf8(options->host, &backend->host, NULL);
	if(!NT_SUCCESS(status))
		goto failed;
	status = scpfs_wide_to_utf8(options->username, &backend->username, NULL);
	if(!NT_SUCCESS(status))
		goto failed;
	status = scpfs_normalize_remote_root(options->remote_root,
		&backend->remote_root);
	if(!NT_SUCCESS(status))
		goto failed;
	if(backend->host[0] == '\0' || backend->username[0] == '\0') {
		status = STATUS_INVALID_PARAMETER;
		goto failed;
	}
	status = scpfs_wide_to_utf8(options->identity_passphrase ?
		options->identity_passphrase : L"", &identity_passphrase, NULL);
	if(!NT_SUCCESS(status))
		goto failed;
	if(!scpfs_read_local_file(options->identity_file,
		SCPFS_MAX_PRIVATE_KEY_BYTES, &private_key, &private_key_length) ||
		private_key_length == 0) {
		status = STATUS_ACCESS_DENIED;
		goto failed;
	}
	port = options->port ? options->port : 22u;
	status = scpfs_open_tcp_socket(backend->host, port, backend->timeout_ms,
		&backend->socket);
	if(!NT_SUCCESS(status))
		goto failed;
	backend->session = libssh2_session_init();
	if(!backend->session) {
		status = STATUS_NO_MEMORY;
		goto failed;
	}
	libssh2_session_set_timeout(backend->session, (long)backend->timeout_ms);
 	(void)libssh2_session_flag(backend->session, LIBSSH2_FLAG_QUOTE_PATHS, 1);
	rc = libssh2_session_handshake(backend->session, backend->socket);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		goto failed;
	}
	status = scpfs_verify_host_key(backend, options->known_hosts_file, port);
	if(!NT_SUCCESS(status))
		goto failed;
	rc = libssh2_userauth_publickey_frommemory(backend->session,
		backend->username, strlen(backend->username), NULL, 0,
		(const char *)private_key, private_key_length,
		identity_passphrase[0] ? identity_passphrase : NULL);
	SecureZeroMemory(private_key, private_key_length);
	free(private_key);
	private_key = NULL;
	SecureZeroMemory(identity_passphrase, strlen(identity_passphrase));
	free(identity_passphrase);
	identity_passphrase = NULL;
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		goto failed;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_parse_remote_root_command(backend);
	LeaveCriticalSection(&backend->mutex);
	if(!NT_SUCCESS(status))
		goto failed;
	*backend_out = backend;
	return STATUS_SUCCESS;
failed:
	if(private_key) {
		SecureZeroMemory(private_key, private_key_length);
		free(private_key);
	}
	if(identity_passphrase) {
		SecureZeroMemory(identity_passphrase, strlen(identity_passphrase));
		free(identity_passphrase);
	}
	if(backend) {
		if(backend->session) {
			(void)libssh2_session_free(backend->session);
			backend->session = NULL;
		}
		if(backend->socket != INVALID_SOCKET) {
			shutdown(backend->socket, SD_BOTH);
			closesocket(backend->socket);
		}
		if(backend->failure_event)
			CloseHandle(backend->failure_event);
		free(backend->host);
		free(backend->username);
		free(backend->remote_root);
		if(backend->mutex_initialized)
			DeleteCriticalSection(&backend->mutex);
		free(backend);
	}
	return status;
}

void
scp_backend_disconnect(SCPFS_BACKEND *backend)
{
	if(!backend)
		return;
	if(backend->mutex_initialized)
		EnterCriticalSection(&backend->mutex);
	if(backend->session) {
		if(!backend->broken)
			(void)libssh2_session_disconnect(backend->session, "scpfs unmount");
		(void)libssh2_session_free(backend->session);
		backend->session = NULL;
	}
	if(backend->socket != INVALID_SOCKET) {
		shutdown(backend->socket, SD_BOTH);
		closesocket(backend->socket);
		backend->socket = INVALID_SOCKET;
	}
	if(backend->mutex_initialized) {
		LeaveCriticalSection(&backend->mutex);
		DeleteCriticalSection(&backend->mutex);
	}
	if(backend->failure_event)
		CloseHandle(backend->failure_event);
	free(backend->host);
	free(backend->username);
	free(backend->remote_root);
	free(backend);
}

WCHAR *
scp_backend_dup_remote_root(const SCPFS_BACKEND *backend)
{
	WCHAR *root = NULL;
	if(backend && backend->remote_root)
		(void)scpfs_utf8_to_wide_n(backend->remote_root,
			strlen(backend->remote_root), &root, NULL);
	return root;
}

NTSTATUS
scp_backend_watch_stream_open(const SCPFS_BACKEND_OPTIONS *options,
	const unsigned char *helper_source, size_t helper_length,
	SCPFS_WATCH_STREAM **stream_out)
{
	static const char command_prefix[] =
		"python3 -u -c 'import sys; n=int(sys.argv[1]); sys.argv=[\"scpfs_watch.py\"]+sys.argv[2:]; "
		"b=sys.stdin.buffer.read(n); "
		"exec(compile(b, \"scpfs_watch.py\", \"exec\"))' ";
	SCPFS_BACKEND_OPTIONS bounded_options;
	SCPFS_WATCH_STREAM *stream = NULL;
	SCPFS_BACKEND *backend = NULL;
	SCPFS_BUFFER command = { 0 };
	char *expected_root = NULL;
	char length_text[32];
	int written;
	size_t offset;
	NTSTATUS status;
	int rc;
	if(!stream_out || !options || !helper_source || helper_length == 0 ||
		helper_length > 256u * 1024u)
		return STATUS_INVALID_PARAMETER;
	*stream_out = NULL;
	bounded_options = *options;
	if(bounded_options.timeout_ms == 0 || bounded_options.timeout_ms > 5000u)
		bounded_options.timeout_ms = 5000u;
	status = scp_backend_connect(&bounded_options, &backend);
	if(!NT_SUCCESS(status))
		return status;
	/* The caller supplies the main connection's pinned canonical root.
	 * Refuse monitoring if another canonicalization resolves elsewhere. */
	status = scpfs_normalize_remote_root(options->remote_root, &expected_root);
	if(!NT_SUCCESS(status) || strcmp(expected_root, backend->remote_root) != 0) {
		free(expected_root);
		scp_backend_disconnect(backend);
		return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
	}
	free(expected_root);
	stream = (SCPFS_WATCH_STREAM *)calloc(1, sizeof(*stream));
	if(!stream) {
		scp_backend_disconnect(backend);
		return STATUS_NO_MEMORY;
	}
	stream->backend = backend;
	written = _snprintf_s(length_text, sizeof(length_text), _TRUNCATE,
		"%zu", helper_length);
	if(written < 0 ||
		!scpfs_buffer_append_text(&command, command_prefix) ||
		!scpfs_buffer_append_text(&command, length_text) ||
		!scpfs_buffer_append_text(&command, " --root ") ||
		!scpfs_append_shell_word(&command, backend->remote_root) ||
		!scpfs_buffer_reserve(&command, 1u)) {
		status = STATUS_NO_MEMORY;
		goto failed;
	}
	command.data[command.length] = '\0';
	EnterCriticalSection(&backend->mutex);
	stream->channel = libssh2_channel_open_session(backend->session);
	if(!stream->channel) {
		status = scpfs_map_libssh2_error(
			libssh2_session_last_errno(backend->session));
		scpfs_poison_backend(backend, status);
		goto unlock_failed;
	}
	rc = libssh2_channel_handle_extended_data2(stream->channel,
		LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		goto unlock_failed;
	}
	rc = libssh2_channel_process_startup(stream->channel, "exec", 4u,
		command.data, (unsigned int)command.length);
	if(rc != 0) {
		status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		goto unlock_failed;
	}
	libssh2_session_set_timeout(backend->session, 5000L);
	offset = 0;
	while(offset < helper_length) {
		ssize_t count = libssh2_channel_write(stream->channel,
			(const char *)helper_source + offset, helper_length - offset);
		if(count <= 0) {
			status = scpfs_map_libssh2_error((int)count);
			if(status == STATUS_UNSUCCESSFUL)
				status = STATUS_CONNECTION_DISCONNECTED;
			scpfs_poison_backend(backend, status);
			goto unlock_failed;
		}
		offset += (size_t)count;
	}
	libssh2_session_set_timeout(backend->session, SCPFS_WATCH_READ_TIMEOUT_MS);
	LeaveCriticalSection(&backend->mutex);
	scpfs_buffer_free(&command);
	*stream_out = stream;
	return STATUS_SUCCESS;

unlock_failed:
	if(stream->channel) {
		(void)libssh2_channel_free(stream->channel);
		stream->channel = NULL;
	}
	LeaveCriticalSection(&backend->mutex);
failed:
	scpfs_buffer_free(&command);
	free(stream);
	scp_backend_disconnect(backend);
	return status;
}

NTSTATUS
scp_backend_watch_stream_write(SCPFS_WATCH_STREAM *stream,
	const void *data, size_t length)
{
	size_t offset = 0;
	NTSTATUS status = STATUS_SUCCESS;
	if(!stream || !stream->backend || !stream->channel || (!data && length))
		return STATUS_INVALID_PARAMETER;
	EnterCriticalSection(&stream->backend->mutex);
	libssh2_session_set_timeout(stream->backend->session, 5000L);
	while(offset < length) {
		ssize_t count = libssh2_channel_write(stream->channel,
			(const char *)data + offset, length - offset);
		if(count <= 0) {
			status = scpfs_map_libssh2_error((int)count);
			if(status == STATUS_UNSUCCESSFUL)
				status = STATUS_CONNECTION_DISCONNECTED;
			scpfs_poison_backend(stream->backend, status);
			break;
		}
		offset += (size_t)count;
	}
	libssh2_session_set_timeout(stream->backend->session,
		SCPFS_WATCH_READ_TIMEOUT_MS);
	LeaveCriticalSection(&stream->backend->mutex);
	return status;
}

NTSTATUS
scp_backend_watch_stream_read(SCPFS_WATCH_STREAM *stream,
	void *buffer, size_t capacity, size_t *read_out)
{
	ssize_t count;
	NTSTATUS status = STATUS_SUCCESS;
	if(!stream || !stream->backend || !stream->channel || !buffer ||
		capacity == 0 || !read_out)
		return STATUS_INVALID_PARAMETER;
	*read_out = 0;
	EnterCriticalSection(&stream->backend->mutex);
	count = libssh2_channel_read(stream->channel, (char *)buffer, capacity);
	if(count > 0) {
		*read_out = (size_t)count;
	} else if(count == LIBSSH2_ERROR_TIMEOUT ||
		count == LIBSSH2_ERROR_SOCKET_TIMEOUT) {
		status = STATUS_IO_TIMEOUT;
	} else if(count == 0 && libssh2_channel_eof(stream->channel)) {
		status = STATUS_CONNECTION_DISCONNECTED;
		scpfs_poison_backend(stream->backend, status);
	} else if(count < 0) {
		status = scpfs_map_libssh2_error((int)count);
		scpfs_poison_backend(stream->backend, status);
	} else {
		status = STATUS_CONNECTION_DISCONNECTED;
		scpfs_poison_backend(stream->backend, status);
	}
	LeaveCriticalSection(&stream->backend->mutex);
	return status;
}

void
scp_backend_watch_stream_close(SCPFS_WATCH_STREAM *stream)
{
	if(!stream)
		return;
	if(stream->backend && stream->backend->socket != INVALID_SOCKET) {
		InterlockedExchange(&stream->backend->broken, 1);
		shutdown(stream->backend->socket, SD_BOTH);
	}
	if(stream->backend && stream->backend->mutex_initialized)
		EnterCriticalSection(&stream->backend->mutex);
	if(stream->channel) {
		(void)libssh2_channel_free(stream->channel);
		stream->channel = NULL;
	}
	if(stream->backend && stream->backend->mutex_initialized)
		LeaveCriticalSection(&stream->backend->mutex);
	scp_backend_disconnect(stream->backend);
	free(stream);
}

HANDLE
scp_backend_failure_event(SCPFS_BACKEND *backend)
{
	return backend ? backend->failure_event : NULL;
}

NTSTATUS
scp_backend_failure_status(const SCPFS_BACKEND *backend)
{
	if(!backend)
		return STATUS_INVALID_PARAMETER;
	return (NTSTATUS)InterlockedCompareExchange(
		(volatile LONG *)&backend->failure_status, 0, 0);
}

NTSTATUS
scp_backend_stat(SCPFS_BACKEND *backend, PCWSTR path,
	SCPFS_REMOTE_STAT *stat_out)
{
	char *remote = NULL;
	NTSTATUS status;
	if(!backend || !stat_out)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	EnterCriticalSection(&backend->mutex);
	status = scpfs_stat_locked(backend, remote, stat_out);
	LeaveCriticalSection(&backend->mutex);
	free(remote);
	return status;
}

NTSTATUS
scp_backend_list(SCPFS_BACKEND *backend, PCWSTR path,
	SCPFS_DIR_LIST *list_out)
{
	char *remote = NULL;
	NTSTATUS status;
	if(!backend || !list_out)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	EnterCriticalSection(&backend->mutex);
	status = scpfs_list_locked(backend, remote, list_out);
	LeaveCriticalSection(&backend->mutex);
	free(remote);
	return status;
}

void
scp_backend_free_list(SCPFS_DIR_LIST *list)
{
	size_t index;
	if(!list)
		return;
	for(index = 0; index < list->count; index++)
		free(list->entries[index].name);
	free(list->entries);
	list->entries = NULL;
	list->count = 0;
}

static bool
scpfs_is_missing_status(NTSTATUS status)
{
	return status == STATUS_OBJECT_NAME_NOT_FOUND ||
		status == STATUS_OBJECT_PATH_NOT_FOUND;
}

static bool
scpfs_same_snapshot(const SCPFS_REMOTE_STAT *left,
	const SCPFS_REMOTE_STAT *right)
{
	return left->type == right->type && left->size == right->size &&
		left->mtime_ns == right->mtime_ns && left->mode == right->mode &&
		left->device == right->device && left->inode == right->inode;
}

static NTSTATUS
scpfs_finish_command(SCPFS_BUFFER *command)
{
	if(!scpfs_buffer_reserve(command, 1u))
		return STATUS_NO_MEMORY;
	command->data[command->length] = '\0';
	return STATUS_SUCCESS;
}

/* The SCP protocol has a final one-byte acknowledgement in both directions.
 * Keep the session unusable after a framing error; the next SSH message could
 * otherwise be mistaken for a later operation's response. */
static NTSTATUS
scpfs_scp_ack_locked(SCPFS_BACKEND *backend, LIBSSH2_CHANNEL *channel,
	bool send_ack)
{
	char ack = '\0';
	ssize_t count;
	if(send_ack) {
		count = libssh2_channel_write(channel, &ack, 1u);
		if(count != 1) {
			NTSTATUS status = scpfs_map_libssh2_error((int)count);
			scpfs_poison_backend(backend, status);
			return status;
		}
	}
	else {
		count = libssh2_channel_read(channel, &ack, 1u);
		if(count != 1 || ack != '\0') {
			NTSTATUS status = count < 0 ? scpfs_map_libssh2_error((int)count) :
				STATUS_DATA_ERROR;
			scpfs_poison_backend(backend, status);
			return status;
		}
	}
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_finish_scp_channel_locked(SCPFS_BACKEND *backend,
	LIBSSH2_CHANNEL *channel)
{
	int rc;
	int exit_status;
	rc = libssh2_channel_send_eof(channel);
	if(rc != 0) {
		NTSTATUS status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		return status;
	}
	rc = libssh2_channel_wait_eof(channel);
	if(rc != 0) {
		NTSTATUS status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		return status;
	}
	rc = libssh2_channel_close(channel);
	if(rc != 0) {
		NTSTATUS status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		return status;
	}
	rc = libssh2_channel_wait_closed(channel);
	if(rc != 0) {
		NTSTATUS status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		return status;
	}
	exit_status = libssh2_channel_get_exit_status(channel);
	if(exit_status != 0) {
		scpfs_poison_backend(backend, STATUS_DATA_ERROR);
		return STATUS_DATA_ERROR;
	}
	return STATUS_SUCCESS;
}

static bool
scpfs_ns_to_seconds(int64_t time_ns, int64_t *seconds_out)
{
	int64_t seconds = time_ns / 1000000000LL;
	int64_t fraction = time_ns % 1000000000LL;
	if(fraction < 0)
		seconds--;
	*seconds_out = seconds;
	return true;
}

static bool
scpfs_ns_to_touch_text(int64_t time_ns, char text[64])
{
	int64_t seconds = time_ns / 1000000000LL;
	int64_t fraction = time_ns % 1000000000LL;
	if(fraction < 0) {
		seconds--;
		fraction += 1000000000LL;
	}
	return snprintf(text, 64u, "@%lld.%09lld", (long long)seconds,
		(long long)fraction) > 0;
}

static bool
scpfs_filetime_to_unix_ns(FILETIME file_time, int64_t *time_ns_out)
{
	const uint64_t unix_epoch_filetime = UINT64_C(116444736000000000);
	ULARGE_INTEGER ticks;
	uint64_t delta;
	ticks.LowPart = file_time.dwLowDateTime;
	ticks.HighPart = file_time.dwHighDateTime;
	if(ticks.QuadPart >= unix_epoch_filetime) {
		delta = ticks.QuadPart - unix_epoch_filetime;
		if(delta > (uint64_t)INT64_MAX / 100u)
			return false;
		*time_ns_out = (int64_t)(delta * 100u);
	}
	else {
		delta = unix_epoch_filetime - ticks.QuadPart;
		if(delta > ((uint64_t)INT64_MAX + 1u) / 100u)
			return false;
		if(delta * 100u == (uint64_t)INT64_MAX + 1u)
			*time_ns_out = INT64_MIN;
		else
			*time_ns_out = -(int64_t)(delta * 100u);
	}
	return true;
}

static NTSTATUS
scpfs_set_times_locked(SCPFS_BACKEND *backend, const char *remote,
	int64_t atime_ns, int64_t mtime_ns, bool set_atime, bool set_mtime)
{
	SCPFS_BUFFER command = { 0 };
	char time_text[64];
	char *output = NULL;
	size_t output_length = 0;
	NTSTATUS status;
	if(!set_atime && !set_mtime)
		return STATUS_SUCCESS;
	if(set_atime) {
		if(!scpfs_ns_to_touch_text(atime_ns, time_text) ||
			!scpfs_buffer_append_text(&command, "touch -c -a -d ") ||
			!scpfs_append_shell_word(&command, time_text) ||
			!scpfs_buffer_append_text(&command, " -- ") ||
			!scpfs_append_shell_word(&command, remote)) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
	}
	if(set_mtime) {
		if(command.length && !scpfs_buffer_append_text(&command, " && ")) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		if(!scpfs_ns_to_touch_text(mtime_ns, time_text) ||
			!scpfs_buffer_append_text(&command, "touch -c -m -d ") ||
			!scpfs_append_shell_word(&command, time_text) ||
			!scpfs_buffer_append_text(&command, " -- ") ||
			!scpfs_append_shell_word(&command, remote)) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
	}
	status = scpfs_finish_command(&command);
	if(NT_SUCCESS(status))
		status = scpfs_run_command_locked(backend, command.data,
			SCPFS_MAX_STAT_OUTPUT, &output, &output_length);
done:
	free(output);
	scpfs_buffer_free(&command);
	return status;
}

static NTSTATUS
scpfs_ignore_extended_data_locked(SCPFS_BACKEND *backend,
	LIBSSH2_CHANNEL *channel)
{
	int rc = libssh2_channel_handle_extended_data2(channel,
		LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE);
	if(rc != 0) {
		NTSTATUS status = scpfs_map_libssh2_error(rc);
		scpfs_poison_backend(backend, status);
		return status;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_write_all_locked(SCPFS_BACKEND *backend, LIBSSH2_CHANNEL *channel,
	HANDLE file, uint64_t size)
{
	unsigned char buffer[SCPFS_IO_BUFFER_SIZE];
	uint64_t remaining = size;
	while(remaining) {
		DWORD wanted = (DWORD)(remaining > sizeof(buffer) ?
			sizeof(buffer) : remaining);
		DWORD read_bytes = 0;
		DWORD sent = 0;
		if(!ReadFile(file, buffer, wanted, &read_bytes, NULL) ||
			read_bytes == 0 || read_bytes > wanted) {
			/* The remote channel is waiting for bytes declared in its C record. */
			scpfs_poison_backend(backend, STATUS_DATA_ERROR);
			return STATUS_DATA_ERROR;
		}
		while(sent < read_bytes) {
			ssize_t written = libssh2_channel_write(channel,
				(const char *)buffer + sent, (size_t)(read_bytes - sent));
			if(written <= 0) {
				NTSTATUS status = scpfs_map_libssh2_error((int)written);
				scpfs_poison_backend(backend, status);
				return status;
			}
			sent += (DWORD)written;
		}
		remaining -= read_bytes;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_read_exact_to_file_locked(SCPFS_BACKEND *backend,
	LIBSSH2_CHANNEL *channel, HANDLE file, uint64_t size)
{
	unsigned char buffer[SCPFS_IO_BUFFER_SIZE];
	uint64_t remaining = size;
	while(remaining) {
		size_t wanted = (size_t)(remaining > sizeof(buffer) ?
			sizeof(buffer) : remaining);
		ssize_t received = libssh2_channel_read(channel, (char *)buffer, wanted);
		DWORD offset = 0;
		if(received <= 0 || (size_t)received > wanted) {
			NTSTATUS status = received < 0 ?
				scpfs_map_libssh2_error((int)received) : STATUS_DATA_ERROR;
			scpfs_poison_backend(backend, status);
			return status;
		}
		while(offset < (DWORD)received) {
			DWORD written = 0;
			if(!WriteFile(file, buffer + offset,
				(DWORD)received - offset, &written, NULL) || written == 0) {
				/* Stop consuming the SCP stream; disconnect before reuse. */
				scpfs_poison_backend(backend, STATUS_DISK_FULL);
				return STATUS_DISK_FULL;
			}
			offset += written;
		}
		remaining -= (uint64_t)received;
	}
	return STATUS_SUCCESS;
}

NTSTATUS
scp_backend_download(SCPFS_BACKEND *backend, PCWSTR path,
	PCWSTR local_cache_path, SCPFS_REMOTE_STAT *stat_out)
{
	char *remote = NULL;
	HANDLE local_file = INVALID_HANDLE_VALUE;
	LIBSSH2_CHANNEL *channel = NULL;
	libssh2_struct_stat scp_attributes;
	SCPFS_REMOTE_STAT before;
	SCPFS_REMOTE_STAT after;
	NTSTATUS status;
	bool keep_local = false;
	if(!backend || !path || !local_cache_path || !stat_out)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	local_file = CreateFileW(local_cache_path, GENERIC_WRITE, 0, NULL,
		CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(local_file == INVALID_HANDLE_VALUE) {
		free(remote);
		return GetLastError() == ERROR_FILE_EXISTS ||
			GetLastError() == ERROR_ALREADY_EXISTS ? STATUS_OBJECT_NAME_COLLISION :
			STATUS_ACCESS_DENIED;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_stat_locked(backend, remote, &before);
	if(!NT_SUCCESS(status))
		goto done;
	if(before.type == SCPFS_REMOTE_SYMLINK) {
		status = STATUS_REPARSE_POINT_ENCOUNTERED;
		goto done;
	}
	if(before.type != SCPFS_REMOTE_FILE) {
		status = before.type == SCPFS_REMOTE_DIRECTORY ?
			STATUS_FILE_IS_A_DIRECTORY : STATUS_ACCESS_DENIED;
		goto done;
	}
	if(before.size > (uint64_t)LLONG_MAX) {
		status = STATUS_FILE_TOO_LARGE;
		goto done;
	}
	memset(&scp_attributes, 0, sizeof(scp_attributes));
	channel = libssh2_scp_recv2(backend->session, remote, &scp_attributes);
	if(!channel) {
		status = scpfs_map_libssh2_error(
			libssh2_session_last_errno(backend->session));
		scpfs_poison_backend(backend, status);
		goto done;
	}
	status = scpfs_ignore_extended_data_locked(backend, channel);
	if(!NT_SUCCESS(status))
		goto done;
	if(scp_attributes.st_size < 0 ||
		(uint64_t)scp_attributes.st_size != before.size) {
		status = STATUS_FILE_LOCK_CONFLICT;
		scpfs_poison_backend(backend, status);
		goto done;
	}
	status = scpfs_read_exact_to_file_locked(backend, channel, local_file,
		before.size);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_scp_ack_locked(backend, channel, true);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_finish_scp_channel_locked(backend, channel);
	if(!NT_SUCCESS(status))
		goto done;
	/* SCP reads may update remote atime; restore the exact snapshot value. */
	status = scpfs_set_times_locked(backend, remote, before.atime_ns, 0,
		true, false);
	if(!NT_SUCCESS(status))
		goto done;
	if(!FlushFileBuffers(local_file)) {
		status = STATUS_DISK_FULL;
		goto done;
	}
	status = scpfs_stat_locked(backend, remote, &after);
	if(!NT_SUCCESS(status))
		goto done;
	if(!scpfs_same_snapshot(&before, &after) ||
		after.atime_ns != before.atime_ns) {
		status = STATUS_FILE_LOCK_CONFLICT;
		goto done;
	}
	*stat_out = after;
	keep_local = true;
	status = STATUS_SUCCESS;
done:
	if(channel)
		(void)libssh2_channel_free(channel);
	LeaveCriticalSection(&backend->mutex);
	if(local_file != INVALID_HANDLE_VALUE)
		CloseHandle(local_file);
	if(!keep_local)
		DeleteFileW(local_cache_path);
	free(remote);
	return status;
}

static NTSTATUS
scpfs_make_temp_sibling_locked(SCPFS_BACKEND *backend, const char *path,
	char **temp_out)
{
	char *parent = NULL;
	NTSTATUS status;
	unsigned int attempt;
	*temp_out = NULL;
	status = scpfs_parent_path(backend, path, &parent);
	if(!NT_SUCCESS(status))
		return status;
	for(attempt = 0; attempt < SCPFS_TEMP_ATTEMPTS; attempt++) {
		unsigned char random_bytes[16];
		char hex[sizeof(random_bytes) * 2u + 1u];
		SCPFS_BUFFER candidate = { 0 };
		SCPFS_REMOTE_STAT ignored;
		NTSTATUS random_status = BCryptGenRandom(NULL, random_bytes,
			(ULONG)sizeof(random_bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		size_t index;
		if(!BCRYPT_SUCCESS(random_status)) {
			status = STATUS_UNSUCCESSFUL;
			goto done;
		}
		for(index = 0; index < sizeof(random_bytes); index++) {
			static const char digits[] = "0123456789abcdef";
			hex[index * 2u] = digits[random_bytes[index] >> 4];
			hex[index * 2u + 1u] = digits[random_bytes[index] & 15u];
		}
		hex[sizeof(hex) - 1u] = '\0';
		if(!scpfs_buffer_append_text(&candidate, parent) ||
			(candidate.length && candidate.data[candidate.length - 1u] != '/' &&
				!scpfs_buffer_append_text(&candidate, "/")) ||
			!scpfs_buffer_append_text(&candidate, ".scpfs-tmp-") ||
			!scpfs_buffer_append_text(&candidate, hex) ||
			!scpfs_buffer_reserve(&candidate, 1u)) {
			scpfs_buffer_free(&candidate);
			status = STATUS_NO_MEMORY;
			goto done;
		}
		candidate.data[candidate.length] = '\0';
		status = scpfs_stat_locked(backend, candidate.data, &ignored);
		if(scpfs_is_missing_status(status)) {
			*temp_out = scpfs_buffer_take_string(&candidate);
			scpfs_buffer_free(&candidate);
			status = *temp_out ? STATUS_SUCCESS : STATUS_NO_MEMORY;
			goto done;
		}
		scpfs_buffer_free(&candidate);
		if(!NT_SUCCESS(status))
			goto done;
	}
	status = STATUS_OBJECT_NAME_COLLISION;
done:
	free(parent);
	return status;
}

static NTSTATUS
scpfs_upload_file_locked(SCPFS_BACKEND *backend, const char *remote,
	PCWSTR local_cache_path, uint32_t mode, uint64_t expected_size,
	int64_t atime_ns, int64_t mtime_ns)
{
	HANDLE local_file = INVALID_HANDLE_VALUE;
	LARGE_INTEGER local_size;
	LIBSSH2_CHANNEL *channel = NULL;
	int64_t atime_seconds;
	int64_t mtime_seconds;
	NTSTATUS status;
	local_file = CreateFileW(local_cache_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if(local_file == INVALID_HANDLE_VALUE)
		return STATUS_ACCESS_DENIED;
	if(!GetFileSizeEx(local_file, &local_size) || local_size.QuadPart < 0 ||
		(uint64_t)local_size.QuadPart != expected_size) {
		status = STATUS_FILE_LOCK_CONFLICT;
		goto done;
	}
	(void)scpfs_ns_to_seconds(atime_ns, &atime_seconds);
	(void)scpfs_ns_to_seconds(mtime_ns, &mtime_seconds);
	channel = libssh2_scp_send64(backend->session, remote,
		(int)(mode & 07777u),
		(libssh2_int64_t)expected_size, (libssh2_int64_t)mtime_seconds,
		(libssh2_int64_t)atime_seconds);
	if(!channel) {
		int error = libssh2_session_last_errno(backend->session);
		status = scpfs_map_libssh2_error(error);
		scpfs_poison_backend(backend, status);
		goto done;
	}
	status = scpfs_ignore_extended_data_locked(backend, channel);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_write_all_locked(backend, channel, local_file, expected_size);
	if(!NT_SUCCESS(status)) {
		goto done;
	}
	/* Tell the SCP sink the declared payload is complete, then consume its
	 * mandatory final acknowledgement before considering the upload complete. */
	status = scpfs_scp_ack_locked(backend, channel, true);
	if(!NT_SUCCESS(status)) {
		goto done;
	}
	status = scpfs_scp_ack_locked(backend, channel, false);
	if(!NT_SUCCESS(status)) {
		goto done;
	}
	status = scpfs_finish_scp_channel_locked(backend, channel);
	if(!NT_SUCCESS(status)) {
		goto done;
	}
	status = STATUS_SUCCESS;
done:
	if(channel) {
		if(!NT_SUCCESS(status))
			scpfs_poison_backend(backend, status);
		(void)libssh2_channel_free(channel);
	}
	CloseHandle(local_file);
	return status;
}

NTSTATUS
scp_backend_upload_atomic(SCPFS_BACKEND *backend, PCWSTR path,
	PCWSTR local_cache_path, const SCPFS_REMOTE_STAT *expected_stat,
	SCPFS_REMOTE_STAT *stat_out)
{
	char *remote = NULL;
	char *temp = NULL;
	SCPFS_REMOTE_STAT current;
	SCPFS_REMOTE_STAT temp_stat;
	SCPFS_REMOTE_STAT final_stat;
	SCPFS_BUFFER command = { 0 };
	HANDLE local_file = INVALID_HANDLE_VALUE;
	LARGE_INTEGER local_size;
	FILETIME local_access_time;
	FILETIME local_write_time;
	char *command_output = NULL;
	size_t command_output_length = 0;
	char mode_text[16];
	uint32_t upload_mode;
	uint32_t final_mode = 0;
	int64_t upload_atime_ns;
	int64_t upload_mtime_ns;
	NTSTATUS status;
	bool temp_uploaded = false;
	if(!backend || !path || !local_cache_path || !stat_out)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	if(scpfs_path_is_root(backend, remote)) {
		status = STATUS_ACCESS_DENIED;
		goto done_unlocked;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_validate_parent_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	local_file = CreateFileW(local_cache_path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(local_file == INVALID_HANDLE_VALUE) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if(!GetFileSizeEx(local_file, &local_size) || local_size.QuadPart < 0) {
		status = STATUS_INVALID_PARAMETER;
		goto done;
	}
	status = scpfs_stat_locked(backend, remote, &current);
	if(expected_stat == NULL) {
		if(NT_SUCCESS(status)) {
			status = STATUS_OBJECT_NAME_COLLISION;
			goto done;
		}
		if(!scpfs_is_missing_status(status))
			goto done;
		upload_mode = 0666u;
		if(!GetFileTime(local_file, NULL, &local_access_time,
			&local_write_time) ||
			!scpfs_filetime_to_unix_ns(local_access_time, &upload_atime_ns) ||
			!scpfs_filetime_to_unix_ns(local_write_time, &upload_mtime_ns)) {
			status = STATUS_INVALID_PARAMETER;
			goto done;
		}
	}
	else {
		if(!NT_SUCCESS(status)) {
			if(scpfs_is_missing_status(status))
				status = STATUS_FILE_LOCK_CONFLICT;
			goto done;
		}
		if(current.type == SCPFS_REMOTE_SYMLINK) {
			status = STATUS_REPARSE_POINT_ENCOUNTERED;
			goto done;
		}
		if(current.type != SCPFS_REMOTE_FILE ||
			!scpfs_same_snapshot(&current, expected_stat)) {
			status = STATUS_FILE_LOCK_CONFLICT;
			goto done;
		}
		upload_mode = expected_stat->mode;
		upload_atime_ns = expected_stat->atime_ns;
		upload_mtime_ns = expected_stat->mtime_ns;
	}
	CloseHandle(local_file);
	local_file = INVALID_HANDLE_VALUE;
	status = scpfs_make_temp_sibling_locked(backend, remote, &temp);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_upload_file_locked(backend, temp, local_cache_path,
		upload_mode, (uint64_t)local_size.QuadPart,
		upload_atime_ns, upload_mtime_ns);
	if(!NT_SUCCESS(status)) {
		goto done;
	}
	temp_uploaded = true;
	status = scpfs_set_times_locked(backend, temp, upload_atime_ns,
		upload_mtime_ns, true, true);
	if(!NT_SUCCESS(status))
		goto done;
	/* Preserve an existing file's exact mode. New files retain the SCP sink's
	 * umask-filtered mode, matching ordinary remote creation semantics. */
	if(expected_stat) {
		(void)snprintf(mode_text, sizeof(mode_text), "%04o",
			upload_mode & 07777u);
		if(!scpfs_buffer_append_text(&command, "chmod ") ||
			!scpfs_buffer_append_text(&command, mode_text) ||
			!scpfs_buffer_append_text(&command, " -- ") ||
			!scpfs_append_shell_word(&command, temp)) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		status = scpfs_finish_command(&command);
		if(NT_SUCCESS(status))
			status = scpfs_run_command_locked(backend, command.data,
				SCPFS_MAX_STAT_OUTPUT, &command_output, &command_output_length);
		free(command_output);
		command_output = NULL;
		command_output_length = 0;
		if(!NT_SUCCESS(status))
			goto done;
		scpfs_buffer_free(&command);
	}
	status = scpfs_stat_locked(backend, temp, &temp_stat);
	if(!NT_SUCCESS(status)) {
		goto done;
	}
	if(temp_stat.type != SCPFS_REMOTE_FILE ||
		temp_stat.size != (uint64_t)local_size.QuadPart ||
		(expected_stat && temp_stat.mode != (upload_mode & 07777u)) ||
		(!expected_stat &&
			(temp_stat.mode & ~(upload_mode & 07777u)) != 0) ||
		temp_stat.atime_ns != upload_atime_ns ||
		temp_stat.mtime_ns != upload_mtime_ns) {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	final_mode = temp_stat.mode;
	/* The fingerprint check is deliberately after the full SCP acknowledgement.
	 * It is best-effort conflict detection, not a server-side compare-and-swap. */
	status = scpfs_validate_parent_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_stat_locked(backend, remote, &current);
	if(expected_stat == NULL) {
		if(NT_SUCCESS(status)) {
			status = STATUS_FILE_LOCK_CONFLICT;
			goto done;
		}
		if(!scpfs_is_missing_status(status))
			goto done;
	}
	else if(!NT_SUCCESS(status) ||
		!scpfs_same_snapshot(&current, expected_stat)) {
		status = STATUS_FILE_LOCK_CONFLICT;
		goto done;
	}
	if(!scpfs_buffer_append_text(&command,
		expected_stat ? "mv -T -- " : "mv -T -n -- ") ||
		!scpfs_append_shell_word(&command, temp) ||
		!scpfs_buffer_append_text(&command, " ") ||
		!scpfs_append_shell_word(&command, remote)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	status = scpfs_finish_command(&command);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_run_command_locked(backend, command.data,
		SCPFS_MAX_STAT_OUTPUT, &command_output, &command_output_length);
	free(command_output);
	command_output = NULL;
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_stat_locked(backend, temp, &temp_stat);
	if(NT_SUCCESS(status)) {
		status = STATUS_FILE_LOCK_CONFLICT;
		goto done;
	}
	if(!scpfs_is_missing_status(status))
		goto done;
	status = scpfs_stat_locked(backend, remote, &final_stat);
	if(!NT_SUCCESS(status))
		goto done;
	if(final_stat.type != SCPFS_REMOTE_FILE ||
		final_stat.size != (uint64_t)local_size.QuadPart ||
		final_stat.mode != final_mode ||
		final_stat.atime_ns != upload_atime_ns ||
		final_stat.mtime_ns != upload_mtime_ns) {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	*stat_out = final_stat;
	status = STATUS_SUCCESS;
done:
	if(local_file != INVALID_HANDLE_VALUE)
		CloseHandle(local_file);
	if(!NT_SUCCESS(status) && temp_uploaded && temp && !backend->broken) {
		SCPFS_BUFFER cleanup = { 0 };
		char *output = NULL;
		size_t output_length = 0;
		if(scpfs_buffer_append_text(&cleanup, "rm -f -- ") &&
			scpfs_append_shell_word(&cleanup, temp) &&
			NT_SUCCESS(scpfs_finish_command(&cleanup))) {
			(void)scpfs_run_command_locked(backend, cleanup.data,
				SCPFS_MAX_STAT_OUTPUT, &output, &output_length);
		}
		free(output);
		scpfs_buffer_free(&cleanup);
	}
	LeaveCriticalSection(&backend->mutex);
done_unlocked:
	free(remote);
	free(temp);
	scpfs_buffer_free(&command);
	return status;
}

static NTSTATUS
scpfs_run_built_command_locked(SCPFS_BACKEND *backend, SCPFS_BUFFER *command,
	size_t max_output)
{
	char *output = NULL;
	size_t output_length = 0;
	NTSTATUS status = scpfs_finish_command(command);
	if(NT_SUCCESS(status))
		status = scpfs_run_command_locked(backend, command->data,
			max_output, &output, &output_length);
	free(output);
	return status;
}

static NTSTATUS
scpfs_require_missing_locked(SCPFS_BACKEND *backend, const char *path)
{
	SCPFS_REMOTE_STAT stat;
	NTSTATUS status = scpfs_stat_locked(backend, path, &stat);
	if(NT_SUCCESS(status))
		return STATUS_OBJECT_NAME_COLLISION;
	if(scpfs_is_missing_status(status))
		return STATUS_SUCCESS;
	return status;
}

NTSTATUS
scp_backend_create(SCPFS_BACKEND *backend, PCWSTR path, uint32_t mode)
{
	char *remote = NULL;
	SCPFS_BUFFER command = { 0 };
	char mode_text[16];
	NTSTATUS status;
	if(!backend || !path)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	if(scpfs_path_is_root(backend, remote)) {
		status = STATUS_ACCESS_DENIED;
		goto done_unlocked;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_validate_parent_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_require_missing_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	(void)snprintf(mode_text, sizeof(mode_text), "%04o", mode & 07777u);
	/* noclobber gives the shell an exclusive create; the quoted path remains a
	 * single redirection operand even when it contains whitespace or metacharacters. */
	if(!scpfs_buffer_append_text(&command,
		"umask 077; set -C; : > ") ||
		!scpfs_append_shell_word(&command, remote) ||
		!scpfs_buffer_append_text(&command, " && chmod ") ||
		!scpfs_buffer_append_text(&command, mode_text) ||
		!scpfs_buffer_append_text(&command, " -- ") ||
		!scpfs_append_shell_word(&command, remote)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	status = scpfs_run_built_command_locked(backend, &command,
		SCPFS_MAX_STAT_OUTPUT);
done:
	LeaveCriticalSection(&backend->mutex);
done_unlocked:
	free(remote);
	scpfs_buffer_free(&command);
	return status;
}

NTSTATUS
scp_backend_mkdir(SCPFS_BACKEND *backend, PCWSTR path, uint32_t mode)
{
	char *remote = NULL;
	SCPFS_BUFFER command = { 0 };
	char mode_text[16];
	NTSTATUS status;
	if(!backend || !path)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	if(scpfs_path_is_root(backend, remote)) {
		status = STATUS_OBJECT_NAME_COLLISION;
		goto done_unlocked;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_validate_parent_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_require_missing_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	(void)snprintf(mode_text, sizeof(mode_text), "%04o", mode & 07777u);
	if(!scpfs_buffer_append_text(&command, "umask 000; mkdir -- ") ||
		!scpfs_append_shell_word(&command, remote) ||
		!scpfs_buffer_append_text(&command, " && chmod ") ||
		!scpfs_buffer_append_text(&command, mode_text) ||
		!scpfs_buffer_append_text(&command, " -- ") ||
		!scpfs_append_shell_word(&command, remote)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	status = scpfs_run_built_command_locked(backend, &command,
		SCPFS_MAX_STAT_OUTPUT);
done:
	LeaveCriticalSection(&backend->mutex);
done_unlocked:
	free(remote);
	scpfs_buffer_free(&command);
	return status;
}

NTSTATUS
scp_backend_remove(SCPFS_BACKEND *backend, PCWSTR path, bool is_directory)
{
	char *remote = NULL;
	SCPFS_BUFFER command = { 0 };
	SCPFS_REMOTE_STAT stat;
	NTSTATUS status;
	if(!backend || !path)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	if(scpfs_path_is_root(backend, remote)) {
		status = STATUS_ACCESS_DENIED;
		goto done_unlocked;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_validate_parent_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_stat_locked(backend, remote, &stat);
	if(!NT_SUCCESS(status))
		goto done;
	if(stat.type == SCPFS_REMOTE_SYMLINK) {
		status = STATUS_REPARSE_POINT_ENCOUNTERED;
		goto done;
	}
	if(stat.type == SCPFS_REMOTE_OTHER) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if(is_directory && stat.type != SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_NOT_A_DIRECTORY;
		goto done;
	}
	if(!is_directory && stat.type == SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_FILE_IS_A_DIRECTORY;
		goto done;
	}
	if(!scpfs_buffer_append_text(&command,
		is_directory ? "rmdir -- " : "rm -- ") ||
		!scpfs_append_shell_word(&command, remote)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	status = scpfs_run_built_command_locked(backend, &command,
		SCPFS_MAX_STAT_OUTPUT);
done:
	LeaveCriticalSection(&backend->mutex);
done_unlocked:
	free(remote);
	scpfs_buffer_free(&command);
	return status;
}

NTSTATUS
scp_backend_rename(SCPFS_BACKEND *backend, PCWSTR old_path, PCWSTR new_path,
	bool replace_existing)
{
	char *old_remote = NULL;
	char *new_remote = NULL;
	SCPFS_BUFFER command = { 0 };
	SCPFS_REMOTE_STAT source_stat;
	SCPFS_REMOTE_STAT destination_stat;
	NTSTATUS status;
	if(!backend || !old_path || !new_path)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, old_path, &old_remote);
	if(!NT_SUCCESS(status))
		goto done_unlocked;
	status = scpfs_path_to_remote(backend, new_path, &new_remote);
	if(!NT_SUCCESS(status))
		goto done_unlocked;
	if(scpfs_path_is_root(backend, old_remote) ||
		scpfs_path_is_root(backend, new_remote)) {
		status = STATUS_ACCESS_DENIED;
		goto done_unlocked;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_validate_parent_locked(backend, old_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_validate_parent_locked(backend, new_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_stat_locked(backend, old_remote, &source_stat);
	if(!NT_SUCCESS(status))
		goto done;
	if(source_stat.type == SCPFS_REMOTE_SYMLINK) {
		status = STATUS_REPARSE_POINT_ENCOUNTERED;
		goto done;
	}
	if(source_stat.type == SCPFS_REMOTE_OTHER) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if(strcmp(old_remote, new_remote) == 0) {
		status = STATUS_SUCCESS;
		goto done;
	}
	status = scpfs_stat_locked(backend, new_remote, &destination_stat);
	if(NT_SUCCESS(status)) {
		if(destination_stat.type == SCPFS_REMOTE_SYMLINK) {
			status = STATUS_REPARSE_POINT_ENCOUNTERED;
			goto done;
		}
		if(destination_stat.type == SCPFS_REMOTE_OTHER) {
			status = STATUS_ACCESS_DENIED;
			goto done;
		}
		if(!replace_existing) {
			status = STATUS_OBJECT_NAME_COLLISION;
			goto done;
		}
	}
	else if(!scpfs_is_missing_status(status)) {
		goto done;
	}
	if(!scpfs_buffer_append_text(&command,
		replace_existing ? "mv -T -- " : "mv -T -n -- ") ||
		!scpfs_append_shell_word(&command, old_remote) ||
		!scpfs_buffer_append_text(&command, " ") ||
		!scpfs_append_shell_word(&command, new_remote)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	status = scpfs_run_built_command_locked(backend, &command,
		SCPFS_MAX_STAT_OUTPUT);
	if(!NT_SUCCESS(status))
		goto done;
	if(!replace_existing) {
		status = scpfs_stat_locked(backend, old_remote, &source_stat);
		if(NT_SUCCESS(status))
			status = STATUS_OBJECT_NAME_COLLISION;
		else if(scpfs_is_missing_status(status))
			status = STATUS_SUCCESS;
	}
done:
	LeaveCriticalSection(&backend->mutex);
done_unlocked:
	free(old_remote);
	free(new_remote);
	scpfs_buffer_free(&command);
	return status;
}

NTSTATUS
scp_backend_setmeta(SCPFS_BACKEND *backend, PCWSTR path, uint32_t mode,
	int64_t atime_ns, int64_t mtime_ns, bool set_mode, bool set_atime,
	bool set_mtime)
{
	char *remote = NULL;
	SCPFS_BUFFER command = { 0 };
	SCPFS_REMOTE_STAT current;
	char mode_text[16];
	NTSTATUS status;
	if(!backend || !path)
		return STATUS_INVALID_PARAMETER;
	if(!set_mode && !set_atime && !set_mtime)
		return STATUS_SUCCESS;
	status = scpfs_path_to_remote(backend, path, &remote);
	if(!NT_SUCCESS(status))
		return status;
	if(scpfs_path_is_root(backend, remote)) {
		status = STATUS_ACCESS_DENIED;
		goto done_unlocked;
	}
	EnterCriticalSection(&backend->mutex);
	status = scpfs_validate_parent_locked(backend, remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_stat_locked(backend, remote, &current);
	if(!NT_SUCCESS(status))
		goto done;
	if(current.type == SCPFS_REMOTE_SYMLINK) {
		status = STATUS_REPARSE_POINT_ENCOUNTERED;
		goto done;
	}
	if(current.type != SCPFS_REMOTE_FILE &&
		current.type != SCPFS_REMOTE_DIRECTORY) {
		status = STATUS_ACCESS_DENIED;
		goto done;
	}
	if(set_mode) {
		(void)snprintf(mode_text, sizeof(mode_text), "%04o", mode & 07777u);
		if(!scpfs_buffer_append_text(&command, "chmod ") ||
			!scpfs_buffer_append_text(&command, mode_text) ||
			!scpfs_buffer_append_text(&command, " -- ") ||
			!scpfs_append_shell_word(&command, remote)) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		status = scpfs_run_built_command_locked(backend, &command,
			SCPFS_MAX_STAT_OUTPUT);
		if(!NT_SUCCESS(status))
			goto done;
		scpfs_buffer_free(&command);
	}
	status = scpfs_set_times_locked(backend, remote, atime_ns, mtime_ns,
		set_atime, set_mtime);
done:
	LeaveCriticalSection(&backend->mutex);
done_unlocked:
	free(remote);
	scpfs_buffer_free(&command);
	return status;
}

static NTSTATUS
scpfs_make_inbox_sibling_locked(SCPFS_BACKEND *backend, const char *path,
	const char *suffix, char **candidate_out)
{
	char *parent = NULL;
	unsigned int attempt;
	NTSTATUS status;
	*candidate_out = NULL;
	status = scpfs_parent_path(backend, path, &parent);
	if(!NT_SUCCESS(status))
		return status;
	for(attempt = 0; attempt < SCPFS_TEMP_ATTEMPTS; attempt++) {
		unsigned char random_bytes[16];
		char hex[sizeof(random_bytes) * 2u + 1u];
		SCPFS_BUFFER candidate = { 0 };
		SCPFS_REMOTE_STAT ignored;
		size_t index;
		if(!BCRYPT_SUCCESS(BCryptGenRandom(NULL, random_bytes,
			(ULONG)sizeof(random_bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			status = STATUS_UNSUCCESSFUL;
			goto done;
		}
		for(index = 0; index < sizeof(random_bytes); index++) {
			static const char digits[] = "0123456789abcdef";
			hex[index * 2u] = digits[random_bytes[index] >> 4];
			hex[index * 2u + 1u] = digits[random_bytes[index] & 15u];
		}
		hex[sizeof(hex) - 1u] = '\0';
		if(!scpfs_buffer_append_text(&candidate, parent) ||
			(candidate.length && candidate.data[candidate.length - 1u] != '/' &&
				!scpfs_buffer_append_text(&candidate, "/")) ||
			!scpfs_buffer_append_text(&candidate, ".scpfs-inbox-") ||
			!scpfs_buffer_append_text(&candidate, hex) ||
			!scpfs_buffer_append_text(&candidate, suffix) ||
			!scpfs_buffer_reserve(&candidate, 1u)) {
			scpfs_buffer_free(&candidate);
			status = STATUS_NO_MEMORY;
			goto done;
		}
		candidate.data[candidate.length] = '\0';
		status = scpfs_stat_locked(backend, candidate.data, &ignored);
		if(scpfs_is_missing_status(status)) {
			*candidate_out = scpfs_buffer_take_string(&candidate);
			scpfs_buffer_free(&candidate);
			status = *candidate_out ? STATUS_SUCCESS : STATUS_NO_MEMORY;
			goto done;
		}
		scpfs_buffer_free(&candidate);
		if(!NT_SUCCESS(status))
			goto done;
	}
	status = STATUS_OBJECT_NAME_COLLISION;
done:
	free(parent);
	return status;
}

static NTSTATUS
scpfs_inbox_output_path_locked(SCPFS_BACKEND *backend, const char *input,
	char **output_out)
{
	char *parent = NULL;
	SCPFS_BUFFER output = { 0 };
	NTSTATUS status = scpfs_parent_path(backend, input, &parent);
	if(!NT_SUCCESS(status))
		return status;
	if(!scpfs_buffer_append_text(&output, parent) ||
		(output.length && output.data[output.length - 1u] != '/' &&
			!scpfs_buffer_append_text(&output, "/")) ||
		!scpfs_buffer_append_text(&output, ".out.txt") ||
		!scpfs_buffer_reserve(&output, 1u)) {
		status = STATUS_NO_MEMORY;
		goto done;
	}
	output.data[output.length] = '\0';
	*output_out = scpfs_buffer_take_string(&output);
	status = *output_out ? STATUS_SUCCESS : STATUS_NO_MEMORY;
done:
	free(parent);
	scpfs_buffer_free(&output);
	return status;
}

static NTSTATUS
scpfs_remote_path_to_mount_path(SCPFS_BACKEND *backend, const char *remote,
	WCHAR **mount_path_out)
{
	size_t root_length;
	const char *relative;
	WCHAR *wide = NULL;
	WCHAR *mount_path = NULL;
	size_t wide_length = 0;
	size_t index;
	NTSTATUS status;
	*mount_path_out = NULL;
	if(!scpfs_path_is_below_root(backend, remote))
		return STATUS_ACCESS_DENIED;
	root_length = strlen(backend->remote_root);
	relative = remote + root_length;
	while(*relative == '/')
		relative++;
	status = scpfs_utf8_to_wide_n(relative, strlen(relative), &wide,
		&wide_length);
	if(!NT_SUCCESS(status))
		return status;
	if(wide_length > (SIZE_MAX / sizeof(WCHAR)) - 2u) {
		free(wide);
		return STATUS_NAME_TOO_LONG;
	}
	mount_path = (WCHAR *)malloc((wide_length + 2u) * sizeof(WCHAR));
	if(!mount_path) {
		free(wide);
		return STATUS_NO_MEMORY;
	}
	mount_path[0] = L'\\';
	for(index = 0; index < wide_length; index++)
		mount_path[index + 1u] = wide[index] == L'/' ? L'\\' : wide[index];
	mount_path[wide_length + 1u] = L'\0';
	free(wide);
	*mount_path_out = mount_path;
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_create_local_inbox_temp(WCHAR **path_out)
{
	WCHAR directory[32768];
	DWORD directory_length;
	unsigned int attempt;
	static const WCHAR prefix[] = L"scpfs-inbox-";
	static const WCHAR suffix[] = L".tmp";
	*path_out = NULL;
	directory_length = GetTempPathW((DWORD)_countof(directory), directory);
	if(directory_length == 0 || directory_length >= _countof(directory))
		return STATUS_ACCESS_DENIED;
	for(attempt = 0; attempt < SCPFS_TEMP_ATTEMPTS; attempt++) {
		unsigned char random_bytes[16];
		WCHAR hex_wide[sizeof(random_bytes) * 2u + 1u];
		bool append_separator = directory[directory_length - 1u] != L'\\' &&
			directory[directory_length - 1u] != L'/';
		size_t base_length = directory_length + (append_separator ? 1u : 0u);
		size_t hex_length = sizeof(hex_wide) / sizeof(hex_wide[0]) - 1u;
		size_t total_length = base_length + (sizeof(prefix) / sizeof(prefix[0]) - 1u) +
			hex_length + (sizeof(suffix) / sizeof(suffix[0]) - 1u);
		WCHAR *path;
		size_t index;
		size_t cursor;
		HANDLE file;
		DWORD error;
		if(!BCRYPT_SUCCESS(BCryptGenRandom(NULL, random_bytes,
			(ULONG)sizeof(random_bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
			return STATUS_UNSUCCESSFUL;
		for(index = 0; index < sizeof(random_bytes); index++) {
			static const WCHAR digits[] = L"0123456789abcdef";
			hex_wide[index * 2u] = digits[random_bytes[index] >> 4];
			hex_wide[index * 2u + 1u] = digits[random_bytes[index] & 15u];
		}
		hex_wide[hex_length] = L'\0';
		path = (WCHAR *)malloc((total_length + 1u) * sizeof(WCHAR));
		if(!path)
			return STATUS_NO_MEMORY;
		memcpy(path, directory, directory_length * sizeof(WCHAR));
		if(append_separator)
			path[directory_length] = L'\\';
		cursor = base_length;
		memcpy(path + cursor, prefix, (sizeof(prefix) / sizeof(prefix[0]) - 1u) * sizeof(WCHAR));
		cursor += sizeof(prefix) / sizeof(prefix[0]) - 1u;
		memcpy(path + cursor, hex_wide, hex_length * sizeof(WCHAR));
		cursor += hex_length;
		memcpy(path + cursor, suffix, (sizeof(suffix) / sizeof(suffix[0]) - 1u) * sizeof(WCHAR));
		path[total_length] = L'\0';
		file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
			CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, NULL);
		if(file == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			free(path);
			if(error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
				continue;
			return STATUS_ACCESS_DENIED;
		}
		CloseHandle(file);
		if(!DeleteFileW(path)) {
			free(path);
			return STATUS_ACCESS_DENIED;
		}
		*path_out = path;
		return STATUS_SUCCESS;
	}
	return STATUS_OBJECT_NAME_COLLISION;
}

static NTSTATUS
scpfs_write_local_inbox_bytes(PCWSTR path, const unsigned char *data,
	size_t length)
{
	HANDLE file;
	size_t offset = 0;
	NTSTATUS status = STATUS_SUCCESS;
	file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
	if(file == INVALID_HANDLE_VALUE)
		return STATUS_ACCESS_DENIED;
	while(offset < length) {
		DWORD wanted = (DWORD)((length - offset) > UINT32_MAX ? UINT32_MAX :
			(length - offset));
		DWORD written = 0;
		if(!WriteFile(file, data + offset, wanted, &written, NULL) ||
			written == 0) {
			status = STATUS_DISK_FULL;
			break;
		}
		offset += written;
	}
	if(NT_SUCCESS(status) && !FlushFileBuffers(file))
		status = STATUS_DISK_FULL;
	CloseHandle(file);
	return status;
}

static const char *
scpfs_validate_normalize_inbox_script(const unsigned char *input,
	size_t input_length, unsigned char **normalized_out,
	size_t *normalized_length_out)
{
	size_t start = 0;
	size_t index;
	size_t output_length = 0;
	unsigned char *normalized;
	*normalized_out = NULL;
	*normalized_length_out = 0;
	if(input_length > SCPFS_INBOX_MAX_INPUT_BYTES)
		return "SCPFS inbox rejected: input exceeds 1048576 bytes; command was not executed.\n";
	if(input_length >= 3u && input[0] == 0xefu && input[1] == 0xbbu &&
		input[2] == 0xbfu)
		start = 3u;
	for(index = start; index < input_length; index++) {
		if(input[index] == 0)
			return "SCPFS inbox rejected: NUL bytes are not allowed; command was not executed.\n";
	}
	if(input_length > start &&
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
			(const char *)input + start, (int)(input_length - start), NULL, 0) == 0)
		return "SCPFS inbox rejected: input is not valid UTF-8; command was not executed.\n";
	normalized = (unsigned char *)malloc(input_length - start + 1u);
	if(!normalized)
		return NULL;
	for(index = start; index < input_length; index++) {
		if(input[index] == '\r') {
			if(index + 1u >= input_length || input[index + 1u] != '\n') {
				free(normalized);
				return "SCPFS inbox rejected: bare CR line endings are not allowed; command was not executed.\n";
			}
			normalized[output_length++] = '\n';
			index++;
		}
		else {
			normalized[output_length++] = input[index];
		}
	}
	normalized[output_length] = 0;
	*normalized_out = normalized;
	*normalized_length_out = output_length;
	return "";
}

static NTSTATUS
scpfs_validate_inbox_output_locked(SCPFS_BACKEND *backend,
	const char *output_path)
{
	SCPFS_REMOTE_STAT output_stat;
	NTSTATUS status = scpfs_validate_parent_locked(backend, output_path);
	if(!NT_SUCCESS(status))
		return status;
	status = scpfs_stat_locked(backend, output_path, &output_stat);
	if(scpfs_is_missing_status(status))
		return STATUS_SUCCESS;
	if(!NT_SUCCESS(status))
		return status;
	if(output_stat.type == SCPFS_REMOTE_SYMLINK)
		return STATUS_REPARSE_POINT_ENCOUNTERED;
	if(output_stat.type == SCPFS_REMOTE_DIRECTORY)
		return STATUS_FILE_IS_A_DIRECTORY;
	if(output_stat.type != SCPFS_REMOTE_FILE)
		return STATUS_ACCESS_DENIED;
	return STATUS_SUCCESS;
}

static bool
scpfs_parse_inbox_exit_code(const char *text, size_t length, int *exit_code_out)
{
	unsigned int value = 0;
	size_t index;
	if(length == 0 || length > 3u)
		return false;
	for(index = 0; index < length; index++) {
		if(text[index] < '0' || text[index] > '9')
			return false;
		value = value * 10u + (unsigned int)(text[index] - '0');
	}
	if(value > 255u)
		return false;
	*exit_code_out = (int)value;
	return true;
}

static NTSTATUS
scpfs_set_inbox_execution_timeout_locked(SCPFS_BACKEND *backend,
	uint32_t timeout_ms, DWORD *old_receive_timeout,
	DWORD *old_send_timeout)
{
	int option_length;
	uint64_t expanded = (uint64_t)timeout_ms + SCPFS_INBOX_TIMEOUT_GRACE_MS;
	DWORD new_timeout;
	if(timeout_ms == 0 || timeout_ms > 540000u)
		return STATUS_INVALID_PARAMETER;
	if(expanded > (uint64_t)LONG_MAX)
		return STATUS_INVALID_PARAMETER;
	option_length = sizeof(*old_receive_timeout);
	if(getsockopt(backend->socket, SOL_SOCKET, SO_RCVTIMEO,
		(char *)old_receive_timeout, &option_length) != 0)
		return STATUS_UNSUCCESSFUL;
	option_length = sizeof(*old_send_timeout);
	if(getsockopt(backend->socket, SOL_SOCKET, SO_SNDTIMEO,
		(char *)old_send_timeout, &option_length) != 0)
		return STATUS_UNSUCCESSFUL;
	new_timeout = (DWORD)expanded;
	if(setsockopt(backend->socket, SOL_SOCKET, SO_RCVTIMEO,
		(const char *)&new_timeout, sizeof(new_timeout)) != 0)
		return STATUS_UNSUCCESSFUL;
	if(setsockopt(backend->socket, SOL_SOCKET, SO_SNDTIMEO,
		(const char *)&new_timeout, sizeof(new_timeout)) != 0) {
		(void)setsockopt(backend->socket, SOL_SOCKET, SO_RCVTIMEO,
			(const char *)old_receive_timeout, sizeof(*old_receive_timeout));
		return STATUS_UNSUCCESSFUL;
	}
	libssh2_session_set_timeout(backend->session, (long)new_timeout);
	return STATUS_SUCCESS;
}

static void
scpfs_restore_execution_timeout_locked(SCPFS_BACKEND *backend,
	DWORD old_receive_timeout, DWORD old_send_timeout)
{
	(void)setsockopt(backend->socket, SOL_SOCKET, SO_RCVTIMEO,
		(const char *)&old_receive_timeout, sizeof(old_receive_timeout));
	(void)setsockopt(backend->socket, SOL_SOCKET, SO_SNDTIMEO,
		(const char *)&old_send_timeout, sizeof(old_send_timeout));
	libssh2_session_set_timeout(backend->session, (long)backend->timeout_ms);
}

static NTSTATUS
scpfs_build_inbox_execution_command(const char *cwd, const char *script,
	const char *spool, const char *status_path, uint32_t timeout_ms,
	SCPFS_BUFFER *command)
{
	char timeout_text[64];
	(void)snprintf(timeout_text, sizeof(timeout_text), "%u.%03us",
		(unsigned int)(timeout_ms / 1000u),
		(unsigned int)(timeout_ms % 1000u));
	if(!scpfs_buffer_append_text(command, "cd ") ||
		!scpfs_append_shell_word(command, cwd) ||
		!scpfs_buffer_append_text(command,
			" || exit 125; set -C; { timeout --signal=TERM --kill-after=2s ") ||
		!scpfs_buffer_append_text(command, timeout_text) ||
		!scpfs_buffer_append_text(command, " /bin/sh -- ") ||
		!scpfs_append_shell_word(command, script) ||
		!scpfs_buffer_append_text(command,
			"; scpfs_exec_status=$?; printf '%d' \"$scpfs_exec_status\" > ") ||
		!scpfs_append_shell_word(command, status_path) ||
		!scpfs_buffer_append_text(command,
			"; } 2>&1 | { set -C; head -c 8388609 > ") ||
		!scpfs_append_shell_word(command, spool) ||
		!scpfs_buffer_append_text(command,
			"; scpfs_head_status=$?; cat >/dev/null; exit \"$scpfs_head_status\"; }; scpfs_capture_status=$?; if [ \"$scpfs_capture_status\" -ne 0 ]; then exit \"$scpfs_capture_status\"; fi; cat -- ") ||
		!scpfs_append_shell_word(command, status_path))
		return STATUS_NO_MEMORY;
	return scpfs_finish_command(command);
}

static NTSTATUS
scpfs_copy_inbox_claim_path(SCPFS_INBOX_RESULT *result, const char *claim)
{
	WCHAR *wide = NULL;
	size_t wide_length = 0;
	NTSTATUS status = scpfs_utf8_to_wide_n(claim, strlen(claim), &wide,
		&wide_length);
	(void)wide_length;
	if(!NT_SUCCESS(status))
		return status;
	free(result->claim_path);
	result->claim_path = wide;
	return STATUS_SUCCESS;
}

static NTSTATUS
scpfs_build_inbox_move_command(const char *source, const char *destination,
	SCPFS_BUFFER *command)
{
	if(!scpfs_buffer_append_text(command, "mv -T -n -- ") ||
		!scpfs_append_shell_word(command, source) ||
		!scpfs_buffer_append_text(command, " ") ||
		!scpfs_append_shell_word(command, destination))
		return STATUS_NO_MEMORY;
	return scpfs_finish_command(command);
}

static NTSTATUS
scpfs_build_inbox_publish_command(const char *source, const char *destination,
	SCPFS_BUFFER *command)
{
	if(!scpfs_buffer_append_text(command, "mv -T -f -- ") ||
		!scpfs_append_shell_word(command, source) ||
		!scpfs_buffer_append_text(command, " ") ||
		!scpfs_append_shell_word(command, destination))
		return STATUS_NO_MEMORY;
	return scpfs_finish_command(command);
}

static NTSTATUS
scpfs_build_inbox_cleanup_command(const char *claim, const char *script,
	const char *spool, const char *status_path, SCPFS_BUFFER *command)
{
	if(!scpfs_buffer_append_text(command, "rm -f -- ") ||
		!scpfs_append_shell_word(command, claim) ||
		!scpfs_buffer_append_text(command, " ") ||
		!scpfs_append_shell_word(command, script) ||
		!scpfs_buffer_append_text(command, " ") ||
		!scpfs_append_shell_word(command, spool) ||
		!scpfs_buffer_append_text(command, " ") ||
		!scpfs_append_shell_word(command, status_path))
		return STATUS_NO_MEMORY;
	return scpfs_finish_command(command);
}

static NTSTATUS
scpfs_build_inbox_truncate_command(const char *spool, SCPFS_BUFFER *command)
{
	if(!scpfs_buffer_append_text(command, "truncate -s 8388608 -- ") ||
		!scpfs_append_shell_word(command, spool) ||
		!scpfs_buffer_append_text(command,
			" && printf '\\n[SCPFS: output truncated after 8388608 bytes]\\n' >> ") ||
		!scpfs_append_shell_word(command, spool))
		return STATUS_NO_MEMORY;
	return scpfs_finish_command(command);
}

static NTSTATUS
scpfs_build_inbox_chmod_command(const char *path, SCPFS_BUFFER *command)
{
	if(!scpfs_buffer_append_text(command, "chmod 0600 -- ") ||
		!scpfs_append_shell_word(command, path))
		return STATUS_NO_MEMORY;
	return scpfs_finish_command(command);
}

static bool
scpfs_inbox_claim_matches(const SCPFS_REMOTE_STAT *input_stat,
	const SCPFS_REMOTE_STAT *claim_stat)
{
	return claim_stat->type == SCPFS_REMOTE_FILE &&
		scpfs_same_snapshot(input_stat, claim_stat);
}

NTSTATUS
scp_backend_execute_inbox(SCPFS_BACKEND *backend, PCWSTR exact_path,
	uint32_t timeout_ms, SCPFS_INBOX_RESULT *result_out)
{
	static const char too_large_message[] =
		"SCPFS inbox rejected: input exceeds 1048576 bytes; command was not executed.\n";
	static const char truncation_marker[] =
		"\n[SCPFS: output truncated after 8388608 bytes]\n";
	char *input_remote = NULL;
	char *output_remote = NULL;
	char *parent_remote = NULL;
	char *claim_remote = NULL;
	char *script_remote = NULL;
	char *spool_remote = NULL;
	char *status_remote = NULL;
	WCHAR *claim_mount_path = NULL;
	WCHAR *script_mount_path = NULL;
	WCHAR *spool_mount_path = NULL;
	WCHAR *local_temp_path = NULL;
	unsigned char *input_bytes = NULL;
	unsigned char *normalized_script = NULL;
	size_t input_length = 0;
	size_t normalized_length = 0;
	const char *rejection = NULL;
	SCPFS_REMOTE_STAT input_stat;
	SCPFS_REMOTE_STAT source_after_claim;
	SCPFS_REMOTE_STAT claim_stat;
	SCPFS_REMOTE_STAT downloaded_stat;
	SCPFS_REMOTE_STAT spool_stat;
	SCPFS_REMOTE_STAT published_stat;
	SCPFS_REMOTE_STAT ignored_stat;
	SCPFS_BUFFER command = { 0 };
	char *command_output = NULL;
	size_t command_output_length = 0;
	int command_exit = -1;
	int script_exit = -1;
	uint32_t effective_timeout = timeout_ms ? timeout_ms :
		SCPFS_INBOX_DEFAULT_TIMEOUT_MS;
	DWORD old_receive_timeout = 0;
	DWORD old_send_timeout = 0;
	NTSTATUS status = STATUS_SUCCESS;
	NTSTATUS claim_command_status;
	bool lock_held = false;
	bool claim_attempted = false;
	bool claimed = false;
	bool execution_completed = false;
	bool output_uploaded = false;
	bool retain_claim = false;
	bool local_temp_created = false;
	size_t truncation_marker_length = sizeof(truncation_marker) - 1u;
	const char *basename;
	PCWSTR failure_stage = L"validate command path";

	if(!backend || !exact_path || !result_out)
		return STATUS_INVALID_PARAMETER;
	memset(result_out, 0, sizeof(*result_out));
	result_out->exit_code = -1;
	if(effective_timeout > 540000u)
		return STATUS_INVALID_PARAMETER;
	status = scpfs_path_to_remote(backend, exact_path, &input_remote);
	if(!NT_SUCCESS(status))
		goto done_unlocked;
	basename = strrchr(input_remote, '/');
	basename = basename ? basename + 1u : input_remote;
	if(strcmp(basename, ".in.txt") != 0 ||
		scpfs_path_is_root(backend, input_remote)) {
		status = STATUS_INVALID_PARAMETER;
		goto done_unlocked;
	}
	status = scpfs_create_local_inbox_temp(&local_temp_path);
	if(!NT_SUCCESS(status))
		goto done_unlocked;
	local_temp_created = true;
	EnterCriticalSection(&backend->mutex);
	lock_held = true;
	failure_stage = L"validate inbox parent and input";
	status = scpfs_validate_parent_locked(backend, input_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_stat_locked(backend, input_remote, &input_stat);
	if(!NT_SUCCESS(status))
		goto done;
	if(input_stat.type == SCPFS_REMOTE_SYMLINK) {
		status = STATUS_REPARSE_POINT_ENCOUNTERED;
		goto done;
	}
	if(input_stat.type != SCPFS_REMOTE_FILE) {
		status = input_stat.type == SCPFS_REMOTE_DIRECTORY ?
			STATUS_FILE_IS_A_DIRECTORY : STATUS_ACCESS_DENIED;
		goto done;
	}
	status = scpfs_inbox_output_path_locked(backend, input_remote,
		&output_remote);
	if(!NT_SUCCESS(status))
		goto done;
	failure_stage = L"validate output destination";
	status = scpfs_validate_inbox_output_locked(backend, output_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_parent_path(backend, input_remote, &parent_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_make_inbox_sibling_locked(backend, input_remote, ".claim",
		&claim_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_make_inbox_sibling_locked(backend, input_remote, ".script",
		&script_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_make_inbox_sibling_locked(backend, input_remote, ".spool",
		&spool_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_make_inbox_sibling_locked(backend, input_remote, ".status",
		&status_remote);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_remote_path_to_mount_path(backend, claim_remote,
		&claim_mount_path);
	if(NT_SUCCESS(status))
		status = scpfs_remote_path_to_mount_path(backend, script_remote,
			&script_mount_path);
	if(NT_SUCCESS(status))
		status = scpfs_remote_path_to_mount_path(backend, spool_remote,
			&spool_mount_path);
	if(!NT_SUCCESS(status))
		goto done;
	status = scpfs_copy_inbox_claim_path(result_out, claim_remote);
	if(!NT_SUCCESS(status))
		goto done;
	failure_stage = L"claim input";
	status = scpfs_build_inbox_move_command(input_remote, claim_remote,
		&command);
	if(!NT_SUCCESS(status))
		goto done;
	claim_attempted = true;
	claim_command_status = scpfs_run_built_command_locked(backend, &command,
		SCPFS_MAX_STAT_OUTPUT);
	scpfs_buffer_free(&command);
	failure_stage = L"verify input claim";
	status = scpfs_stat_locked(backend, input_remote, &source_after_claim);
	if(!NT_SUCCESS(status) && !scpfs_is_missing_status(status)) {
		result_out->outcome_unknown = true;
		retain_claim = true;
		status = claim_command_status;
		if(NT_SUCCESS(status))
			status = STATUS_DATA_ERROR;
		goto done;
	}
	if(NT_SUCCESS(status)) {
		/* mv -n is allowed to return success without moving when a collision
		 * appears after the prior absence check. The source proves no claim. */
		if(!NT_SUCCESS(claim_command_status)) {
			status = claim_command_status;
			goto done;
		}
		status = STATUS_OBJECT_NAME_COLLISION;
		goto done;
	}
	status = scpfs_stat_locked(backend, claim_remote, &claim_stat);
	if(!NT_SUCCESS(status)) {
		result_out->outcome_unknown = claim_attempted;
		retain_claim = claim_attempted;
		status = NT_SUCCESS(claim_command_status) ? STATUS_DATA_ERROR :
			claim_command_status;
		goto done;
	}
	claimed = true;
	result_out->input_consumed = true;
	retain_claim = true;
	if(!scpfs_inbox_claim_matches(&input_stat, &claim_stat)) {
		status = STATUS_FILE_LOCK_CONFLICT;
		goto done;
	}
	if(!NT_SUCCESS(claim_command_status)) {
		/* The state check proves the move happened despite a failed command
		 * response. Keep the claimed input for recovery; never execute blindly. */
		status = claim_command_status;
		result_out->outcome_unknown = true;
		goto done;
	}
	status = scpfs_validate_inbox_output_locked(backend, output_remote);
	if(!NT_SUCCESS(status))
		goto done;

	if(input_stat.size <= SCPFS_INBOX_MAX_INPUT_BYTES) {
		failure_stage = L"download claimed input";
		LeaveCriticalSection(&backend->mutex);
		lock_held = false;
		status = scp_backend_download(backend, claim_mount_path,
			local_temp_path, &downloaded_stat);
		EnterCriticalSection(&backend->mutex);
		lock_held = true;
		if(!NT_SUCCESS(status))
			goto done;
		status = scpfs_stat_locked(backend, claim_remote, &claim_stat);
		if(!NT_SUCCESS(status))
			goto done;
		if(!scpfs_same_snapshot(&input_stat, &claim_stat) ||
			!scpfs_same_snapshot(&input_stat, &downloaded_stat)) {
			status = STATUS_FILE_LOCK_CONFLICT;
			goto done;
		}
		if(!scpfs_read_local_file(local_temp_path,
			SCPFS_INBOX_MAX_INPUT_BYTES, &input_bytes, &input_length)) {
			status = STATUS_DATA_ERROR;
			goto done;
		}
		failure_stage = L"validate command content";
		rejection = scpfs_validate_normalize_inbox_script(input_bytes,
			input_length, &normalized_script, &normalized_length);
		if(!rejection) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
	}
	else {
		rejection = too_large_message;
	}

	if(rejection[0] != '\0') {
		failure_stage = L"write rejection result";
		status = scpfs_write_local_inbox_bytes(local_temp_path,
			(const unsigned char *)rejection, strlen(rejection));
		if(!NT_SUCCESS(status))
			goto done;
	}
	else {
		failure_stage = L"write normalized command";
		status = scpfs_write_local_inbox_bytes(local_temp_path,
			normalized_script, normalized_length);
		if(!NT_SUCCESS(status))
			goto done;
	}

	/* Upload helpers take the same backend mutex. Drop it around these calls;
	 * every operation revalidates paths under the root after reacquiring it. */
	LeaveCriticalSection(&backend->mutex);
	lock_held = false;
	if(rejection[0] == '\0') {
		failure_stage = L"upload normalized command";
		status = scp_backend_upload_atomic(backend, script_mount_path,
			local_temp_path, NULL, &ignored_stat);
		if(NT_SUCCESS(status)) {
			EnterCriticalSection(&backend->mutex);
			lock_held = true;
			status = scpfs_build_inbox_chmod_command(script_remote, &command);
			if(NT_SUCCESS(status))
				status = scpfs_run_built_command_locked(backend, &command,
					SCPFS_MAX_STAT_OUTPUT);
			scpfs_buffer_free(&command);
			LeaveCriticalSection(&backend->mutex);
			lock_held = false;
		}
	}
	else {
		failure_stage = L"upload rejection result";
		status = scp_backend_upload_atomic(backend, spool_mount_path,
			local_temp_path, NULL, &spool_stat);
		if(NT_SUCCESS(status))
			output_uploaded = true;
	}
	if(!NT_SUCCESS(status))
		goto done_unlocked;
	EnterCriticalSection(&backend->mutex);
	lock_held = true;
	if(rejection[0] == '\0') {
		failure_stage = L"revalidate inbox namespace";
		status = scpfs_validate_parent_locked(backend, input_remote);
		if(!NT_SUCCESS(status))
			goto done;
		status = scpfs_validate_inbox_output_locked(backend, output_remote);
		if(!NT_SUCCESS(status))
			goto done;
		if(!NT_SUCCESS(scpfs_require_missing_locked(backend, spool_remote)) ||
			!NT_SUCCESS(scpfs_require_missing_locked(backend, status_remote))) {
			status = STATUS_OBJECT_NAME_COLLISION;
			goto done;
		}
		status = scpfs_build_inbox_execution_command(parent_remote,
			script_remote, spool_remote, status_remote, effective_timeout,
			&command);
		if(!NT_SUCCESS(status))
			goto done;
		status = scpfs_set_inbox_execution_timeout_locked(backend,
			effective_timeout, &old_receive_timeout, &old_send_timeout);
		if(!NT_SUCCESS(status))
			goto done;
		failure_stage = L"execute command";
		status = scpfs_execute_locked(backend, command.data,
			SCPFS_INBOX_CAPTURE_BYTES, &command_output,
			&command_output_length, &command_exit);
		scpfs_restore_execution_timeout_locked(backend, old_receive_timeout,
			old_send_timeout);
		scpfs_buffer_free(&command);
		if(!NT_SUCCESS(status)) {
			result_out->outcome_unknown = true;
			retain_claim = true;
			goto done;
		}
		failure_stage = L"parse command exit result";
		if(!scpfs_parse_inbox_exit_code(command_output,
			command_output_length, &script_exit)) {
			result_out->outcome_unknown = true;
			retain_claim = true;
			status = STATUS_DATA_ERROR;
			goto done;
		}
		(void)command_exit;
		result_out->exit_code = script_exit;
		execution_completed = true;
		result_out->completed = true;
		failure_stage = L"inspect command output spool";
		status = scpfs_stat_locked(backend, spool_remote, &spool_stat);
		if(!NT_SUCCESS(status))
			goto done;
		if(spool_stat.type != SCPFS_REMOTE_FILE ||
			spool_stat.size > SCPFS_INBOX_CAPTURE_BYTES) {
			status = STATUS_DATA_ERROR;
			goto done;
		}
		if(spool_stat.size > SCPFS_INBOX_MAX_OUTPUT_BYTES) {
			failure_stage = L"truncate command output";
			status = scpfs_build_inbox_truncate_command(spool_remote,
				&command);
			if(NT_SUCCESS(status))
				status = scpfs_run_built_command_locked(backend, &command,
					SCPFS_MAX_STAT_OUTPUT);
			scpfs_buffer_free(&command);
			if(!NT_SUCCESS(status))
				goto done;
			status = scpfs_stat_locked(backend, spool_remote, &spool_stat);
			if(!NT_SUCCESS(status))
				goto done;
			if(spool_stat.type != SCPFS_REMOTE_FILE ||
				spool_stat.size != SCPFS_INBOX_MAX_OUTPUT_BYTES +
					truncation_marker_length) {
				status = STATUS_DATA_ERROR;
				goto done;
			}
		}
	}
	else if(!output_uploaded) {
		status = STATUS_DATA_ERROR;
		goto done;
	}

	failure_stage = L"validate output publication";
	status = scpfs_validate_inbox_output_locked(backend, output_remote);
	if(!NT_SUCCESS(status))
		goto done;
	/* Publication replaces an existing regular file atomically. */
	failure_stage = L"publish command output";
	status = scpfs_build_inbox_publish_command(spool_remote, output_remote,
		&command);
	if(NT_SUCCESS(status))
		status = scpfs_run_built_command_locked(backend, &command,
			SCPFS_MAX_STAT_OUTPUT);
	scpfs_buffer_free(&command);
	if(!NT_SUCCESS(status)) {
		if(backend->broken)
			result_out->outcome_unknown = true;
		retain_claim = true;
		goto done;
	}
	failure_stage = L"verify published output";
	status = scpfs_stat_locked(backend, output_remote, &published_stat);
	if(!NT_SUCCESS(status))
		goto done;
	if(published_stat.type != SCPFS_REMOTE_FILE ||
		published_stat.size != spool_stat.size) {
		status = STATUS_DATA_ERROR;
		goto done;
	}
	status = scpfs_require_missing_locked(backend, spool_remote);
	if(!NT_SUCCESS(status))
		goto done;
	result_out->output_published = true;
	result_out->completed = true;
	if(!execution_completed)
		result_out->exit_code = -1;

	failure_stage = L"remove claim and temporary artifacts";
	status = scpfs_build_inbox_cleanup_command(claim_remote, script_remote,
		spool_remote, status_remote, &command);
	if(NT_SUCCESS(status))
		status = scpfs_run_built_command_locked(backend, &command,
			SCPFS_MAX_STAT_OUTPUT);
	scpfs_buffer_free(&command);
	if(NT_SUCCESS(status)) {
		free(result_out->claim_path);
		result_out->claim_path = NULL;
		retain_claim = false;
		result_out->input_consumed = true;
	}
	else {
		retain_claim = true;
		if(backend->broken)
			result_out->outcome_unknown = true;
	}
	done:
	if(lock_held) {
		LeaveCriticalSection(&backend->mutex);
		lock_held = false;
	}
	done_unlocked:
	if(!NT_SUCCESS(status) && !result_out->failure_stage)
		result_out->failure_stage = failure_stage;
	if(claimed && retain_claim && !result_out->claim_path && claim_remote)
		(void)scpfs_copy_inbox_claim_path(result_out, claim_remote);
	if(!claimed && !result_out->outcome_unknown) {
		free(result_out->claim_path);
		result_out->claim_path = NULL;
	}
	if(local_temp_created && local_temp_path)
		(void)DeleteFileW(local_temp_path);
	free(input_bytes);
	free(normalized_script);
	free(input_remote);
	free(output_remote);
	free(parent_remote);
	free(claim_remote);
	free(script_remote);
	free(spool_remote);
	free(status_remote);
	free(claim_mount_path);
	free(script_mount_path);
	free(spool_mount_path);
	free(local_temp_path);
	free(command_output);
	scpfs_buffer_free(&command);
	return status;
}

void
scp_backend_free_inbox_result(SCPFS_INBOX_RESULT *result)
{
	if(!result)
		return;
	free(result->claim_path);
	memset(result, 0, sizeof(*result));
	result->exit_code = -1;
}
