#include "scpfs.h"
#include "fs_frontend.h"
#include "fs_frontend_gui.h"

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <sddl.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ntstatus.h>

typedef struct CLI_OPTIONS {
	bool probe;
	bool service;
	bool install;
	bool uninstall;
	const wchar_t *host;
	const wchar_t *username;
	const wchar_t *remote_root;
	const wchar_t *known_hosts;
	const wchar_t *identity;
	const wchar_t *cache_directory;
	const wchar_t *mount_drive;
	const wchar_t *service_name;
	const wchar_t *log_file;
	const wchar_t *stop_event_name;
	const wchar_t *authorized_user_sid;
	bool service_name_set;
	uint16_t port;
	uint32_t timeout_ms;
	uint32_t command_timeout_ms;
	uint32_t cache_max_mib;
	bool cache_max_mib_set;
	WCHAR resolved_identity[MAX_PATH];
} CLI_OPTIONS;

static HANDLE g_stop_event;
static WCHAR g_gui_identity_default[MAX_PATH];
static WCHAR g_gui_known_hosts_default[MAX_PATH];
static WCHAR g_gui_log_default[MAX_PATH];

static void print_usage(FILE *stream)
{
	fwprintf(stream,
		L"Usage:\n"
		L"  scpfs --probe --host HOST --user USER --remote-root /PATH "
		L"--known-hosts FILE [--identity FILE] [--port PORT] [--timeout-ms MS]\n"
		L"  scpfs --mount X: --host HOST --user USER --remote-root /PATH "
		L"--known-hosts FILE [--identity FILE] [--port PORT] [--timeout-ms MS] "
		L"[--command-timeout-ms MS] [--cache-dir DIR]\n"
		L"  scpfs --install --mount X: --host HOST --user USER --remote-root /PATH "
		L"--known-hosts FILE [--identity FILE] [service options]\n"
		L"  scpfs --uninstall [--service-name NAME]\n"
		L"\n"
		L"Options:\n"
		L"  --probe             Verify the SSH host key and run an SCP round trip.\n"
		L"  --mount DRIVE       Mount the configured remote directory.\n"
		L"  --host HOST         Linux/OpenSSH server name or address.\n"
		L"  --user USER         Remote account name.\n"
		L"  --remote-root PATH  Existing absolute remote directory.\n"
		L"  --known-hosts FILE  OpenSSH known_hosts file used for strict verification.\n"
		L"  --identity FILE     Private key for public-key auth (default: <profile>\\.ssh\\id_ed25519).\n"
		L"  --port PORT         SSH port (default: 22).\n"
		L"  --timeout-ms MS     Per-operation timeout (default: 15000).\n"
		L"  --command-timeout-ms MS  Remote .in.txt command bound (default: 30000, max: 540000).\n"
		L"  --cache-dir DIR     Local cache directory (default: under %%TMP%%).\n"
		L"  --cache-max-mib N  Per-session read-cache limit in MiB (default: 0, range: 0-16384; 0 means unlimited).\n"
		L"  --stop-event NAME  Internal named event used to stop an owned mount child.\n"
		L"  --install           Register and start an automatic LocalSystem service.\n"
		L"  --uninstall         Stop and remove only the named SCPFS service.\n"
		L"  --service           Internal SCM entry point (not for interactive use).\n"
		L"  --service-name NAME Service name (default: Scpfs).\n"
		L"  --log-file FILE     Service log path (default: under ProgramData).\n"
		L"  --authorized-user-sid SID  Internal service mount access SID.\n"
		L"  --version           Show version.\n"
		L"  --help              Show this help.\n");
}

static bool parse_u32(const wchar_t *text, uint32_t minimum,
	uint32_t maximum, uint32_t *value_out)
{
	wchar_t *end = NULL;
	unsigned long value;

	if (text == NULL || text[0] == L'\0')
		return false;
	value = wcstoul(text, &end, 10);
	if (*end != L'\0' || value < minimum || value > maximum)
		return false;
	*value_out = (uint32_t)value;
	return true;
}

static bool append_identity_path(PCWSTR profile, WCHAR path[MAX_PATH])
{
	int length;
	if (profile == NULL || profile[0] == L'\0')
		return false;
	length = _snwprintf_s(path, MAX_PATH, _TRUNCATE,
		L"%ls\\.ssh\\id_ed25519", profile);
	return length >= 0;
}

static bool resolve_identity(CLI_OPTIONS *options)
{
	DWORD chars;
	DWORD attributes;
	WCHAR profile[MAX_PATH];
	PWSTR known_profile = NULL;

	if (options->identity != NULL) {
		if (wcslen(options->identity) >= ARRAYSIZE(options->resolved_identity))
			return false;
		wcscpy_s(options->resolved_identity, ARRAYSIZE(options->resolved_identity),
			options->identity);
	} else {
		chars = GetEnvironmentVariableW(L"HOME", profile, ARRAYSIZE(profile));
		if (chars == 0 || chars >= ARRAYSIZE(profile)) {
			chars = GetEnvironmentVariableW(L"USERPROFILE", profile, ARRAYSIZE(profile));
			if (chars == 0 || chars >= ARRAYSIZE(profile)) {
				if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL,
					&known_profile)) && known_profile != NULL) {
					wcscpy_s(profile, ARRAYSIZE(profile), known_profile);
					CoTaskMemFree(known_profile);
					known_profile = NULL;
				} else {
					return false;
				}
			}
		}
		if (!append_identity_path(profile, options->resolved_identity))
			return false;
	}
	options->identity = options->resolved_identity;
	attributes = GetFileAttributesW(options->identity);
	if (attributes == INVALID_FILE_ATTRIBUTES ||
		(attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		fwprintf(stderr, L"identity: private key file not found or inaccessible: %ls\n",
			options->identity);
		return false;
	}
	return true;
}

static bool parse_options(int argc, wchar_t **argv, CLI_OPTIONS *options,
	const wchar_t **mount_drive_out, bool *help_out)
{
	int i;
	memset(options, 0, sizeof(*options));
	options->port = 22;
	options->timeout_ms = 15000;
	options->command_timeout_ms = 30000;
	options->cache_max_mib = 0;
	options->service_name = L"Scpfs";
	*mount_drive_out = NULL;
	*help_out = false;

	for (i = 1; i < argc; ++i) {
		const wchar_t *arg = argv[i];
		const wchar_t *value = (i + 1 < argc) ? argv[i + 1] : NULL;
		uint32_t number;
		if (wcscmp(arg, L"--help") == 0 || wcscmp(arg, L"-h") == 0) {
			*help_out = true;
		} else if (wcscmp(arg, L"--probe") == 0) {
			options->probe = true;
		} else if (wcscmp(arg, L"--service") == 0) {
			options->service = true;
		} else if (wcscmp(arg, L"--install") == 0) {
			options->install = true;
		} else if (wcscmp(arg, L"--uninstall") == 0) {
			options->uninstall = true;
		} else if (wcscmp(arg, L"--service-name") == 0) {
			if (value == NULL || value[0] == L'\0' || options->service_name_set)
				return false;
			options->service_name = value;
			options->service_name_set = true;
			++i;
		} else if (wcscmp(arg, L"--log-file") == 0) {
			if (value == NULL || value[0] == L'\0' || options->log_file != NULL)
				return false;
			options->log_file = value;
			++i;
		} else if (wcscmp(arg, L"--authorized-user-sid") == 0) {
			if (value == NULL || value[0] == L'\0' || options->authorized_user_sid != NULL)
				return false;
			options->authorized_user_sid = value;
			++i;
		} else if (wcscmp(arg, L"--mount") == 0) {
			if (value == NULL || value[0] == L'\0' || *mount_drive_out != NULL)
				return false;
			*mount_drive_out = value;
			options->mount_drive = value;
			++i;
		} else if (wcscmp(arg, L"--host") == 0) {
			if (value == NULL || value[0] == L'\0' || options->host != NULL)
				return false;
			options->host = value;
			++i;
		} else if (wcscmp(arg, L"--user") == 0) {
			if (value == NULL || value[0] == L'\0' || options->username != NULL)
				return false;
			options->username = value;
			++i;
		} else if (wcscmp(arg, L"--remote-root") == 0) {
			if (value == NULL || value[0] == L'\0' || options->remote_root != NULL)
				return false;
			options->remote_root = value;
			++i;
		} else if (wcscmp(arg, L"--known-hosts") == 0) {
			if (value == NULL || value[0] == L'\0' || options->known_hosts != NULL)
				return false;
			options->known_hosts = value;
			++i;
		} else if (wcscmp(arg, L"--identity") == 0) {
			if (value == NULL || value[0] == L'\0' || options->identity != NULL)
				return false;
			options->identity = value;
			++i;
		} else if (wcscmp(arg, L"--cache-dir") == 0) {
			if (value == NULL || value[0] == L'\0' || options->cache_directory != NULL)
				return false;
			options->cache_directory = value;
			++i;
		} else if (wcscmp(arg, L"--cache-max-mib") == 0) {
			if (options->cache_max_mib_set ||
				!parse_u32(value, 0, 16384, &options->cache_max_mib))
				return false;
			options->cache_max_mib_set = true;
			++i;
		} else if (wcscmp(arg, L"--stop-event") == 0) {
			if (value == NULL || value[0] == L'\0' || options->stop_event_name != NULL)
				return false;
			options->stop_event_name = value;
			++i;
		} else if (wcscmp(arg, L"--port") == 0) {
			if (!parse_u32(value, 1, UINT16_MAX, &number))
				return false;
			options->port = (uint16_t)number;
			++i;
		} else if (wcscmp(arg, L"--timeout-ms") == 0) {
			if (!parse_u32(value, 1, 300000, &number))
				return false;
			options->timeout_ms = number;
			++i;
		} else if (wcscmp(arg, L"--command-timeout-ms") == 0) {
			if (!parse_u32(value, 1, 540000, &number))
				return false;
			options->command_timeout_ms = number;
			++i;
		} else {
			return false;
		}
	}
	if (*help_out)
		return true;
	if (options->uninstall) {
		return !options->install && !options->service && !options->probe &&
			*mount_drive_out == NULL && options->host == NULL && options->username == NULL &&
			options->remote_root == NULL && options->known_hosts == NULL &&
			options->identity == NULL && options->log_file == NULL &&
			options->authorized_user_sid == NULL && options->cache_directory == NULL &&
			options->stop_event_name == NULL && !options->cache_max_mib_set;
	}
	if (options->stop_event_name != NULL &&
		(options->probe || options->install || options->service || *mount_drive_out == NULL))
		return false;
	if ((options->probe == (*mount_drive_out != NULL)) ||
		options->host == NULL || options->username == NULL ||
		options->remote_root == NULL || options->known_hosts == NULL)
		return false;
	if (options->install && options->service)
		return false;
	if ((options->service &&
		(options->probe || options->identity == NULL ||
			options->authorized_user_sid == NULL)) ||
		(options->install && options->probe))
		return false;
	if (!options->service && !options->install &&
		(options->log_file != NULL || options->authorized_user_sid != NULL ||
			options->service_name_set))
		return false;
	return true;
}

static bool write_file(const wchar_t *path, const void *data, DWORD length)
{
	HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_TEMPORARY, NULL);
	DWORD written = 0;
	bool ok;
	if (file == INVALID_HANDLE_VALUE)
		return false;
	ok = WriteFile(file, data, length, &written, NULL) && written == length;
	if (!CloseHandle(file))
		ok = false;
	return ok;
}

static bool files_equal(const wchar_t *right, const void *expected,
	DWORD expected_length)
{
	BYTE buffer[512];
	DWORD read_count = 0;
	HANDLE file = CreateFileW(right, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	bool ok = false;
	if (file == INVALID_HANDLE_VALUE)
		return false;
	if (!ReadFile(file, buffer, sizeof(buffer), &read_count, NULL))
		goto done;
	if (read_count != expected_length ||
		memcmp(buffer, expected, expected_length) != 0)
		goto done;
	{
		BYTE extra;
		DWORD extra_count = 0;
		if (!ReadFile(file, &extra, 1, &extra_count, NULL) || extra_count != 0)
			goto done;
	}
	ok = true;
done:
	CloseHandle(file);
	return ok;
}

static WCHAR *absolute_path_copy(PCWSTR path)
{
	DWORD needed;
	WCHAR *copy;
	if (path == NULL || path[0] == L'\0')
		return NULL;
	needed = GetFullPathNameW(path, 0, NULL, NULL);
	if (needed == 0 || needed > 32767)
		return NULL;
	copy = (WCHAR *)calloc((size_t)needed + 1, sizeof(WCHAR));
	if (copy == NULL)
		return NULL;
	if (GetFullPathNameW(path, needed + 1, copy, NULL) == 0) {
		free(copy);
		return NULL;
	}
	return copy;
}

static WCHAR *current_executable_path(void)
{
	DWORD capacity = MAX_PATH;
	while (capacity <= 32767) {
		WCHAR *path = (WCHAR *)calloc((size_t)capacity, sizeof(WCHAR));
		DWORD copied;
		if (path == NULL)
			return NULL;
		copied = GetModuleFileNameW(NULL, path, capacity);
		if (copied == 0) {
			free(path);
			return NULL;
		}
		if (copied < capacity - 1)
			return path;
		free(path);
		if (capacity > 16384)
			break;
		capacity *= 2;
	}
	return NULL;
}

static bool append_quoted_argument(WCHAR *buffer, size_t capacity,
	size_t *used, PCWSTR value)
{
	size_t index = 0;
	if (buffer == NULL || used == NULL || value == NULL)
		return false;
	if (*used != 0) {
		if (*used + 1 >= capacity)
			return false;
		buffer[(*used)++] = L' ';
	}
	if (*used + 1 >= capacity)
		return false;
	buffer[(*used)++] = L'"';
	while (value[index] != L'\0') {
		size_t slashes = 0;
		while (value[index] == L'\\') {
			++slashes;
			++index;
		}
		if (value[index] == L'"') {
			size_t count = slashes * 2 + 1;
			if (*used + count + 1 >= capacity)
				return false;
			while (count-- != 0)
				buffer[(*used)++] = L'\\';
			buffer[(*used)++] = L'"';
			++index;
		} else if (value[index] == L'\0') {
			size_t count = slashes * 2;
			if (*used + count + 2 >= capacity)
				return false;
			while (count-- != 0)
				buffer[(*used)++] = L'\\';
			break;
		} else {
			if (*used + slashes + 1 >= capacity)
				return false;
			while (slashes-- != 0)
				buffer[(*used)++] = L'\\';
			buffer[(*used)++] = value[index++];
		}
	}
	if (*used + 2 > capacity)
		return false;
	buffer[(*used)++] = L'"';
	buffer[*used] = L'\0';
	return true;
}

static bool build_service_arguments(const CLI_OPTIONS *options,
	PCWSTR identity, PCWSTR known_hosts, PCWSTR log_file, PCWSTR sid,
	WCHAR arguments[32768])
{
	size_t used = 0;
	WCHAR port[16], timeout[16], command_timeout[16], cache_max_mib[16];
	const WCHAR *parts[22];
	size_t i;
	_snwprintf_s(port, ARRAYSIZE(port), _TRUNCATE, L"%u", options->port);
	_snwprintf_s(timeout, ARRAYSIZE(timeout), _TRUNCATE, L"%u", options->timeout_ms);
	_snwprintf_s(command_timeout, ARRAYSIZE(command_timeout), _TRUNCATE,
		L"%u", options->command_timeout_ms);
	parts[0] = L"--service";
	parts[1] = L"--service-name";
	parts[2] = options->service_name;
	parts[3] = L"--mount";
	parts[4] = options->mount_drive;
	parts[5] = L"--host";
	parts[6] = options->host;
	parts[7] = L"--user";
	parts[8] = options->username;
	parts[9] = L"--remote-root";
	parts[10] = options->remote_root;
	parts[11] = L"--known-hosts";
	parts[12] = known_hosts;
	parts[13] = L"--identity";
	parts[14] = identity;
	parts[15] = L"--port";
	parts[16] = port;
	parts[17] = L"--timeout-ms";
	parts[18] = timeout;
	parts[19] = L"--command-timeout-ms";
	parts[20] = command_timeout;
	parts[21] = L"--authorized-user-sid";
	for (i = 0; i < ARRAYSIZE(parts); ++i) {
		if (!append_quoted_argument(arguments, 32768, &used, parts[i]))
			return false;
	}
	if (!append_quoted_argument(arguments, 32768, &used, sid) ||
		!append_quoted_argument(arguments, 32768, &used, L"--log-file") ||
		!append_quoted_argument(arguments, 32768, &used, log_file))
		return false;
	if (options->cache_directory != NULL &&
		(!append_quoted_argument(arguments, 32768, &used, L"--cache-dir") ||
		 !append_quoted_argument(arguments, 32768, &used, options->cache_directory)))
		return false;
	if (options->cache_max_mib != 0) {
		_snwprintf_s(cache_max_mib, ARRAYSIZE(cache_max_mib), _TRUNCATE,
			L"%u", options->cache_max_mib);
		if (!append_quoted_argument(arguments, 32768, &used, L"--cache-max-mib") ||
			!append_quoted_argument(arguments, 32768, &used, cache_max_mib))
			return false;
	}
	return true;
}

static WCHAR *capture_user_sid(void)
{
	HANDLE token = NULL;
	PTOKEN_USER user = NULL;
	DWORD bytes = 0;
	WCHAR *sid = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return NULL;
	(void)GetTokenInformation(token, TokenUser, NULL, 0, &bytes);
	if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto done;
	user = (PTOKEN_USER)malloc(bytes);
	if (user == NULL || !GetTokenInformation(token, TokenUser, user, bytes, &bytes))
		goto done;
	if (!ConvertSidToStringSidW(user->User.Sid, &sid))
		sid = NULL;
done:
	free(user);
	CloseHandle(token);
	return sid;
}

static WCHAR *default_service_log_path(PCWSTR service_name)
{
	WCHAR program_data[MAX_PATH];
	WCHAR path[MAX_PATH];
	DWORD length = GetEnvironmentVariableW(L"ProgramData", program_data,
		ARRAYSIZE(program_data));
	if (length == 0 || length >= ARRAYSIZE(program_data))
		return NULL;
	if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
		L"%ls\\Scpfs\\%ls.log", program_data, service_name) < 0)
		return NULL;
	return absolute_path_copy(path);
}

static void format_probe_path(WCHAR path[96], const WCHAR *suffix,
	const BYTE random_bytes[16])
{
	static const WCHAR hex[] = L"0123456789abcdef";
	size_t pos = 0;
	unsigned int i;
	path[pos++] = L'\\';
	for (i = 0; i < 16; ++i) {
		path[pos++] = hex[random_bytes[i] >> 4];
		path[pos++] = hex[random_bytes[i] & 0x0f];
	}
	while (*suffix != L'\0')
		path[pos++] = *suffix++;
	path[pos] = L'\0';
}

static int run_probe(const CLI_OPTIONS *options)
{
	static const char payload[] = "scpfs-probe-v1\r\nSCP payload round trip.\0binary";
	SCPFS_BACKEND_OPTIONS backend_options;
	SCPFS_BACKEND *backend = NULL;
	SCPFS_REMOTE_STAT remote_stat;
	BYTE random_bytes[16];
	WCHAR first_path[96], second_path[96];
	WCHAR temp_dir[MAX_PATH] = { 0 }, upload_path[MAX_PATH] = { 0 };
	WCHAR download_path[MAX_PATH] = { 0 };
	NTSTATUS status;
	bool uploaded = false;
	bool renamed = false;
	int result = 1;
	DWORD length = (DWORD)(sizeof(payload) - 1);

	memset(&backend_options, 0, sizeof(backend_options));
	backend_options.host = options->host;
	backend_options.username = options->username;
	backend_options.port = options->port;
	backend_options.remote_root = options->remote_root;
	backend_options.known_hosts_file = options->known_hosts;
	backend_options.identity_file = options->identity;
	backend_options.timeout_ms = options->timeout_ms;

	status = BCryptGenRandom(NULL, random_bytes, sizeof(random_bytes),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (status < 0) {
		fwprintf(stderr, L"probe: secure random generation failed (0x%08X)\n",
			(unsigned int)status);
		return 1;
	}
	format_probe_path(first_path, L".upload", random_bytes);
	format_probe_path(second_path, L".renamed", random_bytes);
	if (GetTempPathW(ARRAYSIZE(temp_dir), temp_dir) == 0 ||
		GetTempFileNameW(temp_dir, L"scp", 0, upload_path) == 0 ||
		GetTempFileNameW(temp_dir, L"scp", 0, download_path) == 0) {
		fwprintf(stderr, L"probe: cannot create temporary files (error %lu)\n",
			GetLastError());
		goto done;
	}
	DeleteFileW(download_path);
	if (!write_file(upload_path, payload, length)) {
		fwprintf(stderr, L"probe: cannot write temporary upload file (error %lu)\n",
			GetLastError());
		goto done;
	}

	status = scp_backend_connect(&backend_options, &backend);
	if (status < 0) {
		fwprintf(stderr, L"probe: SSH connection, host-key verification, or authentication failed (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	status = scp_backend_upload_atomic(backend, first_path, upload_path, NULL,
		&remote_stat);
	if (status < 0) {
		fwprintf(stderr, L"probe: SCP upload failed (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	uploaded = true;
	status = scp_backend_stat(backend, first_path, &remote_stat);
	if (status < 0 || remote_stat.type != SCPFS_REMOTE_FILE || remote_stat.size != length) {
		fwprintf(stderr, L"probe: remote stat did not match uploaded file (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	status = scp_backend_download(backend, first_path, download_path, &remote_stat);
	if (status < 0 || !files_equal(download_path, payload, length)) {
		fwprintf(stderr, L"probe: SCP download payload mismatch (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	status = scp_backend_rename(backend, first_path, second_path, false);
	if (status < 0) {
		fwprintf(stderr, L"probe: remote rename failed (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	uploaded = false;
	renamed = true;
	status = scp_backend_stat(backend, second_path, &remote_stat);
	if (status < 0 || remote_stat.type != SCPFS_REMOTE_FILE || remote_stat.size != length) {
		fwprintf(stderr, L"probe: renamed file stat failed (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	status = scp_backend_remove(backend, second_path, false);
	if (status < 0) {
		fwprintf(stderr, L"probe: remote cleanup failed (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	renamed = false;
	wprintf(L"probe: strict host-key verification, SCP upload/download, byte check, rename, and delete succeeded\n");
	fflush(stdout);
	result = 0;

done:
	if (backend != NULL) {
		if (uploaded)
			(void)scp_backend_remove(backend, first_path, false);
		if (renamed)
			(void)scp_backend_remove(backend, second_path, false);
		scp_backend_disconnect(backend);
	}
	if (upload_path[0] != L'\0')
		DeleteFileW(upload_path);
	if (download_path[0] != L'\0')
		DeleteFileW(download_path);
	return result;
}

static BOOL WINAPI console_handler(DWORD control_type)
{
	if (control_type == CTRL_C_EVENT || control_type == CTRL_BREAK_EVENT ||
		control_type == CTRL_CLOSE_EVENT || control_type == CTRL_SHUTDOWN_EVENT) {
		if (g_stop_event != NULL)
			SetEvent(g_stop_event);
		return TRUE;
	}
	return FALSE;
}

static int run_mount(const CLI_OPTIONS *options, PCWSTR mount_point)
{
	SCPFS_OPTIONS fs_options;
	SCPFS *instance = NULL;
	HANDLE wait_handles[3];
	DWORD wait_result;
	NTSTATUS status;
	int result = 1;

	memset(&fs_options, 0, sizeof(fs_options));
	fs_options.backend.host = options->host;
	fs_options.backend.username = options->username;
	fs_options.backend.port = options->port;
	fs_options.backend.remote_root = options->remote_root;
	fs_options.backend.known_hosts_file = options->known_hosts;
	fs_options.backend.identity_file = options->identity;
	fs_options.backend.timeout_ms = options->timeout_ms;
	fs_options.cache_directory = options->cache_directory;
	fs_options.command_timeout_ms = options->command_timeout_ms;
	fs_options.read_cache_max_mib = options->cache_max_mib;

	status = scpfs_create(&fs_options, &instance);
	if (status < 0) {
		fwprintf(stderr, L"mount: cannot initialize filesystem (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	wprintf(L"SCPFS cache: %ls\n", scpfs_cache_directory(instance));
	status = scpfs_mount(instance, mount_point);
	if (status < 0) {
		fwprintf(stderr, L"mount: cannot mount at %ls (0x%08X)\n",
			mount_point, (unsigned int)status);
		goto done;
	}
	status = scpfs_start(instance, 0);
	if (status < 0) {
		fwprintf(stderr, L"mount: cannot start WinFsp dispatcher (0x%08X)\n",
			(unsigned int)status);
		goto done;
	}
	wprintf(L"SCPFS mounted at %ls. Press Ctrl+C to stop.\n", mount_point);
	fflush(stdout);
	wait_handles[0] = g_stop_event;
	wait_handles[1] = scpfs_dispatcher_stopped_event(instance);
	wait_handles[2] = scpfs_backend_failure_event(instance);
	wait_result = WaitForMultipleObjects(ARRAYSIZE(wait_handles), wait_handles,
		FALSE, INFINITE);
	if (wait_result == WAIT_OBJECT_0) {
		scpfs_stop(instance);
		result = 0;
	} else if (wait_result == WAIT_OBJECT_0 + 1) {
		status = scpfs_dispatcher_result(instance);
		if (scpfs_dispatcher_stopped_normally(instance) &&
			WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) {
			result = 0;
		} else {
			if (status >= 0)
				status = STATUS_DEVICE_NOT_CONNECTED;
			fwprintf(stderr, L"mount: WinFsp dispatcher stopped unexpectedly (0x%08X)\n",
				(unsigned int)status);
			result = 7;
		}
	} else if (wait_result == WAIT_OBJECT_0 + 2) {
		status = scpfs_backend_failure_status(instance);
		fwprintf(stderr, L"mount: SSH backend is unusable (0x%08X); restart the process to reconnect.\n",
			(unsigned int)status);
		result = 9;
	} else {
		fwprintf(stderr, L"mount: wait failed (error %lu)\n",
			wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE);
		result = 8;
	}

done:
	if (instance != NULL)
		scpfs_destroy(instance);
	return result;
}

typedef struct SCPFS_SERVICE_CONTEXT {
	CLI_OPTIONS *options;
} SCPFS_SERVICE_CONTEXT;

static FSF_SERVICE_EXIT scpfs_service_backend_run(void *context,
	FSF_SERVICE *service)
{
	SCPFS_SERVICE_CONTEXT *service_context = (SCPFS_SERVICE_CONTEXT *)context;
	CLI_OPTIONS *options = service_context->options;
	SCPFS_OPTIONS fs_options;
	SCPFS *instance = NULL;
	FSF_SERVICE_EXIT result = { FALSE, ERROR_SERVICE_SPECIFIC_ERROR, 1 };
	HANDLE wait_handles[3];
	DWORD wait_result;
	NTSTATUS status;
	DWORD service_error = ERROR_SUCCESS;
	WCHAR message[256];
	memset(&fs_options, 0, sizeof(fs_options));
	fs_options.backend.host = options->host;
	fs_options.backend.username = options->username;
	fs_options.backend.port = options->port;
	fs_options.backend.remote_root = options->remote_root;
	fs_options.backend.known_hosts_file = options->known_hosts;
	fs_options.backend.identity_file = options->identity;
	fs_options.backend.timeout_ms = options->timeout_ms;
	fs_options.cache_directory = options->cache_directory;
	fs_options.command_timeout_ms = options->command_timeout_ms;
	fs_options.read_cache_max_mib = options->cache_max_mib;
	fs_options.authorized_user_sid = options->authorized_user_sid;
	if (PathIsRelativeW(options->identity) || PathIsRelativeW(options->known_hosts) ||
		PathIsRelativeW(options->log_file)) {
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, ERROR_INVALID_NAME,
			L"SCM arguments must use absolute identity, known_hosts, and log paths.");
		result.win32_error = ERROR_SERVICE_SPECIFIC_ERROR;
		result.service_specific_error = ERROR_INVALID_NAME;
		goto done;
	}
	(void)fsf_service_report_start_progress(service, 60000, &service_error);
	status = scpfs_create(&fs_options, &instance);
	if (!NT_SUCCESS(status)) {
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"SCPFS initialization failed (NTSTATUS 0x%08X).", (unsigned int)status);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status, message);
		result.service_specific_error = (DWORD)status;
		goto done;
	}
	(void)fsf_service_report_start_progress(service, 60000, &service_error);
	status = scpfs_mount(instance, options->mount_drive);
	if (!NT_SUCCESS(status)) {
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"SCPFS mount at %ls failed (NTSTATUS 0x%08X).",
			options->mount_drive, (unsigned int)status);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status, message);
		result.service_specific_error = (DWORD)status;
		goto done;
	}
	status = scpfs_start(instance, 1);
	if (!NT_SUCCESS(status)) {
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"SCPFS dispatcher start failed (NTSTATUS 0x%08X).", (unsigned int)status);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status, message);
		result.service_specific_error = (DWORD)status;
		goto done;
	}
	if (!fsf_service_report_running(service, &service_error)) {
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"SCM RUNNING status report failed (Win32 %lu).", service_error);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, service_error, message);
		result.win32_error = service_error;
		result.service_specific_error = 0;
		goto done;
	}
	_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
		L"SCPFS cache startup: directory=%ls max_mib=%u (0=unlimited).",
		scpfs_cache_directory(instance) != NULL ?
			scpfs_cache_directory(instance) : L"(unavailable)",
		options->cache_max_mib);
	fsf_service_log(service, FSF_SERVICE_LOG_INFORMATION, 0, message);
	fsf_service_log(service, FSF_SERVICE_LOG_INFORMATION, 0,
		L"SCPFS mounted and dispatcher started.");
	wait_handles[0] = fsf_service_stop_event(service);
	wait_handles[1] = scpfs_dispatcher_stopped_event(instance);
	wait_handles[2] = scpfs_backend_failure_event(instance);
	wait_result = WaitForMultipleObjects(ARRAYSIZE(wait_handles), wait_handles,
		FALSE, INFINITE);
	if (wait_result == WAIT_OBJECT_0) {
		scpfs_stop(instance);
		result.normal_stop = TRUE;
		result.win32_error = ERROR_SUCCESS;
		result.service_specific_error = ERROR_SUCCESS;
		fsf_service_log(service, FSF_SERVICE_LOG_INFORMATION, 0,
			L"SCPFS service stop was requested by SCM.");
	} else if (wait_result == WAIT_OBJECT_0 + 1) {
		status = scpfs_dispatcher_result(instance);
		result.service_specific_error = (DWORD)status;
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"SCPFS WinFsp dispatcher exited unexpectedly (NTSTATUS 0x%08X).",
			(unsigned int)status);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status, message);
	} else if (wait_result == WAIT_OBJECT_0 + 2) {
		status = scpfs_backend_failure_status(instance);
		result.service_specific_error = (DWORD)status;
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"SCPFS SSH backend became unusable (NTSTATUS 0x%08X).",
			(unsigned int)status);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status, message);
	} else {
		service_error = wait_result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
		result.win32_error = service_error;
		result.service_specific_error = 0;
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, service_error,
			L"SCPFS service wait failed.");
	}
done:
	if (instance != NULL)
		scpfs_destroy(instance);
	return result;
}

static bool valid_service_name(PCWSTR name)
{
	const WCHAR *p;
	if (name == NULL || name[0] == L'\0' || wcslen(name) > 256)
		return false;
	for (p = name; *p != L'\0'; ++p) {
		if (!((*p >= L'a' && *p <= L'z') || (*p >= L'A' && *p <= L'Z') ||
			(*p >= L'0' && *p <= L'9') || *p == L'_' || *p == L'-' || *p == L'.'))
			return false;
	}
	return true;
}

static int install_service(CLI_OPTIONS *options)
{
	static const SC_ACTION actions[] = {
		{ SC_ACTION_RESTART, 1000 },
		{ SC_ACTION_RESTART, 5000 },
		{ SC_ACTION_RESTART, 30000 },
		{ SC_ACTION_NONE, 0 }
	};
	FSF_SERVICE_INSTALL_CONFIG config;
	WCHAR *identity = NULL, *known_hosts = NULL, *log_path = NULL;
	WCHAR *cache_directory = NULL;
	WCHAR *executable = NULL, *sid = NULL;
	WCHAR service_arguments[32768] = { 0 };
	DWORD error;
	int result = 1;
	if (!valid_service_name(options->service_name)) {
		fwprintf(stderr, L"install: invalid service name.\n");
		return 2;
	}
	identity = absolute_path_copy(options->identity);
	known_hosts = absolute_path_copy(options->known_hosts);
	log_path = options->log_file != NULL ? absolute_path_copy(options->log_file) :
		default_service_log_path(options->service_name);
	cache_directory = options->cache_directory != NULL ?
		absolute_path_copy(options->cache_directory) : NULL;
	executable = current_executable_path();
	sid = capture_user_sid();
	if (identity == NULL || known_hosts == NULL || log_path == NULL ||
		(options->cache_directory != NULL && cache_directory == NULL) ||
		executable == NULL || sid == NULL ||
		GetFileAttributesW(identity) == INVALID_FILE_ATTRIBUTES ||
		GetFileAttributesW(known_hosts) == INVALID_FILE_ATTRIBUTES) {
		fwprintf(stderr, L"install: cannot resolve executable, key, known_hosts, log path, or installer SID (error %lu).\n",
			GetLastError());
		goto done;
	}
	options->identity = identity;
	options->known_hosts = known_hosts;
	if (cache_directory != NULL)
		options->cache_directory = cache_directory;
	wprintf(L"install: verifying strict SSH/SCP access before registering service...\n");
	if (run_probe(options) != 0) {
		fwprintf(stderr, L"install: SSH/SCP preflight failed; no service was installed.\n");
		goto done;
	}
	if (!build_service_arguments(options, identity, known_hosts, log_path, sid,
		service_arguments)) {
		fwprintf(stderr, L"install: service arguments exceed the Windows command-line limit.\n");
		goto done;
	}
	memset(&config, 0, sizeof(config));
	config.struct_size = sizeof(config);
	config.abi_version = FS_FRONTEND_ABI_VERSION;
	config.service_name = options->service_name;
	config.display_name = L"SCPFS Remote File System";
	config.description = L"Mounts a remote Linux directory through the SCPFS filesystem.";
	config.absolute_executable = executable;
	config.exact_service_arguments = service_arguments;
	config.log_path = log_path;
	config.authorized_user_sid = sid;
	config.delayed_auto_start = TRUE;
	config.start_timeout_ms = 120000;
	config.failure_reset_seconds = 86400;
	config.failure_action_count = ARRAYSIZE(actions);
	config.failure_actions = (const SC_ACTION *)actions;
	error = fsf_service_install(&config);
	if (error != ERROR_SUCCESS) {
		fwprintf(stderr, L"install: native SCM installation/start failed (Win32 %lu).\n", error);
		goto done;
	}
	wprintf(L"install: service %ls installed and started.\n", options->service_name);
	result = 0;
done:
	free(identity);
	free(known_hosts);
	free(log_path);
	free(cache_directory);
	free(executable);
	if (sid != NULL)
		LocalFree(sid);
	return result;
}

static int uninstall_service(const CLI_OPTIONS *options)
{
	DWORD error;
	if (!valid_service_name(options->service_name)) {
		fwprintf(stderr, L"uninstall: invalid service name.\n");
		return 2;
	}
	error = fsf_service_uninstall(options->service_name, 30000);
	if (error != ERROR_SUCCESS) {
		fwprintf(stderr, L"uninstall: service removal failed (Win32 %lu).\n", error);
		return 1;
	}
	wprintf(L"uninstall: service %ls removed. Driver, cache, keys, and remote data were not changed.\n",
		options->service_name);
	return 0;
}

static int run_service(CLI_OPTIONS *options)
{
	FSF_SERVICE_RUN_CONFIG config;
	FSF_SERVICE_EXIT result;
	SCPFS_SERVICE_CONTEXT context;
	DWORD error;
	WCHAR *default_log = NULL;
	if (!valid_service_name(options->service_name) || options->authorized_user_sid == NULL) {
		return 2;
	}
	if (options->log_file == NULL) {
		default_log = default_service_log_path(options->service_name);
		if (default_log == NULL)
			return 2;
		options->log_file = default_log;
	}
	context.options = options;
	memset(&config, 0, sizeof(config));
	config.struct_size = sizeof(config);
	config.abi_version = FS_FRONTEND_ABI_VERSION;
	config.service_name = options->service_name;
	config.log_path = options->log_file;
	config.authorized_user_sid = options->authorized_user_sid;
	config.app_context = &context;
	config.run = scpfs_service_backend_run;
	error = fsf_service_run(&config, &result);
	free(default_log);
	if (error != ERROR_SUCCESS) {
		fwprintf(stderr, L"service: service control dispatcher failed (Win32 %lu).\n", error);
		return 1;
	}
	return result.normal_stop ? 0 : 1;
}

static bool gui_profile_directory(WCHAR profile[MAX_PATH])
{
	DWORD length = GetEnvironmentVariableW(L"HOME", profile, MAX_PATH);
	PWSTR known_profile = NULL;
	if (length == 0 || length >= MAX_PATH)
		length = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		if (FAILED(SHGetKnownFolderPath(&FOLDERID_Profile, 0, NULL, &known_profile)) ||
			known_profile == NULL)
			return false;
		if (wcslen(known_profile) >= MAX_PATH) {
			CoTaskMemFree(known_profile);
			return false;
		}
		wcscpy_s(profile, MAX_PATH, known_profile);
		CoTaskMemFree(known_profile);
	}
	return profile[0] != L'\0';
}

static bool initialize_gui_defaults(void)
{
	WCHAR profile[MAX_PATH] = { 0 };
	WCHAR program_data[MAX_PATH] = { 0 };
	DWORD length;
	if (!gui_profile_directory(profile))
		return false;
	if (_snwprintf_s(g_gui_identity_default, ARRAYSIZE(g_gui_identity_default),
		_TRUNCATE, L"%ls\\.ssh\\id_ed25519", profile) < 0 ||
		_snwprintf_s(g_gui_known_hosts_default, ARRAYSIZE(g_gui_known_hosts_default),
			_TRUNCATE, L"%ls\\.ssh\\known_hosts", profile) < 0)
		return false;
	length = GetEnvironmentVariableW(L"ProgramData", program_data, ARRAYSIZE(program_data));
	if (length != 0 && length < ARRAYSIZE(program_data))
		(void)_snwprintf_s(g_gui_log_default, ARRAYSIZE(g_gui_log_default),
			_TRUNCATE, L"%ls\\Scpfs\\Scpfs.log", program_data);
	return true;
}

static PCWSTR gui_value(const FSF_GUI_VALUE *values, size_t value_count, PCWSTR id)
{
	size_t i;
	for (i = 0; values != NULL && i < value_count; ++i) {
		if (values[i].id != NULL && wcscmp(values[i].id, id) == 0)
			return values[i].value != NULL ? values[i].value : L"";
	}
	return L"";
}

static BOOL gui_append_pair(FSF_GUI_ARGV *argv, PCWSTR option, PCWSTR value)
{
	return value != NULL && value[0] != L'\0' &&
		fsf_gui_argv_append(argv, option) && fsf_gui_argv_append(argv, value);
}

static BOOL gui_append_common(FSF_GUI_ARGV *argv, PCWSTR host, PCWSTR username,
	PCWSTR remote_root, PCWSTR known_hosts, PCWSTR identity,
	PCWSTR port_text, PCWSTR timeout_text)
{
	uint32_t port, timeout;
	WCHAR port_buffer[16], timeout_buffer[16];
	if (host == NULL || host[0] == L'\0' || username == NULL || username[0] == L'\0' ||
		remote_root == NULL || remote_root[0] != L'/' ||
		known_hosts == NULL || known_hosts[0] == L'\0' ||
		identity == NULL || identity[0] == L'\0' ||
		!parse_u32(port_text, 1, UINT16_MAX, &port) ||
		!parse_u32(timeout_text, 1, 300000, &timeout))
		return FALSE;
	_snwprintf_s(port_buffer, ARRAYSIZE(port_buffer), _TRUNCATE, L"%u", port);
	_snwprintf_s(timeout_buffer, ARRAYSIZE(timeout_buffer), _TRUNCATE, L"%u", timeout);
	return gui_append_pair(argv, L"--host", host) &&
		gui_append_pair(argv, L"--user", username) &&
		gui_append_pair(argv, L"--remote-root", remote_root) &&
		gui_append_pair(argv, L"--known-hosts", known_hosts) &&
		gui_append_pair(argv, L"--identity", identity) &&
		gui_append_pair(argv, L"--port", port_buffer) &&
		gui_append_pair(argv, L"--timeout-ms", timeout_buffer);
}

static BOOL scpfs_gui_build_argv(void *context, FSF_GUI_ACTION action,
	const FSF_GUI_VALUE *values, size_t value_count, PCWSTR stop_event_name,
	FSF_GUI_ARGV *argv)
{
	PCWSTR host, username, remote_root, mount, known_hosts, identity;
	PCWSTR port_text, timeout_text, command_timeout_text, cache_directory;
	PCWSTR cache_max_mib_text;
	PCWSTR service_name, log_file;
	uint32_t command_timeout, cache_max_mib;
	WCHAR command_timeout_buffer[16], cache_max_mib_buffer[16];
	(void)context;
	if (argv == NULL)
		return FALSE;
	if (action == FSF_GUI_ACTION_UNMOUNT)
		return TRUE;
	service_name = gui_value(values, value_count, L"service-name");
	if (service_name[0] == L'\0')
		service_name = L"Scpfs";
	if (action == FSF_GUI_ACTION_UNINSTALL)
		return fsf_gui_argv_append(argv, L"--uninstall") &&
			gui_append_pair(argv, L"--service-name", service_name);
	if (action != FSF_GUI_ACTION_MOUNT && action != FSF_GUI_ACTION_INSTALL &&
		action != FSF_GUI_ACTION_PROBE)
		return FALSE;
	host = gui_value(values, value_count, L"host");
	username = gui_value(values, value_count, L"user");
	remote_root = gui_value(values, value_count, L"remote-root");
	mount = gui_value(values, value_count, L"mount-drive");
	known_hosts = gui_value(values, value_count, L"known-hosts");
	identity = gui_value(values, value_count, L"identity");
	port_text = gui_value(values, value_count, L"port");
	timeout_text = gui_value(values, value_count, L"timeout-ms");
	command_timeout_text = gui_value(values, value_count, L"command-timeout-ms");
	cache_directory = gui_value(values, value_count, L"cache-dir");
	cache_max_mib_text = gui_value(values, value_count, L"cache-max-mib");
	log_file = gui_value(values, value_count, L"log-file");
	if (!gui_append_common(argv, host, username, remote_root,
		known_hosts, identity, port_text, timeout_text))
		return FALSE;
	if (action == FSF_GUI_ACTION_PROBE)
		return fsf_gui_argv_append(argv, L"--probe");
	if (!parse_u32(command_timeout_text, 1, 540000, &command_timeout) ||
		!parse_u32(cache_max_mib_text, 0, 16384, &cache_max_mib))
		return FALSE;
	_snwprintf_s(command_timeout_buffer, ARRAYSIZE(command_timeout_buffer),
		_TRUNCATE, L"%u", command_timeout);
	_snwprintf_s(cache_max_mib_buffer, ARRAYSIZE(cache_max_mib_buffer),
		_TRUNCATE, L"%u", cache_max_mib);
	if (cache_directory[0] != L'\0' &&
		!gui_append_pair(argv, L"--cache-dir", cache_directory))
		return FALSE;
	if (action == FSF_GUI_ACTION_MOUNT) {
		return mount != NULL && mount[0] != L'\0' &&
			stop_event_name != NULL && stop_event_name[0] != L'\0' &&
			fsf_gui_argv_append(argv, L"--mount") &&
			fsf_gui_argv_append(argv, mount) &&
			gui_append_pair(argv, L"--command-timeout-ms", command_timeout_buffer) &&
			gui_append_pair(argv, L"--cache-max-mib", cache_max_mib_buffer) &&
			fsf_gui_argv_append(argv, L"--stop-event") &&
			fsf_gui_argv_append(argv, stop_event_name);
	}
	return mount != NULL && mount[0] != L'\0' &&
		log_file != NULL && log_file[0] != L'\0' &&
		fsf_gui_argv_append(argv, L"--install") &&
		fsf_gui_argv_append(argv, L"--mount") &&
		fsf_gui_argv_append(argv, mount) &&
		gui_append_pair(argv, L"--command-timeout-ms", command_timeout_buffer) &&
		gui_append_pair(argv, L"--cache-max-mib", cache_max_mib_buffer) &&
		gui_append_pair(argv, L"--service-name", service_name) &&
		gui_append_pair(argv, L"--log-file", log_file);
}

static const WCHAR g_gui_identity_filter[] =
	L"OpenSSH private key\0*\0All files\0*.*\0\0";
static const WCHAR g_gui_known_hosts_filter[] =
	L"OpenSSH known_hosts\0*\0All files\0*.*\0\0";

static FSF_GUI_FIELD g_gui_fields[] = {
	{ L"host", L"SSH 主机名或地址", FSF_GUI_FIELD_TEXT, L"", NULL, 0, NULL, FALSE },
	{ L"user", L"SSH 用户名", FSF_GUI_FIELD_TEXT, L"", NULL, 0, NULL, FALSE },
	{ L"port", L"SSH 端口", FSF_GUI_FIELD_TEXT, L"22", NULL, 0, NULL, FALSE },
	{ L"remote-root", L"远程 Linux 目录", FSF_GUI_FIELD_TEXT, L"/", NULL, 0, NULL, FALSE },
	{ L"mount-drive", L"本地挂载盘符", FSF_GUI_FIELD_TEXT, L"X:", NULL, 0, NULL, FALSE },
	{ L"identity", L"Ed25519 私钥文件路径", FSF_GUI_FIELD_FILE,
		g_gui_identity_default, NULL, 0, g_gui_identity_filter, FALSE },
	{ L"known-hosts", L"严格校验的 known_hosts 文件", FSF_GUI_FIELD_FILE,
		g_gui_known_hosts_default, NULL, 0, g_gui_known_hosts_filter, FALSE },
	{ L"timeout-ms", L"SSH 操作超时（毫秒）", FSF_GUI_FIELD_TEXT, L"15000", NULL, 0, NULL, FALSE },
	{ L"command-timeout-ms", L"远程命令超时（毫秒）", FSF_GUI_FIELD_TEXT, L"60000", NULL, 0, NULL, FALSE },
	{ L"cache-dir", L"本地缓存目录（空白使用系统临时目录）", FSF_GUI_FIELD_DIRECTORY,
		L"", NULL, 0, NULL, FALSE },
	{ L"service-name", L"Windows 服务名", FSF_GUI_FIELD_TEXT, L"Scpfs", NULL, 0, NULL, FALSE },
	{ L"log-file", L"服务日志文件", FSF_GUI_FIELD_FILE, g_gui_log_default,
		NULL, 0, NULL, FALSE },
	{ L"cache-max-mib", L"读取缓存上限（MiB，0=不限）", FSF_GUI_FIELD_TEXT,
		L"0", NULL, 0, NULL, FALSE }
};

static const FSF_GUI_ACTION_DESC g_gui_actions[] = {
	{ FSF_GUI_ACTION_MOUNT, L"挂载" },
	{ FSF_GUI_ACTION_UNMOUNT, L"卸载临时挂载" },
	{ FSF_GUI_ACTION_INSTALL, L"安装并启动服务" },
	{ FSF_GUI_ACTION_UNINSTALL, L"卸载服务" },
	{ FSF_GUI_ACTION_PROBE, L"测试连接" }
};

static int run_gui(void)
{
	FSF_GUI_CONFIG config;
	if (!initialize_gui_defaults()) {
		fwprintf(stderr, L"GUI: cannot resolve the current user's profile directory.\n");
		return 1;
	}
	memset(&config, 0, sizeof(config));
	config.struct_size = sizeof(config);
	config.abi_version = FSF_GUI_ABI_VERSION;
	config.title = L"SCPFS 远程文件系统";
	config.fields = g_gui_fields;
	config.field_count = ARRAYSIZE(g_gui_fields);
	config.actions = g_gui_actions;
	config.action_count = ARRAYSIZE(g_gui_actions);
	config.action_timeout_ms = 180000;
	config.build_argv = scpfs_gui_build_argv;
	return fsf_gui_run(&config);
}

int wmain(int argc, wchar_t **argv)
{
	CLI_OPTIONS options;
	const wchar_t *mount_drive;
	bool help;
	if (argc == 1 || (argc > 1 && wcscmp(argv[1], L"--gui") == 0))
		return run_gui();
	if (argc == 2 && wcscmp(argv[1], L"--version") == 0) {
		wprintf(L"scpfs %ls\n", L"0.1.0");
		return 0;
	}
	if (!parse_options(argc, argv, &options, &mount_drive, &help)) {
		print_usage(stderr);
		return 2;
	}
	if (help) {
		print_usage(stdout);
		return 0;
	}
	if (options.uninstall)
		return uninstall_service(&options);
	if (options.service)
		return run_service(&options);
	if (!resolve_identity(&options)) {
		if (options.identity == NULL)
			fwprintf(stderr, L"identity: cannot resolve the Windows profile directory or default key path\n");
		return 2;
	}
	if (options.probe)
		return run_probe(&options);
	if (options.install)
		return install_service(&options);
	if (options.stop_event_name != NULL)
		g_stop_event = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE,
			options.stop_event_name);
	else
		g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (g_stop_event == NULL) {
		fwprintf(stderr, L"mount: cannot open or create stop event (error %lu)\n",
			GetLastError());
		return 1;
	}
	SetConsoleCtrlHandler(console_handler, TRUE);
	{
		int result = run_mount(&options, mount_drive);
		SetConsoleCtrlHandler(console_handler, FALSE);
		CloseHandle(g_stop_event);
		g_stop_event = NULL;
		return result;
	}
}
