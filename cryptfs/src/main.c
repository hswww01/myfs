#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "cryptfs_backend.h"
#include "cryptfs_crypto.h"
#include "cryptfs_driver.h"
#include "cryptfs_store.h"
#include "fs_frontend_gui.h"

typedef enum APP_MODE { APP_MOUNT, APP_CHECK, APP_COMPACT, APP_HELP } APP_MODE;
typedef struct APP_OPTIONS {
	PCWSTR container, mount_point, stop_event;
	APP_MODE mode;
	uint64_t capacity;
	int compression_level;
	BOOL create_new, password_stdin;
} APP_OPTIONS;
static HANDLE g_quit_event;
static BOOL g_allocated_console;

#if defined(CRYPTFS_CLI_TESTING)
#define CRYPTFS_CLI_TEST_UNUSED __attribute__((unused))
#else
#define CRYPTFS_CLI_TEST_UNUSED
#endif

static BOOL dispatcher_result_success(NTSTATUS status, BOOL explicit_stop_request)
{
	return NT_SUCCESS(status) ||
		(explicit_stop_request && status == STATUS_CANCELLED);
}

static BOOL WINAPI console_control_handler(DWORD type)
{
	if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT ||
		type == CTRL_CLOSE_EVENT || type == CTRL_SHUTDOWN_EVENT) {
		if (g_quit_event != NULL) SetEvent(g_quit_event);
		return TRUE;
	}
	return FALSE;
}

static const FSF_GUI_FIELD g_gui_fields[] = {
	{ L"container", L"加密容器文件", FSF_GUI_FIELD_FILE, L"", NULL, 0,
		L"容器文件\0*.cfs;*.cryptfs\0所有文件\0*.*\0\0", TRUE },
	{ L"mount", L"挂载盘符", FSF_GUI_FIELD_TEXT, L"X:", NULL, 0, NULL, TRUE },
	{ L"create", L"创建新容器", FSF_GUI_FIELD_BOOLEAN, L"false", NULL, 0, NULL, FALSE },
	{ L"capacity", L"逻辑容量（字节）", FSF_GUI_FIELD_TEXT, L"1099511627776", NULL, 0, NULL, FALSE },
	{ L"compression", L"压缩级别（1–22）", FSF_GUI_FIELD_TEXT, L"3", NULL, 0, NULL, TRUE },
	{ L"password", L"密码", FSF_GUI_FIELD_PASSWORD, L"", NULL, 0, NULL, TRUE }
};
static const FSF_GUI_ACTION_DESC g_gui_actions[] = {
	{ FSF_GUI_ACTION_MOUNT, L"解锁并挂载" }
};

static PCWSTR gui_value(const FSF_GUI_VALUE *values, size_t count, PCWSTR id)
{
	size_t i;
	for (i = 0; i < count; ++i)
		if (_wcsicmp(values[i].id, id) == 0) return values[i].value;
	return NULL;
}

static BOOL parse_u64(PCWSTR text, uint64_t *value)
{
	uint64_t result = 0;
	PCWSTR p;
	if (text == NULL || *text == L'\0' || value == NULL) return FALSE;
	for (p = text; *p; ++p) {
		unsigned digit;
		if (*p < L'0' || *p > L'9') return FALSE;
		digit = (unsigned)(*p - L'0');
		if (result > (UINT64_MAX - digit) / 10) return FALSE;
		result = result * 10 + digit;
	}
	*value = result;
	return result != 0;
}
static BOOL parse_level(PCWSTR text, int *level);

static BOOL parse_level(PCWSTR text, int *level)
{
	uint64_t parsed;
	if (!parse_u64(text, &parsed) || parsed > 22) return FALSE;
	*level = (int)parsed;
	return TRUE;
}

static BOOL append_pair(FSF_GUI_ARGV *argv, PCWSTR option, PCWSTR value)
{
	return value != NULL && fsf_gui_argv_append(argv, option) &&
		fsf_gui_argv_append(argv, value);
}

static BOOL gui_build_argv(void *context, FSF_GUI_ACTION action,
	const FSF_GUI_VALUE *values, size_t count, PCWSTR stop_event_name,
	FSF_GUI_ARGV *argv)
{
	PCWSTR container = gui_value(values, count, L"container");
	PCWSTR mount = gui_value(values, count, L"mount");
	PCWSTR create = gui_value(values, count, L"create");
	PCWSTR capacity = gui_value(values, count, L"capacity");
	PCWSTR compression = gui_value(values, count, L"compression");
	PCWSTR password = gui_value(values, count, L"password");
	int level;
	uint64_t parsed_capacity;
	int utf8_size;
	int chars;
	BYTE *secret = NULL;
	BOOL ok = FALSE;
	(void)context;
	if (action != FSF_GUI_ACTION_MOUNT || container == NULL || *container == L'\0' ||
		mount == NULL || *mount == L'\0' || password == NULL || *password == L'\0' ||
		compression == NULL || !parse_level(compression, &level) ||
		stop_event_name == NULL || *stop_event_name == L'\0')
		return FALSE;
	if (create != NULL && (_wcsicmp(create, L"true") == 0 || _wcsicmp(create, L"1") == 0)) {
		if (!parse_u64(capacity, &parsed_capacity)) return FALSE;
	}
	chars = (int)wcslen(password);
	utf8_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, password,
		chars, NULL, 0, NULL, NULL);
	if (utf8_size <= 0 || utf8_size > 1024) return FALSE;
	secret = (BYTE *)malloc((size_t)utf8_size + 1);
	if (secret == NULL) return FALSE;
	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, password, chars,
		(LPSTR)secret, utf8_size, NULL, NULL) != utf8_size) goto done;
	if (!cf_password_valid(secret, (size_t)utf8_size)) goto done;
	secret[utf8_size] = '\n';
	if (!fsf_gui_argv_append(argv, L"--container") ||
		!fsf_gui_argv_append(argv, container) ||
		!fsf_gui_argv_append(argv, L"--mount") ||
		!fsf_gui_argv_append(argv, mount) ||
		!fsf_gui_argv_append(argv, L"--compression-level") ||
		!fsf_gui_argv_append(argv, compression)) goto done;
	if (create != NULL && (_wcsicmp(create, L"true") == 0 || _wcsicmp(create, L"1") == 0)) {
		if (!fsf_gui_argv_append(argv, L"--create") ||
			!append_pair(argv, L"--capacity", capacity)) goto done;
	}
	if (!fsf_gui_argv_append(argv, L"--stop-event") ||
		!fsf_gui_argv_append(argv, stop_event_name) ||
		!fsf_gui_argv_append(argv, L"--password-stdin") ||
		!fsf_gui_argv_set_stdin(argv, secret, (size_t)utf8_size + 1)) goto done;
	ok = TRUE;
done:
	SecureZeroMemory(secret, (size_t)utf8_size + 1);
	free(secret);
	return ok;
}

static int CRYPTFS_CLI_TEST_UNUSED run_gui(void)
{
	FSF_GUI_CONFIG config;
	memset(&config, 0, sizeof(config));
	config.struct_size = sizeof(config);
	config.abi_version = FSF_GUI_ABI_VERSION;
	config.title = L"CryptFS 加密文件系统";
	config.fields = g_gui_fields;
	config.field_count = _countof(g_gui_fields);
	config.actions = g_gui_actions;
	config.action_count = _countof(g_gui_actions);
	config.action_timeout_ms = 0;
	config.build_argv = gui_build_argv;
	return fsf_gui_run(&config);
}

static BOOL parse_options(int argc, WCHAR **argv, APP_OPTIONS *options)
{
	int i;
	BOOL capacity_seen = FALSE, compression_seen = FALSE;
	memset(options, 0, sizeof(*options));
	options->mode = APP_MOUNT;
	options->capacity = CF_DEFAULT_CAPACITY;
	options->compression_level = 3;
	for (i = 1; i < argc; ++i) {
		PCWSTR arg = argv[i];
		if (_wcsicmp(arg, L"--help") == 0 || _wcsicmp(arg, L"-h") == 0) {
			options->mode = APP_HELP;
		} else if (_wcsicmp(arg, L"--check") == 0) {
			if (options->mode != APP_MOUNT) return FALSE;
			options->mode = APP_CHECK;
		} else if (_wcsicmp(arg, L"--compact") == 0) {
			if (options->mode != APP_MOUNT) return FALSE;
			options->mode = APP_COMPACT;
		} else if (_wcsicmp(arg, L"--create") == 0) {
			options->create_new = TRUE;
		} else if (_wcsicmp(arg, L"--password-stdin") == 0) {
			options->password_stdin = TRUE;
		} else if (_wcsicmp(arg, L"--container") == 0 && i + 1 < argc) {
			options->container = argv[++i];
		} else if (_wcsicmp(arg, L"--mount") == 0 && i + 1 < argc) {
			options->mount_point = argv[++i];
		} else if (_wcsicmp(arg, L"--stop-event") == 0 && i + 1 < argc) {
			options->stop_event = argv[++i];
		} else if (_wcsicmp(arg, L"--capacity") == 0 && i + 1 < argc) {
			if (!parse_u64(argv[++i], &options->capacity)) return FALSE;
			capacity_seen = TRUE;
		} else if (_wcsicmp(arg, L"--compression-level") == 0 && i + 1 < argc) {
			if (!parse_level(argv[++i], &options->compression_level)) return FALSE;
			compression_seen = TRUE;
		} else {
			return FALSE;
		}
	}
	if (options->mode == APP_HELP) return argc == 2;
	if (options->container == NULL || *options->container == L'\0') return FALSE;
	if (capacity_seen && !options->create_new) return FALSE;
	if (options->create_new && options->mode != APP_MOUNT) return FALSE;
	if (compression_seen && options->mode != APP_MOUNT) return FALSE;
	if (options->mode == APP_MOUNT) {
		if (options->mount_point == NULL || *options->mount_point == L'\0') return FALSE;
	} else if (options->mount_point != NULL || options->stop_event != NULL) return FALSE;
	if (options->stop_event != NULL && *options->stop_event == L'\0') return FALSE;
	return TRUE;
}

static BOOL read_password_stdin(uint8_t buffer[1024], size_t *length)
{
	BYTE input[1027];
	DWORD total = 0;
	HANDLE stream = GetStdHandle(STD_INPUT_HANDLE);
	if (stream == NULL || stream == INVALID_HANDLE_VALUE) return FALSE;
	for (;;) {
		DWORD got = 0;
		DWORD room = (DWORD)sizeof(input) - total;
		if (room == 0) {
			BYTE overflow = 0;
			if (!ReadFile(stream, &overflow, 1, &got, NULL)) {
				DWORD error = GetLastError();
				SecureZeroMemory(&overflow, sizeof(overflow));
				if (error == ERROR_BROKEN_PIPE) break;
				SecureZeroMemory(input, sizeof(input));
				return FALSE;
			}
			if (got == 0) {
				SecureZeroMemory(&overflow, sizeof(overflow));
				break;
			}
			SecureZeroMemory(&overflow, sizeof(overflow));
			SecureZeroMemory(input, sizeof(input));
			return FALSE;
		}
		if (!ReadFile(stream, input + total, room, &got, NULL)) {
			DWORD error = GetLastError();
			if (error == ERROR_BROKEN_PIPE) break;
			SecureZeroMemory(input, sizeof(input));
			return FALSE;
		}
		if (got == 0) break;
		total += got;
	}
	if (total != 0 && input[total - 1] == '\n') {
		--total;
		if (total != 0 && input[total - 1] == '\r') --total;
	}
	if (total == 0 || total > 1024 || memchr(input, '\r', total) != NULL ||
		memchr(input, '\n', total) != NULL) {
		SecureZeroMemory(input, sizeof(input));
		return FALSE;
	}
	memcpy(buffer, input, total);
	*length = total;
	SecureZeroMemory(input, sizeof(input));
	return cf_password_valid(buffer, *length);
}

static BOOL read_password_console(uint8_t buffer[1024], size_t *length)
{
	HANDLE input, output;
	DWORD old_mode, new_mode, read = 0;
	WCHAR wide[1027];
	int bytes;
	BOOL allocated = FALSE, ok = FALSE;
	if (GetConsoleWindow() == NULL) allocated = AllocConsole();
	if (allocated) g_allocated_console = TRUE;
	input = GetStdHandle(STD_INPUT_HANDLE);
	output = GetStdHandle(STD_OUTPUT_HANDLE);
	if (input == NULL || output == NULL || !GetConsoleMode(input, &old_mode)) goto done;
	if (!WriteConsoleW(output, L"Password: ", 10, &read, NULL)) goto done;
	new_mode = old_mode & ~ENABLE_ECHO_INPUT;
	if (!SetConsoleMode(input, new_mode)) goto done;
	if (!ReadConsoleW(input, wide, (DWORD)_countof(wide) - 1, &read, NULL)) {
		(void)SetConsoleMode(input, old_mode);
		goto done;
	}
	(void)SetConsoleMode(input, old_mode);
	(void)WriteConsoleW(output, L"\r\n", 2, &read, NULL);
	if (read != 0 && wide[read - 1] == L'\n') {
		--read;
		if (read != 0 && wide[read - 1] == L'\r') --read;
	}
	wide[read] = L'\0';
	if (read == 0 || wmemchr(wide, L'\r', read) != NULL || wmemchr(wide, L'\n', read) != NULL)
		goto done;
	bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, (int)read,
		(LPSTR)buffer, 1024, NULL, NULL);
	if (bytes <= 0 || bytes > 1024) goto done;
	*length = (size_t)bytes;
	ok = cf_password_valid(buffer, *length);
done:
	SecureZeroMemory(wide, sizeof(wide));
	return ok;
}

static BOOL read_password(BOOL from_stdin, uint8_t password[1024], size_t *length)
{
	*length = 0;
	return from_stdin ? read_password_stdin(password, length) :
		read_password_console(password, length);
}

static void CRYPTFS_CLI_TEST_UNUSED print_help(void)
{
	wprintf(L"CryptFS v1\n\n"
		L"  cryptfs.exe                         Open the configuration window\n"
		L"  --container PATH --mount X: [--create --capacity BYTES]\n"
		L"      [--compression-level 3] [--password-stdin]\n"
		L"  --container PATH --check [--password-stdin]\n"
		L"  --container PATH --compact [--password-stdin]\n\n"
		L"Without --password-stdin, a hidden interactive console prompt is used.\n");
}

static int CRYPTFS_CLI_TEST_UNUSED run_command(const APP_OPTIONS *options)
{
	uint8_t password[1024] = { 0 };
	size_t password_length = 0;
	CF_OPTIONS store_options;
	CF_STORE *store = NULL;
	CF_RESULT store_result;
	CF_STATS stats;
	CRYPTFS_BACKEND *backend = NULL;
	HANDLE stop_event = NULL;
	NTSTATUS status;
	int exit_code = 1;
	BOOL explicit_stop_request = FALSE;
	if (!read_password(options->password_stdin, password, &password_length)) {
		fwprintf(stderr, L"Invalid or unavailable password input.\n");
		SecureZeroMemory(password, sizeof(password));
		return 2;
	}
	memset(&store_options, 0, sizeof(store_options));
	store_options.container = options->container;
	store_options.capacity = options->capacity;
	store_options.compression_level = options->compression_level;
	store_options.create_new = !!options->create_new;
	store_options.background_compaction = options->mode != APP_CHECK;
	store_result = cf_store_open(&store_options, password, password_length, &store);
	SecureZeroMemory(password, sizeof(password));
	password_length = 0;
	if (store_result != CF_OK) {
		fprintf(stderr, "Cannot open container: %s\n", cf_result_text(store_result));
		goto done;
	}
	if (options->mode == APP_CHECK) {
		store_result = cf_store_stats(store, &stats);
		if (store_result == CF_OK) {
			wprintf(L"Container unlocked and validated. Capacity=%llu Free=%llu EOF=%llu LivePages=%llu\n",
				(unsigned long long)stats.capacity, (unsigned long long)stats.free_bytes,
				(unsigned long long)stats.eof_bytes, (unsigned long long)stats.live_pages);
			exit_code = 0;
		} else fprintf(stderr, "Cannot query container: %s\n", cf_result_text(store_result));
		goto done;
	}
	if (options->mode == APP_COMPACT) {
		store_result = cf_store_wait_idle(store, INFINITE);
		if (store_result == CF_OK) store_result = cf_store_flush(store);
		if (store_result == CF_OK) store_result = cf_store_stats(store, &stats);
		if (store_result == CF_OK) {
			wprintf(L"Compaction idle. EOF=%llu LivePages=%llu Moves=%llu\n",
				(unsigned long long)stats.eof_bytes, (unsigned long long)stats.live_pages,
				(unsigned long long)stats.compact_moves);
			exit_code = 0;
		} else fprintf(stderr, "Compaction failed: %s\n", cf_result_text(store_result));
		goto done;
	}
	if (options->stop_event != NULL) {
		stop_event = OpenEventW(SYNCHRONIZE, FALSE, options->stop_event);
		if (stop_event == NULL) {
			fwprintf(stderr, L"Cannot open stop event (Win32 %lu).\n", GetLastError());
			goto done;
		}
	}
	status = cryptfs_backend_create(store, &backend);
	if (!NT_SUCCESS(status)) goto winfsp_error;
	status = cryptfs_backend_mount(backend, options->mount_point);
	if (!NT_SUCCESS(status)) goto winfsp_error;
	status = cryptfs_backend_start(backend);
	if (!NT_SUCCESS(status)) goto winfsp_error;
	wprintf(L"CryptFS mounted at %ls\n", options->mount_point);
	/* stdout is fully buffered on a pipe; the GUI waits for this line. */
	fflush(stdout);
	{
		HANDLE stopped = cryptfs_backend_stopped_event(backend);
		HANDLE wait_handles[3];
		DWORD wait_count = 0;
		DWORD wait_result;
		if (stopped == NULL) goto done;
		g_quit_event = CreateEventW(NULL, TRUE, FALSE, NULL);
		if (g_quit_event == NULL) goto done;
		(void)SetConsoleCtrlHandler(console_control_handler, TRUE);
		if (stop_event != NULL) wait_handles[wait_count++] = stop_event;
		wait_handles[wait_count++] = g_quit_event;
		wait_handles[wait_count++] = stopped;
		wait_result = WaitForMultipleObjects(wait_count, wait_handles, FALSE, INFINITE);
		if (wait_result == WAIT_OBJECT_0 ||
			(stop_event != NULL && wait_result == WAIT_OBJECT_0 + 1)) {
			explicit_stop_request = TRUE;
			cryptfs_backend_stop(backend);
		} else if (wait_result != WAIT_OBJECT_0 + wait_count - 1) {
			fwprintf(stderr, L"Mount wait failed (Win32 %lu).\n", GetLastError());
			goto done;
		}
		(void)SetConsoleCtrlHandler(console_control_handler, FALSE);
		CloseHandle(g_quit_event); g_quit_event = NULL;
		status = cryptfs_backend_dispatcher_result(backend);
		if (!dispatcher_result_success(status, explicit_stop_request)) goto winfsp_error;
		status = cryptfs_backend_flush(backend);
		if (!NT_SUCCESS(status)) goto winfsp_error;
	}
	exit_code = 0;
	goto done;
winfsp_error:
	fwprintf(stderr, L"WinFsp operation failed (NTSTATUS 0x%08lX).\n", (unsigned long)status);
done:
	if (g_quit_event != NULL) {
		(void)SetConsoleCtrlHandler(console_control_handler, FALSE);
		CloseHandle(g_quit_event);
		g_quit_event = NULL;
	}
	if (backend != NULL) {
		cryptfs_backend_stop(backend);
		if (cryptfs_backend_flush(backend) != STATUS_SUCCESS) exit_code = 1;
		cryptfs_backend_destroy(backend);
	}
	if (store != NULL) cf_store_close(store);
	if (stop_event != NULL) CloseHandle(stop_event);
	SecureZeroMemory(password, sizeof(password));
	return exit_code;
}

#if defined(CRYPTFS_CLI_TESTING)
BOOL cryptfs_test_parse_options(int argc, WCHAR **argv)
{
	APP_OPTIONS options;
	return parse_options(argc, argv, &options);
}
BOOL cryptfs_test_dispatcher_result_success(NTSTATUS status, BOOL explicit_stop_request)
{
	return dispatcher_result_success(status, explicit_stop_request);
}
#else
int wmain(int argc, WCHAR **argv)
{
	int result;
	APP_OPTIONS options;
	if (argc == 1 || (argc > 1 && _wcsicmp(argv[1], L"--gui") == 0)) {
		return run_gui();
	}
	if (!parse_options(argc, argv, &options)) {
		fwprintf(stderr, L"Invalid command line. Use --help.\n");
		return 2;
	}
	if (options.mode == APP_HELP) {
		print_help();
		result = 0;
	} else result = run_command(&options);
	if (g_allocated_console) {
		FreeConsole();
		g_allocated_console = FALSE;
	}
	return result;
}
#endif
