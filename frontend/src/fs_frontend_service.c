#include "fs_frontend.h"

#include <sddl.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

struct FSF_SERVICE {
	FSF_SERVICE_RUN_CONFIG config;
	SERVICE_STATUS_HANDLE status_handle;
	SERVICE_STATUS status;
	HANDLE stop_event;
	HANDLE log_handle;
	SRWLOCK state_lock;
	SRWLOCK log_lock;
	BOOL stop_requested;
	FSF_SERVICE_EXIT result;
};

/* A Windows own-process service hosts exactly one service for its lifetime. */
static FSF_SERVICE g_service;
static LONG g_service_run_claimed;

static BOOL fsf_valid_contract(uint32_t size, uint32_t expected, uint32_t version)
{
	return size == expected && version == FS_FRONTEND_ABI_VERSION;
}

static BOOL fsf_absolute_path(PCWSTR path)
{
	return path != NULL && ((wcslen(path) >= 3 && path[1] == L':' &&
		(path[2] == L'\\' || path[2] == L'/')) ||
		(path[0] == L'\\' && path[1] == L'\\'));
}

static DWORD fsf_log_security(PCWSTR sid_text, PSECURITY_DESCRIPTOR *descriptor)
{
	PSID sid = NULL;
	PWSTR canonical_sid = NULL;
	PWSTR sddl = NULL;
	DWORD error = ERROR_SUCCESS;
	size_t length;
	*descriptor = NULL;
	if (sid_text != NULL && *sid_text != L'\0') {
		if (!ConvertStringSidToSidW(sid_text, &sid))
			return GetLastError();
		if (!IsValidSid(sid) || !ConvertSidToStringSidW(sid, &canonical_sid)) {
			error = ERROR_INVALID_SID;
			goto done;
		}
	}
	length = 80 + (canonical_sid != NULL ? wcslen(canonical_sid) : 0);
	sddl = (PWSTR)calloc(length, sizeof(WCHAR));
	if (sddl == NULL) {
		error = ERROR_NOT_ENOUGH_MEMORY;
		goto done;
	}
	if (canonical_sid != NULL)
		swprintf_s(sddl, length, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)", canonical_sid);
	else
		wcscpy_s(sddl, length, L"D:P(A;OICI;FA;;;SY)");
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,
		SDDL_REVISION_1, descriptor, NULL))
		error = GetLastError();
done:
	free(sddl);
	if (canonical_sid != NULL) LocalFree(canonical_sid);
	if (sid != NULL) LocalFree(sid);
	return error;
}

/* Drive roots and some existing ancestors report ACCESS_DENIED rather than ALREADY_EXISTS. */
static DWORD fsf_ensure_directory(PCWSTR path, SECURITY_ATTRIBUTES *attributes)
{
	DWORD error, existing;
	if (CreateDirectoryW(path, attributes)) return ERROR_SUCCESS;
	error = GetLastError();
	if (error == ERROR_ALREADY_EXISTS) return ERROR_SUCCESS;
	existing = GetFileAttributesW(path);
	if (existing != INVALID_FILE_ATTRIBUTES && (existing & FILE_ATTRIBUTE_DIRECTORY) != 0)
		return ERROR_SUCCESS;
	return error;
}

static DWORD fsf_prepare_log(PCWSTR path, PCWSTR sid, HANDLE *handle_out)
{
	PSECURITY_DESCRIPTOR descriptor = NULL;
	SECURITY_ATTRIBUTES attributes;
	PWSTR parent = NULL;
	PWSTR last_separator;
	HANDLE handle = INVALID_HANDLE_VALUE;
	DWORD error;
	size_t index, length, parent_length, first_component;
	*handle_out = INVALID_HANDLE_VALUE;
	if (!fsf_absolute_path(path)) return ERROR_INVALID_NAME;
	error = fsf_log_security(sid, &descriptor);
	if (error != ERROR_SUCCESS) return error;
	attributes.nLength = sizeof(attributes);
	attributes.lpSecurityDescriptor = descriptor;
	attributes.bInheritHandle = FALSE;
	length = wcslen(path);
	parent = (PWSTR)calloc(length + 1, sizeof(WCHAR));
	if (parent == NULL) { error = ERROR_NOT_ENOUGH_MEMORY; goto done; }
	wcscpy_s(parent, length + 1, path);
	for (index = 0; index < length; ++index)
		if (parent[index] == L'/') parent[index] = L'\\';
	last_separator = wcsrchr(parent, L'\\');
	if (last_separator == NULL || last_separator[1] == L'\0') {
		error = ERROR_INVALID_NAME;
		goto done;
	}
	if (last_separator == parent + 2 && parent[1] == L':')
		last_separator[1] = L'\0';
	else
		*last_separator = L'\0';
	parent_length = wcslen(parent);
	first_component = 3;
	if (parent[0] == L'\\' && parent[1] == L'\\') {
		PWSTR server_end = wcschr(parent + 2, L'\\');
		PWSTR share_end;
		if (server_end == NULL || server_end[1] == L'\0') { error = ERROR_INVALID_NAME; goto done; }
		share_end = wcschr(server_end + 1, L'\\');
		first_component = share_end != NULL ? (size_t)(share_end - parent) + 1 : parent_length;
	}
	/* Existing ancestors retain their ACLs; only newly created directories use ours. */
	for (index = first_component; index < parent_length; ++index) {
		if (parent[index] == L'\\') {
			parent[index] = L'\0';
			error = fsf_ensure_directory(parent, &attributes);
			parent[index] = L'\\';
			if (error != ERROR_SUCCESS) goto done;
		}
	}
	error = fsf_ensure_directory(parent, &attributes);
	if (error != ERROR_SUCCESS) goto done;
	handle = CreateFileW(path, FILE_APPEND_DATA | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE,
		&attributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) { error = GetLastError(); goto done; }
	if (!SetKernelObjectSecurity(handle,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor)) {
		error = GetLastError();
		goto done;
	}
	*handle_out = handle;
	handle = INVALID_HANDLE_VALUE;
	error = ERROR_SUCCESS;
done:
	if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
	free(parent);
	LocalFree(descriptor);
	return error;
}

void fsf_service_log(FSF_SERVICE *service, DWORD level, DWORD status, PCWSTR message)
{
	SYSTEMTIME now;
	WCHAR line[2048];
	char utf8[8192];
	DWORD written;
	int length;
	if (service == NULL || message == NULL) return;
	GetSystemTime(&now);
	/* swprintf_s aborts the process on truncation; long messages (paths) must not. */
	if (_snwprintf_s(line, _countof(line) - 2, _TRUNCATE,
		L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ level=%lu status=0x%08lX %s",
		now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
		now.wMilliseconds, level, status, message) < 0 && line[0] == L'\0') return;
	wcscat_s(line, _countof(line), L"\r\n");
	length = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, sizeof(utf8), NULL, NULL);
	if (length <= 1) return;
	AcquireSRWLockExclusive(&service->log_lock);
	if (service->log_handle != INVALID_HANDLE_VALUE)
		(void)WriteFile(service->log_handle, utf8, (DWORD)(length - 1), &written, NULL);
	ReleaseSRWLockExclusive(&service->log_lock);
}

static BOOL fsf_report_locked(FSF_SERVICE *service, DWORD state, DWORD error,
	DWORD specific_error, DWORD wait_hint)
{
	service->status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	service->status.dwCurrentState = state;
	service->status.dwControlsAccepted = state == SERVICE_RUNNING ?
		SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
		(service->config.accept_preshutdown ? SERVICE_ACCEPT_PRESHUTDOWN : 0) : 0;
	service->status.dwWin32ExitCode = error;
	service->status.dwServiceSpecificExitCode = specific_error;
	service->status.dwWaitHint = wait_hint;
	if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
		++service->status.dwCheckPoint;
	else service->status.dwCheckPoint = 0;
	return SetServiceStatus(service->status_handle, &service->status);
}

static DWORD WINAPI fsf_service_control(DWORD control, DWORD event_type,
	PVOID event_data, PVOID context)
{
	FSF_SERVICE *service = (FSF_SERVICE *)context;
	(void)event_type;
	(void)event_data;
	AcquireSRWLockExclusive(&service->state_lock);
	if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN ||
		control == SERVICE_CONTROL_PRESHUTDOWN) {
		service->stop_requested = TRUE;
		if (service->stop_event != NULL) SetEvent(service->stop_event);
		if (service->status.dwCurrentState != SERVICE_STOPPED) {
			(void)fsf_report_locked(service, SERVICE_STOP_PENDING, ERROR_SUCCESS, 0, 120000);
		}
	} else if (control == SERVICE_CONTROL_INTERROGATE) {
		(void)SetServiceStatus(service->status_handle, &service->status);
	} else {
		ReleaseSRWLockExclusive(&service->state_lock);
		return ERROR_CALL_NOT_IMPLEMENTED;
	}
	ReleaseSRWLockExclusive(&service->state_lock);
	return ERROR_SUCCESS;
}

/*
 * SCM launched processes do not necessarily have usable CRT descriptors for
 * stdout/stderr. Reopening the protected log by path also fails under some
 * service configurations while its append-only handle is already held. Make
 * CRT descriptors from duplicates of the handle that was ACL-checked above.
 */
static int fsf_redirect_service_output(FSF_SERVICE *service, DWORD *win32_error)
{
	HANDLE duplicate = INVALID_HANDLE_VALUE;
	intptr_t os_handle;
	int descriptor, redirect_descriptor, temporary[4], temporary_count = 0;
	int crt_error, index, stdout_fd, stderr_fd;
	FILE *stream = NULL;
	unsigned long dos_error = ERROR_SUCCESS;
	*win32_error = ERROR_SUCCESS;
	/* GUI/service subsystem startup can leave the CRT FILE objects unbound. */
	crt_error = _wfreopen_s(&stream, L"NUL", L"w", stdout);
	if (crt_error != 0) {
		if (_get_doserrno(&dos_error) == 0) *win32_error = (DWORD)dos_error;
		return crt_error;
	}
	crt_error = _wfreopen_s(&stream, L"NUL", L"w", stderr);
	if (crt_error != 0) {
		if (_get_doserrno(&dos_error) == 0) *win32_error = (DWORD)dos_error;
		return crt_error;
	}
	stdout_fd = _fileno(stdout);
	stderr_fd = _fileno(stderr);
	if (stdout_fd < 0 || stderr_fd < 0) return EBADF;
	if (!DuplicateHandle(GetCurrentProcess(), service->log_handle,
		GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		*win32_error = GetLastError();
		return EIO;
	}
	os_handle = (intptr_t)duplicate;
	descriptor = _open_osfhandle(os_handle, _O_APPEND | _O_WRONLY | _O_TEXT);
	if (descriptor == -1) {
		crt_error = errno;
		if (_get_doserrno(&dos_error) == 0) *win32_error = (DWORD)dos_error;
		CloseHandle(duplicate); /* Ownership transfers only on success. */
		return crt_error != 0 ? crt_error : EIO;
	}
	/* Keep a source above the standard descriptors, which may be unassigned. */
	redirect_descriptor = descriptor;
	while (redirect_descriptor <= 2) {
		int next_descriptor = _dup(redirect_descriptor);
		if (next_descriptor == -1) {
			crt_error = errno;
			dos_error = ERROR_SUCCESS;
			if (_get_doserrno(&dos_error) == 0) *win32_error = (DWORD)dos_error;
			for (index = 0; index < temporary_count; ++index)
				if (temporary[index] != 1 && temporary[index] != 2) (void)_close(temporary[index]);
			if (descriptor != 1 && descriptor != 2) (void)_close(descriptor);
			return crt_error != 0 ? crt_error : EIO;
		}
		temporary[temporary_count++] = next_descriptor;
		redirect_descriptor = next_descriptor;
	}
	if (_dup2(redirect_descriptor, stdout_fd) != 0 ||
		_dup2(redirect_descriptor, stderr_fd) != 0) {
		crt_error = errno;
		dos_error = ERROR_SUCCESS;
		if (_get_doserrno(&dos_error) == 0) *win32_error = (DWORD)dos_error;
		for (index = 0; index < temporary_count; ++index)
			if (temporary[index] != 1 && temporary[index] != 2) (void)_close(temporary[index]);
		if (descriptor != 1 && descriptor != 2) (void)_close(descriptor);
		return crt_error != 0 ? crt_error : EIO;
	}
	for (index = 0; index < temporary_count; ++index)
		if (temporary[index] != 1 && temporary[index] != 2) (void)_close(temporary[index]);
	if (descriptor != 1 && descriptor != 2) (void)_close(descriptor);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	return 0;
}

HANDLE fsf_service_stop_event(FSF_SERVICE *service)
{
	return service != NULL ? service->stop_event : NULL;
}

BOOL fsf_service_report_running(FSF_SERVICE *service, DWORD *error_out)
{
	BOOL success;
	DWORD error;
	if (service == NULL || service->status_handle == NULL) {
		if (error_out != NULL) *error_out = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	AcquireSRWLockExclusive(&service->state_lock);
	if (service->stop_requested) { success = FALSE; error = ERROR_OPERATION_ABORTED; }
	else {
		success = fsf_report_locked(service, SERVICE_RUNNING, ERROR_SUCCESS, 0, 0);
		error = success ? ERROR_SUCCESS : GetLastError();
	}
	ReleaseSRWLockExclusive(&service->state_lock);
	if (error_out != NULL) *error_out = error;
	if (success) fsf_service_log(service, FSF_SERVICE_LOG_INFORMATION, 0, L"Service running; mount and dispatcher started.");
	return success;
}

BOOL fsf_service_report_start_progress(FSF_SERVICE *service, DWORD wait_hint_ms,
	DWORD *error_out)
{
	BOOL success;
	DWORD error;
	if (service == NULL || service->status_handle == NULL) {
		if (error_out != NULL) *error_out = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	AcquireSRWLockExclusive(&service->state_lock);
	if (service->stop_requested || service->status.dwCurrentState != SERVICE_START_PENDING) {
		success = FALSE;
		error = ERROR_OPERATION_ABORTED;
	} else {
		success = fsf_report_locked(service, SERVICE_START_PENDING, 0, 0, wait_hint_ms);
		error = success ? ERROR_SUCCESS : GetLastError();
	}
	ReleaseSRWLockExclusive(&service->state_lock);
	if (error_out != NULL) *error_out = error;
	return success;
}

static void WINAPI fsf_service_main(DWORD argc, PWSTR *argv)
{
	FSF_SERVICE *service = &g_service;
	DWORD error;
	DWORD redirect_win32_error = ERROR_SUCCESS;
	int redirect_errno, stdout_status, stderr_status;
	unsigned long redirect_dos_error;
	(void)argc;
	(void)argv;
	service->status_handle = RegisterServiceCtrlHandlerExW(
		service->config.service_name, fsf_service_control, service);
	if (service->status_handle == NULL) {
		service->result.win32_error = GetLastError();
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, service->result.win32_error, L"Cannot register SCM control handler.");
		return;
	}
	AcquireSRWLockExclusive(&service->state_lock);
	if (!fsf_report_locked(service, SERVICE_START_PENDING, 0, 0, 120000)) {
		error = GetLastError();
		ReleaseSRWLockExclusive(&service->state_lock);
		service->result.win32_error = error;
		return;
	}
	ReleaseSRWLockExclusive(&service->state_lock);
	fsf_service_log(service, FSF_SERVICE_LOG_INFORMATION, 0, L"Service starting.");
	/* Redirect only after the SCM handshake, preserving console errors for manual --service. */
	redirect_errno = fsf_redirect_service_output(service, &redirect_win32_error);
	if (redirect_errno != 0) {
		service->result.win32_error = ERROR_OPEN_FAILED;
		WCHAR failure[160];
		swprintf_s(failure, _countof(failure), L"Cannot redirect service stdout/stderr (errno=%d, Win32=%lu).",
			redirect_errno, redirect_win32_error);
		fsf_service_log(service, FSF_SERVICE_LOG_ERROR, ERROR_OPEN_FAILED, failure);
	} else {
		stdout_status = fwprintf(stdout, L"Service stdout diagnostics attached.\n");
		if (fflush(stdout) != 0) stdout_status = -1;
		stderr_status = fprintf(stderr, "Service stderr diagnostics attached.\n");
		if (fflush(stderr) != 0) stderr_status = -1;
		if (stdout_status < 0 || stderr_status < 0) {
			redirect_errno = errno;
			redirect_dos_error = ERROR_SUCCESS;
			if (_get_doserrno(&redirect_dos_error) == 0)
				redirect_win32_error = (DWORD)redirect_dos_error;
			service->result.win32_error = ERROR_WRITE_FAULT;
			WCHAR failure[160];
			swprintf_s(failure, _countof(failure), L"Cannot write service stdout/stderr marker (errno=%d, Win32=%lu).",
				redirect_errno, redirect_win32_error);
			fsf_service_log(service, FSF_SERVICE_LOG_ERROR, ERROR_WRITE_FAULT, failure);
		} else {
			service->result = service->config.run(service->config.app_context, service);
		}
	}
	AcquireSRWLockShared(&service->state_lock);
	if (service->stop_requested && service->result.win32_error == ERROR_OPERATION_ABORTED)
		service->result.normal_stop = TRUE;
	ReleaseSRWLockShared(&service->state_lock);
	if (service->result.normal_stop) {
		service->result.win32_error = ERROR_SUCCESS;
		service->result.service_specific_error = 0;
	} else if (service->result.win32_error == ERROR_SUCCESS) {
		service->result.win32_error = ERROR_SERVICE_SPECIFIC_ERROR;
	}
	if (service->result.win32_error == ERROR_SERVICE_SPECIFIC_ERROR) {
		if (service->result.service_specific_error == 0)
			service->result.service_specific_error = ERROR_GEN_FAILURE;
	} else service->result.service_specific_error = 0;
	fsf_service_log(service, service->result.normal_stop ? FSF_SERVICE_LOG_INFORMATION : FSF_SERVICE_LOG_ERROR,
		service->result.service_specific_error != 0 ? service->result.service_specific_error : service->result.win32_error,
		service->result.normal_stop ? L"Service stopped normally." : L"Service stopped with an error; retained recovery data will not be replayed.");
	fflush(stdout);
	fflush(stderr);
	AcquireSRWLockExclusive(&service->state_lock);
	(void)fsf_report_locked(service, SERVICE_STOPPED, service->result.win32_error,
		service->result.service_specific_error, 0);
	ReleaseSRWLockExclusive(&service->state_lock);
}

DWORD fsf_service_run(const FSF_SERVICE_RUN_CONFIG *config, FSF_SERVICE_EXIT *result_out)
{
	SERVICE_TABLE_ENTRYW table[2];
	DWORD error;
	if (result_out != NULL) ZeroMemory(result_out, sizeof(*result_out));
	if (config == NULL || !fsf_valid_contract(config->struct_size, sizeof(*config), config->abi_version) ||
		config->service_name == NULL || *config->service_name == L'\0' || config->run == NULL)
		return ERROR_INVALID_PARAMETER;
	if (InterlockedCompareExchange(&g_service_run_claimed, 1, 0) != 0)
		return ERROR_ALREADY_INITIALIZED;
	ZeroMemory(&g_service, sizeof(g_service));
	g_service.config = *config;
	g_service.log_handle = INVALID_HANDLE_VALUE;
	InitializeSRWLock(&g_service.state_lock);
	InitializeSRWLock(&g_service.log_lock);
	g_service.stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (g_service.stop_event == NULL) { error = GetLastError(); goto done; }
	error = fsf_prepare_log(config->log_path, config->authorized_user_sid, &g_service.log_handle);
	if (error != ERROR_SUCCESS) goto done;
	table[0].lpServiceName = (PWSTR)config->service_name;
	table[0].lpServiceProc = fsf_service_main;
	table[1].lpServiceName = NULL;
	table[1].lpServiceProc = NULL;
	if (!StartServiceCtrlDispatcherW(table)) error = GetLastError();
	else error = g_service.result.win32_error;
done:
	AcquireSRWLockExclusive(&g_service.state_lock);
	if (g_service.stop_event != NULL) CloseHandle(g_service.stop_event);
	g_service.stop_event = NULL;
	ReleaseSRWLockExclusive(&g_service.state_lock);
	AcquireSRWLockExclusive(&g_service.log_lock);
	if (g_service.log_handle != INVALID_HANDLE_VALUE) CloseHandle(g_service.log_handle);
	g_service.log_handle = INVALID_HANDLE_VALUE;
	ReleaseSRWLockExclusive(&g_service.log_lock);
	if (error != ERROR_SUCCESS && g_service.result.win32_error == ERROR_SUCCESS)
		g_service.result.win32_error = error;
	if (result_out != NULL) *result_out = g_service.result;
	return error;
}

static DWORD fsf_query_config(SC_HANDLE service, QUERY_SERVICE_CONFIGW **config_out)
{
	DWORD required = 0;
	QUERY_SERVICE_CONFIGW *config;
	*config_out = NULL;
	(void)QueryServiceConfigW(service, NULL, 0, &required);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return GetLastError();
	config = (QUERY_SERVICE_CONFIGW *)malloc(required);
	if (config == NULL) return ERROR_NOT_ENOUGH_MEMORY;
	if (!QueryServiceConfigW(service, config, required, &required)) {
		DWORD error = GetLastError();
		free(config);
		return error;
	}
	*config_out = config;
	return ERROR_SUCCESS;
}

static DWORD fsf_query_config2(SC_HANDLE service, DWORD level, BYTE **config_out)
{
	DWORD required = 0;
	BYTE *config;
	*config_out = NULL;
	(void)QueryServiceConfig2W(service, level, NULL, 0, &required);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return GetLastError();
	config = (BYTE *)malloc(required);
	if (config == NULL) return ERROR_NOT_ENOUGH_MEMORY;
	if (!QueryServiceConfig2W(service, level, config, required, &required)) {
		DWORD error = GetLastError(); free(config); return error;
	}
	*config_out = config;
	return ERROR_SUCCESS;
}

static DWORD fsf_matching_install(SC_HANDLE service, PCWSTR image,
	const FSF_SERVICE_INSTALL_CONFIG *expected)
{
	QUERY_SERVICE_CONFIGW *config = NULL;
	BYTE *delayed = NULL, *actions = NULL, *flag = NULL;
	SERVICE_FAILURE_ACTIONSW *failure;
	DWORD error, index;
	error = fsf_query_config(service, &config);
	if (error != ERROR_SUCCESS) goto done;
	if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS || config->dwStartType != SERVICE_AUTO_START ||
		wcscmp(config->lpBinaryPathName, image) != 0 || _wcsicmp(config->lpServiceStartName, L"LocalSystem") != 0) {
		error = ERROR_SERVICE_EXISTS; goto done;
	}
	error = fsf_query_config2(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);
	if (error != ERROR_SUCCESS) goto done;
	if (!((SERVICE_DELAYED_AUTO_START_INFO *)delayed)->fDelayedAutostart != !expected->delayed_auto_start) {
		error = ERROR_SERVICE_EXISTS; goto done;
	}
	error = fsf_query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &actions);
	if (error != ERROR_SUCCESS) goto done;
	failure = (SERVICE_FAILURE_ACTIONSW *)actions;
	if (failure->dwResetPeriod != expected->failure_reset_seconds || failure->cActions != expected->failure_action_count ||
		(failure->lpCommand != NULL && *failure->lpCommand != L'\0') ||
		(failure->lpRebootMsg != NULL && *failure->lpRebootMsg != L'\0')) {
		error = ERROR_SERVICE_EXISTS; goto done;
	}
	for (index = 0; index < failure->cActions; ++index)
		if (failure->lpsaActions[index].Type != expected->failure_actions[index].Type ||
			failure->lpsaActions[index].Delay != expected->failure_actions[index].Delay) {
			error = ERROR_SERVICE_EXISTS; goto done;
		}
	error = fsf_query_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
	if (error == ERROR_SUCCESS && !((SERVICE_FAILURE_ACTIONS_FLAG *)flag)->fFailureActionsOnNonCrashFailures)
		error = ERROR_SERVICE_EXISTS;
done:
	free(config); free(delayed); free(actions); free(flag);
	return error;
}

static DWORD fsf_wait_service(SC_HANDLE service, DWORD desired, DWORD timeout_ms)
{
	SERVICE_STATUS_PROCESS status;
	DWORD required;
	ULONGLONG started = GetTickCount64();
	for (;;) {
		if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &required))
			return GetLastError();
		if (status.dwCurrentState == desired) return ERROR_SUCCESS;
		if (desired == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
			return status.dwWin32ExitCode != 0 ? status.dwWin32ExitCode : ERROR_SERVICE_NOT_ACTIVE;
		if (GetTickCount64() - started >= timeout_ms) return ERROR_SERVICE_REQUEST_TIMEOUT;
		Sleep(100);
	}
}

static DWORD fsf_service_belongs_to_this_executable(PCWSTR image)
{
	PWSTR executable = (PWSTR)calloc(32768, sizeof(WCHAR));
	PCWSTR begin, end;
	DWORD length, error = ERROR_SERVICE_EXISTS;
	size_t image_length;
	if (executable == NULL) return ERROR_NOT_ENOUGH_MEMORY;
	length = GetModuleFileNameW(NULL, executable, 32768);
	if (length == 0 || length >= 32768) {
		error = length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
		goto done;
	}
	begin = image;
	while (*begin == L' ' || *begin == L'\t') ++begin;
	if (*begin == L'"') {
		++begin;
		end = wcschr(begin, L'"');
		if (end == NULL) goto done;
	} else {
		end = begin;
		while (*end != L'\0' && *end != L' ' && *end != L'\t') ++end;
	}
	image_length = (size_t)(end - begin);
	if (image_length == length && _wcsnicmp(begin, executable, image_length) == 0)
		error = ERROR_SUCCESS;
done:
	free(executable);
	return error;
}

DWORD fsf_service_install(const FSF_SERVICE_INSTALL_CONFIG *config)
{
	SC_HANDLE manager = NULL, service = NULL;
	PWSTR image = NULL;
	HANDLE log = INVALID_HANDLE_VALUE;
	SERVICE_DESCRIPTIONW description;
	SERVICE_DELAYED_AUTO_START_INFO delayed;
	SERVICE_FAILURE_ACTIONSW failure;
	SERVICE_FAILURE_ACTIONS_FLAG flag;
	DWORD error, file_attributes;
	BOOL created = FALSE;
	size_t capacity;
	if (config == NULL || !fsf_valid_contract(config->struct_size, sizeof(*config), config->abi_version) ||
		config->service_name == NULL || *config->service_name == L'\0' ||
		!fsf_absolute_path(config->absolute_executable) || config->exact_service_arguments == NULL ||
		*config->exact_service_arguments == L'\0' || wcschr(config->absolute_executable, L'"') != NULL ||
		(config->failure_action_count != 0 && config->failure_actions == NULL))
		return ERROR_INVALID_PARAMETER;
	file_attributes = GetFileAttributesW(config->absolute_executable);
	if (file_attributes == INVALID_FILE_ATTRIBUTES) return GetLastError();
	if (file_attributes & FILE_ATTRIBUTE_DIRECTORY) return ERROR_BAD_EXE_FORMAT;
	capacity = wcslen(config->absolute_executable) + wcslen(config->exact_service_arguments) + 5;
	if (capacity > 32768) return ERROR_FILENAME_EXCED_RANGE;
	image = (PWSTR)calloc(capacity, sizeof(WCHAR));
	if (image == NULL) return ERROR_NOT_ENOUGH_MEMORY;
	swprintf_s(image, capacity, L"\"%s\" %s", config->absolute_executable, config->exact_service_arguments);
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (manager == NULL) { error = GetLastError(); goto done; }
	service = CreateServiceW(manager, config->service_name,
		config->display_name != NULL ? config->display_name : config->service_name,
		SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, image,
		NULL, NULL, config->dependencies, NULL, NULL);
	if (service == NULL) {
		error = GetLastError();
		if (error != ERROR_SERVICE_EXISTS) goto done;
		service = OpenServiceW(manager, config->service_name, SERVICE_QUERY_CONFIG | SERVICE_START | SERVICE_QUERY_STATUS);
		if (service == NULL) { error = GetLastError(); goto done; }
		error = fsf_matching_install(service, image, config);
		if (error != ERROR_SUCCESS) goto done;
	} else {
		created = TRUE;
		description.lpDescription = (PWSTR)config->description;
		delayed.fDelayedAutostart = config->delayed_auto_start;
		ZeroMemory(&failure, sizeof(failure));
		failure.dwResetPeriod = config->failure_reset_seconds;
		failure.cActions = config->failure_action_count;
		failure.lpsaActions = (SC_ACTION *)config->failure_actions;
		flag.fFailureActionsOnNonCrashFailures = TRUE;
		if ((config->description != NULL && !ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &description)) ||
			!ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed) ||
			!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure) ||
			!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag)) {
			error = GetLastError(); goto configuration_failed;
		}
		error = fsf_prepare_log(config->log_path, config->authorized_user_sid, &log);
		if (error != ERROR_SUCCESS) goto configuration_failed;
		CloseHandle(log); log = INVALID_HANDLE_VALUE;
	}
	if (!StartServiceW(service, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
		error = GetLastError(); goto done;
	}
	error = fsf_wait_service(service, SERVICE_RUNNING, config->start_timeout_ms != 0 ? config->start_timeout_ms : 120000);
	goto done;
configuration_failed:
	/* Only a newly created, never-started registration is rolled back. */
	if (created) (void)DeleteService(service);
done:
	if (log != INVALID_HANDLE_VALUE) CloseHandle(log);
	if (service != NULL) CloseServiceHandle(service);
	if (manager != NULL) CloseServiceHandle(manager);
	free(image);
	return error;
}

DWORD fsf_service_uninstall(PCWSTR service_name, DWORD stop_timeout_ms)
{
	SC_HANDLE manager = NULL, service = NULL;
	QUERY_SERVICE_CONFIGW *config = NULL;
	SERVICE_STATUS status;
	SERVICE_STATUS_PROCESS process_status;
	DWORD error, required;
	if (service_name == NULL || *service_name == L'\0') return ERROR_INVALID_PARAMETER;
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (manager == NULL) return GetLastError();
	service = OpenServiceW(manager, service_name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
	if (service == NULL) {
		error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST || error == ERROR_SERVICE_MARKED_FOR_DELETE) error = ERROR_SUCCESS;
		goto done;
	}
	error = fsf_query_config(service, &config);
	if (error != ERROR_SUCCESS) goto done;
	if (config->dwServiceType != SERVICE_WIN32_OWN_PROCESS) { error = ERROR_INVALID_SERVICE_CONTROL; goto done; }
	error = fsf_service_belongs_to_this_executable(config->lpBinaryPathName);
	if (error != ERROR_SUCCESS) goto done;
	if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&process_status, sizeof(process_status), &required)) {
		error = GetLastError(); goto done;
	}
	if (process_status.dwCurrentState != SERVICE_STOPPED) {
		if (process_status.dwCurrentState != SERVICE_STOP_PENDING &&
			!ControlService(service, SERVICE_CONTROL_STOP, &status) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
			error = GetLastError(); goto done;
		}
		error = fsf_wait_service(service, SERVICE_STOPPED, stop_timeout_ms != 0 ? stop_timeout_ms : 90000);
		if (error != ERROR_SUCCESS) goto done;
	}
	error = DeleteService(service) ? ERROR_SUCCESS : GetLastError();
	if (error == ERROR_SERVICE_MARKED_FOR_DELETE) error = ERROR_SUCCESS;
done:
	free(config);
	if (service != NULL) CloseServiceHandle(service);
	CloseServiceHandle(manager);
	return error;
}
