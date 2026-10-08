#include "fs_frontend_driver.h"

#include <stdint.h>
#include <string.h>
#include <wchar.h>

#define FSF_RCDATA MAKEINTRESOURCEW(10)

typedef struct FSF_DRIVER_PAYLOAD {
	WORD resource_id;
	const wchar_t *primary_file;
	const wchar_t *alternate_file;
} FSF_DRIVER_PAYLOAD;

static INIT_ONCE g_runtime_once = INIT_ONCE_STATIC_INIT;
static DWORD g_runtime_error = ERROR_SUCCESS;
static wchar_t g_runtime_dir[MAX_PATH];

static DWORD resource_view(WORD resource_id, const void **data, DWORD *size)
{
	HMODULE module = GetModuleHandleW(NULL);
	HRSRC resource;
	HGLOBAL loaded;

	if (data == NULL || size == NULL)
		return ERROR_INVALID_PARAMETER;
	*data = NULL;
	*size = 0;
	resource = FindResourceW(module, MAKEINTRESOURCEW(resource_id), FSF_RCDATA);
	if (resource == NULL)
		return GetLastError();
	*size = SizeofResource(module, resource);
	if (*size == 0)
		return ERROR_RESOURCE_DATA_NOT_FOUND;
	loaded = LoadResource(module, resource);
	if (loaded == NULL)
		return GetLastError();
	*data = LockResource(loaded);
	if (*data == NULL)
		return ERROR_RESOURCE_DATA_NOT_FOUND;
	return ERROR_SUCCESS;
}

DWORD fsf_driver_file_matches_buffer(const wchar_t *path, const void *expected,
	DWORD expected_size, BOOL *matches)
{
	HANDLE file;
	LARGE_INTEGER size;
	const uint8_t *expected_bytes = expected;
	uint8_t buffer[4096];
	DWORD offset = 0;

	if (expected == NULL || matches == NULL)
		return ERROR_INVALID_PARAMETER;
	*matches = FALSE;
	file = CreateFileW(path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) ?
			ERROR_SUCCESS : error;
	}
	if (!GetFileSizeEx(file, &size)) {
		DWORD error = GetLastError();
		CloseHandle(file);
		return error;
	}
	if (size.QuadPart != (LONGLONG)expected_size) {
		CloseHandle(file);
		return ERROR_SUCCESS;
	}
	while (offset < expected_size) {
		DWORD chunk = expected_size - offset;
		DWORD read = 0;
		if (chunk > sizeof(buffer))
			chunk = sizeof(buffer);
		if (!ReadFile(file, buffer, chunk, &read, NULL) || read != chunk) {
			DWORD error = GetLastError();
			CloseHandle(file);
			return error != ERROR_SUCCESS ? error : ERROR_READ_FAULT;
		}
		if (memcmp(buffer, expected_bytes + offset, chunk) != 0) {
			CloseHandle(file);
			return ERROR_SUCCESS;
		}
		offset += chunk;
	}
	CloseHandle(file);
	*matches = TRUE;
	return ERROR_SUCCESS;
}

static DWORD extract_resource(WORD resource_id, const wchar_t *target_path)
{
	const void *data;
	DWORD size, error, written = 0;
	BOOL matches;
	HANDLE file;
	wchar_t temp_path[MAX_PATH];

	error = resource_view(resource_id, &data, &size);
	if (error != ERROR_SUCCESS)
		return error;
	error = fsf_driver_file_matches_buffer(target_path, data, size, &matches);
	if (error == ERROR_SUCCESS && matches)
		return ERROR_SUCCESS;
	if (_snwprintf_s(temp_path, _countof(temp_path), _TRUNCATE, L"%s.tmp.%lu",
		target_path, GetCurrentProcessId()) < 0)
		return ERROR_BUFFER_OVERFLOW;
	file = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return GetLastError();
	if (!WriteFile(file, data, size, &written, NULL) || written != size) {
		error = GetLastError();
		CloseHandle(file);
		DeleteFileW(temp_path);
		return error != ERROR_SUCCESS ? error : ERROR_WRITE_FAULT;
	}
	if (!FlushFileBuffers(file)) {
		error = GetLastError();
		CloseHandle(file);
		DeleteFileW(temp_path);
		return error;
	}
	CloseHandle(file);
	if (!MoveFileExW(temp_path, target_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		error = GetLastError();
		DeleteFileW(temp_path);
		/* A loaded DLL/driver blocks replacement; an identical copy is fine. */
		if (fsf_driver_file_matches_buffer(target_path, data, size, &matches) == ERROR_SUCCESS &&
			matches)
			return ERROR_SUCCESS;
		return error;
	}
	return ERROR_SUCCESS;
}

static BOOL CALLBACK prepare_runtime_once(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
	const FSF_DRIVER_SPEC *spec = (const FSF_DRIVER_SPEC *)parameter;
	wchar_t program_data[MAX_PATH];
	wchar_t dll_path[MAX_PATH];
	DWORD chars;

	(void)once;
	(void)context;
	if (spec->static_runtime) {
		g_runtime_dir[0] = L'\0';
		g_runtime_error = ERROR_SUCCESS;
		return TRUE;
	}
	chars = GetEnvironmentVariableW(L"ProgramData", program_data, _countof(program_data));
	if (chars == 0 || chars >= _countof(program_data)) {
		g_runtime_error = chars == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
		return TRUE;
	}
	if (_snwprintf_s(g_runtime_dir, _countof(g_runtime_dir), _TRUNCATE,
		L"%s\\%s", program_data, spec->runtime_dir_name) < 0) {
		g_runtime_error = ERROR_BUFFER_OVERFLOW;
		return TRUE;
	}
	if (!CreateDirectoryW(g_runtime_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
		g_runtime_error = GetLastError();
		return TRUE;
	}
	if (_snwprintf_s(dll_path, _countof(dll_path), _TRUNCATE,
		L"%s\\%s", g_runtime_dir, L"winfsp-x64.dll") < 0) {
		g_runtime_error = ERROR_BUFFER_OVERFLOW;
		return TRUE;
	}
	g_runtime_error = extract_resource(spec->dll_resource_id, dll_path);
	if (g_runtime_error != ERROR_SUCCESS)
		return TRUE;
	g_runtime_error = SetDllDirectoryW(g_runtime_dir) ? ERROR_SUCCESS : GetLastError();
	return TRUE;
}

DWORD fsf_driver_prepare_runtime(const FSF_DRIVER_SPEC *spec)
{
	if (spec == NULL)
		return ERROR_INVALID_PARAMETER;
	if (!InitOnceExecuteOnce(&g_runtime_once, prepare_runtime_once, (PVOID)spec, NULL))
		return GetLastError();
	return g_runtime_error;
}

const wchar_t *fsf_driver_runtime_directory(const FSF_DRIVER_SPEC *spec)
{
	return fsf_driver_prepare_runtime(spec) == ERROR_SUCCESS ? g_runtime_dir : NULL;
}

static DWORD private_driver_path_for(const wchar_t *file_name, wchar_t path[MAX_PATH])
{
	wchar_t system_dir[MAX_PATH];
	UINT chars;

	if (file_name == NULL || path == NULL)
		return ERROR_INVALID_PARAMETER;
	chars = GetSystemDirectoryW(system_dir, _countof(system_dir));
	if (chars == 0)
		return GetLastError();
	if (chars >= _countof(system_dir))
		return ERROR_BUFFER_OVERFLOW;
	if (_snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\drivers\\%s", system_dir, file_name) < 0)
		return ERROR_BUFFER_OVERFLOW;
	return ERROR_SUCCESS;
}

static DWORD payload_for_machine(const FSF_DRIVER_SPEC *spec, USHORT native_machine,
	FSF_DRIVER_PAYLOAD *payload)
{
	if (spec == NULL || payload == NULL)
		return ERROR_INVALID_PARAMETER;
	switch (native_machine) {
	case IMAGE_FILE_MACHINE_AMD64:
		payload->resource_id = spec->sys_x64_resource_id;
		payload->primary_file = spec->sys_x64_file;
		payload->alternate_file = spec->sys_x64_alt_file;
		return ERROR_SUCCESS;
	case IMAGE_FILE_MACHINE_ARM64:
		payload->resource_id = spec->sys_arm64_resource_id;
		payload->primary_file = spec->sys_arm64_file;
		payload->alternate_file = spec->sys_arm64_alt_file;
		return ERROR_SUCCESS;
	default:
		return ERROR_NOT_SUPPORTED;
	}
}

DWORD fsf_driver_spec_for_machine(const FSF_DRIVER_SPEC *spec, USHORT native_machine,
	WORD *resource_id, const wchar_t **primary_file, const wchar_t **alternate_file)
{
	FSF_DRIVER_PAYLOAD payload;
	DWORD error = payload_for_machine(spec, native_machine, &payload);
	if (error != ERROR_SUCCESS)
		return error;
	if (resource_id) *resource_id = payload.resource_id;
	if (primary_file) *primary_file = payload.primary_file;
	if (alternate_file) *alternate_file = payload.alternate_file;
	return ERROR_SUCCESS;
}

DWORD fsf_driver_native_machine(USHORT *native_machine)
{
	typedef BOOL (WINAPI *IsWow64Process2Fn)(HANDLE, USHORT *, USHORT *);
	HMODULE kernel32;
	IsWow64Process2Fn is_wow64_process2;
	USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
	USHORT host_machine = IMAGE_FILE_MACHINE_UNKNOWN;
	SYSTEM_INFO info;

	if (native_machine == NULL)
		return ERROR_INVALID_PARAMETER;
	kernel32 = GetModuleHandleW(L"kernel32.dll");
	if (kernel32 != NULL) {
		is_wow64_process2 = (IsWow64Process2Fn)(void *)GetProcAddress(kernel32, "IsWow64Process2");
		if (is_wow64_process2 != NULL) {
			if (!is_wow64_process2(GetCurrentProcess(), &process_machine, &host_machine))
				return GetLastError();
			if (host_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
				*native_machine = host_machine;
				return ERROR_SUCCESS;
			}
		}
	}
	/* Older x64 Windows. Windows 11 on Arm reports emulated processor details
	 * to x64 processes, which is why IsWow64Process2 is preferred. */
	GetNativeSystemInfo(&info);
	if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		*native_machine = IMAGE_FILE_MACHINE_AMD64;
		return ERROR_SUCCESS;
	}
	return ERROR_NOT_SUPPORTED;
}

static DWORD current_payload(const FSF_DRIVER_SPEC *spec, FSF_DRIVER_PAYLOAD *payload)
{
	USHORT native_machine;
	DWORD error = fsf_driver_native_machine(&native_machine);
	if (error != ERROR_SUCCESS)
		return error;
	return payload_for_machine(spec, native_machine, payload);
}

static DWORD resource_matches_file(WORD resource_id, const wchar_t *path, BOOL *matches)
{
	const void *data;
	DWORD size;
	DWORD error = resource_view(resource_id, &data, &size);
	if (error != ERROR_SUCCESS)
		return error;
	return fsf_driver_file_matches_buffer(path, data, size, matches);
}

static DWORD query_service_state(SC_HANDLE service, DWORD *state)
{
	SERVICE_STATUS_PROCESS status;
	DWORD bytes = 0;

	if (service == NULL || state == NULL)
		return ERROR_INVALID_PARAMETER;
	if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
		sizeof(status), &bytes))
		return GetLastError();
	*state = status.dwCurrentState;
	return ERROR_SUCCESS;
}

static DWORD query_service_binary_path(SC_HANDLE service, wchar_t path[MAX_PATH])
{
	BYTE buffer[8192];
	QUERY_SERVICE_CONFIGW *config = (QUERY_SERVICE_CONFIGW *)buffer;
	DWORD needed = 0;
	const wchar_t *source;
	size_t length;

	if (service == NULL || path == NULL)
		return ERROR_INVALID_PARAMETER;
	path[0] = L'\0';
	if (!QueryServiceConfigW(service, config, sizeof(buffer), &needed))
		return GetLastError();
	if (config->lpBinaryPathName == NULL || config->lpBinaryPathName[0] == L'\0')
		return ERROR_INVALID_DATA;
	source = config->lpBinaryPathName;
	if (*source == L'"') {
		source++;
		length = wcscspn(source, L"\"");
	} else {
		length = wcslen(source);
	}
	if (length == 0 || length >= MAX_PATH)
		return ERROR_BUFFER_OVERFLOW;
	wmemcpy(path, source, length);
	path[length] = L'\0';
	return ERROR_SUCCESS;
}

static DWORD wait_service_stopped(SC_HANDLE service, DWORD timeout_ms)
{
	ULONGLONG deadline = GetTickCount64() + timeout_ms;
	DWORD state, error;

	for (;;) {
		error = query_service_state(service, &state);
		if (error != ERROR_SUCCESS)
			return error;
		if (state == SERVICE_STOPPED)
			return ERROR_SUCCESS;
		if (GetTickCount64() >= deadline)
			return ERROR_TIMEOUT;
		Sleep(100);
	}
}

static DWORD delete_private_file(const wchar_t *path, BOOL *reboot_required)
{
	DWORD error;

	if (DeleteFileW(path))
		return ERROR_SUCCESS;
	error = GetLastError();
	if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
		return ERROR_SUCCESS;
	if (error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED ||
		error == ERROR_USER_MAPPED_FILE) {
		if (MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
			if (reboot_required)
				*reboot_required = TRUE;
			return ERROR_SUCCESS;
		}
		error = GetLastError();
	}
	return error;
}

static DWORD delete_all_private_driver_files(const FSF_DRIVER_SPEC *spec, BOOL *reboot_required)
{
	const wchar_t *const file_names[] = {
		spec->sys_x64_file, spec->sys_x64_alt_file,
		spec->sys_arm64_file, spec->sys_arm64_alt_file,
	};
	wchar_t path[MAX_PATH];
	DWORD first_error = ERROR_SUCCESS, error;
	size_t i;

	for (i = 0; i < _countof(file_names); ++i) {
		error = private_driver_path_for(file_names[i], path);
		if (error == ERROR_SUCCESS)
			error = delete_private_file(path, reboot_required);
		if (first_error == ERROR_SUCCESS && error != ERROR_SUCCESS)
			first_error = error;
	}
	return first_error;
}

const wchar_t *fsf_driver_select_update_path(const wchar_t *running_path,
	const wchar_t *primary_path, const wchar_t *alternate_path)
{
	if (running_path != NULL && primary_path != NULL && _wcsicmp(running_path, primary_path) == 0)
		return alternate_path;
	return primary_path;
}

DWORD fsf_driver_plan_running_update(const wchar_t *configured_path,
	BOOL configured_matches_payload, const wchar_t *primary_path,
	const wchar_t *alternate_path, const wchar_t **stage_path)
{
	if (stage_path == NULL)
		return ERROR_INVALID_PARAMETER;
	*stage_path = NULL;
	/* QueryServiceConfig reports the image configured for the next start, not
	 * the one loaded in the kernel; a match only proves an upgrade is staged. */
	if (configured_matches_payload)
		return ERROR_SUCCESS_REBOOT_REQUIRED;
	*stage_path = fsf_driver_select_update_path(configured_path, primary_path, alternate_path);
	return ERROR_SUCCESS;
}

BOOL fsf_driver_payload_cleanup_allowed(DWORD service_error)
{
	return service_error == ERROR_SUCCESS;
}

DWORD fsf_driver_install(const FSF_DRIVER_SPEC *spec)
{
	const DWORD access = SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG |
		SERVICE_CHANGE_CONFIG;
	SC_HANDLE manager = NULL, service = NULL;
	FSF_DRIVER_PAYLOAD payload;
	wchar_t primary_path[MAX_PATH], alternate_path[MAX_PATH], configured_path[MAX_PATH];
	DWORD service_state = SERVICE_STOPPED, error, open_error;
	BOOL matches = FALSE;

	if (spec == NULL)
		return ERROR_INVALID_PARAMETER;
	error = current_payload(spec, &payload);
	if (error != ERROR_SUCCESS)
		return error;
	error = private_driver_path_for(payload.primary_file, primary_path);
	if (error == ERROR_SUCCESS)
		error = private_driver_path_for(payload.alternate_file, alternate_path);
	if (error != ERROR_SUCCESS)
		return error;

	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
	if (manager == NULL)
		return GetLastError();
	service = OpenServiceW(manager, spec->service_name, access);
	if (service == NULL) {
		open_error = GetLastError();
		if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
			CloseServiceHandle(manager);
			return open_error;
		}
		error = extract_resource(payload.resource_id, primary_path);
		if (error != ERROR_SUCCESS) {
			CloseServiceHandle(manager);
			return error;
		}
		service = CreateServiceW(manager, spec->service_name, spec->service_name, access,
			SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
			primary_path, NULL, NULL, NULL, NULL, NULL);
		if (service == NULL) {
			error = GetLastError();
			CloseServiceHandle(manager);
			return error;
		}
	} else {
		error = query_service_state(service, &service_state);
		if (error != ERROR_SUCCESS)
			goto exit;
		if (service_state != SERVICE_STOPPED) {
			const wchar_t *stage_path = NULL;
			/* Never treat the configured path as proof of the loaded image.
			 * Stage the payload in the other private slot for the next start;
			 * once that matches, this returns REBOOT_REQUIRED idempotently. */
			error = query_service_binary_path(service, configured_path);
			if (error != ERROR_SUCCESS)
				goto exit;
			error = resource_matches_file(payload.resource_id, configured_path, &matches);
			if (error != ERROR_SUCCESS)
				goto exit;
			error = fsf_driver_plan_running_update(configured_path, matches,
				primary_path, alternate_path, &stage_path);
			if (error != ERROR_SUCCESS)
				goto exit;
			error = extract_resource(payload.resource_id, stage_path);
			if (error != ERROR_SUCCESS)
				goto exit;
			if (!ChangeServiceConfigW(service, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START,
				SERVICE_ERROR_NORMAL, stage_path, NULL, NULL, NULL, NULL, NULL, NULL)) {
				error = GetLastError();
				goto exit;
			}
			error = ERROR_SUCCESS_REBOOT_REQUIRED;
			goto exit;
		}
		/* Stopped: refresh the private payload and point the service at it. */
		error = extract_resource(payload.resource_id, primary_path);
		if (error != ERROR_SUCCESS)
			goto exit;
		if (!ChangeServiceConfigW(service, SERVICE_FILE_SYSTEM_DRIVER, SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL, primary_path, NULL, NULL, NULL, NULL, NULL, NULL)) {
			error = GetLastError();
			goto exit;
		}
	}
	if (!StartServiceW(service, 0, NULL)) {
		/* Another instance may have started the same verified driver first. */
		error = GetLastError();
		if (error == ERROR_SERVICE_ALREADY_RUNNING)
			error = ERROR_SUCCESS;
	} else {
		error = ERROR_SUCCESS;
	}
exit:
	if (service)
		CloseServiceHandle(service);
	if (manager)
		CloseServiceHandle(manager);
	return error;
}

DWORD fsf_driver_uninstall(const FSF_DRIVER_SPEC *spec)
{
	SC_HANDLE manager, service;
	SERVICE_STATUS status;
	DWORD state, error, first_error = ERROR_SUCCESS;
	BOOL reboot_required = FALSE;

	if (spec == NULL)
		return ERROR_INVALID_PARAMETER;
	manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (manager == NULL)
		return GetLastError();
	service = OpenServiceW(manager, spec->service_name, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
	if (service == NULL) {
		error = GetLastError();
		if (error != ERROR_SERVICE_DOES_NOT_EXIST) {
			CloseServiceHandle(manager);
			return error;
		}
	} else {
		error = query_service_state(service, &state);
		if (error != ERROR_SUCCESS) {
			first_error = error;
		} else if (state != SERVICE_STOPPED) {
			if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
				error = GetLastError();
				if (error != ERROR_SERVICE_NOT_ACTIVE)
					first_error = error;
			}
			if (first_error == ERROR_SUCCESS) {
				error = wait_service_stopped(service, 15000);
				if (error != ERROR_SUCCESS)
					first_error = error;
			}
		}
		if (first_error == ERROR_SUCCESS && !DeleteService(service)) {
			error = GetLastError();
			if (error != ERROR_SERVICE_MARKED_FOR_DELETE)
				first_error = error;
		}
	}
	if (service)
		CloseServiceHandle(service);
	CloseServiceHandle(manager);
	/* An unknown SCM state keeps every payload so a retry stays safe. */
	if (!fsf_driver_payload_cleanup_allowed(first_error))
		return first_error;
	/* Only private payload names are deleted, never the configured path. */
	error = delete_all_private_driver_files(spec, &reboot_required);
	if (error != ERROR_SUCCESS)
		return error;
	return reboot_required ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS;
}
