#include "memfs_driver.h"
#include "memfs_resource.h"

#include <Windows.h>
#include <stdint.h>
#include <wchar.h>

#define MEMFS_WINFSP_DRIVER_SERVICE L"WinFsp+MemfsC"
#define MEMFS_RUNTIME_DIR_NAME L"MemfsC"

#define MEMFS_WINFSP_DLL_FILE L"winfsp-x64.dll"
#define MEMFS_WINFSP_SYS_X64_FILE L"memfs-winfsp-x64.sys"
#define MEMFS_WINFSP_SYS_X64_ALT_FILE L"memfs-winfsp-x64.alt.sys"
#define MEMFS_WINFSP_SYS_ARM64_FILE L"memfs-winfsp-a64.sys"
#define MEMFS_WINFSP_SYS_ARM64_ALT_FILE L"memfs-winfsp-a64.alt.sys"

typedef struct MemfsEmbeddedDriverSpec {
    WORD resource_id;
    const wchar_t* primary_file;
    const wchar_t* alternate_file;
} MemfsEmbeddedDriverSpec;

static INIT_ONCE g_runtime_once = INIT_ONCE_STATIC_INIT;
static DWORD g_runtime_error = ERROR_SUCCESS;
static wchar_t g_runtime_dir[MAX_PATH];

static DWORD resource_view(WORD resource_id, const void** data, DWORD* size) {
    HMODULE module = GetModuleHandleW(NULL);
    HRSRC resource;
    HGLOBAL loaded;

    if (data == NULL || size == NULL)
        return ERROR_INVALID_PARAMETER;

    *data = NULL;
    *size = 0;

    resource = FindResourceW(module, MAKEINTRESOURCEW(resource_id), MAKEINTRESOURCEW(10));
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

static DWORD file_matches_buffer(const wchar_t* path,
                                 const void* expected,
                                 DWORD expected_size,
                                 BOOL* matches) {
    HANDLE file;
    LARGE_INTEGER size;
    const uint8_t* expected_bytes = expected;
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
        return (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
                   ? ERROR_SUCCESS
                   : error;
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

#if defined(MEMFS_DRIVER_TESTING)
DWORD memfs_driver_test_file_matches_buffer(const wchar_t* path,
                                            const void* expected,
                                            DWORD expected_size,
                                            BOOL* matches) {
    return file_matches_buffer(path, expected, expected_size, matches);
}
#endif

static DWORD extract_resource(WORD resource_id, const wchar_t* target_path) {
    const void* data;
    DWORD size;
    DWORD error;
    BOOL matches;
    HANDLE file;
    wchar_t temp_path[MAX_PATH];
    DWORD written = 0;

    error = resource_view(resource_id, &data, &size);
    if (error != ERROR_SUCCESS)
        return error;

    error = file_matches_buffer(target_path, data, size, &matches);
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

    if (!MoveFileExW(temp_path, target_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = GetLastError();
        DeleteFileW(temp_path);

        /*
         * A loaded DLL/driver can block replacement. If the installed copy
         * already matches the embedded payload byte-for-byte, it is acceptable.
         */
        if (file_matches_buffer(target_path, data, size, &matches) == ERROR_SUCCESS && matches)
            return ERROR_SUCCESS;
        return error;
    }

    return ERROR_SUCCESS;
}

static BOOL CALLBACK prepare_runtime_once(PINIT_ONCE once, PVOID parameter, PVOID* context) {
    (void)once;
    (void)parameter;
    (void)context;

#if defined(MEMFS_WINFSP_STATIC)
    g_runtime_dir[0] = L'\0';
    g_runtime_error = ERROR_SUCCESS;
    return TRUE;
#else
    wchar_t program_data[MAX_PATH];
    wchar_t dll_path[MAX_PATH];
    DWORD chars;

    chars = GetEnvironmentVariableW(L"ProgramData", program_data, _countof(program_data));
    if (chars == 0 || chars >= _countof(program_data)) {
        g_runtime_error = chars == 0 ? GetLastError() : ERROR_BUFFER_OVERFLOW;
        return TRUE;
    }

    if (_snwprintf_s(g_runtime_dir, _countof(g_runtime_dir), _TRUNCATE,
                     L"%s\\%s", program_data, MEMFS_RUNTIME_DIR_NAME) < 0) {
        g_runtime_error = ERROR_BUFFER_OVERFLOW;
        return TRUE;
    }

    if (!CreateDirectoryW(g_runtime_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        g_runtime_error = GetLastError();
        return TRUE;
    }

    if (_snwprintf_s(dll_path, _countof(dll_path), _TRUNCATE,
                     L"%s\\%s", g_runtime_dir, MEMFS_WINFSP_DLL_FILE) < 0) {
        g_runtime_error = ERROR_BUFFER_OVERFLOW;
        return TRUE;
    }

    g_runtime_error = extract_resource(IDR_MEMFS_WINFSP_DLL, dll_path);
    if (g_runtime_error != ERROR_SUCCESS)
        return TRUE;

    if (!SetDllDirectoryW(g_runtime_dir)) {
        g_runtime_error = GetLastError();
        return TRUE;
    }

    g_runtime_error = ERROR_SUCCESS;
    return TRUE;
#endif
}

DWORD memfs_winfsp_prepare_runtime(void) {
    if (!InitOnceExecuteOnce(&g_runtime_once, prepare_runtime_once, NULL, NULL))
        return GetLastError();
    return g_runtime_error;
}

const wchar_t* memfs_winfsp_runtime_directory(void) {
    if (memfs_winfsp_prepare_runtime() != ERROR_SUCCESS)
        return NULL;
    return g_runtime_dir;
}

static DWORD private_driver_path_for(const wchar_t* file_name,
                                     wchar_t path[MAX_PATH]) {
    wchar_t system_dir[MAX_PATH];
    UINT chars;

    if (file_name == NULL || path == NULL)
        return ERROR_INVALID_PARAMETER;

    chars = GetSystemDirectoryW(system_dir, _countof(system_dir));
    if (chars == 0)
        return GetLastError();
    if (chars >= _countof(system_dir))
        return ERROR_BUFFER_OVERFLOW;

    if (_snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\drivers\\%s",
                     system_dir, file_name) < 0)
        return ERROR_BUFFER_OVERFLOW;
    return ERROR_SUCCESS;
}

static DWORD driver_spec_for_machine(USHORT native_machine,
                                     MemfsEmbeddedDriverSpec* spec) {
    if (spec == NULL)
        return ERROR_INVALID_PARAMETER;

    switch (native_machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        spec->resource_id = IDR_MEMFS_WINFSP_SYS_X64;
        spec->primary_file = MEMFS_WINFSP_SYS_X64_FILE;
        spec->alternate_file = MEMFS_WINFSP_SYS_X64_ALT_FILE;
        return ERROR_SUCCESS;
    case IMAGE_FILE_MACHINE_ARM64:
        spec->resource_id = IDR_MEMFS_WINFSP_SYS_ARM64;
        spec->primary_file = MEMFS_WINFSP_SYS_ARM64_FILE;
        spec->alternate_file = MEMFS_WINFSP_SYS_ARM64_ALT_FILE;
        return ERROR_SUCCESS;
    default:
        return ERROR_NOT_SUPPORTED;
    }
}

static DWORD native_machine_type(USHORT* native_machine) {
    typedef BOOL (WINAPI *IsWow64Process2Fn)(HANDLE, USHORT*, USHORT*);
    HMODULE kernel32;
    IsWow64Process2Fn is_wow64_process2;
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT host_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    SYSTEM_INFO info;

    if (native_machine == NULL)
        return ERROR_INVALID_PARAMETER;

    kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 != NULL) {
        is_wow64_process2 = (IsWow64Process2Fn)GetProcAddress(
            kernel32, "IsWow64Process2");
        if (is_wow64_process2 != NULL) {
            if (!is_wow64_process2(
                    GetCurrentProcess(), &process_machine, &host_machine))
                return GetLastError();
            if (host_machine != IMAGE_FILE_MACHINE_UNKNOWN) {
                *native_machine = host_machine;
                return ERROR_SUCCESS;
            }
        }
    }

    /*
     * Fallback for older x64 Windows. Windows 11 on Arm exposes
     * IsWow64Process2, which is required because GetNativeSystemInfo reports
     * emulated processor details to x64 applications for compatibility.
     */
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        *native_machine = IMAGE_FILE_MACHINE_AMD64;
        return ERROR_SUCCESS;
    }

    return ERROR_NOT_SUPPORTED;
}

static DWORD current_driver_spec(MemfsEmbeddedDriverSpec* spec) {
    USHORT native_machine;
    DWORD error = native_machine_type(&native_machine);
    if (error != ERROR_SUCCESS)
        return error;
    return driver_spec_for_machine(native_machine, spec);
}

#if defined(MEMFS_DRIVER_TESTING)
DWORD memfs_driver_test_spec_for_machine(
    USHORT native_machine,
    WORD* resource_id,
    const wchar_t** primary_file,
    const wchar_t** alternate_file) {
    MemfsEmbeddedDriverSpec spec;
    DWORD error = driver_spec_for_machine(native_machine, &spec);

    if (error != ERROR_SUCCESS)
        return error;
    if (resource_id)
        *resource_id = spec.resource_id;
    if (primary_file)
        *primary_file = spec.primary_file;
    if (alternate_file)
        *alternate_file = spec.alternate_file;
    return ERROR_SUCCESS;
}

DWORD memfs_driver_test_native_machine(USHORT* native_machine) {
    return native_machine_type(native_machine);
}
#endif

static DWORD embedded_driver_paths(const MemfsEmbeddedDriverSpec* spec,
                                   wchar_t primary[MAX_PATH],
                                   wchar_t alternate[MAX_PATH]) {
    DWORD error;

    if (spec == NULL)
        return ERROR_INVALID_PARAMETER;

    error = private_driver_path_for(spec->primary_file, primary);
    if (error != ERROR_SUCCESS)
        return error;
    return private_driver_path_for(spec->alternate_file, alternate);
}

static DWORD resource_matches_file(WORD resource_id,
                                   const wchar_t* path,
                                   BOOL* matches) {
    const void* data;
    DWORD size;
    DWORD error;

    error = resource_view(resource_id, &data, &size);
    if (error != ERROR_SUCCESS)
        return error;
    return file_matches_buffer(path, data, size, matches);
}

static DWORD query_service_state(SC_HANDLE service, DWORD* state) {
    SERVICE_STATUS_PROCESS status;
    DWORD bytes = 0;

    if (service == NULL || state == NULL)
        return ERROR_INVALID_PARAMETER;
    if (!QueryServiceStatusEx(service,
                              SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&status,
                              sizeof(status),
                              &bytes))
        return GetLastError();

    *state = status.dwCurrentState;
    return ERROR_SUCCESS;
}

static DWORD query_service_binary_path(SC_HANDLE service,
                                       wchar_t path[MAX_PATH]) {
    BYTE buffer[8192];
    QUERY_SERVICE_CONFIGW* config = (QUERY_SERVICE_CONFIGW*)buffer;
    DWORD needed = 0;
    const wchar_t* source;
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

static DWORD wait_service_stopped(SC_HANDLE service, DWORD timeout_ms) {
    ULONGLONG deadline = GetTickCount64() + timeout_ms;
    DWORD state;
    DWORD error;

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

static DWORD delete_private_file(const wchar_t* path, BOOL* reboot_required) {
    DWORD error;

    if (DeleteFileW(path))
        return ERROR_SUCCESS;

    error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        return ERROR_SUCCESS;

    if (error == ERROR_SHARING_VIOLATION ||
        error == ERROR_ACCESS_DENIED ||
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

static DWORD delete_all_private_driver_files(BOOL* reboot_required) {
    static const wchar_t* const file_names[] = {
        MEMFS_WINFSP_SYS_X64_FILE,
        MEMFS_WINFSP_SYS_X64_ALT_FILE,
        MEMFS_WINFSP_SYS_ARM64_FILE,
        MEMFS_WINFSP_SYS_ARM64_ALT_FILE,
    };
    wchar_t path[MAX_PATH];
    DWORD first_error = ERROR_SUCCESS;
    DWORD error;
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

static const wchar_t* select_private_update_path(const wchar_t* running_path,
                                                 const wchar_t* primary_path,
                                                 const wchar_t* alternate_path) {
    if (running_path != NULL && primary_path != NULL &&
        _wcsicmp(running_path, primary_path) == 0)
        return alternate_path;
    return primary_path;
}

static DWORD plan_running_private_driver_update(
    const wchar_t* configured_path,
    BOOL configured_matches_payload,
    const wchar_t* primary_path,
    const wchar_t* alternate_path,
    const wchar_t** stage_path) {
    if (stage_path == NULL)
        return ERROR_INVALID_PARAMETER;
    *stage_path = NULL;

    /*
     * QueryServiceConfig reports the image configured for the next service
     * start; it does not identify the image that is already loaded in the
     * kernel. Therefore a matching configured file only proves that an upgrade
     * has been staged, never that the running driver has changed.
     */
    if (configured_matches_payload)
        return ERROR_SUCCESS_REBOOT_REQUIRED;

    *stage_path = select_private_update_path(
        configured_path, primary_path, alternate_path);
    return ERROR_SUCCESS;
}

#if defined(MEMFS_DRIVER_TESTING)
const wchar_t* memfs_driver_test_select_update_path(const wchar_t* running_path,
                                                    const wchar_t* primary_path,
                                                    const wchar_t* alternate_path) {
    return select_private_update_path(running_path, primary_path, alternate_path);
}

DWORD memfs_driver_test_plan_running_update(
    const wchar_t* configured_path,
    BOOL configured_matches_payload,
    const wchar_t* primary_path,
    const wchar_t* alternate_path,
    const wchar_t** stage_path) {
    return plan_running_private_driver_update(
        configured_path, configured_matches_payload,
        primary_path, alternate_path, stage_path);
}
#endif

DWORD memfs_winfsp_install_embedded_driver(void) {
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    MemfsEmbeddedDriverSpec driver_spec;
    wchar_t primary_path[MAX_PATH];
    wchar_t alternate_path[MAX_PATH];
    wchar_t configured_path[MAX_PATH];
    const wchar_t* install_path = primary_path;
    DWORD service_state = SERVICE_STOPPED;
    DWORD error;
    DWORD open_error;
    DWORD start_error;
    BOOL matches = FALSE;

    error = current_driver_spec(&driver_spec);
    if (error != ERROR_SUCCESS)
        return error;

    error = embedded_driver_paths(&driver_spec, primary_path, alternate_path);
    if (error != ERROR_SUCCESS)
        return error;

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (manager == NULL)
        return GetLastError();

    service = OpenServiceW(manager,
                           MEMFS_WINFSP_DRIVER_SERVICE,
                           SERVICE_START |
                           SERVICE_QUERY_STATUS |
                           SERVICE_QUERY_CONFIG |
                           SERVICE_CHANGE_CONFIG);
    if (service == NULL) {
        open_error = GetLastError();
        if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
            CloseServiceHandle(manager);
            return open_error;
        }

        error = extract_resource(driver_spec.resource_id, primary_path);
        if (error != ERROR_SUCCESS) {
            CloseServiceHandle(manager);
            return error;
        }

        service = CreateServiceW(manager,
                                 MEMFS_WINFSP_DRIVER_SERVICE,
                                 MEMFS_WINFSP_DRIVER_SERVICE,
                                 SERVICE_START |
                                 SERVICE_QUERY_STATUS |
                                 SERVICE_QUERY_CONFIG |
                                 SERVICE_CHANGE_CONFIG,
                                 SERVICE_FILE_SYSTEM_DRIVER,
                                 SERVICE_DEMAND_START,
                                 SERVICE_ERROR_NORMAL,
                                 primary_path,
                                 NULL, NULL, NULL, NULL, NULL);
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
            const wchar_t* stage_path = NULL;

            /*
             * SCM exposes the configured image for the next start, not the
             * image already loaded in the kernel. Never use this path as proof
             * that a running driver has been upgraded.
             */
            error = query_service_binary_path(service, configured_path);
            if (error != ERROR_SUCCESS)
                goto exit;

            error = resource_matches_file(
                driver_spec.resource_id, configured_path, &matches);
            if (error != ERROR_SUCCESS)
                goto exit;

            error = plan_running_private_driver_update(
                configured_path, matches, primary_path, alternate_path,
                &stage_path);
            if (error == ERROR_SUCCESS_REBOOT_REQUIRED)
                goto exit;
            if (error != ERROR_SUCCESS)
                goto exit;

            /*
             * The running image remains untouched. Stage the payload in the
             * other MemfsC-owned slot and configure that image for the next
             * service start. Repeated calls are idempotent: once that configured
             * file matches, the branch above returns REBOOT_REQUIRED without
             * rewriting it or claiming the loaded image changed.
             */
            error = extract_resource(driver_spec.resource_id, stage_path);
            if (error != ERROR_SUCCESS)
                goto exit;

            if (!ChangeServiceConfigW(service,
                                      SERVICE_FILE_SYSTEM_DRIVER,
                                      SERVICE_DEMAND_START,
                                      SERVICE_ERROR_NORMAL,
                                      stage_path,
                                      NULL, NULL, NULL, NULL, NULL, NULL)) {
                error = GetLastError();
                goto exit;
            }

            error = ERROR_SUCCESS_REBOOT_REQUIRED;
            goto exit;
        }

        error = extract_resource(driver_spec.resource_id, primary_path);
        if (error != ERROR_SUCCESS)
            goto exit;
        install_path = primary_path;

        if (!ChangeServiceConfigW(service,
                                  SERVICE_FILE_SYSTEM_DRIVER,
                                  SERVICE_DEMAND_START,
                                  SERVICE_ERROR_NORMAL,
                                  install_path,
                                  NULL, NULL, NULL, NULL, NULL, NULL)) {
            error = GetLastError();
            goto exit;
        }
    }

    if (!StartServiceW(service, 0, NULL)) {
        start_error = GetLastError();
        error = start_error == ERROR_SERVICE_ALREADY_RUNNING
                    ? ERROR_SUCCESS
                    : start_error;
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

static BOOL private_driver_payload_cleanup_allowed(DWORD service_error) {
    return service_error == ERROR_SUCCESS;
}

#if defined(MEMFS_DRIVER_TESTING)
BOOL memfs_driver_test_payload_cleanup_allowed(DWORD service_error) {
    return private_driver_payload_cleanup_allowed(service_error);
}
#endif

DWORD memfs_winfsp_uninstall_embedded_driver(void) {
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS status;
    DWORD state;
    DWORD error;
    DWORD first_error = ERROR_SUCCESS;
    BOOL reboot_required = FALSE;

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (manager == NULL)
        return GetLastError();

    service = OpenServiceW(manager,
                           MEMFS_WINFSP_DRIVER_SERVICE,
                           SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
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

        if (first_error == ERROR_SUCCESS &&
            !DeleteService(service)) {
            error = GetLastError();
            if (error != ERROR_SERVICE_MARKED_FOR_DELETE)
                first_error = error;
        }
    }

    if (service)
        CloseServiceHandle(service);
    CloseServiceHandle(manager);

    /*
     * A failed query/stop/wait/delete means SCM state is not known to be
     * quiescent. Preserve every private payload so a still-referenced service
     * can be retried safely; never turn an uninstall failure into a reboot-time
     * file deletion.
     */
    if (!private_driver_payload_cleanup_allowed(first_error))
        return first_error;

    /*
     * Only ever remove our private payload names. Never use the configured
     * service path as a deletion target: a tampered/legacy service must not
     * make us delete an official WinFsp binary.
     */
    error = delete_all_private_driver_files(&reboot_required);
    if (error != ERROR_SUCCESS)
        return error;
    return reboot_required ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS;
}
