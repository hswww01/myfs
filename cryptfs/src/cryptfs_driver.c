#include "cryptfs_driver.h"
#include "cryptfs_resource.h"

#include <Windows.h>
#include <stdint.h>
#include <wchar.h>

#define CRYPTFS_WINFSP_DRIVER_SERVICE L"WinFsp+CryptfsC"
#define CRYPTFS_RUNTIME_DIR_NAME L"CryptfsC"

#define CRYPTFS_WINFSP_DLL_FILE L"winfsp-x64.dll"
#define CRYPTFS_WINFSP_SYS_X64_FILE L"cryptfs-winfsp-x64.sys"
#define CRYPTFS_WINFSP_SYS_X64_ALT_FILE L"cryptfs-winfsp-x64.alt.sys"
#define CRYPTFS_WINFSP_SYS_ARM64_FILE L"cryptfs-winfsp-a64.sys"
#define CRYPTFS_WINFSP_SYS_ARM64_ALT_FILE L"cryptfs-winfsp-a64.alt.sys"

typedef struct CryptfsEmbeddedDriverSpec {
    WORD resource_id;
    const wchar_t* primary_file;
    const wchar_t* alternate_file;
} CryptfsEmbeddedDriverSpec;

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

#if defined(CRYPTFS_DRIVER_TESTING)
DWORD cryptfs_driver_test_file_matches_buffer(const wchar_t* path,
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

#if defined(CRYPTFS_WINFSP_STATIC)
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
                     L"%s\\%s", program_data, CRYPTFS_RUNTIME_DIR_NAME) < 0) {
        g_runtime_error = ERROR_BUFFER_OVERFLOW;
        return TRUE;
    }

    if (!CreateDirectoryW(g_runtime_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        g_runtime_error = GetLastError();
        return TRUE;
    }

    if (_snwprintf_s(dll_path, _countof(dll_path), _TRUNCATE,
                     L"%s\\%s", g_runtime_dir, CRYPTFS_WINFSP_DLL_FILE) < 0) {
        g_runtime_error = ERROR_BUFFER_OVERFLOW;
        return TRUE;
    }

    g_runtime_error = extract_resource(IDR_CRYPTFS_WINFSP_DLL, dll_path);
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

DWORD cryptfs_winfsp_prepare_runtime(void) {
    if (!InitOnceExecuteOnce(&g_runtime_once, prepare_runtime_once, NULL, NULL))
        return GetLastError();
    return g_runtime_error;
}

const wchar_t* cryptfs_winfsp_runtime_directory(void) {
    if (cryptfs_winfsp_prepare_runtime() != ERROR_SUCCESS)
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
                                     CryptfsEmbeddedDriverSpec* spec) {
    if (spec == NULL)
        return ERROR_INVALID_PARAMETER;

    switch (native_machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        spec->resource_id = IDR_CRYPTFS_WINFSP_SYS_X64;
        spec->primary_file = CRYPTFS_WINFSP_SYS_X64_FILE;
        spec->alternate_file = CRYPTFS_WINFSP_SYS_X64_ALT_FILE;
        return ERROR_SUCCESS;
    case IMAGE_FILE_MACHINE_ARM64:
        spec->resource_id = IDR_CRYPTFS_WINFSP_SYS_ARM64;
        spec->primary_file = CRYPTFS_WINFSP_SYS_ARM64_FILE;
        spec->alternate_file = CRYPTFS_WINFSP_SYS_ARM64_ALT_FILE;
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

static DWORD current_driver_spec(CryptfsEmbeddedDriverSpec* spec) {
    USHORT native_machine;
    DWORD error = native_machine_type(&native_machine);
    if (error != ERROR_SUCCESS)
        return error;
    return driver_spec_for_machine(native_machine, spec);
}

#if defined(CRYPTFS_DRIVER_TESTING)
DWORD cryptfs_driver_test_spec_for_machine(
    USHORT native_machine,
    WORD* resource_id,
    const wchar_t** primary_file,
    const wchar_t** alternate_file) {
    CryptfsEmbeddedDriverSpec spec;
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

DWORD cryptfs_driver_test_native_machine(USHORT* native_machine) {
    return native_machine_type(native_machine);
}
#endif

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

#if defined(CRYPTFS_DRIVER_TESTING)
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

const wchar_t* cryptfs_driver_test_select_update_path(const wchar_t* running_path,
                                                    const wchar_t* primary_path,
                                                    const wchar_t* alternate_path) {
    return select_private_update_path(running_path, primary_path, alternate_path);
}

DWORD cryptfs_driver_test_plan_running_update(
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

DWORD cryptfs_winfsp_install_embedded_driver(void) {
    SC_HANDLE manager = NULL;
    SC_HANDLE service = NULL;
    CryptfsEmbeddedDriverSpec driver_spec;
    wchar_t primary_path[MAX_PATH];
    wchar_t configured_path[MAX_PATH];
    DWORD service_state = SERVICE_STOPPED;
    DWORD error;
    DWORD open_error;
    BOOL matches = FALSE;

    error = current_driver_spec(&driver_spec);
    if (error != ERROR_SUCCESS)
        return error;

    error = private_driver_path_for(driver_spec.primary_file, primary_path);
    if (error != ERROR_SUCCESS)
        return error;

    manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (manager == NULL)
        return GetLastError();

    service = OpenServiceW(manager,
                           CRYPTFS_WINFSP_DRIVER_SERVICE,
                           SERVICE_START |
                           SERVICE_QUERY_STATUS |
                           SERVICE_QUERY_CONFIG);
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
                                 CRYPTFS_WINFSP_DRIVER_SERVICE,
                                 CRYPTFS_WINFSP_DRIVER_SERVICE,
                                 SERVICE_START |
                                 SERVICE_QUERY_STATUS |
                                 SERVICE_QUERY_CONFIG,
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
            /* SCM config cannot prove the already-loaded image. Never modify,
             * stop, or stage a different image while this service is active. */
            error = ERROR_SERVICE_ALREADY_RUNNING;
            goto exit;
        }

        error = query_service_binary_path(service, configured_path);
        if (error != ERROR_SUCCESS)
            goto exit;
        error = resource_matches_file(driver_spec.resource_id,
            configured_path, &matches);
        if (error != ERROR_SUCCESS)
            goto exit;
        if (!matches) {
            error = ERROR_SERVICE_EXISTS;
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


