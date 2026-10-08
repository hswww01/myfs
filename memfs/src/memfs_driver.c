/*
 * Memfs's private embedded WinFsp driver. The implementation is shared in
 * frontend/src/fs_frontend_driver.c; this file only supplies Memfs's
 * service name, payload file names and resource identifiers.
 */
#include "memfs_driver.h"
#include "memfs_resource.h"
#include "fs_frontend_driver.h"

static const FSF_DRIVER_SPEC g_driver_spec = {
    L"WinFsp+MemfsC",
    L"MemfsC",
#if defined(MEMFS_WINFSP_STATIC)
    TRUE,
#else
    FALSE,
#endif
    IDR_MEMFS_WINFSP_DLL,
    IDR_MEMFS_WINFSP_SYS_X64,
    IDR_MEMFS_WINFSP_SYS_ARM64,
    L"memfs-winfsp-x64.sys",
    L"memfs-winfsp-x64.alt.sys",
    L"memfs-winfsp-a64.sys",
    L"memfs-winfsp-a64.alt.sys",
};

DWORD memfs_winfsp_prepare_runtime(void) {
    return fsf_driver_prepare_runtime(&g_driver_spec);
}

const wchar_t* memfs_winfsp_runtime_directory(void) {
    return fsf_driver_runtime_directory(&g_driver_spec);
}

DWORD memfs_winfsp_install_embedded_driver(void) {
    return fsf_driver_install(&g_driver_spec);
}

DWORD memfs_winfsp_uninstall_embedded_driver(void) {
    return fsf_driver_uninstall(&g_driver_spec);
}

#if defined(MEMFS_DRIVER_TESTING)
DWORD memfs_driver_test_file_matches_buffer(const wchar_t* path,
                                            const void* expected,
                                            DWORD expected_size,
                                            BOOL* matches) {
    return fsf_driver_file_matches_buffer(path, expected, expected_size, matches);
}

const wchar_t* memfs_driver_test_select_update_path(
    const wchar_t* running_path,
    const wchar_t* primary_path,
    const wchar_t* alternate_path) {
    return fsf_driver_select_update_path(running_path, primary_path, alternate_path);
}

DWORD memfs_driver_test_spec_for_machine(
    USHORT native_machine,
    WORD* resource_id,
    const wchar_t** primary_file,
    const wchar_t** alternate_file) {
    return fsf_driver_spec_for_machine(&g_driver_spec, native_machine,
        resource_id, primary_file, alternate_file);
}

DWORD memfs_driver_test_native_machine(USHORT* native_machine) {
    return fsf_driver_native_machine(native_machine);
}

DWORD memfs_driver_test_plan_running_update(
    const wchar_t* configured_path,
    BOOL configured_matches_payload,
    const wchar_t* primary_path,
    const wchar_t* alternate_path,
    const wchar_t** stage_path) {
    return fsf_driver_plan_running_update(configured_path,
        configured_matches_payload, primary_path, alternate_path, stage_path);
}

BOOL memfs_driver_test_payload_cleanup_allowed(DWORD service_error) {
    return fsf_driver_payload_cleanup_allowed(service_error);
}
#endif
