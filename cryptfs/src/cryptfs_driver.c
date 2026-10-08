/*
 * Cryptfs's private embedded WinFsp driver. The implementation is shared in
 * frontend/src/fs_frontend_driver.c; this file only supplies Cryptfs's
 * service name, payload file names and resource identifiers.
 */
#include "cryptfs_driver.h"
#include "cryptfs_resource.h"
#include "fs_frontend_driver.h"

static const FSF_DRIVER_SPEC g_driver_spec = {
    L"WinFsp+CryptfsC",
    L"CryptfsC",
#if defined(CRYPTFS_WINFSP_STATIC)
    TRUE,
#else
    FALSE,
#endif
    IDR_CRYPTFS_WINFSP_DLL,
    IDR_CRYPTFS_WINFSP_SYS_X64,
    IDR_CRYPTFS_WINFSP_SYS_ARM64,
    L"cryptfs-winfsp-x64.sys",
    L"cryptfs-winfsp-x64.alt.sys",
    L"cryptfs-winfsp-a64.sys",
    L"cryptfs-winfsp-a64.alt.sys",
};

DWORD cryptfs_winfsp_prepare_runtime(void) {
    return fsf_driver_prepare_runtime(&g_driver_spec);
}

const wchar_t* cryptfs_winfsp_runtime_directory(void) {
    return fsf_driver_runtime_directory(&g_driver_spec);
}

DWORD cryptfs_winfsp_install_embedded_driver(void) {
    return fsf_driver_install(&g_driver_spec);
}

#if defined(CRYPTFS_DRIVER_TESTING)
DWORD cryptfs_driver_test_file_matches_buffer(const wchar_t* path,
                                            const void* expected,
                                            DWORD expected_size,
                                            BOOL* matches) {
    return fsf_driver_file_matches_buffer(path, expected, expected_size, matches);
}

const wchar_t* cryptfs_driver_test_select_update_path(
    const wchar_t* running_path,
    const wchar_t* primary_path,
    const wchar_t* alternate_path) {
    return fsf_driver_select_update_path(running_path, primary_path, alternate_path);
}

DWORD cryptfs_driver_test_spec_for_machine(
    USHORT native_machine,
    WORD* resource_id,
    const wchar_t** primary_file,
    const wchar_t** alternate_file) {
    return fsf_driver_spec_for_machine(&g_driver_spec, native_machine,
        resource_id, primary_file, alternate_file);
}

DWORD cryptfs_driver_test_native_machine(USHORT* native_machine) {
    return fsf_driver_native_machine(native_machine);
}

DWORD cryptfs_driver_test_plan_running_update(
    const wchar_t* configured_path,
    BOOL configured_matches_payload,
    const wchar_t* primary_path,
    const wchar_t* alternate_path,
    const wchar_t** stage_path) {
    return fsf_driver_plan_running_update(configured_path,
        configured_matches_payload, primary_path, alternate_path, stage_path);
}

BOOL cryptfs_driver_test_payload_cleanup_allowed(DWORD service_error) {
    return fsf_driver_payload_cleanup_allowed(service_error);
}
#endif
