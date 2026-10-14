/*
 * Scpfs's embedded WinFsp driver: the driver shared by all products
 * (FSF_SHARED_DRIVER_*, implemented in frontend/src/fs_frontend_driver.c);
 * this file only supplies Scpfs's resource identifiers.
 */
#include "scpfs_driver.h"
#include "scpfs_resource.h"
#include "fs_frontend_driver.h"

static const FSF_DRIVER_SPEC g_driver_spec = {
    FSF_SHARED_DRIVER_SERVICE,
    FSF_SHARED_DRIVER_RUNTIME_DIR,
#if defined(SCPFS_WINFSP_STATIC)
    TRUE,
#else
    FALSE,
#endif
    IDR_SCPFS_WINFSP_DLL,
    IDR_SCPFS_WINFSP_SYS_X64,
    IDR_SCPFS_WINFSP_SYS_ARM64,
    FSF_SHARED_DRIVER_SYS_X64,
    FSF_SHARED_DRIVER_SYS_X64_ALT,
    FSF_SHARED_DRIVER_SYS_ARM64,
    FSF_SHARED_DRIVER_SYS_ARM64_ALT,
};

DWORD scpfs_winfsp_prepare_runtime(void) {
    return fsf_driver_prepare_runtime(&g_driver_spec);
}

const wchar_t* scpfs_winfsp_runtime_directory(void) {
    return fsf_driver_runtime_directory(&g_driver_spec);
}

DWORD scpfs_winfsp_install_embedded_driver(void) {
    return fsf_driver_install(&g_driver_spec);
}

#if defined(SCPFS_DRIVER_TESTING)
DWORD scpfs_driver_test_file_matches_buffer(const wchar_t* path,
                                            const void* expected,
                                            DWORD expected_size,
                                            BOOL* matches) {
    return fsf_driver_file_matches_buffer(path, expected, expected_size, matches);
}

const wchar_t* scpfs_driver_test_select_update_path(
    const wchar_t* running_path,
    const wchar_t* primary_path,
    const wchar_t* alternate_path) {
    return fsf_driver_select_update_path(running_path, primary_path, alternate_path);
}

DWORD scpfs_driver_test_spec_for_machine(
    USHORT native_machine,
    WORD* resource_id,
    const wchar_t** primary_file,
    const wchar_t** alternate_file) {
    return fsf_driver_spec_for_machine(&g_driver_spec, native_machine,
        resource_id, primary_file, alternate_file);
}

DWORD scpfs_driver_test_native_machine(USHORT* native_machine) {
    return fsf_driver_native_machine(native_machine);
}

DWORD scpfs_driver_test_plan_running_update(
    const wchar_t* configured_path,
    BOOL configured_matches_payload,
    const wchar_t* primary_path,
    const wchar_t* alternate_path,
    const wchar_t** stage_path) {
    return fsf_driver_plan_running_update(configured_path,
        configured_matches_payload, primary_path, alternate_path, stage_path);
}

BOOL scpfs_driver_test_payload_cleanup_allowed(DWORD service_error) {
    return fsf_driver_payload_cleanup_allowed(service_error);
}
#endif
