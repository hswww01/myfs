#pragma once

#include <Windows.h>

DWORD scpfs_winfsp_prepare_runtime(void);
DWORD scpfs_winfsp_install_embedded_driver(void);
const wchar_t* scpfs_winfsp_runtime_directory(void);

#if defined(SCPFS_DRIVER_TESTING)
DWORD scpfs_driver_test_file_matches_buffer(const wchar_t* path,
                                            const void* expected,
                                            DWORD expected_size,
                                            BOOL* matches);
const wchar_t* scpfs_driver_test_select_update_path(
    const wchar_t* running_path,
    const wchar_t* primary_path,
    const wchar_t* alternate_path);
DWORD scpfs_driver_test_spec_for_machine(
    USHORT native_machine,
    WORD* resource_id,
    const wchar_t** primary_file,
    const wchar_t** alternate_file);
DWORD scpfs_driver_test_native_machine(USHORT* native_machine);
DWORD scpfs_driver_test_plan_running_update(
    const wchar_t* configured_path,
    BOOL configured_matches_payload,
    const wchar_t* primary_path,
    const wchar_t* alternate_path,
    const wchar_t** stage_path);
BOOL scpfs_driver_test_payload_cleanup_allowed(DWORD service_error);
#endif
