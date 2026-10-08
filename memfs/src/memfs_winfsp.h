#pragma once

#include "fs_frontend.h"
#include <winfsp/winfsp.h>

#include "memfs_core.h"

typedef struct MemfsWinFsp {
	FSP_FILE_SYSTEM* file_system;
	FSF_WINFSP* frontend;
	Memfs* store;
} MemfsWinFsp;

NTSTATUS memfs_winfsp_create(const MemfsOptions* options, MemfsWinFsp** out_instance);
NTSTATUS memfs_winfsp_create_ex(
    const MemfsOptions* options,
    MemfsWinFsp** out_instance,
    DWORD* detail_error);

NTSTATUS memfs_winfsp_mount(MemfsWinFsp* instance, const wchar_t* mount_point);
NTSTATUS memfs_winfsp_start(MemfsWinFsp* instance, uint32_t thread_count);
HANDLE memfs_winfsp_dispatcher_stopped_event(MemfsWinFsp* instance);
bool memfs_winfsp_dispatcher_stopped_normally(const MemfsWinFsp* instance);
NTSTATUS memfs_winfsp_dispatcher_result(const MemfsWinFsp* instance);
#if defined(MEMFS_WINFSP_TESTING)
NTSTATUS memfs_winfsp_test_get_volume_info(
    FSP_FILE_SYSTEM* fs, FSP_FSCTL_VOLUME_INFO* info);
void memfs_winfsp_test_volume_params(FSP_FSCTL_VOLUME_PARAMS* params);
NTSTATUS memfs_winfsp_test_overwrite(
    FSP_FILE_SYSTEM* fs, MemfsNode* node, UINT32 attributes,
    BOOLEAN replace_attributes, UINT64 allocation_size, FSP_FSCTL_FILE_INFO* info);
void memfs_winfsp_test_cleanup(FSP_FILE_SYSTEM* fs, MemfsNode* node, ULONG flags);
NTSTATUS memfs_winfsp_test_read_directory(
    FSP_FILE_SYSTEM* fs, MemfsNode* directory, PWSTR pattern, PWSTR marker,
    PVOID buffer, ULONG length, PULONG transferred);
NTSTATUS memfs_winfsp_test_get_security(FSP_FILE_SYSTEM* fs, MemfsNode* node,
    PSECURITY_DESCRIPTOR buffer, SIZE_T* size);
NTSTATUS memfs_winfsp_test_get_security_by_name(FSP_FILE_SYSTEM* fs, PWSTR name,
    PSECURITY_DESCRIPTOR buffer, SIZE_T* size);
NTSTATUS memfs_winfsp_test_set_security(FSP_FILE_SYSTEM* fs, MemfsNode* node,
    SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor);
bool memfs_winfsp_test_name_matches_pattern(
    const wchar_t* pattern,
    const wchar_t* name);
NTSTATUS memfs_winfsp_test_get_dir_info_by_name(
    FSP_FILE_SYSTEM* fs,
    PVOID directory_context,
    PWSTR name,
    FSP_FSCTL_DIR_INFO* dir_info);
#endif

void memfs_winfsp_stop(MemfsWinFsp* instance);
void memfs_winfsp_destroy(MemfsWinFsp* instance);
