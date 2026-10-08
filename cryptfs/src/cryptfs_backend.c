#include "cryptfs_backend.h"
#include "cryptfs_driver.h"

#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

struct CRYPTFS_BACKEND {
	CF_STORE *store;
	FSF_WINFSP *frontend;
	FSP_FILE_SYSTEM *file_system;
};

static INIT_ONCE g_security_once = INIT_ONCE_STATIC_INIT;
static PSECURITY_DESCRIPTOR g_security_descriptor;

static BOOL CALLBACK cryptfs_security_init(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
	HANDLE token = NULL;
	DWORD user_size = 0, group_size = 0;
	TOKEN_USER *token_user = NULL;
	TOKEN_PRIMARY_GROUP *token_group = NULL;
	LPWSTR user_sid = NULL, group_sid = NULL;
	WCHAR sddl[1024];
	BOOL ok = FALSE;
	(void)once;
	(void)parameter;
	(void)context;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
	(void)GetTokenInformation(token, TokenUser, NULL, 0, &user_size);
	(void)GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &group_size);
	if (user_size == 0 || group_size == 0) goto done;
	token_user = (TOKEN_USER *)malloc(user_size);
	token_group = (TOKEN_PRIMARY_GROUP *)malloc(group_size);
	if (token_user == NULL || token_group == NULL ||
		!GetTokenInformation(token, TokenUser, token_user, user_size, &user_size) ||
		!GetTokenInformation(token, TokenPrimaryGroup, token_group, group_size, &group_size) ||
		!ConvertSidToStringSidW(token_user->User.Sid, &user_sid) ||
		!ConvertSidToStringSidW(token_group->PrimaryGroup, &group_sid)) goto done;
	if (_snwprintf_s(sddl, _countof(sddl), _TRUNCATE,
		L"O:%lsG:%lsD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%ls)",
		user_sid, group_sid, user_sid) < 0) goto done;
	ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
		sddl, SDDL_REVISION_1, &g_security_descriptor, NULL);
done:
	SecureZeroMemory(sddl, sizeof(sddl));
	if (user_sid != NULL) LocalFree(user_sid);
	if (group_sid != NULL) LocalFree(group_sid);
	if (token_user != NULL) { SecureZeroMemory(token_user, user_size); free(token_user); }
	if (token_group != NULL) { SecureZeroMemory(token_group, group_size); free(token_group); }
	if (token != NULL) CloseHandle(token);
	return ok;
}

static NTSTATUS cryptfs_status(CF_RESULT result)
{
	switch (result) {
	case CF_OK: return STATUS_SUCCESS;
	case CF_NOT_FOUND: return STATUS_OBJECT_NAME_NOT_FOUND;
	case CF_PATH_NOT_FOUND: return STATUS_OBJECT_PATH_NOT_FOUND;
	case CF_EXISTS: return STATUS_OBJECT_NAME_COLLISION;
	case CF_NOT_DIRECTORY: return STATUS_NOT_A_DIRECTORY;
	case CF_IS_DIRECTORY: return STATUS_FILE_IS_A_DIRECTORY;
	case CF_NOT_EMPTY: return STATUS_DIRECTORY_NOT_EMPTY;
	case CF_NO_SPACE: return STATUS_DISK_FULL;
	case CF_NO_MEMORY: return STATUS_INSUFFICIENT_RESOURCES;
	case CF_ACCESS: return STATUS_ACCESS_DENIED;
	case CF_DATA_ERROR: return STATUS_DATA_ERROR;
	case CF_IO_ERROR: return STATUS_IO_DEVICE_ERROR;
	case CF_NOT_SUPPORTED: return STATUS_NOT_SUPPORTED;
	case CF_INVALID:
	default: return STATUS_INVALID_PARAMETER;
	}
}

static NTSTATUS cryptfs_win32_status(DWORD error)
{
	if (error == ERROR_SUCCESS) return STATUS_SUCCESS;
	if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD)
		return STATUS_ACCESS_DENIED;
	if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
		error == ERROR_MOD_NOT_FOUND || error == ERROR_DLL_NOT_FOUND)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY)
		return STATUS_INSUFFICIENT_RESOURCES;
	if (error == ERROR_SUCCESS_REBOOT_REQUIRED) return STATUS_DEVICE_NOT_READY;
	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS cryptfs_resolve_create_failure(void *context, NTSTATUS first_status,
	BOOL *retry_create, DWORD *win32_detail_out)
{
	DWORD error;
	(void)context;
	if (retry_create == NULL) return STATUS_INVALID_PARAMETER;
	*retry_create = FALSE;
	if (win32_detail_out != NULL) *win32_detail_out = ERROR_SUCCESS;
	if (first_status != STATUS_NO_SUCH_DEVICE && first_status != STATUS_DRIVER_UNABLE_TO_LOAD)
		return first_status;
	error = cryptfs_winfsp_install_embedded_driver();
	if (error == ERROR_SUCCESS) {
		*retry_create = TRUE;
		return STATUS_SUCCESS;
	}
	if (win32_detail_out != NULL) *win32_detail_out = error;
	return cryptfs_win32_status(error);
}

static NTSTATUS cryptfs_get_info(CF_STORE *store, CF_NODE *node, FSP_FSCTL_FILE_INFO *out)
{
	CF_INFO info;
	CF_RESULT result = cf_node_info(store, node, &info);
	if (result != CF_OK) return cryptfs_status(result);
	memset(out, 0, sizeof(*out));
	out->FileAttributes = info.attributes;
	if (out->FileAttributes == 0)
		out->FileAttributes = (info.attributes & FILE_ATTRIBUTE_DIRECTORY) ?
			FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
	out->AllocationSize = info.allocation_size;
	out->FileSize = info.size;
	out->CreationTime = info.creation_time;
	out->LastAccessTime = info.access_time;
	out->LastWriteTime = info.write_time;
	out->ChangeTime = info.change_time;
	out->IndexNumber = info.id;
	return STATUS_SUCCESS;
}

static NTSTATUS cryptfs_copy_security(PSECURITY_DESCRIPTOR buffer, SIZE_T *size)
{
	SIZE_T required;
	if (!InitOnceExecuteOnce(&g_security_once, cryptfs_security_init, NULL, NULL))
		return STATUS_INSUFFICIENT_RESOURCES;
	if (g_security_descriptor == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	required = GetSecurityDescriptorLength(g_security_descriptor);
	if (size == NULL) return STATUS_SUCCESS;
	if (*size < required) {
		*size = required;
		return STATUS_BUFFER_OVERFLOW;
	}
	if (buffer != NULL) memcpy(buffer, g_security_descriptor, required);
	*size = required;
	return STATUS_SUCCESS;
}

static NTSTATUS fs_GetVolumeInfo(FSP_FILE_SYSTEM *fs, FSP_FSCTL_VOLUME_INFO *volume_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_STATS stats;
	CF_RESULT result = cf_store_stats(backend->store, &stats);
	if (result != CF_OK) return cryptfs_status(result);
	memset(volume_info, 0, sizeof(*volume_info));
	volume_info->TotalSize = stats.capacity;
	volume_info->FreeSize = stats.free_bytes;
	memcpy(volume_info->VolumeLabel, L"CRYPTFS", 7 * sizeof(WCHAR));
	volume_info->VolumeLabelLength = 7 * sizeof(WCHAR);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_SetVolumeLabel(FSP_FILE_SYSTEM *fs, PWSTR label,
	FSP_FSCTL_VOLUME_INFO *volume_info)
{
	(void)fs;
	(void)label;
	(void)volume_info;
	return STATUS_NOT_SUPPORTED;
}

static NTSTATUS fs_GetSecurityByName(FSP_FILE_SYSTEM *fs, PWSTR name,
	PUINT32 attributes, PSECURITY_DESCRIPTOR security_descriptor,
	SIZE_T *security_descriptor_size)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_NODE *node = NULL;
	CF_INFO info;
	CF_RESULT result = cf_node_open(backend->store, name, &node);
	NTSTATUS status;
	if (result != CF_OK) return cryptfs_status(result);
	result = cf_node_info(backend->store, node, &info);
	cf_node_close(backend->store, node);
	if (result != CF_OK) return cryptfs_status(result);
	if (attributes != NULL) *attributes = info.attributes;
	status = cryptfs_copy_security(security_descriptor, security_descriptor_size);
	return status;
}

static NTSTATUS fs_Create(FSP_FILE_SYSTEM *fs, PWSTR name, UINT32 create_options,
	UINT32 granted_access, UINT32 attributes, PSECURITY_DESCRIPTOR security,
	UINT64 allocation_size, PVOID *file_context, FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_NODE *node = NULL;
	CF_RESULT result;
	(void)granted_access;
	(void)security;
	if (attributes == INVALID_FILE_ATTRIBUTES) attributes = 0;
	if (create_options & FILE_DIRECTORY_FILE) attributes |= FILE_ATTRIBUTE_DIRECTORY;
	/* AllocationSize is advisory; the sparse store never preallocates, and
	 * rejecting it would fail ordinary CopyFile-style creates. */
	(void)allocation_size;
	result = cf_node_create(backend->store, name, attributes, &node);
	if (result != CF_OK) return cryptfs_status(result);
	*file_context = node;
	{
		NTSTATUS status = cryptfs_get_info(backend->store, node, file_info);
		if (!NT_SUCCESS(status)) {
			(void)cf_node_unlink(backend->store, node);
			cf_node_close(backend->store, node);
			*file_context = NULL;
		}
		return status;
	}
}

static NTSTATUS fs_Open(FSP_FILE_SYSTEM *fs, PWSTR name, UINT32 create_options,
	UINT32 granted_access, PVOID *file_context, FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_NODE *node = NULL;
	CF_INFO info;
	CF_RESULT result;
	(void)granted_access;
	result = cf_node_open(backend->store, name, &node);
	if (result != CF_OK) return cryptfs_status(result);
	result = cf_node_info(backend->store, node, &info);
	if (result != CF_OK) { cf_node_close(backend->store, node); return cryptfs_status(result); }
	if ((create_options & FILE_DIRECTORY_FILE) && !(info.attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		cf_node_close(backend->store, node); return STATUS_NOT_A_DIRECTORY;
	}
	if ((create_options & FILE_NON_DIRECTORY_FILE) && (info.attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		cf_node_close(backend->store, node); return STATUS_FILE_IS_A_DIRECTORY;
	}
	{
		NTSTATUS status = cryptfs_get_info(backend->store, node, file_info);
		if (!NT_SUCCESS(status)) { cf_node_close(backend->store, node); return status; }
	}
	*file_context = node;
	return STATUS_SUCCESS;
}

static NTSTATUS fs_Overwrite(FSP_FILE_SYSTEM *fs, PVOID context, UINT32 attributes,
	BOOLEAN replace_attributes, UINT64 allocation_size, FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_NODE *node = context;
	CF_INFO info;
	CF_RESULT result = cf_node_info(backend->store, node, &info);
	if (result != CF_OK) return cryptfs_status(result);
	if (info.attributes & FILE_ATTRIBUTE_DIRECTORY) return STATUS_FILE_IS_A_DIRECTORY;
	(void)allocation_size; /* Advisory only, as in fs_Create. */
	result = cf_node_resize(backend->store, node, 0, false);
	if (result != CF_OK) return cryptfs_status(result);
	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (!replace_attributes) attributes |= info.attributes;
		result = cf_node_set_basic(backend->store, node, attributes,
			info.creation_time, info.access_time, info.write_time, info.change_time);
		if (result != CF_OK) return cryptfs_status(result);
	}
	return cryptfs_get_info(backend->store, node, file_info);
}

static VOID fs_Cleanup(FSP_FILE_SYSTEM *fs, PVOID context, PWSTR name, ULONG flags)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_NODE *node = context;
	CF_INFO info;
	uint64_t now = 0;
	uint32_t attributes;
	(void)name;
	if (node == NULL) return;
	/* A deleted file needs no timestamp transaction first. */
	if ((flags & FspCleanupDelete) && cf_node_unlink(backend->store, node) == CF_OK) return;
	if (cf_node_info(backend->store, node, &info) != CF_OK) return;
	attributes = info.attributes;
	if (flags & FspCleanupSetArchiveBit) attributes |= FILE_ATTRIBUTE_ARCHIVE;
	if (flags & (FspCleanupSetArchiveBit | FspCleanupSetLastAccessTime |
		FspCleanupSetLastWriteTime | FspCleanupSetChangeTime)) {
		FILETIME ft;
		GetSystemTimeAsFileTime(&ft);
		now = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
		(void)cf_node_set_basic(backend->store, node, attributes,
			info.creation_time,
			(flags & FspCleanupSetLastAccessTime) ? now : info.access_time,
			(flags & FspCleanupSetLastWriteTime) ? now : info.write_time,
			(flags & FspCleanupSetChangeTime) ? now : info.change_time);
	}
}

static VOID fs_Close(FSP_FILE_SYSTEM *fs, PVOID context)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	if (context != NULL) cf_node_close(backend->store, context);
}

static NTSTATUS fs_Read(FSP_FILE_SYSTEM *fs, PVOID context, PVOID buffer,
	UINT64 offset, ULONG length, PULONG transferred)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	uint32_t read = 0;
	CF_RESULT result = cf_node_read(backend->store, context, buffer, offset, length, &read);
	*transferred = read;
	if (result != CF_OK && read == 0) return cryptfs_status(result);
	if (read == 0 && length != 0) return STATUS_END_OF_FILE;
	return STATUS_SUCCESS;
}

static NTSTATUS fs_Write(FSP_FILE_SYSTEM *fs, PVOID context, PVOID buffer,
	UINT64 offset, ULONG length, BOOLEAN to_eof, BOOLEAN constrained,
	PULONG transferred, FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	uint32_t written = 0;
	CF_RESULT result = cf_node_write(backend->store, context, buffer, offset,
		length, !!to_eof, !!constrained, &written);
	*transferred = written;
	if (result != CF_OK && written == 0) return cryptfs_status(result);
	return cryptfs_get_info(backend->store, context, file_info);
}

static NTSTATUS fs_Flush(FSP_FILE_SYSTEM *fs, PVOID context,
	FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_RESULT result = cf_store_flush(backend->store);
	if (result != CF_OK) return cryptfs_status(result);
	return context != NULL && file_info != NULL ?
		cryptfs_get_info(backend->store, context, file_info) : STATUS_SUCCESS;
}

static NTSTATUS fs_GetFileInfo(FSP_FILE_SYSTEM *fs, PVOID context,
	FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	return cryptfs_get_info(backend->store, context, file_info);
}

static NTSTATUS fs_SetBasicInfo(FSP_FILE_SYSTEM *fs, PVOID context,
	UINT32 attributes, UINT64 creation_time, UINT64 access_time,
	UINT64 write_time, UINT64 change_time, FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_INFO info;
	CF_RESULT result = cf_node_info(backend->store, context, &info);
	if (result != CF_OK) return cryptfs_status(result);
	if (attributes == INVALID_FILE_ATTRIBUTES) attributes = info.attributes;
	result = cf_node_set_basic(backend->store, context, attributes,
		creation_time ? creation_time : info.creation_time,
		access_time ? access_time : info.access_time,
		write_time ? write_time : info.write_time,
		change_time ? change_time : info.change_time);
	if (result != CF_OK) return cryptfs_status(result);
	return cryptfs_get_info(backend->store, context, file_info);
}

static NTSTATUS fs_SetFileSize(FSP_FILE_SYSTEM *fs, PVOID context,
	UINT64 new_size, BOOLEAN allocation_only, FSP_FSCTL_FILE_INFO *file_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_RESULT result;
	if (allocation_only) {
		/* NTFS semantics: shrinking allocation below EOF truncates; growing is advisory. */
		CF_INFO info;
		result = cf_node_info(backend->store, context, &info);
		if (result == CF_OK && new_size < info.size)
			result = cf_node_resize(backend->store, context, new_size, false);
	} else {
		result = cf_node_resize(backend->store, context, new_size, false);
	}
	if (result != CF_OK) return cryptfs_status(result);
	return cryptfs_get_info(backend->store, context, file_info);
}

static NTSTATUS fs_CanDelete(FSP_FILE_SYSTEM *fs, PVOID context, PWSTR name)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	(void)name;
	return cryptfs_status(cf_node_can_delete(backend->store, context));
}

static NTSTATUS fs_Rename(FSP_FILE_SYSTEM *fs, PVOID context, PWSTR name,
	PWSTR new_name, BOOLEAN replace)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	(void)name;
	return cryptfs_status(cf_node_rename(backend->store, context, new_name, !!replace));
}

static NTSTATUS fs_GetSecurity(FSP_FILE_SYSTEM *fs, PVOID context,
	PSECURITY_DESCRIPTOR buffer, SIZE_T *size)
{
	(void)fs;
	(void)context;
	return cryptfs_copy_security(buffer, size);
}

static NTSTATUS fs_SetSecurity(FSP_FILE_SYSTEM *fs, PVOID context,
	SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor)
{
	(void)fs;
	(void)context;
	(void)information;
	(void)descriptor;
	return STATUS_NOT_SUPPORTED;
}

static BOOL cryptfs_pattern_match(PCWSTR pattern, PCWSTR name)
{
	size_t p = 0, n = 0, star = SIZE_MAX, retry_name = 0;
	if (pattern == NULL || *pattern == L'\0' || wcscmp(pattern, L"*") == 0 ||
		wcscmp(pattern, L"*.*") == 0) return TRUE;
	while (name[n] != L'\0') {
		if (pattern[p] == L'?' || pattern[p] == name[n]) { ++p; ++n; continue; }
		if (pattern[p] == L'*') { star = p++; retry_name = n; continue; }
		if (star != SIZE_MAX) { p = star + 1; n = ++retry_name; continue; }
		return FALSE;
	}
	while (pattern[p] == L'*') ++p;
	return pattern[p] == L'\0';
}

static NTSTATUS cryptfs_add_dir_info(CF_STORE *store, CF_DIRENT *entry,
	PVOID buffer, ULONG length, PULONG transferred)
{
	BYTE storage[sizeof(FSP_FSCTL_DIR_INFO) + (CF_NAME_MAX + 1u) * sizeof(WCHAR)];
	FSP_FSCTL_DIR_INFO *info = (FSP_FSCTL_DIR_INFO *)storage;
	size_t chars = wcslen(entry->name), bytes = chars * sizeof(WCHAR);
	memset(storage, 0, sizeof(storage));
	info->Size = (UINT16)(sizeof(*info) + bytes);
	info->FileInfo.FileAttributes = entry->info.attributes;
	info->FileInfo.AllocationSize = entry->info.allocation_size;
	info->FileInfo.FileSize = entry->info.size;
	info->FileInfo.CreationTime = entry->info.creation_time;
	info->FileInfo.LastAccessTime = entry->info.access_time;
	info->FileInfo.LastWriteTime = entry->info.write_time;
	info->FileInfo.ChangeTime = entry->info.change_time;
	info->FileInfo.IndexNumber = entry->info.id;
	if (bytes != 0) memcpy(info->FileNameBuf, entry->name, bytes);
	(void)store;
	return FspFileSystemAddDirInfo(info, buffer, length, transferred) ?
		STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
}

static NTSTATUS fs_ReadDirectory(FSP_FILE_SYSTEM *fs, PVOID context,
	PWSTR pattern, PWSTR marker, PVOID buffer, ULONG length, PULONG transferred)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	/* Every entry takes at least a header, so this bounds what one buffer can hold. */
	size_t batch = length / sizeof(FSP_FSCTL_DIR_INFO) + 1;
	WCHAR resume[CF_NAME_MAX + 1];
	PCWSTR after = marker;
	*transferred = 0;
	for (;;) {
		CF_DIRENT *entries = NULL;
		size_t count = 0, i;
		bool more = false, full = false;
		/* Resume from the marker instead of copying the whole directory per call. */
		CF_RESULT result = cf_node_list_after(backend->store, context, after,
			batch, &entries, &count, &more);
		if (result != CF_OK) return cryptfs_status(result);
		for (i = 0; i < count; ++i) {
			if (!cryptfs_pattern_match(pattern, entries[i].name)) continue;
			if (cryptfs_add_dir_info(backend->store, &entries[i], buffer, length, transferred) != STATUS_SUCCESS) {
				full = true;
				break;
			}
		}
		if (count != 0)
			wcscpy_s(resume, _countof(resume), entries[count - 1].name);
		cf_list_free(entries, count);
		if (full) return STATUS_SUCCESS;
		if (!more) break;
		after = resume;
	}
	FspFileSystemAddDirInfo(NULL, buffer, length, transferred);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_GetDirInfoByName(FSP_FILE_SYSTEM *fs, PVOID context,
	PWSTR name, FSP_FSCTL_DIR_INFO *dir_info)
{
	CRYPTFS_BACKEND *backend = fs_frontend_backend_context(fs);
	CF_DIRENT entry;
	size_t length;
	/* Indexed child lookup; copying the whole listing made this O(children). */
	CF_RESULT result = cf_node_child_info(backend->store, context, name, &entry);
	if (result != CF_OK) return cryptfs_status(result);
	length = wcslen(entry.name);
	memset(dir_info, 0, sizeof(*dir_info));
	dir_info->Size = (UINT16)(sizeof(*dir_info) + length * sizeof(WCHAR));
	dir_info->FileInfo.FileAttributes = entry.info.attributes;
	dir_info->FileInfo.AllocationSize = entry.info.allocation_size;
	dir_info->FileInfo.FileSize = entry.info.size;
	dir_info->FileInfo.CreationTime = entry.info.creation_time;
	dir_info->FileInfo.LastAccessTime = entry.info.access_time;
	dir_info->FileInfo.LastWriteTime = entry.info.write_time;
	dir_info->FileInfo.ChangeTime = entry.info.change_time;
	dir_info->FileInfo.IndexNumber = entry.info.id;
	memcpy(dir_info->FileNameBuf, entry.name, length * sizeof(WCHAR));
	SecureZeroMemory(&entry, sizeof(entry));
	return STATUS_SUCCESS;
}

static const FSP_FILE_SYSTEM_INTERFACE g_cryptfs_interface = {
	.GetVolumeInfo = fs_GetVolumeInfo,
	.SetVolumeLabel = fs_SetVolumeLabel,
	.GetSecurityByName = fs_GetSecurityByName,
	.Create = fs_Create,
	.Open = fs_Open,
	.Cleanup = fs_Cleanup,
	.Close = fs_Close,
	.Read = fs_Read,
	.Write = fs_Write,
	.Flush = fs_Flush,
	.GetFileInfo = fs_GetFileInfo,
	.Overwrite = fs_Overwrite,
	.SetBasicInfo = fs_SetBasicInfo,
	.SetFileSize = fs_SetFileSize,
	.CanDelete = fs_CanDelete,
	.Rename = fs_Rename,
	.GetSecurity = fs_GetSecurity,
	.SetSecurity = fs_SetSecurity,
	.ReadDirectory = fs_ReadDirectory,
	.GetDirInfoByName = fs_GetDirInfoByName,
	.DispatcherStopped = NULL,
};

NTSTATUS cryptfs_backend_create(CF_STORE *store, CRYPTFS_BACKEND **backend_out)
{
	CRYPTFS_BACKEND *backend;
	FSP_FSCTL_VOLUME_PARAMS params;
	FSF_WINFSP_CONFIG config;
	NTSTATUS status;
	if (store == NULL || backend_out == NULL) return STATUS_INVALID_PARAMETER;
	*backend_out = NULL;
	if (cryptfs_winfsp_prepare_runtime() != ERROR_SUCCESS) return STATUS_UNSUCCESSFUL;
	backend = (CRYPTFS_BACKEND *)calloc(1, sizeof(*backend));
	if (backend == NULL) return STATUS_INSUFFICIENT_RESOURCES;
	backend->store = store;
	memset(&params, 0, sizeof(params));
	params.Version = sizeof(params);
	params.SectorSize = 4096;
	params.SectorsPerAllocationUnit = 1;
	/* The WinFsp FSD measures components in WCHARs despite fsctl.h's "bytes". */
	params.MaxComponentLength = CF_NAME_MAX;
	params.VolumeSerialNumber = 0x43524653u;
	params.FileInfoTimeout = 250;
	params.CaseSensitiveSearch = 1;
	params.CasePreservedNames = 1;
	params.UnicodeOnDisk = 1;
	params.PersistentAcls = 0;
	params.PostCleanupWhenModifiedOnly = 1;
	params.PassQueryDirectoryFileName = 1;
	params.PassQueryDirectoryPattern = 1;
	params.PostDispositionWhenNecessaryOnly = 1;
	params.AllowOpenInKernelMode = 1;
	params.SupportsPosixUnlinkRename = 0;
	wcscpy_s(params.FileSystemName, _countof(params.FileSystemName), L"CRYPTFS");
	memset(&config, 0, sizeof(config));
	config.struct_size = sizeof(config);
	config.abi_version = FS_FRONTEND_ABI_VERSION;
	config.operation_table_size = sizeof(g_cryptfs_interface);
	config.backend_context = backend;
	config.operations = &g_cryptfs_interface;
	config.volume_params = params;
	config.resolve_create_failure = cryptfs_resolve_create_failure;
	status = fsf_winfsp_create(&config, &backend->frontend, NULL);
	if (!NT_SUCCESS(status)) { free(backend); return status; }
	backend->file_system = fsf_winfsp_object(backend->frontend);
	if (backend->file_system == NULL) {
		fsf_winfsp_destroy(backend->frontend);
		free(backend);
		return STATUS_UNSUCCESSFUL;
	}
	FspFileSystemSetOperationGuardStrategy(backend->file_system,
		FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE);
	*backend_out = backend;
	return STATUS_SUCCESS;
}

NTSTATUS cryptfs_backend_mount(CRYPTFS_BACKEND *backend, PCWSTR mount_point)
{
	return backend != NULL ? fsf_winfsp_mount(backend->frontend, mount_point) : STATUS_INVALID_PARAMETER;
}

NTSTATUS cryptfs_backend_start(CRYPTFS_BACKEND *backend)
{
	return backend != NULL ? fsf_winfsp_start(backend->frontend, 0) : STATUS_INVALID_PARAMETER;
}

HANDLE cryptfs_backend_stopped_event(CRYPTFS_BACKEND *backend)
{
	return backend != NULL ? fsf_winfsp_stopped_event(backend->frontend) : NULL;
}

NTSTATUS cryptfs_backend_dispatcher_result(CRYPTFS_BACKEND *backend)
{
	return backend != NULL ? fsf_winfsp_dispatcher_result(backend->frontend) : STATUS_INVALID_PARAMETER;
}

void cryptfs_backend_stop(CRYPTFS_BACKEND *backend)
{
	if (backend != NULL) fsf_winfsp_stop(backend->frontend);
}

NTSTATUS cryptfs_backend_flush(CRYPTFS_BACKEND *backend)
{
	return backend != NULL ? cryptfs_status(cf_store_flush(backend->store)) : STATUS_INVALID_PARAMETER;
}

void cryptfs_backend_destroy(CRYPTFS_BACKEND *backend)
{
	if (backend == NULL) return;
	fsf_winfsp_destroy(backend->frontend);
	free(backend);
}
