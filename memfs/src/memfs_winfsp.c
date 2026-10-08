#include "memfs_winfsp.h"
#include "memfs_driver.h"

#include <assert.h>
#include <stdio.h>
#include <winternl.h>

static MemfsWinFsp* memfs_instance(FSP_FILE_SYSTEM* file_system) {
	return (MemfsWinFsp*)fs_frontend_backend_context(file_system);
}

typedef BOOLEAN (NTAPI *MemfsRtlIsNameInUnUpcasedExpressionFn)(
	PUNICODE_STRING Expression,
	PUNICODE_STRING Name,
	BOOLEAN IgnoreCase,
	PWCH UpcaseTable);

static INIT_ONCE g_name_expression_once = INIT_ONCE_STATIC_INIT;
static MemfsRtlIsNameInUnUpcasedExpressionFn g_name_expression_match;

static BOOL CALLBACK memfs_name_expression_init(
	PINIT_ONCE once, PVOID parameter, PVOID* context) {
	HMODULE ntdll;

	(void)once;
	(void)parameter;
	(void)context;

	ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll != NULL) {
		g_name_expression_match =
			(MemfsRtlIsNameInUnUpcasedExpressionFn)GetProcAddress(
				ntdll, "RtlIsNameInUnUpcasedExpression");
	}

	return TRUE;
}

static bool memfs_name_matches_pattern(
	const wchar_t* pattern,
	const wchar_t* name) {
	UNICODE_STRING expression;
	UNICODE_STRING candidate;
	size_t pattern_chars;
	size_t name_chars;

	if (pattern == NULL || *pattern == L'\0')
		return true;
	if (name == NULL)
		return false;

	if (!InitOnceExecuteOnce(
			&g_name_expression_once,
			memfs_name_expression_init,
			NULL,
			NULL)) {
		/*
		 * Pattern prefiltering is an optimization only. If the helper cannot
		 * be initialized, return every entry and let WinFsp/FSD perform the
		 * authoritative filtering.
		 */
		return true;
	}
	if (g_name_expression_match == NULL)
		return true;

	pattern_chars = wcslen(pattern);
	name_chars = wcslen(name);
	if (pattern_chars > USHRT_MAX / sizeof(wchar_t) ||
		name_chars > USHRT_MAX / sizeof(wchar_t)) {
		return true;
	}

	expression.Length = (USHORT)(pattern_chars * sizeof(wchar_t));
	expression.MaximumLength = expression.Length;
	expression.Buffer = (PWSTR)pattern;
	candidate.Length = (USHORT)(name_chars * sizeof(wchar_t));
	candidate.MaximumLength = candidate.Length;
	candidate.Buffer = (PWSTR)name;

	/* Names are case-insensitive, so are directory patterns. */
	return FALSE != g_name_expression_match(
		&expression, &candidate, TRUE, NULL);
}

#if defined(MEMFS_WINFSP_TESTING)
bool memfs_winfsp_test_name_matches_pattern(
	const wchar_t* pattern,
	const wchar_t* name) {
	return memfs_name_matches_pattern(pattern, name);
}
#endif


static NTSTATUS memfs_status(MemfsResult result) {
	switch (result) {
	case MEMFS_OK:
		return STATUS_SUCCESS;
	case MEMFS_ERR_NOT_FOUND:
		return STATUS_OBJECT_NAME_NOT_FOUND;
	case MEMFS_ERR_PATH_NOT_FOUND:
		return STATUS_OBJECT_PATH_NOT_FOUND;
	case MEMFS_ERR_EXISTS:
		return STATUS_OBJECT_NAME_COLLISION;
	case MEMFS_ERR_NOT_DIRECTORY:
		return STATUS_NOT_A_DIRECTORY;
	case MEMFS_ERR_IS_DIRECTORY:
		return STATUS_FILE_IS_A_DIRECTORY;
	case MEMFS_ERR_NOT_EMPTY:
		return STATUS_DIRECTORY_NOT_EMPTY;
	case MEMFS_ERR_NO_SPACE:
		return STATUS_DISK_FULL;
	case MEMFS_ERR_NO_MEMORY:
		return STATUS_INSUFFICIENT_RESOURCES;
	case MEMFS_ERR_ACCESS:
		return STATUS_ACCESS_DENIED;
	case MEMFS_ERR_DATA:
		return STATUS_DATA_ERROR;
	case MEMFS_ERR_INVALID:
	default:
		return STATUS_INVALID_PARAMETER;
	}
}

static uint32_t memfs_normalize_attributes(MemfsNode* node, uint32_t attributes) {
	if (memfs_node_is_directory(node)) {
		attributes |= FILE_ATTRIBUTE_DIRECTORY;
		attributes &= ~FILE_ATTRIBUTE_NORMAL;
	} else {
		attributes &= ~FILE_ATTRIBUTE_DIRECTORY;
		if (attributes == 0)
			attributes = FILE_ATTRIBUTE_NORMAL;
		else if (attributes & ~FILE_ATTRIBUTE_NORMAL)
			attributes &= ~FILE_ATTRIBUTE_NORMAL;
	}
	return attributes;
}

static void memfs_fill_file_info(MemfsNode* node, FSP_FSCTL_FILE_INFO* file_info) {
	memset(file_info, 0, sizeof(*file_info));

	file_info->FileAttributes = node->attributes;
	file_info->AllocationSize = memfs_align_allocation(node->allocation_size);
	file_info->FileSize = node->file_size;
	file_info->CreationTime = memfs_node_get_creation_time(node);
	file_info->LastAccessTime = memfs_node_get_last_access_time(node);
	file_info->LastWriteTime = memfs_node_get_last_write_time(node);
	file_info->ChangeTime = memfs_node_get_change_time(node);
	file_info->IndexNumber = memfs_node_index_number(node);
}

static void memfs_fill_volume_info(Memfs* fs, FSP_FSCTL_VOLUME_INFO* volume_info) {
	uint64_t free_bytes = memfs_free_bytes(fs);
	uint64_t total;

	memset(volume_info, 0, sizeof(*volume_info));

	if (fs->capacity_auto) {
		/* Auto mode has no fixed capacity (fs->capacity is 0): report used
		 * bytes plus the current growth allowance, clamped so Total >= Free
		 * and both fit WinFsp's signed allocation-unit arithmetic. */
		LONG64 sampled = InterlockedCompareExchange64(&fs->used_bytes, 0, 0);
		uint64_t used = sampled < 0 ? 0 : (uint64_t)sampled;

		if (free_bytes > (uint64_t)INT64_MAX - used)
			free_bytes = (uint64_t)INT64_MAX - used;
		total = used + free_bytes;
	} else {
		total = fs->capacity;
		if (free_bytes > total)
			free_bytes = total;
	}

	volume_info->TotalSize = total;
	volume_info->FreeSize = free_bytes;

	volume_info->VolumeLabelLength = fs->volume_label_bytes;
	memcpy(volume_info->VolumeLabel, fs->volume_label, fs->volume_label_bytes);
}

static NTSTATUS memfs_copy_security(MemfsNode* node, PSECURITY_DESCRIPTOR security_descriptor,
									SIZE_T* security_descriptor_size) {
	if (security_descriptor_size == NULL)
		return STATUS_SUCCESS;

	if (memfs_node_get_security(node)->size > *security_descriptor_size) {
		*security_descriptor_size = memfs_node_get_security(node)->size;
		return STATUS_BUFFER_OVERFLOW;
	}

	*security_descriptor_size = memfs_node_get_security(node)->size;
	if (security_descriptor)
		memcpy(security_descriptor, memfs_node_get_security(node)->data, memfs_node_get_security(node)->size);

	return STATUS_SUCCESS;
}

static BOOLEAN memfs_add_dir_info(MemfsNode* node, const wchar_t* name, void* buffer, ULONG length,
								  PULONG bytes_transferred) {
	uint8_t storage[sizeof(FSP_FSCTL_DIR_INFO) + (MEMFS_MAX_NAME + 1U) * sizeof(wchar_t)];
	FSP_FSCTL_DIR_INFO* dir_info = (FSP_FSCTL_DIR_INFO*)storage;
	size_t name_chars = wcslen(name);
	size_t name_bytes = name_chars * sizeof(wchar_t);

	if (name_chars > MEMFS_MAX_NAME)
		return FALSE;

	memset(storage, 0, sizeof(storage));
	dir_info->Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + name_bytes);
	memfs_fill_file_info(node, &dir_info->FileInfo);

	if (name_bytes)
		memcpy(dir_info->FileNameBuf, name, name_bytes);

	return FspFileSystemAddDirInfo(dir_info, buffer, length, bytes_transferred);
}

static MemfsResult memfs_get_destination(Memfs* fs, const wchar_t* path, MemfsNode** parent,
										 wchar_t name[MEMFS_MAX_NAME + 1]) {
	return memfs_lookup_parent(fs, path, parent, name);
}

static NTSTATUS fs_GetVolumeInfo(FSP_FILE_SYSTEM* file_system, FSP_FSCTL_VOLUME_INFO* volume_info) {
	MemfsWinFsp* instance = memfs_instance(file_system);

	memfs_fill_volume_info(instance->store, volume_info);
	return STATUS_SUCCESS;
}

#if defined(MEMFS_WINFSP_TESTING)
NTSTATUS memfs_winfsp_test_get_volume_info(
	FSP_FILE_SYSTEM* fs, FSP_FSCTL_VOLUME_INFO* volume_info) {
	return fs_GetVolumeInfo(fs, volume_info);
}
#endif

static NTSTATUS fs_SetVolumeLabel(FSP_FILE_SYSTEM* file_system, PWSTR volume_label,
								  FSP_FSCTL_VOLUME_INFO* volume_info) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	Memfs* fs = instance->store;
	size_t chars;

	if (volume_label == NULL)
		return STATUS_INVALID_PARAMETER;

	chars = wcslen(volume_label);
	if (chars > 31)
		return STATUS_INVALID_VOLUME_LABEL;

	memset(fs->volume_label, 0, sizeof(fs->volume_label));
	memcpy(fs->volume_label, volume_label, chars * sizeof(wchar_t));
	fs->volume_label_bytes = (uint16_t)(chars * sizeof(wchar_t));

	memfs_fill_volume_info(fs, volume_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_GetSecurityByName(FSP_FILE_SYSTEM* file_system, PWSTR file_name, PUINT32 file_attributes,
									 PSECURITY_DESCRIPTOR security_descriptor, SIZE_T* security_descriptor_size) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* node;
	MemfsResult result;

	result = memfs_lookup_path(instance->store, file_name, &node);
	if (result != MEMFS_OK)
		return memfs_status(result);

	if (file_attributes)
		*file_attributes = node->attributes;

	return memfs_copy_security(node, security_descriptor, security_descriptor_size);
}

static NTSTATUS fs_Create(FSP_FILE_SYSTEM* file_system, PWSTR file_name, UINT32 create_options, UINT32 granted_access,
						  UINT32 file_attributes, PSECURITY_DESCRIPTOR security_descriptor, UINT64 allocation_size,
						  PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* parent;
	MemfsNode* node;
	wchar_t name[MEMFS_MAX_NAME + 1];
	bool directory;
	MemfsResult result;

	(void)granted_access;

	result = memfs_get_destination(instance->store, file_name, &parent, name);
	if (result != MEMFS_OK)
		return memfs_status(result);

	directory = 0 != (create_options & FILE_DIRECTORY_FILE);

	result = memfs_node_create(instance->store, parent, name, directory, file_attributes, security_descriptor,
							   directory ? 0 : allocation_size, &node);
	if (result != MEMFS_OK)
		return memfs_status(result);

	*file_context = node;
	memfs_fill_file_info(node, file_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_Open(FSP_FILE_SYSTEM* file_system, PWSTR file_name, UINT32 create_options, UINT32 granted_access,
						PVOID* file_context, FSP_FSCTL_FILE_INFO* file_info) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* node;
	MemfsResult result;

	(void)granted_access;

	result = memfs_lookup_path(instance->store, file_name, &node);
	if (result != MEMFS_OK)
		return memfs_status(result);

	if ((create_options & FILE_DIRECTORY_FILE) && !memfs_node_is_directory(node)) {
		return STATUS_NOT_A_DIRECTORY;
	}

	if ((create_options & FILE_NON_DIRECTORY_FILE) && memfs_node_is_directory(node)) {
		return STATUS_FILE_IS_A_DIRECTORY;
	}

	memfs_node_open(node);
	*file_context = node;
	memfs_fill_file_info(node, file_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_Overwrite(FSP_FILE_SYSTEM* file_system, PVOID file_context, UINT32 file_attributes,
							 BOOLEAN replace_file_attributes, UINT64 allocation_size, FSP_FSCTL_FILE_INFO* file_info) {
	MemfsNode* node = file_context;
	MemfsResult result;

	(void)file_system;

	if (memfs_node_is_directory(node))
		return STATUS_FILE_IS_A_DIRECTORY;

	result = memfs_node_set_allocation_size(node, allocation_size);
	if (result != MEMFS_OK)
		return memfs_status(result);

	result = memfs_node_set_file_size(node, 0);
	if (result != MEMFS_OK)
		return memfs_status(result);

	if (replace_file_attributes)
		node->attributes = file_attributes;
	else
		node->attributes |= file_attributes;

	/* Normalize after adding ARCHIVE so NORMAL never survives beside it. */
	node->attributes = memfs_normalize_attributes(node,
		node->attributes | FILE_ATTRIBUTE_ARCHIVE);
	memfs_node_set_change_time(node, memfs_now());

	memfs_fill_file_info(node, file_info);
	return STATUS_SUCCESS;
}

static VOID fs_Cleanup(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR file_name, ULONG flags) {
	MemfsNode* node = file_context;
	uint64_t now;

	(void)file_system;
	(void)file_name;

	if (node == NULL)
		return;

	now = memfs_now();

	if (flags & FspCleanupSetArchiveBit)
		node->attributes = memfs_normalize_attributes(node,
			node->attributes | FILE_ATTRIBUTE_ARCHIVE);
	if (flags & FspCleanupSetLastAccessTime)
		memfs_node_set_last_access_time(node, now);
	if (flags & FspCleanupSetLastWriteTime)
		memfs_node_set_last_write_time(node, now);
	if (flags & FspCleanupSetChangeTime)
		memfs_node_set_change_time(node, now);

	if (flags & FspCleanupDelete)
		memfs_node_unlink(node);
}

static VOID fs_Close(FSP_FILE_SYSTEM* file_system, PVOID file_context) {
	(void)file_system;
	memfs_node_close((MemfsNode*)file_context);
}

#if defined(MEMFS_WINFSP_TESTING)
NTSTATUS memfs_winfsp_test_overwrite(
	FSP_FILE_SYSTEM* fs, MemfsNode* node, UINT32 attributes,
	BOOLEAN replace_attributes, UINT64 allocation_size,
	FSP_FSCTL_FILE_INFO* info) {
	return fs_Overwrite(fs, node, attributes, replace_attributes,
		allocation_size, info);
}

void memfs_winfsp_test_cleanup(
	FSP_FILE_SYSTEM* fs, MemfsNode* node, ULONG flags) {
	fs_Cleanup(fs, node, NULL, flags);
}
#endif

static NTSTATUS fs_Read(FSP_FILE_SYSTEM* file_system, PVOID file_context, PVOID buffer, UINT64 offset, ULONG length,
						PULONG bytes_transferred) {
	MemfsNode* node = file_context;
	MemfsResult result;
	uint32_t bytes_read = 0;

	(void)file_system;

	if (memfs_node_is_directory(node))
		return STATUS_FILE_IS_A_DIRECTORY;
	if (offset >= node->file_size)
		return STATUS_END_OF_FILE;

	result = memfs_node_read(node, buffer, offset, length, &bytes_read);
	if (result != MEMFS_OK)
		return memfs_status(result);

	*bytes_transferred = bytes_read;
	return STATUS_SUCCESS;
}

static NTSTATUS fs_Write(FSP_FILE_SYSTEM* file_system, PVOID file_context, PVOID buffer, UINT64 offset, ULONG length,
						 BOOLEAN write_to_end_of_file, BOOLEAN constrained_io, PULONG bytes_transferred,
						 FSP_FSCTL_FILE_INFO* file_info) {
	MemfsNode* node = file_context;
	MemfsResult result;
	uint32_t bytes_written = 0;

	(void)file_system;

	if (memfs_node_is_directory(node))
		return STATUS_FILE_IS_A_DIRECTORY;

	result = memfs_node_write(node, buffer, offset, length, !!write_to_end_of_file, !!constrained_io, &bytes_written);
	if (result != MEMFS_OK)
		return memfs_status(result);

	*bytes_transferred = bytes_written;
	memfs_fill_file_info(node, file_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_Flush(FSP_FILE_SYSTEM* file_system, PVOID file_context, FSP_FSCTL_FILE_INFO* file_info) {
	(void)file_system;

	if (file_context && file_info)
		memfs_fill_file_info((MemfsNode*)file_context, file_info);

	return STATUS_SUCCESS;
}

static NTSTATUS fs_GetFileInfo(FSP_FILE_SYSTEM* file_system, PVOID file_context, FSP_FSCTL_FILE_INFO* file_info) {
	(void)file_system;
	memfs_fill_file_info((MemfsNode*)file_context, file_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_SetBasicInfo(FSP_FILE_SYSTEM* file_system, PVOID file_context, UINT32 file_attributes,
								UINT64 creation_time, UINT64 last_access_time, UINT64 last_write_time,
								UINT64 change_time, FSP_FSCTL_FILE_INFO* file_info) {
	MemfsNode* node = file_context;

	(void)file_system;

	if (file_attributes != INVALID_FILE_ATTRIBUTES) {
		if (file_attributes == 0)
			file_attributes = memfs_node_is_directory(node) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;

		node->attributes = memfs_normalize_attributes(node, file_attributes);
	}

	if (creation_time)
		memfs_node_set_creation_time(node, creation_time);
	if (last_access_time)
		memfs_node_set_last_access_time(node, last_access_time);
	if (last_write_time)
		memfs_node_set_last_write_time(node, last_write_time);
	if (change_time)
		memfs_node_set_change_time(node, change_time);

	memfs_fill_file_info(node, file_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_SetFileSize(FSP_FILE_SYSTEM* file_system, PVOID file_context, UINT64 new_size,
							   BOOLEAN set_allocation_size, FSP_FSCTL_FILE_INFO* file_info) {
	MemfsNode* node = file_context;
	MemfsResult result;

	(void)file_system;

	if (set_allocation_size)
		result = memfs_node_set_allocation_size(node, new_size);
	else
		result = memfs_node_set_file_size(node, new_size);

	if (result != MEMFS_OK)
		return memfs_status(result);

	memfs_fill_file_info(node, file_info);
	return STATUS_SUCCESS;
}

static NTSTATUS fs_CanDelete(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR file_name) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* node = file_context;

	(void)file_name;

	if (node == instance->store->root)
		return STATUS_ACCESS_DENIED;

	if (MEMFS_NODE_IS_DIRECTORY(node) && node->dir->child_count)
		return STATUS_DIRECTORY_NOT_EMPTY;

	return STATUS_SUCCESS;
}

static NTSTATUS fs_Rename(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR file_name, PWSTR new_file_name,
						  BOOLEAN replace_if_exists) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* node = file_context;
	MemfsNode* new_parent;
	wchar_t new_name[MEMFS_MAX_NAME + 1];
	MemfsResult result;

	(void)file_name;

	result = memfs_get_destination(instance->store, new_file_name, &new_parent, new_name);
	if (result != MEMFS_OK)
		return memfs_status(result);

	result = memfs_node_rename(node, new_parent, new_name, !!replace_if_exists);
	return memfs_status(result);
}

static NTSTATUS fs_GetSecurity(FSP_FILE_SYSTEM* file_system, PVOID file_context,
							   PSECURITY_DESCRIPTOR security_descriptor, SIZE_T* security_descriptor_size) {
	NTSTATUS status;
	/* QuerySecurity is not part of the FINE namespace guard. Pair it with the
	 * explicit SetSecurity guard; GetSecurityByName already runs inside FINE. */
	AcquireSRWLockShared(&file_system->OpGuardLock);
	status = memfs_copy_security((MemfsNode*)file_context,
		security_descriptor, security_descriptor_size);
	ReleaseSRWLockShared(&file_system->OpGuardLock);
	return status;
}

static NTSTATUS fs_SetSecurity(FSP_FILE_SYSTEM* file_system, PVOID file_context,
							   SECURITY_INFORMATION security_information,
							   PSECURITY_DESCRIPTOR modification_descriptor) {
	MemfsNode* node = file_context;
	PSECURITY_DESCRIPTOR new_descriptor;
	uint32_t new_size;
	MemfsResult result;
	NTSTATUS status;

	/* SetSecurity is unguarded by FINE, yet Create/Open calls
	 * GetSecurityByName on ancestors. Hold the same namespace guard while
	 * replacing/freeing a descriptor so those borrowed snapshots stay alive.
	 * Do not recursively acquire it inside GetSecurityByName. */
	AcquireSRWLockExclusive(&file_system->OpGuardLock);
	status = FspSetSecurityDescriptor(memfs_node_get_security(node)->data, security_information,
									  modification_descriptor, &new_descriptor);
	if (!NT_SUCCESS(status)) {
		ReleaseSRWLockExclusive(&file_system->OpGuardLock);
		return status;
	}

	new_size = GetSecurityDescriptorLength(new_descriptor);
	result = memfs_node_replace_security(node, new_descriptor, new_size);
	FspDeleteSecurityDescriptor(new_descriptor, (NTSTATUS (*)())FspSetSecurityDescriptor);
	ReleaseSRWLockExclusive(&file_system->OpGuardLock);
	return memfs_status(result);
}

#if defined(MEMFS_WINFSP_TESTING)
NTSTATUS memfs_winfsp_test_get_security(FSP_FILE_SYSTEM* fs, MemfsNode* node,
    PSECURITY_DESCRIPTOR buffer, SIZE_T* size) {
    return fs_GetSecurity(fs, node, buffer, size);
}
NTSTATUS memfs_winfsp_test_get_security_by_name(FSP_FILE_SYSTEM* fs, PWSTR name,
    PSECURITY_DESCRIPTOR buffer, SIZE_T* size) {
    NTSTATUS result;
    /* Mirror the FILE_OPEN FINE shared guard around this callback. */
    AcquireSRWLockShared(&fs->OpGuardLock);
    result = fs_GetSecurityByName(fs, name, NULL, buffer, size);
    ReleaseSRWLockShared(&fs->OpGuardLock);
    return result;
}
NTSTATUS memfs_winfsp_test_set_security(FSP_FILE_SYSTEM* fs, MemfsNode* node,
    SECURITY_INFORMATION information, PSECURITY_DESCRIPTOR descriptor) {
    return fs_SetSecurity(fs, node, information, descriptor);
}
#endif

static NTSTATUS fs_ReadDirectory(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR pattern, PWSTR marker,
								 PVOID buffer, ULONG length, PULONG bytes_transferred) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* dir = file_context;
	MemfsNode* node;

	if (!memfs_node_is_directory(dir))
		return STATUS_NOT_A_DIRECTORY;

	*bytes_transferred = 0;

	if (dir != instance->store->root) {
		if (marker == NULL && memfs_name_matches_pattern(pattern, L".")) {
			if (!memfs_add_dir_info(dir, L".", buffer, length, bytes_transferred)) {
				return STATUS_SUCCESS;
			}
		}

		if (marker == NULL || (marker[0] == L'.' && marker[1] == L'\0')) {
			/* An unlinked directory still open by a handle has no parent. */
			MemfsNode* parent = dir->parent != NULL ? dir->parent : dir;

			if (memfs_name_matches_pattern(pattern, L"..") &&
				!memfs_add_dir_info(parent, L"..", buffer, length, bytes_transferred)) {
				return STATUS_SUCCESS;
			}
			marker = NULL;
		} else if (marker[0] == L'.' && marker[1] == L'.' && marker[2] == L'\0') {
			marker = NULL;
		}
	}

	node = marker ? memfs_dir_upper_bound(dir, marker) : memfs_dir_first(dir);

	for (; node; node = memfs_dir_next(node)) {
		if (node->deleted)
			continue;
		if (!memfs_name_matches_pattern(pattern, node->name))
			continue;

		if (!memfs_add_dir_info(node, node->name, buffer, length, bytes_transferred)) {
			return STATUS_SUCCESS;
		}
	}

	FspFileSystemAddDirInfo(NULL, buffer, length, bytes_transferred);
	return STATUS_SUCCESS;
}

#if defined(MEMFS_WINFSP_TESTING)
NTSTATUS memfs_winfsp_test_read_directory(
	FSP_FILE_SYSTEM* fs, MemfsNode* directory, PWSTR pattern, PWSTR marker,
	PVOID buffer, ULONG length, PULONG transferred) {
	return fs_ReadDirectory(fs, directory, pattern, marker,
		buffer, length, transferred);
}
#endif

static NTSTATUS fs_GetDirInfoByName(FSP_FILE_SYSTEM* file_system, PVOID file_context, PWSTR file_name,
									FSP_FSCTL_DIR_INFO* dir_info) {
	MemfsWinFsp* instance = memfs_instance(file_system);
	MemfsNode* dir = file_context;
	MemfsNode* node;
	const wchar_t* output_name;
	size_t name_chars;
	size_t name_bytes;

	if (!memfs_node_is_directory(dir))
		return STATUS_NOT_A_DIRECTORY;

	if (wcscmp(file_name, L".") == 0) {
		node = dir;
		output_name = file_name;
	} else if (wcscmp(file_name, L"..") == 0) {
		node = dir->parent ? dir->parent : dir;
		output_name = file_name;
	} else {
		node = memfs_dir_lookup(dir, file_name);
		output_name = node ? node->name : NULL;
	}

	if (node == NULL)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	(void)instance;

	name_chars = wcslen(output_name);
	if (name_chars > MEMFS_MAX_NAME)
		return STATUS_OBJECT_NAME_INVALID;

	name_bytes = name_chars * sizeof(wchar_t);
	memset(dir_info, 0, sizeof(*dir_info));
	dir_info->Size = (UINT16)(sizeof(FSP_FSCTL_DIR_INFO) + name_bytes);
	memfs_fill_file_info(node, &dir_info->FileInfo);

	if (name_bytes)
		memcpy(dir_info->FileNameBuf, output_name, name_bytes);

	return STATUS_SUCCESS;
}

#if defined(MEMFS_WINFSP_TESTING)
NTSTATUS memfs_winfsp_test_get_dir_info_by_name(
	FSP_FILE_SYSTEM* fs,
	PVOID directory_context,
	PWSTR name,
	FSP_FSCTL_DIR_INFO* dir_info) {
	return fs_GetDirInfoByName(fs, directory_context, name, dir_info);
}
#endif

static const FSP_FILE_SYSTEM_INTERFACE g_memfs_interface = {
	.GetVolumeInfo = fs_GetVolumeInfo,
	.SetVolumeLabel = fs_SetVolumeLabel,
	.GetSecurityByName = fs_GetSecurityByName,
	.Create = fs_Create,
	.Open = fs_Open,
	.Overwrite = fs_Overwrite,
	.Cleanup = fs_Cleanup,
	.Close = fs_Close,
	.Read = fs_Read,
	.Write = fs_Write,
	.Flush = fs_Flush,
	.GetFileInfo = fs_GetFileInfo,
	.SetBasicInfo = fs_SetBasicInfo,
	.SetFileSize = fs_SetFileSize,
	.CanDelete = fs_CanDelete,
	.Rename = fs_Rename,
	.GetSecurity = fs_GetSecurity,
	.SetSecurity = fs_SetSecurity,
	.ReadDirectory = fs_ReadDirectory,
	.GetDirInfoByName = fs_GetDirInfoByName,
	/* Dispatcher event/status ownership is shared by fs_frontend. */
	.DispatcherStopped = NULL,
};

static NTSTATUS memfs_win32_status(DWORD error) {
	if (error == ERROR_SUCCESS)
		return STATUS_SUCCESS;
	if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD)
		return STATUS_ACCESS_DENIED;
	if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
		error == ERROR_MOD_NOT_FOUND || error == ERROR_DLL_NOT_FOUND)
		return STATUS_OBJECT_NAME_NOT_FOUND;
	if (error == ERROR_NOT_ENOUGH_MEMORY || error == ERROR_OUTOFMEMORY)
		return STATUS_INSUFFICIENT_RESOURCES;
	if (error == ERROR_SUCCESS_REBOOT_REQUIRED)
		return STATUS_DEVICE_NOT_READY;
	return STATUS_UNSUCCESSFUL;
}

static bool memfs_winfsp_should_install_embedded_driver(NTSTATUS status) {
	return status == STATUS_NO_SUCH_DEVICE ||
		   status == STATUS_DRIVER_UNABLE_TO_LOAD;
}

static NTSTATUS memfs_winfsp_resolve_create_failure(
	void* backend_context,
	NTSTATUS first_create_status,
	BOOL* retry_create,
	DWORD* win32_detail_out) {
	DWORD error;
	(void)backend_context;
	if (retry_create == NULL)
		return STATUS_INVALID_PARAMETER;
	*retry_create = FALSE;
	if (win32_detail_out != NULL)
		*win32_detail_out = ERROR_SUCCESS;
	if (!memfs_winfsp_should_install_embedded_driver(first_create_status))
		return first_create_status;

	error = memfs_winfsp_install_embedded_driver();
	if (error == ERROR_SUCCESS) {
		*retry_create = TRUE;
		return STATUS_SUCCESS;
	}
	if (win32_detail_out != NULL)
		*win32_detail_out = error;
	return memfs_win32_status(error);
}

static void memfs_winfsp_init_volume_params(FSP_FSCTL_VOLUME_PARAMS* volume_params) {
	memset(volume_params, 0, sizeof(*volume_params));
	volume_params->Version = sizeof(*volume_params);
	volume_params->SectorSize = MEMFS_ALLOCATION_UNIT;
	volume_params->SectorsPerAllocationUnit = 1;
	/* The WinFsp FSD compares this against component length in WCHARs,
	 * despite the "bytes" comment in fsctl.h. */
	volume_params->MaxComponentLength = MEMFS_MAX_NAME;
	volume_params->VolumeCreationTime = memfs_now();
	volume_params->VolumeSerialNumber = (uint32_t)(volume_params->VolumeCreationTime / 10000000ULL);
	volume_params->FileInfoTimeout = 1000;
	volume_params->CaseSensitiveSearch = 0;
	volume_params->CasePreservedNames = 1;
	volume_params->UnicodeOnDisk = 1;
	volume_params->PersistentAcls = 1;
	volume_params->PostCleanupWhenModifiedOnly = 1;
	volume_params->PassQueryDirectoryFileName = 1;
	volume_params->PassQueryDirectoryPattern = 1;
	volume_params->PostDispositionWhenNecessaryOnly = 1;
	volume_params->AllowOpenInKernelMode = 1;
	volume_params->SupportsPosixUnlinkRename = 0;
	wcscpy_s(volume_params->FileSystemName, _countof(volume_params->FileSystemName), L"MEMFS-C");
}

#if defined(MEMFS_WINFSP_TESTING)
void memfs_winfsp_test_volume_params(FSP_FSCTL_VOLUME_PARAMS* params) {
	memfs_winfsp_init_volume_params(params);
}
#endif

NTSTATUS memfs_winfsp_create_ex(
    const MemfsOptions* options,
    MemfsWinFsp** out_instance,
    DWORD* detail_error) {
	FSP_FSCTL_VOLUME_PARAMS volume_params;
	FSF_WINFSP_CONFIG frontend_config;
	MemfsWinFsp* instance;
	Memfs* instance_store;
	MemfsResult result;
	NTSTATUS status;
	DWORD runtime_error;
	DWORD frontend_detail = ERROR_SUCCESS;

	if (options == NULL || out_instance == NULL)
		return STATUS_INVALID_PARAMETER;

	*out_instance = NULL;
	if (detail_error)
		*detail_error = ERROR_SUCCESS;

	runtime_error = memfs_winfsp_prepare_runtime();
	if (runtime_error != ERROR_SUCCESS) {
		if (detail_error)
			*detail_error = runtime_error;
		return memfs_win32_status(runtime_error);
	}

	result = memfs_create_ex(options, &instance_store);
	if (result != MEMFS_OK)
		return memfs_status(result);

	instance = memfs_allocator_alloc_zero(&instance_store->allocator, sizeof(*instance));
	if (instance == NULL) {
		memfs_destroy(instance_store);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	instance->store = instance_store;

	memfs_winfsp_init_volume_params(&volume_params);

	memset(&frontend_config, 0, sizeof(frontend_config));
	frontend_config.struct_size = sizeof(frontend_config);
	frontend_config.abi_version = FS_FRONTEND_ABI_VERSION;
	frontend_config.operation_table_size = sizeof(g_memfs_interface);
	frontend_config.backend_context = instance;
	frontend_config.operations = &g_memfs_interface;
	frontend_config.volume_params = volume_params;
	frontend_config.resolve_create_failure = memfs_winfsp_resolve_create_failure;
	status = fsf_winfsp_create(&frontend_config, &instance->frontend,
		&frontend_detail);
	if (detail_error != NULL)
		*detail_error = frontend_detail;
	if (!NT_SUCCESS(status)) {
		Memfs* store = instance->store;
		if (instance->frontend != NULL)
			fsf_winfsp_destroy(instance->frontend);
		memfs_allocator_free(&store->allocator, instance, sizeof(*instance));
		memfs_destroy(store);
		return status;
	}

	instance->file_system = fsf_winfsp_object(instance->frontend);
	if (instance->file_system == NULL) {
		Memfs* store = instance->store;
		fsf_winfsp_destroy(instance->frontend);
		memfs_allocator_free(&store->allocator, instance, sizeof(*instance));
		memfs_destroy(store);
		return STATUS_UNSUCCESSFUL;
	}

	FspFileSystemSetOperationGuardStrategy(instance->file_system, FSP_FILE_SYSTEM_OPERATION_GUARD_STRATEGY_FINE);

	*out_instance = instance;
	return STATUS_SUCCESS;
}
NTSTATUS memfs_winfsp_create(
    const MemfsOptions* options,
    MemfsWinFsp** out_instance) {
	return memfs_winfsp_create_ex(options, out_instance, NULL);
}

NTSTATUS memfs_winfsp_mount(MemfsWinFsp* instance, const wchar_t* mount_point) {
	if (instance == NULL || instance->frontend == NULL || mount_point == NULL)
		return STATUS_INVALID_PARAMETER;

	return fsf_winfsp_mount(instance->frontend, mount_point);
}

NTSTATUS memfs_winfsp_start(MemfsWinFsp* instance, uint32_t thread_count) {
	if (instance == NULL || instance->frontend == NULL)
		return STATUS_INVALID_PARAMETER;

	return fsf_winfsp_start(instance->frontend, thread_count);
}

HANDLE memfs_winfsp_dispatcher_stopped_event(MemfsWinFsp* instance) {
	return instance != NULL && instance->frontend != NULL
		? fsf_winfsp_stopped_event(instance->frontend) : NULL;
}

bool memfs_winfsp_dispatcher_stopped_normally(const MemfsWinFsp* instance) {
	return instance != NULL && instance->frontend != NULL &&
		fsf_winfsp_dispatcher_stopped_normally(instance->frontend);
}

NTSTATUS memfs_winfsp_dispatcher_result(const MemfsWinFsp* instance) {
	NTSTATUS status = STATUS_INVALID_PARAMETER;

	if (instance == NULL || instance->frontend == NULL)
		return status;

	return fsf_winfsp_dispatcher_result(instance->frontend);
}

void memfs_winfsp_stop(MemfsWinFsp* instance) {
	if (instance != NULL && instance->frontend != NULL)
		fsf_winfsp_stop(instance->frontend);
}

void memfs_winfsp_destroy(MemfsWinFsp* instance) {
	if (instance == NULL)
		return;

	{
		Memfs* store = instance->store;

		if (instance->frontend != NULL)
			fsf_winfsp_destroy(instance->frontend);

		memfs_allocator_free(&store->allocator, instance, sizeof(*instance));
		memfs_destroy(store);
	}
}
