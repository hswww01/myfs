#include "fs_frontend.h"

#include <stdlib.h>
#include <string.h>

struct FSF_WINFSP {
	FSP_FILE_SYSTEM *file_system;
	FSP_FILE_SYSTEM_INTERFACE operations;
	FSP_FILE_SYSTEM_INTERFACE forwarding;
	FSP_FSCTL_VOLUME_PARAMS volume_params;
	void *backend_context;
	FSF_RESOLVE_CREATE_FAILURE_FN resolve_create_failure;
	HANDLE stopped_event;
	volatile LONG dispatcher_stopped_normally;
	bool dispatcher_started;
};

/*
 * WinFsp stores the interface pointer passed to FspFileSystemCreate, and each
 * frontend passes its own embedded forwarding table, so the owning frontend is
 * recovered in O(1) without a global lock on every file-system operation.
 */
static FSF_WINFSP *fsf_winfsp_find(FSP_FILE_SYSTEM *file_system)
{
	if (file_system == NULL || file_system->Interface == NULL)
		return NULL;
	return CONTAINING_RECORD(file_system->Interface, FSF_WINFSP, forwarding);
}

#define FSF_STATUS_FORWARD(Name, Member, Parameters, Arguments) \
	static NTSTATUS fsf_forward_##Name Parameters \
	{ \
		FSF_WINFSP *frontend = fsf_winfsp_find(FileSystem); \
		if (frontend == NULL || frontend->operations.Member == NULL) \
			return STATUS_INVALID_HANDLE; \
		return frontend->operations.Member Arguments; \
	}

#define FSF_VOID_FORWARD(Name, Member, Parameters, Arguments) \
	static VOID fsf_forward_##Name Parameters \
	{ \
		FSF_WINFSP *frontend = fsf_winfsp_find(FileSystem); \
		if (frontend != NULL && frontend->operations.Member != NULL) \
			frontend->operations.Member Arguments; \
	}

FSF_STATUS_FORWARD(get_volume_info, GetVolumeInfo,
	(FSP_FILE_SYSTEM *FileSystem, FSP_FSCTL_VOLUME_INFO *VolumeInfo),
	(FileSystem, VolumeInfo))
FSF_STATUS_FORWARD(set_volume_label, SetVolumeLabel,
	(FSP_FILE_SYSTEM *FileSystem, PWSTR VolumeLabel, FSP_FSCTL_VOLUME_INFO *VolumeInfo),
	(FileSystem, VolumeLabel, VolumeInfo))
FSF_STATUS_FORWARD(get_security_by_name, GetSecurityByName,
	(FSP_FILE_SYSTEM *FileSystem, PWSTR FileName, PUINT32 PFileAttributes,
	 PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize),
	(FileSystem, FileName, PFileAttributes, SecurityDescriptor, PSecurityDescriptorSize))
FSF_STATUS_FORWARD(create, Create,
	(FSP_FILE_SYSTEM *FileSystem, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
	 UINT32 FileAttributes, PSECURITY_DESCRIPTOR SecurityDescriptor, UINT64 AllocationSize,
	 PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileName, CreateOptions, GrantedAccess, FileAttributes,
	 SecurityDescriptor, AllocationSize, PFileContext, FileInfo))
FSF_STATUS_FORWARD(open, Open,
	(FSP_FILE_SYSTEM *FileSystem, PWSTR FileName, UINT32 CreateOptions, UINT32 GrantedAccess,
	 PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileName, CreateOptions, GrantedAccess, PFileContext, FileInfo))
FSF_STATUS_FORWARD(overwrite, Overwrite,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, UINT32 FileAttributes,
	 BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, FileAttributes, ReplaceFileAttributes, AllocationSize, FileInfo))
FSF_VOID_FORWARD(cleanup, Cleanup,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName, ULONG Flags),
	(FileSystem, FileContext, FileName, Flags))
FSF_VOID_FORWARD(close, Close,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext),
	(FileSystem, FileContext))
FSF_STATUS_FORWARD(read, Read,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PVOID Buffer, UINT64 Offset,
	 ULONG Length, PULONG PBytesTransferred),
	(FileSystem, FileContext, Buffer, Offset, Length, PBytesTransferred))
FSF_STATUS_FORWARD(write, Write,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PVOID Buffer, UINT64 Offset,
	 ULONG Length, BOOLEAN WriteToEndOfFile, BOOLEAN ConstrainedIo,
	 PULONG PBytesTransferred, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, Buffer, Offset, Length, WriteToEndOfFile,
	 ConstrainedIo, PBytesTransferred, FileInfo))
FSF_STATUS_FORWARD(flush, Flush,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, FileInfo))
FSF_STATUS_FORWARD(get_file_info, GetFileInfo,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, FileInfo))
FSF_STATUS_FORWARD(set_basic_info, SetBasicInfo,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, UINT32 FileAttributes,
	 UINT64 CreationTime, UINT64 LastAccessTime, UINT64 LastWriteTime,
	 UINT64 ChangeTime, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, FileAttributes, CreationTime, LastAccessTime,
	 LastWriteTime, ChangeTime, FileInfo))
FSF_STATUS_FORWARD(set_file_size, SetFileSize,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, UINT64 NewSize,
	 BOOLEAN SetAllocationSize, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, NewSize, SetAllocationSize, FileInfo))
FSF_STATUS_FORWARD(can_delete, CanDelete,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName),
	(FileSystem, FileContext, FileName))
FSF_STATUS_FORWARD(rename, Rename,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName,
	 PWSTR NewFileName, BOOLEAN ReplaceIfExists),
	(FileSystem, FileContext, FileName, NewFileName, ReplaceIfExists))
FSF_STATUS_FORWARD(get_security, GetSecurity,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext,
	 PSECURITY_DESCRIPTOR SecurityDescriptor, SIZE_T *PSecurityDescriptorSize),
	(FileSystem, FileContext, SecurityDescriptor, PSecurityDescriptorSize))
FSF_STATUS_FORWARD(set_security, SetSecurity,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext,
	 SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR ModificationDescriptor),
	(FileSystem, FileContext, SecurityInformation, ModificationDescriptor))
FSF_STATUS_FORWARD(read_directory, ReadDirectory,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR Pattern, PWSTR Marker,
	 PVOID Buffer, ULONG Length, PULONG PBytesTransferred),
	(FileSystem, FileContext, Pattern, Marker, Buffer, Length, PBytesTransferred))
FSF_STATUS_FORWARD(get_dir_info_by_name, GetDirInfoByName,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName,
	 FSP_FSCTL_DIR_INFO *DirInfo),
	(FileSystem, FileContext, FileName, DirInfo))
FSF_STATUS_FORWARD(resolve_reparse_points, ResolveReparsePoints,
	(FSP_FILE_SYSTEM *FileSystem, PWSTR FileName, UINT32 ReparsePointIndex,
	 BOOLEAN ResolveLastPathComponent, PIO_STATUS_BLOCK PIoStatus,
	 PVOID Buffer, PSIZE_T PSize),
	(FileSystem, FileName, ReparsePointIndex, ResolveLastPathComponent,
	 PIoStatus, Buffer, PSize))
FSF_STATUS_FORWARD(get_reparse_point, GetReparsePoint,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName,
	 PVOID Buffer, PSIZE_T PSize),
	(FileSystem, FileContext, FileName, Buffer, PSize))
FSF_STATUS_FORWARD(set_reparse_point, SetReparsePoint,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName,
	 PVOID Buffer, SIZE_T Size),
	(FileSystem, FileContext, FileName, Buffer, Size))
FSF_STATUS_FORWARD(delete_reparse_point, DeleteReparsePoint,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName,
	 PVOID Buffer, SIZE_T Size),
	(FileSystem, FileContext, FileName, Buffer, Size))
FSF_STATUS_FORWARD(get_stream_info, GetStreamInfo,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PVOID Buffer,
	 ULONG Length, PULONG PBytesTransferred),
	(FileSystem, FileContext, Buffer, Length, PBytesTransferred))
FSF_STATUS_FORWARD(control, Control,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, UINT32 ControlCode,
	 PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
	 ULONG OutputBufferLength, PULONG PBytesTransferred),
	(FileSystem, FileContext, ControlCode, InputBuffer, InputBufferLength,
	 OutputBuffer, OutputBufferLength, PBytesTransferred))
FSF_STATUS_FORWARD(set_delete, SetDelete,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, PWSTR FileName,
	 BOOLEAN DeleteFile),
	(FileSystem, FileContext, FileName, DeleteFile))
FSF_STATUS_FORWARD(create_ex, CreateEx,
	(FSP_FILE_SYSTEM *FileSystem, PWSTR FileName, UINT32 CreateOptions,
	 UINT32 GrantedAccess, UINT32 FileAttributes,
	 PSECURITY_DESCRIPTOR SecurityDescriptor, UINT64 AllocationSize,
	 PVOID ExtraBuffer, ULONG ExtraLength, BOOLEAN ExtraBufferIsReparsePoint,
	 PVOID *PFileContext, FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileName, CreateOptions, GrantedAccess, FileAttributes,
	 SecurityDescriptor, AllocationSize, ExtraBuffer, ExtraLength,
	 ExtraBufferIsReparsePoint, PFileContext, FileInfo))
FSF_STATUS_FORWARD(overwrite_ex, OverwriteEx,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext, UINT32 FileAttributes,
	 BOOLEAN ReplaceFileAttributes, UINT64 AllocationSize,
	 PFILE_FULL_EA_INFORMATION Ea, ULONG EaLength,
	 FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, FileAttributes, ReplaceFileAttributes,
	 AllocationSize, Ea, EaLength, FileInfo))
FSF_STATUS_FORWARD(get_ea, GetEa,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext,
	 PFILE_FULL_EA_INFORMATION Ea, ULONG EaLength, PULONG PBytesTransferred),
	(FileSystem, FileContext, Ea, EaLength, PBytesTransferred))
FSF_STATUS_FORWARD(set_ea, SetEa,
	(FSP_FILE_SYSTEM *FileSystem, PVOID FileContext,
	 PFILE_FULL_EA_INFORMATION Ea, ULONG EaLength,
	 FSP_FSCTL_FILE_INFO *FileInfo),
	(FileSystem, FileContext, Ea, EaLength, FileInfo))

static VOID fsf_forward_dispatcher_stopped(FSP_FILE_SYSTEM *FileSystem, BOOLEAN Normally)
{
	FSF_WINFSP *frontend = fsf_winfsp_find(FileSystem);
	if (frontend == NULL)
		return;
	if (frontend->operations.DispatcherStopped != NULL)
		frontend->operations.DispatcherStopped(FileSystem, Normally);
	InterlockedExchange(&frontend->dispatcher_stopped_normally, Normally ? 1 : 2);
	if (frontend->stopped_event != NULL)
		SetEvent(frontend->stopped_event);
}

static bool fsf_interface_has_unsupported_callbacks(
	const FSP_FILE_SYSTEM_INTERFACE *operations)
{
	unsigned int i;

	if (operations->Obsolete0 != NULL)
		return true;
	for (i = 0; i < ARRAYSIZE(operations->Reserved); ++i) {
		if (operations->Reserved[i] != NULL)
			return true;
	}
	return false;
}

static void fsf_build_forwarding_table(FSF_WINFSP *frontend)
{
	const FSP_FILE_SYSTEM_INTERFACE *source = &frontend->operations;
	FSP_FILE_SYSTEM_INTERFACE *target = &frontend->forwarding;

	memset(target, 0, sizeof(*target));
	if (source->GetVolumeInfo != NULL)
		target->GetVolumeInfo = fsf_forward_get_volume_info;
	if (source->SetVolumeLabel != NULL)
		target->SetVolumeLabel = fsf_forward_set_volume_label;
	if (source->GetSecurityByName != NULL)
		target->GetSecurityByName = fsf_forward_get_security_by_name;
	if (source->Create != NULL)
		target->Create = fsf_forward_create;
	if (source->Open != NULL)
		target->Open = fsf_forward_open;
	if (source->Overwrite != NULL)
		target->Overwrite = fsf_forward_overwrite;
	if (source->Cleanup != NULL)
		target->Cleanup = fsf_forward_cleanup;
	if (source->Close != NULL)
		target->Close = fsf_forward_close;
	if (source->Read != NULL)
		target->Read = fsf_forward_read;
	if (source->Write != NULL)
		target->Write = fsf_forward_write;
	if (source->Flush != NULL)
		target->Flush = fsf_forward_flush;
	if (source->GetFileInfo != NULL)
		target->GetFileInfo = fsf_forward_get_file_info;
	if (source->SetBasicInfo != NULL)
		target->SetBasicInfo = fsf_forward_set_basic_info;
	if (source->SetFileSize != NULL)
		target->SetFileSize = fsf_forward_set_file_size;
	if (source->CanDelete != NULL)
		target->CanDelete = fsf_forward_can_delete;
	if (source->Rename != NULL)
		target->Rename = fsf_forward_rename;
	if (source->GetSecurity != NULL)
		target->GetSecurity = fsf_forward_get_security;
	if (source->SetSecurity != NULL)
		target->SetSecurity = fsf_forward_set_security;
	if (source->ReadDirectory != NULL)
		target->ReadDirectory = fsf_forward_read_directory;
	if (source->GetDirInfoByName != NULL)
		target->GetDirInfoByName = fsf_forward_get_dir_info_by_name;
	if (source->ResolveReparsePoints != NULL)
		target->ResolveReparsePoints = fsf_forward_resolve_reparse_points;
	if (source->GetReparsePoint != NULL)
		target->GetReparsePoint = fsf_forward_get_reparse_point;
	if (source->SetReparsePoint != NULL)
		target->SetReparsePoint = fsf_forward_set_reparse_point;
	if (source->DeleteReparsePoint != NULL)
		target->DeleteReparsePoint = fsf_forward_delete_reparse_point;
	if (source->GetStreamInfo != NULL)
		target->GetStreamInfo = fsf_forward_get_stream_info;
	if (source->Control != NULL)
		target->Control = fsf_forward_control;
	if (source->SetDelete != NULL)
		target->SetDelete = fsf_forward_set_delete;
	if (source->CreateEx != NULL)
		target->CreateEx = fsf_forward_create_ex;
	if (source->OverwriteEx != NULL)
		target->OverwriteEx = fsf_forward_overwrite_ex;
	if (source->GetEa != NULL)
		target->GetEa = fsf_forward_get_ea;
	if (source->SetEa != NULL)
		target->SetEa = fsf_forward_set_ea;
	target->DispatcherStopped = fsf_forward_dispatcher_stopped;
}

static NTSTATUS fsf_call_file_system_create(FSF_WINFSP *frontend)
{
	NTSTATUS status = FspFileSystemCreate(L"" FSP_FSCTL_DISK_DEVICE_NAME,
		&frontend->volume_params, &frontend->forwarding, &frontend->file_system);
	if (NT_SUCCESS(status))
		frontend->file_system->UserContext = frontend->backend_context;
	return status;
}

NTSTATUS fsf_winfsp_create(const FSF_WINFSP_CONFIG *config,
	FSF_WINFSP **frontend_out, DWORD *win32_detail_out)
{
	FSF_WINFSP *frontend;
	NTSTATUS status;
	if (frontend_out == NULL)
		return STATUS_INVALID_PARAMETER;
	*frontend_out = NULL;
	if (win32_detail_out != NULL)
		*win32_detail_out = ERROR_SUCCESS;
	if (config == NULL || config->struct_size != sizeof(*config) ||
		config->abi_version != FS_FRONTEND_ABI_VERSION ||
		config->operation_table_size != sizeof(FSP_FILE_SYSTEM_INTERFACE) ||
		config->operations == NULL)
		return STATUS_REVISION_MISMATCH;
	if (fsf_interface_has_unsupported_callbacks(config->operations))
		return STATUS_NOT_SUPPORTED;

	frontend = (FSF_WINFSP *)calloc(1, sizeof(*frontend));
	if (frontend == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	frontend->operations = *config->operations;
	frontend->volume_params = config->volume_params;
	frontend->backend_context = config->backend_context;
	frontend->resolve_create_failure = config->resolve_create_failure;
	frontend->stopped_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (frontend->stopped_event == NULL) {
		status = FspNtStatusFromWin32(GetLastError());
		goto fail;
	}
	fsf_build_forwarding_table(frontend);

	status = fsf_call_file_system_create(frontend);
	if (!NT_SUCCESS(status) && frontend->resolve_create_failure != NULL) {
		NTSTATUS first_status = status;
		DWORD detail_error = ERROR_SUCCESS;
		BOOL retry_create = FALSE;
		NTSTATUS resolution_status = frontend->resolve_create_failure(
			frontend->backend_context, first_status, &retry_create, &detail_error);
		if (win32_detail_out != NULL)
			*win32_detail_out = detail_error;
		if (retry_create && NT_SUCCESS(resolution_status)) {
			status = fsf_call_file_system_create(frontend);
		} else if (!retry_create && !NT_SUCCESS(resolution_status)) {
			status = resolution_status;
		} else {
			status = first_status;
		}
	}
	if (!NT_SUCCESS(status))
		goto fail;
	*frontend_out = frontend;
	return STATUS_SUCCESS;

fail:
	if (frontend->file_system != NULL)
		FspFileSystemDelete(frontend->file_system);
	if (frontend->stopped_event != NULL)
		CloseHandle(frontend->stopped_event);
	free(frontend);
	return status;
}

FSP_FILE_SYSTEM *fsf_winfsp_object(FSF_WINFSP *frontend)
{
	return frontend != NULL ? frontend->file_system : NULL;
}

NTSTATUS fsf_winfsp_mount(FSF_WINFSP *frontend, PCWSTR mount_point)
{
	if (frontend == NULL || frontend->file_system == NULL || mount_point == NULL)
		return STATUS_INVALID_PARAMETER;
	return FspFileSystemSetMountPoint(frontend->file_system, (PWSTR)mount_point);
}

NTSTATUS fsf_winfsp_start(FSF_WINFSP *frontend, uint32_t dispatcher_threads)
{
	NTSTATUS status;
	if (frontend == NULL || frontend->file_system == NULL || frontend->stopped_event == NULL)
		return STATUS_INVALID_PARAMETER;
	if (frontend->dispatcher_started)
		return STATUS_INVALID_DEVICE_STATE;
	ResetEvent(frontend->stopped_event);
	InterlockedExchange(&frontend->dispatcher_stopped_normally, 0);
	status = FspFileSystemStartDispatcher(frontend->file_system, dispatcher_threads);
	if (NT_SUCCESS(status))
		frontend->dispatcher_started = true;
	return status;
}

HANDLE fsf_winfsp_stopped_event(FSF_WINFSP *frontend)
{
	return frontend != NULL ? frontend->stopped_event : NULL;
}

BOOL fsf_winfsp_dispatcher_stopped_normally(FSF_WINFSP *frontend)
{
	return frontend != NULL && InterlockedCompareExchange(
		&frontend->dispatcher_stopped_normally, 0, 0) == 1;
}

NTSTATUS fsf_winfsp_dispatcher_result(FSF_WINFSP *frontend)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	if (frontend != NULL && frontend->file_system != NULL)
		FspFileSystemGetDispatcherResult(frontend->file_system, &status);
	return status;
}

void fsf_winfsp_stop(FSF_WINFSP *frontend)
{
	if (frontend == NULL || frontend->file_system == NULL || !frontend->dispatcher_started)
		return;
	/* WinFsp StopDispatcher joins its dispatcher thread; DispatcherStopped runs
	 * on that thread before it exits, so no separate unbounded event wait is needed. */
	FspFileSystemStopDispatcher(frontend->file_system);
	frontend->dispatcher_started = false;
}

void fsf_winfsp_destroy(FSF_WINFSP *frontend)
{
	if (frontend == NULL)
		return;
	if (frontend->file_system != NULL) {
		if (frontend->dispatcher_started)
			fsf_winfsp_stop(frontend);
		FspFileSystemDelete(frontend->file_system);
		frontend->file_system = NULL;
	}
	if (frontend->stopped_event != NULL)
		CloseHandle(frontend->stopped_event);
	free(frontend);
}

void *fs_frontend_backend_context(FSP_FILE_SYSTEM *file_system)
{
	return file_system != NULL ? file_system->UserContext : NULL;
}
