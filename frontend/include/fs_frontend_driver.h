#ifndef FS_FRONTEND_DRIVER_H
#define FS_FRONTEND_DRIVER_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Private embedded WinFsp driver deployment shared by every product. Each
 * product embeds the signed SYS files (and, for a dynamic build, the user-mode
 * DLL) as RCDATA resources of its own executable and owns a private driver
 * service name, so products never touch an official WinFsp installation.
 */
typedef struct FSF_DRIVER_SPEC {
	PCWSTR service_name;      /* e.g. L"WinFsp+MemfsC" */
	PCWSTR runtime_dir_name;  /* %ProgramData% subdirectory for a dynamic runtime */
	BOOL static_runtime;      /* WinFsp user mode is linked statically: no DLL */
	WORD dll_resource_id;
	WORD sys_x64_resource_id;
	WORD sys_arm64_resource_id;
	PCWSTR sys_x64_file;      /* file names below %SystemRoot%\System32\drivers */
	PCWSTR sys_x64_alt_file;
	PCWSTR sys_arm64_file;
	PCWSTR sys_arm64_alt_file;
} FSF_DRIVER_SPEC;

/* One product per process: the first spec passed initializes the runtime. */
DWORD fsf_driver_prepare_runtime(const FSF_DRIVER_SPEC *spec);
const wchar_t *fsf_driver_runtime_directory(const FSF_DRIVER_SPEC *spec);
/* Installs/starts the private driver; ERROR_SUCCESS_REBOOT_REQUIRED when an
 * upgrade could only be staged because the old image is still loaded. */
DWORD fsf_driver_install(const FSF_DRIVER_SPEC *spec);
/* Stops and deletes only the private service, then its private payload files. */
DWORD fsf_driver_uninstall(const FSF_DRIVER_SPEC *spec);

/* Pure helpers, exposed for product unit tests. */
DWORD fsf_driver_file_matches_buffer(const wchar_t *path, const void *expected,
	DWORD expected_size, BOOL *matches);
const wchar_t *fsf_driver_select_update_path(const wchar_t *running_path,
	const wchar_t *primary_path, const wchar_t *alternate_path);
DWORD fsf_driver_spec_for_machine(const FSF_DRIVER_SPEC *spec, USHORT native_machine,
	WORD *resource_id, const wchar_t **primary_file, const wchar_t **alternate_file);
DWORD fsf_driver_native_machine(USHORT *native_machine);
DWORD fsf_driver_plan_running_update(const wchar_t *configured_path,
	BOOL configured_matches_payload, const wchar_t *primary_path,
	const wchar_t *alternate_path, const wchar_t **stage_path);
BOOL fsf_driver_payload_cleanup_allowed(DWORD service_error);

#ifdef __cplusplus
}
#endif

#endif /* FS_FRONTEND_DRIVER_H */
