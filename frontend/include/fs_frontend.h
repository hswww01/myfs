#ifndef FS_FRONTEND_H
#define FS_FRONTEND_H

#include <winsock2.h>
#include <windows.h>
#include <winsvc.h>
#include <winternl.h>
/* Some SDK include paths expose NTSTATUS without its pointer alias. */
typedef NTSTATUS *PNTSTATUS;
#include <winfsp/winfsp.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FS_FRONTEND_ABI_VERSION 1u

typedef struct FSF_WINFSP FSF_WINFSP;
typedef struct FSF_SERVICE FSF_SERVICE;

/*
 * Called after FspFileSystemCreate fails. The backend decides whether this
 * status is eligible for its private embedded-driver recovery, performs only
 * that recovery, and returns the backend's established status mapping. Set
 * retry_create only when retrying FspFileSystemCreate is safe.
 */
typedef NTSTATUS (*FSF_RESOLVE_CREATE_FAILURE_FN)(
	void *backend_context,
	NTSTATUS first_create_status,
	BOOL *retry_create,
	DWORD *win32_detail_out);

typedef struct FSF_WINFSP_CONFIG {
	uint32_t struct_size;
	uint32_t abi_version;
	uint32_t operation_table_size;
	void *backend_context;
	const FSP_FILE_SYSTEM_INTERFACE *operations;
	FSP_FSCTL_VOLUME_PARAMS volume_params;
	FSF_RESOLVE_CREATE_FAILURE_FN resolve_create_failure;
} FSF_WINFSP_CONFIG;

NTSTATUS fsf_winfsp_create(const FSF_WINFSP_CONFIG *config,
	FSF_WINFSP **frontend_out, DWORD *win32_detail_out);
FSP_FILE_SYSTEM *fsf_winfsp_object(FSF_WINFSP *frontend);
NTSTATUS fsf_winfsp_mount(FSF_WINFSP *frontend, PCWSTR mount_point);
NTSTATUS fsf_winfsp_start(FSF_WINFSP *frontend, uint32_t dispatcher_threads);
HANDLE fsf_winfsp_stopped_event(FSF_WINFSP *frontend);
BOOL fsf_winfsp_dispatcher_stopped_normally(FSF_WINFSP *frontend);
NTSTATUS fsf_winfsp_dispatcher_result(FSF_WINFSP *frontend);
void fsf_winfsp_stop(FSF_WINFSP *frontend);
/* Stops and joins dispatch, deletes the WinFsp object, then frees the frontend. */
void fsf_winfsp_destroy(FSF_WINFSP *frontend);
/* Thin accessor: returns FileSystem->UserContext unchanged, including in test fakes. */
void *fs_frontend_backend_context(FSP_FILE_SYSTEM *file_system);

typedef struct FSF_SERVICE_EXIT {
	BOOL normal_stop;
	DWORD win32_error;
	DWORD service_specific_error;
} FSF_SERVICE_EXIT;

typedef FSF_SERVICE_EXIT (*FSF_SERVICE_RUN_FN)(
	void *app_context, FSF_SERVICE *service);

typedef struct FSF_SERVICE_RUN_CONFIG {
	uint32_t struct_size;
	uint32_t abi_version;
	PCWSTR service_name;
	/* Required absolute path; product resolves a default before calling. */
	PCWSTR log_path;
	PCWSTR authorized_user_sid;
	void *app_context;
	FSF_SERVICE_RUN_FN run;
	/* Also stop on SERVICE_CONTROL_PRESHUTDOWN, which gives the service the
	 * preshutdown timeout to finish instead of the few seconds SHUTDOWN
	 * allows. For services whose stop must complete (e.g. a disk detach). */
	BOOL accept_preshutdown;
} FSF_SERVICE_RUN_CONFIG;

/* Called by the product run callback on the SCM service-main thread. */
DWORD fsf_service_run(const FSF_SERVICE_RUN_CONFIG *config,
	FSF_SERVICE_EXIT *result_out);
HANDLE fsf_service_stop_event(FSF_SERVICE *service);
/* Report RUNNING only after the backend mount and dispatcher both succeeded. */
BOOL fsf_service_report_running(FSF_SERVICE *service, DWORD *win32_error_out);
BOOL fsf_service_report_start_progress(FSF_SERVICE *service,
	DWORD wait_hint_ms, DWORD *win32_error_out);

enum {
	FSF_SERVICE_LOG_INFORMATION = 1,
	FSF_SERVICE_LOG_WARNING = 2,
	FSF_SERVICE_LOG_ERROR = 3
};
/* Appends to the protected service log (SYSTEM and explicit SID only). */
void fsf_service_log(FSF_SERVICE *service, DWORD level,
	DWORD status, PCWSTR message);

typedef struct FSF_SERVICE_INSTALL_CONFIG {
	uint32_t struct_size;
	uint32_t abi_version;
	PCWSTR service_name;
	PCWSTR display_name;
	PCWSTR description;
	PCWSTR absolute_executable;
	PCWSTR exact_service_arguments;
	PCWSTR log_path;
	PCWSTR authorized_user_sid;
	BOOL delayed_auto_start;
	DWORD start_timeout_ms;
	DWORD failure_reset_seconds;
	DWORD failure_action_count;
	const SC_ACTION *failure_actions;
	/* Optional double-NUL-terminated list of services that must start first. */
	PCWSTR dependencies;
} FSF_SERVICE_INSTALL_CONFIG;

/* Creates a LocalSystem automatic service, configures bounded recovery, and starts it. */
DWORD fsf_service_install(const FSF_SERVICE_INSTALL_CONFIG *config);
/* Bounded-stop only the named user-mode service, then delete that registration. */
DWORD fsf_service_uninstall(PCWSTR service_name, DWORD stop_timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* FS_FRONTEND_H */
