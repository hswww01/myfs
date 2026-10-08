#ifndef SCPFS_SCPFS_H
#define SCPFS_SCPFS_H

#include <winsock2.h>
#include "scp_backend.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SCPFS SCPFS;

typedef struct SCPFS_OPTIONS {
	SCPFS_BACKEND_OPTIONS backend;
	/* Optional writable parent directory. A unique session directory is created below it. */
	PCWSTR cache_directory;
	/* Immutable remote payload capacity in MiB; zero means unlimited, always enabled. */
	uint32_t read_cache_max_mib;
	/* Remote inbox command timeout; zero selects the 30-second default. */
	uint32_t command_timeout_ms;
	/*
	 * Optional SID granted access in addition to the launch TokenUser and SYSTEM.
	 * The SID string is parsed and copied into the default security descriptor
	 * during scpfs_create; NULL preserves the launch-user-only default.
	 */
	PCWSTR authorized_user_sid;
} SCPFS_OPTIONS;

NTSTATUS scpfs_create(const SCPFS_OPTIONS *options, SCPFS **instance_out);
PCWSTR scpfs_cache_directory(const SCPFS *instance);
NTSTATUS scpfs_mount(SCPFS *instance, PCWSTR mount_point);
/* Zero selects the required serialized dispatcher; counts greater than one are rejected. */
NTSTATUS scpfs_start(SCPFS *instance, uint32_t dispatcher_thread_count);
HANDLE scpfs_dispatcher_stopped_event(SCPFS *instance);
bool scpfs_dispatcher_stopped_normally(const SCPFS *instance);
NTSTATUS scpfs_dispatcher_result(const SCPFS *instance);
/* Borrowed, manual-reset event/status reporting the first poisoned SSH backend. */
HANDLE scpfs_backend_failure_event(SCPFS *instance);
NTSTATUS scpfs_backend_failure_status(const SCPFS *instance);
void scpfs_stop(SCPFS *instance);
void scpfs_destroy(SCPFS *instance);

#ifdef __cplusplus
}
#endif

#endif /* SCPFS_SCPFS_H */
