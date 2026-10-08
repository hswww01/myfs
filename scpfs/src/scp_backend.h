#ifndef SCPFS_SCP_BACKEND_H
#define SCPFS_SCP_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SCPFS_BACKEND SCPFS_BACKEND;
typedef struct SCPFS_WATCH_STREAM SCPFS_WATCH_STREAM;

typedef enum SCPFS_REMOTE_TYPE {
	SCPFS_REMOTE_OTHER = 0,
	SCPFS_REMOTE_FILE = 1,
	SCPFS_REMOTE_DIRECTORY = 2,
	SCPFS_REMOTE_SYMLINK = 3
} SCPFS_REMOTE_TYPE;

typedef struct SCPFS_REMOTE_STAT {
	SCPFS_REMOTE_TYPE type;
	uint32_t mode;
	uint64_t size;
	int64_t atime_ns;
	int64_t mtime_ns;
	uint64_t device;
	uint64_t inode;
	uint64_t uid;
	uint64_t gid;
	int64_t ctime_ns;
} SCPFS_REMOTE_STAT;

typedef struct SCPFS_DIR_ENTRY {
	WCHAR *name;
	size_t name_length;
	SCPFS_REMOTE_STAT stat;
} SCPFS_DIR_ENTRY;

typedef struct SCPFS_DIR_LIST {
	SCPFS_DIR_ENTRY *entries;
	size_t count;
} SCPFS_DIR_LIST;

typedef struct SCPFS_INBOX_RESULT {
	bool input_consumed;
	bool completed;
	bool outcome_unknown;
	bool output_published;
	int exit_code;
	/* Static backend-owned diagnostic stage; never free this pointer. */
	PCWSTR failure_stage;
	/* Allocated UTF-16 remote absolute path, present when claim is retained. */
	WCHAR *claim_path;
} SCPFS_INBOX_RESULT;

typedef struct SCPFS_BACKEND_OPTIONS {
	PCWSTR host;
	PCWSTR username;
	uint16_t port;
	PCWSTR remote_root;
	PCWSTR known_hosts_file;
	PCWSTR identity_file;
	PCWSTR identity_passphrase;
	uint32_t timeout_ms;
} SCPFS_BACKEND_OPTIONS;

/*
 * All paths passed to operations are WinFsp-style absolute paths rooted at
 * the mount (for example L"\\docs\\report.txt"). The backend resolves
 * them below remote_root and preserves Linux case sensitivity. The backend
 * serializes operations that share its SSH session; callers may use one
 * backend from multiple WinFsp callbacks.
 */
NTSTATUS scp_backend_connect(const SCPFS_BACKEND_OPTIONS *options,
	SCPFS_BACKEND **backend_out);
void scp_backend_disconnect(SCPFS_BACKEND *backend);
/* Allocated UTF-16 copy of the root pinned by connect; caller frees it. */
WCHAR *scp_backend_dup_remote_root(const SCPFS_BACKEND *backend);
/* Borrowed manual-reset event; valid until disconnect and signaled on first poison. */
HANDLE scp_backend_failure_event(SCPFS_BACKEND *backend);
/* Wait for the event before reading after failure; it is signaled after status latching. */
NTSTATUS scp_backend_failure_status(const SCPFS_BACKEND *backend);

/* Private monitor transport used only by scp_watch.c. All operations are
 * bounded; the stream owns a second authenticated SCPFS_BACKEND session. */
NTSTATUS scp_backend_watch_stream_open(const SCPFS_BACKEND_OPTIONS *options,
	const unsigned char *helper_source, size_t helper_length,
	SCPFS_WATCH_STREAM **stream_out);
NTSTATUS scp_backend_watch_stream_write(SCPFS_WATCH_STREAM *stream,
	const void *data, size_t length);
NTSTATUS scp_backend_watch_stream_read(SCPFS_WATCH_STREAM *stream,
	void *buffer, size_t capacity, size_t *read_out);
void scp_backend_watch_stream_close(SCPFS_WATCH_STREAM *stream);
/* Waits until the stream has data, wake_event or stop_event is signaled, or
 * timeout_ms elapses; *readable reports stream data. */
NTSTATUS scp_backend_watch_stream_wait(SCPFS_WATCH_STREAM *stream,
	HANDLE wake_event, HANDLE stop_event, DWORD timeout_ms, bool *readable);

/* Converts one remote UTF-8 directory entry name exactly as listing does;
 * STATUS_OBJECT_NAME_INVALID when Windows cannot represent it. */
NTSTATUS scp_backend_decode_name(const char *utf8, size_t length,
	WCHAR **name_out, size_t *name_length_out);

NTSTATUS scp_backend_stat(SCPFS_BACKEND *backend, PCWSTR path,
	SCPFS_REMOTE_STAT *stat_out);
/* Capacity and space available to the account on the remote root's file system. */
NTSTATUS scp_backend_statfs(SCPFS_BACKEND *backend, uint64_t *total_bytes,
	uint64_t *available_bytes);
NTSTATUS scp_backend_list(SCPFS_BACKEND *backend, PCWSTR path,
	SCPFS_DIR_LIST *list_out);
void scp_backend_free_list(SCPFS_DIR_LIST *list);
void scp_backend_free_inbox_result(SCPFS_INBOX_RESULT *result);

NTSTATUS scp_backend_download(SCPFS_BACKEND *backend, PCWSTR path,
	PCWSTR local_cache_path, SCPFS_REMOTE_STAT *stat_out);
/* expected_stat == NULL means the remote destination must not already exist. */
NTSTATUS scp_backend_upload_atomic(SCPFS_BACKEND *backend, PCWSTR path,
	PCWSTR local_cache_path, const SCPFS_REMOTE_STAT *expected_stat,
	SCPFS_REMOTE_STAT *stat_out);

NTSTATUS scp_backend_create(SCPFS_BACKEND *backend, PCWSTR path,
	uint32_t mode);
NTSTATUS scp_backend_mkdir(SCPFS_BACKEND *backend, PCWSTR path,
	uint32_t mode);
NTSTATUS scp_backend_remove(SCPFS_BACKEND *backend, PCWSTR path,
	bool is_directory);
NTSTATUS scp_backend_rename(SCPFS_BACKEND *backend, PCWSTR old_path,
	PCWSTR new_path, bool replace_existing);
NTSTATUS scp_backend_setmeta(SCPFS_BACKEND *backend, PCWSTR path,
	uint32_t mode, int64_t atime_ns, int64_t mtime_ns, bool set_mode,
	bool set_atime, bool set_mtime);

/* Execute the literal .in.txt sibling inbox contract. A nonzero or timed out
 * command is still completed when its .out.txt has been atomically published. */
NTSTATUS scp_backend_execute_inbox(SCPFS_BACKEND *backend, PCWSTR exact_path,
	uint32_t timeout_ms, SCPFS_INBOX_RESULT *result_out);

#ifdef __cplusplus
}
#endif

#endif /* SCPFS_SCP_BACKEND_H */
