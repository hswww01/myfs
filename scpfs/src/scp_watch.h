#ifndef SCPFS_SCP_WATCH_H
#define SCPFS_SCP_WATCH_H

#include "scp_backend.h"
#include "scp_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Client of the remote inotify helper (server/scpfs_watch.py) on its own SSH
 * session. The helper answers stat/list requests in one round trip and keeps
 * reporting changes to whatever it answered; the monitor thread applies those
 * reports to the cache as they arrive. Requests from many threads are
 * pipelined on the one stream.
 */
typedef struct SCPFS_WATCH SCPFS_WATCH;

/* Starts the monitor asynchronously; events are applied to cache. */
NTSTATUS scp_watch_start(const SCPFS_BACKEND_OPTIONS *options,
	SCPFS_CACHE *cache, SCPFS_WATCH **watch_out);

/*
 * Returns STATUS_NOT_SUPPORTED when the helper cannot answer (not connected,
 * path not watchable); callers then use the backend. Otherwise *cacheable
 * tells whether the answer (a stat, or STATUS_OBJECT_NAME_NOT_FOUND) is
 * covered by watches, and *sequence is the cache sequence it was observed at.
 */
NTSTATUS scp_watch_stat(SCPFS_WATCH *watch, PCWSTR path,
	SCPFS_REMOTE_STAT *stat_out, bool *cacheable, uint64_t *sequence);
/* Entries whose names Windows cannot represent are omitted, as by the backend. */
NTSTATUS scp_watch_list(SCPFS_WATCH *watch, PCWSTR path,
	SCPFS_DIR_LIST *list_out, uint64_t *sequence);
/* Whole content of a regular file of at most limit (capped at 8 MiB) bytes,
 * written to destination (created new). The stat describes those bytes;
 * STATUS_NOT_SUPPORTED means larger, unwatchable or changing: use SCP. */
NTSTATUS scp_watch_read(SCPFS_WATCH *watch, PCWSTR path, uint64_t limit,
	PCWSTR destination, SCPFS_REMOTE_STAT *stat_out, uint64_t *sequence);
/*
 * Mutations performed by the helper in one round trip, with the backend's
 * semantics. STATUS_NOT_SUPPORTED means nothing was done (use the backend);
 * STATUS_IO_TIMEOUT / STATUS_CONNECTION_DISCONNECTED mean the request may
 * have been carried out and must not be repeated blindly.
 */
/* Atomic replace of path with local_path's bytes (at most 8 MiB). expected
 * NULL: path must not exist. Otherwise it must still match expected, whose
 * mode the new file keeps. */
NTSTATUS scp_watch_write(SCPFS_WATCH *watch, PCWSTR path, PCWSTR local_path,
	const SCPFS_REMOTE_STAT *expected, int64_t atime_ns, int64_t mtime_ns,
	SCPFS_REMOTE_STAT *stat_out);
NTSTATUS scp_watch_setmeta(SCPFS_WATCH *watch, PCWSTR path, uint32_t mode,
	int64_t atime_ns, int64_t mtime_ns, bool set_mode, bool set_atime,
	bool set_mtime, SCPFS_REMOTE_STAT *stat_out);
NTSTATUS scp_watch_mkdir(SCPFS_WATCH *watch, PCWSTR path, uint32_t mode,
	SCPFS_REMOTE_STAT *stat_out);
NTSTATUS scp_watch_remove(SCPFS_WATCH *watch, PCWSTR path, bool directory);
NTSTATUS scp_watch_rename(SCPFS_WATCH *watch, PCWSTR old_path, PCWSTR new_path,
	bool replace_existing);
NTSTATUS scp_watch_statfs(SCPFS_WATCH *watch, uint64_t *total_bytes,
	uint64_t *available_bytes);
bool scp_watch_healthy(SCPFS_WATCH *watch);
/* The monitor may connect before the main session has resolved the remote
 * root; it serves nothing until this is called and the helper's resolved
 * root matches it. */
void scp_watch_expect_root(SCPFS_WATCH *watch, PCWSTR canonical_root);
bool scp_watch_wait_healthy(SCPFS_WATCH *watch, DWORD timeout_ms);

/* Stops and joins the monitor thread. */
void scp_watch_stop(SCPFS_WATCH *watch);

#ifdef __cplusplus
}
#endif

#endif /* SCPFS_SCP_WATCH_H */
