#ifndef SCPFS_SCP_WATCH_H
#define SCPFS_SCP_WATCH_H

#include "scp_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SCPFS_WATCH SCPFS_WATCH;

typedef struct SCPFS_WATCH_STATE {
	bool healthy;
	uint64_t metadata_epoch;
	uint64_t content_epoch;
} SCPFS_WATCH_STATE;

/* Starts the independent SSH monitor asynchronously. */
NTSTATUS scp_watch_start(const SCPFS_BACKEND_OPTIONS *options,
	SCPFS_WATCH **watch_out);
/* Adds acknowledged coverage for a WinFsp virtual path. */
bool scp_watch_ensure(SCPFS_WATCH *watch, PCWSTR path, bool directory);
/* Drains pending events on the monitor connection before returning. */
bool scp_watch_barrier(SCPFS_WATCH *watch);
/* Returns unhealthy/zero epochs when watch is NULL. */
void scp_watch_snapshot(SCPFS_WATCH *watch, SCPFS_WATCH_STATE *state_out);
/* Stops and joins the monitor owner thread. Call outside adapter locks. */
void scp_watch_stop(SCPFS_WATCH *watch);

#ifdef __cplusplus
}
#endif

#endif /* SCPFS_SCP_WATCH_H */
