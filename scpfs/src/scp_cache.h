#ifndef SCPFS_SCP_CACHE_H
#define SCPFS_SCP_CACHE_H

#include "scp_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCPFS_CACHE_METADATA_LIMIT_BYTES (8u * 1024u * 1024u)
#define SCPFS_CACHE_METADATA_LIMIT_ENTRIES 4096u

typedef struct SCPFS_CACHE SCPFS_CACHE;

typedef struct SCPFS_CACHE_COUNTERS {
	uint64_t stat_hit;
	uint64_t stat_miss;
	uint64_t list_hit;
	uint64_t list_miss;
	uint64_t payload_hit;
	uint64_t payload_miss;
	uint64_t evictions;
	uint64_t invalidations;
	uint64_t monitor_bypass;
} SCPFS_CACHE_COUNTERS;

NTSTATUS scp_cache_create(PCWSTR session_directory, uint32_t max_payload_mib,
	SCPFS_CACHE **cache_out);
void scp_cache_destroy(SCPFS_CACHE *cache);

bool scp_cache_get_stat(SCPFS_CACHE *cache, PCWSTR path,
	uint64_t metadata_epoch, uint64_t content_epoch,
	SCPFS_REMOTE_STAT *stat_out);
void scp_cache_put_stat(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, uint64_t metadata_epoch,
	uint64_t content_epoch);

bool scp_cache_get_list(SCPFS_CACHE *cache, PCWSTR path,
	uint64_t metadata_epoch, uint64_t content_epoch,
	SCPFS_DIR_LIST *list_out);
void scp_cache_put_list(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_DIR_LIST *list, uint64_t metadata_epoch,
	uint64_t content_epoch);

/* The returned payload path is borrowed until the next cache mutation. */
bool scp_cache_get_payload(SCPFS_CACHE *cache, PCWSTR path,
	uint64_t metadata_epoch, uint64_t content_epoch, PCWSTR *payload_path_out,
	SCPFS_REMOTE_STAT *provenance_out, uint64_t *metadata_epoch_out,
	bool *metadata_stale_out);
bool scp_cache_validate_payload(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *fresh_stat, uint64_t metadata_epoch);
void scp_cache_put_payload(SCPFS_CACHE *cache, PCWSTR path,
	PCWSTR source_path, const SCPFS_REMOTE_STAT *provenance,
	uint64_t metadata_epoch, uint64_t content_epoch);
void scp_cache_evict_payload(SCPFS_CACHE *cache, PCWSTR path);

void scp_cache_invalidate_metadata(SCPFS_CACHE *cache);
void scp_cache_invalidate_all(SCPFS_CACHE *cache);
void scp_cache_record_monitor_bypass(SCPFS_CACHE *cache);
void scp_cache_record_payload_hit(SCPFS_CACHE *cache);
void scp_cache_record_payload_miss(SCPFS_CACHE *cache);
void scp_cache_get_counters(const SCPFS_CACHE *cache,
	SCPFS_CACHE_COUNTERS *counters_out);

#ifdef __cplusplus
}
#endif

#endif /* SCPFS_SCP_CACHE_H */
