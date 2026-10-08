#ifndef SCPFS_SCP_CACHE_H
#define SCPFS_SCP_CACHE_H

#include "scp_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCPFS_CACHE_METADATA_LIMIT_BYTES (64u * 1024u * 1024u)
#define SCPFS_CACHE_METADATA_LIMIT_ENTRIES 131072u

/*
 * Read cache for remote metadata and file payloads. Every entry is valid only
 * while the watch helper covers its path; the monitor thread reports each
 * change through scp_cache_invalidate_path(). All functions are thread safe.
 *
 * Admission is ordered against invalidation with a sequence number: callers
 * read scp_cache_sequence() when the data was observed and pass it to put.
 * A put is dropped when an invalidation touching the same path (or an
 * ancestor/descendant) was recorded after that sequence.
 */
typedef struct SCPFS_CACHE SCPFS_CACHE;

typedef enum SCPFS_CACHE_LOOKUP {
	SCPFS_CACHE_MISS = 0,
	SCPFS_CACHE_PRESENT,
	SCPFS_CACHE_ABSENT
} SCPFS_CACHE_LOOKUP;

/* Invalidation kinds; they match the helper's C/M/T events. */
#define SCPFS_CACHE_CHANGE_METADATA 1u /* path stat + parent listing */
#define SCPFS_CACHE_CHANGE_CONTENT  2u /* + payload, own listing, parent stat */
#define SCPFS_CACHE_CHANGE_SUBTREE  4u /* + everything below path */

typedef struct SCPFS_CACHE_COUNTERS {
	uint64_t stat_hit;
	uint64_t stat_miss;
	uint64_t list_hit;
	uint64_t list_miss;
	uint64_t payload_hit;
	uint64_t payload_miss;
	uint64_t evictions;
	uint64_t invalidations;
	uint64_t rejected_puts;
} SCPFS_CACHE_COUNTERS;

NTSTATUS scp_cache_create(PCWSTR session_directory, uint32_t max_payload_mib,
	SCPFS_CACHE **cache_out);
void scp_cache_destroy(SCPFS_CACHE *cache);

uint64_t scp_cache_sequence(SCPFS_CACHE *cache);

SCPFS_CACHE_LOOKUP scp_cache_get_stat(SCPFS_CACHE *cache, PCWSTR path,
	SCPFS_REMOTE_STAT *stat_out);
/* stat == NULL records that path does not exist. */
void scp_cache_put_stat(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *stat, uint64_t sequence);

bool scp_cache_get_list(SCPFS_CACHE *cache, PCWSTR path,
	SCPFS_DIR_LIST *list_out);
/* Also records the stat of every entry. */
void scp_cache_put_list(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_DIR_LIST *list, uint64_t sequence);

/* Copies the cached bytes to destination when the payload was taken from
 * the same inode, size and mtime as expected. */
bool scp_cache_copy_payload(SCPFS_CACHE *cache, PCWSTR path,
	const SCPFS_REMOTE_STAT *expected, PCWSTR destination);
void scp_cache_put_payload(SCPFS_CACHE *cache, PCWSTR path,
	PCWSTR source_path, const SCPFS_REMOTE_STAT *provenance, uint64_t sequence);

void scp_cache_invalidate_path(SCPFS_CACHE *cache, PCWSTR path, unsigned kind);
void scp_cache_invalidate_all(SCPFS_CACHE *cache);
void scp_cache_get_counters(SCPFS_CACHE *cache,
	SCPFS_CACHE_COUNTERS *counters_out);

#ifdef __cplusplus
}
#endif

#endif /* SCPFS_SCP_CACHE_H */
