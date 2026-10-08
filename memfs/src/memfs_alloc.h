#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <Windows.h>
#else
typedef void SRWLOCK;
typedef long long LONG64;
#endif

typedef struct MemfsAllocatorState MemfsAllocatorState;

enum { MEMFS_ALLOC_CLASS_COUNT = 19 };
enum { MEMFS_ALLOC_AREA_THRESHOLD = 8192 };
/*
 * Minimum alignment guaranteed for every non-NULL allocation returned to a
 * caller. Size classes intentionally include 8- and 24-byte slots, so the
 * public contract is 8 bytes; internal slab/area payload starts may use a
 * stronger alignment without changing this guarantee.
 */
enum { MEMFS_ALLOC_MIN_ALIGNMENT = 8 };

typedef enum MemfsAllocFailPoint {
    MEMFS_ALLOC_FAIL_NONE = 0,
    MEMFS_ALLOC_FAIL_BOOTSTRAP,
    MEMFS_ALLOC_FAIL_SLAB,
    MEMFS_ALLOC_FAIL_DEDICATED,
    MEMFS_ALLOC_FAIL_NODE,
    MEMFS_ALLOC_FAIL_DIR,
    MEMFS_ALLOC_FAIL_GROUP,
    MEMFS_ALLOC_FAIL_NAME,
    MEMFS_ALLOC_FAIL_GENERIC,
    MEMFS_ALLOC_FAIL_METADATA,
    MEMFS_ALLOC_FAIL_PAGE,
    MEMFS_ALLOC_FAIL_SECURITY
} MemfsAllocFailPoint;

#if !defined(NDEBUG)
void memfs_allocator_test_fail_after(MemfsAllocFailPoint point,
                                     uint32_t successful_calls_before_failure,
                                     uint32_t failure_count);
void memfs_allocator_test_clear_failures(void);
bool memfs_allocator_test_should_fail(MemfsAllocFailPoint point);
#else
static inline void memfs_allocator_test_fail_after(MemfsAllocFailPoint point,
                                                    uint32_t successful_calls_before_failure,
                                                    uint32_t failure_count) {
    (void)point;
    (void)successful_calls_before_failure;
    (void)failure_count;
}
static inline void memfs_allocator_test_clear_failures(void) {
}
static inline bool memfs_allocator_test_should_fail(MemfsAllocFailPoint point) {
    (void)point;
    return false;
}
#endif

/*
 * One allocator = one unified set of size classes.
 *
 * Node/Dir/PageGroup/name/generic allocations intentionally share the same
 * class pool when their rounded size is identical. Small allocations use
 * adaptive 4K/8K/16K/32K/64K slabs. Larger allocations use an area allocation
 * with an in-band header and O(1) unlink/free.
 */
typedef struct MemfsAllocator {
    MemfsAllocatorState* state;
    size_t node_size;
    size_t dir_size;
    size_t page_group_size;
    volatile LONG64 scavenged_bytes;
    volatile LONG64 scavenge_count;
} MemfsAllocator;

/*
 * Allocator statistics are a lock-safe aggregate, not a globally atomic
 * instant. Shards are sampled one at a time, so values can describe slightly
 * different instants while allocation/free activity is concurrent. Quiescent
 * callers can use the result as an exact baseline.
 */
typedef struct MemfsAllocatorStats {
    uint64_t reserved_bytes;
    uint64_t committed_bytes;
    uint64_t physical_bytes;
    uint64_t live_bytes;
    uint64_t live_objects;
    uint32_t slab_count;

    /*
     * Kept for API/test compatibility. "dedicated" now means area allocation
     * (> MEMFS_ALLOC_AREA_THRESHOLD), not a linearly-searched dedicated list.
     */
    uint32_t dedicated_count;
    uint64_t dedicated_reserved_bytes;
    uint64_t dedicated_committed_bytes;
    uint64_t dedicated_live_bytes;
    uint32_t area_cached_count;
    uint64_t area_cached_bytes;

    uint64_t scavenged_bytes;
    uint64_t scavenge_count;
} MemfsAllocatorStats;

#if !defined(NDEBUG)
bool memfs_allocator_test_class_layout(size_t bytes,
                                       size_t* class_bytes,
                                       size_t* slab_bytes);
size_t memfs_allocator_test_class_size(uint32_t class_index);
void* memfs_allocator_test_alloc_from_shard(MemfsAllocator* allocator,
                                            size_t bytes,
                                            uint32_t shard_index);
uint32_t memfs_allocator_test_shard_count(void);
#endif

bool memfs_allocator_init(MemfsAllocator* allocator,
                          size_t node_size,
                          size_t dir_size,
                          size_t page_group_size);
void memfs_allocator_destroy(MemfsAllocator* allocator);

void* memfs_allocator_alloc_node(MemfsAllocator* allocator);
void memfs_allocator_free_node(MemfsAllocator* allocator, void* ptr);

void* memfs_allocator_alloc_dir(MemfsAllocator* allocator);
void memfs_allocator_free_dir(MemfsAllocator* allocator, void* ptr);

void* memfs_allocator_alloc_page_group(MemfsAllocator* allocator);
void memfs_allocator_free_page_group(MemfsAllocator* allocator, void* ptr);

void* memfs_allocator_alloc_name(MemfsAllocator* allocator, size_t bytes);
void memfs_allocator_free_name(MemfsAllocator* allocator, void* ptr, size_t bytes);

void* memfs_allocator_alloc(MemfsAllocator* allocator, size_t bytes);
/*
 * Fast path for storage that the caller will completely overwrite before any
 * read. Unlike memfs_allocator_alloc()/alloc_zero(), contents are unspecified
 * and may contain bytes from a previously freed object.
 */
void* memfs_allocator_alloc_uninit(MemfsAllocator* allocator, size_t bytes);
void* memfs_allocator_alloc_zero(MemfsAllocator* allocator, size_t bytes);
void* memfs_allocator_realloc(MemfsAllocator* allocator,
                              void* ptr,
                              size_t old_bytes,
                              size_t new_bytes);
void memfs_allocator_free(MemfsAllocator* allocator, void* ptr, size_t bytes);

/*
 * See MemfsAllocatorStats above: concurrent results are approximate aggregates;
 * call while quiescent when exact cross-field relationships are required.
 */
/*
 * O(1) committed backing query used by auto-capacity admission. This counter
 * tracks allocator VM backing only; detailed per-shard diagnostics still come
 * from memfs_allocator_get_stats().
 */
uint64_t memfs_allocator_committed_bytes(MemfsAllocator* allocator);
/* Cumulative successful VM commitments; frees do not reduce this counter. */
uint64_t memfs_allocator_commit_total_bytes(MemfsAllocator* allocator);
void memfs_allocator_get_stats(MemfsAllocator* allocator, MemfsAllocatorStats* stats);
uint64_t memfs_allocator_scavenge(MemfsAllocator* allocator);

/*
 * Process-wide control allocation for objects that must exist before their own
 * per-filesystem allocator can be initialized (currently Memfs itself).
 *
 * This path uses the same size-class/slab/area allocator as normal allocations;
 * only the allocator state's own bootstrap reaches the VM backend directly.
 */
void* memfs_allocator_alloc_control(size_t bytes);
void memfs_allocator_free_control(void* ptr, size_t bytes);
