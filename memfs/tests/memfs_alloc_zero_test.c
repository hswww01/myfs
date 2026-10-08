#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memfs_alloc.h"

typedef enum ZeroAllocationKind {
    ZERO_ALLOC_GENERIC,
    ZERO_ALLOC_EXPLICIT,
    ZERO_ALLOC_NODE
} ZeroAllocationKind;

static uint32_t g_failures;

static void check(bool condition, const char* description, size_t bytes) {
    if (!condition) {
        fprintf(stderr, "FAIL size=%llu: %s\n",
                (unsigned long long)bytes, description);
        ++g_failures;
    }
}

static void check_zero(const void* allocation, size_t bytes, const char* phase) {
    const uint8_t* data = allocation;
    size_t i;

    for (i = 0; i < bytes; ++i) {
        if (data[i] != 0U) {
            fprintf(stderr, "FAIL phase=%s size=%llu offset=%llu value=%u\n",
                    phase, (unsigned long long)bytes,
                    (unsigned long long)i, (unsigned int)data[i]);
            ++g_failures;
            return;
        }
    }
}

static void* allocate_zero(MemfsAllocator* allocator,
                           size_t bytes,
                           ZeroAllocationKind kind) {
    if (kind == ZERO_ALLOC_NODE)
        return memfs_allocator_alloc_node(allocator);
    if (kind == ZERO_ALLOC_EXPLICIT)
        return memfs_allocator_alloc_zero(allocator, bytes);
    return memfs_allocator_alloc(allocator, bytes);
}

static void free_allocation(MemfsAllocator* allocator,
                            void* allocation,
                            size_t bytes,
                            ZeroAllocationKind kind) {
    if (kind == ZERO_ALLOC_NODE)
        memfs_allocator_free_node(allocator, allocation);
    else
        memfs_allocator_free(allocator, allocation, bytes);
}

static void run_case(size_t bytes, ZeroAllocationKind kind, bool cached) {
    MemfsAllocator allocator = {0};
    MemfsAllocatorStats baseline;
    MemfsAllocatorStats stats;
    void* first = NULL;
    void* second = NULL;
    void* after_scavenge = NULL;

    check(memfs_allocator_init(&allocator, bytes, 64U, 64U),
          "allocator initialization", bytes);
    if (allocator.state == NULL)
        return;

    memfs_allocator_get_stats(&allocator, &baseline);
    first = allocate_zero(&allocator, bytes, kind);
    check(first != NULL, "fresh allocation", bytes);
    if (first == NULL)
        goto cleanup;
    check_zero(first, bytes, "fresh");

    /* A cache hit must erase the previous user's entire requested payload. */
    memset(first, 0xA5, bytes);
    free_allocation(&allocator, first, bytes, kind);
    memfs_allocator_get_stats(&allocator, &stats);
    check(stats.area_cached_count == (cached ? 1U : 0U),
          "expected fresh or cached branch", bytes);

    second = allocate_zero(&allocator, bytes, kind);
    check(second != NULL, "second allocation", bytes);
    if (second != NULL) {
        if (cached)
            check(second == first, "dirty cached area reused", bytes);
        check_zero(second, bytes, cached ? "cached" : "fresh-after-release");
        memset(second, 0x5A, bytes);
        free_allocation(&allocator, second, bytes, kind);
        second = NULL;
    }
    first = NULL;

    /* Explicit cache reclamation also exercises a new committed region. */
    (void)memfs_allocator_scavenge(&allocator);
    memfs_allocator_get_stats(&allocator, &stats);
    check(stats.area_cached_count == 0U && stats.area_cached_bytes == 0U,
          "cache reclaimed", bytes);

    after_scavenge = allocate_zero(&allocator, bytes, kind);
    check(after_scavenge != NULL, "fresh allocation after scavenge", bytes);
    if (after_scavenge != NULL) {
        check_zero(after_scavenge, bytes, "fresh-after-scavenge");
        free_allocation(&allocator, after_scavenge, bytes, kind);
        after_scavenge = NULL;
    }

cleanup:
    (void)memfs_allocator_scavenge(&allocator);
    memfs_allocator_get_stats(&allocator, &stats);
    check(stats.live_objects == baseline.live_objects &&
          stats.live_bytes == baseline.live_bytes &&
          stats.reserved_bytes == baseline.reserved_bytes &&
          stats.committed_bytes == baseline.committed_bytes,
          "quiescent allocator returned to baseline", bytes);
    memfs_allocator_destroy(&allocator);
}

int main(void) {
    run_case((size_t)MEMFS_ALLOC_AREA_THRESHOLD + 1U, ZERO_ALLOC_GENERIC, true);
    run_case(16U * 1024U, ZERO_ALLOC_EXPLICIT, true);
    run_case(64U * 1024U, ZERO_ALLOC_NODE, true);
    run_case(1024U * 1024U + 17U, ZERO_ALLOC_GENERIC, false);
    run_case(1024U * 1024U + 17U, ZERO_ALLOC_EXPLICIT, false);

    if (g_failures != 0U) {
        fprintf(stderr, "allocator zero-initialization failures=%u\n", g_failures);
        return 1;
    }
    puts("allocator fresh/cached zero-initialization PASS");
    return 0;
}
