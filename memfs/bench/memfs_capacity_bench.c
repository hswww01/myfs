#include <Windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memfs_core.h"

#define BENCH_QUERY_COUNT 50000U
#define BENCH_GROW_COUNT 50000U

static double seconds_between(LARGE_INTEGER start,
                              LARGE_INTEGER end,
                              LARGE_INTEGER frequency) {
    return (double)(end.QuadPart - start.QuadPart) /
           (double)frequency.QuadPart;
}

static double ns_per_op(double seconds, uint32_t count) {
    return count ? (seconds * 1000000000.0) / (double)count : 0.0;
}

static int create_fs(bool auto_capacity, Memfs** out_fs) {
    MemfsOptions options;

    memset(&options, 0, sizeof(options));
    options.capacity_auto = auto_capacity;
    options.capacity = auto_capacity ? 0 : (1ULL << 30);
    options.volume_label = auto_capacity ? L"AUTO" : L"FIXED";
    return memfs_create_ex(&options, out_fs) == MEMFS_OK ? 0 : 1;
}

static int bench_committed_query(Memfs* fs,
                                 LARGE_INTEGER frequency,
                                 double* out_ns) {
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    volatile uint64_t sink = 0;
    uint32_t i;

    for (i = 0; i < 1000U; ++i)
        sink ^= memfs_committed_bytes(fs);

    QueryPerformanceCounter(&start);
    for (i = 0; i < BENCH_QUERY_COUNT; ++i)
        sink ^= memfs_committed_bytes(fs);
    QueryPerformanceCounter(&end);

    *out_ns = ns_per_op(seconds_between(start, end, frequency),
                        BENCH_QUERY_COUNT);
    if (sink == UINT64_MAX)
        fprintf(stderr, "sink=%llu\n", (unsigned long long)sink);
    return 0;
}

static int bench_allowance_query(Memfs* fs,
                                 LARGE_INTEGER frequency,
                                 double* out_ns) {
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    volatile uint64_t sink = 0;
    uint32_t i;

    for (i = 0; i < 100U; ++i)
        sink ^= memfs_auto_allowance_bytes(fs);

    QueryPerformanceCounter(&start);
    for (i = 0; i < BENCH_QUERY_COUNT; ++i)
        sink ^= memfs_auto_allowance_bytes(fs);
    QueryPerformanceCounter(&end);

    *out_ns = ns_per_op(seconds_between(start, end, frequency),
                        BENCH_QUERY_COUNT);
    if (sink == UINT64_MAX)
        fprintf(stderr, "sink=%llu\n", (unsigned long long)sink);
    return 0;
}

static int bench_growth(bool auto_capacity,
                        LARGE_INTEGER frequency,
                        double* out_ns) {
    Memfs* fs = NULL;
    MemfsNode* node = NULL;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint32_t i;
    int rc = 1;

    if (create_fs(auto_capacity, &fs) != 0)
        goto cleanup;

    if (memfs_node_create(fs, fs->root, L"growth.bin", false,
                          FILE_ATTRIBUTE_NORMAL, NULL, 0,
                          &node) != MEMFS_OK) {
        goto cleanup;
    }

    for (i = 1; i <= 100U; ++i) {
        if (memfs_node_set_file_size(node, i) != MEMFS_OK)
            goto cleanup;
    }

    QueryPerformanceCounter(&start);
    for (i = 101U; i <= BENCH_GROW_COUNT + 100U; ++i) {
        if (memfs_node_set_file_size(node, i) != MEMFS_OK)
            goto cleanup;
    }
    QueryPerformanceCounter(&end);

    *out_ns = ns_per_op(seconds_between(start, end, frequency),
                        BENCH_GROW_COUNT);
    rc = 0;

cleanup:
    if (node)
        memfs_node_close(node);
    if (fs)
        memfs_destroy(fs);
    return rc;
}

int main(void) {
    Memfs* fixed = NULL;
    Memfs* auto_fs = NULL;
    LARGE_INTEGER frequency;
    double committed_ns = 0.0;
    double allowance_ns = 0.0;
    double fixed_growth_ns = 0.0;
    double auto_growth_ns = 0.0;
    MemfsAllocatorStats stats;
    int rc = 1;

    if (!QueryPerformanceFrequency(&frequency)) {
        fprintf(stderr, "QueryPerformanceFrequency failed\n");
        return 2;
    }

    if (create_fs(false, &fixed) != 0 ||
        create_fs(true, &auto_fs) != 0) {
        fprintf(stderr, "memfs_create_ex failed\n");
        goto cleanup;
    }

    if (bench_committed_query(auto_fs, frequency, &committed_ns) != 0 ||
        bench_allowance_query(auto_fs, frequency, &allowance_ns) != 0 ||
        bench_growth(false, frequency, &fixed_growth_ns) != 0 ||
        bench_growth(true, frequency, &auto_growth_ns) != 0) {
        fprintf(stderr, "capacity benchmark failed\n");
        goto cleanup;
    }

    memfs_allocator_get_stats(&auto_fs->allocator, &stats);

    printf("memfs_capacity_bench\n");
    printf("query_count=%u grow_count=%u\n",
           BENCH_QUERY_COUNT, BENCH_GROW_COUNT);
    printf("committed_query_ns=%.1f\n", committed_ns);
    printf("auto_allowance_query_ns=%.1f\n", allowance_ns);
    printf("fixed_growth_ns=%.1f\n", fixed_growth_ns);
    printf("auto_growth_ns=%.1f\n", auto_growth_ns);
    printf("auto_vs_fixed=%.2fx\n",
           fixed_growth_ns > 0.0
               ? auto_growth_ns / fixed_growth_ns
               : 0.0);
    printf("committed_bytes=%llu stats_committed_bytes=%llu\n",
           (unsigned long long)memfs_committed_bytes(auto_fs),
           (unsigned long long)stats.committed_bytes);

    rc = 0;

cleanup:
    if (auto_fs)
        memfs_destroy(auto_fs);
    if (fixed)
        memfs_destroy(fixed);
    return rc;
}
