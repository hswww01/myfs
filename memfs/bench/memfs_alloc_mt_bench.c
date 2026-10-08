#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memfs_alloc.h"

#define ALLOC_BENCH_MAX_THREADS 16
#define ALLOC_BENCH_SLOTS 64

typedef struct AllocBenchThread {
    MemfsAllocator* allocator;
    HANDLE start_event;
    volatile LONG* stop_flag;
    size_t size;
    uint32_t iterations;
    bool uninitialized;
    uint64_t operations;
    uint64_t errors;
    void* slots[ALLOC_BENCH_SLOTS];
} AllocBenchThread;

static DWORD WINAPI alloc_bench_worker(LPVOID parameter) {
    AllocBenchThread* thread = (AllocBenchThread*)parameter;
    uint32_t i;

    WaitForSingleObject(thread->start_event, INFINITE);

    for (i = 0;
         i < thread->iterations &&
         InterlockedCompareExchange(thread->stop_flag, 0, 0) == 0;
         ++i) {
        uint32_t slot = i % ALLOC_BENCH_SLOTS;
        void* next = thread->uninitialized
            ? memfs_allocator_alloc_uninit(thread->allocator, thread->size)
            : memfs_allocator_alloc(thread->allocator, thread->size);

        if (next == NULL) {
            thread->errors++;
            continue;
        }

        ((volatile uint8_t*)next)[0] = (uint8_t)(i + 1U);
        thread->operations++;

        if (thread->slots[slot] != NULL) {
            memfs_allocator_free(
                thread->allocator, thread->slots[slot], thread->size);
            thread->operations++;
        }
        thread->slots[slot] = next;
    }

    for (i = 0; i < ALLOC_BENCH_SLOTS; ++i) {
        if (thread->slots[i] != NULL) {
            memfs_allocator_free(
                thread->allocator, thread->slots[i], thread->size);
            thread->slots[i] = NULL;
            thread->operations++;
        }
    }

    return 0;
}

static int run_case(size_t size, int thread_count, uint32_t iterations, bool uninitialized) {
    MemfsAllocator allocator;
    MemfsAllocatorStats baseline;
    MemfsAllocatorStats stats;
    MemfsAllocatorStats after_scavenge;
    AllocBenchThread contexts[ALLOC_BENCH_MAX_THREADS];
    HANDLE threads[ALLOC_BENCH_MAX_THREADS];
    HANDLE start_event = NULL;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t operations = 0;
    uint64_t errors = 0;
    double seconds;
    double ops_per_second;
    int started = 0;
    volatile LONG stop_flag = 0;
    int result = 1;
    int i;

    memset(&allocator, 0, sizeof(allocator));
    memset(&stats, 0, sizeof(stats));
    memset(contexts, 0, sizeof(contexts));
    memset(threads, 0, sizeof(threads));

    if (!memfs_allocator_init(&allocator, 64U, 64U, 64U)) {
        fprintf(stderr, "allocator init failed\n");
        return 1;
    }

    memfs_allocator_get_stats(&allocator, &baseline);

    start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (start_event == NULL)
        goto cleanup;

    for (i = 0; i < thread_count; ++i) {
        contexts[i].allocator = &allocator;
        contexts[i].start_event = start_event;
        contexts[i].stop_flag = &stop_flag;
        contexts[i].size = size;
        contexts[i].iterations = iterations;
        contexts[i].uninitialized = uninitialized;
        threads[i] = CreateThread(
            NULL, 0, alloc_bench_worker, &contexts[i], 0, NULL);
        if (threads[i] == NULL)
            goto cleanup;
        started++;
    }

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    SetEvent(start_event);

    if (WaitForMultipleObjects(
            (DWORD)started, threads, TRUE, 120000) != WAIT_OBJECT_0) {
        fprintf(stderr, "allocator benchmark timeout size=%llu threads=%d\n",
                (unsigned long long)size, thread_count);
        goto cleanup;
    }

    QueryPerformanceCounter(&end);

    for (i = 0; i < started; ++i) {
        operations += contexts[i].operations;
        errors += contexts[i].errors;
    }

    seconds = (double)(end.QuadPart - start.QuadPart)
        / (double)frequency.QuadPart;
    ops_per_second = seconds > 0.0 ? (double)operations / seconds : 0.0;

    memfs_allocator_get_stats(&allocator, &stats);

    printf(
        "mode=%-6s size=%-6llu threads=%-2d iterations/thread=%-7u "
        "ops=%-10llu seconds=%8.4f ops/s=%12.0f "
        "errors=%llu post_slabs=%u post_areas=%u post_cached=%u "
        "post_cached_bytes=%llu post_reserved=%llu",
        uninitialized ? "uninit" : "zero",
        (unsigned long long)size,
        thread_count,
        iterations,
        (unsigned long long)operations,
        seconds,
        ops_per_second,
        (unsigned long long)errors,
        stats.slab_count,
        stats.dedicated_count,
        stats.area_cached_count,
        (unsigned long long)stats.area_cached_bytes,
        (unsigned long long)stats.reserved_bytes);

    if (errors != 0 ||
        stats.live_objects != baseline.live_objects ||
        stats.live_bytes != baseline.live_bytes ||
        stats.slab_count != baseline.slab_count ||
        stats.dedicated_count != baseline.dedicated_count) {
        fprintf(stderr,
                "\nallocator benchmark invariant failed size=%llu threads=%d\n",
                (unsigned long long)size, thread_count);
        goto cleanup;
    }

    {
        uint64_t scavenged = memfs_allocator_scavenge(&allocator);
        memfs_allocator_get_stats(&allocator, &after_scavenge);
        printf(" scavenged=%llu\n", (unsigned long long)scavenged);

        if (after_scavenge.area_cached_count != 0U ||
            after_scavenge.area_cached_bytes != 0U ||
            after_scavenge.live_objects != baseline.live_objects ||
            after_scavenge.live_bytes != baseline.live_bytes ||
            after_scavenge.reserved_bytes != baseline.reserved_bytes ||
            after_scavenge.committed_bytes != baseline.committed_bytes) {
            fprintf(stderr,
                    "allocator benchmark scavenge mismatch size=%llu threads=%d\n",
                    (unsigned long long)size, thread_count);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    InterlockedExchange(&stop_flag, 1);
    if (start_event != NULL)
        SetEvent(start_event);

    if (started > 0) {
        DWORD wait = WaitForMultipleObjects(
            (DWORD)started, threads, TRUE, 5000);
        if (wait != WAIT_OBJECT_0) {
            fprintf(stderr,
                    "allocator benchmark workers failed to stop safely; "
                    "terminating process before shared-state teardown\n");
            fflush(stderr);
            ExitProcess(2);
        }
    }

    for (i = 0; i < started; ++i) {
        if (threads[i] != NULL)
            CloseHandle(threads[i]);
    }

    if (start_event != NULL)
        CloseHandle(start_event);

    memfs_allocator_destroy(&allocator);
    return result;
}

int main(void) {
    static const int thread_counts[] = {1, 2, 4, 8, 16};
    static const struct {
        size_t size;
        uint32_t iterations;
    } workloads[] = {
        {64U, 500000U},
        {512U, 400000U},
        {4096U, 200000U},
        {16384U, 20000U},        {65536U, 10000U},
    };
    size_t w;
    size_t t;
    int mode;

    printf("=== memfs allocator shared-pool contention benchmark ===\n");
    printf("one logical size-class pool is shared by all worker threads\n");

    for (mode = 0; mode < 2; ++mode) {
        printf("\n[%s allocations]\n", mode ? "uninitialized" : "zeroed");
        for (w = 0; w < sizeof(workloads) / sizeof(workloads[0]); ++w) {
            printf("\n[allocation size %llu]\n",
                   (unsigned long long)workloads[w].size);
            for (t = 0; t < sizeof(thread_counts) / sizeof(thread_counts[0]); ++t) {
                if (run_case(
                        workloads[w].size,
                        thread_counts[t],
                        workloads[w].iterations,
                        mode != 0) != 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}
