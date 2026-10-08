#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <psapi.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memfs_alloc.h"

#define AREA_BENCH_CACHE_MAX_BYTES (256U * 1024U)
#define AREA_BENCH_MAX_BYTES (32U * 1024U * 1024U)
#define AREA_BENCH_MAX_TOTAL_BYTES (1024ULL * 1024ULL * 1024ULL)
#define AREA_BENCH_WARMUP_COUNT 4U

static bool parse_unsigned(const char* text, uint64_t* value) {
    uint64_t result = 0;

    if (text == NULL || *text == '\0')
        return false;
    while (*text != '\0') {
        uint32_t digit;

        if (*text < '0' || *text > '9')
            return false;
        digit = (uint32_t)(*text++ - '0');
        if (result > (UINT64_MAX - digit) / 10U)
            return false;
        result = result * 10U + digit;
    }
    *value = result;
    return true;
}

static bool allocate_touch_free(MemfsAllocator* allocator,
                                size_t bytes,
                                bool full_touch,
                                uint64_t* checksum) {
    uint8_t* data = memfs_allocator_alloc(allocator, bytes);
    uint64_t sum = 0;

    if (data == NULL) {
        fputs("area allocation failed\n", stderr);
        return false;
    }
    if (full_touch) {
        for (size_t i = 0; i < bytes; ++i)
            sum += data[i];
    } else {
        sum = (uint64_t)data[0] + data[bytes - 1U];
    }
    /* Dirty the pages so a subsequent new mapping must expose fresh zeros. */
    data[0] = 0xA5U;
    data[bytes - 1U] = 0x5AU;
    memfs_allocator_free(allocator, data, bytes);
    *checksum += sum;
    return true;
}

static void usage(const char* program) {
    fprintf(stderr,
            "Usage: %s [--size BYTES] [--count COUNT] [--touch ends|full]\n"
            "size: 262145..33554432; count: 1..4096; "
            "measured bytes <= 1 GiB\n", program);
}

int main(int argc, char** argv) {
    uint64_t bytes_value = 1024U * 1024U + 17U;
    uint64_t count_value = 128U;
    bool full_touch = false;
    MemfsAllocator allocator = {0};
    MemfsAllocatorStats baseline;
    MemfsAllocatorStats after;
    PROCESS_MEMORY_COUNTERS before_process;
    PROCESS_MEMORY_COUNTERS after_process;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t checksum = 0;
    DWORD faults;
    double seconds;
    int result = 1;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 && argc == 2) {
            usage(argv[0]);
            return 0;
        }
        if (i + 1 >= argc) {
            usage(argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--size") == 0) {
            if (!parse_unsigned(argv[++i], &bytes_value))
                return 2;
        } else if (strcmp(argv[i], "--count") == 0) {
            if (!parse_unsigned(argv[++i], &count_value))
                return 2;
        } else if (strcmp(argv[i], "--touch") == 0) {
            ++i;
            if (strcmp(argv[i], "ends") == 0)
                full_touch = false;
            else if (strcmp(argv[i], "full") == 0)
                full_touch = true;
            else
                return 2;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (bytes_value <= AREA_BENCH_CACHE_MAX_BYTES ||
        bytes_value > AREA_BENCH_MAX_BYTES ||
        bytes_value > SIZE_MAX || count_value == 0U || count_value > 4096U ||
        bytes_value > AREA_BENCH_MAX_TOTAL_BYTES / count_value) {
        usage(argv[0]);
        return 2;
    }

    if (!memfs_allocator_init(&allocator, 64U, 64U, 64U)) {
        fputs("allocator initialization failed\n", stderr);
        return 1;
    }
    memfs_allocator_get_stats(&allocator, &baseline);
    for (uint32_t i = 0; i < AREA_BENCH_WARMUP_COUNT; ++i) {
        if (!allocate_touch_free(&allocator, (size_t)bytes_value,
                                 full_touch, &checksum))
            goto cleanup;
    }
    if (checksum != 0U) {
        fputs("warmup returned nonzero newly allocated memory\n", stderr);
        goto cleanup;
    }

    memset(&before_process, 0, sizeof(before_process));
    memset(&after_process, 0, sizeof(after_process));
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        !GetProcessMemoryInfo(GetCurrentProcess(), &before_process,
                              sizeof(before_process)) ||
        !QueryPerformanceCounter(&start)) {
        fputs("performance sampling failed\n", stderr);
        goto cleanup;
    }
    for (uint64_t i = 0; i < count_value; ++i) {
        if (!allocate_touch_free(&allocator, (size_t)bytes_value,
                                 full_touch, &checksum))
            goto cleanup;
    }
    if (!QueryPerformanceCounter(&end) || end.QuadPart < start.QuadPart ||
        !GetProcessMemoryInfo(GetCurrentProcess(), &after_process,
                              sizeof(after_process))) {
        fputs("performance sampling failed\n", stderr);
        goto cleanup;
    }
    memfs_allocator_get_stats(&allocator, &after);
    if (checksum != 0U || after.area_cached_count != 0U ||
        after.live_objects != baseline.live_objects ||
        after.live_bytes != baseline.live_bytes ||
        after.reserved_bytes != baseline.reserved_bytes ||
        after.committed_bytes != baseline.committed_bytes) {
        fputs("zero payload or quiescent allocator invariant failed\n", stderr);
        goto cleanup;
    }

    /* Subtract QPC counters before conversion; never multiply absolute ticks. */
    seconds = (double)(end.QuadPart - start.QuadPart) /
              (double)frequency.QuadPart;
    faults = after_process.PageFaultCount - before_process.PageFaultCount;
    printf("size=%llu count=%llu touch=%s total_ms=%.3f avg_us=%.3f "
           "page_faults=%lu faults_per_op=%.3f checksum=%llu "
           "area_cached_count=%u committed_bytes=%llu\n",
           (unsigned long long)bytes_value, (unsigned long long)count_value,
           full_touch ? "full" : "ends", seconds * 1000.0,
           seconds * 1000000.0 / (double)count_value, (unsigned long)faults,
           (double)faults / (double)count_value,
           (unsigned long long)checksum, after.area_cached_count,
           (unsigned long long)after.committed_bytes);
    result = 0;

cleanup:
    memfs_allocator_destroy(&allocator);
    return result;
}
