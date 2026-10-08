#include <Windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zstd.h>

#define DATA_BYTES (16U * 1024U * 1024U)
#define LOGICAL_PAGE_BYTES 4096U
#define REWRITE_OPS 4000U
#define CONCURRENCY_THREADS 8U
#define CONCURRENCY_BYTES (256U * 1024U * 1024U)

typedef enum BenchPattern {
    BENCH_PATTERN_ZERO = 0,
    BENCH_PATTERN_CROSS_PAGE = 1,
    BENCH_PATTERN_RANDOM = 2,
} BenchPattern;

typedef struct EncodedSet {
    size_t unit_bytes;
    size_t unit_count;
    size_t stride;
    uint8_t* storage;
    uint32_t* sizes;
    uint8_t* compressed;
    uint64_t stored_bytes;
} EncodedSet;

typedef struct WorkerCtx {
    HANDLE start_event;
    const uint8_t* data;
    size_t data_bytes;
    size_t unit_bytes;
    uint64_t bytes_to_process;
    volatile LONG failed;
} WorkerCtx;

static uint64_t rng_next(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void fill_random(uint8_t* dst, size_t bytes, uint64_t* state) {
    size_t i = 0;
    while (i + sizeof(uint64_t) <= bytes) {
        uint64_t value = rng_next(state);
        memcpy(dst + i, &value, sizeof(value));
        i += sizeof(value);
    }
    while (i < bytes) {
        dst[i++] = (uint8_t)rng_next(state);
    }
}

static const char* pattern_name(BenchPattern pattern) {
    switch (pattern) {
    case BENCH_PATTERN_ZERO:
        return "zero";
    case BENCH_PATTERN_CROSS_PAGE:
        return "cross_page";
    case BENCH_PATTERN_RANDOM:
        return "random";
    default:
        return "unknown";
    }
}

static void make_dataset(uint8_t* data, size_t bytes, BenchPattern pattern) {
    uint64_t rng = 0x9e3779b97f4a7c15ULL;
    size_t offset;

    if (pattern == BENCH_PATTERN_ZERO) {
        memset(data, 0, bytes);
        return;
    }

    if (pattern == BENCH_PATTERN_RANDOM) {
        fill_random(data, bytes, &rng);
        return;
    }

    /*
     * Every 64 KiB region contains sixteen near-identical 4 KiB pages.
     * Each base page is itself pseudo-random and therefore does not compress
     * well in isolation. Larger compression units can exploit the redundancy
     * across logical sparse pages without changing the 4 KiB page granularity.
     */
    for (offset = 0; offset < bytes; offset += 64U * 1024U) {
        uint8_t base[LOGICAL_PAGE_BYTES];
        uint32_t page;
        size_t remaining = bytes - offset;

        fill_random(base, sizeof(base), &rng);
        for (page = 0; page < 16U; ++page) {
            size_t page_offset = offset + (size_t)page * LOGICAL_PAGE_BYTES;
            size_t copy_bytes;
            if (page_offset >= bytes)
                break;
            copy_bytes = bytes - page_offset;
            if (copy_bytes > sizeof(base))
                copy_bytes = sizeof(base);
            memcpy(data + page_offset, base, copy_bytes);
            if (copy_bytes >= 16U) {
                uint64_t marker = ((uint64_t)(offset / (64U * 1024U)) << 8) | page;
                memcpy(data + page_offset, &marker, sizeof(marker));
                memcpy(data + page_offset + 8U, &marker, sizeof(marker));
            }
        }
        (void)remaining;
    }
}

static double seconds_between(LARGE_INTEGER start,
                              LARGE_INTEGER end,
                              LARGE_INTEGER frequency) {
    return (double)(end.QuadPart - start.QuadPart) /
           (double)frequency.QuadPart;
}

static void encoded_set_destroy(EncodedSet* set) {
    if (set == NULL)
        return;
    free(set->storage);
    free(set->sizes);
    free(set->compressed);
    memset(set, 0, sizeof(*set));
}

static int encode_dataset(const uint8_t* data,
                          size_t data_bytes,
                          size_t unit_bytes,
                          int level,
                          EncodedSet* out,
                          double* elapsed_seconds) {
    ZSTD_CCtx* cctx = NULL;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    size_t count;
    size_t stride;
    size_t i;

    memset(out, 0, sizeof(*out));
    count = data_bytes / unit_bytes;
    stride = ZSTD_compressBound(unit_bytes);

    out->unit_bytes = unit_bytes;
    out->unit_count = count;
    out->stride = stride;
    out->storage = (uint8_t*)malloc(count * stride);
    out->sizes = (uint32_t*)calloc(count, sizeof(*out->sizes));
    out->compressed = (uint8_t*)calloc(count, sizeof(*out->compressed));
    if (out->storage == NULL || out->sizes == NULL || out->compressed == NULL)
        goto fail;

    cctx = ZSTD_createCCtx();
    if (cctx == NULL)
        goto fail;
    if (!QueryPerformanceFrequency(&frequency))
        goto fail;

    QueryPerformanceCounter(&start);
    for (i = 0; i < count; ++i) {
        const uint8_t* src = data + i * unit_bytes;
        uint8_t* dst = out->storage + i * stride;
        size_t compressed = ZSTD_compressCCtx(
            cctx, dst, stride, src, unit_bytes, level);

        if (ZSTD_isError(compressed))
            goto fail;
        if (compressed < unit_bytes) {
            out->sizes[i] = (uint32_t)compressed;
            out->compressed[i] = 1;
            out->stored_bytes += compressed;
        } else {
            memcpy(dst, src, unit_bytes);
            out->sizes[i] = (uint32_t)unit_bytes;
            out->compressed[i] = 0;
            out->stored_bytes += unit_bytes;
        }
    }
    QueryPerformanceCounter(&end);

    *elapsed_seconds = seconds_between(start, end, frequency);
    ZSTD_freeCCtx(cctx);
    return 0;

fail:
    if (cctx)
        ZSTD_freeCCtx(cctx);
    encoded_set_destroy(out);
    return 1;
}

static int decode_unit(const EncodedSet* set,
                       size_t index,
                       uint8_t* plain,
                       ZSTD_DCtx* dctx) {
    const uint8_t* src = set->storage + index * set->stride;
    if (!set->compressed[index]) {
        memcpy(plain, src, set->unit_bytes);
        return 0;
    }

    {
        size_t result = ZSTD_decompressDCtx(
            dctx, plain, set->unit_bytes, src, set->sizes[index]);
        if (ZSTD_isError(result) || result != set->unit_bytes)
            return 1;
    }
    return 0;
}

static int bench_rewrite(const EncodedSet* set,
                         int level,
                         double* ns_per_op,
                         double* encoded_write_amp) {
    uint8_t* plain = NULL;
    uint8_t* output = NULL;
    uint8_t rewrite_pages[16][LOGICAL_PAGE_BYTES];
    ZSTD_CCtx* cctx = NULL;
    ZSTD_DCtx* dctx = NULL;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t rng = 0x123456789abcdef0ULL;
    uint64_t total_encoded = 0;
    uint32_t pages_per_unit;
    uint32_t op;
    int rc = 1;

    pages_per_unit = (uint32_t)(set->unit_bytes / LOGICAL_PAGE_BYTES);
    plain = (uint8_t*)malloc(set->unit_bytes);
    output = (uint8_t*)malloc(ZSTD_compressBound(set->unit_bytes));
    cctx = ZSTD_createCCtx();
    dctx = ZSTD_createDCtx();
    if (plain == NULL || output == NULL || cctx == NULL || dctx == NULL)
        goto cleanup;

    for (op = 0; op < 16U; ++op)
        fill_random(rewrite_pages[op], LOGICAL_PAGE_BYTES, &rng);

    if (!QueryPerformanceFrequency(&frequency))
        goto cleanup;

    QueryPerformanceCounter(&start);
    for (op = 0; op < REWRITE_OPS; ++op) {
        size_t unit_index = (size_t)(rng_next(&rng) % set->unit_count);
        uint32_t page_index = (uint32_t)(rng_next(&rng) % pages_per_unit);
        size_t compressed;

        if (decode_unit(set, unit_index, plain, dctx) != 0)
            goto cleanup;

        memcpy(plain + (size_t)page_index * LOGICAL_PAGE_BYTES,
               rewrite_pages[op & 15U],
               LOGICAL_PAGE_BYTES);

        compressed = ZSTD_compressCCtx(
            cctx, output, ZSTD_compressBound(set->unit_bytes),
            plain, set->unit_bytes, level);
        if (ZSTD_isError(compressed))
            goto cleanup;

        total_encoded += compressed < set->unit_bytes
            ? compressed
            : set->unit_bytes;
    }
    QueryPerformanceCounter(&end);

    *ns_per_op = seconds_between(start, end, frequency) *
                 1000000000.0 / (double)REWRITE_OPS;
    *encoded_write_amp = (double)total_encoded /
                         ((double)REWRITE_OPS * LOGICAL_PAGE_BYTES);
    rc = 0;

cleanup:
    ZSTD_freeCCtx(cctx);
    ZSTD_freeDCtx(dctx);
    free(output);
    free(plain);
    return rc;
}

static DWORD WINAPI compression_worker(LPVOID parameter) {
    WorkerCtx* worker = (WorkerCtx*)parameter;
    ZSTD_CCtx* cctx = NULL;
    uint8_t* output = NULL;
    size_t bound;
    uint64_t done = 0;
    size_t index = 0;

    cctx = ZSTD_createCCtx();
    bound = ZSTD_compressBound(worker->unit_bytes);
    output = (uint8_t*)malloc(bound);
    if (cctx == NULL || output == NULL) {
        InterlockedExchange(&worker->failed, 1);
        goto cleanup;
    }

    WaitForSingleObject(worker->start_event, INFINITE);
    while (done < worker->bytes_to_process) {
        const uint8_t* src = worker->data + index * worker->unit_bytes;
        size_t result = ZSTD_compressCCtx(
            cctx, output, bound, src, worker->unit_bytes, 1);
        if (ZSTD_isError(result)) {
            InterlockedExchange(&worker->failed, 1);
            break;
        }
        done += worker->unit_bytes;
        index++;
        if ((index + 1U) * worker->unit_bytes > worker->data_bytes)
            index = 0;
    }

cleanup:
    free(output);
    ZSTD_freeCCtx(cctx);
    return 0;
}

static int bench_concurrency(const uint8_t* data,
                             size_t data_bytes,
                             size_t unit_bytes,
                             double* mb_per_second) {
    HANDLE threads[CONCURRENCY_THREADS] = {0};
    WorkerCtx workers[CONCURRENCY_THREADS];
    HANDLE start_event = NULL;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    uint64_t per_thread_bytes;
    uint32_t i;
    int rc = 1;

    start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (start_event == NULL || !QueryPerformanceFrequency(&frequency))
        goto cleanup;

    per_thread_bytes = CONCURRENCY_BYTES / CONCURRENCY_THREADS;
    per_thread_bytes -= per_thread_bytes % unit_bytes;

    memset(workers, 0, sizeof(workers));
    for (i = 0; i < CONCURRENCY_THREADS; ++i) {
        workers[i].start_event = start_event;
        workers[i].data = data;
        workers[i].data_bytes = data_bytes;
        workers[i].unit_bytes = unit_bytes;
        workers[i].bytes_to_process = per_thread_bytes;
        threads[i] = CreateThread(
            NULL, 0, compression_worker, &workers[i], 0, NULL);
        if (threads[i] == NULL)
            goto cleanup;
    }

    QueryPerformanceCounter(&start);
    SetEvent(start_event);
    if (WaitForMultipleObjects(
            CONCURRENCY_THREADS, threads, TRUE, INFINITE) != WAIT_OBJECT_0) {
        goto cleanup;
    }
    QueryPerformanceCounter(&end);

    for (i = 0; i < CONCURRENCY_THREADS; ++i) {
        if (InterlockedCompareExchange(&workers[i].failed, 0, 0) != 0)
            goto cleanup;
    }

    {
        double seconds = seconds_between(start, end, frequency);
        double mib = ((double)per_thread_bytes * CONCURRENCY_THREADS) /
                     (1024.0 * 1024.0);
        *mb_per_second = seconds > 0.0 ? mib / seconds : 0.0;
    }
    rc = 0;

cleanup:
    if (start_event)
        SetEvent(start_event);
    for (i = 0; i < CONCURRENCY_THREADS; ++i) {
        if (threads[i]) {
            WaitForSingleObject(threads[i], INFINITE);
            CloseHandle(threads[i]);
        }
    }
    if (start_event)
        CloseHandle(start_event);
    return rc;
}

static int run_case(const uint8_t* data,
                    BenchPattern pattern,
                    size_t unit_bytes,
                    int level) {
    EncodedSet set;
    double encode_seconds = 0.0;
    double rewrite_ns = 0.0;
    double encoded_write_amp = 0.0;
    double concurrency_mib_s = 0.0;
    double ratio;
    double encode_mib_s;

    if (encode_dataset(
            data, DATA_BYTES, unit_bytes, level, &set, &encode_seconds) != 0) {
        fprintf(stderr, "encode failed pattern=%s unit=%zu\n",
                pattern_name(pattern), unit_bytes);
        return 1;
    }

    if (bench_rewrite(
            &set, level, &rewrite_ns, &encoded_write_amp) != 0) {
        fprintf(stderr, "rewrite failed pattern=%s unit=%zu\n",
                pattern_name(pattern), unit_bytes);
        encoded_set_destroy(&set);
        return 1;
    }

    if (bench_concurrency(
            data, DATA_BYTES, unit_bytes, &concurrency_mib_s) != 0) {
        fprintf(stderr, "concurrency failed pattern=%s unit=%zu\n",
                pattern_name(pattern), unit_bytes);
        encoded_set_destroy(&set);
        return 1;
    }

    ratio = (double)set.stored_bytes / (double)DATA_BYTES;
    encode_mib_s = encode_seconds > 0.0
        ? ((double)DATA_BYTES / (1024.0 * 1024.0)) / encode_seconds
        : 0.0;

    printf(
        "pattern=%s unit_kib=%zu stored_bytes=%llu ratio=%.6f "
        "encode_mib_s=%.1f rewrite_ns=%.1f raw_write_amp=%.1fx "
        "encoded_write_amp=%.3fx concurrency_%uthread_mib_s=%.1f\n",
        pattern_name(pattern),
        unit_bytes / 1024U,
        (unsigned long long)set.stored_bytes,
        ratio,
        encode_mib_s,
        rewrite_ns,
        (double)unit_bytes / LOGICAL_PAGE_BYTES,
        encoded_write_amp,
        CONCURRENCY_THREADS,
        concurrency_mib_s);

    encoded_set_destroy(&set);
    return 0;
}

int main(void) {
    static const size_t units[] = {
        4U * 1024U,
        16U * 1024U,
        64U * 1024U,
    };
    static const BenchPattern patterns[] = {
        BENCH_PATTERN_ZERO,
        BENCH_PATTERN_CROSS_PAGE,
        BENCH_PATTERN_RANDOM,
    };
    uint8_t* data = NULL;
    size_t p;
    size_t u;
    int rc = 1;

    data = (uint8_t*)malloc(DATA_BYTES);
    if (data == NULL) {
        fprintf(stderr, "allocation failed\n");
        return 2;
    }

    printf("memfs_compression_unit_bench data_mib=%u logical_page_kib=%u "
           "rewrite_ops=%u threads=%u zstd_level=1\n",
           DATA_BYTES / (1024U * 1024U),
           LOGICAL_PAGE_BYTES / 1024U,
           REWRITE_OPS,
           CONCURRENCY_THREADS);

    for (p = 0; p < _countof(patterns); ++p) {
        make_dataset(data, DATA_BYTES, patterns[p]);
        for (u = 0; u < _countof(units); ++u) {
            if (run_case(data, patterns[p], units[u], 1) != 0)
                goto cleanup;
        }
    }

    rc = 0;

cleanup:
    free(data);
    return rc;
}
