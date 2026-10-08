#include <Windows.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zstd.h>

#define LOGICAL_PAGE_BYTES 4096U
#define EXTENT_PAGES 16U
#define EXTENT_BYTES (LOGICAL_PAGE_BYTES * EXTENT_PAGES)
#define DATA_BYTES (16U * 1024U * 1024U)
#define EXTENT_COUNT (DATA_BYTES / EXTENT_BYTES)
#define RANDOM_REWRITE_OPS 4000U
#define MIXED_OPS 4000U
#define EXTENT_PROBE_MASK 15U
#define EXTENT_SCORE_SKIP 2
#define MERGE_MIN_SAVING_BYTES LOGICAL_PAGE_BYTES

typedef enum BenchPattern {
    BENCH_PATTERN_CROSS_PAGE = 0,
    BENCH_PATTERN_RANDOM = 1,
} BenchPattern;

typedef enum Policy {
    POLICY_4K = 0,
    POLICY_64K = 1,
    POLICY_ADAPTIVE = 2,
} Policy;

typedef struct Workspace {
    size_t page_stride;
    size_t extent_stride;
    uint8_t* page_storage;
    uint32_t* page_sizes;
    uint8_t* page_compressed;
    uint8_t* extent_storage;
    uint32_t* extent_sizes;
    uint8_t* extent_compressed;
    uint8_t* merged;
    uint8_t* hot;
    uint64_t stored_bytes;
    uint64_t encoded_input_bytes;
    uint64_t merge_count;
    uint64_t split_count;
    uint64_t extent_probe_count;
    int extent_score;
} Workspace;

typedef struct Metrics {
    uint64_t stored_bytes;
    uint64_t encoded_input_bytes;
    uint64_t logical_write_bytes;
    uint64_t merge_count;
    uint64_t split_count;
    uint64_t extent_probe_count;
    uint32_t merged_extents;
    double elapsed_ms;
    double ns_per_op;
} Metrics;

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
    while (i < bytes)
        dst[i++] = (uint8_t)rng_next(state);
}

static void make_dataset(uint8_t* data, BenchPattern pattern) {
    uint64_t rng = 0x9e3779b97f4a7c15ULL;
    size_t offset;

    if (pattern == BENCH_PATTERN_RANDOM) {
        fill_random(data, DATA_BYTES, &rng);
        return;
    }

    for (offset = 0; offset < DATA_BYTES; offset += EXTENT_BYTES) {
        uint8_t base[LOGICAL_PAGE_BYTES];
        uint32_t page;

        fill_random(base, sizeof(base), &rng);
        for (page = 0; page < EXTENT_PAGES; ++page) {
            uint8_t* dst = data + offset + (size_t)page * LOGICAL_PAGE_BYTES;
            uint64_t marker = ((uint64_t)(offset / EXTENT_BYTES) << 8) | page;
            memcpy(dst, base, sizeof(base));
            memcpy(dst, &marker, sizeof(marker));
            memcpy(dst + sizeof(marker), &marker, sizeof(marker));
        }
    }
}

static const char* pattern_name(BenchPattern pattern) {
    return pattern == BENCH_PATTERN_CROSS_PAGE ? "cross_page" : "random";
}

static const char* policy_name(Policy policy) {
    switch (policy) {
    case POLICY_4K: return "4k";
    case POLICY_64K: return "64k";
    case POLICY_ADAPTIVE: return "adaptive";
    default: return "?";
    }
}

static double milliseconds_between(
    LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER frequency) {
    return 1000.0 * (double)(end.QuadPart - start.QuadPart) /
           (double)frequency.QuadPart;
}

static int workspace_init(Workspace* w) {
    size_t page_count = DATA_BYTES / LOGICAL_PAGE_BYTES;

    memset(w, 0, sizeof(*w));
    w->page_stride = ZSTD_compressBound(LOGICAL_PAGE_BYTES);
    w->extent_stride = ZSTD_compressBound(EXTENT_BYTES);
    w->page_storage = (uint8_t*)malloc(page_count * w->page_stride);
    w->page_sizes = (uint32_t*)calloc(page_count, sizeof(*w->page_sizes));
    w->page_compressed = (uint8_t*)calloc(page_count, 1);
    w->extent_storage = (uint8_t*)malloc(EXTENT_COUNT * w->extent_stride);
    w->extent_sizes = (uint32_t*)calloc(EXTENT_COUNT, sizeof(*w->extent_sizes));
    w->extent_compressed = (uint8_t*)calloc(EXTENT_COUNT, 1);
    w->merged = (uint8_t*)calloc(EXTENT_COUNT, 1);
    w->hot = (uint8_t*)calloc(EXTENT_COUNT, 1);
    if (!w->page_storage || !w->page_sizes || !w->page_compressed ||
        !w->extent_storage || !w->extent_sizes ||
        !w->extent_compressed || !w->merged || !w->hot)
        return 1;
    return 0;
}

static void workspace_destroy(Workspace* w) {
    free(w->page_storage);
    free(w->page_sizes);
    free(w->page_compressed);
    free(w->extent_storage);
    free(w->extent_sizes);
    free(w->extent_compressed);
    free(w->merged);
    free(w->hot);
    memset(w, 0, sizeof(*w));
}

static size_t page_flat_index(uint32_t extent, uint32_t page) {
    return (size_t)extent * EXTENT_PAGES + page;
}

static uint8_t* page_slot(Workspace* w, uint32_t extent, uint32_t page) {
    return w->page_storage +
           page_flat_index(extent, page) * w->page_stride;
}

static uint8_t* extent_slot(Workspace* w, uint32_t extent) {
    return w->extent_storage + (size_t)extent * w->extent_stride;
}

static int encode_block(
    ZSTD_CCtx* cctx, const uint8_t* plain, size_t plain_bytes,
    uint8_t* dst, size_t dst_capacity,
    uint32_t* stored_size, uint8_t* compressed,
    uint64_t* encoded_input_bytes) {
    size_t result = ZSTD_compressCCtx(cctx, dst, dst_capacity,
                                      plain, plain_bytes, 1);
    if (ZSTD_isError(result))
        return 1;

    *encoded_input_bytes += plain_bytes;
    if (result < plain_bytes) {
        *stored_size = (uint32_t)result;
        *compressed = 1;
    } else {
        memcpy(dst, plain, plain_bytes);
        *stored_size = (uint32_t)plain_bytes;
        *compressed = 0;
    }
    return 0;
}

static int decode_block(
    ZSTD_DCtx* dctx, const uint8_t* src, uint32_t stored_size,
    uint8_t compressed, uint8_t* plain, size_t plain_bytes) {
    if (!compressed) {
        memcpy(plain, src, plain_bytes);
        return 0;
    }

    {
        size_t result = ZSTD_decompressDCtx(
            dctx, plain, plain_bytes, src, stored_size);
        return ZSTD_isError(result) || result != plain_bytes;
    }
}

static uint64_t extent_page_stored_bytes(
    const Workspace* w, uint32_t extent) {
    uint64_t total = 0;
    uint32_t page;
    for (page = 0; page < EXTENT_PAGES; ++page)
        total += w->page_sizes[page_flat_index(extent, page)];
    return total;
}

static bool adaptive_should_probe(const Workspace* w, uint32_t extent) {
    if (w->extent_score < EXTENT_SCORE_SKIP)
        return true;
    return 0 == (extent & EXTENT_PROBE_MASK);
}

static void adaptive_feedback(Workspace* w, bool useful) {
    if (useful) {
        if (w->extent_score > -8)
            w->extent_score--;
    } else if (w->extent_score < 8) {
        w->extent_score++;
    }
}

static void clear_page_accounting_for_extent(Workspace* w, uint32_t extent) {
    uint32_t page;
    for (page = 0; page < EXTENT_PAGES; ++page) {
        size_t index = page_flat_index(extent, page);
        w->page_sizes[index] = 0;
        w->page_compressed[index] = 0;
    }
}

static int encode_pages_for_extent(
    Workspace* w, uint32_t extent, const uint8_t* plain,
    ZSTD_CCtx* cctx) {
    uint32_t page;

    for (page = 0; page < EXTENT_PAGES; ++page) {
        size_t index = page_flat_index(extent, page);
        uint32_t old_size = w->page_sizes[index];
        uint32_t new_size = 0;
        uint8_t compressed = 0;

        if (encode_block(cctx,
                         plain + (size_t)page * LOGICAL_PAGE_BYTES,
                         LOGICAL_PAGE_BYTES,
                         page_slot(w, extent, page), w->page_stride,
                         &new_size, &compressed,
                         &w->encoded_input_bytes) != 0)
            return 1;

        if (!w->merged[extent]) {
            w->stored_bytes -= old_size;
            w->stored_bytes += new_size;
        }
        w->page_sizes[index] = new_size;
        w->page_compressed[index] = compressed;
    }
    return 0;
}

static int encode_extent_representation(
    Workspace* w, uint32_t extent, const uint8_t* plain,
    ZSTD_CCtx* cctx, uint32_t* stored_size_out, uint8_t* compressed_out) {
    uint32_t size = 0;
    uint8_t compressed = 0;

    if (encode_block(cctx, plain, EXTENT_BYTES,
                     extent_slot(w, extent), w->extent_stride,
                     &size, &compressed,
                     &w->encoded_input_bytes) != 0)
        return 1;

    w->extent_sizes[extent] = size;
    w->extent_compressed[extent] = compressed;
    if (stored_size_out)
        *stored_size_out = size;
    if (compressed_out)
        *compressed_out = compressed;
    return 0;
}

static int adaptive_try_merge(
    Workspace* w, uint32_t extent, const uint8_t* plain,
    ZSTD_CCtx* cctx) {
    uint64_t page_bytes;
    uint32_t extent_size = 0;
    uint8_t extent_compressed = 0;
    bool useful;

    if (w->hot[extent])
        return 0;

    if (!adaptive_should_probe(w, extent))
        return 0;

    w->extent_probe_count++;
    page_bytes = extent_page_stored_bytes(w, extent);
    if (encode_extent_representation(
            w, extent, plain, cctx,
            &extent_size, &extent_compressed) != 0)
        return 1;

    useful = extent_compressed &&
             page_bytes > extent_size &&
             page_bytes - extent_size >= MERGE_MIN_SAVING_BYTES;

    adaptive_feedback(w, useful);
    if (!useful)
        return 0;

    w->stored_bytes -= page_bytes;
    w->stored_bytes += extent_size;
    w->merged[extent] = 1;
    w->merge_count++;
    return 0;
}

static int build_initial(
    Workspace* w, Policy policy, const uint8_t* data,
    Metrics* metrics) {
    ZSTD_CCtx* cctx = NULL;
    LARGE_INTEGER freq, start, end;
    uint32_t extent;

    memset(metrics, 0, sizeof(*metrics));
    cctx = ZSTD_createCCtx();
    if (!cctx || !QueryPerformanceFrequency(&freq))
        goto fail;

    QueryPerformanceCounter(&start);
    for (extent = 0; extent < EXTENT_COUNT; ++extent) {
        const uint8_t* plain = data + (size_t)extent * EXTENT_BYTES;

        if (policy == POLICY_64K) {
            uint32_t size = 0;
            uint8_t compressed = 0;
            if (encode_extent_representation(
                    w, extent, plain, cctx, &size, &compressed) != 0)
                goto fail;
            w->merged[extent] = 1;
            w->stored_bytes += size;
            w->merge_count++;
        } else {
            if (encode_pages_for_extent(w, extent, plain, cctx) != 0)
                goto fail;
            if (policy == POLICY_ADAPTIVE &&
                adaptive_try_merge(w, extent, plain, cctx) != 0)
                goto fail;
        }
    }
    QueryPerformanceCounter(&end);

    metrics->stored_bytes = w->stored_bytes;
    metrics->encoded_input_bytes = w->encoded_input_bytes;
    metrics->logical_write_bytes = DATA_BYTES;
    metrics->merge_count = w->merge_count;
    metrics->extent_probe_count = w->extent_probe_count;
    metrics->elapsed_ms = milliseconds_between(start, end, freq);
    for (extent = 0; extent < EXTENT_COUNT; ++extent)
        metrics->merged_extents += !!w->merged[extent];

    ZSTD_freeCCtx(cctx);
    return 0;

fail:
    ZSTD_freeCCtx(cctx);
    return 1;
}

static int decode_page(
    Workspace* w, uint32_t extent, uint32_t page,
    uint8_t* plain, ZSTD_DCtx* dctx) {
    size_t index = page_flat_index(extent, page);
    return decode_block(dctx,
                        page_slot(w, extent, page),
                        w->page_sizes[index],
                        w->page_compressed[index],
                        plain, LOGICAL_PAGE_BYTES);
}

static int decode_extent(
    Workspace* w, uint32_t extent,
    uint8_t* plain, ZSTD_DCtx* dctx) {
    uint32_t page;

    if (w->merged[extent]) {
        return decode_block(dctx,
                            extent_slot(w, extent),
                            w->extent_sizes[extent],
                            w->extent_compressed[extent],
                            plain, EXTENT_BYTES);
    }

    for (page = 0; page < EXTENT_PAGES; ++page) {
        if (decode_page(w, extent, page,
                        plain + (size_t)page * LOGICAL_PAGE_BYTES,
                        dctx) != 0)
            return 1;
    }
    return 0;
}

static int rewrite_one_page(
    Workspace* w, Policy policy, uint32_t extent, uint32_t page,
    const uint8_t* replacement,
    ZSTD_CCtx* cctx, ZSTD_DCtx* dctx,
    uint8_t* extent_plain, uint8_t* page_plain) {
    size_t index = page_flat_index(extent, page);

    if (policy == POLICY_64K) {
        uint32_t old_size = w->extent_sizes[extent];
        uint32_t new_size = 0;
        uint8_t compressed = 0;

        if (decode_extent(w, extent, extent_plain, dctx) != 0)
            return 1;
        memcpy(extent_plain + (size_t)page * LOGICAL_PAGE_BYTES,
               replacement, LOGICAL_PAGE_BYTES);
        if (encode_extent_representation(
                w, extent, extent_plain, cctx,
                &new_size, &compressed) != 0)
            return 1;
        w->stored_bytes -= old_size;
        w->stored_bytes += new_size;
        return 0;
    }

    if (policy == POLICY_ADAPTIVE && w->merged[extent]) {
        uint32_t old_extent_size = w->extent_sizes[extent];

        if (decode_extent(w, extent, extent_plain, dctx) != 0)
            return 1;
        memcpy(extent_plain + (size_t)page * LOGICAL_PAGE_BYTES,
               replacement, LOGICAL_PAGE_BYTES);

        w->stored_bytes -= old_extent_size;
        w->merged[extent] = 0;
        w->split_count++;
        w->hot[extent] = 1;
        clear_page_accounting_for_extent(w, extent);
        if (encode_pages_for_extent(w, extent, extent_plain, cctx) != 0)
            return 1;
        return 0;
    }

    if (decode_page(w, extent, page, page_plain, dctx) != 0)
        return 1;
    memcpy(page_plain, replacement, LOGICAL_PAGE_BYTES);

    {
        uint32_t old_size = w->page_sizes[index];
        uint32_t new_size = 0;
        uint8_t compressed = 0;
        if (encode_block(cctx, page_plain, LOGICAL_PAGE_BYTES,
                         page_slot(w, extent, page), w->page_stride,
                         &new_size, &compressed,
                         &w->encoded_input_bytes) != 0)
            return 1;
        w->page_sizes[index] = new_size;
        w->page_compressed[index] = compressed;
        w->stored_bytes -= old_size;
        w->stored_bytes += new_size;
    }
    return 0;
}

static int rewrite_full_extent(
    Workspace* w, Policy policy, uint32_t extent,
    const uint8_t* replacement,
    ZSTD_CCtx* cctx) {
    if (policy == POLICY_64K) {
        uint32_t old_size = w->extent_sizes[extent];
        uint32_t new_size = 0;
        uint8_t compressed = 0;
        if (encode_extent_representation(
                w, extent, replacement, cctx,
                &new_size, &compressed) != 0)
            return 1;
        w->stored_bytes -= old_size;
        w->stored_bytes += new_size;
        return 0;
    }

    if (policy == POLICY_ADAPTIVE && w->merged[extent]) {
        uint32_t old_size = w->extent_sizes[extent];
        uint32_t new_size = 0;
        uint8_t compressed = 0;

        /*
         * A complete 64 KiB overwrite does not need to split an already merged
         * cold extent. Keep the representation merged and replace it directly.
         */
        if (encode_extent_representation(
                w, extent, replacement, cctx,
                &new_size, &compressed) != 0)
            return 1;
        w->stored_bytes -= old_size;
        w->stored_bytes += new_size;
        return 0;
    }

    if (w->merged[extent]) {
        w->stored_bytes -= w->extent_sizes[extent];
        w->merged[extent] = 0;
        clear_page_accounting_for_extent(w, extent);
    }

    if (encode_pages_for_extent(w, extent, replacement, cctx) != 0)
        return 1;

    if (policy == POLICY_ADAPTIVE)
        return adaptive_try_merge(w, extent, replacement, cctx);
    return 0;
}

static void capture_metrics(
    const Workspace* w, Metrics* m, uint64_t logical_write_bytes,
    LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER freq,
    uint32_t ops) {
    uint32_t extent;

    memset(m, 0, sizeof(*m));
    m->stored_bytes = w->stored_bytes;
    m->encoded_input_bytes = w->encoded_input_bytes;
    m->logical_write_bytes = logical_write_bytes;
    m->merge_count = w->merge_count;
    m->split_count = w->split_count;
    m->extent_probe_count = w->extent_probe_count;
    m->elapsed_ms = milliseconds_between(start, end, freq);
    m->ns_per_op = ops
        ? m->elapsed_ms * 1000000.0 / (double)ops
        : 0.0;
    for (extent = 0; extent < EXTENT_COUNT; ++extent)
        m->merged_extents += !!w->merged[extent];
}

static int bench_random_rewrites(
    Workspace* w, Policy policy, Metrics* metrics) {
    ZSTD_CCtx* cctx = NULL;
    ZSTD_DCtx* dctx = NULL;
    LARGE_INTEGER freq, start, end;
    uint8_t replacement[LOGICAL_PAGE_BYTES];
    uint8_t extent_plain[EXTENT_BYTES];
    uint8_t page_plain[LOGICAL_PAGE_BYTES];
    uint64_t rng = 0x123456789abcdef0ULL;
    uint64_t start_encoded = w->encoded_input_bytes;
    uint32_t op;

    cctx = ZSTD_createCCtx();
    dctx = ZSTD_createDCtx();
    if (!cctx || !dctx || !QueryPerformanceFrequency(&freq))
        goto fail;

    QueryPerformanceCounter(&start);
    for (op = 0; op < RANDOM_REWRITE_OPS; ++op) {
        uint32_t extent = (uint32_t)(rng_next(&rng) % EXTENT_COUNT);
        uint32_t page = (uint32_t)(rng_next(&rng) % EXTENT_PAGES);
        fill_random(replacement, sizeof(replacement), &rng);
        if (rewrite_one_page(w, policy, extent, page, replacement,
                             cctx, dctx, extent_plain, page_plain) != 0)
            goto fail;
    }
    QueryPerformanceCounter(&end);

    capture_metrics(w, metrics,
                    (uint64_t)RANDOM_REWRITE_OPS * LOGICAL_PAGE_BYTES,
                    start, end, freq, RANDOM_REWRITE_OPS);
    metrics->encoded_input_bytes -= start_encoded;

    ZSTD_freeCCtx(cctx);
    ZSTD_freeDCtx(dctx);
    return 0;

fail:
    ZSTD_freeCCtx(cctx);
    ZSTD_freeDCtx(dctx);
    return 1;
}

static int bench_mixed(
    Workspace* w, Policy policy, BenchPattern base_pattern,
    Metrics* metrics) {
    ZSTD_CCtx* cctx = NULL;
    ZSTD_DCtx* dctx = NULL;
    LARGE_INTEGER freq, start, end;
    uint8_t replacement_page[LOGICAL_PAGE_BYTES];
    uint8_t replacement_extent[EXTENT_BYTES];
    uint8_t extent_plain[EXTENT_BYTES];
    uint8_t page_plain[LOGICAL_PAGE_BYTES];
    uint64_t rng = 0x0ddc0ffeebadf00dULL;
    uint64_t start_encoded = w->encoded_input_bytes;
    uint64_t logical_write_bytes = 0;
    uint32_t op;

    cctx = ZSTD_createCCtx();
    dctx = ZSTD_createDCtx();
    if (!cctx || !dctx || !QueryPerformanceFrequency(&freq))
        goto fail;

    QueryPerformanceCounter(&start);
    for (op = 0; op < MIXED_OPS; ++op) {
        uint32_t extent = (uint32_t)(rng_next(&rng) % EXTENT_COUNT);

        if ((op & 7U) == 0U) {
            if (base_pattern == BENCH_PATTERN_CROSS_PAGE) {
                uint8_t base[LOGICAL_PAGE_BYTES];
                uint32_t page;
                fill_random(base, sizeof(base), &rng);
                for (page = 0; page < EXTENT_PAGES; ++page) {
                    uint8_t* dst = replacement_extent +
                                   (size_t)page * LOGICAL_PAGE_BYTES;
                    memcpy(dst, base, sizeof(base));
                    dst[0] ^= (uint8_t)page;
                    dst[1] ^= (uint8_t)(op >> 3);
                }
            } else {
                fill_random(replacement_extent,
                            sizeof(replacement_extent), &rng);
            }

            if (rewrite_full_extent(
                    w, policy, extent, replacement_extent, cctx) != 0)
                goto fail;
            logical_write_bytes += EXTENT_BYTES;
        } else {
            uint32_t page = (uint32_t)(rng_next(&rng) % EXTENT_PAGES);
            fill_random(replacement_page, sizeof(replacement_page), &rng);
            if (rewrite_one_page(w, policy, extent, page,
                                 replacement_page, cctx, dctx,
                                 extent_plain, page_plain) != 0)
                goto fail;
            logical_write_bytes += LOGICAL_PAGE_BYTES;
        }
    }
    QueryPerformanceCounter(&end);

    capture_metrics(w, metrics, logical_write_bytes,
                    start, end, freq, MIXED_OPS);
    metrics->encoded_input_bytes -= start_encoded;

    ZSTD_freeCCtx(cctx);
    ZSTD_freeDCtx(dctx);
    return 0;

fail:
    ZSTD_freeCCtx(cctx);
    ZSTD_freeDCtx(dctx);
    return 1;
}

static void print_metrics(
    BenchPattern pattern, Policy policy, const char* phase,
    const Metrics* m) {
    double stored_pct = 100.0 * (double)m->stored_bytes / (double)DATA_BYTES;
    double encoded_amp = m->logical_write_bytes
        ? (double)m->encoded_input_bytes / (double)m->logical_write_bytes
        : 0.0;
    double merged_pct = 100.0 * (double)m->merged_extents /
                        (double)EXTENT_COUNT;

    printf(
        "pattern=%-10s policy=%-8s phase=%-7s "
        "stored=%9llu (%6.2f%%) encoded_amp=%6.2fx "
        "elapsed=%8.3fms ns/op=%9.1f merged=%3u (%5.1f%%) "
        "merge=%llu split=%llu probes=%llu\n",
        pattern_name(pattern), policy_name(policy), phase,
        (unsigned long long)m->stored_bytes, stored_pct,
        encoded_amp, m->elapsed_ms, m->ns_per_op,
        m->merged_extents, merged_pct,
        (unsigned long long)m->merge_count,
        (unsigned long long)m->split_count,
        (unsigned long long)m->extent_probe_count);
}

static int run_case(BenchPattern pattern, Policy policy) {
    uint8_t* data = NULL;
    Workspace w;
    Metrics init, rewrites, mixed;
    int rc = 1;

    memset(&w, 0, sizeof(w));
    data = (uint8_t*)malloc(DATA_BYTES);
    if (!data || workspace_init(&w) != 0)
        goto cleanup;

    make_dataset(data, pattern);
    if (build_initial(&w, policy, data, &init) != 0)
        goto cleanup;
    print_metrics(pattern, policy, "initial", &init);

    if (bench_random_rewrites(&w, policy, &rewrites) != 0)
        goto cleanup;
    print_metrics(pattern, policy, "random", &rewrites);

    workspace_destroy(&w);
    if (workspace_init(&w) != 0)
        goto cleanup;
    if (build_initial(&w, policy, data, &init) != 0)
        goto cleanup;
    if (bench_mixed(&w, policy, pattern, &mixed) != 0)
        goto cleanup;
    print_metrics(pattern, policy, "mixed", &mixed);

    rc = 0;

cleanup:
    workspace_destroy(&w);
    free(data);
    return rc;
}

int main(void) {
    BenchPattern pattern;
    Policy policy;

    printf("adaptive extent benchmark: page=4KiB extent=64KiB "
           "probe=1/%u score_skip=%d min_saving=%u\n",
           EXTENT_PROBE_MASK + 1U, EXTENT_SCORE_SKIP,
           MERGE_MIN_SAVING_BYTES);

    for (pattern = BENCH_PATTERN_CROSS_PAGE;
         pattern <= BENCH_PATTERN_RANDOM;
         pattern = (BenchPattern)(pattern + 1)) {
        for (policy = POLICY_4K; policy <= POLICY_ADAPTIVE;
             policy = (Policy)(policy + 1)) {
            if (run_case(pattern, policy) != 0) {
                fprintf(stderr, "benchmark failed: pattern=%s policy=%s\n",
                        pattern_name(pattern), policy_name(policy));
                return 1;
            }
        }
    }
    return 0;
}
