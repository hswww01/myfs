#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "memfs_core.h"

#define SOAK_DEFAULT_SECONDS 3U
#define SOAK_MIN_MINUTES 10U
#define SOAK_MAX_MINUTES 60U
#define SOAK_DEFAULT_SAMPLE_MS 1000U
#define SOAK_CAPACITY_BYTES (512ULL * 1024ULL * 1024ULL)
#define SOAK_LARGE_BYTES (256U * 1024U)
#define SOAK_CHUNK_BYTES (64U * 1024U)
#define SOAK_SPARSE_OFFSET (64ULL * 1024ULL * 1024ULL)

typedef struct DriftFit {
    double count;
    double sum_x;
    double sum_y;
    double sum_xx;
    double sum_xy;
} DriftFit;

static uint64_t private_bytes(void) {
    PROCESS_MEMORY_COUNTERS_EX counters;

    memset(&counters, 0, sizeof(counters));
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(
            GetCurrentProcess(),
            (PROCESS_MEMORY_COUNTERS*)&counters,
            sizeof(counters))) {
        return 0;
    }
    return (uint64_t)counters.PrivateUsage;
}

static void drift_add(DriftFit* fit, double seconds, uint64_t bytes) {
    double y = (double)bytes;

    fit->count += 1.0;
    fit->sum_x += seconds;
    fit->sum_y += y;
    fit->sum_xx += seconds * seconds;
    fit->sum_xy += seconds * y;
}

static double drift_slope(const DriftFit* fit) {
    double denominator;

    if (fit->count < 2.0)
        return 0.0;

    denominator = fit->count * fit->sum_xx - fit->sum_x * fit->sum_x;
    if (denominator == 0.0)
        return 0.0;

    return (fit->count * fit->sum_xy - fit->sum_x * fit->sum_y) /
           denominator;
}

static void fill_pattern(uint8_t* buffer, size_t bytes, uint64_t seed) {
    uint64_t x = seed ? seed : 0x9e3779b97f4a7c15ULL;
    size_t i;

    for (i = 0; i < bytes; i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buffer[i] = (uint8_t)x;
    }
}

static int tiny_cycle(Memfs* fs, uint64_t cycle) {
    MemfsNode* node = NULL;
    uint8_t write_buffer[256];
    uint8_t read_buffer[256];
    wchar_t renamed[64];
    uint32_t length = (uint32_t)(cycle % sizeof(write_buffer)) + 1U;
    uint32_t transferred = 0;
    MemfsResult result;
    int rc = 1;

    memset(write_buffer, (int)(cycle & 0xffU), length);
    result = memfs_node_create(
        fs, fs->root, L"soak-tiny.tmp", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &node);
    if (result != MEMFS_OK || node == NULL)
        goto cleanup;

    result = memfs_node_write(
        node, write_buffer, 0, length, false, false, &transferred);
    if (result != MEMFS_OK || transferred != length)
        goto cleanup;

    memset(read_buffer, 0, length);
    result = memfs_node_read(node, read_buffer, 0, length, &transferred);
    if (result != MEMFS_OK || transferred != length ||
        memcmp(write_buffer, read_buffer, length) != 0) {
        goto cleanup;
    }

    _snwprintf_s(
        renamed, _countof(renamed), _TRUNCATE,
        L"soak-tiny-%llu.ren", (unsigned long long)(cycle & 0xffffU));
    result = memfs_node_rename(node, fs->root, renamed, true);
    if (result != MEMFS_OK)
        goto cleanup;

    rc = 0;

cleanup:
    if (node != NULL) {
        if (memfs_node_unlink(node) != MEMFS_OK)
            rc = 1;
        memfs_node_close(node);
    }
    return rc;
}

static int large_cycle(Memfs* fs, uint64_t cycle) {
    MemfsNode* node = NULL;
    uint8_t write_buffer[SOAK_CHUNK_BYTES];
    uint8_t zero_buffer[4096];
    uint32_t transferred = 0;
    uint32_t chunk;
    MemfsResult result;
    int rc = 1;

    result = memfs_node_create(
        fs, fs->root, L"soak-large.bin", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &node);
    if (result != MEMFS_OK || node == NULL)
        goto cleanup;

    for (chunk = 0; chunk < SOAK_LARGE_BYTES / SOAK_CHUNK_BYTES; chunk++) {
        if ((cycle + chunk) & 1U)
            fill_pattern(write_buffer, sizeof(write_buffer), cycle + chunk + 1U);
        else
            memset(write_buffer, (int)((cycle + chunk) & 0xffU), sizeof(write_buffer));

        result = memfs_node_write(
            node, write_buffer,
            (uint64_t)chunk * SOAK_CHUNK_BYTES,
            sizeof(write_buffer), false, false, &transferred);
        if (result != MEMFS_OK || transferred != sizeof(write_buffer))
            goto cleanup;
    }

    result = memfs_node_set_file_size(node, SOAK_CHUNK_BYTES);
    if (result != MEMFS_OK)
        goto cleanup;
    result = memfs_node_set_file_size(node, SOAK_LARGE_BYTES);
    if (result != MEMFS_OK)
        goto cleanup;

    memset(zero_buffer, 0xff, sizeof(zero_buffer));
    result = memfs_node_read(
        node, zero_buffer, 2U * SOAK_CHUNK_BYTES,
        sizeof(zero_buffer), &transferred);
    if (result != MEMFS_OK || transferred != sizeof(zero_buffer))
        goto cleanup;
    for (chunk = 0; chunk < sizeof(zero_buffer); chunk++) {
        if (zero_buffer[chunk] != 0)
            goto cleanup;
    }

    rc = 0;

cleanup:
    if (node != NULL) {
        if (memfs_node_unlink(node) != MEMFS_OK)
            rc = 1;
        memfs_node_close(node);
    }
    return rc;
}

static int sparse_cycle(Memfs* fs, uint64_t cycle) {
    MemfsNode* node = NULL;
    uint8_t page[MEMFS_PAGE_SIZE];
    uint8_t verify[MEMFS_PAGE_SIZE];
    uint32_t transferred = 0;
    MemfsResult result;
    int rc = 1;

    fill_pattern(page, sizeof(page), cycle + 0x12345678ULL);
    result = memfs_node_create(
        fs, fs->root, L"soak-sparse.bin", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &node);
    if (result != MEMFS_OK || node == NULL)
        goto cleanup;

    result = memfs_node_write(
        node, page, SOAK_SPARSE_OFFSET, sizeof(page),
        false, false, &transferred);
    if (result != MEMFS_OK || transferred != sizeof(page))
        goto cleanup;

    memset(verify, 0, sizeof(verify));
    result = memfs_node_read(
        node, verify, SOAK_SPARSE_OFFSET, sizeof(verify), &transferred);
    if (result != MEMFS_OK || transferred != sizeof(verify) ||
        memcmp(page, verify, sizeof(page)) != 0) {
        goto cleanup;
    }

    if (memfs_node_page_group_count(node) != 1U)
        goto cleanup;

    result = memfs_node_set_file_size(node, MEMFS_PAGE_SIZE);
    if (result != MEMFS_OK)
        goto cleanup;
    result = memfs_node_set_file_size(node, 2U * MEMFS_PAGE_SIZE);
    if (result != MEMFS_OK)
        goto cleanup;

    rc = 0;

cleanup:
    if (node != NULL) {
        if (memfs_node_unlink(node) != MEMFS_OK)
            rc = 1;
        memfs_node_close(node);
    }
    return rc;
}

static int workload_cycle(Memfs* fs, uint64_t cycle) {
    if (tiny_cycle(fs, cycle) != 0)
        return 1;
    if (large_cycle(fs, cycle) != 0)
        return 1;
    if (sparse_cycle(fs, cycle) != 0)
        return 1;
    return 0;
}

static void sample_stats(
    Memfs* fs,
    double seconds,
    uint64_t cycles,
    DriftFit* private_fit,
    DriftFit* committed_fit) {
    MemfsRuntimeStats stats;
    uint64_t process_private;

    memfs_get_runtime_stats(fs, &stats);
    process_private = private_bytes();

    drift_add(private_fit, seconds, process_private);
    drift_add(committed_fit, seconds, stats.allocator_committed_bytes);

    printf(
        "sample seconds=%.3f cycles=%llu logical=%llu resident=%llu "
        "alloc_live=%llu alloc_reserved=%llu alloc_committed=%llu "
        "alloc_physical=%llu private=%llu slabs=%u areas=%u cached_areas=%u\n",
        seconds,
        (unsigned long long)cycles,
        (unsigned long long)stats.logical_used_bytes,
        (unsigned long long)stats.resident_bytes,
        (unsigned long long)stats.allocator_live_bytes,
        (unsigned long long)stats.allocator_reserved_bytes,
        (unsigned long long)stats.allocator_committed_bytes,
        (unsigned long long)stats.allocator_physical_bytes,
        (unsigned long long)process_private,
        stats.slab_count,
        stats.area_count,
        stats.area_cached_count);
}

static void usage(const char* exe) {
    fprintf(
        stderr,
        "Usage: %s [--seconds N] [--soak MINUTES] [--sample-ms N] [--auto-capacity]\n"
        "  no arguments      short CI run (%u seconds)\n"
        "  --seconds N       explicit short run, 1..30 seconds\n"
        "  --soak MINUTES    long soak, %u..%u minutes\n"
        "  --sample-ms N     sample interval, 250..10000 ms\n"
        "  --auto-capacity   exercise adaptive capacity/cache instead of fixed quota\n",
        exe,
        SOAK_DEFAULT_SECONDS,
        SOAK_MIN_MINUTES,
        SOAK_MAX_MINUTES);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    MemfsOptions options;
    Memfs* fs = NULL;
    MemfsRuntimeStats baseline;
    MemfsRuntimeStats final_stats;
    DriftFit private_fit = {0};
    DriftFit committed_fit = {0};
    uint32_t duration_seconds = SOAK_DEFAULT_SECONDS;
    uint32_t sample_ms = SOAK_DEFAULT_SAMPLE_MS;
    bool auto_capacity = false;
    uint64_t duration_ms;
    uint64_t start_tick;
    uint64_t next_sample;
    uint64_t last_sample_tick;
    uint64_t cycles = 0;
    uint64_t private_start;
    uint64_t private_end;
    double elapsed;
    double private_slope;
    double committed_slope;
    int i;
    int rc = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            unsigned long value = strtoul(argv[++i], NULL, 10);
            if (value < 1U || value > 30U) {
                usage(argv[0]);
                return 2;
            }
            duration_seconds = (uint32_t)value;
        } else if (strcmp(argv[i], "--soak") == 0 && i + 1 < argc) {
            unsigned long value = strtoul(argv[++i], NULL, 10);
            if (value < SOAK_MIN_MINUTES || value > SOAK_MAX_MINUTES) {
                usage(argv[0]);
                return 2;
            }
            duration_seconds = (uint32_t)value * 60U;
        } else if (strcmp(argv[i], "--sample-ms") == 0 && i + 1 < argc) {
            unsigned long value = strtoul(argv[++i], NULL, 10);
            if (value < 250U || value > 10000U) {
                usage(argv[0]);
                return 2;
            }
            sample_ms = (uint32_t)value;
        } else if (strcmp(argv[i], "--auto-capacity") == 0) {
            auto_capacity = true;
        } else if (strcmp(argv[i], "--help") == 0 ||
                   strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    memset(&options, 0, sizeof(options));
    options.capacity = auto_capacity ? 0 : SOAK_CAPACITY_BYTES;
    options.capacity_auto = auto_capacity;
    printf("capacity_mode=%s\n", auto_capacity ? "auto" : "fixed");
    options.volume_label = L"SOAK";
    options.compression_enabled = true;
    options.compression_level = 1;
    options.encryption_enabled = true;

    if (memfs_create_ex(&options, &fs) != MEMFS_OK || fs == NULL) {
        fprintf(stderr, "soak: memfs_create_ex failed\n");
        goto cleanup;
    }

    /*
     * Warm all codec/crypto/allocator shape variants before defining the drift
     * baseline. One round is not enough because compressible/incompressible
     * pages and varying tiny-name lengths can lazily initialize different
     * library/runtime paths.
     */
    for (i = 0; i < 32; i++) {
        if (workload_cycle(fs, (uint64_t)i) != 0) {
            fprintf(stderr, "soak: warmup workload failed round=%d\n", i);
            goto cleanup;
        }
    }
    (void)memfs_allocator_scavenge(&fs->allocator);
    memfs_get_runtime_stats(fs, &baseline);
    private_start = private_bytes();
    private_start = private_bytes();

    if (baseline.logical_used_bytes != 0U || baseline.resident_bytes != 0U) {
        fprintf(stderr, "soak: warmup did not return filesystem to baseline\n");
        goto cleanup;
    }

    duration_ms = (uint64_t)duration_seconds * 1000ULL;
    start_tick = GetTickCount64();
    next_sample = start_tick;
    last_sample_tick = start_tick;
    sample_stats(fs, 0.0, cycles, &private_fit, &committed_fit);
    /* Exclude the t=0 instrumentation/runtime transition from drift fit. */
    memset(&private_fit, 0, sizeof(private_fit));
    memset(&committed_fit, 0, sizeof(committed_fit));
    next_sample += sample_ms;

    while (GetTickCount64() - start_tick < duration_ms) {
        uint64_t now;

        cycles++;
        if (workload_cycle(fs, cycles) != 0) {
            fprintf(stderr, "soak: workload failed at cycle=%llu\n",
                    (unsigned long long)cycles);
            goto cleanup;
        }

        now = GetTickCount64();
        if (now >= next_sample) {
            elapsed = (double)(now - start_tick) / 1000.0;
            sample_stats(
                fs, elapsed, cycles, &private_fit, &committed_fit);
            last_sample_tick = now;
            do {
                next_sample += sample_ms;
            } while (next_sample <= now);
        }
    }

    {
        uint64_t end_tick = GetTickCount64();
        elapsed = (double)(end_tick - start_tick) / 1000.0;
        if (end_tick - last_sample_tick >= sample_ms / 4U) {
            sample_stats(fs, elapsed, cycles, &private_fit, &committed_fit);
            last_sample_tick = end_tick;
        }
    }

    (void)memfs_allocator_scavenge(&fs->allocator);
    memfs_get_runtime_stats(fs, &final_stats);
    private_end = private_bytes();

    private_slope = drift_slope(&private_fit);
    committed_slope = drift_slope(&committed_fit);

    printf(
        "summary seconds=%.3f cycles=%llu private_start=%llu private_end=%llu "
        "private_drift_bytes_per_second=%.2f private_drift_bytes_per_hour=%.2f "
        "committed_drift_bytes_per_second=%.2f committed_drift_bytes_per_hour=%.2f\n",
        elapsed,
        (unsigned long long)cycles,
        (unsigned long long)private_start,
        (unsigned long long)private_end,
        private_slope,
        private_slope * 3600.0,
        committed_slope,
        committed_slope * 3600.0);

    if (final_stats.logical_used_bytes != baseline.logical_used_bytes ||
        final_stats.resident_bytes != baseline.resident_bytes ||
        final_stats.allocator_live_bytes != baseline.allocator_live_bytes ||
        final_stats.allocator_live_objects != baseline.allocator_live_objects ||
        final_stats.allocator_reserved_bytes != baseline.allocator_reserved_bytes ||
        final_stats.allocator_committed_bytes != baseline.allocator_committed_bytes ||
        final_stats.allocator_physical_bytes != baseline.allocator_physical_bytes ||
        final_stats.slab_count != baseline.slab_count ||
        final_stats.area_count != baseline.area_count ||
        final_stats.area_cached_count != 0U ||
        final_stats.area_cached_bytes != 0U) {
        fprintf(
            stderr,
            "soak: final baseline mismatch "
            "used=%llu/%llu resident=%llu/%llu live=%llu/%llu "
            "objects=%llu/%llu reserved=%llu/%llu committed=%llu/%llu\n",
            (unsigned long long)final_stats.logical_used_bytes,
            (unsigned long long)baseline.logical_used_bytes,
            (unsigned long long)final_stats.resident_bytes,
            (unsigned long long)baseline.resident_bytes,
            (unsigned long long)final_stats.allocator_live_bytes,
            (unsigned long long)baseline.allocator_live_bytes,
            (unsigned long long)final_stats.allocator_live_objects,
            (unsigned long long)baseline.allocator_live_objects,
            (unsigned long long)final_stats.allocator_reserved_bytes,
            (unsigned long long)baseline.allocator_reserved_bytes,
            (unsigned long long)final_stats.allocator_committed_bytes,
            (unsigned long long)baseline.allocator_committed_bytes);
        goto cleanup;
    }

    printf("soak PASS\n");
    rc = 0;

cleanup:
    if (fs != NULL)
        memfs_destroy(fs);
    return rc;
}
