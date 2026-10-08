#include "memfs_core.h"

#include <stdio.h>
#include <string.h>

/* This target compiles the production core with NDEBUG and only substitutes
 * the OS memory/clock providers. Assertions remain active in both presets. */
static int failures;
#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); ++failures; \
} } while (0)

typedef struct MockSystem {
    volatile LONG64 available;
    volatile LONG64 ticks;
    volatile LONG64 queries;
    volatile LONG64 advance_during_query;
    volatile LONG fail_clock;
    volatile LONG allocate_during_query;
    Memfs* fs;
    void* injected;
} MockSystem;

static uint64_t mock_available(void* opaque) {
    MockSystem* m = opaque;
    InterlockedIncrement64(&m->queries);
    if (InterlockedExchange(&m->allocate_during_query, 0))
        m->injected = memfs_allocator_alloc(&m->fs->allocator, 16384);
    InterlockedAdd64(&m->ticks,
        InterlockedExchange64(&m->advance_during_query, 0));
    return (uint64_t)InterlockedCompareExchange64(&m->available, 0, 0);
}

static bool mock_clock(void* opaque, uint64_t* ticks) {
    MockSystem* m = opaque;
    if (InterlockedCompareExchange(&m->fail_clock, 0, 0))
        return false;
    *ticks = (uint64_t)InterlockedCompareExchange64(&m->ticks, 0, 0);
    return true;
}

static Memfs* create_mock_fs(MockSystem* m) {
    Memfs* fs = NULL;
    MemfsOptions options = {0};
    MemfsCapacityTestHooks hooks = {mock_available, mock_clock, m};
    memset(m, 0, sizeof(*m));
    m->available = 4LL * 1024LL * 1024LL * 1024LL;
    m->ticks = 1000;
    memfs_test_capacity_set_hooks(&hooks);
    options.capacity_auto = true;
    options.volume_label = L"CACHE_TEST";
    CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
    CHECK(fs != NULL);
    m->fs = fs;
    if (fs) {
        CHECK(fs->auto_available_cache_interval_qpc > 0);
        fs->auto_available_cache_deadline_qpc = 0;
        m->queries = 0;
    }
    if (!fs) memfs_test_capacity_set_hooks(NULL);
    return fs;
}

static void destroy_mock_fs(MockSystem* m) {
    if (m->injected)
        memfs_allocator_free(&m->fs->allocator, m->injected, 16384);
    memfs_destroy(m->fs);
    memfs_test_capacity_set_hooks(NULL);
}

static void test_hit_expiry_force_and_slow_query(void) {
    MockSystem m;
    Memfs* fs = create_mock_fs(&m);
    uint64_t value, initial;
    LONG64 calls;
    if (!fs) return;
    initial = (uint64_t)m.available;
    CHECK(memfs_test_capacity_available(fs, false) == initial);
    CHECK(m.queries == 1);
    m.available = (LONG64)initial - 100;
    CHECK(memfs_test_capacity_available(fs, false) == initial);
    CHECK(m.queries == 1);
    CHECK(memfs_test_capacity_available(fs, true) == initial - 100);
    CHECK(m.queries == 2);

    m.ticks = (LONG64)fs->auto_available_cache_deadline_qpc;
    m.available = (LONG64)initial - 200;
    CHECK(memfs_test_capacity_available(fs, false) == initial - 200);
    CHECK(m.queries == 3); /* Deadline is exclusive. */

    calls = m.queries;
    m.advance_during_query = (LONG64)fs->auto_available_cache_interval_qpc + 1;
    value = memfs_test_capacity_available(fs, true);
    CHECK(value == initial - 200);
    CHECK(fs->auto_available_cache_deadline_qpc < (uint64_t)m.ticks);
    CHECK(memfs_test_capacity_available(fs, false) == value);
    CHECK(m.queries == calls + 2); /* Slow query did not acquire a new TTL. */

    m.fail_clock = 1;
    m.available = 123;
    CHECK(memfs_test_capacity_available(fs, false) == 123);
    CHECK(fs->auto_available_cache_deadline_qpc == 0);
    m.fail_clock = 0;
    m.available = 456;
    CHECK(memfs_test_capacity_available(fs, false) == 456);

    /* Counter rollback cannot make a snapshot from the future valid. */
    m.ticks = 1;
    m.available = 789;
    calls = m.queries;
    CHECK(memfs_test_capacity_available(fs, false) == 789);
    CHECK(m.queries == calls + 1);
    m.available = 0; /* Simulated failed OS query / exhausted memory. */
    CHECK(memfs_test_capacity_available(fs, true) == 0);
    destroy_mock_fs(&m);
    puts("snapshot hit/expiry/force/slow-query/clock-failure PASS");
}

static void test_growth_during_sample_and_free_reallocate(void) {
    MockSystem m;
    Memfs* fs = create_mock_fs(&m);
    uint64_t before, after, available, net;
    void* p;
    if (!fs) return;
    before = memfs_allocator_commit_total_bytes(&fs->allocator);
    net = memfs_allocator_committed_bytes(&fs->allocator);
    m.allocate_during_query = 1;
    available = memfs_test_capacity_available(fs, true);
    after = memfs_allocator_commit_total_bytes(&fs->allocator);
    CHECK(m.injected != NULL);
    CHECK(after > before);
    CHECK(fs->auto_available_cached_commit_total == before);
    CHECK(available == (uint64_t)m.available - (after - before));
    memfs_allocator_free(&fs->allocator, m.injected, 16384);
    m.injected = NULL;
    (void)memfs_allocator_scavenge(&fs->allocator);
    CHECK(memfs_allocator_committed_bytes(&fs->allocator) == net);
    CHECK(memfs_allocator_commit_total_bytes(&fs->allocator) == after);
    CHECK(memfs_test_capacity_available(fs, false) == available);
    p = memfs_allocator_alloc(&fs->allocator, 16384);
    CHECK(p != NULL);
    CHECK(memfs_allocator_commit_total_bytes(&fs->allocator) > after);
    CHECK(memfs_test_capacity_available(fs, false) < available);
    if (p) memfs_allocator_free(&fs->allocator, p, 16384);
    (void)memfs_allocator_scavenge(&fs->allocator);
    CHECK(memfs_allocator_committed_bytes(&fs->allocator) == net);
    CHECK(memfs_test_capacity_available(fs, false) < available);
    destroy_mock_fs(&m);
    CHECK(memfs_allocator_commit_total_bytes(NULL) == 0);
    puts("snapshot in-query growth and gross-commit debit PASS");
}

static void test_pressure_preserves_data(void) {
    MockSystem m;
    Memfs* fs = create_mock_fs(&m);
    MemfsNode* file = NULL;
    uint8_t input[32], output[32];
    uint32_t transferred = 0;
    uint64_t old_size, old_used;
    if (!fs) return;
    CHECK(memfs_node_create(fs, fs->root, L"atomic.bin", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &file) == MEMFS_OK);
    if (!file) { destroy_mock_fs(&m); return; }
    memset(input, 0x5a, sizeof(input));
    CHECK(memfs_node_write(file, input, 0, sizeof(input), false, false,
        &transferred) == MEMFS_OK);
    CHECK(transferred == sizeof(input));
    old_size = file->file_size;
    old_used = (uint64_t)fs->used_bytes;
    m.available = (LONG64)MEMFS_AUTO_HARD_MARGIN_BYTES - 1;
    m.ticks += (LONG64)fs->auto_available_cache_interval_qpc + 1;
    CHECK(memfs_node_set_file_size(file, old_size + 1) == MEMFS_ERR_NO_SPACE);
    CHECK(file->file_size == old_size);
    CHECK((uint64_t)fs->used_bytes == old_used);
    CHECK(memfs_node_read(file, output, 0, sizeof(output), &transferred) == MEMFS_OK);
    CHECK(transferred == sizeof(input) && memcmp(input, output, sizeof(input)) == 0);
    m.available = 4LL * 1024LL * 1024LL * 1024LL;
    /* Low cached allowance triggers a forced live query even before TTL expiry. */
    CHECK(memfs_node_set_file_size(file, old_size + 1) == MEMFS_OK);
    CHECK(file->file_size == old_size + 1);
    CHECK(memfs_node_unlink(file) == MEMFS_OK);
    memfs_node_close(file);
    destroy_mock_fs(&m);
    puts("production pressure rejection/rollback/relief PASS");
}

#define READER_COUNT 4
#define STRESS_VALUE (4ULL * 1024ULL * 1024ULL * 1024ULL)
typedef struct Stress {
    Memfs* fs;
    HANDLE start;
    volatile LONG stop;
    volatile LONG errors;
    volatile LONG64 hits;
    uint64_t commit_total;
} Stress;

static DWORD WINAPI refresh_writer(void* opaque) {
    Stress* s = opaque;
    if (WaitForSingleObject(s->start, 10000) != WAIT_OBJECT_0) return 1;
    for (unsigned i = 0; i < 20000; ++i) {
        uint64_t debit = (i & 1) ? 4096 : 0;
        if (InterlockedCompareExchange(&s->stop, 0, 0)) break;
        AcquireSRWLockExclusive(&s->fs->auto_available_refresh_lock);
        s->fs->auto_available_cached_bytes = STRESS_VALUE + debit;
        if ((i & 31) == 0) SwitchToThread();
        s->fs->auto_available_cached_commit_total = s->commit_total - debit;
        s->fs->auto_available_sample_qpc = 1;
        s->fs->auto_available_cache_deadline_qpc = UINT64_MAX;
        ReleaseSRWLockExclusive(&s->fs->auto_available_refresh_lock);
    }
    return 0;
}

static DWORD WINAPI cached_reader(void* opaque) {
    Stress* s = opaque;
    if (WaitForSingleObject(s->start, 10000) != WAIT_OBJECT_0) return 1;
    for (unsigned i = 0; i < 50000; ++i) {
        if (InterlockedCompareExchange(&s->stop, 0, 0)) break;
        if (memfs_test_capacity_available(s->fs, false) != STRESS_VALUE)
            InterlockedIncrement(&s->errors);
        InterlockedIncrement64(&s->hits);
    }
    return 0;
}

static void test_concurrent_production_snapshot(void) {
    MockSystem m;
    Memfs* fs = create_mock_fs(&m);
    Stress s = {0};
    HANDLE workers[READER_COUNT + 1];
    DWORD count = 0;
    if (!fs) return;
    s.fs = fs;
    s.commit_total = memfs_allocator_commit_total_bytes(&fs->allocator);
    CHECK(s.commit_total >= 4096);
    fs->auto_available_cached_bytes = STRESS_VALUE;
    fs->auto_available_cached_commit_total = s.commit_total;
    fs->auto_available_sample_qpc = 1;
    fs->auto_available_cache_deadline_qpc = UINT64_MAX;
    s.start = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(s.start != NULL);
    if (!s.start) { destroy_mock_fs(&m); return; }
    for (unsigned i = 0; i < READER_COUNT + 1; ++i) {
        workers[count] = CreateThread(NULL, 0,
            i == 0 ? refresh_writer : cached_reader, &s, 0, NULL);
        if (!workers[count]) { CHECK(0); InterlockedExchange(&s.stop, 1); break; }
        ++count;
    }
    SetEvent(s.start);
    if (count && WaitForMultipleObjects(count, workers, TRUE, 30000) != WAIT_OBJECT_0)
        ExitProcess(2); /* Never free storage while a test worker is alive. */
    for (DWORD i = 0; i < count; ++i) {
        DWORD code = 1;
        CHECK(GetExitCodeThread(workers[i], &code) && code == 0);
        CloseHandle(workers[i]);
    }
    CloseHandle(s.start);
    CHECK(s.errors == 0);
    CHECK(s.hits == READER_COUNT * 50000LL);
    CHECK(m.queries == 0);
    printf("production snapshot: reads=%lld mixed_snapshots=%ld\n", s.hits, s.errors);
    destroy_mock_fs(&m);
}

int main(void) {
    test_hit_expiry_force_and_slow_query();
    test_growth_during_sample_and_free_reallocate();
    test_pressure_preserves_data();
    test_concurrent_production_snapshot();
    printf("memfs_capacity_snapshot_test: %s (%d failures)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
