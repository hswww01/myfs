#include "memfs_core.h"
#include <stdio.h>
#include <string.h>

/* WinFsp FINE does not serialize FILE_OPEN with other opens, and its kernel
 * queues Close as best-effort asynchronous work. Keep namespace mutation
 * single-threaded here, but deliberately race handle and orphan transitions. */
#define THREADS 8
#define REF_OPS 20000
#define NODES 512
static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); ++failures; } } while (0)

typedef struct Worker {
    HANDLE start;
    MemfsNode* node;
    MemfsNode** nodes;
    unsigned count;
    unsigned stride;
    unsigned offset;
    unsigned mode;
} Worker;

static DWORD WINAPI run_worker(void* opaque) {
    Worker* w = opaque;
    if (WaitForSingleObject(w->start, 10000) != WAIT_OBJECT_0) return 1;
    if (w->nodes) {
        for (unsigned i = w->offset; i < w->count; i += w->stride) {
            if ((i & 7) == 0) SwitchToThread();
            memfs_node_close(w->nodes[i]);
        }
    } else {
        for (unsigned i = 0; i < REF_OPS; ++i) {
            if (w->mode != 1) memfs_node_open(w->node);
            if (w->mode != 0) memfs_node_close(w->node);
        }
    }
    return 0;
}

static unsigned start_workers(Worker workers[THREADS], HANDLE handles[THREADS],
                              MemfsNode* node, MemfsNode** nodes, unsigned count,
                              unsigned mode, HANDLE start) {
    unsigned created = 0;
    for (unsigned i = 0; i < THREADS; ++i) {
        workers[i] = (Worker){start, node, nodes, count, THREADS, i, mode};
        handles[i] = CreateThread(NULL, 0, run_worker, &workers[i], 0, NULL);
        if (!handles[i]) { CHECK(0); break; }
        ++created;
    }
    SetEvent(start);
    return created;
}

static void join_workers(HANDLE handles[THREADS], unsigned count) {
    if (count && WaitForMultipleObjects(count, handles, TRUE, 30000) != WAIT_OBJECT_0) {
        fprintf(stderr, "lifetime worker timeout; not freeing shared state\n");
        ExitProcess(2);
    }
    for (unsigned i = 0; i < count; ++i) {
        DWORD code = 1;
        CHECK(GetExitCodeThread(handles[i], &code) && code == 0);
        CloseHandle(handles[i]);
    }
}

static bool reference_counts(void) {
    Worker workers[THREADS];
    HANDLE handles[THREADS];
    Memfs* fs = NULL;
    MemfsNode* node = NULL;
    HANDLE start;
    unsigned created;
    CHECK(memfs_create(64ULL << 20, L"REFS", &fs) == MEMFS_OK);
    if (!fs) return false;
    CHECK(memfs_node_create(fs, fs->root, L"shared", false, FILE_ATTRIBUTE_NORMAL,
                           NULL, 0, &node) == MEMFS_OK);
    if (!node) { memfs_destroy(fs); return false; }
    start = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start) { CHECK(0); memfs_destroy(fs); return false; }
    created = start_workers(workers, handles, node, NULL, 0, 0, start);
    join_workers(handles, created);
    printf("parallel open: observed=%u expected=%u\n", node->open_count,
           1 + created * REF_OPS);
    CHECK(node->open_count == 1 + created * REF_OPS);
    if (node->open_count != 1 + created * REF_OPS) {
        /* All workers have joined and no real user remains. Teardown is safe
         * even when the old implementation corrupted the logical count. */
        CloseHandle(start);
        memfs_destroy(fs);
        return false;
    }
    ResetEvent(start);
    created = start_workers(workers, handles, node, NULL, 0, 1, start);
    join_workers(handles, created);
    CHECK(node->open_count == 1);
    ResetEvent(start);
    created = start_workers(workers, handles, node, NULL, 0, 2, start);
    join_workers(handles, created);
    CHECK(node->open_count == 1);
    CHECK(IsValidSecurityDescriptor(memfs_node_get_security(node)->data));
    CHECK(memfs_node_unlink(node) == MEMFS_OK);
    memfs_node_close(node);
    CHECK(fs->orphan_head == NULL);
    CloseHandle(start);
    memfs_destroy(fs);
    return failures == 0;
}

static void orphan_transitions(unsigned scenario) {
    Worker workers[THREADS];
    HANDLE handles[THREADS];
    Memfs* fs = NULL;
    MemfsNode* nodes[NODES] = {0};
    MemfsNode* replacements[NODES] = {0};
    HANDLE start = NULL;
    unsigned created;
    unsigned allocated = 0;
    MemfsAllocatorStats baseline, final;
    CHECK(memfs_create(64ULL << 20, L"ORPHANS", &fs) == MEMFS_OK);
    if (!fs) return;
    memfs_allocator_get_stats(&fs->allocator, &baseline);
    for (unsigned i = 0; i < NODES; ++i) {
        wchar_t name[32];
        swprintf_s(name, _countof(name), L"node-%u", i);
        CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL,
                               NULL, 0, &nodes[i]) == MEMFS_OK);
        if (!nodes[i]) break;
        ++allocated;
        if (scenario == 2) {
            swprintf_s(name, _countof(name), L"replacement-%u", i);
            CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL,
                                   NULL, 0, &replacements[i]) == MEMFS_OK);
            if (!replacements[i]) break;
        }
        if (scenario == 0) CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
    }
    if (allocated != NODES || (scenario == 2 && !replacements[NODES-1])) {
        memfs_destroy(fs); return;
    }
    start = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!start) { CHECK(0); memfs_destroy(fs); return; }
    created = start_workers(workers, handles, NULL, nodes, NODES, 1, start);
    for (unsigned i = 0; scenario != 0 && i < NODES; ++i) {
        if (scenario == 1) {
            CHECK(memfs_node_unlink(nodes[i]) == MEMFS_OK);
        } else {
            wchar_t name[32];
            swprintf_s(name, _countof(name), L"node-%u", i);
            CHECK(memfs_node_rename(replacements[i], fs->root, name, true) == MEMFS_OK);
            CHECK(memfs_node_unlink(replacements[i]) == MEMFS_OK);
            memfs_node_close(replacements[i]);
        }
    }
    join_workers(handles, created);
    CloseHandle(start);
    CHECK(created == THREADS);
    CHECK(fs->orphan_head == NULL);
    CHECK(fs->root->dir->child_count == 0);
    CHECK(IsValidSecurityDescriptor(memfs_node_get_security(fs->root)->data));
    CHECK(memfs_node_get_security(fs->root)->ref_count == 1);
    memfs_allocator_get_stats(&fs->allocator, &final);
    CHECK(final.live_bytes == baseline.live_bytes);
    printf("orphan scenario=%u nodes=%u live_before=%llu live_after=%llu\n",
           scenario, NODES, (unsigned long long)baseline.live_bytes,
           (unsigned long long)final.live_bytes);
    memfs_destroy(fs);
}

int main(int argc, char** argv) {
    bool refs = reference_counts();
    if (argc > 1 && strcmp(argv[1], "--references-only") == 0) return refs ? 0 : 1;
    if (!refs) return 1;
    for (unsigned round = 0; round < 8; ++round) {
        orphan_transitions(0); /* many independent final closes */
        orphan_transitions(1); /* unlink versus last close */
        orphan_transitions(2); /* replacement rename versus last close */
    }
    printf("memfs_lifetime_test: %s (%d failures)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
