#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "memfs_core.h"

#define MAX_THREADS 16
#define OPS_PER_THREAD 30000U

typedef struct Worker {
    MemfsNode *node;
    HANDLE start_event;
    uint32_t id;
    LONG errors;
} Worker;

static DWORD WINAPI worker_main(void *arg) {
    Worker *w = (Worker *)arg;
    uint8_t page[MEMFS_PAGE_SIZE];
    uint32_t written;
    WaitForSingleObject(w->start_event, INFINITE);
    for (uint32_t i = 0; i < OPS_PER_THREAD; ++i) {
        memset(page, (int)((w->id * 29U + i) & 0xffU), sizeof(page));
        written = 0;
        if (memfs_node_write(w->node, page, 0, sizeof(page), false, false, &written) != MEMFS_OK ||
            written != sizeof(page)) {
            InterlockedIncrement(&w->errors);
            break;
        }
    }
    return 0;
}

static int run_case(int thread_count) {
    MemfsOptions options;
    Memfs *fs = NULL;
    Worker workers[MAX_THREADS];
    HANDLE threads[MAX_THREADS] = {0};
    HANDLE start_event = NULL;
    uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
    LARGE_INTEGER freq, begin, end;
    double seconds, ops_per_sec;
    LONG errors = 0;
    int result = 1;

    memset(&options, 0, sizeof(options));
    memset(workers, 0, sizeof(workers));
    for (uint32_t i = 0; i < sizeof(key); ++i)
        key[i] = (uint8_t)(0xa5U ^ i);
    options.capacity = 1024ULL * 1024ULL * 1024ULL;
    options.encryption_enabled = true;
    options.encryption_key = key;
    options.encryption_key_size = sizeof(key);
    options.volume_label = L"NONCEBENCH";

    if (memfs_create_ex(&options, &fs) != MEMFS_OK || fs == NULL)
        goto cleanup;
    printf("algorithm=%s threads=%d\n",
           fs->encryption_aes_gcm ? "aes-256-gcm" : "xchacha20-poly1305",
           thread_count);
    start_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (start_event == NULL)
        goto cleanup;

    for (int i = 0; i < thread_count; ++i) {
        wchar_t name[32];
        swprintf_s(name, _countof(name), L"t%02d.bin", i);
        if (memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL,
                              NULL, 0, &workers[i].node) != MEMFS_OK ||
            workers[i].node == NULL)
            goto cleanup;
        workers[i].start_event = start_event;
        workers[i].id = (uint32_t)i;
        threads[i] = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
        if (threads[i] == NULL)
            goto cleanup;
    }

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&begin);
    SetEvent(start_event);
    if (WaitForMultipleObjects((DWORD)thread_count, threads, TRUE, INFINITE) != WAIT_OBJECT_0)
        goto cleanup;
    QueryPerformanceCounter(&end);

    for (int i = 0; i < thread_count; ++i)
        errors += workers[i].errors;
    seconds = (double)(end.QuadPart - begin.QuadPart) / (double)freq.QuadPart;
    ops_per_sec = seconds > 0.0
        ? ((double)thread_count * OPS_PER_THREAD) / seconds : 0.0;
    printf("threads=%2d ops=%u seconds=%.6f ops/s=%.0f ns/op=%.1f errors=%ld\n",
           thread_count, (unsigned)(thread_count * OPS_PER_THREAD), seconds,
           ops_per_sec, ops_per_sec > 0.0 ? 1e9 / ops_per_sec : 0.0, errors);
    result = errors == 0 ? 0 : 1;

cleanup:
    if (start_event)
        SetEvent(start_event);
    for (int i = 0; i < thread_count; ++i) {
        if (threads[i]) {
            WaitForSingleObject(threads[i], INFINITE);
            CloseHandle(threads[i]);
        }
        if (workers[i].node) {
            (void)memfs_node_unlink(workers[i].node);
            memfs_node_close(workers[i].node);
        }
    }
    if (start_event)
        CloseHandle(start_event);
    if (fs)
        memfs_destroy(fs);
    return result;
}

int main(void) {
    static const int counts[] = {1, 2, 4, 8, 16};
    for (size_t i = 0; i < _countof(counts); ++i) {
        if (run_case(counts[i]) != 0)
            return 1;
    }
    return 0;
}
