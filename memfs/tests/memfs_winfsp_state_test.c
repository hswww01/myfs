#include <stdio.h>
#include <string.h>

#include "memfs_winfsp.h"
#include <sddl.h>

static int g_failures;

#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fprintf(stderr, "CHECK failed: %s:%d: %s\n",                     \
                    __FILE__, __LINE__, #expr);                                \
            g_failures++;                                                      \
        }                                                                      \
    } while (0)

typedef struct SecurityWorker {
    FSP_FILE_SYSTEM* fs;
    MemfsNode* node;
    HANDLE start;
    HANDLE ready;
    HANDLE done;
    PSECURITY_DESCRIPTOR descriptor[2];
    volatile LONG errors;
    unsigned iterations;
    bool writer;
} SecurityWorker;

static DWORD WINAPI security_worker(void* opaque) {
    SecurityWorker* w = opaque;
    if (WaitForSingleObject(w->start, 10000) != WAIT_OBJECT_0)
        return 1;
    if (w->ready) SetEvent(w->ready);
    for (unsigned i = 0; i < w->iterations; ++i) {
        NTSTATUS status;
        if (w->writer) {
            status = memfs_winfsp_test_set_security(w->fs, w->node,
                DACL_SECURITY_INFORMATION, w->descriptor[i & 1]);
        } else {
            union { UINT64 alignment; BYTE data[4096]; } buffer;
            SIZE_T bytes = sizeof(buffer.data);
            if (i & 1)
                status = memfs_winfsp_test_get_security(w->fs, w->node, buffer.data, &bytes);
            else
                status = memfs_winfsp_test_get_security_by_name(w->fs, L"\\acl", buffer.data, &bytes);
            if (NT_SUCCESS(status) &&
                (bytes > sizeof(buffer.data) || !IsValidSecurityDescriptor(buffer.data)))
                InterlockedIncrement(&w->errors);
        }
        if (!NT_SUCCESS(status)) InterlockedIncrement(&w->errors);
    }
    if (w->done) SetEvent(w->done);
    return 0;
}

static void test_security_snapshot_guards(void) {
    Memfs* store = NULL;
    MemfsNode* node = NULL;
    FSP_FILE_SYSTEM fs;
    MemfsWinFsp instance;
    SecurityWorker workers[3];
    HANDLE handles[3] = {0};
    HANDLE start = NULL, ready = NULL, done = NULL;
    PSECURITY_DESCRIPTOR descriptors[2] = {0};
    DWORD count = 0;
    memset(&fs, 0, sizeof(fs));
    memset(&instance, 0, sizeof(instance));
    memset(workers, 0, sizeof(workers));
    CHECK(memfs_create(64ULL << 20, L"SD_GUARDS", &store) == MEMFS_OK);
    if (!store) return;
    CHECK(memfs_node_create(store, store->root, L"acl", false, FILE_ATTRIBUTE_NORMAL,
                           NULL, 0, &node) == MEMFS_OK);
    if (!node) goto cleanup;
    instance.store = store;
    instance.file_system = &fs;
    fs.UserContext = &instance;
    CHECK(fs_frontend_backend_context(&fs) == &instance);
    InitializeSRWLock(&fs.OpGuardLock);
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)",
        SDDL_REVISION_1, &descriptors[0], NULL));
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)",
        SDDL_REVISION_1, &descriptors[1], NULL));
    if (!descriptors[0] || !descriptors[1]) goto cleanup;
    start = CreateEventW(NULL, TRUE, TRUE, NULL);
    ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    done = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(start && ready && done);
    if (!start || !ready || !done) goto cleanup;
    workers[0] = (SecurityWorker){&fs, node, start, ready, done,
        {descriptors[0], descriptors[1]}, 0, 1, true};
    /* Mirror a FILE_OPEN borrow of the descriptor under FINE's shared guard.
     * SetSecurity must not free that snapshot until the borrow ends. */
    AcquireSRWLockShared(&fs.OpGuardLock);
    handles[0] = CreateThread(NULL, 0, security_worker, &workers[0], 0, NULL);
    CHECK(handles[0] != NULL);
    if (handles[0]) {
        CHECK(WaitForSingleObject(ready, 10000) == WAIT_OBJECT_0);
        CHECK(WaitForSingleObject(done, 50) == WAIT_TIMEOUT);
    }
    ReleaseSRWLockShared(&fs.OpGuardLock);
    if (!handles[0]) goto cleanup;
    if (WaitForSingleObject(handles[0], 10000) != WAIT_OBJECT_0) ExitProcess(2);
    CHECK(workers[0].errors == 0);
    CloseHandle(handles[0]); handles[0] = NULL;
    ResetEvent(start);
    for (unsigned i = 0; i < 3; ++i) {
        workers[i] = (SecurityWorker){&fs, node, start, NULL, NULL,
            {descriptors[0], descriptors[1]}, 0, i == 0 ? 2000U : 10000U, i == 0};
        handles[i] = CreateThread(NULL, 0, security_worker, &workers[i], 0, NULL);
        CHECK(handles[i] != NULL);
        if (!handles[i]) break;
        ++count;
    }
    SetEvent(start);
    if (count && WaitForMultipleObjects(count, handles, TRUE, 30000) != WAIT_OBJECT_0)
        ExitProcess(2);
    for (unsigned i = 0; i < count; ++i) {
        DWORD code = 1;
        CHECK(GetExitCodeThread(handles[i], &code) && code == 0);
        CHECK(workers[i].errors == 0);
        CloseHandle(handles[i]); handles[i] = NULL;
    }
    CHECK(count == 3);
    CHECK(IsValidSecurityDescriptor(memfs_node_get_security(node)->data));
    puts("security snapshot: 2000 replacements / 20000 callback reads PASS");
cleanup:
    if (start) CloseHandle(start);
    if (ready) CloseHandle(ready);
    if (done) CloseHandle(done);
    if (descriptors[0]) LocalFree(descriptors[0]);
    if (descriptors[1]) LocalFree(descriptors[1]);
    if (node) { CHECK(memfs_node_unlink(node) == MEMFS_OK); memfs_node_close(node); }
    memfs_destroy(store);
}

static void test_case_sensitive_directory_info(void) {
    Memfs* store = NULL;
    MemfsNode* upper = NULL;
    MemfsNode* lower = NULL;
    FSP_FILE_SYSTEM fs;
    MemfsWinFsp instance;
    union {
        UINT64 alignment;
        BYTE bytes[sizeof(FSP_FSCTL_DIR_INFO) + 64 * sizeof(WCHAR)];
    } buffer;
    FSP_FSCTL_DIR_INFO* dir_info = (FSP_FSCTL_DIR_INFO*)buffer.bytes;
    NTSTATUS status;

    memset(&fs, 0, sizeof(fs));
    memset(&instance, 0, sizeof(instance));
    CHECK(memfs_create(8ULL << 20, L"CASE_INFO", &store) == MEMFS_OK);
    if (store == NULL)
        return;
    CHECK(memfs_node_create(store, store->root, L"Case.txt", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &upper) == MEMFS_OK);
    CHECK(memfs_node_create(store, store->root, L"case.txt", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &lower) == MEMFS_OK);
    if (upper == NULL || lower == NULL)
        goto cleanup;

    instance.store = store;
    instance.file_system = &fs;
    fs.UserContext = &instance;
    CHECK(fs_frontend_backend_context(&fs) == &instance);
    status = memfs_winfsp_test_get_dir_info_by_name(&fs, store->root,
        L"Case.txt", dir_info);
    CHECK(NT_SUCCESS(status));
    if (NT_SUCCESS(status))
        CHECK(memcmp(dir_info->FileNameBuf, L"Case.txt",
            wcslen(L"Case.txt") * sizeof(WCHAR)) == 0);

    status = memfs_winfsp_test_get_dir_info_by_name(&fs, store->root,
        L"case.txt", dir_info);
    CHECK(NT_SUCCESS(status));
    if (NT_SUCCESS(status))
        CHECK(memcmp(dir_info->FileNameBuf, L"case.txt",
            wcslen(L"case.txt") * sizeof(WCHAR)) == 0);

    status = memfs_winfsp_test_get_dir_info_by_name(&fs, store->root,
        L"CASE.TXT", dir_info);
    CHECK(status == STATUS_OBJECT_NAME_NOT_FOUND);

cleanup:
    if (upper != NULL) {
        if (!upper->deleted)
            (void)memfs_node_unlink(upper);
        memfs_node_close(upper);
    }
    if (lower != NULL) {
        if (!lower->deleted)
            (void)memfs_node_unlink(lower);
        memfs_node_close(lower);
    }
    memfs_destroy(store);
}

static void test_volume_reports(void) {
    MemfsOptions options = {0};
    Memfs* store = NULL;
    FSP_FILE_SYSTEM fs = {0};
    MemfsWinFsp instance = {0};
    FSP_FSCTL_VOLUME_INFO info;
    FSP_FSCTL_VOLUME_PARAMS params;
    const uint64_t capacity = 8ULL << 20;
    const uint64_t used = 4096;

    memfs_winfsp_test_volume_params(&params);
    CHECK(params.MaxComponentLength == MEMFS_MAX_NAME);
    CHECK(params.CaseSensitiveSearch && params.CasePreservedNames);
    CHECK(params.SectorSize == MEMFS_ALLOCATION_UNIT);

    CHECK(memfs_create(capacity, L"FIXED", &store) == MEMFS_OK);
    if (store == NULL)
        return;
    instance.store = store;
    fs.UserContext = &instance;
    InterlockedExchange64(&store->used_bytes, (LONG64)used);
    CHECK(NT_SUCCESS(memfs_winfsp_test_get_volume_info(&fs, &info)));
    CHECK(info.TotalSize == capacity);
    CHECK(info.FreeSize == capacity - used);
    InterlockedExchange64(&store->used_bytes, 0);
    memfs_destroy(store);

    options.capacity_auto = true;
    CHECK(memfs_create_ex(&options, &store) == MEMFS_OK);
    if (store == NULL)
        return;
    instance.store = store;
    InterlockedExchange64(&store->used_bytes, (LONG64)used);
    CHECK(NT_SUCCESS(memfs_winfsp_test_get_volume_info(&fs, &info)));
    CHECK(info.TotalSize >= info.FreeSize);
    CHECK(info.TotalSize - info.FreeSize == used);
    CHECK(info.TotalSize <= INT64_MAX);

    /* Boundary accounting samples must not overflow the signed WinFsp
     * allocation-unit fields or report more free bytes than total bytes. */
    InterlockedExchange64(&store->used_bytes, INT64_MAX - 16);
    CHECK(NT_SUCCESS(memfs_winfsp_test_get_volume_info(&fs, &info)));
    CHECK(info.TotalSize >= info.FreeSize);
    CHECK(info.TotalSize - info.FreeSize == (uint64_t)INT64_MAX - 16);
    CHECK(info.TotalSize <= INT64_MAX && info.FreeSize <= 16);
    InterlockedExchange64(&store->used_bytes, INT64_MAX);
    CHECK(NT_SUCCESS(memfs_winfsp_test_get_volume_info(&fs, &info)));
    CHECK(info.TotalSize == INT64_MAX && info.FreeSize == 0);
    InterlockedExchange64(&store->used_bytes, 0);
    memfs_destroy(store);
}

static void test_archive_attributes(void) {
    Memfs* store = NULL;
    MemfsNode* node = NULL;
    FSP_FILE_SYSTEM fs = {0};
    MemfsWinFsp instance = {0};
    FSP_FSCTL_FILE_INFO info;

    CHECK(memfs_create(8ULL << 20, L"ATTRIBUTES", &store) == MEMFS_OK);
    if (store == NULL)
        return;
    instance.store = store;
    fs.UserContext = &instance;
    CHECK(memfs_node_create(store, store->root, L"normal", false,
        FILE_ATTRIBUTE_NORMAL, NULL, 0, &node) == MEMFS_OK);
    if (node != NULL) {
        memfs_winfsp_test_cleanup(&fs, node, FspCleanupSetArchiveBit);
        CHECK(node->attributes == FILE_ATTRIBUTE_ARCHIVE);

        node->attributes = FILE_ATTRIBUTE_NORMAL;
        CHECK(NT_SUCCESS(memfs_winfsp_test_overwrite(&fs, node, 0,
            FALSE, 0, &info)));
        CHECK(node->attributes == FILE_ATTRIBUTE_ARCHIVE);
        CHECK(info.FileAttributes == FILE_ATTRIBUTE_ARCHIVE);
        CHECK(memfs_node_unlink(node) == MEMFS_OK);
        memfs_node_close(node);
    }
    memfs_destroy(store);
}

static void test_unlinked_directory_read(void) {
    Memfs* store = NULL;
    MemfsNode* directory = NULL;
    FSP_FILE_SYSTEM fs = {0};
    MemfsWinFsp instance = {0};
    union { UINT64 alignment; BYTE bytes[2048]; } buffer;
    ULONG transferred = 0;
    ULONG position = 0;
    unsigned dots = 0;
    NTSTATUS status;

    CHECK(memfs_create(8ULL << 20, L"UNLINKED", &store) == MEMFS_OK);
    if (store == NULL)
        return;
    instance.store = store;
    fs.UserContext = &instance;
    CHECK(memfs_node_create(store, store->root, L"empty", true,
        FILE_ATTRIBUTE_DIRECTORY, NULL, 0, &directory) == MEMFS_OK);
    if (directory != NULL) {
        CHECK(memfs_node_unlink(directory) == MEMFS_OK);
        CHECK(directory->deleted && directory->parent == NULL);
        memset(&buffer, 0xA5, sizeof(buffer));
        status = memfs_winfsp_test_read_directory(&fs, directory, NULL,
            NULL, buffer.bytes, sizeof(buffer.bytes), &transferred);
        CHECK(NT_SUCCESS(status));
        CHECK(transferred <= sizeof(buffer.bytes));
        while (position + sizeof(UINT16) <= transferred) {
            FSP_FSCTL_DIR_INFO* entry = (FSP_FSCTL_DIR_INFO*)(buffer.bytes + position);
            ULONG name_bytes;
            if (entry->Size == 0)
                break;
            CHECK(entry->Size >= sizeof(*entry));
            if (entry->Size < sizeof(*entry) || entry->Size > transferred - position)
                break;
            name_bytes = entry->Size - (ULONG)sizeof(*entry);
            CHECK((name_bytes == sizeof(WCHAR) &&
                memcmp(entry->FileNameBuf, L".", name_bytes) == 0) ||
                (name_bytes == 2 * sizeof(WCHAR) &&
                memcmp(entry->FileNameBuf, L"..", name_bytes) == 0));
            CHECK(entry->FileInfo.IndexNumber == memfs_node_index_number(directory));
            ++dots;
            position += (entry->Size + 7U) & ~7U;
        }
        CHECK(dots == 2);
        memfs_node_close(directory);
    }
    memfs_destroy(store);
}

static void test_unlinked_directory_child(void) {
    wchar_t executable[MAX_PATH];
    wchar_t command[MAX_PATH + 40];
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD chars, code = 1, wait;

    chars = GetModuleFileNameW(NULL, executable, _countof(executable));
    CHECK(chars != 0 && chars < _countof(executable));
    if (chars == 0 || chars >= _countof(executable))
        return;
    CHECK(swprintf_s(command, _countof(command),
        L"\"%s\" --unlinked-directory-read", executable) > 0);
    startup.cb = sizeof(startup);
    CHECK(CreateProcessW(executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
    if (process.hProcess == NULL)
        return;
    wait = WaitForSingleObject(process.hProcess, 10000);
    CHECK(wait == WAIT_OBJECT_0);
    if (wait != WAIT_OBJECT_0) {
        /* This child owns only a disposable in-process fixture. */
        TerminateProcess(process.hProcess, 2);
        WaitForSingleObject(process.hProcess, 10000);
    }
    CHECK(GetExitCodeProcess(process.hProcess, &code));
    printf("unlinked directory callback child exit=0x%08lX\n", code);
    CHECK(code == 0);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--unlinked-directory-read") == 0) {
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        test_unlinked_directory_read();
        return g_failures ? 1 : 0;
    }
    CHECK(memfs_winfsp_test_name_matches_pattern(NULL, L"anything.bin"));
    CHECK(memfs_winfsp_test_name_matches_pattern(L"*", L"anything.bin"));
    CHECK(memfs_winfsp_test_name_matches_pattern(L"*.TXT", L"readme.TXT"));
    CHECK(!memfs_winfsp_test_name_matches_pattern(L"*.TXT", L"readme.txt"));
    CHECK(memfs_winfsp_test_name_matches_pattern(L"file?.dat", L"file1.dat"));
    CHECK(!memfs_winfsp_test_name_matches_pattern(L"file?.dat", L"FILE1.DAT"));
    CHECK(memfs_winfsp_test_name_matches_pattern(L"foo*", L"foobar"));
    CHECK(!memfs_winfsp_test_name_matches_pattern(L"foo*", L"Foobar"));
    CHECK(!memfs_winfsp_test_name_matches_pattern(L"*.txt", L"image.bin"));
    CHECK(!memfs_winfsp_test_name_matches_pattern(L"file?.dat", L"file12.dat"));

    test_security_snapshot_guards();
    test_case_sensitive_directory_info();
    test_volume_reports();
    test_archive_attributes();
    test_unlinked_directory_child();

    if (g_failures != 0) {
        fprintf(stderr, "memfs_winfsp_state_test: %d failure(s)\n", g_failures);
        return 1;
    }

    printf("memfs_winfsp_state_test: OK\n");
    return 0;
}
