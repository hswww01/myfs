#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "cryptfs_format.h"
#include "cryptfs_crypto.h"
#include "cryptfs_store.h"

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static const uint8_t g_password[] = "cryptfs-test-only-password";
static wchar_t g_container[MAX_PATH * 2];
static wchar_t g_backup[MAX_PATH * 2];
static wchar_t g_directory[MAX_PATH * 2];
static wchar_t g_executable[MAX_PATH * 2];
static uint64_t g_second_child_id;
static uint64_t g_auth_parent_id;

static BOOL
make_test_path(void)
{
    wchar_t module_path[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(NULL, g_executable, ARRAYSIZE(g_executable));
    wchar_t *slash;
    if (n == 0 || n >= ARRAYSIZE(g_executable))
        return FALSE;
    wcscpy_s(module_path, ARRAYSIZE(module_path), g_executable);
    slash = wcsrchr(module_path, L'\\');
    if (slash == NULL)
        return FALSE;
    *slash = L'\0';
    if (wcscpy_s(g_directory, ARRAYSIZE(g_directory), module_path) != 0)
        return FALSE;
    if (_snwprintf_s(g_container, ARRAYSIZE(g_container), _TRUNCATE,
        L"%ls\\cryptfs-store-test-%lu.cf", module_path,
        (unsigned long)GetCurrentProcessId()) < 0)
        return FALSE;
    return _snwprintf_s(g_backup, ARRAYSIZE(g_backup), _TRUNCATE,
        L"%ls\\cryptfs-store-test-%lu-pristine.cf", module_path,
        (unsigned long)GetCurrentProcessId()) >= 0;
}

static CF_RESULT
open_store(const wchar_t *path, BOOL create_new, BOOL background, CF_STORE **store)
{
    CF_OPTIONS options;
    memset(&options, 0, sizeof(options));
    options.container = path;
    options.capacity = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    options.compression_level = 3;
    options.create_new = create_new != FALSE;
    options.background_compaction = background != FALSE;
    return cf_store_open(&options, g_password, sizeof(g_password) - 1, store);
}

static BOOL
copy_sparse_container(const wchar_t *source, const wchar_t *destination)
{
    HANDLE file;
    FILE_SET_SPARSE_BUFFER sparse;
    DWORD returned = 0;
    BOOL ok;
    if (!CopyFileW(source, destination, FALSE))
        return FALSE;
    file = CreateFileW(destination, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "sparse fixture copy: open failed (error %lu)\n",
            (unsigned long)GetLastError());
        DeleteFileW(destination);
        return FALSE;
    }
    sparse.SetSparse = TRUE;
    ok = DeviceIoControl(file, FSCTL_SET_SPARSE, &sparse, sizeof(sparse),
        NULL, 0, &returned, NULL);
    if (!ok)
        fprintf(stderr, "sparse fixture copy: FSCTL_SET_SPARSE failed (error %lu)\n",
            (unsigned long)GetLastError());
    CloseHandle(file);
    if (!ok)
        DeleteFileW(destination);
    return ok;
}

static BOOL
write_byte(CF_STORE *store, CF_NODE *node, uint64_t offset, uint8_t value)
{
    uint32_t transferred = 0;
    return cf_node_write(store, node, &value, offset, 1, FALSE, FALSE,
        &transferred) == CF_OK && transferred == 1;
}

static BOOL
read_byte(CF_STORE *store, CF_NODE *node, uint64_t offset, uint8_t *value)
{
    uint32_t transferred = 0;
    return cf_node_read(store, node, value, offset, 1, &transferred) == CF_OK &&
        transferred == 1;
}

static BOOL
hash_file(const wchar_t *path, uint8_t digest[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD object_size = 0, got = 0;
    uint8_t *object = NULL;
    uint8_t buffer[64 * 1024];
    HANDLE file = INVALID_HANDLE_VALUE;
    BOOL ok = FALSE;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
        NULL, 0);
    if (status < 0)
        goto done;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size, sizeof(object_size), &got, 0);
    if (status < 0 || got != sizeof(object_size) || object_size == 0)
        goto done;
    object = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, object_size);
    if (object == NULL)
        goto done;
    status = BCryptCreateHash(algorithm, &hash, object, object_size, NULL, 0, 0);
    if (status < 0)
        goto done;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto done;
    for (;;) {
        DWORD read_bytes = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &read_bytes, NULL))
            goto done;
        if (read_bytes == 0)
            break;
        status = BCryptHashData(hash, buffer, read_bytes, 0);
        if (status < 0)
            goto done;
    }
    status = BCryptFinishHash(hash, digest, 32, 0);
    ok = status >= 0;
done:
    SecureZeroMemory(buffer, sizeof(buffer));
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (hash != NULL)
        BCryptDestroyHash(hash);
    if (object != NULL) {
        SecureZeroMemory(object, object_size);
        HeapFree(GetProcessHeap(), 0, object);
    }
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static BOOL
mutate_container_byte(const wchar_t *path, uint64_t offset)
{
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER position;
    uint8_t byte;
    DWORD count = 0;
    BOOL ok = FALSE;
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    position.QuadPart = (LONGLONG)offset;
    if (SetFilePointerEx(file, position, NULL, FILE_BEGIN) &&
        ReadFile(file, &byte, 1, &count, NULL) && count == 1) {
        byte ^= 0x80u;
        position.QuadPart = (LONGLONG)offset;
        if (SetFilePointerEx(file, position, NULL, FILE_BEGIN) &&
            WriteFile(file, &byte, 1, &count, NULL) && count == 1 &&
            FlushFileBuffers(file))
            ok = TRUE;
    }
    CloseHandle(file);
    return ok;
}

static BOOL
find_record_page_offset(const wchar_t *path, uint16_t record_type,
    uint64_t record_id, unsigned occurrence, uint64_t *offset_out)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER size, position;
    uint8_t page[CF_PAGE_SIZE];
    BOOL found = FALSE;
    unsigned matches = 0;
    uint64_t offset;
    if (file == INVALID_HANDLE_VALUE || offset_out == NULL) {
        fprintf(stderr, "graph fixture: cannot open container or invalid page-offset output\n");
        return FALSE;
    }
    if (!GetFileSizeEx(file, &size)) {
        fprintf(stderr, "graph fixture: GetFileSizeEx failed (error %lu)\n",
            (unsigned long)GetLastError());
        goto done;
    }
    for (offset = CF_PAGES_OFFSET; offset + CF_PAGE_SIZE <= (uint64_t)size.QuadPart;
        offset += CF_PAGE_SIZE) {
        DWORD read_bytes = 0;
        position.QuadPart = (LONGLONG)offset;
        if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN) ||
            !ReadFile(file, page, sizeof(page), &read_bytes, NULL) ||
            read_bytes != sizeof(page))
            { fprintf(stderr, "record fixture: failed reading page at offset %llu\n",
                (unsigned long long)offset); goto done; }
        if (memcmp(page, "CFRP", 4) == 0 &&
            cf_get_u16(page + 4) == CF_FORMAT_VERSION &&
            cf_get_u16(page + 6) == record_type &&
            cf_get_u64(page + 8) == record_id) {
            ++matches;
            if (matches == occurrence) {
                *offset_out = offset;
                found = TRUE;
                break;
            }
        }
    }
done:
    if (!found)
        fprintf(stderr, "record fixture: type %u record %llu occurrence %u not found (found %u, file size %llu)\n",
            (unsigned)record_type, (unsigned long long)record_id,
            occurrence, matches,
            (unsigned long long)(GetFileSizeEx(file, &size) ? size.QuadPart : 0));
    SecureZeroMemory(page, sizeof(page));
    CloseHandle(file);
    return found;
}

static BOOL
find_inode_page_offset(const wchar_t *path, uint64_t record_id,
    uint64_t *offset_out)
{
    return find_record_page_offset(path, CF_RECORD_INODE, record_id, 1, offset_out);
}

static BOOL
derive_test_record_keys(const wchar_t *path, uint8_t uuid[16], CF_KEYS *keys)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER position;
    uint8_t sb[CF_PAGE_SIZE], aad[80 + CF_PAGE_SIZE - CF_SB_RESERVED];
    uint8_t wrapping_key[CF_KEY_BYTES], master[CF_KEY_BYTES];
    DWORD read_bytes = 0;
    size_t plain_length = 0;
    BOOL ok = FALSE;
    if (uuid == NULL || keys == NULL) {
        fprintf(stderr, "graph fixture: invalid key-derivation output\n");
        return FALSE;
    }
    if (!cf_crypto_init()) {
        fprintf(stderr, "graph fixture: crypto initialization failed\n");
        return FALSE;
    }
    memset(sb, 0, sizeof(sb)); memset(aad, 0, sizeof(aad));
    memset(wrapping_key, 0, sizeof(wrapping_key));
    memset(master, 0, sizeof(master)); memset(keys, 0, sizeof(*keys));
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "graph fixture: derive keys cannot open container (error %lu)\n",
            (unsigned long)GetLastError());
        goto done;
    }
    position.QuadPart = CF_SB0_OFFSET;
    if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN) ||
        !ReadFile(file, sb, sizeof(sb), &read_bytes, NULL) ||
        read_bytes != sizeof(sb)) {
        fprintf(stderr, "graph fixture: derive keys cannot read superblock (error %lu, bytes %lu)\n",
            (unsigned long)GetLastError(), (unsigned long)read_bytes);
        goto done;
    }
    memcpy(aad, sb, 80);
    memcpy(aad + 80, sb + CF_SB_RESERVED, CF_PAGE_SIZE - CF_SB_RESERVED);
    if (!cf_password_key(g_password, sizeof(g_password) - 1,
        sb + CF_SB_SALT, cf_get_u64(sb + CF_SB_KDF_OPS),
        cf_get_u64(sb + CF_SB_KDF_MEM), wrapping_key)) {
        fprintf(stderr, "graph fixture: password KDF failed\n");
        goto done;
    }
    if (!cf_decrypt(wrapping_key, sb + CF_SB_WRAP_NONCE,
        aad, sizeof(aad), sb + CF_SB_WRAPPED_KEY,
        CF_KEY_BYTES + CF_TAG_BYTES, master, sizeof(master), &plain_length) ||
        plain_length != sizeof(master)) {
        fprintf(stderr, "graph fixture: wrapped master-key decrypt failed (plain length %zu)\n",
            plain_length);
        goto done;
    }
    memcpy(uuid, sb + CF_SB_UUID, 16);
    ok = cf_keys_derive(master, keys);
    if (!ok)
        fprintf(stderr, "graph fixture: record subkey derivation failed\n");
done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    cf_wipe(sb, sizeof(sb)); cf_wipe(aad, sizeof(aad));
    cf_wipe(wrapping_key, sizeof(wrapping_key)); cf_wipe(master, sizeof(master));
    if (!ok) {
        cf_wipe(uuid, 16);
        cf_wipe(keys, sizeof(*keys));
    }
    return ok;
}

static BOOL
rewrite_inode_payload_u64(const wchar_t *path, const uint8_t uuid[16],
    const CF_KEYS *keys, uint64_t record_id, uint32_t payload_offset,
    uint64_t value)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    uint64_t page_offset, slot;
    LARGE_INTEGER position;
    uint8_t page[CF_PAGE_SIZE], aad[72], payload[CF_PAYLOAD_SIZE];
    uint8_t nonce[CF_NONCE_BYTES];
    DWORD read_bytes = 0, written = 0;
    size_t plain_length = 0;
    BOOL ok = FALSE;
    if (uuid == NULL || keys == NULL ||
        payload_offset > CF_PAYLOAD_SIZE - sizeof(uint64_t) ||
        !find_inode_page_offset(path, record_id, &page_offset)) {
        fprintf(stderr, "graph fixture: cannot locate/decrypt target inode record %llu\n",
            (unsigned long long)record_id);
        return FALSE;
    }
    slot = (page_offset - CF_PAGES_OFFSET) / CF_PAGE_SIZE + 1;
    memset(page, 0, sizeof(page)); memset(aad, 0, sizeof(aad));
    memset(payload, 0, sizeof(payload)); memset(nonce, 0, sizeof(nonce));
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "graph fixture: rewrite cannot open container (error %lu)\n",
            (unsigned long)GetLastError());
        goto done;
    }
    position.QuadPart = (LONGLONG)page_offset;
    if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN) ||
        !ReadFile(file, page, sizeof(page), &read_bytes, NULL) ||
        read_bytes != sizeof(page) || memcmp(page, "CFRP", 4) != 0 ||
        cf_get_u16(page + 4) != CF_FORMAT_VERSION ||
        cf_get_u16(page + 6) != CF_RECORD_INODE ||
        cf_get_u64(page + 8) != record_id) {
        fprintf(stderr, "graph fixture: rewrite page header mismatch/read failure (record %llu, bytes %lu)\n",
            (unsigned long long)record_id, (unsigned long)read_bytes);
        goto done;
    }
    memcpy(aad, uuid, 16);
    cf_put_u64(aad + 16, slot);
    memcpy(aad + 24, page, CF_PAGE_HEADER_SIZE);
    if (!cf_decrypt(keys->records, page + 24, aad, sizeof(aad),
        page + CF_PAGE_HEADER_SIZE, CF_PAGE_CIPHER_SIZE, payload,
        sizeof(payload), &plain_length) || plain_length != sizeof(payload)) {
        fprintf(stderr, "graph fixture: target inode AEAD decrypt failed (record %llu, plain %zu)\n",
            (unsigned long long)record_id, plain_length);
        goto done;
    }
    cf_put_u64(payload + payload_offset, value);
    cf_random(nonce, sizeof(nonce));
    memcpy(page + 24, nonce, sizeof(nonce));
    memcpy(aad + 24, page, CF_PAGE_HEADER_SIZE);
    if (!cf_encrypt(keys->records, nonce, aad, sizeof(aad), payload,
        sizeof(payload), page + CF_PAGE_HEADER_SIZE, CF_PAGE_CIPHER_SIZE))
        goto done;
    position.QuadPart = (LONGLONG)page_offset;
    if (!SetFilePointerEx(file, position, NULL, FILE_BEGIN) ||
        !WriteFile(file, page, sizeof(page), &written, NULL) ||
        written != sizeof(page) || !FlushFileBuffers(file)) {
        fprintf(stderr, "graph fixture: authenticated inode page write/flush failed (error %lu, bytes %lu)\n",
            (unsigned long)GetLastError(), (unsigned long)written);
        goto done;
    }
    ok = TRUE;
done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    cf_wipe(page, sizeof(page)); cf_wipe(aad, sizeof(aad));
    cf_wipe(payload, sizeof(payload)); cf_wipe(nonce, sizeof(nonce));
    return ok;
}

static int
run_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_RESULT result;
    uint8_t value = (uint8_t)('A' + phase);
    uint32_t transferred = 0;
    result = open_store(path, FALSE, FALSE, &store);
    if (result != CF_OK)
        return 20;
    result = cf_node_open(store, L"\\crash", &node);
    if (result != CF_OK) {
        cf_store_close(store);
        return 21;
    }
    cf_test_crash_phase(phase);
    result = cf_node_write(store, node, &value, 0, 1, FALSE, FALSE,
        &transferred);
    cf_node_close(store, node);
    cf_store_close(store);
    return result == CF_OK && transferred == 1 ? 22 : 23;
}

static int
run_resize_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_RESULT result = open_store(path, FALSE, FALSE, &store);
    if (result != CF_OK)
        return 50;
    result = cf_node_open(store, L"\\resize-crash", &node);
    if (result != CF_OK) {
        cf_store_close(store);
        return 51;
    }
    cf_test_crash_phase(phase);
    result = cf_node_resize(store, node, 1024, FALSE);
    cf_node_close(store, node);
    cf_store_close(store);
    return result == CF_OK ? 52 : 53;
}

static int
run_map_trim_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        return 54;
    if (cf_node_open(store, L"\\map-crash", &node) != CF_OK) {
        cf_store_close(store);
        return 55;
    }
    cf_test_crash_phase(phase);
    if (cf_node_resize(store, node, 63ULL * CF_BLOCK_SIZE, FALSE) != CF_OK)
        return 56;
    cf_node_close(store, node);
    cf_store_close(store);
    return 57;
}

static BOOL
run_resize_crash_phase(unsigned phase)
{
    wchar_t path[MAX_PATH * 2], command[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_INFO info;
    uint8_t *initial = NULL, *tail = NULL;
    uint32_t transferred = 0, i;
    DWORD exit_code = 0;
    size_t tail_length = CF_BLOCK_SIZE - 1024u;
    BOOL ok = FALSE;
    if (phase < 1 || phase > 5 ||
        _snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
            L"%ls\\cryptfs-resize-crash-%lu-%u.cf", g_directory,
            (unsigned long)GetCurrentProcessId(), phase) < 0)
        return FALSE;
    DeleteFileW(path);
    initial = (uint8_t *)malloc(CF_BLOCK_SIZE);
    tail = (uint8_t *)malloc(tail_length);
    if (!initial || !tail)
        goto done;
    for (i = 0; i < CF_BLOCK_SIZE; ++i)
        initial[i] = (uint8_t)(i * 37u + 11u);
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\resize-crash", FILE_ATTRIBUTE_NORMAL,
            &node) != CF_OK ||
        cf_node_write(store, node, initial, 0, CF_BLOCK_SIZE, FALSE, FALSE,
            &transferred) != CF_OK || transferred != CF_BLOCK_SIZE ||
        cf_store_flush(store) != CF_OK)
        goto done;
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" --resize-crash \"%ls\" %u", g_executable,
        path, phase) < 0)
        goto done;
    memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    if (!CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        goto done;
    if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code) ||
        exit_code != 100u + phase) {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        goto done;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\resize-crash", &node) != CF_OK ||
        cf_node_info(store, node, &info) != CF_OK)
        goto done;
    if (phase == 1) {
        if (info.size != CF_BLOCK_SIZE ||
            cf_node_read(store, node, tail, 1024, (uint32_t)tail_length,
                &transferred) != CF_OK || transferred != tail_length ||
            memcmp(tail, initial + 1024, tail_length) != 0)
            goto done;
    } else {
        if (info.size != 1024 ||
            cf_node_resize(store, node, CF_BLOCK_SIZE, FALSE) != CF_OK ||
            cf_node_read(store, node, tail, 1024, (uint32_t)tail_length,
                &transferred) != CF_OK || transferred != tail_length)
            goto done;
        for (i = 0; i < tail_length; ++i)
            if (tail[i] != 0)
                goto done;
        if (cf_node_read(store, node, tail, 0, 1024, &transferred) != CF_OK ||
            transferred != 1024 || memcmp(tail, initial, 1024) != 0)
            goto done;
    }
    ok = TRUE;
done:
    if (node && store)
        cf_node_close(store, node);
    if (store)
        cf_store_close(store);
    if (initial) {
        cf_wipe(initial, CF_BLOCK_SIZE);
        free(initial);
    }
    if (tail) {
        cf_wipe(tail, tail_length);
        free(tail);
    }
    DeleteFileW(path);
    return ok;
}

static BOOL
run_map_trim_crash_phase(unsigned phase)
{
    const uint32_t initial_blocks = 130;
    const uint32_t retained_blocks = 63;
    const size_t full_length = (size_t)initial_blocks * CF_BLOCK_SIZE;
    wchar_t path[MAX_PATH * 2], command[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_INFO info, initial_info;
    uint8_t *input = NULL;
    uint8_t actual = 0;
    uint32_t transferred = 0, i;
    DWORD exit_code = 0;
    BOOL ok = FALSE;
    if (phase < 1 || phase > 5 ||
        _snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
            L"%ls\\cryptfs-map-crash-%lu-%u.cf", g_directory,
            (unsigned long)GetCurrentProcessId(), phase) < 0)
        return FALSE;
    DeleteFileW(path);
    input = (uint8_t *)malloc(full_length);
    if (!input)
        goto done;
    for (i = 0; i < initial_blocks; ++i)
        memset(input + (size_t)i * CF_BLOCK_SIZE, (int)(i * 29u), CF_BLOCK_SIZE);
    memset(&initial_info, 0, sizeof(initial_info));
    {
        CF_RESULT setup_result = open_store(path, TRUE, FALSE, &store);
        if (setup_result != CF_OK) {
            fprintf(stderr, "map crash phase %u: create store result=%u\n",
                phase, (unsigned)setup_result);
            goto done;
        }
        setup_result = cf_node_create(store, L"\\map-crash", FILE_ATTRIBUTE_NORMAL,
            &node);
        if (setup_result != CF_OK) {
            fprintf(stderr, "map crash phase %u: create file result=%u\n",
                phase, (unsigned)setup_result);
            goto done;
        }
        setup_result = cf_node_write(store, node, input, 0, (uint32_t)full_length,
            FALSE, FALSE, &transferred);
        if (setup_result != CF_OK || transferred != full_length ||
            cf_node_info(store, node, &initial_info) != CF_OK ||
            initial_info.size != full_length || cf_store_flush(store) != CF_OK) {
            fprintf(stderr, "map crash phase %u: setup write=%u transferred=%u size=%llu expected=%llu\n",
                phase, (unsigned)setup_result, transferred,
                (unsigned long long)initial_info.size,
                (unsigned long long)full_length);
            goto done;
        }
        if (cf_node_read(store, node, &actual, full_length - 1, 1,
            &transferred) != CF_OK || transferred != 1 ||
            actual != input[full_length - 1]) {
            fprintf(stderr, "map crash phase %u: pre-close fixture tail=%u expected=%u transferred=%u\n",
                phase, (unsigned)actual, (unsigned)input[full_length - 1], transferred);
            goto done;
        }
    }
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    {
        CF_RESULT reopen_result = open_store(path, FALSE, FALSE, &store);
        if (reopen_result != CF_OK ||
            cf_node_open(store, L"\\map-crash", &node) != CF_OK ||
            cf_node_info(store, node, &initial_info) != CF_OK ||
            initial_info.size != full_length ||
            cf_node_read(store, node, &actual, full_length - 1, 1,
                &transferred) != CF_OK || transferred != 1 ||
            actual != input[full_length - 1]) {
            fprintf(stderr, "map crash phase %u: pre-child remount result=%u size=%llu tail=%u expected=%u transferred=%u\n",
                phase, (unsigned)reopen_result,
                (unsigned long long)initial_info.size, (unsigned)actual,
                (unsigned)input[full_length - 1], transferred);
            goto done;
        }
        cf_node_close(store, node); node = NULL;
        cf_store_close(store); store = NULL;
    }
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" --map-crash \"%ls\" %u", g_executable, path, phase) < 0)
        goto done;
    memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    if (!CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        fprintf(stderr, "map crash phase %u: CreateProcess error=%lu\n",
            phase, (unsigned long)GetLastError());
        goto done;
    }
    if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code) ||
        exit_code != 100u + phase) {
        fprintf(stderr, "map crash phase %u: child exit=%lu expected=%u wait=%lu\n",
            phase, (unsigned long)exit_code, 100u + phase,
            (unsigned long)WaitForSingleObject(process.hProcess, 0));
        goto process_done;
    }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    {
        CF_RESULT mount_result = open_store(path, FALSE, FALSE, &store);
        if (mount_result != CF_OK) {
            fprintf(stderr, "map crash phase %u: remount result=%u\n",
                phase, (unsigned)mount_result);
            goto done;
        }
        mount_result = cf_node_open(store, L"\\map-crash", &node);
        if (mount_result != CF_OK || cf_node_info(store, node, &info) != CF_OK) {
            fprintf(stderr, "map crash phase %u: open/info result=%u\n",
                phase, (unsigned)mount_result);
            goto done;
        }
    }
    if (phase == 1) {
        if (info.size != full_length ||
            cf_node_read(store, node, &actual, full_length - 1, 1,
                &transferred) != CF_OK || transferred != 1 ||
            actual != input[full_length - 1]) {
            fprintf(stderr, "map crash phase 1: old-state size=%llu expected=%llu tail=%u expected-byte=%u transferred=%u\n",
                (unsigned long long)info.size, (unsigned long long)full_length,
                (unsigned)actual, (unsigned)input[full_length - 1], transferred);
            goto done;
        }
    } else {
        if (info.size != (uint64_t)retained_blocks * CF_BLOCK_SIZE ||
            cf_node_read(store, node, &actual,
                (uint64_t)retained_blocks * CF_BLOCK_SIZE - 1, 1,
                &transferred) != CF_OK || transferred != 1 ||
            actual != (uint8_t)((retained_blocks - 1) * 29u) ||
            cf_node_resize(store, node, full_length, FALSE) != CF_OK ||
            cf_node_read(store, node, &actual,
                (uint64_t)retained_blocks * CF_BLOCK_SIZE, 1,
                &transferred) != CF_OK || transferred != 1 || actual != 0 ||
            cf_node_read(store, node, &actual, full_length - 1, 1,
                &transferred) != CF_OK || transferred != 1 || actual != 0) {
            fprintf(stderr, "map crash phase %u: trimmed/grown-state size=%llu boundary-or-tail=%u transferred=%u\n",
                phase, (unsigned long long)info.size, (unsigned)actual, transferred);
            goto done;
        }
        cf_node_close(store, node); node = NULL;
        cf_store_close(store); store = NULL;
        if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
            cf_node_open(store, L"\\map-crash", &node) != CF_OK ||
            cf_node_read(store, node, &actual, full_length - 1, 1,
                &transferred) != CF_OK || transferred != 1 || actual != 0)
            goto done;
    }
    ok = TRUE;
    goto done;
process_done:
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
done:
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    if (input) { cf_wipe(input, full_length); free(input); }
    if (ok)
        DeleteFileW(path);
    else
        fwprintf(stderr, L"map crash fixture preserved for diagnosis: %ls\n", path);
    return ok;
}

static int
test_map_trim_crash_matrix(void)
{
    for (unsigned phase = 1; phase <= 5; ++phase) {
        if (!run_map_trim_crash_phase(phase)) {
            fprintf(stderr, "multi-map truncate crash phase %u failed\n", phase);
            return 1;
        }
    }
    return 0;
}

static int
run_orphan_crash_child(const wchar_t *path)
{
    CF_STORE *store = NULL;
    CF_NODE *first = NULL, *second = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        return 30;
    if (cf_node_create(store, L"\\orphan-one", FILE_ATTRIBUTE_NORMAL, &first) != CF_OK ||
        cf_node_create(store, L"\\orphan-two", FILE_ATTRIBUTE_NORMAL, &second) != CF_OK)
        return 31;
    if (cf_node_unlink(store, first) != CF_OK || cf_node_unlink(store, second) != CF_OK)
        return 32;
    if (cf_store_flush(store) != CF_OK)
        return 33;
    /* Deliberately skip cf_node_close/cf_store_close, like process termination. */
    ExitProcess(77);
    return 34;
}

static int
run_trim_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    bool progress = false;
    CF_RESULT result = open_store(path, FALSE, FALSE, &store);
    if (result != CF_OK)
        return 40;
    cf_test_crash_phase(phase);
    result = cf_store_compact_step(store, &progress);
    cf_store_close(store);
    return result == CF_OK && progress ? 41 : 42;
}

static int
run_unlink_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        return 60;
    if (cf_node_open(store, L"\\victim", &node) != CF_OK) {
        cf_store_close(store);
        return 61;
    }
    cf_test_crash_phase(phase);
    if (cf_node_unlink(store, node) != CF_OK)
        return 62;
    cf_node_close(store, node);
    cf_store_close(store);
    return 63;
}

static int
run_rename_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        return 64;
    if (cf_node_open(store, L"\\source", &node) != CF_OK) {
        cf_store_close(store);
        return 65;
    }
    cf_test_crash_phase(phase);
    if (cf_node_rename(store, node, L"\\target", TRUE) != CF_OK)
        return 66;
    cf_node_close(store, node);
    cf_store_close(store);
    return 67;
}

static int
run_move_crash_child(const wchar_t *path, unsigned phase)
{
    CF_STORE *store = NULL;
    bool progress = false;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        return 68;
    cf_test_crash_phase(phase);
    if (cf_store_compact_step(store, &progress) != CF_OK || !progress)
        return 69;
    cf_store_close(store);
    return 70;
}

static BOOL
prepare_zero_image_shrink(const wchar_t *path)
{
    CF_STORE *store = NULL;
    CF_NODE *file = NULL;
    CF_STATS stats;
    uint8_t block[CF_BLOCK_SIZE];
    uint32_t transferred = 0;
    if (!cf_crypto_init())
        return FALSE;
    cf_random(block, sizeof(block));
    if (open_store(path, TRUE, FALSE, &store) != CF_OK)
        return FALSE;
    if (cf_node_create(store, L"\\trim-phase", FILE_ATTRIBUTE_NORMAL, &file) != CF_OK)
        goto fail;
    if (cf_node_write(store, file, block, 0, sizeof(block), FALSE, FALSE,
        &transferred) != CF_OK || transferred != sizeof(block))
        goto fail;
    cf_node_close(store, file); file = NULL;
    if (cf_node_open(store, L"\\trim-phase", &file) != CF_OK)
        goto fail;
    if (cf_node_can_delete(store, file) != CF_OK ||
        cf_node_unlink(store, file) != CF_OK)
        goto fail;
    cf_node_close(store, file); file = NULL;
    if (cf_store_flush(store) != CF_OK ||
        cf_store_stats(store, &stats) != CF_OK || stats.live_pages != 1 ||
        stats.eof_bytes <= CF_MIN_EOF)
        goto fail;
    cf_store_close(store);
    return TRUE;
fail:
    if (file != NULL) cf_node_close(store, file);
    if (store != NULL) cf_store_close(store);
    return FALSE;
}

static BOOL
run_zero_image_shrink_phase(unsigned phase)
{
    wchar_t path[MAX_PATH * 2], command[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD exit_code = 0;
    CF_STORE *store = NULL;
    CF_STATS stats;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-zero-shrink-%lu-%u.cf", g_directory,
        (unsigned long)GetCurrentProcessId(), phase) < 0)
        return FALSE;
    DeleteFileW(path);
    if (!prepare_zero_image_shrink(path)) {
        DeleteFileW(path);
        return FALSE;
    }
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" --trim-crash \"%ls\" %u", g_executable,
        path, phase) < 0) {
        DeleteFileW(path);
        return FALSE;
    }
    memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    if (!CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        DeleteFileW(path);
        return FALSE;
    }
    if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code) ||
        exit_code != 100u + phase)
        goto done;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        goto done;
    if (cf_store_stats(store, &stats) != CF_OK || stats.poisoned ||
        stats.live_pages != 1 || stats.eof_bytes != CF_MIN_EOF)
        goto done;
    ok = TRUE;
done:
    if (store != NULL) cf_store_close(store);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    DeleteFileW(path);
    return ok;
}

static BOOL
run_namespace_compaction_crash_case(unsigned operation, unsigned phase)
{
    wchar_t path[MAX_PATH * 2], command[4096];
    const wchar_t *mode = operation == 1 ? L"--unlink-crash" :
        (operation == 2 ? L"--rename-crash" : L"--move-crash");
    CF_STORE *store = NULL;
    CF_NODE *first = NULL, *second = NULL, *opened = NULL;
    CF_INFO info;
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD exit_code = 0;
    uint8_t block[CF_BLOCK_SIZE];
    uint8_t first_byte = (uint8_t)'S', second_byte = (uint8_t)'T', actual = 0;
    uint32_t transferred = 0;
    BOOL ok = FALSE;
    if (phase < 1 || phase > 5 || operation < 1 || operation > 3 ||
        _snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
            L"%ls\\cryptfs-op-crash-%lu-%u-%u.cf", g_directory,
            (unsigned long)GetCurrentProcessId(), operation, phase) < 0)
        return FALSE;
    DeleteFileW(path);
    if (operation == 3) {
        for (size_t i = 0; i < sizeof(block); ++i)
            block[i] = (uint8_t)(i * 73u + 19u);
    }
    if (open_store(path, TRUE, FALSE, &store) != CF_OK)
        goto done;
    if (operation == 1) {
        if (cf_node_create(store, L"\\victim", FILE_ATTRIBUTE_NORMAL,
                &first) != CF_OK ||
            cf_node_write(store, first, &first_byte, 0, 1, FALSE, FALSE,
                &transferred) != CF_OK || transferred != 1)
            goto done;
        cf_node_close(store, first); first = NULL;
    } else if (operation == 2) {
        if (cf_node_create(store, L"\\source", FILE_ATTRIBUTE_NORMAL,
                &first) != CF_OK ||
            cf_node_create(store, L"\\target", FILE_ATTRIBUTE_NORMAL,
                &second) != CF_OK ||
            cf_node_write(store, first, &first_byte, 0, 1, FALSE, FALSE,
                &transferred) != CF_OK || transferred != 1 ||
            cf_node_write(store, second, &second_byte, 0, 1, FALSE, FALSE,
                &transferred) != CF_OK || transferred != 1)
            goto done;
        cf_node_close(store, first); first = NULL;
        cf_node_close(store, second); second = NULL;
    } else {
        if (cf_node_create(store, L"\\hole", FILE_ATTRIBUTE_NORMAL,
                &first) != CF_OK ||
            cf_node_create(store, L"\\data", FILE_ATTRIBUTE_NORMAL,
                &second) != CF_OK ||
            cf_node_write(store, second, block, 0, sizeof(block), FALSE, FALSE,
                &transferred) != CF_OK || transferred != sizeof(block))
            goto done;
        cf_node_close(store, first); /* zero-reference linked node remains owned */
        if (cf_node_unlink(store, first) != CF_OK)
            goto done;
        first = NULL;
        cf_node_close(store, second); second = NULL;
    }
    if (cf_store_flush(store) != CF_OK)
        goto done;
    cf_store_close(store); store = NULL;

    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" %ls \"%ls\" %u", g_executable, mode, path, phase) < 0)
        goto done;
    memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    if (!CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        goto done;
    if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code) ||
        exit_code != 100u + phase)
        goto process_done;

    if (open_store(path, FALSE, FALSE, &store) != CF_OK)
        goto process_done;
    if (operation == 1) {
        CF_RESULT expected = phase == 1 ? CF_OK : CF_NOT_FOUND;
        if (cf_node_open(store, L"\\victim", &opened) != expected)
            goto process_done;
        if (phase == 1 && (!read_byte(store, opened, 0, &actual) || actual != first_byte))
            goto process_done;
    } else if (operation == 2) {
        CF_RESULT source_expected = phase == 1 ? CF_OK : CF_NOT_FOUND;
        if (cf_node_open(store, L"\\source", &opened) != source_expected)
            goto process_done;
        if (phase == 1) {
            if (!read_byte(store, opened, 0, &actual) || actual != first_byte)
                goto process_done;
            cf_node_close(store, opened); opened = NULL;
            if (cf_node_open(store, L"\\target", &opened) != CF_OK ||
                !read_byte(store, opened, 0, &actual) || actual != second_byte)
                goto process_done;
        } else {
            if (cf_node_open(store, L"\\target", &opened) != CF_OK ||
                !read_byte(store, opened, 0, &actual) || actual != first_byte)
                goto process_done;
        }
    } else {
        if (cf_node_open(store, L"\\data", &opened) != CF_OK ||
            cf_node_info(store, opened, &info) != CF_OK || info.size != CF_BLOCK_SIZE ||
            cf_node_read(store, opened, block, 0, sizeof(block), &transferred) != CF_OK ||
            transferred != sizeof(block))
            goto process_done;
        for (size_t i = 0; i < sizeof(block); ++i) {
            if (block[i] != (uint8_t)(i * 73u + 19u))
                goto process_done;
        }
        for (unsigned step = 0; step < 64; ++step) {
            bool progress = false;
            if (cf_store_compact_step(store, &progress) != CF_OK)
                goto process_done;
            if (!progress)
                break;
            if (step == 63)
                goto process_done;
        }
        if (cf_node_read(store, opened, block, 0, sizeof(block), &transferred) != CF_OK ||
            transferred != sizeof(block))
            goto process_done;
        for (size_t i = 0; i < sizeof(block); ++i) {
            if (block[i] != (uint8_t)(i * 73u + 19u))
                goto process_done;
        }
    }
    ok = TRUE;
process_done:
    if (opened && store) cf_node_close(store, opened);
    if (store) {
        cf_store_close(store);
        store = NULL;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
done:
    if (first && store) cf_node_close(store, first);
    if (second && store) cf_node_close(store, second);
    if (store) cf_store_close(store);
    cf_wipe(block, sizeof(block));
    DeleteFileW(path);
    return ok;
}

static int
test_namespace_compaction_crash_phases(void)
{
    for (unsigned phase = 1; phase <= 5; ++phase) {
        if (!run_namespace_compaction_crash_case(1, phase)) {
            fprintf(stderr, "unlink crash phase %u failed\n", phase);
            return 1;
        }
        if (!run_namespace_compaction_crash_case(2, phase)) {
            fprintf(stderr, "rename replacement crash phase %u failed\n", phase);
            return 1;
        }
        if (!run_namespace_compaction_crash_case(3, phase)) {
            fprintf(stderr, "compaction move crash phase %u failed\n", phase);
            return 1;
        }
    }
    return 0;
}

static BOOL
run_orphan_crash_and_reopen(void)
{
    wchar_t command[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD exit_code = 0;
    CF_STORE *store = NULL;
    CF_NODE *root = NULL, *node = NULL;
    CF_DIRENT *entries = NULL;
    size_t count = 0, i;
    BOOL one_found = FALSE, two_found = FALSE, ok = FALSE;
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" --orphan-crash \"%ls\"", g_executable, g_container) < 0)
        return FALSE;
    memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    if (!CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        return FALSE;
    if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code) || exit_code != 77)
        goto done;
    if (open_store(g_container, FALSE, FALSE, &store) != CF_OK)
        goto done;
    if (cf_node_open(store, L"\\", &root) != CF_OK)
        goto done;
    if (cf_node_open(store, L"\\orphan-one", &node) != CF_NOT_FOUND || node != NULL)
        goto done;
    if (cf_node_open(store, L"\\orphan-two", &node) != CF_NOT_FOUND || node != NULL)
        goto done;
    if (cf_node_list(store, root, &entries, &count) != CF_OK)
        goto done;
    for (i = 0; i < count; ++i) {
        if (wcscmp(entries[i].name, L"orphan-one") == 0) one_found = TRUE;
        if (wcscmp(entries[i].name, L"orphan-two") == 0) two_found = TRUE;
    }
    ok = !one_found && !two_found;
done:
    if (entries != NULL) cf_list_free(entries, count);
    if (node != NULL) cf_node_close(store, node);
    if (root != NULL) cf_node_close(store, root);
    if (store != NULL) cf_store_close(store);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return ok;
}

static BOOL
run_crash_phase(unsigned phase, uint8_t expected)
{
    wchar_t command[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD exit_code = 0;
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    uint8_t actual = 0;
    BOOL ok = FALSE;
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" --crash \"%ls\" %u", g_executable, g_container,
        phase) < 0)
        return FALSE;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    if (!CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process))
        return FALSE;
    if (WaitForSingleObject(process.hProcess, 120000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process.hProcess, &exit_code) ||
        exit_code != 100u + phase)
        goto done;
    if (open_store(g_container, FALSE, FALSE, &store) != CF_OK)
        goto done;
    if (cf_node_open(store, L"\\crash", &node) != CF_OK)
        goto done;
    if (!read_byte(store, node, 0, &actual) || actual != expected)
        goto done;
    ok = TRUE;
done:
    if (node != NULL)
        cf_node_close(store, node);
    if (store != NULL) {
        cf_store_close(store);
        store = NULL;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return ok;
}

static int
test_store_functionality(void)
{
    CF_STORE *store = NULL;
    CF_NODE *root = NULL, *directory = NULL, *file = NULL, *sparse = NULL;
    CF_NODE *orphan = NULL, *missing = NULL;
    CF_NODE *same_ref = NULL, *replace_old = NULL, *replacement = NULL;
    CF_NODE *auth_parent = NULL, *first_child = NULL, *second_child = NULL;
    CF_INFO info, same_info;
    CF_STATS stats;
    CF_DIRENT *entries = NULL;
    size_t count = 0, i;
    CF_RESULT result;
    uint8_t block[CF_BLOCK_SIZE], output[CF_BLOCK_SIZE];
    uint8_t sample[128];
    uint32_t transferred = 0;
    unsigned found_file = 0, found_case = 0;
    static const wchar_t file_path[] = L"\\Dir\\Data";
    static const wchar_t renamed_path[] = L"\\Dir\\Moved";
    static const wchar_t replace_path[] = L"\\Dir\\ReplaceTarget";

    result = open_store(g_container, TRUE, FALSE, &store);
    CHECK(result == CF_OK && store != NULL);
    CHECK(cf_node_open(store, L"\\", &root) == CF_OK);
    CHECK(cf_node_create(store, L"\\Dir", FILE_ATTRIBUTE_DIRECTORY,
        &directory) == CF_OK);
    CHECK(cf_node_create(store, file_path, FILE_ATTRIBUTE_NORMAL, &file) == CF_OK);
    CHECK(cf_node_create(store, L"\\dir", FILE_ATTRIBUTE_DIRECTORY,
        &sparse) == CF_OK);
    cf_node_close(store, sparse); sparse = NULL;

    /* Exact UTF-16 names are case-sensitive. */
    CHECK(cf_node_open(store, L"\\DIR\\Data", &sparse) == CF_PATH_NOT_FOUND &&
        sparse == NULL);
    CHECK(cf_node_open(store, L"\\Dir\\data", &sparse) == CF_NOT_FOUND);

    /* Compression must preserve a full block; an uncompressible block stays valid. */
    memset(block, 'Q', sizeof(block));
    CHECK(cf_node_write(store, file, block, 0, sizeof(block), FALSE, FALSE,
        &transferred) == CF_OK && transferred == sizeof(block));
    CHECK(cf_crypto_init());
    cf_random(block, sizeof(block));
    CHECK(cf_node_write(store, file, block, CF_BLOCK_SIZE, sizeof(block),
        FALSE, FALSE, &transferred) == CF_OK && transferred == sizeof(block));
    memset(output, 0, sizeof(output));
    CHECK(cf_node_read(store, file, output, 0, sizeof(output), &transferred) == CF_OK &&
        transferred == sizeof(output));
    for (i = 0; i < sizeof(output); ++i) CHECK(output[i] == (uint8_t)'Q');
    CHECK(cf_node_read(store, file, output, CF_BLOCK_SIZE, sizeof(output),
        &transferred) == CF_OK && transferred == sizeof(output) &&
        memcmp(output, block, sizeof(block)) == 0);
    /* Constrained writes must stop at EOF and never enlarge the file. */
    CHECK(cf_node_write(store, file, "WXYZ", 2ULL * CF_BLOCK_SIZE - 2,
        4, FALSE, TRUE, &transferred) == CF_OK && transferred == 2);
    CHECK(cf_node_info(store, file, &info) == CF_OK &&
        info.size == 2ULL * CF_BLOCK_SIZE);
    CHECK(cf_node_read(store, file, output, 2ULL * CF_BLOCK_SIZE - 2,
        2, &transferred) == CF_OK && transferred == 2 &&
        output[0] == (uint8_t)'W' && output[1] == (uint8_t)'X');

    /* Sparse resize/read returns zeros without materializing untouched blocks. */
    CHECK(cf_node_create(store, L"\\sparse", FILE_ATTRIBUTE_NORMAL, &sparse) == CF_OK);
    CHECK(cf_node_resize(store, sparse, 128ULL * 1024ULL * 1024ULL, FALSE) == CF_OK);
    CHECK(cf_node_info(store, sparse, &info) == CF_OK &&
        info.size == 128ULL * 1024ULL * 1024ULL);
    memset(sample, 0xcc, sizeof(sample));
    CHECK(cf_node_read(store, sparse, sample, 64ULL * 1024ULL * 1024ULL,
        sizeof(sample), &transferred) == CF_OK && transferred == sizeof(sample));
    for (i = 0; i < sizeof(sample); ++i) CHECK(sample[i] == 0);
    CHECK(cf_node_write(store, sparse, "xyz", 64ULL * 1024ULL * 1024ULL,
        3, FALSE, FALSE, &transferred) == CF_OK && transferred == 3);
    cf_node_close(store, sparse); sparse = NULL;

    CHECK(cf_node_list(store, directory, &entries, &count) == CF_OK);
    for (i = 0; i < count; ++i)
        if (wcscmp(entries[i].name, L"Data") == 0) found_file = 1;
    cf_list_free(entries, count); entries = NULL; count = 0;
    CHECK(found_file);
    CHECK(cf_node_list(store, root, &entries, &count) == CF_OK);
    for (i = 0; i < count; ++i)
        if (wcscmp(entries[i].name, L"Dir") == 0) found_case = 1;
    cf_list_free(entries, count); entries = NULL; count = 0;
    CHECK(found_case);

    CHECK(cf_node_can_delete(store, directory) == CF_NOT_EMPTY);
    CHECK(cf_node_unlink(store, directory) == CF_NOT_EMPTY);
    CHECK(cf_node_set_basic(store, directory,
        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE,
        132510000000000000ULL, 132510000000000001ULL,
        132510000000000002ULL, 132510000000000003ULL) == CF_OK);
    CHECK(cf_node_info(store, directory, &info) == CF_OK &&
        info.creation_time == 132510000000000000ULL &&
        info.access_time == 132510000000000001ULL &&
        info.write_time == 132510000000000002ULL &&
        info.change_time == 132510000000000003ULL &&
        (info.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (info.attributes & FILE_ATTRIBUTE_ARCHIVE) != 0);

    /* Two opens of one inode keep the same object alive and share identity. */
    CHECK(cf_node_open(store, file_path, &same_ref) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK);
    CHECK(cf_node_info(store, same_ref, &same_info) == CF_OK);
    CHECK(info.id == same_info.id);
    cf_node_close(store, file); file = NULL;
    CHECK(read_byte(store, same_ref, 0, &sample[0]) && sample[0] == (uint8_t)'Q');
    file = same_ref; same_ref = NULL;

    CHECK(cf_node_rename(store, file, renamed_path, FALSE) == CF_OK);
    CHECK(cf_node_open(store, file_path, &missing) == CF_NOT_FOUND && missing == NULL);
    CHECK(cf_node_resize(store, file, 1024, FALSE) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK && info.size == 1024);
    CHECK(cf_node_resize(store, file, CF_BLOCK_SIZE, FALSE) == CF_OK);
    memset(output, 0xcc, sizeof(output));
    CHECK(cf_node_read(store, file, output, 1024, CF_BLOCK_SIZE - 1024,
        &transferred) == CF_OK && transferred == CF_BLOCK_SIZE - 1024);
    for (i = 0; i < CF_BLOCK_SIZE - 1024; ++i) CHECK(output[i] == 0);
    CHECK(cf_node_resize(store, file, 1024, FALSE) == CF_OK);

    /* Replacing an open target preserves its old handle while the path names source. */
    CHECK(cf_node_create(store, replace_path, FILE_ATTRIBUTE_NORMAL, &replace_old) == CF_OK);
    CHECK(write_byte(store, replace_old, 0, (uint8_t)'T'));
    CHECK(cf_node_rename(store, file, replace_path, TRUE) == CF_OK);
    CHECK(cf_node_open(store, replace_path, &replacement) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK);
    {
        CF_INFO replacement_info, old_info;
        CHECK(cf_node_info(store, replacement, &replacement_info) == CF_OK);
        CHECK(cf_node_info(store, replace_old, &old_info) == CF_OK);
        CHECK(replacement_info.id == info.id && old_info.id != info.id);
    }
    CHECK(read_byte(store, replace_old, 0, &sample[0]) && sample[0] == (uint8_t)'T');
    CHECK(read_byte(store, replacement, 0, &sample[0]) && sample[0] == (uint8_t)'Q');
    cf_node_close(store, replace_old); replace_old = NULL;
    cf_node_close(store, replacement); replacement = NULL;
    CHECK(cf_node_set_basic(store, file, FILE_ATTRIBUTE_ARCHIVE,
        132500000000000000ULL, 132500000000000001ULL,
        132500000000000002ULL, 132500000000000003ULL) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK &&
        info.creation_time == 132500000000000000ULL &&
        info.access_time == 132500000000000001ULL &&
        info.write_time == 132500000000000002ULL &&
        info.change_time == 132500000000000003ULL &&
        (info.attributes & FILE_ATTRIBUTE_ARCHIVE) != 0);

    /* An open file remains readable after unlink and is reclaimed on final close. */
    CHECK(cf_node_create(store, L"\\orphan", FILE_ATTRIBUTE_NORMAL, &orphan) == CF_OK);
    CHECK(write_byte(store, orphan, 0, (uint8_t)'O'));
    CHECK(cf_node_can_delete(store, orphan) == CF_OK);
    CHECK(cf_node_unlink(store, orphan) == CF_OK);
    CHECK(cf_node_open(store, L"\\orphan", &missing) == CF_NOT_FOUND && missing == NULL);
    CHECK(cf_node_open(store, L"\\Dir", &directory) == CF_OK);
    CHECK(cf_node_info(store, directory, &info) == CF_OK &&
        info.creation_time == 132510000000000000ULL &&
        info.access_time == 132510000000000001ULL &&
        info.write_time == 132510000000000002ULL &&
        info.change_time == 132510000000000003ULL &&
        (info.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (info.attributes & FILE_ATTRIBUTE_ARCHIVE) != 0);
    cf_node_close(store, directory); directory = NULL;
    CHECK(read_byte(store, orphan, 0, &sample[0]) && sample[0] == (uint8_t)'O');
    cf_node_close(store, orphan); orphan = NULL;

    /* Keep a valid parent and first sibling ahead of the inode we will tamper. */
    CHECK(cf_node_create(store, L"\\AuthParent", FILE_ATTRIBUTE_DIRECTORY,
        &auth_parent) == CF_OK);
    CHECK(cf_node_info(store, auth_parent, &info) == CF_OK && info.id > 0);
    g_auth_parent_id = info.id;
    CHECK(cf_node_create(store, L"\\AuthParent\\First", FILE_ATTRIBUTE_NORMAL,
        &first_child) == CF_OK);
    CHECK(cf_node_create(store, L"\\AuthParent\\Second", FILE_ATTRIBUTE_NORMAL,
        &second_child) == CF_OK);
    CHECK(cf_node_info(store, second_child, &info) == CF_OK && info.id > 0);
    g_second_child_id = info.id;
    CHECK(write_byte(store, second_child, 0, (uint8_t)'S'));
    cf_node_close(store, second_child); second_child = NULL;
    cf_node_close(store, first_child); first_child = NULL;
    cf_node_close(store, auth_parent); auth_parent = NULL;

    CHECK(cf_node_create(store, L"\\crash", FILE_ATTRIBUTE_NORMAL, &sparse) == CF_OK);
    CHECK(write_byte(store, sparse, 0, (uint8_t)'A'));
    cf_node_close(store, sparse); sparse = NULL;
    cf_node_close(store, file); file = NULL;
    cf_node_close(store, directory); directory = NULL;
    cf_node_close(store, root); root = NULL;
    CHECK(cf_store_flush(store) == CF_OK);
    CHECK(cf_store_stats(store, &stats) == CF_OK && !stats.poisoned);
    cf_store_close(store); store = NULL;

    /* Reopen must retain the namespace/data and reject the wrong password. */
    CHECK(open_store(g_container, FALSE, FALSE, &store) == CF_OK);
    CHECK(cf_node_open(store, replace_path, &file) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK && info.size == 1024);
    CHECK(info.creation_time == 132500000000000000ULL &&
        info.access_time == 132500000000000001ULL &&
        info.write_time == 132500000000000002ULL &&
        info.change_time == 132500000000000003ULL);
    cf_node_close(store, file); file = NULL;
    CHECK(cf_node_open(store, L"\\orphan", &missing) == CF_NOT_FOUND && missing == NULL);
    cf_store_close(store); store = NULL;
    {
        CF_OPTIONS options;
        CF_STORE *wrong = NULL;
        uint8_t before[32], after[32];
        static const uint8_t wrong_password[] = "incorrect";
        memset(&options, 0, sizeof(options));
        options.container = g_container;
        options.capacity = 8ULL * 1024ULL * 1024ULL * 1024ULL;
        CHECK(hash_file(g_container, before));
        result = cf_store_open(&options, wrong_password,
            sizeof(wrong_password) - 1, &wrong);
        CHECK(result == CF_ACCESS && wrong == NULL);
        CHECK(hash_file(g_container, after) && memcmp(before, after, sizeof(before)) == 0);
    }
    return 0;
}

static int
test_authenticated_tamper_no_write(void)
{
    uint8_t before[32], after[32];
    uint64_t offset = CF_ROOT_OFFSET + CF_PAGE_HEADER_SIZE + 1;
    CF_OPTIONS options;
    CF_STORE *store = NULL;
    CF_RESULT result;
    CHECK(copy_sparse_container(g_container, g_backup));
    CHECK(mutate_container_byte(g_container, CF_ROOT_OFFSET + CF_PAGE_HEADER_SIZE + 1));
    CHECK(hash_file(g_container, before));
    memset(&options, 0, sizeof(options));
    options.container = g_container;
    result = cf_store_open(&options, g_password, sizeof(g_password) - 1, &store);
    CHECK(result == CF_DATA_ERROR && store == NULL);
    CHECK(hash_file(g_container, after) && memcmp(before, after, sizeof(before)) == 0);
    CHECK(copy_sparse_container(g_backup, g_container));
    CHECK(open_store(g_container, FALSE, FALSE, &store) == CF_OK);
    cf_store_close(store); store = NULL;
    if (g_second_child_id != 0) {
        CHECK(find_inode_page_offset(g_container, g_second_child_id, &offset));
        CHECK(mutate_container_byte(g_container, offset + CF_PAGE_HEADER_SIZE + 1));
        CHECK(hash_file(g_container, before));
        store = NULL;
        result = cf_store_open(&options, g_password, sizeof(g_password) - 1, &store);
        CHECK(result == CF_DATA_ERROR && store == NULL);
        CHECK(hash_file(g_container, after) && memcmp(before, after, sizeof(before)) == 0);
        CHECK(copy_sparse_container(g_backup, g_container));
        CHECK(open_store(g_container, FALSE, FALSE, &store) == CF_OK);
        cf_store_close(store); store = NULL;
    }
    DeleteFileW(g_backup);
    return 0;
}

static int
test_fragment_tamper_no_write(void)
{
    wchar_t path[MAX_PATH * 2], backup[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_INFO info;
    CF_OPTIONS options;
    CF_RESULT result;
    uint8_t block[CF_BLOCK_SIZE], before[32], after[32];
    uint64_t page_offset;
    uint32_t transferred = 0;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-fragment-tamper-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0 ||
        _snwprintf_s(backup, ARRAYSIZE(backup), _TRUNCATE,
        L"%ls\\cryptfs-fragment-tamper-%lu-pristine.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path); DeleteFileW(backup);
    if (!cf_crypto_init())
        goto done;
    cf_random(block, sizeof(block));
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\fragment", FILE_ATTRIBUTE_NORMAL, &node) != CF_OK ||
        cf_node_info(store, node, &info) != CF_OK ||
        cf_node_write(store, node, block, 0, sizeof(block), FALSE, FALSE,
            &transferred) != CF_OK || transferred != sizeof(block) ||
        cf_store_flush(store) != CF_OK)
        goto done;
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (!copy_sparse_container(path, backup) ||
        !find_record_page_offset(path, CF_RECORD_FRAGMENT, info.id, 2, &page_offset) ||
        !mutate_container_byte(path, page_offset + CF_PAGE_HEADER_SIZE + 1) ||
        !hash_file(path, before))
        goto done;
    memset(&options, 0, sizeof(options));
    options.container = path;
    result = cf_store_open(&options, g_password, sizeof(g_password) - 1, &store);
    if (result != CF_DATA_ERROR || store != NULL) {
        fprintf(stderr, "fragment tamper: expected CF_DATA_ERROR, got %u store=%p\n",
            (unsigned)result, (void *)store);
        goto done;
    }
    if (!hash_file(path, after) || memcmp(before, after, sizeof(before)) != 0) {
        fprintf(stderr, "fragment tamper: rejected container changed on disk\n");
        goto done;
    }
    if (!copy_sparse_container(backup, path) ||
        open_store(path, FALSE, FALSE, &store) != CF_OK) {
        fprintf(stderr, "fragment tamper: pristine sparse fixture did not reopen\n");
        goto done;
    }
    cf_store_close(store); store = NULL;
    ok = TRUE;
done:
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    cf_wipe(block, sizeof(block));
    DeleteFileW(backup); DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_page_registration_failure_recovery(void)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_STATS stats;
    uint8_t block[CF_BLOCK_SIZE], value = 0, actual = 0;
    uint32_t transferred = 0;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-register-fail-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!cf_crypto_init())
        goto done;
    cf_random(block, sizeof(block));
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\register", FILE_ATTRIBUTE_NORMAL, &node) != CF_OK ||
        cf_node_write(store, node, block, 0, sizeof(block), FALSE, FALSE,
            &transferred) != CF_OK || transferred != sizeof(block) ||
        cf_store_flush(store) != CF_OK)
        goto done;
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;

    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\register", &node) != CF_OK)
        goto done;
    value = (uint8_t)(block[0] ^ 0xffu);
    cf_test_fail_page_register(1);
    if (cf_node_write(store, node, &value, 0, 1, FALSE, FALSE,
        &transferred) != CF_IO_ERROR || transferred != 0) {
        fprintf(stderr, "page-register failure: write did not report poisoned postcommit failure\n");
        goto done;
    }
    if (cf_store_stats(store, &stats) != CF_IO_ERROR || !stats.poisoned) {
        fprintf(stderr, "page-register failure: store did not enter poisoned state\n");
        goto done;
    }
    cf_test_fail_page_register(0);
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\register", &node) != CF_OK ||
        !read_byte(store, node, 0, &actual) || actual != value) {
        fprintf(stderr, "page-register failure: committed replacement did not recover\n");
        goto done;
    }
    ok = TRUE;
done:
    cf_test_fail_page_register(0);
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    cf_wipe(block, sizeof(block));
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_page_allocation_failure_atomicity(void)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *node = NULL, *missing = NULL;
    CF_INFO info;
    CF_STATS stats;
    CF_RESULT op_result;
    uint8_t block[CF_BLOCK_SIZE], output[CF_BLOCK_SIZE];
    uint8_t before[32], after[32];
    uint32_t transferred = 0;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-allocation-fail-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!cf_crypto_init())
        goto done;
    cf_random(block, sizeof(block));
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\allocation", FILE_ATTRIBUTE_NORMAL, &node) != CF_OK ||
        cf_node_write(store, node, block, 0, sizeof(block), FALSE, FALSE,
            &transferred) != CF_OK || transferred != sizeof(block) ||
        cf_store_flush(store) != CF_OK) {
        fprintf(stderr, "allocation failure: initial full-block fixture setup failed\n");
        goto done;
    }
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (!hash_file(path, before)) {
        fprintf(stderr, "allocation failure: initial host hash failed after close\n");
        goto done;
    }
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\allocation", &node) != CF_OK) {
        fprintf(stderr, "allocation failure: remount before injected resize failed\n");
        goto done;
    }
    cf_test_fail_page_allocation(1);
    op_result = cf_node_resize(store, node, 1024, FALSE);
    if (op_result != CF_NO_SPACE) {
        fprintf(stderr, "allocation failure: partial shrink expected CF_NO_SPACE, got %u\n",
            (unsigned)op_result);
        goto done;
    }
    op_result = cf_store_stats(store, &stats);
    if (op_result != CF_OK || stats.poisoned) {
        fprintf(stderr, "allocation failure: stats got %u poisoned=%u\n",
            (unsigned)op_result, (unsigned)stats.poisoned);
        goto done;
    }
    op_result = cf_node_info(store, node, &info);
    if (op_result != CF_OK || info.size != CF_BLOCK_SIZE) {
        fprintf(stderr, "allocation failure: old size check got %u size=%llu\n",
            (unsigned)op_result, (unsigned long long)info.size);
        goto done;
    }
    op_result = cf_node_read(store, node, output, 0, sizeof(output), &transferred);
    if (op_result != CF_OK || transferred != sizeof(output) ||
        memcmp(output, block, sizeof(block)) != 0) {
        fprintf(stderr, "allocation failure: old bytes check got %u transferred=%u equal=%u\n",
            (unsigned)op_result, transferred,
            (unsigned)(memcmp(output, block, sizeof(block)) == 0));
        goto done;
    }
    cf_test_fail_page_allocation(0);
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (!hash_file(path, after)) {
        fprintf(stderr, "allocation failure: post-failure host hash failed after close\n");
        goto done;
    }
    if (memcmp(before, after, sizeof(before)) != 0) {
        fprintf(stderr, "allocation failure: partial shrink changed host bytes\n");
        goto done;
    }
    if (open_store(path, FALSE, FALSE, &store) != CF_OK) {
        fprintf(stderr, "allocation failure: remount after partial shrink failed\n");
        goto done;
    }
    if (cf_node_open(store, L"\\allocation", &node) != CF_OK) {
        fprintf(stderr, "allocation failure: remounted file open failed\n");
        goto done;
    }
    op_result = cf_node_read(store, node, output, 0, sizeof(output), &transferred);
    if (op_result != CF_OK || transferred != sizeof(output) ||
        memcmp(output, block, sizeof(block)) != 0) {
        fprintf(stderr, "allocation failure: remounted original bytes check got %u transferred=%u\n",
            (unsigned)op_result, transferred);
        goto done;
    }

    /* The aligned shrink and unlink need no newly allocated physical pages. */
    cf_test_fail_page_allocation(1);
    op_result = cf_node_resize(store, node, 0, FALSE);
    if (op_result != CF_OK) {
        fprintf(stderr, "allocation failure: aligned truncate expected CF_OK, got %u\n",
            (unsigned)op_result);
        goto done;
    }
    if (cf_node_info(store, node, &info) != CF_OK || info.size != 0) {
        fprintf(stderr, "allocation failure: aligned truncate size did not reach zero\n");
        goto done;
    }
    op_result = cf_node_unlink(store, node);
    if (op_result != CF_OK) {
        fprintf(stderr, "allocation failure: unlink expected CF_OK, got %u\n",
            (unsigned)op_result);
        goto done;
    }
    cf_test_fail_page_allocation(0);
    cf_node_close(store, node); node = NULL;
    if (cf_node_open(store, L"\\allocation", &missing) != CF_NOT_FOUND || missing) {
        fprintf(stderr, "allocation failure: path remained visible after unlink\n");
        goto done;
    }
    cf_store_close(store); store = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK) {
        fprintf(stderr, "allocation failure: remount after unlink failed\n");
        goto done;
    }
    if (cf_node_open(store, L"\\allocation", &missing) != CF_NOT_FOUND || missing) {
        fprintf(stderr, "allocation failure: unlinked path returned after remount\n");
        goto done;
    }
    ok = TRUE;
done:
    cf_test_fail_page_allocation(0);
    if (node && store) cf_node_close(store, node);
    if (missing && store) cf_node_close(store, missing);
    if (store) cf_store_close(store);
    cf_wipe(block, sizeof(block)); cf_wipe(output, sizeof(output));
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static void
clear_host_io_hooks(void)
{
    cf_test_fail_host_io(CF_TEST_IO_WRITE, 0);
    cf_test_fail_host_io(CF_TEST_IO_FLUSH, 0);
    cf_test_fail_host_io(CF_TEST_IO_EOF, 0);
    cf_test_fail_host_io(CF_TEST_IO_PUNCH, 0);
}

static BOOL
check_creation_time_after_reopen(const wchar_t *path, uint64_t expected)
{
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_INFO info;
    BOOL ok = FALSE;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\fault", &node) != CF_OK ||
        cf_node_info(store, node, &info) != CF_OK ||
        info.creation_time != expected) {
        fprintf(stderr, "host I/O fixture: reopened creation time did not match %llu\n",
            (unsigned long long)expected);
        goto done;
    }
    ok = TRUE;
done:
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    return ok;
}

static int
run_host_io_failure_case(unsigned case_id, unsigned operation,
    unsigned occurrence, BOOL short_marker, BOOL expect_poison,
    uint64_t expected_creation_time)
{
    wchar_t path[MAX_PATH * 2];
    const uint64_t initial_time = 111111111ULL;
    const uint64_t changed_time = 222222222ULL;
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_STATS stats;
    CF_RESULT result;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-host-io-%u-%lu.cf", g_directory, case_id,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\fault", FILE_ATTRIBUTE_NORMAL, &node) != CF_OK ||
        cf_node_set_basic(store, node, FILE_ATTRIBUTE_NORMAL,
            initial_time, 0, 0, 0) != CF_OK)
        goto done;
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;

    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\fault", &node) != CF_OK)
        goto done;
    if (short_marker)
        cf_test_short_marker_write();
    else
        cf_test_fail_host_io(operation, occurrence);
    result = cf_node_set_basic(store, node, FILE_ATTRIBUTE_NORMAL,
        changed_time, 0, 0, 0);
    if (result != CF_IO_ERROR) {
        fprintf(stderr, "host I/O case %u: expected CF_IO_ERROR, got %u\n",
            case_id, (unsigned)result);
        goto done;
    }
    result = cf_store_stats(store, &stats);
    if ((expect_poison && (result != CF_IO_ERROR || !stats.poisoned)) ||
        (!expect_poison && (result != CF_OK || stats.poisoned))) {
        fprintf(stderr, "host I/O case %u: stats result=%u poisoned=%u\n",
            case_id, (unsigned)result, (unsigned)stats.poisoned);
        goto done;
    }
    if (expect_poison && cf_node_set_basic(store, node, FILE_ATTRIBUTE_NORMAL,
        changed_time + 1, 0, 0, 0) != CF_IO_ERROR) {
        fprintf(stderr, "host I/O case %u: poisoned store accepted another mutation\n",
            case_id);
        goto done;
    }
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (!check_creation_time_after_reopen(path, expected_creation_time)) {
        fprintf(stderr, "host I/O case %u: remount did not yield expected logical state\n",
            case_id);
        goto done;
    }
    ok = TRUE;
done:
    clear_host_io_hooks();
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_host_io_transaction_failures(void)
{
    /* WRITE/FLUSH #1 are before the durable commit marker. WRITE #2 is the
       marker write seam, while FLUSH #2 is after its bytes were written. */
    CHECK(run_host_io_failure_case(1, CF_TEST_IO_WRITE, 1, FALSE, FALSE,
        111111111ULL) == 0);
    CHECK(run_host_io_failure_case(2, CF_TEST_IO_FLUSH, 1, FALSE, FALSE,
        111111111ULL) == 0);
    CHECK(run_host_io_failure_case(3, CF_TEST_IO_WRITE, 2, FALSE, TRUE,
        111111111ULL) == 0);
    CHECK(run_host_io_failure_case(4, CF_TEST_IO_FLUSH, 2, FALSE, TRUE,
        222222222ULL) == 0);
    CHECK(run_host_io_failure_case(5, CF_TEST_IO_EOF, 1, FALSE, TRUE,
        222222222ULL) == 0);
    CHECK(run_host_io_failure_case(6, 0, 0, TRUE, TRUE,
        222222222ULL) == 0);
    return 0;
}

static int
run_block_overwrite_io_failure(unsigned case_id, unsigned write_occurrence,
    BOOL expect_poison)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_STATS stats;
    uint8_t original[CF_BLOCK_SIZE], replacement[CF_BLOCK_SIZE];
    uint8_t output[CF_BLOCK_SIZE], before[32], after[32];
    uint32_t transferred = 0;
    CF_RESULT result;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-overwrite-io-%u-%lu.cf", g_directory, case_id,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!cf_crypto_init())
        goto done;
    cf_random(original, sizeof(original));
    cf_random(replacement, sizeof(replacement));
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\overwrite", FILE_ATTRIBUTE_NORMAL, &node) != CF_OK ||
        cf_node_write(store, node, original, 0, sizeof(original), FALSE, FALSE,
            &transferred) != CF_OK || transferred != sizeof(original) ||
        cf_store_flush(store) != CF_OK)
        goto done;
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (!hash_file(path, before) || open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\overwrite", &node) != CF_OK)
        goto done;
    cf_test_fail_host_io(CF_TEST_IO_WRITE, write_occurrence);
    result = cf_node_write(store, node, replacement, 0, sizeof(replacement),
        FALSE, FALSE, &transferred);
    if (result != CF_IO_ERROR || transferred != 0) {
        fprintf(stderr, "overwrite I/O case %u: result=%u transferred=%u\n",
            case_id, (unsigned)result, transferred);
        goto done;
    }
    result = cf_store_stats(store, &stats);
    if ((expect_poison && (result != CF_IO_ERROR || !stats.poisoned)) ||
        (!expect_poison && (result != CF_OK || stats.poisoned))) {
        fprintf(stderr, "overwrite I/O case %u: stats result=%u poisoned=%u\n",
            case_id, (unsigned)result, (unsigned)stats.poisoned);
        goto done;
    }
    if (!expect_poison &&
        (cf_node_read(store, node, output, 0, sizeof(output), &transferred) != CF_OK ||
            transferred != sizeof(output) || memcmp(output, original, sizeof(original)) != 0)) {
        fprintf(stderr, "overwrite I/O case %u: precommit RAM rollback lost old bytes\n", case_id);
        goto done;
    }
    clear_host_io_hooks();
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (!expect_poison && (!hash_file(path, after) ||
        memcmp(before, after, sizeof(before)) != 0)) {
        fprintf(stderr, "overwrite I/O case %u: failed journal write changed host bytes\n", case_id);
        goto done;
    }
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\overwrite", &node) != CF_OK ||
        cf_node_read(store, node, output, 0, sizeof(output), &transferred) != CF_OK ||
        transferred != sizeof(output) || memcmp(output, original, sizeof(original)) != 0) {
        fprintf(stderr, "overwrite I/O case %u: old block did not survive remount\n", case_id);
        goto done;
    }
    ok = TRUE;
done:
    clear_host_io_hooks();
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    cf_wipe(original, sizeof(original));
    cf_wipe(replacement, sizeof(replacement));
    cf_wipe(output, sizeof(output));
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_block_overwrite_io_failures(void)
{
    CHECK(run_block_overwrite_io_failure(1, 1, FALSE) == 0);
    CHECK(run_block_overwrite_io_failure(2, 2, TRUE) == 0);
    return 0;
}

static int
test_reclaim_failure_namespace_commit(void)
{
    wchar_t unlink_path[MAX_PATH * 2], rename_path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *unlinked = NULL, *source = NULL, *target = NULL, *opened = NULL;
    CF_INFO source_info, actual_info;
    uint8_t source_byte = (uint8_t)'S', target_byte = (uint8_t)'T', actual = 0;
    uint32_t transferred = 0;
    BOOL ok = FALSE;
    if (_snwprintf_s(unlink_path, ARRAYSIZE(unlink_path), _TRUNCATE,
        L"%ls\\cryptfs-reclaim-unlink-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0 ||
        _snwprintf_s(rename_path, ARRAYSIZE(rename_path), _TRUNCATE,
        L"%ls\\cryptfs-reclaim-rename-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(unlink_path); DeleteFileW(rename_path);

    if (open_store(unlink_path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\victim", FILE_ATTRIBUTE_NORMAL, &unlinked) != CF_OK)
        goto done;
    cf_node_close(store, unlinked); /* linked, zero-reference node remains store-owned */
    cf_test_fail_reclaim(1);
    if (cf_node_unlink(store, unlinked) != CF_OK ||
        cf_node_open(store, L"\\victim", &opened) != CF_NOT_FOUND || opened) {
        fprintf(stderr, "reclaim failure: committed unlink did not report namespace success\n");
        goto done;
    }
    cf_test_fail_reclaim(0);
    cf_store_close(store); store = NULL; unlinked = NULL;
    if (open_store(unlink_path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\victim", &opened) != CF_NOT_FOUND || opened)
        goto done;
    cf_store_close(store); store = NULL;

    if (open_store(rename_path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\source", FILE_ATTRIBUTE_NORMAL, &source) != CF_OK ||
        cf_node_create(store, L"\\target", FILE_ATTRIBUTE_NORMAL, &target) != CF_OK ||
        cf_node_write(store, source, &source_byte, 0, 1, FALSE, FALSE,
            &transferred) != CF_OK || transferred != 1 ||
        cf_node_write(store, target, &target_byte, 0, 1, FALSE, FALSE,
            &transferred) != CF_OK || transferred != 1 ||
        cf_node_info(store, source, &source_info) != CF_OK)
        goto done;
    cf_node_close(store, target); target = NULL; /* replacement candidate has zero refs */
    cf_test_fail_reclaim(1);
    if (cf_node_rename(store, source, L"\\target", TRUE) != CF_OK ||
        cf_node_open(store, L"\\source", &opened) != CF_NOT_FOUND || opened ||
        cf_node_open(store, L"\\target", &opened) != CF_OK ||
        cf_node_info(store, opened, &actual_info) != CF_OK ||
        actual_info.id != source_info.id || !read_byte(store, opened, 0, &actual) ||
        actual != source_byte) {
        fprintf(stderr, "reclaim failure: replacement rename did not preserve namespace source\n");
        goto done;
    }
    cf_node_close(store, opened); opened = NULL;
    cf_test_fail_reclaim(0);
    cf_node_close(store, source); source = NULL;
    cf_store_close(store); store = NULL;
    if (open_store(rename_path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\target", &opened) != CF_OK ||
        cf_node_info(store, opened, &actual_info) != CF_OK ||
        actual_info.id != source_info.id || !read_byte(store, opened, 0, &actual) ||
        actual != source_byte)
        goto done;
    ok = TRUE;
done:
    cf_test_fail_reclaim(0);
    if (target && store) cf_node_close(store, target);
    if (source && store) cf_node_close(store, source);
    if (opened && store) cf_node_close(store, opened);
    if (store) cf_store_close(store);
    DeleteFileW(unlink_path); DeleteFileW(rename_path);
    return ok ? 0 : 1;
}

static int
run_reclaim_host_io_case(unsigned case_id, unsigned operation,
    unsigned occurrence, BOOL expect_poison)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *victim = NULL, *missing = NULL;
    CF_STATS stats;
    CF_RESULT result;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-reclaim-io-%u-%lu.cf", g_directory, case_id,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\victim", FILE_ATTRIBUTE_NORMAL, &victim) != CF_OK)
        goto done;
    cf_node_close(store, victim); /* linked, zero-reference node is store-owned */
    cf_test_fail_host_io(operation, occurrence);
    result = cf_node_unlink(store, victim);
    if (result != CF_OK) {
        fprintf(stderr, "reclaim host-I/O case %u: unlink expected namespace CF_OK, got %u\n",
            case_id, (unsigned)result);
        goto done;
    }
    result = cf_store_stats(store, &stats);
    if ((expect_poison && (result != CF_IO_ERROR || !stats.poisoned)) ||
        (!expect_poison && (result != CF_OK || stats.poisoned))) {
        fprintf(stderr, "reclaim host-I/O case %u: stats result=%u poisoned=%u\n",
            case_id, (unsigned)result, (unsigned)stats.poisoned);
        goto done;
    }
    result = cf_node_open(store, L"\\victim", &missing);
    if ((expect_poison && (result != CF_IO_ERROR || missing)) ||
        (!expect_poison && (result != CF_NOT_FOUND || missing))) {
        fprintf(stderr, "reclaim host-I/O case %u: lookup result=%u poisoned=%u node=%p\n",
            case_id, (unsigned)result, (unsigned)expect_poison, (void *)missing);
        goto done;
    }
    clear_host_io_hooks();
    cf_store_close(store); store = NULL; victim = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\victim", &missing) != CF_NOT_FOUND || missing) {
        fprintf(stderr, "reclaim host-I/O case %u: namespace did not survive remount\n",
            case_id);
        goto done;
    }
    ok = TRUE;
done:
    clear_host_io_hooks();
    if (missing && store) cf_node_close(store, missing);
    if (store) cf_store_close(store);
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_reclaim_host_io_failures(void)
{
    /* First two transaction writes are the committed unlink. Reclamation
       then writes its journal at #6 and its commit marker at #7. */
    CHECK(run_reclaim_host_io_case(1, CF_TEST_IO_WRITE, 6, FALSE) == 0);
    CHECK(run_reclaim_host_io_case(2, CF_TEST_IO_WRITE, 7, TRUE) == 0);
    CHECK(run_reclaim_host_io_case(3, CF_TEST_IO_FLUSH, 6, FALSE) == 0);
    CHECK(run_reclaim_host_io_case(4, CF_TEST_IO_FLUSH, 7, TRUE) == 0);
    return 0;
}

static BOOL
prepare_compaction_hole(const wchar_t *path, uint8_t block[CF_BLOCK_SIZE])
{
    CF_STORE *store = NULL;
    CF_NODE *hole = NULL, *data = NULL;
    uint32_t transferred = 0;
    BOOL ok = FALSE;
    for (size_t i = 0; i < CF_BLOCK_SIZE; ++i)
        block[i] = (uint8_t)(i * 41u + 7u);
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\hole", FILE_ATTRIBUTE_NORMAL, &hole) != CF_OK ||
        cf_node_create(store, L"\\data", FILE_ATTRIBUTE_NORMAL, &data) != CF_OK ||
        cf_node_write(store, data, block, 0, CF_BLOCK_SIZE, FALSE, FALSE,
            &transferred) != CF_OK || transferred != CF_BLOCK_SIZE)
        goto done;
    cf_node_close(store, hole); /* preserve the zero-reference node for unlink */
    if (cf_node_unlink(store, hole) != CF_OK)
        goto done;
    hole = NULL;
    cf_node_close(store, data); data = NULL;
    ok = cf_store_flush(store) == CF_OK;
done:
    if (hole && store) cf_node_close(store, hole);
    if (data && store) cf_node_close(store, data);
    if (store) cf_store_close(store);
    return ok;
}

static int
run_compaction_move_io_case(unsigned case_id, unsigned operation,
    unsigned occurrence, BOOL precommit)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    CF_STATS before, after;
    uint8_t block[CF_BLOCK_SIZE], output[CF_BLOCK_SIZE];
    uint32_t transferred = 0;
    bool progress = false;
    CF_RESULT result;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-move-io-%u-%lu.cf", g_directory, case_id,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!prepare_compaction_hole(path, block) ||
        open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\data", &node) != CF_OK ||
        cf_store_stats(store, &before) != CF_OK)
        goto done;
    cf_test_fail_host_io(operation, occurrence);
    result = cf_store_compact_step(store, &progress);
    if (result != CF_IO_ERROR || progress) {
        fprintf(stderr, "compaction move I/O case %u: expected failed step, got %u progress=%u\n",
            case_id, (unsigned)result, (unsigned)progress);
        goto done;
    }
    result = cf_store_stats(store, &after);
    if ((precommit && (result != CF_OK || after.poisoned ||
            after.eof_bytes != before.eof_bytes)) ||
        (!precommit && (result != CF_IO_ERROR || !after.poisoned))) {
        fprintf(stderr, "compaction move I/O case %u: stats result=%u poisoned=%u EOF=%llu/%llu\n",
            case_id, (unsigned)result, (unsigned)after.poisoned,
            (unsigned long long)after.eof_bytes, (unsigned long long)before.eof_bytes);
        goto done;
    }
    if (precommit) {
        clear_host_io_hooks();
        progress = false;
        if (cf_store_compact_step(store, &progress) != CF_OK || !progress) {
            fprintf(stderr, "compaction move I/O case %u: retry did not progress\n", case_id);
            goto done;
        }
    }
    clear_host_io_hooks();
    cf_node_close(store, node); node = NULL;
    cf_store_close(store); store = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\data", &node) != CF_OK ||
        cf_node_read(store, node, output, 0, sizeof(output), &transferred) != CF_OK ||
        transferred != sizeof(output) || memcmp(block, output, sizeof(block)) != 0) {
        fprintf(stderr, "compaction move I/O case %u: remounted block mismatch\n", case_id);
        goto done;
    }
    if (!precommit) {
        progress = false;
        if (cf_store_compact_step(store, &progress) != CF_OK || !progress) {
            fprintf(stderr, "compaction move I/O case %u: recovery did not allow next step\n",
                case_id);
            goto done;
        }
        if (cf_node_read(store, node, output, 0, sizeof(output), &transferred) != CF_OK ||
            transferred != sizeof(output) || memcmp(block, output, sizeof(block)) != 0)
            goto done;
    }
    ok = TRUE;
done:
    clear_host_io_hooks();
    if (node && store) cf_node_close(store, node);
    if (store) cf_store_close(store);
    cf_wipe(block, sizeof(block)); cf_wipe(output, sizeof(output));
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
run_compaction_trim_io_case(unsigned case_id, unsigned operation,
    unsigned occurrence, BOOL precommit, uint64_t expected_eof)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_STATS before, after;
    bool progress = false;
    CF_RESULT result;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-trim-io-%u-%lu.cf", g_directory, case_id,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!prepare_zero_image_shrink(path) ||
        open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_store_stats(store, &before) != CF_OK)
        goto done;
    cf_test_fail_host_io(operation, occurrence);
    result = cf_store_compact_step(store, &progress);
    if (result != CF_IO_ERROR || progress) {
        fprintf(stderr, "compaction trim I/O case %u: expected failed step, got %u progress=%u\n",
            case_id, (unsigned)result, (unsigned)progress);
        goto done;
    }
    result = cf_store_stats(store, &after);
    if ((precommit && (result != CF_OK || after.poisoned ||
            after.eof_bytes != before.eof_bytes)) ||
        (!precommit && (result != CF_IO_ERROR || !after.poisoned))) {
        fprintf(stderr, "compaction trim I/O case %u: stats result=%u poisoned=%u EOF=%llu/%llu\n",
            case_id, (unsigned)result, (unsigned)after.poisoned,
            (unsigned long long)after.eof_bytes, (unsigned long long)before.eof_bytes);
        goto done;
    }
    if (precommit) {
        clear_host_io_hooks();
        progress = false;
        if (cf_store_compact_step(store, &progress) != CF_OK || !progress ||
            cf_store_stats(store, &after) != CF_OK || after.eof_bytes != CF_MIN_EOF) {
            fprintf(stderr, "compaction trim I/O case %u: retry failed to trim EOF\n", case_id);
            goto done;
        }
    }
    clear_host_io_hooks();
    cf_store_close(store); store = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_store_stats(store, &after) != CF_OK || after.poisoned ||
        after.eof_bytes != expected_eof) {
        fprintf(stderr, "compaction trim I/O case %u: remount EOF=%llu expected=%llu\n",
            case_id, (unsigned long long)after.eof_bytes,
            (unsigned long long)expected_eof);
        goto done;
    }
    ok = TRUE;
done:
    clear_host_io_hooks();
    if (store) cf_store_close(store);
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_compaction_host_io_failures(void)
{
    uint64_t tail_eof;
    wchar_t path[MAX_PATH * 2];
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-trim-size-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!prepare_zero_image_shrink(path)) {
        DeleteFileW(path);
        return 1;
    }
    {
        CF_STORE *store = NULL;
        CF_STATS stats;
        if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
            cf_store_stats(store, &stats) != CF_OK) {
            if (store) cf_store_close(store);
            DeleteFileW(path);
            return 1;
        }
        tail_eof = stats.eof_bytes;
        cf_store_close(store);
    }
    DeleteFileW(path);

    CHECK(run_compaction_move_io_case(1, CF_TEST_IO_WRITE, 1, TRUE) == 0);
    CHECK(run_compaction_move_io_case(2, CF_TEST_IO_FLUSH, 1, TRUE) == 0);
    CHECK(run_compaction_move_io_case(3, CF_TEST_IO_WRITE, 2, FALSE) == 0);
    CHECK(run_compaction_move_io_case(4, CF_TEST_IO_FLUSH, 2, FALSE) == 0);
    CHECK(run_compaction_move_io_case(5, CF_TEST_IO_WRITE, 3, FALSE) == 0);
    CHECK(run_compaction_move_io_case(6, CF_TEST_IO_EOF, 1, FALSE) == 0);
    CHECK(run_compaction_move_io_case(7, CF_TEST_IO_WRITE, 5, FALSE) == 0);

    CHECK(run_compaction_trim_io_case(1, CF_TEST_IO_WRITE, 1, TRUE, CF_MIN_EOF) == 0);
    CHECK(run_compaction_trim_io_case(2, CF_TEST_IO_FLUSH, 1, TRUE, CF_MIN_EOF) == 0);
    CHECK(run_compaction_trim_io_case(3, CF_TEST_IO_WRITE, 2, FALSE, tail_eof) == 0);
    CHECK(run_compaction_trim_io_case(4, CF_TEST_IO_FLUSH, 2, FALSE, CF_MIN_EOF) == 0);
    CHECK(run_compaction_trim_io_case(5, CF_TEST_IO_EOF, 1, FALSE, CF_MIN_EOF) == 0);
    CHECK(run_compaction_trim_io_case(6, CF_TEST_IO_WRITE, 3, FALSE, CF_MIN_EOF) == 0);
    return 0;
}

static int
test_compaction_punch_failure(void)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *victim = NULL, *data_node = NULL;
    CF_STATS before, after;
    uint8_t input[CF_BLOCK_SIZE], output[CF_BLOCK_SIZE];
    uint32_t transferred = 0;
    bool progress = false;
    BOOL ok = FALSE;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-punch-fail-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    if (!cf_crypto_init())
        goto done;
    cf_random(input, sizeof(input));
    if (open_store(path, TRUE, FALSE, &store) != CF_OK ||
        cf_node_create(store, L"\\hole", FILE_ATTRIBUTE_NORMAL, &victim) != CF_OK ||
        cf_node_create(store, L"\\data", FILE_ATTRIBUTE_NORMAL, &data_node) != CF_OK ||
        cf_node_write(store, data_node, input, 0, sizeof(input), FALSE, FALSE,
            &transferred) != CF_OK || transferred != sizeof(input)) {
        fprintf(stderr, "compaction punch: fixture creation/write failed\n");
        goto done;
    }
    cf_node_close(store, victim); /* zero-reference linked node stays store-owned */
    if (cf_node_unlink(store, victim) != CF_OK) {
        fprintf(stderr, "compaction punch: unlink hole fixture failed\n");
        goto done;
    }
    victim = NULL;
    if (cf_store_stats(store, &before) != CF_OK || before.live_pages < 3) {
        fprintf(stderr, "compaction punch: expected active pages and a hole\n");
        goto done;
    }
    cf_test_fail_host_io(CF_TEST_IO_PUNCH, 1);
    if (cf_store_compact_step(store, &progress) != CF_OK || !progress) {
        fprintf(stderr, "compaction punch: relocation did not complete nonfatally\n");
        goto done;
    }
    clear_host_io_hooks();
    if (cf_store_stats(store, &after) != CF_OK || after.poisoned ||
        after.last_host_error != ERROR_NOT_SUPPORTED ||
        cf_node_read(store, data_node, output, 0, sizeof(output), &transferred) != CF_OK ||
        transferred != sizeof(output) || memcmp(input, output, sizeof(input)) != 0) {
        fprintf(stderr, "compaction punch: data or nonfatal error state check failed\n");
        goto done;
    }
    progress = false;
    if (cf_store_compact_step(store, &progress) != CF_OK || !progress ||
        cf_store_stats(store, &after) != CF_OK || after.eof_bytes >= before.eof_bytes) {
        fprintf(stderr, "compaction punch: follow-up EOF trim did not reclaim tail\n");
        goto done;
    }
    cf_node_close(store, data_node); data_node = NULL;
    cf_store_close(store); store = NULL;
    if (open_store(path, FALSE, FALSE, &store) != CF_OK ||
        cf_node_open(store, L"\\data", &data_node) != CF_OK ||
        cf_node_read(store, data_node, output, 0, sizeof(output), &transferred) != CF_OK ||
        transferred != sizeof(output) || memcmp(input, output, sizeof(input)) != 0) {
        fprintf(stderr, "compaction punch: post-trim remount data check failed\n");
        goto done;
    }
    ok = TRUE;
done:
    clear_host_io_hooks();
    if (victim && store) cf_node_close(store, victim);
    if (data_node && store) cf_node_close(store, data_node);
    if (store) cf_store_close(store);
    cf_wipe(input, sizeof(input)); cf_wipe(output, sizeof(output));
    DeleteFileW(path);
    return ok ? 0 : 1;
}

static int
test_multi_map_trim_persistence(void)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *file = NULL;
    const uint32_t initial_blocks = 130;
    const uint32_t deep_trim_blocks = 63;
    const uint32_t trim_boundary = 125;
    const size_t bytes = (size_t)initial_blocks * CF_BLOCK_SIZE;
    uint8_t *input = NULL;
    uint8_t last = 0;
    uint32_t transferred = 0;
    CF_INFO info;
    uint32_t i;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-map-trim-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    input = (uint8_t *)malloc(bytes);
    CHECK(input != NULL);
    /* Distinct but highly compressible blocks exercise a multi-map chain. */
    for (i = 0; i < initial_blocks; ++i)
        memset(input + (size_t)i * CF_BLOCK_SIZE, (int)(i * 29u), CF_BLOCK_SIZE);
    CHECK(open_store(path, TRUE, FALSE, &store) == CF_OK);
    CHECK(cf_node_create(store, L"\\multi", FILE_ATTRIBUTE_NORMAL, &file) == CF_OK);
    CHECK(cf_node_write(store, file, input, 0, (uint32_t)bytes, FALSE, FALSE,
        &transferred) == CF_OK && transferred == bytes);
    /* Trimming at the full-map boundary removes the entire second map. */
    CHECK(cf_node_resize(store, file,
        (uint64_t)trim_boundary * CF_BLOCK_SIZE, FALSE) == CF_OK);
    cf_node_close(store, file); file = NULL;
    CHECK(cf_store_flush(store) == CF_OK);
    cf_store_close(store); store = NULL;

    CHECK(open_store(path, FALSE, FALSE, &store) == CF_OK);
    CHECK(cf_node_open(store, L"\\multi", &file) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK &&
        info.size == (uint64_t)trim_boundary * CF_BLOCK_SIZE);
    CHECK(cf_node_read(store, file, &last, info.size - 1, 1,
        &transferred) == CF_OK && transferred == 1 &&
        last == (uint8_t)((trim_boundary - 1) * 29u));

    /* Remove entries within the retained first map after the tail map has
       already been detached. */
    CHECK(cf_node_resize(store, file,
        (uint64_t)deep_trim_blocks * CF_BLOCK_SIZE, FALSE) == CF_OK);
    cf_node_close(store, file); file = NULL;
    CHECK(cf_store_flush(store) == CF_OK);
    cf_store_close(store); store = NULL;
    CHECK(open_store(path, FALSE, FALSE, &store) == CF_OK);
    CHECK(cf_node_open(store, L"\\multi", &file) == CF_OK);
    CHECK(cf_node_info(store, file, &info) == CF_OK &&
        info.size == (uint64_t)deep_trim_blocks * CF_BLOCK_SIZE);
    CHECK(cf_node_read(store, file, &last, info.size - 1, 1,
        &transferred) == CF_OK && transferred == 1 &&
        last == (uint8_t)((deep_trim_blocks - 1) * 29u));
    cf_node_close(store, file); file = NULL;
    cf_store_close(store); store = NULL;
    cf_wipe(input, bytes);
    free(input);
    DeleteFileW(path);
    return 0;
}

static BOOL
expect_authenticated_graph_reject(const uint8_t uuid[16], const CF_KEYS *keys,
    uint64_t record_id, uint32_t field_offset, uint64_t invalid_value)
{
    uint8_t before[32], after[32];
    CF_OPTIONS options;
    CF_STORE *store = NULL;
    CF_RESULT result;
    BOOL ok = FALSE;
    if (!copy_sparse_container(g_container, g_backup)) {
        fprintf(stderr, "graph fixture: backup failed (error %lu)\n", (unsigned long)GetLastError());
        goto done;
    }
    if (!rewrite_inode_payload_u64(g_container, uuid, keys, record_id,
        field_offset, invalid_value)) {
        fprintf(stderr, "graph fixture: authenticated page rewrite failed record=%llu field=%u\n",
            (unsigned long long)record_id, field_offset);
        goto done;
    }
    if (!hash_file(g_container, before)) {
        fprintf(stderr, "graph fixture: pre-open hash failed after rewrite\n");
        goto done;
    }
    memset(&options, 0, sizeof(options));
    options.container = g_container;
    result = cf_store_open(&options, g_password, sizeof(g_password) - 1, &store);
    if (result != CF_DATA_ERROR || store != NULL) {
        fprintf(stderr, "graph fixture: expected CF_DATA_ERROR, got %u store=%p\n",
            (unsigned)result, (void *)store);
        goto done;
    }
    if (!hash_file(g_container, after)) {
        fprintf(stderr, "graph fixture: post-open hash failed\n");
        goto done;
    }
    if (memcmp(before, after, sizeof(before)) != 0) {
        fprintf(stderr, "graph fixture: rejected container changed on disk\n");
        goto done;
    }
    ok = TRUE;
done:
    if (store != NULL) {
        cf_store_close(store);
        store = NULL;
    }
    if (GetFileAttributesW(g_backup) != INVALID_FILE_ATTRIBUTES) {
        if (!copy_sparse_container(g_backup, g_container)) {
            fprintf(stderr, "graph fixture: restore backup failed (error %lu)\n",
                (unsigned long)GetLastError());
            ok = FALSE;
        } else if (open_store(g_container, FALSE, FALSE, &store) != CF_OK) {
            fprintf(stderr, "graph fixture: restored pristine container did not reopen\n");
            ok = FALSE;
        } else {
            cf_store_close(store);
            store = NULL;
        }
        DeleteFileW(g_backup);
    }
    return ok;
}

static int
test_authenticated_graph_corruption_no_write(void)
{
    uint8_t uuid[16];
    uint64_t parent_page_offset, parent_slot;
    CF_KEYS keys;
    int result = 1;
    memset(uuid, 0, sizeof(uuid)); memset(&keys, 0, sizeof(keys));
    if (g_auth_parent_id == 0 || g_second_child_id == 0) {
        fprintf(stderr, "graph fixture: expected inode IDs are absent (parent=%llu child=%llu)\n",
            (unsigned long long)g_auth_parent_id, (unsigned long long)g_second_child_id);
        goto done;
    }
    if (!derive_test_record_keys(g_container, uuid, &keys)) {
        fprintf(stderr, "graph fixture: record key derivation failed\n");
        goto done;
    }
    if (!find_inode_page_offset(g_container, g_auth_parent_id, &parent_page_offset)) {
        fprintf(stderr, "graph fixture: parent inode page lookup failed\n");
        goto done;
    }
    parent_slot = (parent_page_offset - CF_PAGES_OFFSET) / CF_PAGE_SIZE + 1;

    /* An authenticated first_child edge back to this directory is a graph cycle. */
    fprintf(stdout, "  graph case: authenticated self-cycle\n"); fflush(stdout);
    if (!expect_authenticated_graph_reject(uuid, &keys, g_auth_parent_id,
        CF_INODE_FIRST_CHILD, parent_slot)) {
        fprintf(stderr, "graph fixture: authenticated self-cycle case failed\n");
        goto done;
    }

    /* An authenticated child with a different parent_id breaks the sibling graph. */
    fprintf(stdout, "  graph case: authenticated parent mismatch\n"); fflush(stdout);
    if (!expect_authenticated_graph_reject(uuid, &keys, g_second_child_id,
        CF_INODE_PARENT_ID, g_auth_parent_id + 9999)) {
        fprintf(stderr, "graph fixture: authenticated parent-mismatch case failed\n");
        goto done;
    }
    result = 0;
done:
    cf_wipe(uuid, sizeof(uuid));
    cf_wipe(&keys, sizeof(keys));
    return result;
}

static int
test_committed_wal_tamper_no_write(void)
{
    wchar_t command[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD exit_code = 0;
    uint8_t before[32], after[32];
    CF_OPTIONS options;
    CF_STORE *store = NULL;
    CHECK(copy_sparse_container(g_container, g_backup));
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE,
        L"\"%ls\" --crash \"%ls\" 2", g_executable, g_container) < 0)
        return 1;
    memset(&startup, 0, sizeof(startup)); startup.cb = sizeof(startup);
    memset(&process, 0, sizeof(process));
    CHECK(CreateProcessW(g_executable, command, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
    CHECK(WaitForSingleObject(process.hProcess, 120000) == WAIT_OBJECT_0);
    CHECK(GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 102);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    /* Phase 2 exits after COMMITTED; corrupt encrypted WAL payload, not a home page. */
    CHECK(mutate_container_byte(g_container, CF_JOURNAL_OFFSET + CF_WAL_HEADER_SIZE + 1));
    CHECK(hash_file(g_container, before));
    memset(&options, 0, sizeof(options));
    options.container = g_container;
    CHECK(cf_store_open(&options, g_password, sizeof(g_password) - 1, &store) ==
        CF_DATA_ERROR && store == NULL);
    CHECK(hash_file(g_container, after) && memcmp(before, after, sizeof(before)) == 0);
    CHECK(copy_sparse_container(g_backup, g_container));
    CHECK(open_store(g_container, FALSE, FALSE, &store) == CF_OK);
    cf_store_close(store); store = NULL;
    DeleteFileW(g_backup);
    return 0;
}

static int
test_crash_recovery(void)
{
    unsigned phase;
    CF_STORE *store = NULL;
    CF_NODE *node = NULL;
    uint8_t actual;
    for (phase = 1; phase <= 5; ++phase) {
        uint8_t expected = phase == 1 ? (uint8_t)'A' : (uint8_t)('A' + phase);
        CHECK(run_crash_phase(phase, expected));
    }
    CHECK(open_store(g_container, FALSE, FALSE, &store) == CF_OK);
    CHECK(cf_node_open(store, L"\\crash", &node) == CF_OK);
    CHECK(read_byte(store, node, 0, &actual) && actual == (uint8_t)('A' + 5));
    cf_node_close(store, node);
    cf_store_close(store);
    CHECK(run_orphan_crash_and_reopen());
    CHECK(run_zero_image_shrink_phase(2));
    CHECK(run_zero_image_shrink_phase(3));
    CHECK(run_zero_image_shrink_phase(4));
    for (phase = 1; phase <= 5; ++phase)
        CHECK(run_resize_crash_phase(phase));
    CHECK(test_map_trim_crash_matrix() == 0);
    CHECK(test_namespace_compaction_crash_phases() == 0);
    return 0;
}

static int
test_background_shrink(void)
{
    wchar_t path[MAX_PATH * 2];
    CF_STORE *store = NULL;
    CF_NODE *file = NULL;
    CF_STATS before, after;
    uint8_t block[CF_BLOCK_SIZE];
    uint32_t transferred = 0;
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-shrink-test-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) < 0)
        return 1;
    DeleteFileW(path);
    CHECK(open_store(path, TRUE, TRUE, &store) == CF_OK);
    CHECK(cf_node_create(store, L"\\tail", FILE_ATTRIBUTE_NORMAL, &file) == CF_OK);
    if (!cf_crypto_init())
        return 1;
    cf_random(block, sizeof(block));
    CHECK(cf_node_write(store, file, block, 0, sizeof(block), FALSE, FALSE,
        &transferred) == CF_OK && transferred == sizeof(block));
    cf_node_close(store, file); file = NULL;
    CHECK(cf_store_wait_idle(store, 30000) == CF_OK);
    CHECK(cf_store_stats(store, &before) == CF_OK && before.eof_bytes > CF_MIN_EOF);
    CHECK(cf_node_open(store, L"\\tail", &file) == CF_OK);
    CHECK(cf_node_can_delete(store, file) == CF_OK);
    CHECK(cf_node_unlink(store, file) == CF_OK);
    cf_node_close(store, file); file = NULL;
    CHECK(cf_store_wait_idle(store, 30000) == CF_OK);
    CHECK(cf_store_stats(store, &after) == CF_OK && !after.poisoned);
    CHECK(after.eof_bytes == CF_MIN_EOF);
    cf_store_close(store);
    DeleteFileW(path);
    return 0;
}

/* Marker-based paging and exact child lookup used by the WinFsp directory callbacks. */
static int
test_directory_paging_and_lookup(void)
{
    enum { FILE_COUNT = 40, PAGE = 7 };
    wchar_t path[MAX_PATH * 2];
    wchar_t name[64];
    wchar_t last[CF_NAME_MAX + 1];
    CF_STORE *store = NULL;
    CF_NODE *directory = NULL, *file = NULL;
    CF_DIRENT *entries = NULL;
    CF_DIRENT entry;
    uint8_t block[CF_BLOCK_SIZE];
    size_t count = 0, seen = 0, i;
    uint32_t transferred = 0;
    bool more = true;
    int index;

    CHECK(_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE,
        L"%ls\\cryptfs-paging-%lu.cf", g_directory,
        (unsigned long)GetCurrentProcessId()) >= 0);
    DeleteFileW(path);
    CHECK(open_store(path, TRUE, FALSE, &store) == CF_OK && store != NULL);
    CHECK(cf_node_create(store, L"\\d", FILE_ATTRIBUTE_DIRECTORY, &directory) == CF_OK);
    for (index = FILE_COUNT - 1; index >= 0; --index) {
        CHECK(_snwprintf_s(name, ARRAYSIZE(name), _TRUNCATE, L"\\d\\f%03d", index) >= 0);
        CHECK(cf_node_create(store, name, FILE_ATTRIBUTE_NORMAL, &file) == CF_OK);
        if (index == 7) {
            memset(block, 0x5a, sizeof(block));
            CHECK(cf_node_write(store, file, block, 0, sizeof(block), false, false,
                &transferred) == CF_OK && transferred == sizeof(block));
        }
        cf_node_close(store, file);
        file = NULL;
    }

    /* Page through the directory with a small window; names arrive sorted, once. */
    last[0] = L'\0';
    while (more) {
        CHECK(cf_node_list_after(store, directory, seen ? last : NULL, PAGE,
            &entries, &count, &more) == CF_OK);
        CHECK(count <= PAGE && (count == PAGE || !more));
        for (i = 0; i < count; ++i) {
            CHECK(_snwprintf_s(name, ARRAYSIZE(name), _TRUNCATE, L"f%03u",
                (unsigned)(seen + i)) >= 0);
            CHECK(wcscmp(entries[i].name, name) == 0);
        }
        if (count != 0)
            wcscpy_s(last, ARRAYSIZE(last), entries[count - 1].name);
        seen += count;
        cf_list_free(entries, count);
        entries = NULL;
    }
    CHECK(seen == FILE_COUNT);

    /* A marker that is not an existing name resumes at the next larger name. */
    CHECK(cf_node_list_after(store, directory, L"f0105", PAGE, &entries, &count,
        &more) == CF_OK && count == PAGE && more &&
        wcscmp(entries[0].name, L"f011") == 0);
    cf_list_free(entries, count);
    entries = NULL;

    /* Exact, case-sensitive lookup; allocation reports one stored block. */
    CHECK(cf_node_child_info(store, directory, L"f007", &entry) == CF_OK &&
        wcscmp(entry.name, L"f007") == 0 && entry.info.size == CF_BLOCK_SIZE &&
        entry.info.allocation_size == CF_BLOCK_SIZE);
    CHECK(cf_node_child_info(store, directory, L"F007", &entry) == CF_NOT_FOUND);
    CHECK(cf_node_open(store, L"\\d\\f001", &file) == CF_OK);
    CHECK(cf_node_child_info(store, file, L"x", &entry) == CF_NOT_DIRECTORY);
    CHECK(cf_node_list_after(store, file, NULL, PAGE, &entries, &count, &more) ==
        CF_NOT_DIRECTORY);
    cf_node_close(store, file);
    cf_node_close(store, directory);
    cf_store_close(store);
    CHECK(DeleteFileW(path));
    return 0;
}

int
wmain(int argc, wchar_t **argv)
{
    if (argc == 4 && wcscmp(argv[1], L"--crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 1 || phase > 5)
            return 10;
        return run_crash_child(argv[2], phase);
    }
    if (argc == 4 && wcscmp(argv[1], L"--resize-crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 1 || phase > 5)
            return 49;
        return run_resize_crash_child(argv[2], phase);
    }
    if (argc == 4 && wcscmp(argv[1], L"--map-crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 1 || phase > 5)
            return 58;
        return run_map_trim_crash_child(argv[2], phase);
    }
    if (argc == 3 && wcscmp(argv[1], L"--orphan-crash") == 0)
        return run_orphan_crash_child(argv[2]);
    if (argc == 4 && wcscmp(argv[1], L"--trim-crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 2 || phase > 4)
            return 43;
        return run_trim_crash_child(argv[2], phase);
    }
    if (argc == 4 && wcscmp(argv[1], L"--unlink-crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 1 || phase > 5)
            return 71;
        return run_unlink_crash_child(argv[2], phase);
    }
    if (argc == 4 && wcscmp(argv[1], L"--rename-crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 1 || phase > 5)
            return 72;
        return run_rename_crash_child(argv[2], phase);
    }
    if (argc == 4 && wcscmp(argv[1], L"--move-crash") == 0) {
        unsigned phase = (unsigned)_wtoi(argv[3]);
        if (phase < 1 || phase > 5)
            return 73;
        return run_move_crash_child(argv[2], phase);
    }
    if (!make_test_path()) {
        fprintf(stderr, "cannot construct test container path\n");
        return 1;
    }
    if (argc == 2 && wcscmp(argv[1], L"--map-tests") == 0)
        return test_map_trim_crash_matrix();
    if (argc == 2 && wcscmp(argv[1], L"--namespace-tests") == 0)
        return test_namespace_compaction_crash_phases();
    DeleteFileW(g_container);
    DeleteFileW(g_backup);
    printf("stage: store functionality\n"); fflush(stdout);
    if (test_store_functionality() != 0)
        return 1;
    printf("stage: multi-map trim persistence\n"); fflush(stdout);
    if (test_multi_map_trim_persistence() != 0)
        return 1;
    printf("stage: authenticated page tamper\n"); fflush(stdout);
    if (test_authenticated_tamper_no_write() != 0)
        return 1;
    printf("stage: authenticated fragment tamper\n"); fflush(stdout);
    if (test_fragment_tamper_no_write() != 0)
        return 1;
    printf("stage: page-registration failure recovery\n"); fflush(stdout);
    if (test_page_registration_failure_recovery() != 0)
        return 1;
    printf("stage: page-allocation failure atomicity\n"); fflush(stdout);
    if (test_page_allocation_failure_atomicity() != 0)
        return 1;
    printf("stage: host I/O transaction failures\n"); fflush(stdout);
    if (test_host_io_transaction_failures() != 0)
        return 1;
    printf("stage: block-overwrite I/O rollback\n"); fflush(stdout);
    if (test_block_overwrite_io_failures() != 0)
        return 1;
    printf("stage: reclaim host I/O failures\n"); fflush(stdout);
    if (test_reclaim_host_io_failures() != 0)
        return 1;
    printf("stage: compaction host I/O failures\n"); fflush(stdout);
    if (test_compaction_host_io_failures() != 0)
        return 1;
    printf("stage: compaction punch failure\n"); fflush(stdout);
    if (test_compaction_punch_failure() != 0)
        return 1;
    printf("stage: reclaim failure namespace commit\n"); fflush(stdout);
    if (test_reclaim_failure_namespace_commit() != 0)
        return 1;
    printf("stage: authenticated graph corruption\n"); fflush(stdout);
    if (test_authenticated_graph_corruption_no_write() != 0)
        return 1;
    printf("stage: committed WAL tamper\n"); fflush(stdout);
    if (test_committed_wal_tamper_no_write() != 0)
        return 1;
    printf("stage: crash recovery\n"); fflush(stdout);
    if (test_crash_recovery() != 0)
        return 1;
    printf("stage: background shrink\n"); fflush(stdout);
    if (test_background_shrink() != 0)
        return 1;
    printf("stage: directory paging and lookup\n"); fflush(stdout);
    if (test_directory_paging_and_lookup() != 0)
        return 1;
    DeleteFileW(g_container);
    printf("store tests passed\n");
    return 0;
}
