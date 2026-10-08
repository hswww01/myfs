#pragma once
#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CF_BLOCK_SIZE 65536u
#define CF_NAME_MAX 255u
#define CF_DEFAULT_CAPACITY (1ULL << 40)
#define CF_MAX_NODES 65536u
#define CF_MAX_DEPTH 64u
#define CF_MAX_PAGES 4000000u

typedef enum CF_RESULT {
    CF_OK = 0, CF_NOT_FOUND, CF_PATH_NOT_FOUND, CF_EXISTS, CF_NOT_DIRECTORY,
    CF_IS_DIRECTORY, CF_NOT_EMPTY, CF_NO_SPACE, CF_NO_MEMORY, CF_INVALID,
    CF_ACCESS, CF_DATA_ERROR, CF_IO_ERROR, CF_NOT_SUPPORTED
} CF_RESULT;
typedef struct CF_STORE CF_STORE;
typedef struct CF_NODE CF_NODE;
typedef struct CF_OPTIONS {
    const wchar_t *container;
    uint64_t capacity;
    int compression_level;
    bool create_new;
    bool background_compaction;
} CF_OPTIONS;
typedef struct CF_INFO {
    uint64_t id, size, allocation_size;
    uint64_t creation_time, access_time, write_time, change_time;
    uint32_t attributes;
} CF_INFO;
typedef struct CF_DIRENT { wchar_t name[CF_NAME_MAX + 1]; CF_INFO info; } CF_DIRENT;
typedef struct CF_STATS {
    uint64_t capacity, free_bytes, logical_used, live_pages, eof_bytes, allocated_bytes;
    uint64_t commits, compact_moves;
    DWORD last_host_error;
    bool poisoned;
} CF_STATS;

/* Store owns keys; supplied password bytes are borrowed only until return. */
CF_RESULT cf_store_open(const CF_OPTIONS *, const uint8_t *password, size_t length, CF_STORE **);
void cf_store_close(CF_STORE *);
CF_RESULT cf_store_flush(CF_STORE *);
CF_RESULT cf_store_stats(CF_STORE *, CF_STATS *);
/* One bounded relocation/reclamation step; true means progress was made. */
CF_RESULT cf_store_compact_step(CF_STORE *, bool *progress);
/* Waits for an idle worker; inspect stats/errors to confirm reclamation. */
CF_RESULT cf_store_wait_idle(CF_STORE *, DWORD timeout_ms);
DWORD cf_store_host_error(CF_STORE *);
const char *cf_result_text(CF_RESULT);

/* Open/create return a referenced node; the final close reclaims unlinked files. */
CF_RESULT cf_node_open(CF_STORE *, const wchar_t *path, CF_NODE **);
CF_RESULT cf_node_create(CF_STORE *, const wchar_t *path, uint32_t attributes, CF_NODE **);
void cf_node_close(CF_STORE *, CF_NODE *);
CF_RESULT cf_node_info(CF_STORE *, CF_NODE *, CF_INFO *);
CF_RESULT cf_node_set_basic(CF_STORE *, CF_NODE *, uint32_t attributes,
    uint64_t creation_time, uint64_t access_time, uint64_t write_time, uint64_t change_time);
CF_RESULT cf_node_resize(CF_STORE *, CF_NODE *, uint64_t size, bool allocation_only);
CF_RESULT cf_node_read(CF_STORE *, CF_NODE *, void *buffer, uint64_t offset,
    uint32_t length, uint32_t *transferred);
CF_RESULT cf_node_write(CF_STORE *, CF_NODE *, const void *buffer, uint64_t offset,
    uint32_t length, bool append, bool constrained, uint32_t *transferred);
CF_RESULT cf_node_can_delete(CF_STORE *, CF_NODE *);
CF_RESULT cf_node_unlink(CF_STORE *, CF_NODE *);
CF_RESULT cf_node_rename(CF_STORE *, CF_NODE *, const wchar_t *new_path, bool replace);
CF_RESULT cf_node_list(CF_STORE *, CF_NODE *, CF_DIRENT **entries, size_t *count);
/* Lists at most max_entries children strictly after marker (NULL: from the start). */
CF_RESULT cf_node_list_after(CF_STORE *, CF_NODE *, const wchar_t *marker,
    size_t max_entries, CF_DIRENT **entries, size_t *count, bool *more);
/* Parent directory info; CF_NOT_FOUND for the root or an unlinked node. */
CF_RESULT cf_node_parent_info(CF_STORE *, CF_NODE *, CF_INFO *info);
/* Exact-name child lookup through the sorted directory index. */
CF_RESULT cf_node_child_info(CF_STORE *, CF_NODE *, const wchar_t *name, CF_DIRENT *entry);
void cf_list_free(CF_DIRENT *entries, size_t count);

#ifdef CRYPTFS_TESTING
/* Test-only process crash at durable phases 1..5; 0 disables it. */
void cf_test_crash_phase(unsigned phase);
/* Test-only one-shot failures; 1 fails the next call, 0 disables the hook. */
void cf_test_fail_page_register(unsigned occurrence);
void cf_test_fail_reclaim(unsigned occurrence);
void cf_test_fail_page_allocation(unsigned occurrence);
enum {
    CF_TEST_IO_WRITE = 1, CF_TEST_IO_FLUSH, CF_TEST_IO_EOF, CF_TEST_IO_PUNCH
};
void cf_test_fail_host_io(unsigned operation, unsigned occurrence);
/* Write a complete authenticated marker prefix, then report a short write. */
void cf_test_short_marker_write(void);
#endif
