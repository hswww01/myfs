#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "cryptfs_store.h"
#include "cryptfs_crypto.h"
#include "cryptfs_format.h"

typedef struct CF_PAGE CF_PAGE;
typedef struct CF_MAP_PAGE CF_MAP_PAGE;
typedef struct CF_BLOCK CF_BLOCK;
typedef struct CF_TX CF_TX;
typedef struct CF_IMAGE CF_IMAGE;

struct CF_PAGE {
    uint64_t slot;
    uint64_t record_id;
    uint16_t type;
    uint16_t reserved;
    uint32_t owner_offset;
    bool registered;
    CF_PAGE *owner;
    CF_PAGE *owned_head;
    CF_PAGE *owned_next;
    CF_NODE *inode;
    CF_MAP_PAGE *map;
};

struct CF_BLOCK {
    uint64_t index;
    uint32_t encoded_length;
    uint32_t codec;
    uint32_t fragment_count;
    CF_PAGE *fragments[CF_MAX_FRAGMENTS];
};

struct CF_MAP_PAGE {
    CF_PAGE *page;
    CF_MAP_PAGE *next;
    uint32_t count;
    /* Entry positions changed since owners were last derived (RAM only). */
    bool owners_dirty;
    CF_BLOCK *blocks[CF_MAP_CAPACITY];
};

struct CF_NODE {
    CF_STORE *store;
    uint64_t id;
    uint64_t parent_id;
    uint64_t size;
    uint64_t creation_time;
    uint64_t access_time;
    uint64_t write_time;
    uint64_t change_time;
    uint32_t attributes;
    uint16_t name_length;
    uint16_t depth;
    wchar_t name[CF_NAME_MAX + 1];
    uint32_t references;
    bool unlinked;
    bool reclaiming;
    CF_PAGE *page;
    CF_NODE *parent;
    CF_NODE *first_child;
    CF_NODE *next_sibling;
    CF_NODE *orphan_next;
    CF_NODE **children;
    size_t child_count;
    size_t child_capacity;
    CF_MAP_PAGE *maps;
    CF_MAP_PAGE *maps_tail;
};

struct CF_IMAGE {
    uint64_t slot;
    bool used;
    uint8_t pad[7];
    uint8_t bytes[CF_PAGE_SIZE];
};

struct CF_TX {
    CF_STORE *store;
    CF_IMAGE *images;
    uint32_t count;
    uint64_t reserved[CF_MAX_TRANSACTION_PAGES];
    uint32_t reserved_count;
    uint64_t final_eof;
    CF_RESULT failure;
};

struct CF_STORE {
    HANDLE file;
    wchar_t *path;
    SRWLOCK lock;
    CF_KEYS keys;
    uint8_t uuid[16];
    uint64_t capacity;
    uint64_t next_inode_id;
    uint64_t generation;
    uint64_t eof;
    uint64_t disk_eof;
    uint64_t logical_used;
    uint64_t live_page_count;
    uint64_t commits;
    uint64_t compact_moves;
    uint64_t slot_count;
    uint64_t allocation_hint;
    /* Every slot in [1, free_floor) is occupied in slots[]; 0 means 1. Lowered
     * whenever a slot is freed, so allocation never rescans a dense prefix. */
    uint64_t free_floor;
    CF_PAGE **slots;
    size_t slot_capacity;
    CF_PAGE *root_page;
    CF_NODE *root;
    CF_NODE **nodes;
    size_t node_count;
    size_t node_capacity;
    DWORD last_error;
    bool poisoned;
    int compression_level;
    bool stopping;
    HANDLE worker_thread;
    HANDLE worker_wake;
    HANDLE worker_idle;
    HANDLE worker_stop;
};

static const uint8_t g_sb_magic[8] = {'C','R','Y','P','T','F','S','1'};
static const uint8_t g_page_magic[4] = {'C','F','R','P'};
static const uint8_t g_marker_magic[8] = {'C','F','M','A','R','K','1',0};
static const uint8_t g_wal_magic[8] = {'C','F','W','A','L','1',0,0};
static const uint8_t g_wal_plain_magic[8] = {'C','F','J','N','L','1',0,0};

#ifdef CRYPTFS_TESTING
static volatile LONG g_test_crash_phase;
static volatile LONG g_test_fail_page_register_count;
static volatile LONG g_test_fail_reclaim_count;
static volatile LONG g_test_fail_page_allocation_count;
static volatile LONG g_test_host_io_count[CF_TEST_IO_PUNCH + 1];
static volatile LONG g_test_short_marker_write_pending;

void cf_test_crash_phase(unsigned phase) {
    InterlockedExchange(&g_test_crash_phase, phase <= 5 ? (LONG)phase : 0);
}

static bool cf_test_countdown_failure(volatile LONG *count) {
    LONG remaining = InterlockedCompareExchange(count, 0, 0);
    while (remaining > 0) {
        LONG observed = InterlockedCompareExchange(count, remaining - 1, remaining);
        if (observed == remaining)
            return remaining == 1;
        remaining = observed;
    }
    return false;
}

void cf_test_fail_page_register(unsigned occurrence) {
    LONG count = occurrence <= (unsigned)LONG_MAX ? (LONG)occurrence : 0;
    InterlockedExchange(&g_test_fail_page_register_count, count);
}

void cf_test_fail_reclaim(unsigned occurrence) {
    LONG count = occurrence <= (unsigned)LONG_MAX ? (LONG)occurrence : 0;
    InterlockedExchange(&g_test_fail_reclaim_count, count);
}

void cf_test_fail_page_allocation(unsigned occurrence) {
    LONG count = occurrence <= (unsigned)LONG_MAX ? (LONG)occurrence : 0;
    InterlockedExchange(&g_test_fail_page_allocation_count, count);
}

void cf_test_fail_host_io(unsigned operation, unsigned occurrence) {
    LONG count;
    if (operation < CF_TEST_IO_WRITE || operation > CF_TEST_IO_PUNCH)
        return;
    count = occurrence <= (unsigned)LONG_MAX ? (LONG)occurrence : 0;
    InterlockedExchange(&g_test_host_io_count[operation], count);
}

void cf_test_short_marker_write(void) {
    InterlockedExchange(&g_test_short_marker_write_pending, 1);
}

static DWORD cf_test_host_io_error(unsigned operation) {
    switch (operation) {
    case CF_TEST_IO_WRITE:
    case CF_TEST_IO_FLUSH:
        return ERROR_WRITE_FAULT;
    case CF_TEST_IO_EOF:
        return ERROR_DISK_FULL;
    case CF_TEST_IO_PUNCH:
        return ERROR_NOT_SUPPORTED;
    default:
        return ERROR_GEN_FAILURE;
    }
}

static bool cf_test_fail_host_io_now(unsigned operation, DWORD *error) {
    DWORD host_error;
    if (operation < CF_TEST_IO_WRITE || operation > CF_TEST_IO_PUNCH ||
        !cf_test_countdown_failure(&g_test_host_io_count[operation]))
        return false;
    host_error = cf_test_host_io_error(operation);
    if (error)
        *error = host_error;
    SetLastError(host_error);
    return true;
}

static bool cf_test_take_short_marker_write(uint64_t offset, uint32_t length) {
    if ((offset != CF_MARK0_OFFSET && offset != CF_MARK1_OFFSET) ||
        length != CF_PAGE_SIZE)
        return false;
    return InterlockedExchange(&g_test_short_marker_write_pending, 0) != 0;
}

static void cf_crash_after_phase(unsigned phase) {
    if (InterlockedCompareExchange(&g_test_crash_phase, 0, (LONG)phase) == (LONG)phase)
        ExitProcess(100u + phase);
}
#else
static void cf_crash_after_phase(unsigned phase) { (void)phase; }
#endif

static bool cf_all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; ++i)
        acc |= p[i];
    return acc == 0;
}

static void cf_set_error(CF_STORE *s, DWORD error) {
    /* Readers run under the shared lock, so the last error is published atomically. */
    if (s)
        InterlockedExchange((volatile LONG *)&s->last_error, (LONG)error);
}

/* Positioned read: one syscall, and safe for concurrent shared-lock readers
 * because it never depends on the handle's shared file pointer. */
static bool cf_seek_read(HANDLE h, uint64_t offset, void *buffer, uint32_t length, DWORD *error) {
    OVERLAPPED position;
    DWORD got = 0;
    memset(&position, 0, sizeof(position));
    position.Offset = (DWORD)offset;
    position.OffsetHigh = (DWORD)(offset >> 32);
    if (!ReadFile(h, buffer, length, &got, &position)) {
        if (error) *error = GetLastError();
        return false;
    }
    if (got != length) {
        if (error) *error = ERROR_HANDLE_EOF;
        return false;
    }
    return true;
}

static bool cf_seek_write(HANDLE h, uint64_t offset, const void *buffer, uint32_t length, DWORD *error) {
    LARGE_INTEGER pos;
    DWORD put = 0;
    uint32_t write_length = length;
#ifdef CRYPTFS_TESTING
    bool short_marker;
    DWORD injected_error = ERROR_SUCCESS;
    if (cf_test_fail_host_io_now(CF_TEST_IO_WRITE, &injected_error)) {
        if (error)
            *error = injected_error;
        return false;
    }
    short_marker = cf_test_take_short_marker_write(offset, length);
    if (short_marker)
        write_length = CF_MARK_RESERVED;
#endif
    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN)) {
        if (error) *error = GetLastError();
        return false;
    }
    if (!WriteFile(h, buffer, write_length, &put, NULL)) {
        if (error) *error = GetLastError();
        return false;
    }
    if (put != write_length) {
        if (error) *error = ERROR_WRITE_FAULT;
        return false;
    }
#ifdef CRYPTFS_TESTING
    if (short_marker) {
        if (error) *error = ERROR_WRITE_FAULT;
        SetLastError(ERROR_WRITE_FAULT);
        return false;
    }
#endif
    return true;
}

static bool cf_read_physical(CF_STORE *s, uint64_t slot, uint8_t bytes[CF_PAGE_SIZE]) {
    uint64_t offset;
    DWORD error = 0;
    if (slot == CF_ROOT_SLOT)
        offset = CF_ROOT_OFFSET;
    else if (!cf_slot_offset(slot, &offset))
        return false;
    if (!cf_seek_read(s->file, offset, bytes, CF_PAGE_SIZE, &error)) {
        cf_set_error(s, error);
        return false;
    }
    return true;
}

static bool cf_write_physical(CF_STORE *s, uint64_t slot, const uint8_t bytes[CF_PAGE_SIZE]) {
    uint64_t offset;
    DWORD error = 0;
    if (slot == CF_ROOT_SLOT)
        offset = CF_ROOT_OFFSET;
    else if (!cf_slot_offset(slot, &offset))
        return false;
    if (!cf_seek_write(s->file, offset, bytes, CF_PAGE_SIZE, &error)) {
        cf_set_error(s, error);
        return false;
    }
    return true;
}

static bool cf_flush_file(CF_STORE *s) {
#ifdef CRYPTFS_TESTING
    DWORD injected_error = ERROR_SUCCESS;
    if (cf_test_fail_host_io_now(CF_TEST_IO_FLUSH, &injected_error)) {
        cf_set_error(s, injected_error);
        return false;
    }
#endif
    if (!FlushFileBuffers(s->file)) {
        cf_set_error(s, GetLastError());
        return false;
    }
    return true;
}

static bool cf_set_eof(CF_STORE *s, uint64_t eof) {
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)eof;
    if (!cf_eof_valid(eof))
        return false;
#ifdef CRYPTFS_TESTING
    DWORD injected_error = ERROR_SUCCESS;
    if (cf_test_fail_host_io_now(CF_TEST_IO_EOF, &injected_error)) {
        cf_set_error(s, injected_error);
        return false;
    }
#endif
    if (!SetFilePointerEx(s->file, pos, NULL, FILE_BEGIN) || !SetEndOfFile(s->file)) {
        cf_set_error(s, GetLastError());
        return false;
    }
    return true;
}

static size_t cf_make_page_aad(CF_STORE *s, uint64_t slot,
    const uint8_t header[CF_PAGE_HEADER_SIZE], uint8_t aad[72]) {
    memcpy(aad, s->uuid, 16);
    cf_put_u64(aad + 16, slot);
    memcpy(aad + 24, header, CF_PAGE_HEADER_SIZE);
    return 24 + CF_PAGE_HEADER_SIZE;
}

static bool cf_page_encrypt(CF_STORE *s, uint64_t slot, uint16_t type,
    uint64_t record_id, const uint8_t payload[CF_PAYLOAD_SIZE],
    uint8_t bytes[CF_PAGE_SIZE]) {
    uint8_t aad[72];
    uint8_t nonce[CF_NONCE_BYTES];
    size_t aad_length;
    memset(bytes, 0, CF_PAGE_SIZE);
    memcpy(bytes, g_page_magic, sizeof(g_page_magic));
    cf_put_u16(bytes + 4, CF_FORMAT_VERSION);
    cf_put_u16(bytes + 6, type);
    cf_put_u64(bytes + 8, record_id);
    cf_put_u64(bytes + 16, 0);
    cf_random(nonce, sizeof(nonce));
    memcpy(bytes + 24, nonce, sizeof(nonce));
    aad_length = cf_make_page_aad(s, slot, bytes, aad);
    if (!cf_encrypt(s->keys.records, nonce, aad, aad_length,
        payload, CF_PAYLOAD_SIZE, bytes + CF_PAGE_HEADER_SIZE, CF_PAGE_CIPHER_SIZE)) {
        cf_wipe(aad, sizeof(aad));
        cf_wipe(nonce, sizeof(nonce));
        cf_wipe(bytes, CF_PAGE_SIZE);
        return false;
    }
    cf_wipe(aad, sizeof(aad));
    cf_wipe(nonce, sizeof(nonce));
    return true;
}

static bool cf_page_decrypt(CF_STORE *s, uint64_t slot,
    const uint8_t bytes[CF_PAGE_SIZE], uint16_t expected_type,
    uint64_t expected_record_id, uint8_t payload[CF_PAYLOAD_SIZE],
    uint64_t *record_id_out) {
    uint8_t aad[72];
    uint8_t nonce[CF_NONCE_BYTES];
    size_t plain_length = 0;
    size_t aad_length;
    uint16_t type;
    uint64_t record_id;
    bool ok;
    cf_wipe(payload, CF_PAYLOAD_SIZE);
    if (memcmp(bytes, g_page_magic, sizeof(g_page_magic)) != 0 ||
        cf_get_u16(bytes + 4) != CF_FORMAT_VERSION ||
        !cf_all_zero(bytes + 16, 8))
        return false;
    type = cf_get_u16(bytes + 6);
    record_id = cf_get_u64(bytes + 8);
    if ((expected_type && type != expected_type) ||
        (expected_record_id && record_id != expected_record_id) ||
        (type < CF_RECORD_INODE || type > CF_RECORD_FRAGMENT))
        return false;
    memcpy(nonce, bytes + 24, sizeof(nonce));
    aad_length = cf_make_page_aad(s, slot, bytes, aad);
    ok = cf_decrypt(s->keys.records, nonce, aad, aad_length,
        bytes + CF_PAGE_HEADER_SIZE, CF_PAGE_CIPHER_SIZE, payload,
        CF_PAYLOAD_SIZE, &plain_length);
    cf_wipe(aad, sizeof(aad));
    cf_wipe(nonce, sizeof(nonce));
    if (!ok || plain_length != CF_PAYLOAD_SIZE) {
        cf_wipe(payload, CF_PAYLOAD_SIZE);
        return false;
    }
    if (record_id_out)
        *record_id_out = record_id;
    return true;
}

static CF_PAGE *cf_page_new(uint64_t slot, uint16_t type, uint64_t record_id) {
    CF_PAGE *page = (CF_PAGE *)calloc(1, sizeof(*page));
    if (!page)
        return NULL;
    page->slot = slot;
    page->type = type;
    page->record_id = record_id;
    return page;
}

static bool cf_slots_ensure(CF_STORE *s, uint64_t slots) {
    CF_PAGE **next;
    size_t count;
    if (slots > CF_MAX_SLOTS || slots > SIZE_MAX / sizeof(CF_PAGE *))
        return false;
    count = (size_t)slots + 1;
    if (count <= s->slot_capacity)
        return true;
    next = (CF_PAGE **)realloc(s->slots, count * sizeof(CF_PAGE *));
    if (!next)
        return false;
    memset(next + s->slot_capacity, 0, (count - s->slot_capacity) * sizeof(CF_PAGE *));
    s->slots = next;
    s->slot_capacity = count;
    return true;
}

static bool cf_page_register(CF_STORE *s, CF_PAGE *page) {
#ifdef CRYPTFS_TESTING
    if (cf_test_countdown_failure(&g_test_fail_page_register_count)) {
        cf_set_error(s, ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
#endif
    if (page->slot == CF_ROOT_SLOT) {
        if (s->root_page && s->root_page != page)
            return false;
        page->registered = true;
        s->root_page = page;
        return true;
    }
    if (page->slot == 0 || page->slot > CF_MAX_SLOTS ||
        !cf_slots_ensure(s, page->slot) || s->slots[page->slot])
        return false;
    s->slots[page->slot] = page;
    page->registered = true;
    ++s->live_page_count;
    if (page->slot > s->slot_count)
        s->slot_count = page->slot;
    return true;
}

static void cf_page_unlink_owner(CF_PAGE *page) {
    CF_PAGE **link;
    if (!page || !page->owner)
        return;
    link = &page->owner->owned_head;
    while (*link && *link != page)
        link = &(*link)->owned_next;
    if (*link == page)
        *link = page->owned_next;
    page->owner = NULL;
    page->owned_next = NULL;
    page->owner_offset = 0;
}

static void cf_page_set_owner(CF_PAGE *page, CF_PAGE *owner, uint32_t offset) {
    CF_PAGE **link;
    if (!page || page == owner)
        return;
    if (page->owner == owner && page->owner_offset == offset)
        return;
    cf_page_unlink_owner(page);
    page->owner = owner;
    page->owner_offset = offset;
    if (!owner)
        return;
    link = &owner->owned_head;
    page->owned_next = *link;
    *link = page;
}

static void cf_page_unregister_tree(CF_STORE *s, CF_PAGE *page) {
    CF_PAGE *current;
    if (!page)
        return;
    cf_page_unlink_owner(page);
    current = page;
    while (current) {
        if (current->owned_head) {
            CF_PAGE *child = current->owned_head;
            current->owned_head = child->owned_next;
            child->owned_next = NULL;
            current = child;
            continue;
        }
        {
            CF_PAGE *parent = current->owner;
            if (current->slot != CF_ROOT_SLOT && current->slot <= s->slot_count &&
                s->slots[current->slot] == current) {
                s->slots[current->slot] = NULL;
                if (current->slot < s->free_floor)
                    s->free_floor = current->slot;
                if (s->live_page_count)
                    --s->live_page_count;
            }
            cf_wipe(current, sizeof(*current));
            free(current);
            current = parent;
        }
    }
}

static int cf_name_compare_raw(const wchar_t *a, size_t an,
    const wchar_t *b, size_t bn) {
    size_t n = an < bn ? an : bn;
    int cmp = wmemcmp(a, b, n);
    if (cmp)
        return cmp < 0 ? -1 : 1;
    return an < bn ? -1 : an > bn ? 1 : 0;
}

static size_t cf_child_lower_bound(CF_NODE *parent, const wchar_t *name, size_t length) {
    size_t lo = 0, hi = parent->child_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        CF_NODE *n = parent->children[mid];
        int c = cf_name_compare_raw(n->name, n->name_length, name, length);
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static CF_NODE *cf_child_find(CF_NODE *parent, const wchar_t *name, size_t length) {
    size_t i = cf_child_lower_bound(parent, name, length);
    if (i < parent->child_count &&
        cf_name_compare_raw(parent->children[i]->name, parent->children[i]->name_length,
            name, length) == 0)
        return parent->children[i];
    return NULL;
}

static bool cf_child_index_reserve(CF_NODE *parent, size_t wanted) {
    CF_NODE **next;
    size_t capacity;
    if (wanted <= parent->child_capacity)
        return true;
    capacity = parent->child_capacity ? parent->child_capacity * 2 : 8;
    if (capacity < wanted)
        capacity = wanted;
    if (capacity > CF_MAX_NODES || capacity > SIZE_MAX / sizeof(CF_NODE *))
        return false;
    next = (CF_NODE **)realloc(parent->children, capacity * sizeof(CF_NODE *));
    if (!next)
        return false;
    parent->children = next;
    parent->child_capacity = capacity;
    return true;
}

static bool cf_child_index_insert(CF_NODE *parent, CF_NODE *child) {
    size_t i = cf_child_lower_bound(parent, child->name, child->name_length);
    if (i < parent->child_count &&
        cf_name_compare_raw(parent->children[i]->name, parent->children[i]->name_length,
            child->name, child->name_length) == 0)
        return false;
    if (!cf_child_index_reserve(parent, parent->child_count + 1))
        return false;
    memmove(parent->children + i + 1, parent->children + i,
        (parent->child_count - i) * sizeof(CF_NODE *));
    parent->children[i] = child;
    ++parent->child_count;
    child->parent = parent;
    return true;
}

static void cf_child_index_remove(CF_NODE *parent, CF_NODE *child) {
    size_t i = cf_child_lower_bound(parent, child->name, child->name_length);
    if (i < parent->child_count && parent->children[i] == child) {
        memmove(parent->children + i, parent->children + i + 1,
            (parent->child_count - i - 1) * sizeof(CF_NODE *));
        --parent->child_count;
    }
    child->parent = NULL;
}

static bool cf_node_array_add(CF_STORE *s, CF_NODE *node) {
    CF_NODE **next;
    size_t capacity;
    if (s->node_count >= CF_MAX_NODES)
        return false;
    if (s->node_count == s->node_capacity) {
        capacity = s->node_capacity ? s->node_capacity * 2 : 16;
        if (capacity > CF_MAX_NODES)
            capacity = CF_MAX_NODES;
        next = (CF_NODE **)realloc(s->nodes, capacity * sizeof(CF_NODE *));
        if (!next)
            return false;
        s->nodes = next;
        s->node_capacity = capacity;
    }
    s->nodes[s->node_count++] = node;
    return true;
}

static void cf_node_array_remove(CF_STORE *s, CF_NODE *node) {
    size_t i;
    for (i = 0; i < s->node_count; ++i) {
        if (s->nodes[i] == node) {
            memmove(s->nodes + i, s->nodes + i + 1,
                (s->node_count - i - 1) * sizeof(CF_NODE *));
            --s->node_count;
            return;
        }
    }
}

static uint64_t cf_now_filetime(void) {
    FILETIME t;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&t);
    u.LowPart = t.dwLowDateTime;
    u.HighPart = t.dwHighDateTime;
    return u.QuadPart;
}

static void cf_node_fill_info(CF_NODE *node, CF_INFO *info) {
    uint64_t allocated = 0;
    CF_MAP_PAGE *m;
    if (!(node->attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        for (m = node->maps; m; m = m->next)
            allocated += (uint64_t)m->count * CF_BLOCK_SIZE;
    }
    info->id = node->id;
    info->size = node->size;
    info->allocation_size = allocated;
    info->creation_time = node->creation_time;
    info->access_time = node->access_time;
    info->write_time = node->write_time;
    info->change_time = node->change_time;
    info->attributes = node->attributes;
}

typedef struct CF_HEADER_CANDIDATE {
    bool structural;
    bool unwrapped;
    uint8_t bytes[CF_PAGE_SIZE];
    uint8_t uuid[16];
    uint64_t capacity;
    uint8_t master[CF_KEY_BYTES];
    CF_KEYS keys;
} CF_HEADER_CANDIDATE;

typedef struct CF_MARKER {
    bool valid;
    uint32_t physical_slot;
    uint32_t state;
    uint64_t generation;
    uint32_t journal_length;
    uint64_t final_eof;
    uint8_t journal_hash[32];
    uint8_t bytes[CF_PAGE_SIZE];
} CF_MARKER;

static bool cf_file_write_at(HANDLE file, uint64_t offset,
    const void *bytes, uint32_t length, DWORD *error) {
    return cf_seek_write(file, offset, bytes, length, error);
}

static bool cf_file_read_at(HANDLE file, uint64_t offset,
    void *bytes, uint32_t length, DWORD *error) {
    return cf_seek_read(file, offset, bytes, length, error);
}

static bool cf_sb_structural(const uint8_t sb[CF_PAGE_SIZE]) {
    uint32_t flags;
    uint64_t capacity, ops, mem;
    if (memcmp(sb + CF_SB_MAGIC, g_sb_magic, sizeof(g_sb_magic)) != 0 ||
        cf_get_u32(sb + CF_SB_VERSION) != CF_FORMAT_VERSION ||
        cf_get_u32(sb + CF_SB_HEADER_LENGTH) != 152 ||
        !cf_all_zero(sb + CF_SB_RESERVED0, 4) ||
        !cf_all_zero(sb + CF_SB_RESERVED, CF_PAGE_SIZE - CF_SB_RESERVED))
        return false;
    flags = cf_get_u32(sb + CF_SB_FLAGS);
    capacity = cf_get_u64(sb + CF_SB_CAPACITY);
    ops = cf_get_u64(sb + CF_SB_KDF_OPS);
    mem = cf_get_u64(sb + CF_SB_KDF_MEM);
    if (flags != 1 || capacity == 0 || capacity > CF_DEFAULT_CAPACITY ||
        ops < 1 || ops > 6 || mem < 64ULL * 1024 * 1024 ||
        mem > 512ULL * 1024 * 1024)
        return false;
    return true;
}

static bool cf_sb_unwrap(const uint8_t sb[CF_PAGE_SIZE],
    const uint8_t *password, size_t password_length,
    CF_HEADER_CANDIDATE *candidate) {
    uint8_t wrapping_key[CF_KEY_BYTES];
    uint8_t aad[80 + CF_PAGE_SIZE - CF_SB_RESERVED];
    size_t plain_length = 0;
    bool ok;
    candidate->structural = cf_sb_structural(sb);
    candidate->unwrapped = false;
    if (!candidate->structural)
        return false;
    if (!cf_password_key(password, password_length, sb + CF_SB_SALT,
        cf_get_u64(sb + CF_SB_KDF_OPS), cf_get_u64(sb + CF_SB_KDF_MEM),
        wrapping_key)) {
        cf_wipe(wrapping_key, sizeof(wrapping_key));
        return false;
    }
    memcpy(aad, sb, 80);
    memcpy(aad + 80, sb + CF_SB_RESERVED, CF_PAGE_SIZE - CF_SB_RESERVED);
    ok = cf_decrypt(wrapping_key, sb + CF_SB_WRAP_NONCE,
        aad, sizeof(aad), sb + CF_SB_WRAPPED_KEY, CF_KEY_BYTES + CF_TAG_BYTES,
        candidate->master, sizeof(candidate->master), &plain_length);
    cf_wipe(wrapping_key, sizeof(wrapping_key));
    cf_wipe(aad, sizeof(aad));
    if (!ok || plain_length != CF_KEY_BYTES) {
        cf_wipe(candidate->master, sizeof(candidate->master));
        return false;
    }
    memcpy(candidate->uuid, sb + CF_SB_UUID, sizeof(candidate->uuid));
    candidate->capacity = cf_get_u64(sb + CF_SB_CAPACITY);
    candidate->unwrapped = cf_keys_derive(candidate->master, &candidate->keys);
    if (!candidate->unwrapped) {
        cf_wipe(candidate->master, sizeof(candidate->master));
        cf_wipe(&candidate->keys, sizeof(candidate->keys));
        return false;
    }
    return true;
}

static bool cf_marker_authenticate(CF_STORE *s, uint32_t slot,
    const uint8_t bytes[CF_PAGE_SIZE], CF_MARKER *marker) {
    uint8_t mac[32];
    uint8_t mac_input[16 + CF_MARK_MAC];
    uint32_t state, length;
    uint64_t generation, eof;
    memset(marker, 0, sizeof(*marker));
    if (memcmp(bytes + CF_MARK_MAGIC, g_marker_magic, sizeof(g_marker_magic)) != 0 ||
        cf_get_u32(bytes + CF_MARK_VERSION) != CF_FORMAT_VERSION ||
        cf_get_u32(bytes + CF_MARK_SLOT) != slot ||
        !cf_all_zero(bytes + CF_MARK_RESERVED0, 4) ||
        !cf_all_zero(bytes + CF_MARK_RESERVED1, 4) ||
        !cf_all_zero(bytes + CF_MARK_RESERVED, CF_PAGE_SIZE - CF_MARK_RESERVED))
        return false;
    state = cf_get_u32(bytes + CF_MARK_STATE);
    length = cf_get_u32(bytes + CF_MARK_JOURNAL_LENGTH);
    generation = cf_get_u64(bytes + CF_MARK_GENERATION);
    eof = cf_get_u64(bytes + CF_MARK_FINAL_EOF);
    if (state > CF_MARK_COMMITTED || (generation & 1) != slot || !cf_eof_valid(eof))
        return false;
    if ((state == CF_MARK_EMPTY && (length != 0 ||
        !cf_all_zero(bytes + CF_MARK_JOURNAL_HASH, 32))) ||
        (state == CF_MARK_COMMITTED && (length < CF_WAL_HEADER_SIZE + 32 + CF_TAG_BYTES ||
            length > CF_MAX_TRANSACTION_BYTES)))
        return false;
    memcpy(mac_input, s->uuid, 16);
    memcpy(mac_input + 16, bytes, CF_MARK_MAC);
    cf_mac(s->keys.header, mac_input, sizeof(mac_input), mac);
    if (!cf_mac_verify(bytes + CF_MARK_MAC, mac)) {
        cf_wipe(mac, sizeof(mac));
        cf_wipe(mac_input, sizeof(mac_input));
        return false;
    }
    cf_wipe(mac, sizeof(mac));
    cf_wipe(mac_input, sizeof(mac_input));
    marker->valid = true;
    marker->physical_slot = slot;
    marker->state = state;
    marker->generation = generation;
    marker->journal_length = length;
    marker->final_eof = eof;
    memcpy(marker->journal_hash, bytes + CF_MARK_JOURNAL_HASH, 32);
    memcpy(marker->bytes, bytes, CF_PAGE_SIZE);
    return true;
}

static void cf_marker_build(CF_STORE *s, uint32_t slot, uint32_t state,
    uint64_t generation, uint32_t journal_length, uint64_t final_eof,
    const uint8_t journal_hash[32], uint8_t bytes[CF_PAGE_SIZE]) {
    uint8_t mac[32];
    uint8_t mac_input[16 + CF_MARK_MAC];
    memset(bytes, 0, CF_PAGE_SIZE);
    memcpy(bytes + CF_MARK_MAGIC, g_marker_magic, sizeof(g_marker_magic));
    cf_put_u32(bytes + CF_MARK_VERSION, CF_FORMAT_VERSION);
    cf_put_u32(bytes + CF_MARK_SLOT, slot);
    cf_put_u32(bytes + CF_MARK_STATE, state);
    cf_put_u64(bytes + CF_MARK_GENERATION, generation);
    cf_put_u32(bytes + CF_MARK_JOURNAL_LENGTH, journal_length);
    cf_put_u64(bytes + CF_MARK_FINAL_EOF, final_eof);
    if (journal_hash)
        memcpy(bytes + CF_MARK_JOURNAL_HASH, journal_hash, 32);
    memcpy(mac_input, s->uuid, 16);
    memcpy(mac_input + 16, bytes, CF_MARK_MAC);
    cf_mac(s->keys.header, mac_input, sizeof(mac_input), mac);
    memcpy(bytes + CF_MARK_MAC, mac, sizeof(mac));
    cf_wipe(mac, sizeof(mac));
    cf_wipe(mac_input, sizeof(mac_input));
}

static bool cf_marker_same_state(const CF_MARKER *a, const CF_MARKER *b) {
    return a->state == b->state && a->journal_length == b->journal_length &&
        a->final_eof == b->final_eof &&
        memcmp(a->journal_hash, b->journal_hash, sizeof(a->journal_hash)) == 0;
}

static bool cf_file_sparse(HANDLE file) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(file, &info))
        return false;
    return (info.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0 &&
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
}

static bool cf_init_new_container(CF_STORE *s, const uint8_t *password,
    size_t password_length, uint64_t capacity) {
    uint8_t sb[CF_PAGE_SIZE];
    uint8_t aad[80 + CF_PAGE_SIZE - CF_SB_RESERVED];
    uint8_t wrapping_key[CF_KEY_BYTES];
    uint8_t master[CF_KEY_BYTES];
    uint8_t payload[CF_PAYLOAD_SIZE];
    uint8_t page[CF_PAGE_SIZE];
    uint8_t marker[CF_PAGE_SIZE];
    DWORD returned = 0, error = 0;
    CF_NODE *root = NULL;
    CF_PAGE *root_page = NULL;
    bool ok = false;
    FILE_SET_SPARSE_BUFFER sparse;
    LARGE_INTEGER zero;
    memset(&sparse, 0, sizeof(sparse));
    sparse.SetSparse = TRUE;
    if (!DeviceIoControl(s->file, FSCTL_SET_SPARSE, &sparse, sizeof(sparse),
        NULL, 0, &returned, NULL)) {
        cf_set_error(s, GetLastError());
        goto done;
    }
    if (!cf_file_sparse(s->file))
        goto done;
    if (!cf_password_valid(password, password_length))
        goto done;
    if (!cf_crypto_init())
        goto done;
    s->capacity = capacity ? capacity : CF_DEFAULT_CAPACITY;
    if (s->capacity == 0 || s->capacity > CF_DEFAULT_CAPACITY)
        goto done;
    cf_random(s->uuid, sizeof(s->uuid));
    cf_random(master, sizeof(master));
    memset(sb, 0, sizeof(sb));
    memcpy(sb + CF_SB_MAGIC, g_sb_magic, sizeof(g_sb_magic));
    cf_put_u32(sb + CF_SB_VERSION, CF_FORMAT_VERSION);
    cf_put_u32(sb + CF_SB_HEADER_LENGTH, 152);
    memcpy(sb + CF_SB_UUID, s->uuid, sizeof(s->uuid));
    cf_put_u32(sb + CF_SB_FLAGS, 1);
    cf_put_u64(sb + CF_SB_CAPACITY, s->capacity);
    cf_put_u64(sb + CF_SB_KDF_OPS, CF_KDF_OPS);
    cf_put_u64(sb + CF_SB_KDF_MEM, CF_KDF_MEM);
    cf_random(sb + CF_SB_SALT, CF_SALT_BYTES);
    if (!cf_password_key(password, password_length, sb + CF_SB_SALT,
        CF_KDF_OPS, CF_KDF_MEM, wrapping_key))
        goto done;
    cf_random(sb + CF_SB_WRAP_NONCE, CF_NONCE_BYTES);
    memcpy(aad, sb, 80);
    memcpy(aad + 80, sb + CF_SB_RESERVED, CF_PAGE_SIZE - CF_SB_RESERVED);
    if (!cf_encrypt(wrapping_key, sb + CF_SB_WRAP_NONCE, aad, sizeof(aad),
        master, sizeof(master), sb + CF_SB_WRAPPED_KEY, CF_KEY_BYTES + CF_TAG_BYTES))
        goto done;
    if (!cf_keys_derive(master, &s->keys))
        goto done;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(s->file, zero, NULL, FILE_BEGIN) || !SetEndOfFile(s->file)) {
        cf_set_error(s, GetLastError());
        goto done;
    }
    zero.QuadPart = CF_MIN_EOF;
    if (!SetFilePointerEx(s->file, zero, NULL, FILE_BEGIN) || !SetEndOfFile(s->file)) {
        cf_set_error(s, GetLastError());
        goto done;
    }
    s->eof = CF_MIN_EOF;
    s->disk_eof = CF_MIN_EOF;
    if (!cf_file_write_at(s->file, CF_SB0_OFFSET, sb, CF_PAGE_SIZE, &error) ||
        !cf_file_write_at(s->file, CF_SB1_OFFSET, sb, CF_PAGE_SIZE, &error)) {
        cf_set_error(s, error);
        goto done;
    }
    root = (CF_NODE *)calloc(1, sizeof(*root));
    root_page = cf_page_new(CF_ROOT_SLOT, CF_RECORD_INODE, 1);
    if (!root || !root_page)
        goto done;
    root->store = s;
    root->id = 1;
    root->attributes = FILE_ATTRIBUTE_DIRECTORY;
    root->creation_time = root->access_time = root->write_time = root->change_time = cf_now_filetime();
    root->page = root_page;
    root_page->inode = root;
    memset(payload, 0, sizeof(payload));
    cf_put_u64(payload + CF_INODE_ID, 1);
    cf_put_u32(payload + CF_INODE_ATTRIBUTES, FILE_ATTRIBUTE_DIRECTORY);
    cf_put_u64(payload + CF_INODE_CREATED, root->creation_time);
    cf_put_u64(payload + CF_INODE_ACCESSED, root->access_time);
    cf_put_u64(payload + CF_INODE_WRITTEN, root->write_time);
    cf_put_u64(payload + CF_INODE_CHANGED, root->change_time);
    cf_put_u64(payload + CF_INODE_NEXT_ID, 2);
    if (!cf_page_encrypt(s, CF_ROOT_SLOT, CF_RECORD_INODE, 1, payload, page) ||
        !cf_file_write_at(s->file, CF_ROOT_OFFSET, page, CF_PAGE_SIZE, &error)) {
        cf_set_error(s, error);
        goto done;
    }
    cf_marker_build(s, 0, CF_MARK_EMPTY, 0, 0, CF_MIN_EOF, NULL, marker);
    if (!cf_file_write_at(s->file, CF_MARK0_OFFSET, marker, CF_PAGE_SIZE, &error) ||
        !cf_flush_file(s)) {
        cf_set_error(s, error ? error : GetLastError());
        goto done;
    }
    s->generation = 0;
    s->next_inode_id = 2;
    s->root = root;
    if (!cf_node_array_add(s, root) || !cf_page_register(s, root_page))
        goto done;
    ok = true;
done:
    if (!ok) {
        if (root) {
            cf_wipe(root, sizeof(*root));
            free(root);
        }
        if (root_page) {
            cf_wipe(root_page, sizeof(*root_page));
            free(root_page);
        }
    }
    cf_wipe(sb, sizeof(sb));
    cf_wipe(aad, sizeof(aad));
    cf_wipe(wrapping_key, sizeof(wrapping_key));
    cf_wipe(master, sizeof(master));
    cf_wipe(payload, sizeof(payload));
    cf_wipe(page, sizeof(page));
    cf_wipe(marker, sizeof(marker));
    return ok;
}

typedef struct CF_GRAPH {
    CF_STORE *store;
    CF_IMAGE *overlay;
    uint32_t overlay_count;
    uint64_t target_eof;
    uint64_t target_slots;
    uint64_t *ids;
    CF_RESULT error;
} CF_GRAPH;

static int __cdecl cf_image_compare(const void *a, const void *b) {
    const CF_IMAGE *ia = (const CF_IMAGE *)a;
    const CF_IMAGE *ib = (const CF_IMAGE *)b;
    return ia->slot < ib->slot ? -1 : ia->slot > ib->slot ? 1 : 0;
}

static CF_IMAGE *cf_image_find(CF_IMAGE *images, uint32_t count, uint64_t slot) {
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (images[mid].slot < slot)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < count && images[lo].slot == slot)
        return &images[lo];
    return NULL;
}

static bool cf_graph_read_page(CF_GRAPH *g, uint64_t slot,
    uint8_t bytes[CF_PAGE_SIZE]) {
    CF_STORE *s = g->store;
    uint64_t offset;
    CF_IMAGE *image = cf_image_find(g->overlay, g->overlay_count, slot);
    if (image) {
        image->used = true;
        memcpy(bytes, image->bytes, CF_PAGE_SIZE);
        return true;
    }
    if (slot == CF_ROOT_SLOT) {
        offset = CF_ROOT_OFFSET;
    } else {
        if (!cf_slot_offset(slot, &offset) || slot > g->target_slots ||
            offset > UINT64_MAX - CF_PAGE_SIZE || offset + CF_PAGE_SIZE > g->target_eof ||
            offset + CF_PAGE_SIZE > s->disk_eof)
            return false;
    }
    return cf_read_physical(s, slot, bytes);
}

static void cf_graph_set_error(CF_GRAPH *g, CF_RESULT error) {
    if (g->error == CF_OK)
        g->error = error;
}

static bool cf_idset_insert(CF_GRAPH *g, uint64_t id) {
    size_t mask = 131072u - 1u;
    size_t index = (size_t)((id ^ (id >> 33) ^ (id >> 17)) * 0x9e3779b97f4a7c15ULL) & mask;
    size_t n;
    for (n = 0; n < 131072u; ++n) {
        if (g->ids[index] == id)
            return false;
        if (g->ids[index] == 0) {
            g->ids[index] = id;
            return true;
        }
        index = (index + 1) & mask;
    }
    return false;
}

static bool cf_valid_name_units(const wchar_t *name, uint16_t length) {
    uint16_t i;
    if (length == 0 || length > CF_NAME_MAX)
        return false;
    for (i = 0; i < length; ++i) {
        uint16_t c = (uint16_t)name[i];
        if (c == 0 || c < 32 || c == L'\\' || c == L'/' || c == L':' ||
            c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|')
            return false;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (i + 1 >= length)
                return false;
            c = (uint16_t)name[++i];
            if (c < 0xdc00 || c > 0xdfff)
                return false;
        } else if (c >= 0xdc00 && c <= 0xdfff) {
            return false;
        }
    }
    if ((length == 1 && name[0] == L'.') ||
        (length == 2 && name[0] == L'.' && name[1] == L'.'))
        return false;
    return true;
}

static uint64_t cf_ceil_blocks(uint64_t size) {
    return size / CF_BLOCK_SIZE + ((size % CF_BLOCK_SIZE) != 0);
}

static bool cf_graph_load_maps(CF_GRAPH *g, CF_NODE *node, uint64_t first_slot) {
    CF_MAP_PAGE *previous = NULL;
    uint64_t slot = first_slot;
    uint64_t last_block = 0;
    bool have_last = false;
    uint64_t block_limit = cf_ceil_blocks(node->size);
    uint32_t maps_seen = 0;
    while (slot) {
        uint8_t disk[CF_PAGE_SIZE];
        uint8_t payload[CF_PAYLOAD_SIZE];
        uint64_t record_id = 0, next_slot;
        uint16_t count;
        CF_PAGE *page;
        CF_MAP_PAGE *map;
        uint32_t i;
        if (++maps_seen > CF_MAX_PAGES || slot > g->target_slots ||
            (slot < g->store->slot_capacity && g->store->slots[slot]) ||
            !cf_graph_read_page(g, slot, disk) ||
            !cf_page_decrypt(g->store, slot, disk, CF_RECORD_MAP, node->id,
                payload, &record_id) || record_id != node->id ||
            cf_get_u64(payload + CF_MAP_FILE_ID) != node->id ||
            !cf_all_zero(payload + 18, 6)) {
            cf_wipe(disk, sizeof(disk));
            cf_wipe(payload, sizeof(payload));
            return false;
        }
        count = cf_get_u16(payload + CF_MAP_COUNT);
        next_slot = cf_get_u64(payload + CF_MAP_NEXT);
        if (count == 0 || count > CF_MAP_CAPACITY ||
            !cf_all_zero(payload + CF_MAP_ENTRIES + (size_t)count * CF_MAP_ENTRY_SIZE,
                CF_PAYLOAD_SIZE - CF_MAP_ENTRIES - (size_t)count * CF_MAP_ENTRY_SIZE)) {
            cf_wipe(disk, sizeof(disk));
            cf_wipe(payload, sizeof(payload));
            return false;
        }
        page = cf_page_new(slot, CF_RECORD_MAP, node->id);
        map = (CF_MAP_PAGE *)calloc(1, sizeof(*map));
        if (!page || !map) {
            free(page);
            free(map);
            cf_graph_set_error(g, CF_NO_MEMORY);
            cf_wipe(disk, sizeof(disk));
            cf_wipe(payload, sizeof(payload));
            return false;
        }
        map->page = page;
        map->count = count;
        page->map = map;
        if (!cf_page_register(g->store, page)) {
            cf_wipe(page, sizeof(*page));
            free(page);
            free(map);
            cf_wipe(disk, sizeof(disk));
            cf_wipe(payload, sizeof(payload));
            return false;
        }
        if (previous) {
            previous->next = map;
            cf_page_set_owner(page, previous->page, CF_MAP_NEXT);
        } else {
            node->maps = map;
            cf_page_set_owner(page, node->page, CF_INODE_MAP_HEAD);
        }
        node->maps_tail = map;
        for (i = 0; i < count; ++i) {
            const uint8_t *entry = payload + CF_MAP_ENTRIES + (size_t)i * CF_MAP_ENTRY_SIZE;
            CF_BLOCK *block = (CF_BLOCK *)calloc(1, sizeof(*block));
            uint64_t block_index = cf_get_u64(entry + CF_MAP_ENTRY_BLOCK);
            uint64_t frag_slot = cf_get_u64(entry + CF_MAP_ENTRY_FRAGMENT);
            uint32_t frag_count = cf_get_u32(entry + CF_MAP_ENTRY_FRAGMENT_COUNT);
            uint32_t encoded_length = cf_get_u32(entry + CF_MAP_ENTRY_ENCODED_LENGTH);
            uint32_t codec = cf_get_u32(entry + CF_MAP_ENTRY_CODEC);
            uint32_t j;
            if (!block || (have_last && block_index <= last_block) ||
                block_index >= block_limit || cf_get_u32(entry + CF_MAP_ENTRY_RAW_LENGTH) != CF_BLOCK_SIZE ||
                encoded_length == 0 || encoded_length > CF_BLOCK_SIZE || frag_count == 0 ||
                frag_count > CF_MAX_FRAGMENTS ||
                frag_count != (encoded_length + CF_FRAGMENT_CAPACITY - 1u) / CF_FRAGMENT_CAPACITY ||
                (codec != 0 && codec != 1) || (codec == 0 && encoded_length != CF_BLOCK_SIZE) ||
                frag_slot == 0) {
                free(block);
                cf_wipe(disk, sizeof(disk));
                cf_wipe(payload, sizeof(payload));
                return false;
            }
            block->index = block_index;
            block->encoded_length = encoded_length;
            block->codec = codec;
            block->fragment_count = frag_count;
            /* From this point the map owns the block. Any graph-load failure
             * is cleaned up through the node/map graph during store disposal. */
            map->blocks[i] = block;
            for (j = 0; j < frag_count; ++j) {
                uint8_t frag_disk[CF_PAGE_SIZE];
                uint8_t frag_payload[CF_PAYLOAD_SIZE];
                uint64_t frag_record_id = 0, frag_next;
                uint32_t expected = encoded_length - j * CF_FRAGMENT_CAPACITY;
                uint32_t used = expected > CF_FRAGMENT_CAPACITY ? CF_FRAGMENT_CAPACITY : expected;
                CF_PAGE *frag_page;
                if (frag_slot == 0 || frag_slot > g->target_slots ||
                    (frag_slot < g->store->slot_capacity && g->store->slots[frag_slot]) ||
                    !cf_graph_read_page(g, frag_slot, frag_disk) ||
                    !cf_page_decrypt(g->store, frag_slot, frag_disk, CF_RECORD_FRAGMENT,
                        node->id, frag_payload, &frag_record_id) || frag_record_id != node->id ||
                    cf_get_u64(frag_payload + CF_FRAGMENT_FILE_ID) != node->id ||
                    cf_get_u64(frag_payload + CF_FRAGMENT_BLOCK) != block_index ||
                    cf_get_u32(frag_payload + CF_FRAGMENT_SEQUENCE) != j ||
                    cf_get_u32(frag_payload + CF_FRAGMENT_LENGTH) != used ||
                    !cf_all_zero(frag_payload + CF_FRAGMENT_DATA + used,
                        CF_PAYLOAD_SIZE - CF_FRAGMENT_DATA - used)) {
                    cf_wipe(frag_disk, sizeof(frag_disk));
                    cf_wipe(frag_payload, sizeof(frag_payload));
                    cf_wipe(disk, sizeof(disk));
                    cf_wipe(payload, sizeof(payload));
                    return false;
                }
                frag_next = cf_get_u64(frag_payload + CF_FRAGMENT_NEXT);
                if ((j + 1 == frag_count && frag_next != 0) ||
                    (j + 1 < frag_count && frag_next == 0)) {
                    cf_wipe(frag_disk, sizeof(frag_disk));
                    cf_wipe(frag_payload, sizeof(frag_payload));
                    cf_wipe(disk, sizeof(disk));
                    cf_wipe(payload, sizeof(payload));
                    return false;
                }
                frag_page = cf_page_new(frag_slot, CF_RECORD_FRAGMENT, node->id);
                if (!frag_page) {
                    cf_graph_set_error(g, CF_NO_MEMORY);
                    cf_wipe(frag_disk, sizeof(frag_disk));
                    cf_wipe(frag_payload, sizeof(frag_payload));
                    cf_wipe(disk, sizeof(disk));
                    cf_wipe(payload, sizeof(payload));
                    return false;
                }
                if (!cf_page_register(g->store, frag_page)) {
                    free(frag_page);
                    cf_wipe(frag_disk, sizeof(frag_disk));
                    cf_wipe(frag_payload, sizeof(frag_payload));
                    cf_wipe(disk, sizeof(disk));
                    cf_wipe(payload, sizeof(payload));
                    return false;
                }
                block->fragments[j] = frag_page;
                cf_page_set_owner(frag_page, j ? block->fragments[j - 1] : page,
                    j ? CF_FRAGMENT_NEXT : (uint32_t)(CF_MAP_ENTRIES + (size_t)i * CF_MAP_ENTRY_SIZE + CF_MAP_ENTRY_FRAGMENT));
                if (j + 1 < frag_count && frag_next != 0 && j + 1 < CF_MAX_FRAGMENTS)
                    frag_slot = frag_next;
                cf_wipe(frag_disk, sizeof(frag_disk));
                cf_wipe(frag_payload, sizeof(frag_payload));
            }
            /* Each fragment above was read and authenticated with its exact
             * identity, sequence, length and link; decoding the codec frame
             * happens on read, so unlock no longer decompresses all data. */
            if (block_index > UINT64_MAX / CF_BLOCK_SIZE) {
                cf_wipe(disk, sizeof(disk));
                cf_wipe(payload, sizeof(payload));
                return false;
            }
            last_block = block_index;
            have_last = true;
        }
        previous = map;
        slot = next_slot;
        cf_wipe(disk, sizeof(disk));
        cf_wipe(payload, sizeof(payload));
    }
    return true;
}

static bool cf_graph_load_inode(CF_GRAPH *g, uint64_t slot, CF_NODE *parent,
    uint64_t expected_parent_id, uint16_t depth, bool orphan,
    CF_PAGE *owner_page, uint32_t owner_offset, CF_NODE **out_node,
    uint64_t *out_next_sibling_slot, uint64_t *out_next_orphan_slot) {
    uint8_t disk[CF_PAGE_SIZE];
    uint8_t payload[CF_PAYLOAD_SIZE];
    uint64_t record_id = 0;
    uint64_t first_child, next_sibling, map_head, orphan_link;
    CF_NODE *node = NULL;
    CF_PAGE *page = NULL;
    uint16_t name_length;
    uint32_t attrs;
    bool is_directory;
    bool node_registered = false, page_registered = false;
    if (depth > CF_MAX_DEPTH || slot == 0 || slot > g->target_slots ||
        (slot < g->store->slot_capacity && g->store->slots[slot]) ||
        !cf_graph_read_page(g, slot, disk) ||
        !cf_page_decrypt(g->store, slot, disk, CF_RECORD_INODE, 0,
            payload, &record_id))
        goto bad;
    node = (CF_NODE *)calloc(1, sizeof(*node));
    page = cf_page_new(slot, CF_RECORD_INODE, record_id);
    if (!node || !page) {
        cf_graph_set_error(g, CF_NO_MEMORY);
        goto bad;
    }
    node->store = g->store;
    node->id = cf_get_u64(payload + CF_INODE_ID);
    node->parent_id = cf_get_u64(payload + CF_INODE_PARENT_ID);
    first_child = cf_get_u64(payload + CF_INODE_FIRST_CHILD);
    next_sibling = cf_get_u64(payload + CF_INODE_NEXT_SIBLING);
    map_head = cf_get_u64(payload + CF_INODE_MAP_HEAD);
    orphan_link = cf_get_u64(payload + CF_INODE_ORPHAN_LINK);
    node->size = cf_get_u64(payload + CF_INODE_SIZE);
    node->creation_time = cf_get_u64(payload + CF_INODE_CREATED);
    node->access_time = cf_get_u64(payload + CF_INODE_ACCESSED);
    node->write_time = cf_get_u64(payload + CF_INODE_WRITTEN);
    node->change_time = cf_get_u64(payload + CF_INODE_CHANGED);
    attrs = cf_get_u32(payload + CF_INODE_ATTRIBUTES);
    name_length = cf_get_u16(payload + CF_INODE_NAME_LENGTH);
    if (node->id == 0 || node->id == 1 || node->id >= g->store->next_inode_id ||
        record_id != node->id || !cf_idset_insert(g, node->id) ||
        node->parent_id != expected_parent_id ||
        cf_get_u16(payload + CF_INODE_FLAGS) != 0)
        goto bad;
    if (name_length == 0 || name_length > CF_NAME_MAX ||
        !cf_all_zero(payload + CF_INODE_NAME + (size_t)name_length * 2,
            CF_INODE_NAME_BYTES - (size_t)name_length * 2))
        goto bad;
    for (uint16_t i = 0; i < name_length; ++i)
        node->name[i] = (wchar_t)cf_get_u16(payload + CF_INODE_NAME + (size_t)i * 2);
    node->name[name_length] = 0;
    node->name_length = name_length;
    if (!cf_valid_name_units(node->name, node->name_length))
        goto bad;
    if (!cf_all_zero(payload + 606, 2) || !cf_all_zero(payload + 608, CF_PAYLOAD_SIZE - 608))
        goto bad;
    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        node->size > g->store->capacity ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY && (map_head != 0 || node->size != 0)) ||
        (!(attrs & FILE_ATTRIBUTE_DIRECTORY) && first_child != 0) ||
        (orphan && (node->parent_id != 0 || next_sibling != 0 || first_child != 0)) ||
        (!orphan && orphan_link != 0))
        goto bad;
    is_directory = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    node->attributes = attrs;
    node->depth = depth;
    node->parent = parent;
    node->unlinked = orphan;
    node->page = page;
    page->inode = node;
    if (!cf_node_array_add(g->store, node)) {
        cf_graph_set_error(g, CF_NO_MEMORY);
        goto bad;
    }
    node_registered = true;
    if (!cf_page_register(g->store, page))
        goto bad;
    page_registered = true;
    cf_page_set_owner(page, owner_page, owner_offset);
    if (node->size > UINT64_MAX - g->store->logical_used ||
        g->store->logical_used + node->size > g->store->capacity)
        goto bad;
    g->store->logical_used += node->size;
    if (is_directory) {
        uint64_t child_slot = first_child;
        CF_NODE *previous = NULL;
        uint32_t guard = 0;
        while (child_slot) {
            CF_NODE *child = NULL;
            uint64_t sibling_slot = 0;
            uint64_t child_orphan_slot = 0;
            CF_PAGE *child_owner = previous ? previous->page : node->page;
            uint32_t off = previous ? CF_INODE_NEXT_SIBLING : CF_INODE_FIRST_CHILD;
            if (++guard > CF_MAX_NODES ||
                !cf_graph_load_inode(g, child_slot, node, node->id,
                    (uint16_t)(depth + 1), false, child_owner, off,
                    &child, &sibling_slot, &child_orphan_slot) || child_orphan_slot != 0)
                goto bad;
            if (cf_child_find(node, child->name, child->name_length))
                goto bad;
            if (!cf_child_index_insert(node, child)) {
                cf_graph_set_error(g, CF_NO_MEMORY);
                goto bad;
            }
            if (previous)
                previous->next_sibling = child;
            else
                node->first_child = child;
            previous = child;
            child_slot = sibling_slot;
        }
    }
    if (!is_directory && map_head && !cf_graph_load_maps(g, node, map_head))
        goto bad;
    *out_node = node;
    *out_next_sibling_slot = next_sibling;
    *out_next_orphan_slot = orphan_link;
    cf_wipe(disk, sizeof(disk));
    cf_wipe(payload, sizeof(payload));
    return true;
bad:
    if (node && !node_registered) {
        cf_wipe(node, sizeof(*node));
        free(node);
    }
    if (node_registered && !page_registered)
        node->page = NULL;
    if (page && !page_registered) {
        cf_wipe(page, sizeof(*page));
        free(page);
    }
    cf_wipe(disk, sizeof(disk));
    cf_wipe(payload, sizeof(payload));
    return false;
}

static bool cf_graph_load_root(CF_GRAPH *g) {
    uint8_t disk[CF_PAGE_SIZE];
    uint8_t payload[CF_PAYLOAD_SIZE];
    uint64_t record_id = 0, first_child, orphan_slot;
    uint64_t next_id;
    CF_NODE *root = NULL;
    CF_PAGE *page = NULL;
    bool node_registered = false, page_registered = false;
    if (!cf_graph_read_page(g, CF_ROOT_SLOT, disk) ||
        !cf_page_decrypt(g->store, CF_ROOT_SLOT, disk, CF_RECORD_INODE, 1,
            payload, &record_id) || record_id != 1)
        goto bad;
    root = (CF_NODE *)calloc(1, sizeof(*root));
    page = cf_page_new(CF_ROOT_SLOT, CF_RECORD_INODE, 1);
    if (!root || !page) {
        cf_graph_set_error(g, CF_NO_MEMORY);
        goto bad;
    }
    first_child = cf_get_u64(payload + CF_INODE_FIRST_CHILD);
    orphan_slot = cf_get_u64(payload + CF_INODE_ORPHAN_LINK);
    next_id = cf_get_u64(payload + CF_INODE_NEXT_ID);
    if (cf_get_u64(payload + CF_INODE_ID) != 1 ||
        cf_get_u64(payload + CF_INODE_PARENT_ID) != 0 ||
        cf_get_u64(payload + CF_INODE_NEXT_SIBLING) != 0 ||
        cf_get_u64(payload + CF_INODE_MAP_HEAD) != 0 ||
        cf_get_u64(payload + CF_INODE_SIZE) != 0 ||
        cf_get_u32(payload + CF_INODE_ATTRIBUTES) != FILE_ATTRIBUTE_DIRECTORY ||
        cf_get_u16(payload + CF_INODE_NAME_LENGTH) != 0 ||
        cf_get_u16(payload + CF_INODE_FLAGS) != 0 || next_id < 2 ||
        !cf_all_zero(payload + CF_INODE_NAME, CF_INODE_NAME_BYTES) ||
        !cf_all_zero(payload + 606, 2) ||
        !cf_all_zero(payload + 616, CF_PAYLOAD_SIZE - 616) ||
        !cf_idset_insert(g, 1))
        goto bad;
    root->store = g->store;
    root->id = 1;
    root->attributes = FILE_ATTRIBUTE_DIRECTORY;
    root->creation_time = cf_get_u64(payload + CF_INODE_CREATED);
    root->access_time = cf_get_u64(payload + CF_INODE_ACCESSED);
    root->write_time = cf_get_u64(payload + CF_INODE_WRITTEN);
    root->change_time = cf_get_u64(payload + CF_INODE_CHANGED);
    root->page = page;
    page->inode = root;
    g->store->root = root;
    g->store->root_page = page;
    g->store->next_inode_id = next_id;
    if (!cf_node_array_add(g->store, root)) {
        cf_graph_set_error(g, CF_NO_MEMORY);
        goto bad;
    }
    node_registered = true;
    if (!cf_page_register(g->store, page)) {
        cf_graph_set_error(g, CF_DATA_ERROR);
        goto bad;
    }
    page_registered = true;
    {
        uint64_t child_slot = first_child;
        CF_NODE *previous = NULL;
        uint32_t guard = 0;
        while (child_slot) {
            CF_NODE *child = NULL;
            uint64_t sibling_slot = 0, child_orphan_slot = 0;
            CF_PAGE *owner = previous ? previous->page : page;
            uint32_t off = previous ? CF_INODE_NEXT_SIBLING : CF_INODE_FIRST_CHILD;
            if (++guard > CF_MAX_NODES ||
                !cf_graph_load_inode(g, child_slot, root, 1, 1, false,
                    owner, off, &child, &sibling_slot, &child_orphan_slot) || child_orphan_slot != 0)
                goto bad;
            if (cf_child_find(root, child->name, child->name_length))
                goto bad;
            if (!cf_child_index_insert(root, child)) {
                cf_graph_set_error(g, CF_NO_MEMORY);
                goto bad;
            }
            if (previous)
                previous->next_sibling = child;
            else
                root->first_child = child;
            previous = child;
            child_slot = sibling_slot;
        }
    }
    {
        uint64_t slot = orphan_slot;
        CF_NODE *previous = NULL;
        uint32_t guard = 0;
        while (slot) {
            CF_NODE *orphan = NULL;
            uint64_t sibling_slot = 0, next_orphan_slot = 0;
            CF_PAGE *owner = previous ? previous->page : page;
            if (++guard > CF_MAX_NODES ||
                !cf_graph_load_inode(g, slot, NULL, 0, 0, true, owner,
                    CF_INODE_ORPHAN_LINK, &orphan, &sibling_slot, &next_orphan_slot) || sibling_slot != 0)
                goto bad;
            if (previous)
                previous->orphan_next = orphan;
            else
                root->orphan_next = orphan;
            previous = orphan;
            slot = next_orphan_slot;
        }
    }
    cf_wipe(disk, sizeof(disk));
    cf_wipe(payload, sizeof(payload));
    return true;
bad:
    if (root && !node_registered) {
        g->store->root = NULL;
        cf_wipe(root, sizeof(*root));
        free(root);
    }
    if (root && node_registered && !page_registered)
        root->page = NULL;
    if (page && !page_registered) {
        g->store->root_page = NULL;
        cf_wipe(page, sizeof(*page));
        free(page);
    }
    cf_wipe(disk, sizeof(disk));
    cf_wipe(payload, sizeof(payload));
    return false;
}

static bool cf_graph_validate(CF_STORE *s, CF_IMAGE *overlay,
    uint32_t overlay_count, uint64_t target_eof, CF_RESULT *error) {
    CF_GRAPH graph;
    uint32_t i;
    memset(&graph, 0, sizeof(graph));
    graph.store = s;
    graph.overlay = overlay;
    graph.overlay_count = overlay_count;
    graph.target_eof = target_eof;
    graph.target_slots = (target_eof - CF_PAGES_OFFSET) / CF_PAGE_SIZE;
    graph.error = CF_OK;
    graph.ids = (uint64_t *)calloc(131072u, sizeof(uint64_t));
    if (!graph.ids) {
        *error = CF_NO_MEMORY;
        return false;
    }
    if (!cf_slots_ensure(s, graph.target_slots)) {
        *error = CF_NO_MEMORY;
        free(graph.ids);
        return false;
    }
    s->eof = target_eof;
    s->slot_count = 0;
    s->live_page_count = 0;
    s->logical_used = 0;
    s->root = NULL;
    s->root_page = NULL;
    s->node_count = 0;
    s->free_floor = 1;
    if (s->slot_capacity)
        memset(s->slots, 0, s->slot_capacity * sizeof(CF_PAGE *));
    if (!cf_graph_load_root(&graph))
        goto fail;
    for (i = 0; i < overlay_count; ++i) {
        if (!overlay[i].used) {
            graph.error = CF_DATA_ERROR;
            goto fail;
        }
    }
    *error = CF_OK;
    cf_wipe(graph.ids, 131072u * sizeof(uint64_t));
    free(graph.ids);
    return true;
fail:
    *error = graph.error == CF_OK ? CF_DATA_ERROR : graph.error;
    cf_wipe(graph.ids, 131072u * sizeof(uint64_t));
    free(graph.ids);
    return false;
}

static bool cf_wal_read(CF_STORE *s, const CF_MARKER *marker,
    CF_IMAGE **images_out, uint32_t *count_out, CF_RESULT *error) {
    uint8_t *bytes = NULL;
    uint8_t *plain = NULL;
    uint8_t aad[56];
    uint8_t hash[32];
    size_t plain_length = 0;
    uint32_t cipher_length, count = 0, i;
    CF_IMAGE *images = NULL;
    bool ok = false;
    *images_out = NULL;
    *count_out = 0;
    *error = CF_DATA_ERROR;
    bytes = (uint8_t *)malloc(marker->journal_length);
    if (!bytes) {
        *error = CF_NO_MEMORY;
        goto done;
    }
    if (!cf_file_read_at(s->file, CF_JOURNAL_OFFSET, bytes,
        marker->journal_length, NULL))
        goto done;
    cf_hash(bytes, marker->journal_length, hash);
    if (memcmp(hash, marker->journal_hash, sizeof(hash)) != 0 ||
        memcmp(bytes + CF_WAL_MAGIC, g_wal_magic, sizeof(g_wal_magic)) != 0 ||
        cf_get_u32(bytes + CF_WAL_VERSION) != CF_FORMAT_VERSION)
        goto done;
    cipher_length = cf_get_u32(bytes + CF_WAL_CIPHER_LENGTH);
    if (cipher_length != marker->journal_length - CF_WAL_HEADER_SIZE ||
        cipher_length < CF_TAG_BYTES + CF_WAL_PLAIN_HEADER_SIZE)
        goto done;
    plain_length = cipher_length - CF_TAG_BYTES;
    plain = (uint8_t *)malloc(plain_length);
    if (!plain) {
        *error = CF_NO_MEMORY;
        goto done;
    }
    memcpy(aad, s->uuid, 16);
    memcpy(aad + 16, bytes, CF_WAL_HEADER_SIZE);
    if (!cf_decrypt(s->keys.journal, bytes + CF_WAL_NONCE, aad, sizeof(aad),
        bytes + CF_WAL_CIPHER, cipher_length, plain, plain_length, &plain_length))
        goto done;
    if (plain_length < CF_WAL_PLAIN_HEADER_SIZE ||
        memcmp(plain, g_wal_plain_magic, sizeof(g_wal_plain_magic)) != 0 ||
        cf_get_u32(plain + 8) != CF_FORMAT_VERSION)
        goto done;
    count = cf_get_u32(plain + 12);
    if (count > CF_MAX_TRANSACTION_PAGES ||
        plain_length != CF_WAL_PLAIN_HEADER_SIZE + (size_t)count * CF_WAL_PAGE_ENTRY_SIZE ||
        cf_get_u64(plain + 16) != marker->generation ||
        cf_get_u64(plain + 24) != marker->final_eof ||
        (count == 0 && marker->final_eof > s->disk_eof))
        goto done;
    images = count ? (CF_IMAGE *)calloc(count, sizeof(CF_IMAGE)) : NULL;
    if (count && !images) {
        *error = CF_NO_MEMORY;
        goto done;
    }
    for (i = 0; i < count; ++i) {
        const uint8_t *entry = plain + CF_WAL_PLAIN_HEADER_SIZE + (size_t)i * CF_WAL_PAGE_ENTRY_SIZE;
        uint64_t slot = cf_get_u64(entry);
        uint64_t offset;
        if (slot == CF_ROOT_SLOT) {
            offset = CF_ROOT_OFFSET;
        } else if (!cf_slot_offset(slot, &offset) ||
            offset > UINT64_MAX - CF_PAGE_SIZE || offset + CF_PAGE_SIZE > marker->final_eof) {
            goto done;
        }
        images[i].slot = slot;
        memcpy(images[i].bytes, entry + CF_WAL_PAGE_BYTES, CF_PAGE_SIZE);
    }
    if (count)
        qsort(images, count, sizeof(CF_IMAGE), cf_image_compare);
    for (i = 1; i < count; ++i) {
        if (images[i - 1].slot == images[i].slot)
            goto done;
    }
    *images_out = images;
    *count_out = count;
    images = NULL;
    *error = CF_OK;
    ok = true;
done:
    if (!ok && *error == CF_OK)
        *error = CF_DATA_ERROR;
    if (images) {
        cf_wipe(images, (size_t)(count ? count : 0) * sizeof(CF_IMAGE));
        free(images);
    }
    if (bytes) {
        cf_wipe(bytes, marker->journal_length);
        free(bytes);
    }
    if (plain) {
        cf_wipe(plain, plain_length);
        free(plain);
    }
    cf_wipe(aad, sizeof(aad));
    cf_wipe(hash, sizeof(hash));
    return ok;
}

static void cf_node_serialize(CF_STORE *s, CF_NODE *node,
    uint8_t payload[CF_PAYLOAD_SIZE]) {
    uint32_t i;
    memset(payload, 0, CF_PAYLOAD_SIZE);
    cf_put_u64(payload + CF_INODE_ID, node->id);
    cf_put_u64(payload + CF_INODE_PARENT_ID, node == s->root ? 0 : (node->parent ? node->parent->id : 0));
    cf_put_u64(payload + CF_INODE_FIRST_CHILD,
        node->first_child ? node->first_child->page->slot : 0);
    cf_put_u64(payload + CF_INODE_NEXT_SIBLING,
        node->next_sibling ? node->next_sibling->page->slot : 0);
    cf_put_u64(payload + CF_INODE_MAP_HEAD,
        node->maps ? node->maps->page->slot : 0);
    cf_put_u64(payload + CF_INODE_ORPHAN_LINK,
        node->orphan_next ? node->orphan_next->page->slot : 0);
    cf_put_u64(payload + CF_INODE_SIZE, node->size);
    cf_put_u64(payload + CF_INODE_CREATED, node->creation_time);
    cf_put_u64(payload + CF_INODE_ACCESSED, node->access_time);
    cf_put_u64(payload + CF_INODE_WRITTEN, node->write_time);
    cf_put_u64(payload + CF_INODE_CHANGED, node->change_time);
    cf_put_u32(payload + CF_INODE_ATTRIBUTES, node->attributes);
    cf_put_u16(payload + CF_INODE_NAME_LENGTH, node->name_length);
    for (i = 0; i < node->name_length; ++i)
        cf_put_u16(payload + CF_INODE_NAME + (size_t)i * 2, (uint16_t)node->name[i]);
    if (node == s->root)
        cf_put_u64(payload + CF_INODE_NEXT_ID, s->next_inode_id);
}

static void cf_map_serialize(CF_NODE *node, CF_MAP_PAGE *map,
    uint8_t payload[CF_PAYLOAD_SIZE]) {
    uint32_t i;
    memset(payload, 0, CF_PAYLOAD_SIZE);
    cf_put_u64(payload + CF_MAP_FILE_ID, node->id);
    cf_put_u64(payload + CF_MAP_NEXT,
        map->next ? map->next->page->slot : 0);
    cf_put_u16(payload + CF_MAP_COUNT, (uint16_t)map->count);
    for (i = 0; i < map->count; ++i) {
        CF_BLOCK *block = map->blocks[i];
        uint8_t *entry = payload + CF_MAP_ENTRIES + (size_t)i * CF_MAP_ENTRY_SIZE;
        cf_put_u64(entry + CF_MAP_ENTRY_BLOCK, block->index);
        cf_put_u64(entry + CF_MAP_ENTRY_FRAGMENT,
            block->fragment_count ? block->fragments[0]->slot : 0);
        cf_put_u32(entry + CF_MAP_ENTRY_ENCODED_LENGTH, block->encoded_length);
        cf_put_u32(entry + CF_MAP_ENTRY_CODEC, block->codec);
        cf_put_u32(entry + CF_MAP_ENTRY_RAW_LENGTH, CF_BLOCK_SIZE);
        cf_put_u32(entry + CF_MAP_ENTRY_FRAGMENT_COUNT, block->fragment_count);
    }
}

static bool cf_tx_begin(CF_STORE *s, CF_TX *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->images = (CF_IMAGE *)calloc(CF_MAX_TRANSACTION_PAGES, sizeof(CF_IMAGE));
    if (!tx->images)
        return false;
    tx->store = s;
    tx->final_eof = s->eof;
    return true;
}

static void cf_tx_dispose(CF_TX *tx) {
    if (tx->images) {
        cf_wipe(tx->images, CF_MAX_TRANSACTION_PAGES * sizeof(CF_IMAGE));
        free(tx->images);
    }
    memset(tx, 0, sizeof(*tx));
}

static bool cf_tx_fail(CF_TX *tx, CF_RESULT failure) {
    if (tx)
        tx->failure = failure;
    return false;
}

static CF_RESULT cf_tx_failure_result(CF_TX *tx, CF_RESULT fallback) {
    if (tx && tx->failure != CF_OK)
        return tx->failure;
    if (tx && tx->store && tx->store->poisoned)
        return CF_IO_ERROR;
    return fallback;
}

static bool cf_tx_contains(const CF_TX *tx, uint64_t slot) {
    uint32_t i;
    for (i = 0; i < tx->count; ++i) {
        if (tx->images[i].slot == slot)
            return true;
    }
    for (i = 0; i < tx->reserved_count; ++i) {
        if (tx->reserved[i] == slot)
            return true;
    }
    return false;
}

static bool cf_tx_add_raw(CF_TX *tx, uint64_t slot,
    const uint8_t bytes[CF_PAGE_SIZE]) {
    uint32_t i;
    uint64_t offset;
    for (i = 0; i < tx->count; ++i) {
        if (tx->images[i].slot == slot) {
            memcpy(tx->images[i].bytes, bytes, CF_PAGE_SIZE);
            return true;
        }
    }
    if (tx->count >= CF_MAX_TRANSACTION_PAGES)
        return false;
    tx->images[tx->count].slot = slot;
    memcpy(tx->images[tx->count].bytes, bytes, CF_PAGE_SIZE);
    ++tx->count;
    if (slot != CF_ROOT_SLOT) {
        if (!cf_slot_offset(slot, &offset))
            return false;
        if (offset + CF_PAGE_SIZE > tx->final_eof)
            tx->final_eof = offset + CF_PAGE_SIZE;
    }
    return true;
}

static bool cf_tx_add_payload(CF_TX *tx, uint64_t slot, uint16_t type,
    uint64_t record_id, const uint8_t payload[CF_PAYLOAD_SIZE]) {
    uint8_t bytes[CF_PAGE_SIZE];
    bool ok = cf_page_encrypt(tx->store, slot, type, record_id, payload, bytes) &&
        cf_tx_add_raw(tx, slot, bytes);
    cf_wipe(bytes, sizeof(bytes));
    return ok;
}

static bool cf_tx_add_node(CF_TX *tx, CF_NODE *node) {
    uint8_t payload[CF_PAYLOAD_SIZE];
    bool ok;
    cf_node_serialize(tx->store, node, payload);
    ok = cf_tx_add_payload(tx, node->page->slot, CF_RECORD_INODE, node->id, payload);
    cf_wipe(payload, sizeof(payload));
    return ok;
}

static bool cf_tx_add_map(CF_TX *tx, CF_NODE *node, CF_MAP_PAGE *map) {
    uint8_t payload[CF_PAYLOAD_SIZE];
    bool ok;
    cf_map_serialize(node, map, payload);
    ok = cf_tx_add_payload(tx, map->page->slot, CF_RECORD_MAP, node->id, payload);
    cf_wipe(payload, sizeof(payload));
    return ok;
}

static bool cf_tx_add_fragment(CF_TX *tx, CF_NODE *node, CF_BLOCK *block,
    uint32_t sequence, const uint8_t *encoded) {
    uint8_t payload[CF_PAYLOAD_SIZE];
    uint32_t offset = sequence * CF_FRAGMENT_CAPACITY;
    uint32_t remaining = block->encoded_length - offset;
    uint32_t used = remaining > CF_FRAGMENT_CAPACITY ? CF_FRAGMENT_CAPACITY : remaining;
    CF_PAGE *page = block->fragments[sequence];
    memset(payload, 0, sizeof(payload));
    cf_put_u64(payload + CF_FRAGMENT_FILE_ID, node->id);
    cf_put_u64(payload + CF_FRAGMENT_BLOCK, block->index);
    cf_put_u64(payload + CF_FRAGMENT_NEXT,
        sequence + 1 < block->fragment_count ? block->fragments[sequence + 1]->slot : 0);
    cf_put_u32(payload + CF_FRAGMENT_SEQUENCE, sequence);
    cf_put_u32(payload + CF_FRAGMENT_LENGTH, used);
    memcpy(payload + CF_FRAGMENT_DATA, encoded + offset, used);
    {
        bool ok = cf_tx_add_payload(tx, page->slot, CF_RECORD_FRAGMENT,
            node->id, payload);
        cf_wipe(payload, sizeof(payload));
        return ok;
    }
}

/* Advances the dense-prefix floor over committed pages; caller holds the lock exclusively. */
static uint64_t cf_free_floor(CF_STORE *s, uint64_t limit) {
    uint64_t slot = s->free_floor ? s->free_floor : 1;
    while (slot <= limit && slot < s->slot_capacity && s->slots[slot])
        ++slot;
    s->free_floor = slot;
    return slot;
}

static uint64_t cf_tx_find_free_slot(CF_TX *tx) {
    CF_STORE *s = tx->store;
    uint64_t high_eof = tx->final_eof > s->eof ? tx->final_eof : s->eof;
    uint64_t eof_slots = (high_eof - CF_PAGES_OFFSET) / CF_PAGE_SIZE;
    uint64_t start = s->allocation_hint ? s->allocation_hint : 1;
    uint64_t floor = cf_free_floor(s, eof_slots);
    uint64_t slot;
    if (start > eof_slots + 1)
        start = floor;
    if (start < floor)
        start = floor;
    for (slot = start; slot <= eof_slots; ++slot) {
        if ((!s->slots || slot >= s->slot_capacity || !s->slots[slot]) &&
            !cf_tx_contains(tx, slot)) {
            uint64_t offset;
            if (tx->reserved_count >= CF_MAX_TRANSACTION_PAGES || !cf_slots_ensure(s, slot))
                return 0;
            tx->reserved[tx->reserved_count++] = slot;
            cf_slot_offset(slot, &offset);
            if (offset + CF_PAGE_SIZE > tx->final_eof)
                tx->final_eof = offset + CF_PAGE_SIZE;
            s->allocation_hint = slot + 1;
            return slot;
        }
    }
    /* Without the floor this wrap-around rescanned every slot for each new
     * page once the container had no holes, making appends O(pages). */
    for (slot = floor; slot < start && slot <= eof_slots; ++slot) {
        if ((!s->slots || slot >= s->slot_capacity || !s->slots[slot]) &&
            !cf_tx_contains(tx, slot)) {
            uint64_t offset;
            if (tx->reserved_count >= CF_MAX_TRANSACTION_PAGES || !cf_slots_ensure(s, slot))
                return 0;
            tx->reserved[tx->reserved_count++] = slot;
            cf_slot_offset(slot, &offset);
            if (offset + CF_PAGE_SIZE > tx->final_eof)
                tx->final_eof = offset + CF_PAGE_SIZE;
            s->allocation_hint = slot + 1;
            return slot;
        }
    }
    if (eof_slots < CF_MAX_SLOTS) {
        slot = eof_slots + 1;
        if (!cf_tx_contains(tx, slot) && tx->reserved_count < CF_MAX_TRANSACTION_PAGES &&
            cf_slots_ensure(s, slot)) {
            uint64_t offset;
            tx->reserved[tx->reserved_count++] = slot;
            cf_slot_offset(slot, &offset);
            tx->final_eof = offset + CF_PAGE_SIZE;
            s->allocation_hint = slot + 1;
            return slot;
        }
    }
    return 0;
}

static CF_PAGE *cf_tx_new_page(CF_TX *tx, uint16_t type, uint64_t record_id) {
#ifdef CRYPTFS_TESTING
    if (cf_test_countdown_failure(&g_test_fail_page_allocation_count))
        return NULL;
#endif
    uint64_t slot = cf_tx_find_free_slot(tx);
    CF_PAGE *page;
    if (!slot)
        return NULL;
    page = cf_page_new(slot, type, record_id);
    return page;
}

static void cf_marker_offset(uint32_t slot, uint64_t *offset) {
    *offset = slot ? CF_MARK1_OFFSET : CF_MARK0_OFFSET;
}

static bool cf_tx_commit(CF_TX *tx) {
    CF_STORE *s;
    uint8_t *plain = NULL;
    uint8_t *journal = NULL;
    uint8_t aad[56];
    uint8_t hash[32];
    uint8_t marker[CF_PAGE_SIZE];
    size_t plain_length, cipher_length, journal_length;
    uint64_t committed_generation, empty_generation;
    uint32_t i, r;
    uint64_t marker_offset;
    bool committed = false;
    DWORD error = 0;
    bool ok = false;
    if (!tx)
        return false;
    tx->failure = CF_OK;
    s = tx->store;
    if (!s)
        return cf_tx_fail(tx, CF_DATA_ERROR);
    if (s->poisoned)
        return cf_tx_fail(tx, CF_IO_ERROR);
    if (tx->count > CF_MAX_TRANSACTION_PAGES ||
        tx->reserved_count > CF_MAX_TRANSACTION_PAGES ||
        !cf_eof_valid(tx->final_eof) || tx->final_eof > CF_MAX_EOF ||
        (tx->count == 0 && tx->final_eof >= s->eof))
        return cf_tx_fail(tx, CF_INVALID);
    if (s->generation > UINT64_MAX - 2)
        return cf_tx_fail(tx, CF_NO_SPACE);
    plain_length = CF_WAL_PLAIN_HEADER_SIZE + (size_t)tx->count * CF_WAL_PAGE_ENTRY_SIZE;
    cipher_length = plain_length + CF_TAG_BYTES;
    journal_length = CF_WAL_HEADER_SIZE + cipher_length;
    if (journal_length > CF_MAX_TRANSACTION_BYTES || journal_length > CF_JOURNAL_SIZE ||
        journal_length > UINT32_MAX)
        return cf_tx_fail(tx, CF_NO_SPACE);
    if (tx->count)
        qsort(tx->images, tx->count, sizeof(CF_IMAGE), cf_image_compare);
    for (i = 0; i < tx->count; ++i) {
        uint64_t slot = tx->images[i].slot;
        uint64_t offset;
        if (i && tx->images[i - 1].slot == slot)
            return cf_tx_fail(tx, CF_DATA_ERROR);
        if (slot == CF_ROOT_SLOT)
            continue;
        if (!cf_slot_offset(slot, &offset) || offset + CF_PAGE_SIZE > tx->final_eof)
            return cf_tx_fail(tx, CF_DATA_ERROR);
    }
    for (r = 0; r < tx->reserved_count; ++r) {
        bool imaged = false;
        for (i = 0; i < tx->count; ++i) {
            if (tx->images[i].slot == tx->reserved[r]) {
                imaged = true;
                break;
            }
        }
        if (!imaged)
            return cf_tx_fail(tx, CF_DATA_ERROR);
    }
    plain = (uint8_t *)calloc(1, plain_length ? plain_length : 1);
    journal = (uint8_t *)calloc(1, journal_length ? journal_length : 1);
    if (!plain || !journal) {
        tx->failure = CF_NO_MEMORY;
        goto done;
    }
    memcpy(plain, g_wal_plain_magic, sizeof(g_wal_plain_magic));
    cf_put_u32(plain + 8, CF_FORMAT_VERSION);
    cf_put_u32(plain + 12, tx->count);
    committed_generation = s->generation + 1;
    empty_generation = committed_generation + 1;
    cf_put_u64(plain + 16, committed_generation);
    cf_put_u64(plain + 24, tx->final_eof);
    for (i = 0; i < tx->count; ++i) {
        uint8_t *entry = plain + CF_WAL_PLAIN_HEADER_SIZE + (size_t)i * CF_WAL_PAGE_ENTRY_SIZE;
        cf_put_u64(entry + CF_WAL_PAGE_SLOT, tx->images[i].slot);
        memcpy(entry + CF_WAL_PAGE_BYTES, tx->images[i].bytes, CF_PAGE_SIZE);
    }
    memcpy(journal + CF_WAL_MAGIC, g_wal_magic, sizeof(g_wal_magic));
    cf_put_u32(journal + CF_WAL_VERSION, CF_FORMAT_VERSION);
    cf_put_u32(journal + CF_WAL_CIPHER_LENGTH, (uint32_t)cipher_length);
    cf_random(journal + CF_WAL_NONCE, CF_NONCE_BYTES);
    memcpy(aad, s->uuid, 16);
    memcpy(aad + 16, journal, CF_WAL_HEADER_SIZE);
    if (!cf_encrypt(s->keys.journal, journal + CF_WAL_NONCE,
        aad, sizeof(aad), plain, plain_length, journal + CF_WAL_CIPHER,
        cipher_length)) {
        tx->failure = CF_DATA_ERROR;
        goto done;
    }
    cf_hash(journal, journal_length, hash);
    cf_marker_build(s, (uint32_t)(committed_generation & 1), CF_MARK_COMMITTED,
        committed_generation, (uint32_t)journal_length, tx->final_eof, hash, marker);
    cf_marker_offset((uint32_t)(committed_generation & 1), &marker_offset);
    if (!cf_file_write_at(s->file, CF_JOURNAL_OFFSET, journal,
        (uint32_t)journal_length, &error) || !cf_flush_file(s)) {
        cf_set_error(s, error ? error : GetLastError());
        tx->failure = CF_IO_ERROR;
        goto done;
    }
    cf_crash_after_phase(1);
    /* From the first byte of the alternating commit marker onward, the
     * durable outcome is uncertain if an I/O call fails. Do not permit any
     * further transaction until the container is reopened and recovered. */
    committed = true;
    if (!cf_file_write_at(s->file, marker_offset, marker, CF_PAGE_SIZE, &error)) {
        cf_set_error(s, error ? error : GetLastError());
        tx->failure = CF_IO_ERROR;
        goto done;
    }
    if (!cf_flush_file(s)) {
        tx->failure = CF_IO_ERROR;
        goto done;
    }
    cf_crash_after_phase(2);
    for (i = 0; i < tx->count; ++i) {
        if (!cf_write_physical(s, tx->images[i].slot, tx->images[i].bytes)) {
            tx->failure = CF_IO_ERROR;
            goto done;
        }
    }
    if (!cf_flush_file(s)) {
        tx->failure = CF_IO_ERROR;
        goto done;
    }
    cf_crash_after_phase(3);
    /* Most transactions rewrite pages in place; resizing and flushing an
     * unchanged EOF only cost another full FlushFileBuffers. */
    if (tx->final_eof != s->disk_eof &&
        (!cf_set_eof(s, tx->final_eof) || !cf_flush_file(s))) {
        tx->failure = CF_IO_ERROR;
        goto done;
    }
    cf_crash_after_phase(4);
    cf_marker_build(s, (uint32_t)(empty_generation & 1), CF_MARK_EMPTY,
        empty_generation, 0, tx->final_eof, NULL, marker);
    cf_marker_offset((uint32_t)(empty_generation & 1), &marker_offset);
    if (!cf_file_write_at(s->file, marker_offset, marker, CF_PAGE_SIZE, &error) ||
        !cf_flush_file(s)) {
        cf_set_error(s, error ? error : GetLastError());
        tx->failure = CF_IO_ERROR;
        goto done;
    }
    cf_crash_after_phase(5);
    s->generation = empty_generation;
    s->eof = tx->final_eof;
    s->disk_eof = tx->final_eof;
    s->slot_count = (s->eof - CF_PAGES_OFFSET) / CF_PAGE_SIZE;
    ++s->commits;
    ok = true;
    tx->failure = CF_OK;
    if (s->worker_idle)
        ResetEvent(s->worker_idle);
    if (s->worker_wake)
        SetEvent(s->worker_wake);
done:
    if (!ok && committed) {
        s->poisoned = true;
        tx->failure = CF_IO_ERROR;
    } else if (!ok && tx->failure == CF_OK) {
        tx->failure = CF_NO_MEMORY;
    }
    if (plain) {
        cf_wipe(plain, plain_length);
        free(plain);
    }
    if (journal) {
        cf_wipe(journal, journal_length);
        free(journal);
    }
    cf_wipe(aad, sizeof(aad));
    cf_wipe(hash, sizeof(hash));
    cf_wipe(marker, sizeof(marker));
    return ok;
}

static CF_RESULT cf_reclaim_orphans(CF_STORE *s);
static CF_RESULT cf_store_compact_locked(CF_STORE *s, bool *progress);

static void cf_node_free_contents(CF_NODE *node, bool pages_already_freed) {
    CF_MAP_PAGE *map, *next_map;
    if (!node)
        return;
    map = node->maps;
    while (map) {
        uint32_t i;
        next_map = map->next;
        for (i = 0; i < map->count; ++i) {
            CF_BLOCK *block = map->blocks[i];
            if (block) {
                if (!pages_already_freed) {
                    uint32_t j;
                    for (j = 0; j < block->fragment_count; ++j) {
                        CF_PAGE *frag = block->fragments[j];
                        if (frag && !frag->registered) {
                            cf_wipe(frag, sizeof(*frag));
                            free(frag);
                        }
                    }
                }
                cf_wipe(block, sizeof(*block));
                free(block);
            }
        }
        if (!pages_already_freed && map->page && !map->page->registered) {
            cf_wipe(map->page, sizeof(*map->page));
            free(map->page);
        }
        cf_wipe(map, sizeof(*map));
        free(map);
        map = next_map;
    }
    if (!pages_already_freed && node->page && node->page->slot != CF_ROOT_SLOT &&
        !node->page->registered) {
        cf_wipe(node->page, sizeof(*node->page));
        free(node->page);
    }
    if (node->children) {
        cf_wipe(node->children, node->child_capacity * sizeof(CF_NODE *));
        free(node->children);
    }
    cf_wipe(node, sizeof(*node));
    free(node);
}

static void cf_store_dispose(CF_STORE *s) {
    size_t i;
    if (!s)
        return;
    if (s->worker_thread) {
        if (s->worker_stop)
            SetEvent(s->worker_stop);
        if (s->worker_wake)
            SetEvent(s->worker_wake);
        WaitForSingleObject(s->worker_thread, INFINITE);
        CloseHandle(s->worker_thread);
        s->worker_thread = NULL;
    }
    if (s->worker_stop) CloseHandle(s->worker_stop);
    if (s->worker_wake) CloseHandle(s->worker_wake);
    if (s->worker_idle) CloseHandle(s->worker_idle);
    for (i = 0; i < s->node_count; ++i)
        cf_node_free_contents(s->nodes[i], false);
    if (s->nodes) {
        cf_wipe(s->nodes, s->node_capacity * sizeof(CF_NODE *));
        free(s->nodes);
    }
    if (s->slots) {
        for (i = 1; i < s->slot_capacity; ++i) {
            if (s->slots[i]) {
                cf_wipe(s->slots[i], sizeof(CF_PAGE));
                free(s->slots[i]);
            }
        }
        cf_wipe(s->slots, s->slot_capacity * sizeof(CF_PAGE *));
        free(s->slots);
    }
    if (s->root_page) {
        cf_wipe(s->root_page, sizeof(*s->root_page));
        free(s->root_page);
    }
    if (s->file && s->file != INVALID_HANDLE_VALUE)
        CloseHandle(s->file);
    if (s->path) {
        cf_wipe(s->path, (wcslen(s->path) + 1) * sizeof(wchar_t));
        free(s->path);
    }
    cf_wipe(&s->keys, sizeof(s->keys));
    cf_wipe(s->uuid, sizeof(s->uuid));
    cf_wipe(s, sizeof(*s));
    free(s);
}

static bool cf_recover_committed(CF_STORE *s, const CF_MARKER *marker,
    CF_IMAGE *images, uint32_t count) {
    uint32_t i, empty_slot;
    uint64_t empty_generation, offset;
    uint8_t empty_marker[CF_PAGE_SIZE];
    DWORD error = 0;
    if (marker->generation == UINT64_MAX || !cf_eof_valid(marker->final_eof))
        return false;
    for (i = 0; i < count; ++i) {
        if (!cf_write_physical(s, images[i].slot, images[i].bytes))
            goto fail;
    }
    if (!cf_flush_file(s) || !cf_set_eof(s, marker->final_eof) || !cf_flush_file(s))
        goto fail;
    empty_generation = marker->generation + 1;
    empty_slot = (uint32_t)(empty_generation & 1);
    cf_marker_build(s, empty_slot, CF_MARK_EMPTY, empty_generation, 0,
        marker->final_eof, NULL, empty_marker);
    cf_marker_offset(empty_slot, &offset);
    if (!cf_file_write_at(s->file, offset, empty_marker, CF_PAGE_SIZE, &error) ||
        !cf_flush_file(s)) {
        cf_set_error(s, error ? error : GetLastError());
        goto fail;
    }
    s->generation = empty_generation;
    s->eof = marker->final_eof;
    s->disk_eof = marker->final_eof;
    s->slot_count = (s->eof - CF_PAGES_OFFSET) / CF_PAGE_SIZE;
    ++s->commits;
    cf_wipe(empty_marker, sizeof(empty_marker));
    return true;
fail:
    cf_wipe(empty_marker, sizeof(empty_marker));
    return false;
}

static CF_RESULT cf_reclaim_orphans(CF_STORE *s) {
#ifdef CRYPTFS_TESTING
    if (cf_test_countdown_failure(&g_test_fail_reclaim_count))
        return CF_NO_MEMORY;
#endif
    while (s->root && s->root->orphan_next) {
        CF_NODE *previous = s->root;
        CF_NODE *node = previous->orphan_next;
        while (node && node->references != 0) {
            previous = node;
            node = node->orphan_next;
        }
        if (!node)
            break;
        CF_NODE *next = node->orphan_next;
        CF_NODE **subtree = NULL;
        size_t subtree_count = 0, i, out = 0;
        uint64_t reclaimed_bytes = 0;
        CF_TX tx;
        CF_RESULT result = CF_IO_ERROR;
        /* Collect and mark the complete inode subtree before committing. The
         * physical ownership tree will free its CF_PAGE objects after commit;
         * every associated CF_NODE/Cf_MAP_PAGE must then be destroyed without
         * inspecting those page pointers. */
        if (s->node_count == 0 ||
            s->node_count > SIZE_MAX / sizeof(*subtree))
            return CF_DATA_ERROR;
        subtree = (CF_NODE **)malloc(s->node_count * sizeof(*subtree));
        if (!subtree)
            return CF_NO_MEMORY;
        {
            size_t pending = 0;
            subtree[pending++] = node;
            while (out < pending) {
                CF_NODE *current = subtree[out++];
                size_t child_index;
                if (!current || subtree_count >= s->node_count) {
                    free(subtree);
                    return CF_DATA_ERROR;
                }
                subtree[subtree_count++] = current;
                for (child_index = 0; child_index < current->child_count; ++child_index) {
                    if (pending >= s->node_count) {
                        free(subtree);
                        return CF_DATA_ERROR;
                    }
                    subtree[pending++] = current->children[child_index];
                }
            }
        }
        for (i = 0; i < subtree_count; ++i) {
            CF_NODE *current = subtree[i];
            if (current->reclaiming || current->size > UINT64_MAX - reclaimed_bytes) {
                for (i = 0; i < subtree_count; ++i)
                    subtree[i]->reclaiming = false;
                free(subtree);
                return CF_DATA_ERROR;
            }
            current->reclaiming = true;
            reclaimed_bytes += current->size;
        }
        if (reclaimed_bytes > s->logical_used) {
            for (i = 0; i < subtree_count; ++i)
                subtree[i]->reclaiming = false;
            free(subtree);
            return CF_DATA_ERROR;
        }
        previous->orphan_next = next;
        if (next)
            cf_page_set_owner(next->page,
                previous == s->root ? s->root_page : previous->page,
                CF_INODE_ORPHAN_LINK);
        if (!cf_tx_begin(s, &tx)) {
            previous->orphan_next = node;
            if (next)
                cf_page_set_owner(next->page, node->page, CF_INODE_ORPHAN_LINK);
            for (i = 0; i < subtree_count; ++i)
                subtree[i]->reclaiming = false;
            free(subtree);
            return CF_NO_MEMORY;
        }
        if (cf_tx_add_node(&tx, previous) && cf_tx_commit(&tx)) {
            s->logical_used -= reclaimed_bytes;
            for (i = 0, out = 0; i < s->node_count; ++i) {
                CF_NODE *candidate = s->nodes[i];
                if (!candidate->reclaiming)
                    s->nodes[out++] = candidate;
            }
            s->node_count = out;
            cf_page_unregister_tree(s, node->page);
            for (i = 0; i < subtree_count; ++i)
                cf_node_free_contents(subtree[i], true);
            result = CF_OK;
        } else {
            result = cf_tx_failure_result(&tx, CF_NO_MEMORY);
            previous->orphan_next = node;
            if (next)
                cf_page_set_owner(next->page, node->page, CF_INODE_ORPHAN_LINK);
            for (i = 0; i < subtree_count; ++i)
                subtree[i]->reclaiming = false;
        }
        cf_tx_dispose(&tx);
        free(subtree);
        if (result != CF_OK)
            return result;
    }
    return CF_OK;
}

static void cf_record_reclaim_failure(CF_STORE *s, CF_RESULT result) {
    DWORD error;
    if (!s || result == CF_OK)
        return;
    switch (result) {
    case CF_NO_MEMORY:
        error = ERROR_NOT_ENOUGH_MEMORY;
        break;
    case CF_NO_SPACE:
        error = ERROR_DISK_FULL;
        break;
    case CF_DATA_ERROR:
        error = ERROR_CRC;
        s->poisoned = true;
        break;
    case CF_IO_ERROR:
        if (s->last_error == ERROR_SUCCESS)
            s->last_error = ERROR_GEN_FAILURE;
        return;
    default:
        error = ERROR_GEN_FAILURE;
        break;
    }
    cf_set_error(s, error);
}

static bool cf_header_load(CF_STORE *s, const uint8_t sb0[CF_PAGE_SIZE],
    const uint8_t sb1[CF_PAGE_SIZE], const uint8_t *password,
    size_t password_length, CF_RESULT *error) {
    CF_HEADER_CANDIDATE candidates[2];
    bool identical = memcmp(sb0, sb1, CF_PAGE_SIZE) == 0;
    int selected = -1;
    memset(candidates, 0, sizeof(candidates));
    memcpy(candidates[0].bytes, sb0, CF_PAGE_SIZE);
    memcpy(candidates[1].bytes, sb1, CF_PAGE_SIZE);
    cf_sb_unwrap(candidates[0].bytes, password, password_length, &candidates[0]);
    if (identical) {
        candidates[1].structural = candidates[0].structural;
        candidates[1].unwrapped = candidates[0].unwrapped;
        if (candidates[0].unwrapped) {
            memcpy(candidates[1].uuid, candidates[0].uuid, 16);
            candidates[1].capacity = candidates[0].capacity;
            memcpy(candidates[1].master, candidates[0].master, CF_KEY_BYTES);
            candidates[1].keys = candidates[0].keys;
        }
    } else {
        cf_sb_unwrap(candidates[1].bytes, password, password_length, &candidates[1]);
    }
    if (candidates[0].unwrapped && candidates[1].unwrapped &&
        memcmp(candidates[0].bytes, candidates[1].bytes, CF_PAGE_SIZE) != 0) {
        *error = CF_DATA_ERROR;
        goto done;
    }
    if (candidates[0].unwrapped)
        selected = 0;
    else if (candidates[1].unwrapped)
        selected = 1;
    if (selected < 0) {
        *error = (candidates[0].structural || candidates[1].structural) ? CF_ACCESS : CF_DATA_ERROR;
        goto done;
    }
    memcpy(s->uuid, candidates[selected].uuid, sizeof(s->uuid));
    s->capacity = candidates[selected].capacity;
    s->keys = candidates[selected].keys;
    *error = CF_OK;
done:
    cf_wipe(candidates, sizeof(candidates));
    return selected >= 0;
}

static CF_RESULT cf_start_worker(CF_STORE *s);
static DWORD WINAPI cf_worker_proc(LPVOID parameter);

CF_RESULT cf_store_open(const CF_OPTIONS *options, const uint8_t *password,
    size_t password_length, CF_STORE **out_store) {
    CF_STORE *s = NULL;
    CF_RESULT result = CF_INVALID;
    uint8_t sb0[CF_PAGE_SIZE], sb1[CF_PAGE_SIZE];
    uint8_t marker_bytes[2][CF_PAGE_SIZE];
    CF_MARKER markers[2];
    CF_MARKER *selected = NULL;
    CF_IMAGE *images = NULL;
    uint32_t image_count = 0;
    CF_RESULT graph_error = CF_DATA_ERROR;
    LARGE_INTEGER file_size;
    DWORD error = 0;
    bool created = false;
    bool header_unwrapped = false;
    if (out_store)
        *out_store = NULL;
    if (!options || !options->container || !options->container[0] || !out_store ||
        !password || !cf_password_valid(password, password_length))
        return CF_INVALID;
    if (options->compression_level < -5 || options->compression_level > 22)
        return CF_INVALID;
    if (!cf_crypto_init())
        return CF_DATA_ERROR;
    s = (CF_STORE *)calloc(1, sizeof(*s));
    if (!s)
        return CF_NO_MEMORY;
    InitializeSRWLock(&s->lock);
    s->file = INVALID_HANDLE_VALUE;
    s->path = _wcsdup(options->container);
    if (!s->path) {
        result = CF_NO_MEMORY;
        goto fail;
    }
    s->compression_level = options->compression_level ? options->compression_level : 3;
    s->file = CreateFileW(options->container, GENERIC_READ | GENERIC_WRITE |
        (options->create_new ? DELETE : 0), 0, NULL,
        options->create_new ? CREATE_NEW : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_RANDOM_ACCESS,
        NULL);
    if (s->file == INVALID_HANDLE_VALUE) {
        s->last_error = GetLastError();
        result = (options->create_new && (s->last_error == ERROR_FILE_EXISTS ||
            s->last_error == ERROR_ALREADY_EXISTS)) ? CF_EXISTS : CF_IO_ERROR;
        goto fail;
    }
    created = options->create_new;
    if (options->create_new) {
        uint64_t capacity = options->capacity ? options->capacity : CF_DEFAULT_CAPACITY;
        if (capacity == 0 || capacity > CF_DEFAULT_CAPACITY) {
            result = CF_INVALID;
            goto fail;
        }
        if (!cf_init_new_container(s, password, password_length, capacity)) {
            result = s->last_error ? CF_IO_ERROR : CF_DATA_ERROR;
            goto fail;
        }
        if (options->background_compaction) {
            result = cf_start_worker(s);
            if (result != CF_OK)
                goto fail;
        }
        *out_store = s;
        return CF_OK;
    }
    if (!cf_file_sparse(s->file)) {
        result = CF_NOT_SUPPORTED;
        goto fail;
    }
    if (!GetFileSizeEx(s->file, &file_size)) {
        s->last_error = GetLastError();
        result = CF_IO_ERROR;
        goto fail;
    }
    if (file_size.QuadPart < (LONGLONG)CF_MIN_EOF ||
        (uint64_t)file_size.QuadPart > CF_MAX_EOF) {
        result = CF_DATA_ERROR;
        goto fail;
    }
    s->disk_eof = (uint64_t)file_size.QuadPart;
    if (!cf_file_read_at(s->file, CF_SB0_OFFSET, sb0, CF_PAGE_SIZE, &error) ||
        !cf_file_read_at(s->file, CF_SB1_OFFSET, sb1, CF_PAGE_SIZE, &error)) {
        s->last_error = error;
        result = CF_IO_ERROR;
        goto fail;
    }
    if (!cf_header_load(s, sb0, sb1, password, password_length, &result))
        goto fail;
    header_unwrapped = true;
    if (!cf_file_read_at(s->file, CF_MARK0_OFFSET, marker_bytes[0], CF_PAGE_SIZE, &error) ||
        !cf_file_read_at(s->file, CF_MARK1_OFFSET, marker_bytes[1], CF_PAGE_SIZE, &error)) {
        s->last_error = error;
        result = CF_IO_ERROR;
        goto fail;
    }
    memset(markers, 0, sizeof(markers));
    markers[0].valid = cf_marker_authenticate(s, 0, marker_bytes[0], &markers[0]);
    markers[1].valid = cf_marker_authenticate(s, 1, marker_bytes[1], &markers[1]);
    if (!markers[0].valid && !markers[1].valid) {
        result = CF_DATA_ERROR;
        goto fail;
    }
    if (markers[0].valid && markers[1].valid &&
        markers[0].generation == markers[1].generation) {
        if (!cf_marker_same_state(&markers[0], &markers[1])) {
            result = CF_DATA_ERROR;
            goto fail;
        }
        selected = &markers[0];
    } else if (!markers[1].valid || (markers[0].valid &&
        markers[0].generation > markers[1].generation)) {
        selected = &markers[0];
    } else {
        selected = &markers[1];
    }
    if (selected->state == CF_MARK_EMPTY && s->disk_eof != selected->final_eof) {
        result = CF_DATA_ERROR;
        goto fail;
    }
    s->eof = selected->final_eof;
    s->generation = selected->generation;
    if (selected->state == CF_MARK_COMMITTED) {
        result = CF_DATA_ERROR;
        if (!cf_wal_read(s, selected, &images, &image_count, &result))
            goto fail;
    }
    if (!cf_graph_validate(s, images, image_count, selected->final_eof, &graph_error)) {
        result = graph_error;
        goto fail;
    }
    if (selected->state == CF_MARK_COMMITTED) {
        if (!cf_recover_committed(s, selected, images, image_count)) {
            result = CF_IO_ERROR;
            goto fail;
        }
    }
    if (images) {
        cf_wipe(images, (size_t)image_count * sizeof(CF_IMAGE));
        free(images);
        images = NULL;
    }
    result = cf_reclaim_orphans(s);
    if (result != CF_OK)
        goto fail;
    if (options->background_compaction) {
        result = cf_start_worker(s);
        if (result != CF_OK)
            goto fail;
    }
    *out_store = s;
    cf_wipe(sb0, sizeof(sb0));
    cf_wipe(sb1, sizeof(sb1));
    cf_wipe(marker_bytes, sizeof(marker_bytes));
    cf_wipe(markers, sizeof(markers));
    return CF_OK;
fail:
    if (images) {
        cf_wipe(images, (size_t)image_count * sizeof(CF_IMAGE));
        free(images);
    }
    cf_wipe(sb0, sizeof(sb0));
    cf_wipe(sb1, sizeof(sb1));
    cf_wipe(marker_bytes, sizeof(marker_bytes));
    cf_wipe(markers, sizeof(markers));
    if (s) {
        if (created && s->file != INVALID_HANDLE_VALUE) {
            FILE_DISPOSITION_INFO disposition;
            disposition.DeleteFile = TRUE;
            if (!SetFileInformationByHandle(s->file, FileDispositionInfo,
                &disposition, sizeof(disposition)))
                s->last_error = GetLastError();
        }
        cf_store_dispose(s);
    }
    (void)header_unwrapped;
    return result;
}

static bool cf_store_check_node(CF_STORE *s, CF_NODE *node) {
    return s && node && node->store == s && !s->poisoned;
}

static size_t cf_path_length(const wchar_t *path) {
    size_t i;
    if (!path)
        return SIZE_MAX;
    for (i = 0; i <= 32767; ++i) {
        if (!path[i])
            return i;
    }
    return SIZE_MAX;
}

static bool cf_path_next(const wchar_t **cursor, wchar_t token[CF_NAME_MAX + 1],
    uint16_t *length, bool *trailing_separator) {
    const wchar_t *p = *cursor;
    const wchar_t *start;
    size_t n;
    bool had_separator = false;
    while (*p == L'\\' || *p == L'/') {
        had_separator = true;
        ++p;
    }
    if (!*p) {
        *cursor = p;
        *trailing_separator = had_separator;
        return false;
    }
    start = p;
    while (*p && *p != L'\\' && *p != L'/')
        ++p;
    n = (size_t)(p - start);
    if (n == 0 || n > CF_NAME_MAX)
        return false;
    memcpy(token, start, n * sizeof(wchar_t));
    token[n] = 0;
    *length = (uint16_t)n;
    had_separator = false;
    while (*p == L'\\' || *p == L'/') {
        had_separator = true;
        ++p;
    }
    *cursor = p;
    *trailing_separator = had_separator && !*p;
    return true;
}

static CF_RESULT cf_path_lookup(CF_STORE *s, const wchar_t *path, CF_NODE **out) {
    const wchar_t *cursor = path;
    wchar_t token[CF_NAME_MAX + 1];
    uint16_t length = 0;
    bool trailing = false;
    CF_NODE *current = s->root;
    size_t path_length = cf_path_length(path);
    if (path_length == SIZE_MAX || path_length > 32767)
        return CF_INVALID;
    while (cf_path_next(&cursor, token, &length, &trailing)) {
        bool more = *cursor != 0;
        if (length == 1 && token[0] == L'.')
            continue;
        if (length == 2 && token[0] == L'.' && token[1] == L'.') {
            if (current->parent)
                current = current->parent;
            continue;
        }
        if (!cf_valid_name_units(token, length))
            return CF_INVALID;
        if (!(current->attributes & FILE_ATTRIBUTE_DIRECTORY))
            return CF_NOT_DIRECTORY;
        current = cf_child_find(current, token, length);
        if (!current)
            return more ? CF_PATH_NOT_FOUND : CF_NOT_FOUND;
        if (more && !(current->attributes & FILE_ATTRIBUTE_DIRECTORY))
            return CF_NOT_DIRECTORY;
    }
    if (*cursor)
        return CF_INVALID;
    if (trailing && !(current->attributes & FILE_ATTRIBUTE_DIRECTORY))
        return CF_NOT_DIRECTORY;
    *out = current;
    return CF_OK;
}

static CF_RESULT cf_path_parent(CF_STORE *s, const wchar_t *path,
    CF_NODE **out_parent, wchar_t name[CF_NAME_MAX + 1], uint16_t *name_length) {
    const wchar_t *cursor = path;
    wchar_t token[CF_NAME_MAX + 1], pending[CF_NAME_MAX + 1];
    uint16_t length = 0, pending_length = 0;
    bool trailing = false, pending_trailing = false;
    CF_NODE *current = s->root;
    size_t path_length = cf_path_length(path);
    bool have_pending = false;
    if (path_length == SIZE_MAX || path_length == 0 || path_length > 32767)
        return CF_INVALID;
    while (cf_path_next(&cursor, token, &length, &trailing)) {
        if (have_pending) {
            if (pending_length == 1 && pending[0] == L'.') {
                /* Current remains unchanged. */
            } else if (pending_length == 2 && pending[0] == L'.' && pending[1] == L'.') {
                if (current->parent)
                    current = current->parent;
            } else {
                if (!cf_valid_name_units(pending, pending_length))
                    return CF_INVALID;
                if (!(current->attributes & FILE_ATTRIBUTE_DIRECTORY))
                    return CF_NOT_DIRECTORY;
                current = cf_child_find(current, pending, pending_length);
                if (!current)
                    return CF_PATH_NOT_FOUND;
                if (!(current->attributes & FILE_ATTRIBUTE_DIRECTORY))
                    return CF_NOT_DIRECTORY;
            }
        }
        memcpy(pending, token, ((size_t)length + 1) * sizeof(wchar_t));
        pending_length = length;
        pending_trailing = trailing;
        have_pending = true;
    }
    if (*cursor || !have_pending || pending_trailing ||
        (pending_length == 1 && pending[0] == L'.') ||
        (pending_length == 2 && pending[0] == L'.' && pending[1] == L'.') ||
        !cf_valid_name_units(pending, pending_length))
        return CF_INVALID;
    if (!(current->attributes & FILE_ATTRIBUTE_DIRECTORY))
        return CF_NOT_DIRECTORY;
    memcpy(name, pending, ((size_t)pending_length + 1) * sizeof(wchar_t));
    *name_length = pending_length;
    *out_parent = current;
    return CF_OK;
}

static bool cf_punch_hole_locked(CF_STORE *s, uint64_t slot) {
    FILE_ZERO_DATA_INFORMATION range;
    uint64_t offset;
    DWORD returned = 0;
    if (slot == 0 || slot > CF_MAX_SLOTS ||
        (slot < s->slot_capacity && s->slots[slot]) ||
        !cf_slot_offset(slot, &offset))
        return false;
#ifdef CRYPTFS_TESTING
    DWORD injected_error = ERROR_SUCCESS;
    if (cf_test_fail_host_io_now(CF_TEST_IO_PUNCH, &injected_error)) {
        cf_set_error(s, injected_error);
        return false;
    }
#endif
    range.FileOffset.QuadPart = (LONGLONG)offset;
    range.BeyondFinalZero.QuadPart = (LONGLONG)(offset + CF_PAGE_SIZE);
    if (!DeviceIoControl(s->file, FSCTL_SET_ZERO_DATA, &range, sizeof(range),
        NULL, 0, &returned, NULL)) {
        cf_set_error(s, GetLastError());
        return false;
    }
    return true;
}

CF_RESULT cf_store_flush(CF_STORE *s) {
    CF_RESULT result;
    if (!s)
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    result = s->poisoned ? CF_IO_ERROR : (cf_flush_file(s) ? CF_OK : CF_IO_ERROR);
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

CF_RESULT cf_store_stats(CF_STORE *s, CF_STATS *stats) {
    FILE_STANDARD_INFO standard;
    ULARGE_INTEGER free_bytes;
    uint64_t free_pages, page_bound, logical_bound, host_bound = UINT64_MAX;
    wchar_t volume[MAX_PATH];
    CF_RESULT result = CF_OK;
    if (!s || !stats)
        return CF_INVALID;
    memset(stats, 0, sizeof(*stats));
    AcquireSRWLockExclusive(&s->lock);
    stats->capacity = s->capacity;
    stats->logical_used = s->logical_used;
    stats->live_pages = s->live_page_count + 1;
    stats->eof_bytes = s->eof;
    stats->commits = s->commits;
    stats->compact_moves = s->compact_moves;
    stats->last_host_error = s->last_error;
    stats->poisoned = s->poisoned;
    if (s->poisoned) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (!GetFileInformationByHandleEx(s->file, FileStandardInfo,
        &standard, sizeof(standard))) {
        s->last_error = GetLastError();
        result = CF_IO_ERROR;
        goto done;
    }
    stats->allocated_bytes = standard.AllocationSize.QuadPart < 0 ? 0 :
        (uint64_t)standard.AllocationSize.QuadPart;
    logical_bound = s->capacity - s->logical_used;
    free_pages = s->live_page_count >= CF_MAX_SLOTS ? 0 : CF_MAX_SLOTS - s->live_page_count;
    page_bound = free_pages / CF_MAX_FRAGMENTS * CF_BLOCK_SIZE;
    if (GetVolumePathNameW(s->path, volume, ARRAYSIZE(volume)) &&
        GetDiskFreeSpaceExW(volume, &free_bytes, NULL, NULL))
        host_bound = free_bytes.QuadPart;
    stats->free_bytes = logical_bound;
    if (page_bound < stats->free_bytes)
        stats->free_bytes = page_bound;
    if (host_bound < stats->free_bytes)
        stats->free_bytes = host_bound;
done:
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

DWORD cf_store_host_error(CF_STORE *s) {
    DWORD error;
    if (!s)
        return ERROR_INVALID_PARAMETER;
    AcquireSRWLockShared(&s->lock);
    error = s->last_error;
    ReleaseSRWLockShared(&s->lock);
    return error;
}

const char *cf_result_text(CF_RESULT result) {
    static const char *const text[] = {
        "success", "not found", "path not found", "already exists",
        "not a directory", "is a directory", "directory not empty",
        "no space", "out of memory", "invalid argument", "access denied",
        "data integrity error", "I/O error", "not supported"
    };
    return (unsigned)result < ARRAYSIZE(text) ? text[result] : "unknown error";
}

CF_RESULT cf_node_open(CF_STORE *s, const wchar_t *path, CF_NODE **out_node) {
    CF_NODE *node = NULL;
    CF_RESULT result;
    if (out_node)
        *out_node = NULL;
    if (!s || !path || !out_node)
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (s->poisoned) {
        result = CF_IO_ERROR;
    } else {
        result = cf_path_lookup(s, path, &node);
        if (result == CF_OK) {
            if (node->references == UINT32_MAX)
                result = CF_NO_SPACE;
            else {
                ++node->references;
                *out_node = node;
            }
        }
    }
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

static uint32_t cf_supported_attributes(uint32_t attributes) {
    const uint32_t supported = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
        FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE |
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_OFFLINE |
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_NORMAL;
    return attributes & ~supported;
}

CF_RESULT cf_node_create(CF_STORE *s, const wchar_t *path,
    uint32_t attributes, CF_NODE **out_node) {
    CF_NODE *parent = NULL, *node = NULL;
    CF_PAGE *page = NULL;
    CF_NODE *old_first;
    CF_TX tx;
    CF_RESULT result;
    wchar_t name[CF_NAME_MAX + 1];
    uint16_t name_length = 0;
    bool tx_started = false, index_added = false, array_added = false;
    bool id_incremented = false, committed_successfully = false;
    if (out_node)
        *out_node = NULL;
    if (!s || !path || !out_node || cf_supported_attributes(attributes) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (s->poisoned) {
        result = CF_IO_ERROR;
        goto done;
    }
    result = cf_path_parent(s, path, &parent, name, &name_length);
    if (result != CF_OK)
        goto done;
    if (cf_child_find(parent, name, name_length)) {
        result = CF_EXISTS;
        goto done;
    }
    if (s->node_count >= CF_MAX_NODES || s->next_inode_id == 0 ||
        s->next_inode_id == UINT64_MAX || parent->depth >= CF_MAX_DEPTH) {
        result = CF_NO_SPACE;
        goto done;
    }
    if (!cf_child_index_reserve(parent, parent->child_count + 1)) {
        result = CF_NO_MEMORY;
        goto done;
    }
    node = (CF_NODE *)calloc(1, sizeof(*node));
    if (!node) {
        result = CF_NO_MEMORY;
        goto done;
    }
    node->store = s;
    node->id = s->next_inode_id;
    node->parent_id = parent->id;
    node->attributes = attributes ? attributes : FILE_ATTRIBUTE_NORMAL;
    if ((node->attributes & ~FILE_ATTRIBUTE_NORMAL) != 0)
        node->attributes &= ~FILE_ATTRIBUTE_NORMAL;
    node->name_length = name_length;
    node->depth = (uint16_t)(parent->depth + 1);
    node->references = 1;
    node->creation_time = node->access_time = node->write_time =
        node->change_time = cf_now_filetime();
    memcpy(node->name, name, ((size_t)name_length + 1) * sizeof(wchar_t));
    if (node->attributes & FILE_ATTRIBUTE_DIRECTORY)
        node->attributes &= ~FILE_ATTRIBUTE_NORMAL;
    if (!cf_tx_begin(s, &tx)) {
        result = CF_NO_MEMORY;
        goto done;
    }
    tx_started = true;
    page = cf_tx_new_page(&tx, CF_RECORD_INODE, node->id);
    if (!page) {
        result = CF_NO_SPACE;
        goto done;
    }
    node->page = page;
    page->inode = node;
    old_first = parent->first_child;
    node->next_sibling = old_first;
    parent->first_child = node;
    ++s->next_inode_id;
    id_incremented = true;
    if (!cf_node_array_add(s, node)) {
        parent->first_child = old_first;
        node->next_sibling = NULL;
        result = CF_NO_MEMORY;
        goto done;
    }
    array_added = true;
    if (!cf_child_index_insert(parent, node)) {
        cf_node_array_remove(s, node);
        array_added = false;
        parent->first_child = old_first;
        node->next_sibling = NULL;
        result = CF_NO_MEMORY;
        goto done;
    }
    index_added = true;
    if (!cf_tx_add_node(&tx, node) || !cf_tx_add_node(&tx, parent) ||
        !cf_tx_add_node(&tx, s->root) ||
        !cf_tx_commit(&tx)) {
        result = cf_tx_failure_result(&tx, CF_NO_MEMORY);
        goto done;
    }
    committed_successfully = true;
    if (!cf_page_register(s, page)) {
        s->poisoned = true;
        result = CF_IO_ERROR;
        goto done;
    }
    if (old_first)
        cf_page_set_owner(old_first->page, page, CF_INODE_NEXT_SIBLING);
    cf_page_set_owner(page, parent->page, CF_INODE_FIRST_CHILD);
    page = NULL;
    *out_node = node;
    node = NULL;
    result = CF_OK;
done:
    if (result != CF_OK && !committed_successfully) {
        if (node && index_added) {
            cf_child_index_remove(parent, node);
            index_added = false;
        }
        if (node && array_added)
            cf_node_array_remove(s, node);
        if (node && parent && parent->first_child == node)
            parent->first_child = node->next_sibling;
        if (id_incremented)
            --s->next_inode_id;
        if (page && !page->registered) {
            if (node)
                node->page = NULL;
            cf_wipe(page, sizeof(*page));
            free(page);
        }
        if (node)
            cf_node_free_contents(node, false);
    }
    if (tx_started)
        cf_tx_dispose(&tx);
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

void cf_node_close(CF_STORE *s, CF_NODE *node) {
    if (!s || !node || node->store != s)
        return;
    AcquireSRWLockExclusive(&s->lock);
    if (node->references)
        --node->references;
    if (!s->poisoned && node->unlinked && node->references == 0) {
        CF_RESULT reclaim_result = cf_reclaim_orphans(s);
        if (reclaim_result != CF_OK)
            cf_record_reclaim_failure(s, reclaim_result);
    }
    ReleaseSRWLockExclusive(&s->lock);
}

CF_RESULT cf_node_info(CF_STORE *s, CF_NODE *node, CF_INFO *info) {
    CF_RESULT result = CF_OK;
    if (!s || !node || !info)
        return CF_INVALID;
    AcquireSRWLockShared(&s->lock);
    if (!cf_store_check_node(s, node))
        result = CF_IO_ERROR;
    else
        cf_node_fill_info(node, info);
    ReleaseSRWLockShared(&s->lock);
    return result;
}

CF_RESULT cf_node_set_basic(CF_STORE *s, CF_NODE *node, uint32_t attributes,
    uint64_t creation_time, uint64_t access_time, uint64_t write_time,
    uint64_t change_time) {
    CF_NODE old;
    CF_TX tx;
    bool tx_started = false;
    CF_RESULT result = CF_OK;
    if (!s || !node || cf_supported_attributes(attributes) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(node->attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        result = CF_INVALID;
        goto done;
    }
    old = *node;
    node->attributes = (attributes ? attributes : FILE_ATTRIBUTE_NORMAL) |
        (old.attributes & FILE_ATTRIBUTE_DIRECTORY);
    if ((node->attributes & ~FILE_ATTRIBUTE_NORMAL) != 0)
        node->attributes &= ~FILE_ATTRIBUTE_NORMAL;
    if (creation_time) node->creation_time = creation_time;
    if (access_time) node->access_time = access_time;
    if (write_time) node->write_time = write_time;
    if (change_time) node->change_time = change_time;
    if (!cf_tx_begin(s, &tx)) {
        *node = old;
        result = CF_NO_MEMORY;
        goto done;
    }
    tx_started = true;
    if (!cf_tx_add_node(&tx, node) || !cf_tx_commit(&tx)) {
        *node = old;
        result = cf_tx_failure_result(&tx, CF_NO_MEMORY);
    }
done:
    if (tx_started)
        cf_tx_dispose(&tx);
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

static CF_BLOCK *cf_node_find_block(CF_NODE *node, uint64_t index,
    CF_MAP_PAGE **map_out, uint32_t *position_out) {
    CF_MAP_PAGE *map;
    for (map = node->maps; map; map = map->next) {
        uint32_t lo = 0, hi = map->count;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (map->blocks[mid]->index < index)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo < map->count && map->blocks[lo]->index == index) {
            if (map_out) *map_out = map;
            if (position_out) *position_out = lo;
            return map->blocks[lo];
        }
    }
    if (map_out) *map_out = NULL;
    if (position_out) *position_out = 0;
    return NULL;
}

static CF_RESULT cf_node_decode_block(CF_STORE *s, CF_NODE *node,
    CF_BLOCK *block, uint8_t decoded[CF_BLOCK_SIZE]) {
    uint8_t encoded[CF_BLOCK_SIZE];
    uint32_t copied = 0, i;
    CF_RESULT result = CF_DATA_ERROR;
    memset(encoded, 0, sizeof(encoded));
    memset(decoded, 0, CF_BLOCK_SIZE);
    if (!block || block->encoded_length == 0 || block->encoded_length > CF_BLOCK_SIZE ||
        block->fragment_count == 0 || block->fragment_count > CF_MAX_FRAGMENTS ||
        block->fragment_count != (block->encoded_length + CF_FRAGMENT_CAPACITY - 1u) /
            CF_FRAGMENT_CAPACITY)
        goto done;
    for (i = 0; i < block->fragment_count; ++i) {
        CF_PAGE *page = block->fragments[i];
        uint8_t disk[CF_PAGE_SIZE];
        uint8_t payload[CF_PAYLOAD_SIZE];
        uint64_t record_id = 0;
        uint32_t remaining = block->encoded_length - copied;
        uint32_t used = remaining > CF_FRAGMENT_CAPACITY ? CF_FRAGMENT_CAPACITY : remaining;
        DWORD error = 0;
        bool valid;
        if (!page || page->slot == CF_ROOT_SLOT || page->slot == 0 ||
            !cf_slot_offset(page->slot, &(uint64_t){0}))
            goto done;
        if (!cf_seek_read(s->file, (page->slot - 1) * CF_PAGE_SIZE + CF_PAGES_OFFSET,
            disk, CF_PAGE_SIZE, &error)) {
            cf_set_error(s, error);
            result = CF_IO_ERROR;
            cf_wipe(disk, sizeof(disk));
            cf_wipe(payload, sizeof(payload));
            goto done;
        }
        valid = cf_page_decrypt(s, page->slot, disk, CF_RECORD_FRAGMENT,
            node->id, payload, &record_id) && record_id == node->id &&
            cf_get_u64(payload + CF_FRAGMENT_FILE_ID) == node->id &&
            cf_get_u64(payload + CF_FRAGMENT_BLOCK) == block->index &&
            cf_get_u32(payload + CF_FRAGMENT_SEQUENCE) == i &&
            cf_get_u32(payload + CF_FRAGMENT_LENGTH) == used &&
            cf_all_zero(payload + CF_FRAGMENT_DATA + used,
                CF_PAYLOAD_SIZE - CF_FRAGMENT_DATA - used);
        if (valid) {
            uint64_t expected_next = i + 1 < block->fragment_count ?
                block->fragments[i + 1]->slot : 0;
            valid = cf_get_u64(payload + CF_FRAGMENT_NEXT) == expected_next;
        }
        if (!valid) {
            cf_wipe(disk, sizeof(disk));
            cf_wipe(payload, sizeof(payload));
            goto done;
        }
        memcpy(encoded + copied, payload + CF_FRAGMENT_DATA, used);
        copied += used;
        cf_wipe(disk, sizeof(disk));
        cf_wipe(payload, sizeof(payload));
    }
    if (copied != block->encoded_length ||
        !cf_block_decode(encoded, block->encoded_length, block->codec, decoded))
        goto done;
    result = CF_OK;
done:
    if (result != CF_OK)
        cf_wipe(decoded, CF_BLOCK_SIZE);
    cf_wipe(encoded, sizeof(encoded));
    return result;
}

static bool cf_map_insert_block(CF_NODE *node, CF_BLOCK *block,
    CF_MAP_PAGE **target_out, CF_MAP_PAGE **new_map_out,
    CF_MAP_PAGE **previous_out, uint32_t *position_out,
    CF_BLOCK *old_blocks[CF_MAP_CAPACITY + 1], uint32_t *old_count_out,
    CF_MAP_PAGE **old_next_out, CF_MAP_PAGE **old_head_out,
    CF_MAP_PAGE **old_tail_out, bool *split_out) {
    CF_MAP_PAGE *map = node->maps, *previous = NULL, *target = NULL;
    CF_MAP_PAGE *new_map = NULL;
    CF_BLOCK *merged[CF_MAP_CAPACITY + 1];
    uint32_t pos = 0, i, merged_count;
    bool split = false;
    while (map) {
        if (map->count == 0 || map->count > CF_MAP_CAPACITY)
            return false;
        if (block->index <= map->blocks[map->count - 1]->index) {
            target = map;
            break;
        }
        previous = map;
        map = map->next;
    }
    *old_head_out = node->maps;
    *old_tail_out = node->maps_tail;
    *new_map_out = NULL;
    *previous_out = previous;
    if (!target) {
        if (previous && previous->count < CF_MAP_CAPACITY) {
            target = previous;
            pos = target->count;
        } else {
            new_map = (CF_MAP_PAGE *)calloc(1, sizeof(*new_map));
            if (!new_map)
                return false;
            new_map->page = NULL;
            new_map->count = 1;
            new_map->blocks[0] = block;
            new_map->next = NULL;
            *target_out = NULL;
            *new_map_out = new_map;
            *position_out = 0;
            *old_count_out = 0;
            *old_next_out = NULL;
            *split_out = false;
            return true;
        }
    } else {
        uint32_t lo = 0, hi = target->count;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2;
            if (target->blocks[mid]->index < block->index)
                lo = mid + 1;
            else
                hi = mid;
        }
        pos = lo;
        for (i = 0; i < target->count; ++i) {
            if (target->blocks[i]->index == block->index)
                return false;
        }
    }
    *target_out = target;
    *position_out = pos;
    *old_count_out = target->count;
    *old_next_out = target->next;
    for (i = 0; i < target->count; ++i)
        old_blocks[i] = target->blocks[i];
    memcpy(merged, old_blocks, target->count * sizeof(CF_BLOCK *));
    merged_count = target->count + 1;
    memmove(merged + pos + 1, merged + pos,
        (target->count - pos) * sizeof(CF_BLOCK *));
    merged[pos] = block;
    if (merged_count > CF_MAP_CAPACITY) {
        new_map = (CF_MAP_PAGE *)calloc(1, sizeof(*new_map));
        if (!new_map)
            return false;
        split = true;
        new_map->count = merged_count - (merged_count / 2);
        target->count = merged_count / 2;
        for (i = 0; i < target->count; ++i)
            target->blocks[i] = merged[i];
        for (i = 0; i < new_map->count; ++i)
            new_map->blocks[i] = merged[target->count + i];
        new_map->next = target->next;
        target->next = new_map;
        if (node->maps_tail == target)
            node->maps_tail = new_map;
    } else {
        target->count = merged_count;
        for (i = 0; i < merged_count; ++i)
            target->blocks[i] = merged[i];
    }
    *new_map_out = new_map;
    *split_out = split;
    return true;
}

static void cf_map_rollback_insert(CF_NODE *node, CF_MAP_PAGE *target,
    CF_MAP_PAGE *new_map, CF_MAP_PAGE *previous, uint32_t position,
    CF_BLOCK *old_blocks[CF_MAP_CAPACITY + 1], uint32_t old_count,
    CF_MAP_PAGE *old_next, CF_MAP_PAGE *old_head, CF_MAP_PAGE *old_tail,
    bool split) {
    if (!target || (target == new_map && !split && old_count == 0)) {
        if (previous)
            previous->next = old_next;
        else
            node->maps = old_head;
        node->maps_tail = old_tail;
        return;
    }
    target->count = old_count;
    target->next = old_next;
    memcpy(target->blocks, old_blocks, old_count * sizeof(CF_BLOCK *));
    node->maps = old_head;
    node->maps_tail = old_tail;
    (void)position;
}

/*
 * A write stages many blocks into one transaction. Each stage records exactly
 * what it changed in RAM so a failed batch is undone newest-first, and so the
 * committed pages can be registered once the single commit is durable.
 */
typedef struct CF_BLOCK_STAGE {
    CF_BLOCK *new_block;
    CF_BLOCK *old_block;
    CF_MAP_PAGE *target;
    CF_MAP_PAGE *new_map;
    CF_MAP_PAGE *previous;
    CF_MAP_PAGE *old_head;
    CF_MAP_PAGE *old_tail;
    CF_MAP_PAGE *old_next;
    CF_PAGE *map_page;
    uint32_t old_count;
    uint32_t pos;
    bool split;
    bool map_mutated;
    CF_BLOCK *old_blocks[CF_MAP_CAPACITY + 1];
} CF_BLOCK_STAGE;

/* Undoes one stage's RAM changes and frees everything it allocated. */
static void cf_block_unstage(CF_NODE *node, CF_BLOCK_STAGE *st) {
    uint32_t i;
    if (st->map_mutated) {
        if (st->old_block) {
            if (st->target) {
                memcpy(st->target->blocks, st->old_blocks, st->old_count * sizeof(CF_BLOCK *));
                st->target->count = st->old_count;
                st->target->next = st->old_next;
            }
            node->maps = st->old_head;
            node->maps_tail = st->old_tail;
        } else if (st->target || st->new_map) {
            cf_map_rollback_insert(node, st->target, st->new_map, st->previous, st->pos,
                st->old_blocks, st->old_count, st->old_next, st->old_head, st->old_tail,
                st->split);
        }
    }
    if (st->new_map && (st->new_map != st->target || st->old_count == 0)) {
        CF_PAGE *new_map_page = st->new_map->page;
        if (new_map_page && !new_map_page->registered) {
            if (st->map_page == new_map_page)
                st->map_page = NULL;
            cf_wipe(new_map_page, sizeof(*new_map_page));
            free(new_map_page);
        }
        cf_wipe(st->new_map, sizeof(*st->new_map));
        free(st->new_map);
    }
    if (st->map_page && !st->map_page->registered) {
        cf_wipe(st->map_page, sizeof(*st->map_page));
        free(st->map_page);
    }
    if (st->new_block) {
        for (i = 0; i < st->new_block->fragment_count; ++i) {
            CF_PAGE *page = st->new_block->fragments[i];
            if (page && !page->registered) {
                cf_wipe(page, sizeof(*page));
                free(page);
            }
        }
        cf_wipe(st->new_block, sizeof(*st->new_block));
        free(st->new_block);
    }
    memset(st, 0, sizeof(*st));
}

/* Stages one encoded block into tx; on failure this block's changes are undone. */
static CF_RESULT cf_block_stage(CF_STORE *s, CF_NODE *node, CF_TX *tx,
    uint64_t block_index, const uint8_t raw[CF_BLOCK_SIZE],
    uint8_t encoded[CF_BLOCK_SIZE], CF_BLOCK_STAGE *st) {
    uint32_t encoded_length = 0, codec = 0, i;
    bool appended_map_after_previous = false;
    CF_RESULT result = CF_NO_MEMORY;
    memset(st, 0, sizeof(*st));
    if (!cf_block_encode(raw, s->compression_level, encoded, &encoded_length, &codec))
        return CF_DATA_ERROR;
    st->new_block = (CF_BLOCK *)calloc(1, sizeof(*st->new_block));
    if (!st->new_block)
        goto fail;
    st->new_block->index = block_index;
    st->new_block->encoded_length = encoded_length;
    st->new_block->codec = codec;
    st->new_block->fragment_count = (encoded_length + CF_FRAGMENT_CAPACITY - 1u) /
        CF_FRAGMENT_CAPACITY;
    if (st->new_block->fragment_count == 0 || st->new_block->fragment_count > CF_MAX_FRAGMENTS) {
        result = CF_DATA_ERROR;
        goto fail;
    }
    for (i = 0; i < st->new_block->fragment_count; ++i) {
        st->new_block->fragments[i] = cf_tx_new_page(tx, CF_RECORD_FRAGMENT, node->id);
        if (!st->new_block->fragments[i]) {
            result = CF_NO_SPACE;
            goto fail;
        }
    }
    st->old_block = cf_node_find_block(node, block_index, &st->target, &st->pos);
    if (st->old_block) {
        st->old_head = node->maps;
        st->old_tail = node->maps_tail;
        st->old_count = st->target->count;
        st->old_next = st->target->next;
        memcpy(st->old_blocks, st->target->blocks, st->old_count * sizeof(CF_BLOCK *));
        st->target->blocks[st->pos] = st->new_block;
        st->map_mutated = true;
    } else {
        if (!cf_map_insert_block(node, st->new_block, &st->target, &st->new_map,
            &st->previous, &st->pos, st->old_blocks, &st->old_count, &st->old_next,
            &st->old_head, &st->old_tail, &st->split)) {
            result = CF_NO_MEMORY;
            goto fail;
        }
        st->map_mutated = true;
        if (!st->target) {
            st->map_page = cf_tx_new_page(tx, CF_RECORD_MAP, node->id);
            if (!st->map_page) {
                result = CF_NO_SPACE;
                goto fail;
            }
            st->new_map->page = st->map_page;
            st->map_page->map = st->new_map;
            if (st->previous) {
                st->new_map->next = st->previous->next;
                st->previous->next = st->new_map;
                appended_map_after_previous = true;
                if (node->maps_tail == st->previous)
                    node->maps_tail = st->new_map;
            } else {
                st->new_map->next = node->maps;
                node->maps = st->new_map;
                if (!node->maps_tail)
                    node->maps_tail = st->new_map;
            }
            st->target = st->new_map;
            st->pos = 0;
        } else if (st->split) {
            st->map_page = cf_tx_new_page(tx, CF_RECORD_MAP, node->id);
            if (!st->map_page) {
                result = CF_NO_SPACE;
                goto fail;
            }
            st->new_map->page = st->map_page;
            st->map_page->map = st->new_map;
        }
    }
    st->target->owners_dirty = true;
    if (st->new_map)
        st->new_map->owners_dirty = true;
    for (i = 0; i < st->new_block->fragment_count; ++i) {
        if (!cf_tx_add_fragment(tx, node, st->new_block, i, encoded)) {
            result = CF_NO_MEMORY;
            goto fail;
        }
    }
    if (!cf_tx_add_map(tx, node, st->target) ||
        (appended_map_after_previous && !cf_tx_add_map(tx, node, st->previous)) ||
        (st->new_map && st->new_map != st->target && !cf_tx_add_map(tx, node, st->new_map))) {
        result = s->poisoned ? CF_IO_ERROR : CF_NO_MEMORY;
        goto fail;
    }
    return CF_OK;
fail:
    cf_block_unstage(node, st);
    return result;
}

/* After a durable commit: publish new pages and retire the replaced block. */
static bool cf_block_finish(CF_STORE *s, CF_BLOCK_STAGE *st) {
    bool ok = true;
    uint32_t i;
    for (i = 0; i < st->new_block->fragment_count; ++i)
        ok = cf_page_register(s, st->new_block->fragments[i]) && ok;
    if (st->map_page)
        ok = cf_page_register(s, st->map_page) && ok;
    if (st->old_block) {
        if (st->old_block->fragment_count)
            cf_page_unregister_tree(s, st->old_block->fragments[0]);
        cf_wipe(st->old_block, sizeof(*st->old_block));
        free(st->old_block);
    }
    memset(st, 0, sizeof(*st));
    return ok;
}

/* Re-derives physical ownership for map links and every map whose entries moved. */
static void cf_node_refresh_map_owners(CF_NODE *node) {
    CF_MAP_PAGE *map, *previous = NULL;
    for (map = node->maps; map; previous = map, map = map->next) {
        uint32_t i, j;
        cf_page_set_owner(map->page, previous ? previous->page : node->page,
            previous ? CF_MAP_NEXT : CF_INODE_MAP_HEAD);
        if (!map->owners_dirty)
            continue;
        for (i = 0; i < map->count; ++i) {
            CF_BLOCK *block = map->blocks[i];
            cf_page_set_owner(block->fragments[0], map->page,
                (uint32_t)(CF_MAP_ENTRIES + (size_t)i * CF_MAP_ENTRY_SIZE + CF_MAP_ENTRY_FRAGMENT));
            for (j = 1; j < block->fragment_count; ++j)
                cf_page_set_owner(block->fragments[j], block->fragments[j - 1], CF_FRAGMENT_NEXT);
        }
        map->owners_dirty = false;
    }
}

/* Worst-case pages one staged block adds: fragments, two maps, the inode. */
#define CF_STAGE_PAGE_BUDGET (CF_MAX_FRAGMENTS + 3u)
#define CF_WRITE_BATCH_BLOCKS 128u

typedef struct CF_WRITE_BATCH {
    CF_TX tx;
    bool open;
    uint32_t staged;
    uint32_t pending_bytes;
    uint64_t size, logical_used, write_time, change_time;
    CF_BLOCK_STAGE *stages;
} CF_WRITE_BATCH;

static void cf_write_batch_abort(CF_STORE *s, CF_NODE *node, CF_WRITE_BATCH *b) {
    while (b->staged)
        cf_block_unstage(node, &b->stages[--b->staged]);
    node->size = b->size;
    node->write_time = b->write_time;
    node->change_time = b->change_time;
    s->logical_used = b->logical_used;
    cf_tx_dispose(&b->tx);
    b->open = false;
    b->pending_bytes = 0;
}

static CF_RESULT cf_write_batch_begin(CF_STORE *s, CF_NODE *node, CF_WRITE_BATCH *b) {
    if (!cf_tx_begin(s, &b->tx))
        return CF_NO_MEMORY;
    b->open = true;
    b->staged = 0;
    b->pending_bytes = 0;
    b->size = node->size;
    b->logical_used = s->logical_used;
    b->write_time = node->write_time;
    b->change_time = node->change_time;
    return CF_OK;
}

/* Commits every staged block with one WAL transaction. */
static CF_RESULT cf_write_batch_commit(CF_STORE *s, CF_NODE *node, CF_WRITE_BATCH *b) {
    CF_RESULT result = CF_OK;
    uint32_t i;
    bool ok = true;
    if (!b->open)
        return CF_OK;
    if (b->staged == 0) {
        cf_tx_dispose(&b->tx);
        b->open = false;
        return CF_OK;
    }
    if (!cf_tx_add_node(&b->tx, node) || !cf_tx_commit(&b->tx)) {
        result = cf_tx_failure_result(&b->tx, CF_NO_MEMORY);
        cf_write_batch_abort(s, node, b);
        return result;
    }
    for (i = 0; i < b->staged; ++i)
        ok = cf_block_finish(s, &b->stages[i]) && ok;
    cf_node_refresh_map_owners(node);
    if (!ok) {
        s->poisoned = true;
        result = CF_IO_ERROR;
    }
    b->staged = 0;
    b->pending_bytes = 0;
    cf_tx_dispose(&b->tx);
    b->open = false;
    return result;
}

CF_RESULT cf_node_read(CF_STORE *s, CF_NODE *node, void *buffer,
    uint64_t offset, uint32_t length, uint32_t *transferred) {
    uint8_t block_bytes[CF_BLOCK_SIZE];
    uint64_t end, current;
    uint32_t done = 0;
    CF_RESULT result = CF_OK;
    if (transferred)
        *transferred = 0;
    if (!s || !node || !transferred || (!buffer && length) ||
        offset > UINT64_MAX - length)
        return CF_INVALID;
    AcquireSRWLockShared(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_DIRECTORY) {
        result = CF_IS_DIRECTORY;
        goto done;
    }
    if (offset >= node->size || length == 0)
        goto done;
    end = offset + length;
    if (end > node->size)
        end = node->size;
    current = offset;
    while (current < end) {
        uint64_t index = current / CF_BLOCK_SIZE;
        uint32_t in_block = (uint32_t)(current % CF_BLOCK_SIZE);
        uint32_t take = (uint32_t)(end - current);
        CF_BLOCK *block;
        CF_RESULT block_result;
        if (take > CF_BLOCK_SIZE - in_block)
            take = CF_BLOCK_SIZE - in_block;
        block = cf_node_find_block(node, index, NULL, NULL);
        if (!block) {
            memset((uint8_t *)buffer + done, 0, take);
        } else {
            block_result = cf_node_decode_block(s, node, block, block_bytes);
            if (block_result != CF_OK) {
                result = block_result;
                break;
            }
            memcpy((uint8_t *)buffer + done, block_bytes + in_block, take);
            cf_wipe(block_bytes, sizeof(block_bytes));
        }
        current += take;
        done += take;
    }
    *transferred = done;
done:
    cf_wipe(block_bytes, sizeof(block_bytes));
    ReleaseSRWLockShared(&s->lock);
    return result;
}

CF_RESULT cf_node_write(CF_STORE *s, CF_NODE *node, const void *buffer,
    uint64_t offset, uint32_t length, bool append, bool constrained,
    uint32_t *transferred) {
    uint8_t *block_bytes = NULL, *encoded = NULL;
    uint64_t end, current;
    uint32_t done = 0;
    CF_RESULT result = CF_OK;
    CF_WRITE_BATCH batch;
    memset(&batch, 0, sizeof(batch));
    if (transferred)
        *transferred = 0;
    if (!s || !node || !transferred || (!buffer && length))
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_DIRECTORY) {
        result = CF_IS_DIRECTORY;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_READONLY) {
        result = CF_ACCESS;
        goto done;
    }
    if (append)
        offset = node->size;
    if (offset > UINT64_MAX - length) {
        result = CF_INVALID;
        goto done;
    }
    if (constrained) {
        if (offset >= node->size)
            goto done;
        if ((uint64_t)length > node->size - offset)
            length = (uint32_t)(node->size - offset);
    }
    if (offset >= s->capacity) {
        result = length ? CF_NO_SPACE : CF_OK;
        goto done;
    }
    if ((uint64_t)length > s->capacity - offset) {
        if (constrained) {
            result = CF_NO_SPACE;
            goto done;
        }
        length = (uint32_t)(s->capacity - offset);
    }
    if (length == 0)
        goto done;
    block_bytes = (uint8_t *)malloc(CF_BLOCK_SIZE);
    encoded = (uint8_t *)malloc(CF_BLOCK_SIZE);
    batch.stages = (CF_BLOCK_STAGE *)calloc(CF_WRITE_BATCH_BLOCKS, sizeof(*batch.stages));
    if (!block_bytes || !encoded || !batch.stages) {
        result = CF_NO_MEMORY;
        goto done;
    }
    end = offset + length;
    current = offset;
    while (current < end) {
        uint64_t block_index = current / CF_BLOCK_SIZE;
        uint32_t in_block = (uint32_t)(current % CF_BLOCK_SIZE);
        uint32_t take = (uint32_t)(end - current);
        uint64_t size_after;
        if (take > CF_BLOCK_SIZE - in_block)
            take = CF_BLOCK_SIZE - in_block;
        /* Close the transaction before it could overflow the journal. */
        if (batch.open && (batch.staged == CF_WRITE_BATCH_BLOCKS ||
            batch.tx.count + CF_STAGE_PAGE_BUDGET > CF_MAX_TRANSACTION_PAGES)) {
            uint32_t pending = batch.pending_bytes;
            result = cf_write_batch_commit(s, node, &batch);
            if (result != CF_OK)
                break;
            done += pending;
        }
        if (!batch.open) {
            result = cf_write_batch_begin(s, node, &batch);
            if (result != CF_OK)
                break;
        }
        if (in_block == 0 && take == CF_BLOCK_SIZE) {
            /* A whole-block overwrite never needs the old contents. */
            memcpy(block_bytes, (const uint8_t *)buffer + done + batch.pending_bytes, take);
        } else {
            CF_BLOCK *existing = cf_node_find_block(node, block_index, NULL, NULL);
            if (existing) {
                result = cf_node_decode_block(s, node, existing, block_bytes);
                if (result != CF_OK)
                    break;
            } else {
                memset(block_bytes, 0, CF_BLOCK_SIZE);
            }
            memcpy(block_bytes + in_block, (const uint8_t *)buffer + done + batch.pending_bytes,
                take);
        }
        size_after = current + take;
        if (size_after < node->size)
            size_after = node->size;
        if (size_after > s->capacity ||
            size_after - node->size > s->capacity - s->logical_used) {
            result = CF_NO_SPACE;
            break;
        }
        result = cf_block_stage(s, node, &batch.tx, block_index, block_bytes, encoded,
            &batch.stages[batch.staged]);
        cf_wipe(block_bytes, CF_BLOCK_SIZE);
        if (result != CF_OK)
            break;
        ++batch.staged;
        s->logical_used += size_after - node->size;
        node->size = size_after;
        /* Paging (constrained) writes come from the lazy writer after the
         * handle's Cleanup already stamped or explicitly set the times. */
        if (!constrained)
            node->write_time = node->change_time = cf_now_filetime();
        batch.pending_bytes += take;
        current += take;
    }
    if (result == CF_OK) {
        uint32_t pending = batch.pending_bytes;
        result = cf_write_batch_commit(s, node, &batch);
        if (result == CF_OK)
            done += pending;
    } else if (batch.open) {
        cf_write_batch_abort(s, node, &batch);
    }
    /* Bytes of every committed transaction are reported even on failure. */
    *transferred = done;
done:
    if (batch.open)
        cf_write_batch_abort(s, node, &batch);
    free(batch.stages);
    if (block_bytes) {
        cf_wipe(block_bytes, CF_BLOCK_SIZE);
        free(block_bytes);
    }
    if (encoded) {
        cf_wipe(encoded, CF_BLOCK_SIZE);
        free(encoded);
    }
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

static void cf_map_chain_free(CF_MAP_PAGE *map, bool pages_already_freed) {
    while (map) {
        CF_MAP_PAGE *next_map = map->next;
        uint32_t i;
        for (i = 0; i < map->count; ++i) {
            CF_BLOCK *block = map->blocks[i];
            if (!block)
                continue;
            if (!pages_already_freed) {
                uint32_t j;
                for (j = 0; j < block->fragment_count; ++j) {
                    CF_PAGE *page = block->fragments[j];
                    if (page && !page->registered) {
                        cf_wipe(page, sizeof(*page));
                        free(page);
                    }
                }
            }
            cf_wipe(block, sizeof(*block));
            free(block);
        }
        if (!pages_already_freed && map->page && !map->page->registered) {
            cf_wipe(map->page, sizeof(*map->page));
            free(map->page);
        }
        cf_wipe(map, sizeof(*map));
        free(map);
        map = next_map;
    }
}

static void cf_free_block_after_pages(CF_BLOCK *block) {
    if (!block)
        return;
    cf_wipe(block, sizeof(*block));
    free(block);
}

CF_RESULT cf_node_resize(CF_STORE *s, CF_NODE *node, uint64_t size,
    bool allocation_only) {
    CF_TX tx;
    CF_RESULT result = CF_OK;
    uint64_t old_size = 0, old_logical = 0, keep_blocks;
    uint64_t old_creation, old_access, old_write, old_change;
    CF_MAP_PAGE *map, *previous = NULL, *last_kept = NULL, *removed_head = NULL;
    CF_MAP_PAGE *old_maps_head = NULL, *old_maps_tail = NULL;
    CF_MAP_PAGE *boundary_map = NULL;
    CF_BLOCK *boundary_old = NULL, *boundary_new = NULL;
    uint32_t boundary_pos = 0, boundary_fragments = 0, encoded_length = 0, codec = 0;
    uint32_t old_last_count = 0, keep_last_count = 0;
    CF_MAP_PAGE *old_last_next = NULL;
    uint8_t raw[CF_BLOCK_SIZE], encoded[CF_BLOCK_SIZE];
    bool tx_started = false, map_changed = false, committed = false;
    if (!s || !node)
        return CF_INVALID;
    if (allocation_only)
        return CF_NOT_SUPPORTED;
    AcquireSRWLockExclusive(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_DIRECTORY) {
        result = CF_IS_DIRECTORY;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_READONLY) {
        result = CF_ACCESS;
        goto done;
    }
    if (size > s->capacity ||
        (size > node->size && size - node->size > s->capacity - s->logical_used)) {
        result = CF_NO_SPACE;
        goto done;
    }
    if (size == node->size)
        goto done;
    old_size = node->size;
    old_logical = s->logical_used;
    old_creation = node->creation_time;
    old_access = node->access_time;
    old_write = node->write_time;
    old_change = node->change_time;
    old_maps_head = node->maps;
    old_maps_tail = node->maps_tail;
    memset(raw, 0, sizeof(raw));
    memset(encoded, 0, sizeof(encoded));
    if (size < old_size && (size % CF_BLOCK_SIZE) != 0) {
        boundary_old = cf_node_find_block(node, size / CF_BLOCK_SIZE,
            &boundary_map, &boundary_pos);
        if (boundary_old) {
            result = cf_node_decode_block(s, node, boundary_old, raw);
            if (result != CF_OK)
                goto done;
            memset(raw + (size % CF_BLOCK_SIZE), 0,
                CF_BLOCK_SIZE - (size_t)(size % CF_BLOCK_SIZE));
            if (!cf_block_encode(raw, s->compression_level, encoded,
                &encoded_length, &codec)) {
                result = CF_DATA_ERROR;
                goto done;
            }
            boundary_new = (CF_BLOCK *)calloc(1, sizeof(*boundary_new));
            if (!boundary_new) {
                result = CF_NO_MEMORY;
                goto done;
            }
            boundary_new->index = boundary_old->index;
            boundary_new->encoded_length = encoded_length;
            boundary_new->codec = codec;
            boundary_new->fragment_count = (encoded_length + CF_FRAGMENT_CAPACITY - 1u) /
                CF_FRAGMENT_CAPACITY;
            boundary_fragments = boundary_new->fragment_count;
            if (boundary_fragments == 0 || boundary_fragments > CF_MAX_FRAGMENTS) {
                result = CF_DATA_ERROR;
                goto done;
            }
        }
    }
    if (!cf_tx_begin(s, &tx)) {
        result = CF_NO_MEMORY;
        goto done;
    }
    tx_started = true;
    for (uint32_t i = 0; i < boundary_fragments; ++i) {
        boundary_new->fragments[i] = cf_tx_new_page(&tx,
            CF_RECORD_FRAGMENT, node->id);
        if (!boundary_new->fragments[i]) {
            result = CF_NO_SPACE;
            goto done;
        }
    }
    if (size < old_size) {
        keep_blocks = cf_ceil_blocks(size);
        for (map = node->maps; map; map = map->next) {
            uint32_t keep = 0;
            while (keep < map->count && map->blocks[keep]->index < keep_blocks)
                ++keep;
            if (keep < map->count) {
                if (keep == 0) {
                    removed_head = map;
                    if (previous) {
                        last_kept = previous;
                        old_last_count = previous->count;
                        keep_last_count = previous->count;
                        old_last_next = previous->next;
                        previous->next = NULL;
                    } else {
                        node->maps = NULL;
                    }
                    node->maps_tail = previous;
                } else {
                    last_kept = map;
                    old_last_count = map->count;
                    keep_last_count = keep;
                    old_last_next = map->next;
                    map->count = keep;
                    map->next = NULL;
                    removed_head = old_last_next;
                    node->maps_tail = map;
                }
                map_changed = true;
                break;
            }
            previous = map;
        }
    }
    node->size = size;
    node->write_time = node->change_time = cf_now_filetime();
    if (size > old_size)
        s->logical_used += size - old_size;
    else
        s->logical_used -= old_size - size;
    if (boundary_new)
        boundary_map->blocks[boundary_pos] = boundary_new;
    if (boundary_new) {
        for (uint32_t i = 0; i < boundary_fragments; ++i) {
            if (!cf_tx_add_fragment(&tx, node, boundary_new, i, encoded)) {
                result = CF_NO_MEMORY;
                goto rollback;
            }
        }
    }
    if (!cf_tx_add_node(&tx, node) ||
        (boundary_new && !cf_tx_add_map(&tx, node, boundary_map)) ||
        (map_changed && last_kept && last_kept != boundary_map &&
            !cf_tx_add_map(&tx, node, last_kept)) ||
        !cf_tx_commit(&tx)) {
        result = cf_tx_failure_result(&tx, CF_NO_MEMORY);
        goto rollback;
    }
    committed = true;
    if (boundary_new) {
        bool register_ok = true;
        for (uint32_t i = 0; i < boundary_fragments; ++i) {
            if (!cf_page_register(s, boundary_new->fragments[i])) {
                register_ok = false;
                break;
            }
        }
        if (register_ok) {
            for (uint32_t i = 1; i < boundary_fragments; ++i)
                cf_page_set_owner(boundary_new->fragments[i],
                    boundary_new->fragments[i - 1], CF_FRAGMENT_NEXT);
            cf_page_set_owner(boundary_new->fragments[0], boundary_map->page,
                (uint32_t)(CF_MAP_ENTRIES + (size_t)boundary_pos * CF_MAP_ENTRY_SIZE +
                    CF_MAP_ENTRY_FRAGMENT));
        } else {
            s->poisoned = true;
            result = CF_IO_ERROR;
        }
        if (boundary_old->fragment_count)
            cf_page_unregister_tree(s, boundary_old->fragments[0]);
        cf_free_block_after_pages(boundary_old);
        boundary_old = NULL;
        boundary_new = NULL;
    }
    if (last_kept) {
        uint32_t i;
        for (i = keep_last_count; i < old_last_count; ++i) {
            CF_BLOCK *block = last_kept->blocks[i];
            if (block && block->fragment_count)
                cf_page_unregister_tree(s, block->fragments[0]);
            cf_free_block_after_pages(block);
            last_kept->blocks[i] = NULL;
        }
    }
    if (removed_head) {
        cf_page_unregister_tree(s, removed_head->page);
        cf_map_chain_free(removed_head, true);
        removed_head = NULL;
    }
    goto done;
rollback:
    if (!committed) {
        if (boundary_new && boundary_map)
            boundary_map->blocks[boundary_pos] = boundary_old;
        if (map_changed && last_kept) {
            last_kept->count = old_last_count;
            last_kept->next = old_last_next;
        } else if (map_changed && previous) {
            previous->next = removed_head;
        }
        if (map_changed) {
            node->maps = old_maps_head;
            node->maps_tail = old_maps_tail;
        }
        node->size = old_size;
        node->creation_time = old_creation;
        node->access_time = old_access;
        node->write_time = old_write;
        node->change_time = old_change;
        s->logical_used = old_logical;
    }
done:
    if (result != CF_OK && committed && boundary_old) {
        if (boundary_old->fragment_count)
            cf_page_unregister_tree(s, boundary_old->fragments[0]);
        cf_free_block_after_pages(boundary_old);
        boundary_old = NULL;
    }
    if (result != CF_OK && !committed && boundary_new) {
        for (uint32_t i = 0; i < boundary_fragments; ++i) {
            CF_PAGE *page = boundary_new->fragments[i];
            if (page && !page->registered) {
                cf_wipe(page, sizeof(*page));
                free(page);
            }
        }
        cf_wipe(boundary_new, sizeof(*boundary_new));
        free(boundary_new);
        boundary_new = NULL;
    }
    if (tx_started)
        cf_tx_dispose(&tx);
    cf_wipe(raw, sizeof(raw));
    cf_wipe(encoded, sizeof(encoded));
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

CF_RESULT cf_node_can_delete(CF_STORE *s, CF_NODE *node) {
    CF_RESULT result = CF_OK;
    if (!s || !node)
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (!cf_store_check_node(s, node))
        result = CF_IO_ERROR;
    else if (node == s->root || node->unlinked || !node->parent)
        result = CF_ACCESS;
    else if (node->attributes & FILE_ATTRIBUTE_READONLY)
        result = CF_ACCESS;
    else if ((node->attributes & FILE_ATTRIBUTE_DIRECTORY) && node->child_count)
        result = CF_NOT_EMPTY;
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

CF_RESULT cf_node_unlink(CF_STORE *s, CF_NODE *node) {
    CF_TX tx;
    CF_NODE *parent, *sibling_prev = NULL, *sibling, *old_next, *old_orphan_head;
    CF_RESULT result = CF_OK;
    bool tx_started = false;
    if (!s || !node)
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (node == s->root || node->unlinked || !node->parent) {
        result = CF_ACCESS;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_READONLY) {
        result = CF_ACCESS;
        goto done;
    }
    if ((node->attributes & FILE_ATTRIBUTE_DIRECTORY) && node->child_count) {
        result = CF_NOT_EMPTY;
        goto done;
    }
    parent = node->parent;
    sibling = parent->first_child;
    while (sibling && sibling != node) {
        sibling_prev = sibling;
        sibling = sibling->next_sibling;
    }
    if (!sibling) {
        result = CF_DATA_ERROR;
        goto done;
    }
    old_next = node->next_sibling;
    old_orphan_head = s->root->orphan_next;
    if (sibling_prev)
        sibling_prev->next_sibling = old_next;
    else
        parent->first_child = old_next;
    node->parent = NULL;
    node->parent_id = 0;
    node->next_sibling = NULL;
    node->orphan_next = old_orphan_head;
    node->unlinked = true;
    s->root->orphan_next = node;
    if (!cf_tx_begin(s, &tx)) {
        result = CF_NO_MEMORY;
        goto rollback;
    }
    tx_started = true;
    if (!cf_tx_add_node(&tx, node) || !cf_tx_add_node(&tx, parent) ||
        (sibling_prev && !cf_tx_add_node(&tx, sibling_prev)) ||
        !cf_tx_add_node(&tx, s->root) || !cf_tx_commit(&tx)) {
        result = cf_tx_failure_result(&tx, CF_NO_MEMORY);
        goto rollback;
    }
    cf_child_index_remove(parent, node);
    if (old_next)
        cf_page_set_owner(old_next->page,
            sibling_prev ? sibling_prev->page : parent->page,
            sibling_prev ? CF_INODE_NEXT_SIBLING : CF_INODE_FIRST_CHILD);
    if (old_orphan_head)
        cf_page_set_owner(old_orphan_head->page, node->page, CF_INODE_ORPHAN_LINK);
    cf_page_set_owner(node->page, s->root_page, CF_INODE_ORPHAN_LINK);
    if (node->references == 0) {
        CF_RESULT reclaim_result = cf_reclaim_orphans(s);
        if (reclaim_result != CF_OK)
            cf_record_reclaim_failure(s, reclaim_result);
    }
    goto done;
rollback:
    if (sibling_prev)
        sibling_prev->next_sibling = node;
    else
        parent->first_child = node;
    node->parent = parent;
    node->parent_id = parent->id;
    node->next_sibling = old_next;
    node->orphan_next = NULL;
    node->unlinked = false;
    s->root->orphan_next = old_orphan_head;
done:
    if (tx_started)
        cf_tx_dispose(&tx);
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

typedef struct CF_LINK_SAVE {
    CF_NODE *node;
    CF_NODE *next_sibling;
} CF_LINK_SAVE;

static void cf_link_save_add(CF_LINK_SAVE saves[8], size_t *count, CF_NODE *node) {
    size_t i;
    if (!node)
        return;
    for (i = 0; i < *count; ++i) {
        if (saves[i].node == node)
            return;
    }
    if (*count < 8) {
        saves[*count].node = node;
        saves[*count].next_sibling = node->next_sibling;
        ++*count;
    }
}

static CF_NODE *cf_sibling_previous(CF_NODE *parent, CF_NODE *node) {
    CF_NODE *previous = NULL, *current = parent ? parent->first_child : NULL;
    while (current && current != node) {
        previous = current;
        current = current->next_sibling;
    }
    return current == node ? previous : NULL;
}

static CF_NODE *cf_sibling_unlink(CF_NODE *parent, CF_NODE *node) {
    CF_NODE *previous = cf_sibling_previous(parent, node);
    if (!parent || !node || (parent->first_child != node && !previous))
        return (CF_NODE *)(uintptr_t)1;
    if (previous)
        previous->next_sibling = node->next_sibling;
    else
        parent->first_child = node->next_sibling;
    node->next_sibling = NULL;
    return previous;
}

static void cf_child_index_remove_pointer(CF_NODE *parent, CF_NODE *child) {
    size_t i;
    if (!parent || !child)
        return;
    for (i = 0; i < parent->child_count; ++i) {
        if (parent->children[i] == child) {
            memmove(parent->children + i, parent->children + i + 1,
                (parent->child_count - i - 1) * sizeof(CF_NODE *));
            --parent->child_count;
            child->parent = NULL;
            return;
        }
    }
}

static bool cf_node_collect_subtree(CF_STORE *s, CF_NODE *root,
    CF_NODE **nodes, size_t *count) {
    size_t pending = 0, out = 0;
    if (!s || !root || !nodes || !count || s->node_count == 0)
        return false;
    nodes[pending++] = root;
    *count = 0;
    while (out < pending) {
        CF_NODE *current = nodes[out++];
        size_t i;
        if (!current || *count >= s->node_count)
            return false;
        ++*count;
        for (i = 0; i < current->child_count; ++i) {
            if (pending >= s->node_count)
                return false;
            nodes[pending++] = current->children[i];
        }
    }
    return true;
}

static void cf_refresh_child_page_owners(CF_NODE *parent) {
    CF_NODE *previous = NULL, *child;
    for (child = parent->first_child; child; child = child->next_sibling) {
        cf_page_set_owner(child->page,
            previous ? previous->page : parent->page,
            previous ? CF_INODE_NEXT_SIBLING : CF_INODE_FIRST_CHILD);
        previous = child;
    }
}

CF_RESULT cf_node_rename(CF_STORE *s, CF_NODE *node,
    const wchar_t *new_path, bool replace) {
    CF_NODE *destination_parent = NULL, *source_parent, *target = NULL;
    CF_NODE *source_previous_before, *target_previous_before = NULL;
    CF_NODE *source_link_previous = NULL, *target_link_previous = NULL;
    CF_NODE *old_source_first, *old_destination_first, *old_orphan_head;
    CF_LINK_SAVE links[8];
    size_t link_count = 0, i, subtree_count = 0;
    CF_NODE **subtree = NULL;
    wchar_t new_name[CF_NAME_MAX + 1];
    wchar_t old_name[CF_NAME_MAX + 1];
    uint16_t new_name_length = 0, old_name_length;
    uint64_t old_parent_id, old_creation, old_change;
    uint16_t old_depth;
    bool old_unlinked, committed = false, tx_started = false;
    CF_NODE *old_parent_pointer, *old_orphan_pointer;
    CF_TX tx;
    CF_RESULT result;
    int depth_delta = 0;
    if (!s || !node || !new_path)
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (node == s->root || node->unlinked || !node->parent) {
        result = CF_ACCESS;
        goto done;
    }
    source_parent = node->parent;
    result = cf_path_parent(s, new_path, &destination_parent, new_name,
        &new_name_length);
    if (result != CF_OK)
        goto done;
    for (CF_NODE *ancestor = destination_parent; ancestor; ancestor = ancestor->parent) {
        if (ancestor == node) {
            result = CF_INVALID;
            goto done;
        }
    }
    target = cf_child_find(destination_parent, new_name, new_name_length);
    if (target == node) {
        result = CF_OK;
        goto done;
    }
    if (target && !replace) {
        result = CF_EXISTS;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_READONLY) {
        result = CF_ACCESS;
        goto done;
    }
    if (target && (target->attributes & FILE_ATTRIBUTE_READONLY)) {
        result = CF_ACCESS;
        goto done;
    }
    if (target && (target->attributes & FILE_ATTRIBUTE_DIRECTORY) && target->child_count) {
        result = CF_NOT_EMPTY;
        goto done;
    }
    if (target && ((target->attributes ^ node->attributes) & FILE_ATTRIBUTE_DIRECTORY)) {
        result = CF_INVALID;
        goto done;
    }
    if (destination_parent->child_count > CF_MAX_NODES ||
        !cf_child_index_reserve(destination_parent,
            destination_parent->child_count +
                ((destination_parent != source_parent && !target) ? 1u : 0u))) {
        result = CF_NO_MEMORY;
        goto done;
    }
    if (node->attributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (s->node_count > SIZE_MAX / sizeof(*subtree)) {
            result = CF_NO_MEMORY;
            goto done;
        }
        subtree = (CF_NODE **)malloc(s->node_count * sizeof(*subtree));
        if (!subtree) {
            result = CF_NO_MEMORY;
            goto done;
        }
        if (!cf_node_collect_subtree(s, node, subtree, &subtree_count)) {
            result = CF_DATA_ERROR;
            goto done;
        }
        depth_delta = (int)destination_parent->depth + 1 - (int)node->depth;
        for (i = 0; i < subtree_count; ++i) {
            int new_depth = (int)subtree[i]->depth + depth_delta;
            if (new_depth < 1 || new_depth > (int)CF_MAX_DEPTH) {
                result = CF_INVALID;
                goto done;
            }
        }
    }
    source_previous_before = cf_sibling_previous(source_parent, node);
    if (target)
        target_previous_before = cf_sibling_previous(destination_parent, target);
    cf_link_save_add(links, &link_count, node);
    cf_link_save_add(links, &link_count, target);
    cf_link_save_add(links, &link_count, source_previous_before);
    cf_link_save_add(links, &link_count, target_previous_before);
    old_source_first = source_parent->first_child;
    old_destination_first = destination_parent->first_child;
    old_orphan_head = s->root->orphan_next;
    old_parent_pointer = node->parent;
    old_parent_id = node->parent_id;
    old_name_length = node->name_length;
    memcpy(old_name, node->name, sizeof(old_name));
    old_depth = node->depth;
    old_creation = node->creation_time;
    old_change = node->change_time;
    old_unlinked = node->unlinked;
    if (target) {
        old_orphan_pointer = target->orphan_next;
        if (cf_sibling_unlink(destination_parent, target) == (CF_NODE *)(uintptr_t)1) {
            result = CF_DATA_ERROR;
            goto rollback;
        }
        target_link_previous = target_previous_before;
        target->parent = NULL;
        target->parent_id = 0;
        target->orphan_next = old_orphan_head;
        target->unlinked = true;
    } else {
        old_orphan_pointer = NULL;
    }
    source_link_previous = cf_sibling_unlink(source_parent, node);
    if (source_link_previous == (CF_NODE *)(uintptr_t)1) {
        result = CF_DATA_ERROR;
        goto rollback;
    }
    node->parent = destination_parent;
    node->parent_id = destination_parent->id;
    memset(node->name, 0, sizeof(node->name));
    memcpy(node->name, new_name, ((size_t)new_name_length + 1) * sizeof(wchar_t));
    node->name_length = new_name_length;
    node->change_time = cf_now_filetime();
    node->next_sibling = destination_parent->first_child;
    destination_parent->first_child = node;
    if (target)
        s->root->orphan_next = target;
    if (!cf_tx_begin(s, &tx)) {
        result = CF_NO_MEMORY;
        goto rollback;
    }
    tx_started = true;
    if (!cf_tx_add_node(&tx, node) || !cf_tx_add_node(&tx, source_parent) ||
        !cf_tx_add_node(&tx, destination_parent) ||
        (source_link_previous && !cf_tx_add_node(&tx, source_link_previous)) ||
        (target && (!cf_tx_add_node(&tx, target) ||
            !cf_tx_add_node(&tx, s->root))) ||
        (target_link_previous && !cf_tx_add_node(&tx, target_link_previous)) ||
        !cf_tx_commit(&tx)) {
        result = cf_tx_failure_result(&tx, CF_NO_MEMORY);
        goto rollback;
    }
    committed = true;
    cf_child_index_remove_pointer(source_parent, node);
    if (target)
        cf_child_index_remove_pointer(destination_parent, target);
    if (!cf_child_index_insert(destination_parent, node)) {
        s->poisoned = true;
        result = CF_IO_ERROR;
    } else {
        result = CF_OK;
    }
    cf_refresh_child_page_owners(source_parent);
    if (destination_parent != source_parent)
        cf_refresh_child_page_owners(destination_parent);
    if (target) {
        cf_page_set_owner(target->page, s->root_page, CF_INODE_ORPHAN_LINK);
        if (old_orphan_head)
            cf_page_set_owner(old_orphan_head->page, target->page,
                CF_INODE_ORPHAN_LINK);
    }
    for (i = 0; i < subtree_count; ++i)
        subtree[i]->depth = (uint16_t)((int)subtree[i]->depth + depth_delta);
    if (target && target->references == 0 && !s->poisoned) {
        CF_RESULT reclaim_result = cf_reclaim_orphans(s);
        if (reclaim_result != CF_OK)
            cf_record_reclaim_failure(s, reclaim_result);
    }
    goto done;
rollback:
    if (!committed) {
        for (i = 0; i < link_count; ++i)
            links[i].node->next_sibling = links[i].next_sibling;
        source_parent->first_child = old_source_first;
        destination_parent->first_child = old_destination_first;
        s->root->orphan_next = old_orphan_head;
        node->parent = old_parent_pointer;
        node->parent_id = old_parent_id;
        memcpy(node->name, old_name, sizeof(old_name));
        node->name_length = old_name_length;
        node->depth = old_depth;
        node->creation_time = old_creation;
        node->change_time = old_change;
        node->unlinked = old_unlinked;
        if (target) {
            target->parent = destination_parent;
            target->parent_id = destination_parent->id;
            target->unlinked = false;
            target->orphan_next = old_orphan_pointer;
        }
    }
done:
    if (tx_started)
        cf_tx_dispose(&tx);
    if (subtree) {
        cf_wipe(subtree, s->node_count * sizeof(*subtree));
        free(subtree);
    }
    cf_wipe(old_name, sizeof(old_name));
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

CF_RESULT cf_node_list(CF_STORE *s, CF_NODE *node,
    CF_DIRENT **entries, size_t *count) {
    CF_DIRENT *list = NULL;
    size_t i;
    CF_RESULT result = CF_OK;
    if (entries) *entries = NULL;
    if (count) *count = 0;
    if (!s || !node || !entries || !count)
        return CF_INVALID;
    AcquireSRWLockShared(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (!(node->attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        result = CF_NOT_DIRECTORY;
        goto done;
    }
    if (node->child_count) {
        if (node->child_count > SIZE_MAX / sizeof(*list)) {
            result = CF_NO_MEMORY;
            goto done;
        }
        list = (CF_DIRENT *)calloc(node->child_count, sizeof(*list));
        if (!list) {
            result = CF_NO_MEMORY;
            goto done;
        }
        for (i = 0; i < node->child_count; ++i) {
            CF_NODE *child = node->children[i];
            memcpy(list[i].name, child->name,
                ((size_t)child->name_length + 1) * sizeof(wchar_t));
            cf_node_fill_info(child, &list[i].info);
        }
    }
    *entries = list;
    *count = node->child_count;
    list = NULL;
done:
    if (list) {
        cf_wipe(list, node ? node->child_count * sizeof(*list) : 0);
        free(list);
    }
    ReleaseSRWLockShared(&s->lock);
    return result;
}

CF_RESULT cf_node_list_after(CF_STORE *s, CF_NODE *node, const wchar_t *marker,
    size_t max_entries, CF_DIRENT **entries, size_t *count, bool *more) {
    CF_DIRENT *list = NULL;
    size_t first = 0, total, i;
    CF_RESULT result = CF_OK;
    if (entries) *entries = NULL;
    if (count) *count = 0;
    if (more) *more = false;
    if (!s || !node || !entries || !count || !more || max_entries == 0)
        return CF_INVALID;
    AcquireSRWLockShared(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
        goto done;
    }
    if (!(node->attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        result = CF_NOT_DIRECTORY;
        goto done;
    }
    if (marker) {
        size_t marker_length = wcslen(marker);
        /* Children are sorted by raw code units; resume strictly after the marker. */
        first = cf_child_lower_bound(node, marker, marker_length);
        if (first < node->child_count &&
            cf_name_compare_raw(node->children[first]->name,
                node->children[first]->name_length, marker, marker_length) == 0)
            ++first;
    }
    total = node->child_count - first;
    if (total > max_entries) {
        total = max_entries;
        *more = true;
    }
    if (total) {
        list = (CF_DIRENT *)calloc(total, sizeof(*list));
        if (!list) {
            result = CF_NO_MEMORY;
            goto done;
        }
        for (i = 0; i < total; ++i) {
            CF_NODE *child = node->children[first + i];
            memcpy(list[i].name, child->name,
                ((size_t)child->name_length + 1) * sizeof(wchar_t));
            cf_node_fill_info(child, &list[i].info);
        }
    }
    *entries = list;
    *count = total;
done:
    ReleaseSRWLockShared(&s->lock);
    return result;
}

CF_RESULT cf_node_parent_info(CF_STORE *s, CF_NODE *node, CF_INFO *info) {
    CF_RESULT result = CF_OK;
    if (!s || !node || !info)
        return CF_INVALID;
    memset(info, 0, sizeof(*info));
    AcquireSRWLockShared(&s->lock);
    if (!cf_store_check_node(s, node))
        result = CF_IO_ERROR;
    else if (node == s->root || !node->parent)
        result = CF_NOT_FOUND;
    else
        cf_node_fill_info(node->parent, info);
    ReleaseSRWLockShared(&s->lock);
    return result;
}

CF_RESULT cf_node_child_info(CF_STORE *s, CF_NODE *node, const wchar_t *name,
    CF_DIRENT *entry) {
    CF_NODE *child;
    size_t length;
    CF_RESULT result = CF_OK;
    if (!s || !node || !name || !entry)
        return CF_INVALID;
    memset(entry, 0, sizeof(*entry));
    length = wcslen(name);
    if (length == 0 || length > CF_NAME_MAX)
        return CF_NOT_FOUND;
    AcquireSRWLockShared(&s->lock);
    if (!cf_store_check_node(s, node)) {
        result = CF_IO_ERROR;
    } else if (!(node->attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        result = CF_NOT_DIRECTORY;
    } else if ((child = cf_child_find(node, name, length)) == NULL) {
        result = CF_NOT_FOUND;
    } else {
        memcpy(entry->name, child->name,
            ((size_t)child->name_length + 1) * sizeof(wchar_t));
        cf_node_fill_info(child, &entry->info);
    }
    ReleaseSRWLockShared(&s->lock);
    return result;
}

void cf_list_free(CF_DIRENT *entries, size_t count) {
    if (entries) {
        cf_wipe(entries, count * sizeof(*entries));
        free(entries);
    }
}

#include "cryptfs_compact.inc"

