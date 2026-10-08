#pragma once

#include "cryptfs_store.h"
#include <stdbool.h>
#include <stdint.h>

#define CF_FORMAT_VERSION 1u
#define CF_PAGE_SIZE 4096u
#define CF_PAYLOAD_SIZE 4032u
#define CF_PAGE_HEADER_SIZE 48u
#define CF_PAGE_CIPHER_SIZE 4048u
#define CF_RECORD_COUNT 4u

#define CF_SB0_OFFSET 0ULL
#define CF_SB1_OFFSET 4096ULL
#define CF_MARK0_OFFSET 8192ULL
#define CF_MARK1_OFFSET 12288ULL
#define CF_JOURNAL_OFFSET 16384ULL
#define CF_JOURNAL_SIZE (4ULL * 1024ULL * 1024ULL)
#define CF_ROOT_OFFSET (CF_JOURNAL_OFFSET + CF_JOURNAL_SIZE)
#define CF_PAGES_OFFSET (CF_ROOT_OFFSET + CF_PAGE_SIZE)
#define CF_MIN_EOF CF_PAGES_OFFSET
#define CF_ROOT_SLOT UINT64_MAX
#define CF_MAX_SLOTS (CF_MAX_PAGES - 1u)
#define CF_MAX_EOF (CF_PAGES_OFFSET + (uint64_t)CF_MAX_SLOTS * CF_PAGE_SIZE)
#define CF_MAX_TRANSACTION_BYTES (2u * 1024u * 1024u)
#define CF_MAX_TRANSACTION_PAGES 510u
#define CF_MAP_CAPACITY 125u
#define CF_FRAGMENT_CAPACITY 4000u
#define CF_MAX_FRAGMENTS ((CF_BLOCK_SIZE + CF_FRAGMENT_CAPACITY - 1u) / CF_FRAGMENT_CAPACITY)

enum {
    CF_RECORD_INODE = 1,
    CF_RECORD_MAP = 2,
    CF_RECORD_FRAGMENT = 3
};

enum {
    CF_SB_MAGIC = 0,
    CF_SB_VERSION = 8,
    CF_SB_HEADER_LENGTH = 12,
    CF_SB_UUID = 16,
    CF_SB_FLAGS = 32,
    CF_SB_RESERVED0 = 36,
    CF_SB_CAPACITY = 40,
    CF_SB_KDF_OPS = 48,
    CF_SB_KDF_MEM = 56,
    CF_SB_SALT = 64,
    CF_SB_WRAP_NONCE = 80,
    CF_SB_WRAPPED_KEY = 104,
    CF_SB_RESERVED = 152
};

enum {
    CF_MARK_MAGIC = 0,
    CF_MARK_VERSION = 8,
    CF_MARK_SLOT = 12,
    CF_MARK_STATE = 16,
    CF_MARK_RESERVED0 = 20,
    CF_MARK_GENERATION = 24,
    CF_MARK_JOURNAL_LENGTH = 32,
    CF_MARK_RESERVED1 = 36,
    CF_MARK_FINAL_EOF = 40,
    CF_MARK_JOURNAL_HASH = 48,
    CF_MARK_MAC = 80,
    CF_MARK_RESERVED = 112
};

enum {
    CF_MARK_EMPTY = 0,
    CF_MARK_COMMITTED = 1
};

enum {
    CF_WAL_MAGIC = 0,
    CF_WAL_VERSION = 8,
    CF_WAL_CIPHER_LENGTH = 12,
    CF_WAL_NONCE = 16,
    CF_WAL_CIPHER = 40,
    CF_WAL_HEADER_SIZE = 40,
    CF_WAL_PLAIN_HEADER_SIZE = 32,
    CF_WAL_PAGE_SLOT = 0,
    CF_WAL_PAGE_BYTES = 8,
    CF_WAL_PAGE_ENTRY_SIZE = 8 + CF_PAGE_SIZE
};

enum {
    CF_INODE_ID = 0,
    CF_INODE_PARENT_ID = 8,
    CF_INODE_FIRST_CHILD = 16,
    CF_INODE_NEXT_SIBLING = 24,
    CF_INODE_MAP_HEAD = 32,
    CF_INODE_ORPHAN_LINK = 40,
    CF_INODE_SIZE = 48,
    CF_INODE_CREATED = 56,
    CF_INODE_ACCESSED = 64,
    CF_INODE_WRITTEN = 72,
    CF_INODE_CHANGED = 80,
    CF_INODE_ATTRIBUTES = 88,
    CF_INODE_NAME_LENGTH = 92,
    CF_INODE_FLAGS = 94,
    CF_INODE_NAME = 96,
    CF_INODE_NAME_BYTES = CF_NAME_MAX * 2u,
    CF_INODE_NEXT_ID = 608
};

enum {
    CF_MAP_FILE_ID = 0,
    CF_MAP_NEXT = 8,
    CF_MAP_COUNT = 16,
    CF_MAP_ENTRIES = 24,
    CF_MAP_ENTRY_SIZE = 32,
    CF_MAP_ENTRY_BLOCK = 0,
    CF_MAP_ENTRY_FRAGMENT = 8,
    CF_MAP_ENTRY_ENCODED_LENGTH = 16,
    CF_MAP_ENTRY_CODEC = 20,
    CF_MAP_ENTRY_RAW_LENGTH = 24,
    CF_MAP_ENTRY_FRAGMENT_COUNT = 28
};

enum {
    CF_FRAGMENT_FILE_ID = 0,
    CF_FRAGMENT_BLOCK = 8,
    CF_FRAGMENT_NEXT = 16,
    CF_FRAGMENT_SEQUENCE = 24,
    CF_FRAGMENT_LENGTH = 28,
    CF_FRAGMENT_DATA = 32
};

static inline uint16_t cf_get_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t cf_get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t cf_get_u64(const uint8_t *p) {
    return (uint64_t)cf_get_u32(p) | ((uint64_t)cf_get_u32(p + 4) << 32);
}

static inline void cf_put_u16(uint8_t *p, uint16_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
}

static inline void cf_put_u32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static inline void cf_put_u64(uint8_t *p, uint64_t x) {
    cf_put_u32(p, (uint32_t)x);
    cf_put_u32(p + 4, (uint32_t)(x >> 32));
}

static inline bool cf_slot_offset(uint64_t slot, uint64_t *out) {
    uint64_t index;
    if (slot == 0 || slot > CF_MAX_SLOTS)
        return false;
    index = slot - 1;
    if (index > (UINT64_MAX - CF_PAGES_OFFSET) / CF_PAGE_SIZE)
        return false;
    *out = CF_PAGES_OFFSET + index * CF_PAGE_SIZE;
    return true;
}

static inline bool cf_eof_valid(uint64_t eof) {
    uint64_t delta;
    if (eof < CF_MIN_EOF)
        return false;
    delta = eof - CF_PAGES_OFFSET;
    return (delta % CF_PAGE_SIZE) == 0 &&
        delta / CF_PAGE_SIZE <= CF_MAX_SLOTS;
}
