#pragma once

/*
 * Sparse block store for the block-device mode.
 *
 * A virtual disk of `size` bytes is striped in 1 MiB chunks (one memfs page
 * group) across several internal memfs nodes, each with its own lock, so
 * I/O to different stripes runs in parallel. Storage reuses memfs pages:
 * all-zero pages are never stored, optional Zstd compression and
 * authenticated encryption apply per page, and unmap frees pages at once.
 *
 * The Memfs instance must be created with MemfsOptions.block_backing so the
 * virtual extents are not charged to the quota; capacity then limits
 * resident page memory (fixed bytes, or free system memory in auto mode).
 */

#include <stdint.h>

#include "memfs_core.h"

#define MEMFS_BLOCK_CHUNK_SHIFT 20U
#define MEMFS_BLOCK_CHUNK_SIZE (1ULL << MEMFS_BLOCK_CHUNK_SHIFT)
#define MEMFS_BLOCK_DEFAULT_STRIPES 16U
#define MEMFS_BLOCK_MAX_STRIPES 256U
#define MEMFS_BLOCK_SECTOR_SIZE 512U

typedef struct MemfsBlock MemfsBlock;

/* size must be a positive multiple of MEMFS_BLOCK_SECTOR_SIZE; stripes is a
 * power of two in [1, MEMFS_BLOCK_MAX_STRIPES] (0 selects the default). */
MemfsResult memfs_block_create(Memfs* fs, uint64_t size, uint32_t stripes, MemfsBlock** out_block);
void memfs_block_destroy(MemfsBlock* block);

uint64_t memfs_block_size(const MemfsBlock* block);
Memfs* memfs_block_fs(const MemfsBlock* block);

/* Requests outside the disk return MEMFS_ERR_INVALID. Writes that would need
 * more resident memory than the capacity allows return MEMFS_ERR_NO_SPACE
 * before any data is changed. */
MemfsResult memfs_block_read(MemfsBlock* block, uint64_t offset, void* buffer, uint32_t length);
MemfsResult memfs_block_write(MemfsBlock* block, uint64_t offset, const void* buffer, uint32_t length);

/* Unmap (TRIM) and zero both leave the range reading as zeros and free its
 * page memory; partial pages at the edges are zeroed in place. */
MemfsResult memfs_block_unmap(MemfsBlock* block, uint64_t offset, uint64_t length);
