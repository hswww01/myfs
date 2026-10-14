#include "memfs_block.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct MemfsBlockStripe {
	SRWLOCK lock;
	MemfsNode* node;
} MemfsBlockStripe;

struct MemfsBlock {
	Memfs* fs;
	uint64_t size;
	uint32_t stripes;
	uint32_t stripe_shift;
	MemfsBlockStripe stripe[];
};

uint64_t memfs_block_size(const MemfsBlock* block) {
	return block ? block->size : 0;
}

Memfs* memfs_block_fs(const MemfsBlock* block) {
	return block ? block->fs : NULL;
}

static bool memfs_block_range_ok(const MemfsBlock* block, uint64_t offset, uint64_t length) {
	return block != NULL && offset <= block->size && length <= block->size - offset;
}

/* Maps a disk offset to (stripe, node offset). Chunks rotate over stripes. */
static MemfsBlockStripe* memfs_block_locate(MemfsBlock* block, uint64_t offset, uint64_t* node_offset,
										   uint64_t* chunk_left) {
	uint64_t chunk = offset >> MEMFS_BLOCK_CHUNK_SHIFT;
	uint64_t within = offset & (MEMFS_BLOCK_CHUNK_SIZE - 1U);

	*node_offset = ((chunk >> block->stripe_shift) << MEMFS_BLOCK_CHUNK_SHIFT) | within;
	*chunk_left = MEMFS_BLOCK_CHUNK_SIZE - within;
	return &block->stripe[chunk & (block->stripes - 1U)];
}

MemfsResult memfs_block_create(Memfs* fs, uint64_t size, uint32_t stripes, MemfsBlock** out_block) {
	MemfsBlock* block;
	uint64_t chunks;
	uint64_t per_stripe;
	uint32_t i;

	if (out_block == NULL)
		return MEMFS_ERR_INVALID;
	*out_block = NULL;
	if (stripes == 0)
		stripes = MEMFS_BLOCK_DEFAULT_STRIPES;
	if (fs == NULL || !fs->block_backing || size == 0 || (size % MEMFS_BLOCK_SECTOR_SIZE) != 0 ||
		stripes > MEMFS_BLOCK_MAX_STRIPES || (stripes & (stripes - 1U)) != 0)
		return MEMFS_ERR_INVALID;

	block = calloc(1, sizeof(*block) + (size_t)stripes * sizeof(block->stripe[0]));
	if (block == NULL)
		return MEMFS_ERR_NO_MEMORY;
	block->fs = fs;
	block->size = size;
	block->stripes = stripes;
	while ((1U << block->stripe_shift) < stripes)
		block->stripe_shift++;

	chunks = (size + MEMFS_BLOCK_CHUNK_SIZE - 1U) >> MEMFS_BLOCK_CHUNK_SHIFT;
	per_stripe = ((chunks + stripes - 1U) / stripes) << MEMFS_BLOCK_CHUNK_SHIFT;

	for (i = 0; i < stripes; i++) {
		wchar_t name[32];
		MemfsResult result;

		InitializeSRWLock(&block->stripe[i].lock);
		swprintf(name, sizeof(name) / sizeof(name[0]), L"block-stripe-%03u", i);
		result = memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL, NULL, 0, &block->stripe[i].node);
		if (result == MEMFS_OK) {
			memfs_node_open(block->stripe[i].node);
			result = memfs_node_set_file_size(block->stripe[i].node, per_stripe);
		}
		if (result != MEMFS_OK) {
			memfs_block_destroy(block);
			return result;
		}
	}

	*out_block = block;
	return MEMFS_OK;
}

void memfs_block_destroy(MemfsBlock* block) {
	uint32_t i;

	if (block == NULL)
		return;
	for (i = 0; i < block->stripes; i++) {
		MemfsNode* node = block->stripe[i].node;

		if (node == NULL)
			continue;
		(void)memfs_node_set_file_size(node, 0);
		(void)memfs_node_unlink(node);
		memfs_node_close(node);
	}
	free(block);
}

MemfsResult memfs_block_read(MemfsBlock* block, uint64_t offset, void* buffer, uint32_t length) {
	uint8_t* out = buffer;

	if (buffer == NULL || !memfs_block_range_ok(block, offset, length))
		return MEMFS_ERR_INVALID;

	while (length != 0) {
		uint64_t node_offset;
		uint64_t chunk_left;
		MemfsBlockStripe* stripe = memfs_block_locate(block, offset, &node_offset, &chunk_left);
		uint32_t part = (uint32_t)(chunk_left < length ? chunk_left : length);
		uint32_t done = 0;
		MemfsResult result;

		AcquireSRWLockExclusive(&stripe->lock);
		result = memfs_node_read(stripe->node, out, node_offset, part, &done);
		ReleaseSRWLockExclusive(&stripe->lock);
		if (result != MEMFS_OK)
			return result;
		if (done < part)
			memset(out + done, 0, part - done);

		out += part;
		offset += part;
		length -= part;
	}
	return MEMFS_OK;
}

MemfsResult memfs_block_write(MemfsBlock* block, uint64_t offset, const void* buffer, uint32_t length) {
	const uint8_t* in = buffer;

	if (buffer == NULL || !memfs_block_range_ok(block, offset, length))
		return MEMFS_ERR_INVALID;
	/* Worst case every byte becomes a new resident page byte. Refusing up
	 * front keeps a failed write from being half applied. */
	if (!memfs_block_capacity_allows(block->fs, length))
		return MEMFS_ERR_NO_SPACE;

	while (length != 0) {
		uint64_t node_offset;
		uint64_t chunk_left;
		MemfsBlockStripe* stripe = memfs_block_locate(block, offset, &node_offset, &chunk_left);
		uint32_t part = (uint32_t)(chunk_left < length ? chunk_left : length);
		uint32_t done = 0;
		MemfsResult result;

		AcquireSRWLockExclusive(&stripe->lock);
		result = memfs_node_write(stripe->node, in, node_offset, part, false, true, &done);
		ReleaseSRWLockExclusive(&stripe->lock);
		if (result != MEMFS_OK)
			return result;
		if (done != part)
			return MEMFS_ERR_INVALID;

		in += part;
		offset += part;
		length -= part;
	}
	return MEMFS_OK;
}

MemfsResult memfs_block_unmap(MemfsBlock* block, uint64_t offset, uint64_t length) {
	if (!memfs_block_range_ok(block, offset, length))
		return MEMFS_ERR_INVALID;

	while (length != 0) {
		uint64_t node_offset;
		uint64_t chunk_left;
		MemfsBlockStripe* stripe;
		uint64_t part;
		MemfsResult result;

		/* A whole-disk TRIM covers every stripe: punch each stripe's share in
		 * one call per stripe instead of one call per 1 MiB chunk. */
		if ((offset & (MEMFS_BLOCK_CHUNK_SIZE - 1U)) == 0 &&
			length >= ((uint64_t)block->stripes << MEMFS_BLOCK_CHUNK_SHIFT)) {
			uint64_t rounds = length / ((uint64_t)block->stripes << MEMFS_BLOCK_CHUNK_SHIFT);
			uint32_t i;

			for (i = 0; i < block->stripes; i++) {
				stripe = memfs_block_locate(block, offset + ((uint64_t)i << MEMFS_BLOCK_CHUNK_SHIFT),
											&node_offset, &chunk_left);
				AcquireSRWLockExclusive(&stripe->lock);
				result = memfs_node_punch_hole(stripe->node, node_offset, rounds << MEMFS_BLOCK_CHUNK_SHIFT);
				ReleaseSRWLockExclusive(&stripe->lock);
				if (result != MEMFS_OK)
					return result;
			}
			part = rounds * ((uint64_t)block->stripes << MEMFS_BLOCK_CHUNK_SHIFT);
		} else {
			stripe = memfs_block_locate(block, offset, &node_offset, &chunk_left);
			part = chunk_left < length ? chunk_left : length;
			AcquireSRWLockExclusive(&stripe->lock);
			result = memfs_node_punch_hole(stripe->node, node_offset, part);
			ReleaseSRWLockExclusive(&stripe->lock);
			if (result != MEMFS_OK)
				return result;
		}

		offset += part;
		length -= part;
	}
	return MEMFS_OK;
}
