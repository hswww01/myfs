/* Block-device store: sparse striping, unmap/TRIM reclaim, resident-memory
 * capacity, compression/encryption round trips and concurrent I/O. */
#include "memfs_block.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(expression) do { \
	++checks; \
	if (!(expression)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); \
		++failures; \
	} \
} while (0)

#define MIB (1024ULL * 1024ULL)
#define GIB (1024ULL * MIB)
#define TIB (1024ULL * GIB)

static Memfs* create_fs(uint64_t capacity, bool compression, bool encryption) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;

	options.capacity = capacity;
	options.volume_label = L"BLOCK-TEST";
	options.compression_enabled = compression;
	options.compression_level = 1;
	options.encryption_enabled = encryption;
	options.block_backing = true;
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	return fs;
}

static void fill_pattern(uint8_t* buffer, size_t size, uint32_t seed) {
	uint32_t x = seed * 2654435761U + 1U;
	size_t i;

	for (i = 0; i < size; i++) {
		x ^= x << 13; x ^= x >> 17; x ^= x << 5;
		buffer[i] = (uint8_t)x;
	}
}

static bool all_zero(const uint8_t* buffer, size_t size) {
	size_t i;

	for (i = 0; i < size; i++)
		if (buffer[i] != 0)
			return false;
	return true;
}

static void test_arguments(void) {
	MemfsOptions plain = {0};
	Memfs* normal = NULL;
	Memfs* fs = create_fs(64 * MIB, false, false);
	MemfsBlock* block = NULL;
	uint8_t sector[512] = {0};

	plain.capacity = 64 * MIB;
	plain.volume_label = L"PLAIN";
	CHECK(memfs_create_ex(&plain, &normal) == MEMFS_OK);
	/* An ordinary volume charges file sizes, so it refuses to be a disk. */
	CHECK(memfs_block_create(normal, GIB, 0, &block) == MEMFS_ERR_INVALID && block == NULL);
	memfs_destroy(normal);

	CHECK(memfs_block_create(fs, 0, 0, &block) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_create(fs, GIB + 1, 0, &block) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_create(fs, GIB, 3, &block) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_create(fs, GIB, 512, &block) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_create(fs, GIB, 4, &block) == MEMFS_OK && block != NULL);
	CHECK(memfs_block_size(block) == GIB);
	CHECK(memfs_block_read(block, GIB, sector, 512) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_write(block, GIB - 256, sector, 512) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_unmap(block, GIB, 1) == MEMFS_ERR_INVALID);
	CHECK(memfs_block_read(block, GIB - 512, sector, 512) == MEMFS_OK);
	memfs_block_destroy(block);
	memfs_destroy(fs);
}

/* A 1 TiB disk on a 64 MiB volume: extents are free, data is not. */
static void test_sparse_round_trip(void) {
	Memfs* fs = create_fs(64 * MIB, false, false);
	MemfsBlock* block = NULL;
	uint8_t* data = malloc(3 * MIB);
	uint8_t* back = malloc(3 * MIB);
	uint64_t offsets[] = {0, 100 * MIB - 512, 17 * MIB + 4096 + 512, 600 * GIB + 3, TIB - 3 * MIB};
	uint64_t base;
	size_t i;

	CHECK(data && back);
	CHECK(memfs_block_create(fs, TIB, 16, &block) == MEMFS_OK);
	base = memfs_resident_bytes(fs);
	CHECK(base < MIB);

	/* Unwritten areas read as zeros without allocating. */
	memset(back, 0xA5, 3 * MIB);
	CHECK(memfs_block_read(block, 500 * GIB, back, (uint32_t)(3 * MIB)) == MEMFS_OK && all_zero(back, 3 * MIB));

	for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		uint64_t offset = offsets[i] & ~511ULL;

		fill_pattern(data, 3 * MIB, (uint32_t)i + 7U);
		CHECK(memfs_block_write(block, offset, data, (uint32_t)(3 * MIB)) == MEMFS_OK);
		memset(back, 0, 3 * MIB);
		CHECK(memfs_block_read(block, offset, back, (uint32_t)(3 * MIB)) == MEMFS_OK);
		CHECK(memcmp(data, back, 3 * MIB) == 0);
	}
	/* Last sector is addressable (NTFS keeps its backup boot sector there). */
	fill_pattern(data, 512, 99);
	CHECK(memfs_block_write(block, TIB - 512, data, 512) == MEMFS_OK);
	CHECK(memfs_block_read(block, TIB - 512, back, 512) == MEMFS_OK && memcmp(data, back, 512) == 0);

	CHECK(memfs_resident_bytes(fs) >= base + 5 * 3 * MIB);
	CHECK(memfs_resident_bytes(fs) < base + 5 * 3 * MIB + 2 * MIB);
	memfs_block_destroy(block);
	CHECK(memfs_resident_bytes(fs) < MIB);
	memfs_destroy(fs);
	free(data);
	free(back);
}

static void test_unmap(void) {
	Memfs* fs = create_fs(256 * MIB, false, false);
	MemfsBlock* block = NULL;
	uint8_t* data = malloc(8 * MIB);
	uint8_t* back = malloc(8 * MIB);
	uint64_t written;
	LARGE_INTEGER start, stop, frequency;

	CHECK(data && back);
	CHECK(memfs_block_create(fs, TIB, 0, &block) == MEMFS_OK);
	fill_pattern(data, 8 * MIB, 3);
	CHECK(memfs_block_write(block, 40 * MIB, data, (uint32_t)(8 * MIB)) == MEMFS_OK);
	written = memfs_resident_bytes(fs);
	CHECK(written >= 8 * MIB);

	/* Unaligned unmap: edge pages are zeroed in place, whole pages freed. */
	CHECK(memfs_block_unmap(block, 40 * MIB + 1000, 2 * MIB + 5000) == MEMFS_OK);
	CHECK(memfs_block_read(block, 40 * MIB, back, (uint32_t)(8 * MIB)) == MEMFS_OK);
	CHECK(memcmp(back, data, 1000) == 0);
	CHECK(all_zero(back + 1000, 2 * MIB + 5000));
	CHECK(memcmp(back + 1000 + 2 * MIB + 5000, data + 1000 + 2 * MIB + 5000, 8 * MIB - 1000 - 2 * MIB - 5000) == 0);
	CHECK(memfs_resident_bytes(fs) <= written - 2 * MIB + 8192);

	/* Whole-disk TRIM (what format and Optimize-Volume -ReTrim send) is fast
	 * because only existing page groups are visited. */
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);
	CHECK(memfs_block_unmap(block, 0, TIB) == MEMFS_OK);
	QueryPerformanceCounter(&stop);
	CHECK((double)(stop.QuadPart - start.QuadPart) / (double)frequency.QuadPart < 1.0);
	CHECK(memfs_resident_bytes(fs) < MIB);
	CHECK(memfs_block_read(block, 40 * MIB, back, (uint32_t)(8 * MIB)) == MEMFS_OK && all_zero(back, 8 * MIB));

	/* Zero-length and sub-page unmaps. */
	CHECK(memfs_block_write(block, 4096, data, 4096) == MEMFS_OK);
	CHECK(memfs_block_unmap(block, 4096 + 100, 0) == MEMFS_OK);
	CHECK(memfs_block_unmap(block, 4096 + 100, 200) == MEMFS_OK);
	CHECK(memfs_block_read(block, 4096, back, 4096) == MEMFS_OK);
	CHECK(memcmp(back, data, 100) == 0 && all_zero(back + 100, 200) && memcmp(back + 300, data + 300, 4096 - 300) == 0);

	memfs_block_destroy(block);
	memfs_destroy(fs);
	free(data);
	free(back);
}

/* Fixed capacity limits resident memory; a refused write changes nothing. */
static void test_capacity(void) {
	Memfs* fs = create_fs(8 * MIB, false, false);
	MemfsBlock* block = NULL;
	uint8_t* data = malloc(4 * MIB);
	uint8_t* back = malloc(4 * MIB);
	uint8_t* before = malloc(4 * MIB);

	CHECK(data && back && before);
	CHECK(memfs_block_create(fs, 100 * GIB, 0, &block) == MEMFS_OK);
	fill_pattern(data, 4 * MIB, 11);
	CHECK(memfs_block_write(block, 0, data, (uint32_t)(4 * MIB)) == MEMFS_OK);
	CHECK(memfs_block_read(block, 10 * GIB, before, (uint32_t)(4 * MIB)) == MEMFS_OK);
	CHECK(memfs_block_write(block, 10 * GIB, data, (uint32_t)(4 * MIB)) == MEMFS_ERR_NO_SPACE ||
		  memfs_block_write(block, 20 * GIB, data, (uint32_t)(4 * MIB)) == MEMFS_ERR_NO_SPACE);
	CHECK(memfs_resident_bytes(fs) <= 8 * MIB + MIB);
	/* Freeing space through unmap makes room again. */
	CHECK(memfs_block_unmap(block, 0, 100 * GIB) == MEMFS_OK);
	CHECK(memfs_block_write(block, 20 * GIB, data, (uint32_t)(4 * MIB)) == MEMFS_OK);
	CHECK(memfs_block_read(block, 20 * GIB, back, (uint32_t)(4 * MIB)) == MEMFS_OK && memcmp(back, data, 4 * MIB) == 0);
	memfs_block_destroy(block);
	memfs_destroy(fs);
	free(data);
	free(back);
	free(before);
}

/* Fixed capacity counts stored data: a disk exactly as large as the capacity
 * can be filled completely (encrypted, so heap use exceeds the data), and
 * rewriting stored pages on the full disk still succeeds. A disk filling up
 * must surface as "disk full" in NTFS, never as a device error. */
static void test_full_disk_rewrites(void) {
	const uint64_t size = 16 * MIB;
	Memfs* fs = create_fs(size, true, true);
	MemfsBlock* block = NULL;
	uint8_t* data = malloc(4 * MIB);
	uint8_t* back = malloc(4 * MIB);
	uint64_t offset;

	CHECK(data && back);
	CHECK(memfs_block_create(fs, size, 0, &block) == MEMFS_OK);
	if (!data || !back || !block)
		goto done;
	for (offset = 0; offset < size; offset += 4 * MIB) {
		fill_pattern(data, 4 * MIB, (uint32_t)(offset >> 20) + 1U);
		CHECK(memfs_block_write(block, offset, data, (uint32_t)(4 * MIB)) == MEMFS_OK);
	}
	CHECK(memfs_block_stored_pages(block) == size / 4096U);
	CHECK(memfs_resident_bytes(fs) > size); /* headers + AEAD tags */
	for (offset = 0; offset < size; offset += 4 * MIB) {
		fill_pattern(data, 4 * MIB, (uint32_t)(offset >> 20) + 100U);
		CHECK(memfs_block_write(block, offset, data, (uint32_t)(4 * MIB)) == MEMFS_OK);
		CHECK(memfs_block_read(block, offset, back, (uint32_t)(4 * MIB)) == MEMFS_OK &&
			  memcmp(back, data, 4 * MIB) == 0);
	}
	/* Zeros free pages; their capacity is then available again. */
	memset(data, 0, MIB);
	CHECK(memfs_block_write(block, 0, data, (uint32_t)MIB) == MEMFS_OK);
	CHECK(memfs_block_stored_pages(block) == (size - MIB) / 4096U);
	CHECK(memfs_block_unmap(block, MIB, MIB) == MEMFS_OK);
	CHECK(memfs_block_stored_pages(block) == (size - 2 * MIB) / 4096U);

done:
	memfs_block_destroy(block);
	memfs_destroy(fs);
	free(data);
	free(back);
}

static void test_codecs(void) {
	unsigned mode;

	for (mode = 1; mode <= 3; mode++) {
		Memfs* fs = create_fs(64 * MIB, (mode & 1U) != 0, (mode & 2U) != 0);
		MemfsBlock* block = NULL;
		uint8_t* data = malloc(4 * MIB);
		uint8_t* back = malloc(4 * MIB);
		size_t i;

		CHECK(data && back);
		CHECK(memfs_block_create(fs, 10 * GIB, 0, &block) == MEMFS_OK);
		/* Compressible text-like content. */
		for (i = 0; i < 4 * MIB; i++)
			data[i] = (uint8_t)("RowDesk memfs block "[i % 20]);
		CHECK(memfs_block_write(block, 3 * GIB + 512, data, (uint32_t)(4 * MIB)) == MEMFS_OK);
		CHECK(memfs_block_read(block, 3 * GIB + 512, back, (uint32_t)(4 * MIB)) == MEMFS_OK);
		CHECK(memcmp(data, back, 4 * MIB) == 0);
		if (mode & 1U)
			CHECK(memfs_resident_bytes(fs) < 2 * MIB);
		CHECK(memfs_block_unmap(block, 0, 10 * GIB) == MEMFS_OK && memfs_resident_bytes(fs) < MIB);
		memfs_block_destroy(block);
		memfs_destroy(fs);
		free(data);
		free(back);
	}
}

typedef struct Worker {
	MemfsBlock* block;
	uint32_t id;
	int errors;
} Worker;

static DWORD WINAPI worker_main(LPVOID parameter) {
	Worker* worker = parameter;
	uint8_t* data = malloc(256 * 1024);
	uint8_t* back = malloc(256 * 1024);
	uint32_t round;

	if (!data || !back) {
		worker->errors++;
		free(data);
		free(back);
		return 0;
	}
	for (round = 0; round < 64; round++) {
		/* Interleaved regions: neighbouring workers share stripes. */
		uint64_t offset = ((uint64_t)round * 8U + worker->id) * 384ULL * 1024ULL;

		fill_pattern(data, 256 * 1024, worker->id * 1000U + round);
		if (memfs_block_write(worker->block, offset, data, 256 * 1024) != MEMFS_OK ||
			memfs_block_read(worker->block, offset, back, 256 * 1024) != MEMFS_OK ||
			memcmp(data, back, 256 * 1024) != 0)
			worker->errors++;
		if ((round & 7U) == 7U && memfs_block_unmap(worker->block, offset, 256 * 1024) != MEMFS_OK)
			worker->errors++;
	}
	free(data);
	free(back);
	return 0;
}

static void test_concurrency(void) {
	Memfs* fs = create_fs(512 * MIB, true, false);
	MemfsBlock* block = NULL;
	Worker workers[8];
	HANDLE threads[8];
	uint32_t i;

	CHECK(memfs_block_create(fs, 64 * GIB, 0, &block) == MEMFS_OK);
	for (i = 0; i < 8; i++) {
		workers[i].block = block;
		workers[i].id = i;
		workers[i].errors = 0;
		threads[i] = CreateThread(NULL, 0, worker_main, &workers[i], 0, NULL);
		CHECK(threads[i] != NULL);
	}
	WaitForMultipleObjects(8, threads, TRUE, INFINITE);
	for (i = 0; i < 8; i++) {
		CHECK(workers[i].errors == 0);
		CloseHandle(threads[i]);
	}
	memfs_block_destroy(block);
	memfs_destroy(fs);
}

int main(void) {
	test_arguments();
	test_sparse_round_trip();
	test_unmap();
	test_capacity();
	test_full_disk_rewrites();
	test_codecs();
	test_concurrency();
	if (failures) {
		fprintf(stderr, "%d of %d block checks failed\n", failures, checks);
		return 1;
	}
	printf("%d block checks passed\n", checks);
	return 0;
}
