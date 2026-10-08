#include "memfs_core.h"

#include <stdio.h>
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

static Memfs* create_fs(unsigned mode) {
	MemfsOptions options = {0};
	Memfs* fs = NULL;

	options.capacity = 32ULL * 1024ULL * 1024ULL;
	options.volume_label = L"STORAGE-REGRESSION";
	options.compression_enabled = (mode & 1U) != 0;
	options.compression_level = 1;
	options.encryption_enabled = (mode & 2U) != 0;
	CHECK(memfs_create_ex(&options, &fs) == MEMFS_OK);
	CHECK(fs != NULL);
	return fs;
}

static MemfsNode* create_file(Memfs* fs, const wchar_t* name) {
	MemfsNode* node = NULL;
	CHECK(memfs_node_create(fs, fs->root, name, false, FILE_ATTRIBUTE_NORMAL,
		NULL, 0, &node) == MEMFS_OK);
	CHECK(node != NULL);
	return node;
}

static void release_file(MemfsNode* node) {
	if (node == NULL)
		return;
	CHECK(memfs_node_unlink(node) == MEMFS_OK);
	memfs_node_close(node);
}

static bool is_zero(const uint8_t* data, size_t size) {
	for (size_t i = 0; i < size; ++i) {
		if (data[i] != 0)
			return false;
	}
	return true;
}

/* A short overwrite changes bytes inside EOF, never the resident tail. */
static void test_small_overwrite_preserves_tail(Memfs* fs) {
	MemfsNode* node = create_file(fs, L"small-overwrite.bin");
	uint8_t expected[100];
	uint8_t actual[100];
	uint8_t patch = 0xe7;
	uint32_t transferred = 0;

	if (node == NULL)
		return;
	for (size_t i = 0; i < sizeof(expected); ++i)
		expected[i] = (uint8_t)(i + 1U);
	CHECK(memfs_node_write(node, expected, 0, sizeof(expected), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(expected));
	CHECK(memfs_node_write(node, &patch, 0, 1, false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == 1);
	expected[0] = patch;
	CHECK(node->file_size == sizeof(expected));
	memset(actual, 0xff, sizeof(actual));
	CHECK(memfs_node_read(node, actual, 0, sizeof(actual), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(actual));
	CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
	release_file(node);
}

/* Sparse growth need not promote a small resident head to paged storage. */
static void test_sparse_small_truncate_preserves_head(Memfs* fs) {
	MemfsNode* node = create_file(fs, L"small-sparse-truncate.bin");
	uint8_t expected[100];
	uint8_t actual[5000];
	uint32_t transferred = 0;

	if (node == NULL)
		return;
	memset(expected, 0x5a, sizeof(expected));
	CHECK(memfs_node_write(node, expected, 0, sizeof(expected), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(expected));
	CHECK(memfs_node_set_file_size(node, MEMFS_PAGE_GROUP_BYTES) == MEMFS_OK);
	CHECK(memfs_node_set_file_size(node, sizeof(actual)) == MEMFS_OK);
	CHECK(node->file_size == sizeof(actual));
	memset(actual, 0xff, sizeof(actual));
	CHECK(memfs_node_read(node, actual, 0, sizeof(actual), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(actual));
	CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
	CHECK(is_zero(actual + sizeof(expected), sizeof(actual) - sizeof(expected)));
	release_file(node);
}

/* A group can temporarily become empty inside one atomic write. */
static void test_group_zero_prefix_nonzero_tail(Memfs* fs) {
	MemfsNode* node = create_file(fs, L"group-zero-prefix.bin");
	uint8_t initial[2U * MEMFS_PAGE_SIZE];
	uint8_t expected[4U * MEMFS_PAGE_SIZE];
	uint8_t actual[4U * MEMFS_PAGE_SIZE];
	uint32_t transferred = 0;

	if (node == NULL)
		return;
	memset(initial, 0x31, sizeof(initial));
	memset(expected, 0, 2U * MEMFS_PAGE_SIZE);
	memset(expected + 2U * MEMFS_PAGE_SIZE, 0x72, MEMFS_PAGE_SIZE);
	memset(expected + 3U * MEMFS_PAGE_SIZE, 0xb5, MEMFS_PAGE_SIZE);
	CHECK(memfs_node_write(node, initial, 0, sizeof(initial), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(initial));
	CHECK(memfs_node_write(node, expected, 0, sizeof(expected), false, false,
		&transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(expected));
	CHECK(node->file_size == sizeof(expected));
	memset(actual, 0xff, sizeof(actual));
	CHECK(memfs_node_read(node, actual, 0, sizeof(actual), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(actual));
	CHECK(memcmp(actual, expected, sizeof(expected)) == 0);
	CHECK(memfs_node_page_group_count(node) == 1);
	CHECK(memfs_node_resident_bytes(node) > 0);
	release_file(node);
}

#if !defined(NDEBUG)
/* Failure after preparation must either keep all old bytes or commit all new bytes. */
static void test_group_shrink_failure_atomicity(Memfs* fs) {
	MemfsNode* node = create_file(fs, L"group-shrink-failure.bin");
	uint8_t original[4U * MEMFS_PAGE_SIZE];
	uint8_t expected[4U * MEMFS_PAGE_SIZE];
	uint8_t actual[4U * MEMFS_PAGE_SIZE];
	uint32_t transferred = 0;
	MemfsResult result;

	if (node == NULL)
		return;
	memset(original, 0x31, 2U * MEMFS_PAGE_SIZE);
	memset(original + 2U * MEMFS_PAGE_SIZE, 0, 2U * MEMFS_PAGE_SIZE);
	memset(expected, 0, MEMFS_PAGE_SIZE);
	memset(expected + MEMFS_PAGE_SIZE, 0x82, 3U * MEMFS_PAGE_SIZE);
	CHECK(memfs_node_write(node, original, 0, 2U * MEMFS_PAGE_SIZE,
		false, false, &transferred) == MEMFS_OK);
	CHECK(memfs_node_set_file_size(node, sizeof(original)) == MEMFS_OK);

	/* Vector + 3 encoded pages + initial group reserve succeed. */
	memfs_allocator_test_fail_after(MEMFS_ALLOC_FAIL_GENERIC, 5, 1);
	transferred = 1234;
	result = memfs_node_write(node, expected, 0, sizeof(expected), false, false,
		&transferred);
	memfs_allocator_test_clear_failures();
	CHECK(result == MEMFS_OK || result == MEMFS_ERR_NO_MEMORY);
	CHECK(transferred == (result == MEMFS_OK ? sizeof(expected) : 0));
	CHECK(node->file_size == sizeof(original));
	memset(actual, 0xff, sizeof(actual));
	CHECK(memfs_node_read(node, actual, 0, sizeof(actual), &transferred) == MEMFS_OK);
	CHECK(transferred == sizeof(actual));
	CHECK(memcmp(actual, result == MEMFS_OK ? expected : original,
		sizeof(actual)) == 0);
	release_file(node);
}
#endif

int main(void) {
	static const char* modes[] = {"raw", "compression", "encryption", "compression+encryption"};
	for (unsigned mode = 0; mode < 4U; ++mode) {
		Memfs* fs;
		printf("== storage regression: %s ==\n", modes[mode]);
		fs = create_fs(mode);
		if (fs == NULL)
			continue;
		test_small_overwrite_preserves_tail(fs);
		test_sparse_small_truncate_preserves_head(fs);
		test_group_zero_prefix_nonzero_tail(fs);
#if !defined(NDEBUG)
		test_group_shrink_failure_atomicity(fs);
#endif
		CHECK((uint64_t)fs->used_bytes == 0);
		CHECK(memfs_resident_bytes(fs) == 0);
		memfs_destroy(fs);
	}
	printf("memfs_storage_regression_test: checks=%d failures=%d => %s\n",
		checks, failures, failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
