#pragma once

#include <Windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
#include "memfs_alloc.h"

#define MEMFS_ALLOCATION_UNIT 512U
#define MEMFS_MAX_NAME 255U

// 小目录只用 treap；达到该规模后再启用 hash 加速精确查找。
#define MEMFS_DIR_HASH_THRESHOLD 256U
#define MEMFS_DIR_HASH_LOAD_PERCENT 85U

// 极小文件 resident storage：1/2/4/8B class，8B 以上再按 8B 对齐。
// Windows AllocationSize 仍按 512B 对外报告。
#define MEMFS_SMALL_GRANULE 8U
#define MEMFS_SMALL_LIMIT 4096U
#define MEMFS_COMPRESSION_SKIP_SCORE 4
#define MEMFS_COMPRESSION_CONTEXT_LANES 16U

// 大文件按 4KB logical page 管理，一个二级 group 覆盖 1MB 文件范围。
#define MEMFS_PAGE_SHIFT 12U
#define MEMFS_PAGE_SIZE (1U << MEMFS_PAGE_SHIFT)
#define MEMFS_PAGE_MASK (MEMFS_PAGE_SIZE - 1U)
#define MEMFS_PAGES_PER_GROUP 256U
#define MEMFS_PAGE_GROUP_SHIFT 8U
#define MEMFS_PAGE_GROUP_MASK (MEMFS_PAGES_PER_GROUP - 1U)
#define MEMFS_PAGE_GROUP_WORDS (MEMFS_PAGES_PER_GROUP / 64U)
#define MEMFS_PAGE_GROUP_BYTES ((uint64_t)MEMFS_PAGE_SIZE * MEMFS_PAGES_PER_GROUP)

#define MEMFS_ENCRYPTION_KEY_SIZE 32U
#define MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE 16U

enum {
	MEMFS_PAGE_COMPRESSED = 0x01,
	MEMFS_PAGE_ENCRYPTED = 0x02,
	MEMFS_PAGE_AES_GCM = 0x04,
};

typedef enum MemfsResult {
	MEMFS_OK = 0,
	MEMFS_ERR_NOT_FOUND,
	MEMFS_ERR_PATH_NOT_FOUND,
	MEMFS_ERR_EXISTS,
	MEMFS_ERR_NOT_DIRECTORY,
	MEMFS_ERR_IS_DIRECTORY,
	MEMFS_ERR_NOT_EMPTY,
	MEMFS_ERR_NO_SPACE,
	MEMFS_ERR_NO_MEMORY,
	MEMFS_ERR_INVALID,
	MEMFS_ERR_ACCESS,
	MEMFS_ERR_DATA
} MemfsResult;

typedef struct Memfs Memfs;
typedef struct MemfsNode MemfsNode;
typedef struct MemfsStorageMeta MemfsStorageMeta;
typedef struct MemfsDir MemfsDir;
typedef struct MemfsDirHash MemfsDirHash;
typedef struct MemfsSecurity MemfsSecurity;
typedef struct MemfsPage MemfsPage;
typedef struct MemfsPageGroup MemfsPageGroup;
typedef struct MemfsPageGroupEntry MemfsPageGroupEntry;

typedef struct MemfsCompressionLane {
	SRWLOCK lock;
	void* context;
} MemfsCompressionLane;

typedef struct MemfsOptions {
	uint64_t capacity;
	bool capacity_auto;
	/* Auto capacity only: system commit held from the start, so this much
	 * can always be stored; beyond it the volume grows with free memory. */
	uint64_t auto_reserve_bytes;
	const wchar_t* volume_label;
	bool compression_enabled;
	int compression_level;
	bool encryption_enabled;
	const uint8_t* encryption_key;
	size_t encryption_key_size;
	/* Block-device backing store: file sizes are virtual disk extents, so
	 * they are not charged to the quota. Capacity applies to resident page
	 * memory instead (memfs_block_capacity_allows). */
	bool block_backing;
} MemfsOptions;

#define MEMFS_AUTO_HARD_MARGIN_BYTES (256ULL * 1024ULL * 1024ULL)
#define MEMFS_AUTO_SOFT_MARGIN_BYTES (512ULL * 1024ULL * 1024ULL)
#define MEMFS_AUTO_DEFAULT_RESERVE_BYTES (1024ULL * 1024ULL * 1024ULL)

/*
 * Runtime statistics are a lock-safe aggregate, not a globally atomic instant.
 * Individual allocator shards and scalar counters are sampled sequentially.
 * Under concurrent I/O/allocation, cross-field relationships are therefore
 * approximate; collect while quiescent when an exact baseline is required.
 */
typedef struct MemfsRuntimeStats {
	uint64_t logical_used_bytes;
	uint64_t resident_bytes;
	uint64_t capacity_bytes;
	uint64_t free_bytes;
	uint64_t auto_allowance_bytes;
	uint64_t auto_hard_margin_bytes;
	uint64_t auto_soft_margin_bytes;
	uint64_t allocator_live_bytes;
	uint64_t allocator_live_objects;
	uint64_t allocator_reserved_bytes;
	uint64_t allocator_committed_bytes;
	uint64_t allocator_physical_bytes;
	uint64_t allocator_scavenged_bytes;
	uint64_t allocator_scavenge_count;
	uint64_t area_cached_bytes;
	uint32_t slab_count;
	uint32_t area_count;
	uint32_t area_cached_count;
	bool capacity_auto;
} MemfsRuntimeStats;

struct MemfsDirHash {
	MemfsNode** slots;
	uint32_t capacity;
	uint32_t count;
	MemfsAllocator* owner;
};

struct MemfsDir {
	MemfsNode* root;
	MemfsDirHash* hash;
	uint32_t child_count;
};

// 大多数节点继承完全相同的 ACL，使用引用计数共享，避免每节点复制安全描述符。
struct MemfsSecurity {
	volatile LONG ref_count;
	uint32_t size;
	MemfsAllocator* owner;
	uint8_t data[];
};

// encoded blob header。raw/compressed payload 存在 data 中。
// 加密 payload 前 8B 保存 nonce sequence；flags 记录实际 AEAD 算法。
// AES-GCM 使用每挂载派生子密钥 + 64-bit sequence nonce；无硬件支持时回落 XChaCha20-Poly1305。
struct MemfsPage {
	uint16_t stored_size;
	uint16_t plain_size;
	uint8_t flags;
	uint8_t reserved[3];
	uint8_t data[];
};

// 自适应 compact group：
// bitmap 表示 256 个 logical page 是否存在；pages[] 只保存实际存在 page 的紧凑指针。
// sparse group 不再固定付 2KB pointer table。
struct MemfsPageGroup {
	uint64_t bitmap[MEMFS_PAGE_GROUP_WORDS];
	union {
		MemfsPage** pages;
		MemfsPage* inline_page;
	};
	uint16_t page_count;
	uint16_t page_capacity;
};

struct MemfsPageGroupEntry {
	uint64_t index;
	MemfsPageGroup* group;
};

#if defined(_WIN64)
_Static_assert(sizeof(MemfsDir) == 24,
	"MemfsDir must stay in the allocator 24-byte size class");
_Static_assert(sizeof(MemfsDirHash) == 24,
	"MemfsDirHash must stay in the allocator 24-byte size class");
_Static_assert(offsetof(MemfsSecurity, data) == 16,
	"MemfsSecurity header must stay 16 bytes");
_Static_assert(offsetof(MemfsPage, data) == 8,
	"MemfsPage encoded header must stay 8 bytes");
_Static_assert(sizeof(MemfsPageGroup) == 48,
	"MemfsPageGroup must stay in the allocator 48-byte size class");
_Static_assert(sizeof(MemfsPageGroupEntry) == 16,
	"MemfsPageGroupEntry must stay in the allocator 16-byte size class");
#endif

MemfsNode* memfs_node_metadata(MemfsNode* node);
MemfsSecurity* memfs_node_get_security(MemfsNode* node);
uint64_t memfs_node_get_creation_time(const MemfsNode* node);
uint64_t memfs_node_get_last_access_time(const MemfsNode* node);
uint64_t memfs_node_get_last_write_time(const MemfsNode* node);
uint64_t memfs_node_get_change_time(const MemfsNode* node);
uint64_t memfs_node_index_number(const MemfsNode* node);
void memfs_node_set_creation_time(MemfsNode* node, uint64_t value);
void memfs_node_set_last_access_time(MemfsNode* node, uint64_t value);
void memfs_node_set_last_write_time(MemfsNode* node, uint64_t value);
void memfs_node_set_change_time(MemfsNode* node, uint64_t value);

uint32_t memfs_node_page_group_count(const MemfsNode* node);
uint32_t memfs_node_page_group_capacity(const MemfsNode* node);
uint64_t memfs_node_page_group_index(const MemfsNode* node, uint32_t position);
MemfsPageGroup* memfs_node_page_group(const MemfsNode* node, uint32_t position);
MemfsPage* memfs_page_group_page(const MemfsPageGroup* group, uint32_t position);
int8_t memfs_node_compression_score(const MemfsNode* node);

struct MemfsNode {
	Memfs* fs;
	MemfsNode* parent;

	// namespace 中是 treap links；节点 unlink 后这三个字段会复用为 orphan 链。
	MemfsNode* tree_left;
	MemfsNode* tree_right;
	MemfsNode* tree_parent;

	wchar_t* name;

	// 目录索引、tiny storage、paged storage 三种状态互斥，共用一个指针宽度。
	union {
		MemfsDir* dir;
		MemfsPage* small_page;
		uint8_t small_inline_data[sizeof(MemfsPage*)];
		MemfsStorageMeta* storage_meta;
	};

	uint64_t file_size;
	uint64_t allocation_size;

	union {
		MemfsSecurity* security;
		/* ADS shares the owner's ACL. Use the otherwise unused slot to
		 * distinguish live FILE_OBJECTs from delayed Close references. */
		volatile LONG stream_active_opens;
	};
	uint64_t creation_time;
	uint64_t last_access_time;
	uint64_t last_write_time;
	uint64_t change_time;

	uint32_t attributes;
	uint32_t open_count; // protected by fs->lifetime_lock after publication
	uint32_t name_hash;
	uint16_t small_capacity;
	uint8_t small_inline : 1;
	uint8_t deleted : 1;
	uint8_t paged_storage : 1;
	uint8_t named_stream : 1;
	// 最后一次数据修改之后，曾通过 SetBasicInfo 显式设置 LastWriteTime。
	// 与其他标志位同字节，只在持有本节点 io 锁（独占）时读写；命名流不使用。
	uint8_t explicit_write_time : 1;
	uint8_t reserved_flags : 3;
	int8_t compression_score;
};

#if defined(_WIN64)
_Static_assert(sizeof(MemfsNode) == 128,
	"MemfsNode must stay in the allocator 128-byte size class");
#endif

#define MEMFS_NODE_IS_DIRECTORY(node) ((node) != NULL && 0 != ((node)->attributes & FILE_ATTRIBUTE_DIRECTORY))

struct Memfs {
	MemfsAllocator allocator;

	MemfsNode* root;

	/* ADS nodes are indexed by their stable owner pointer, not the path.
	 * No per-file size increase: ordinary nodes remain 128 bytes. Stream
	 * parent pins its owner; tree_left is the bucket link until unlink.
	 * Namespace/stream index access requires the external namespace guard. */
	MemfsNode* stream_buckets[64];
	bool destroying;

	// 仅保存已经从 namespace 移除但仍被 open handle 引用的节点。
	// orphan 节点复用 tree_left/tree_right 作为 prev/next。
	MemfsNode* orphan_head;
	// FINE does NOT guard asynchronous Close. Serialize only handle counts and
	// orphan publication/removal; ordinary file data I/O never takes this lock.
	SRWLOCK lifetime_lock;

	// Cross-file accounting is atomic; handle lifetime is guarded separately.
	uint64_t capacity;
	bool capacity_auto;
	bool block_backing;
	volatile LONG64 used_bytes;
	volatile LONG64 resident_bytes;
	volatile LONG64 pressure_last_scavenge_tick;
	SRWLOCK auto_available_refresh_lock;
	/* Snapshot fields are protected by auto_available_refresh_lock. */
	uint64_t auto_available_cached_bytes;
	uint64_t auto_available_cached_commit_total;
	uint64_t auto_available_sample_qpc;
	uint64_t auto_available_cache_deadline_qpc;
	uint64_t auto_available_cache_interval_qpc;
	uint64_t treap_seed;

	bool compression_enabled;
	bool encryption_enabled;
	bool encryption_aes_gcm;
	int compression_level;

	MemfsCompressionLane compression_lanes[MEMFS_COMPRESSION_CONTEXT_LANES];
	MemfsCompressionLane decompression_lanes[MEMFS_COMPRESSION_CONTEXT_LANES];

	uint8_t encryption_key[MEMFS_ENCRYPTION_KEY_SIZE];
	uint8_t encryption_aes_key[MEMFS_ENCRYPTION_KEY_SIZE];
	SRWLOCK encryption_aes_epoch_lock;
	uint64_t encryption_aes_epoch;
	uint8_t encryption_aes_epoch_key[MEMFS_ENCRYPTION_KEY_SIZE];
	bool encryption_aes_epoch_valid;
	uint8_t encryption_nonce_prefix[MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE];
	volatile LONG64 encryption_nonce_counter;

	wchar_t volume_label[32];
	uint16_t volume_label_bytes;
};

uint64_t memfs_now(void);
uint64_t memfs_align_allocation(uint64_t size);
uint64_t memfs_free_bytes(Memfs* fs);
uint64_t memfs_auto_allowance_bytes(Memfs* fs);
uint64_t memfs_resident_bytes(Memfs* fs);
uint64_t memfs_node_resident_bytes(const MemfsNode* node);

// Allocator committed/physical backing. This is not logical used_bytes and is
// not resident payload; use it for capacity policy that needs real backing.
uint64_t memfs_committed_bytes(Memfs* fs);
uint64_t memfs_physical_bytes(Memfs* fs);
// Concurrent snapshot semantics are documented on MemfsRuntimeStats above.
void memfs_get_runtime_stats(Memfs* fs, MemfsRuntimeStats* stats);

#if defined(MEMFS_CAPACITY_TESTING)
typedef struct MemfsCapacityTestHooks {
	uint64_t (*available)(void* context);
	bool (*clock)(void* context, uint64_t* ticks);
	void* context;
} MemfsCapacityTestHooks;
void memfs_test_capacity_set_hooks(const MemfsCapacityTestHooks* hooks);
uint64_t memfs_test_capacity_available(Memfs* fs, bool force_refresh);
#endif

#if !defined(NDEBUG)
void memfs_test_set_system_available_bytes(uint64_t bytes);
void memfs_test_clear_system_available_bytes(void);
uint64_t memfs_test_adjust_cached_available(
	uint64_t sampled_available,
	uint64_t sampled_committed,
	uint64_t current_committed);
void memfs_test_force_xchacha(bool force);
bool memfs_test_page_info(MemfsNode* node,
                          uint64_t page_index,
                          bool* is_raw,
                          size_t* heap_bytes,
                          uintptr_t* allocation_address);
bool memfs_test_next_nonce_sequence(Memfs* fs, uint64_t* sequence);
#endif

MemfsResult memfs_create(uint64_t capacity, const wchar_t* volume_label, Memfs** out_fs);
MemfsResult memfs_create_ex(const MemfsOptions* options, Memfs** out_fs);
void memfs_destroy(Memfs* fs);

MemfsResult memfs_lookup_path(Memfs* fs, const wchar_t* path, MemfsNode** out_node);
MemfsResult memfs_lookup_parent(Memfs* fs, const wchar_t* path, MemfsNode** out_parent,
								wchar_t name[MEMFS_MAX_NAME + 1]);

MemfsNode* memfs_dir_lookup(MemfsNode* dir, const wchar_t* name);
MemfsNode* memfs_dir_first(MemfsNode* dir);
MemfsNode* memfs_dir_upper_bound(MemfsNode* dir, const wchar_t* marker);
MemfsNode* memfs_dir_next(MemfsNode* node);

MemfsResult memfs_node_create(Memfs* fs, MemfsNode* parent, const wchar_t* name, bool directory, uint32_t attributes,
							  PSECURITY_DESCRIPTOR security, uint64_t allocation_size, MemfsNode** out_node);

/* Named data streams share owner metadata/ACL, but have independent storage.
 * Callers serialize namespace operations; Close remains independently safe. */
MemfsResult memfs_lookup_stream_parent(Memfs* fs, const wchar_t* path,
    MemfsNode** owner, wchar_t name[MEMFS_MAX_NAME + 1]);
MemfsNode* memfs_stream_first(MemfsNode* owner);
MemfsNode* memfs_stream_next(MemfsNode* stream);
MemfsNode* memfs_stream_lookup(MemfsNode* owner, const wchar_t* name);
MemfsResult memfs_stream_create(MemfsNode* owner, const wchar_t* name,
    uint64_t allocation_size, MemfsNode** out_node);
MemfsResult memfs_stream_rename(MemfsNode* node, MemfsNode* owner,
    const wchar_t* name, bool replace);
void memfs_stream_unlink_all(MemfsNode* owner, bool only_closed);

// Retaining requires a live handle or an externally guarded namespace lookup.
// Release/unlink/replace coordinate lifetime internally; destroy requires quiescence.
void memfs_node_open(MemfsNode* node);
void memfs_node_close(MemfsNode* node);
MemfsResult memfs_node_unlink(MemfsNode* node);
MemfsResult memfs_node_rename(MemfsNode* node, MemfsNode* new_parent, const wchar_t* new_name, bool replace_if_exists);

MemfsResult memfs_node_set_file_size(MemfsNode* node, uint64_t new_size);
MemfsResult memfs_node_set_allocation_size(MemfsNode* node, uint64_t new_size);
MemfsResult memfs_node_read(MemfsNode* node, void* buffer, uint64_t offset, uint32_t length, uint32_t* bytes_read);
MemfsResult memfs_node_write(MemfsNode* node, const void* buffer, uint64_t offset, uint32_t length, bool write_to_end,
							 bool constrained_io, uint32_t* bytes_written);

/* Frees whole pages in [offset, offset + length) and zeroes partial edge
 * pages, without changing the file size. Only existing page groups are
 * visited, so punching a huge sparse range is cheap. Caller serializes I/O
 * on the node exactly as for memfs_node_write. */
MemfsResult memfs_node_punch_hole(MemfsNode* node, uint64_t offset, uint64_t length);
/* Block-backing volumes: may `bytes` more resident page memory be used?
 * Fixed capacity limits resident bytes; auto capacity follows free memory. */
bool memfs_block_capacity_allows(Memfs* fs, uint64_t bytes);

MemfsResult memfs_node_replace_security(MemfsNode* node, PSECURITY_DESCRIPTOR security, uint32_t security_size);

bool memfs_node_is_directory(const MemfsNode* node);
bool memfs_node_is_ancestor(const MemfsNode* ancestor, const MemfsNode* node);
