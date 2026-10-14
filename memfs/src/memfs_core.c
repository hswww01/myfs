#include "memfs_core.h"
#include "memfs_object.h"

#include <intrin.h>
#include <sddl.h>
#include <sodium.h>
#include <zstd.h>

/* Shared temporary-directory policy. Authenticated users may create entries
 * here, but cannot delete other users' entries or rewrite this directory's
 * DACL. Only SYSTEM, administrators and the creator inherit file access.
 * The internal NULL-security create path also uses this template for --mkdir
 * bootstrap directories; ordinary WinFsp creates supply a caller-derived SD. */
#define MEMFS_DEFAULT_SDDL \
	L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" \
	L"(A;OICIIO;FA;;;CO)(A;;0x1201bf;;;AU)"

_Static_assert((MEMFS_COMPRESSION_CONTEXT_LANES & (MEMFS_COMPRESSION_CONTEXT_LANES - 1U)) == 0,
	"compression context lane count must be a power of two");

struct MemfsStorageMeta {
	MemfsPageGroupEntry* groups;
	uint32_t count;
	uint32_t capacity;
};

#if defined(_WIN64)
_Static_assert(sizeof(MemfsStorageMeta) == 16,
	"MemfsStorageMeta must stay in the allocator 16-byte size class");
#endif

MemfsNode* memfs_node_metadata(MemfsNode* node) {
    return node != NULL && node->named_stream ? node->parent : node;
}

MemfsSecurity* memfs_node_get_security(MemfsNode* node) {
    node = memfs_node_metadata(node);
    return node ? node->security : NULL;
}

uint64_t memfs_node_get_creation_time(const MemfsNode* node) {
	node = memfs_node_metadata((MemfsNode*)node);
	return node ? node->creation_time : 0;
}

uint64_t memfs_node_get_last_access_time(const MemfsNode* node) {
	node = memfs_node_metadata((MemfsNode*)node);
	return node ? node->last_access_time : 0;
}

uint64_t memfs_node_get_last_write_time(const MemfsNode* node) {
	node = memfs_node_metadata((MemfsNode*)node);
	return node ? node->last_write_time : 0;
}

uint64_t memfs_node_get_change_time(const MemfsNode* node) {
	node = memfs_node_metadata((MemfsNode*)node);
	return node ? node->change_time : 0;
}

static uint64_t memfs_mix64(uint64_t x) {
	x += 0x9e3779b97f4a7c15ULL;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

uint64_t memfs_node_index_number(const MemfsNode* node) {
	if (node == NULL || node->fs == NULL)
		return 0;

	/*
	 * Node addresses remain stable for the lifetime of an open file object.
	 * SplitMix64 is a permutation over 64 bits, so distinct live node
	 * addresses map to distinct opaque IDs for the same filesystem seed.
	 * Freed-node ID reuse is acceptable for this volatile filesystem.
	 */
	return memfs_mix64((uint64_t)(uintptr_t)node ^ node->fs->treap_seed);
}

void memfs_node_set_creation_time(MemfsNode* node, uint64_t value) {
	node = memfs_node_metadata(node);
	if (node)
		node->creation_time = value;
}

void memfs_node_set_last_access_time(MemfsNode* node, uint64_t value) {
	node = memfs_node_metadata(node);
	if (node)
		node->last_access_time = value;
}

void memfs_node_set_last_write_time(MemfsNode* node, uint64_t value) {
	node = memfs_node_metadata(node);
	if (node)
		node->last_write_time = value;
}

void memfs_node_set_change_time(MemfsNode* node, uint64_t value) {
	node = memfs_node_metadata(node);
	if (node)
		node->change_time = value;
}

#define MEMFS_AUTO_REFRESH_INTERVAL_MS 250ULL
#define MEMFS_AUTO_AVAILABLE_CACHE_INTERVAL_US 1000ULL

#if !defined(NDEBUG)
static volatile LONG64 g_memfs_test_system_available_bytes = -1;
static volatile LONG g_memfs_test_force_xchacha;

void memfs_test_set_system_available_bytes(uint64_t bytes) {
	InterlockedExchange64(&g_memfs_test_system_available_bytes, (LONG64)bytes);
}

void memfs_test_clear_system_available_bytes(void) {
	InterlockedExchange64(&g_memfs_test_system_available_bytes, -1);
}

void memfs_test_force_xchacha(bool force) {
	InterlockedExchange(&g_memfs_test_force_xchacha, force ? 1 : 0);
}
#endif

static uint64_t memfs_min_u64(uint64_t a, uint64_t b) {
	return a < b ? a : b;
}

#if defined(MEMFS_CAPACITY_TESTING)
static MemfsCapacityTestHooks g_memfs_capacity_hooks;

void memfs_test_capacity_set_hooks(const MemfsCapacityTestHooks* hooks) {
	/* Install/remove only while no filesystem/test worker is running. */
	if (hooks)
		g_memfs_capacity_hooks = *hooks;
	else
		memset(&g_memfs_capacity_hooks, 0, sizeof(g_memfs_capacity_hooks));
}
#endif

static bool memfs_capacity_clock(uint64_t* ticks) {
	LARGE_INTEGER now;
#if defined(MEMFS_CAPACITY_TESTING)
	if (g_memfs_capacity_hooks.clock)
		return g_memfs_capacity_hooks.clock(g_memfs_capacity_hooks.context, ticks);
#endif
	if (!QueryPerformanceCounter(&now) || now.QuadPart < 0)
		return false;
	*ticks = (uint64_t)now.QuadPart;
	return true;
}

static uint64_t memfs_system_available_bytes(void) {
	MEMORYSTATUSEX status;
#if defined(MEMFS_CAPACITY_TESTING)
	if (g_memfs_capacity_hooks.available)
		return g_memfs_capacity_hooks.available(g_memfs_capacity_hooks.context);
#endif
#if !defined(NDEBUG)
	{
		LONG64 forced = InterlockedCompareExchange64(
			&g_memfs_test_system_available_bytes, 0, 0);
		if (forced >= 0)
			return (uint64_t)forced;
	}
#endif
	status.dwLength = sizeof(status);
	if (!GlobalMemoryStatusEx(&status))
		return 0;
	return memfs_min_u64(status.ullAvailPhys, status.ullAvailPageFile);
}

static uint64_t memfs_adjust_cached_available(
	uint64_t sampled_available,
	uint64_t sampled_commit_total,
	uint64_t current_commit_total) {
	uint64_t growth;
	/* Cumulative gross commitments never decrease. Fail closed on wrap. */
	if (current_commit_total < sampled_commit_total)
		return 0;
	growth = current_commit_total - sampled_commit_total;
	return growth < sampled_available ? sampled_available - growth : 0;
}

#if !defined(NDEBUG)
uint64_t memfs_test_adjust_cached_available(
	uint64_t sampled_available,
	uint64_t sampled_committed,
	uint64_t current_committed) {
	return memfs_adjust_cached_available(
		sampled_available, sampled_committed, current_committed);
}
#endif

/* Caller holds the cache's shared or exclusive lock. */
static bool memfs_cached_available_locked(Memfs* fs, uint64_t now, uint64_t* available) {
	if (now < fs->auto_available_sample_qpc ||
		now >= fs->auto_available_cache_deadline_qpc)
		return false;
	*available = memfs_adjust_cached_available(
		fs->auto_available_cached_bytes,
		fs->auto_available_cached_commit_total,
		memfs_allocator_commit_total_bytes(&fs->allocator));
	return true;
}

static uint64_t memfs_auto_capacity_available_bytes(Memfs* fs, bool force_refresh) {
	uint64_t now;
	uint64_t available;
	uint64_t commit_total;
	uint64_t sampled_at;
	bool valid;

#if !defined(NDEBUG)
	/* Only explicit legacy pressure overrides bypass caching. Normal Debug
	 * and the dedicated instrumented Release tests use the production path. */
	if (InterlockedCompareExchange64(&g_memfs_test_system_available_bytes, 0, 0) >= 0)
		return memfs_system_available_bytes();
#endif
	if (fs == NULL || fs->auto_available_cache_interval_qpc == 0)
		return memfs_system_available_bytes();

	if (!force_refresh) {
		AcquireSRWLockShared(&fs->auto_available_refresh_lock);
		valid = memfs_capacity_clock(&now) && memfs_cached_available_locked(fs, now, &available);
		ReleaseSRWLockShared(&fs->auto_available_refresh_lock);
		if (valid)
			return available;
	}

	AcquireSRWLockExclusive(&fs->auto_available_refresh_lock);
	if (!memfs_capacity_clock(&sampled_at)) {
		fs->auto_available_cache_deadline_qpc = 0;
		available = memfs_system_available_bytes();
		ReleaseSRWLockExclusive(&fs->auto_available_refresh_lock);
		return available;
	}
	/* Refresh may have been completed by a thread ahead of us. */
	if (!force_refresh && memfs_cached_available_locked(fs, sampled_at, &available)) {
		ReleaseSRWLockExclusive(&fs->auto_available_refresh_lock);
		return available;
	}

	/* Sample gross commits BEFORE asking the OS. Growth during the query is
	 * debited too; free/reallocate churn cannot erase it via a net counter. */
	commit_total = memfs_allocator_commit_total_bytes(&fs->allocator);
	available = memfs_system_available_bytes();
	fs->auto_available_cached_bytes = available;
	fs->auto_available_cached_commit_total = commit_total;
	fs->auto_available_sample_qpc = sampled_at;
	fs->auto_available_cache_deadline_qpc =
		sampled_at <= UINT64_MAX - fs->auto_available_cache_interval_qpc
		? sampled_at + fs->auto_available_cache_interval_qpc : 0;
	/* The TTL starts before the OS query, not after a potentially slow one. */
	available = memfs_adjust_cached_available(available, commit_total,
		memfs_allocator_commit_total_bytes(&fs->allocator));
	ReleaseSRWLockExclusive(&fs->auto_available_refresh_lock);
	return available;
}

#if defined(MEMFS_CAPACITY_TESTING)
uint64_t memfs_test_capacity_available(Memfs* fs, bool force_refresh) {
	return memfs_auto_capacity_available_bytes(fs, force_refresh);
}
#endif

/* Growth beyond the reserve, from what the system has free. */
static uint64_t memfs_auto_system_allowance(uint64_t available) {
	/* The OS reports remaining available memory, so existing allocator backing
	 * and resident file data are already accounted for in this sample. */
	return available > MEMFS_AUTO_HARD_MARGIN_BYTES
		? available - MEMFS_AUTO_HARD_MARGIN_BYTES
		: 0;
}

static uint64_t memfs_auto_allowance_for_available(Memfs* fs, uint64_t available) {
	uint64_t reserved;
	uint64_t allowance;

	if (fs == NULL || !fs->capacity_auto)
		return 0;

	/* The unused part of the reserve is ours whatever the system has free. */
	reserved = memfs_allocator_reserve_available(&fs->allocator);
	allowance = memfs_auto_system_allowance(available);
	return allowance > UINT64_MAX - reserved ? UINT64_MAX : allowance + reserved;
}

uint64_t memfs_auto_allowance_bytes(Memfs* fs) {
	return memfs_auto_allowance_for_available(
		fs, memfs_system_available_bytes());
}

static bool memfs_auto_pressure_scavenge_due(Memfs* fs) {
	uint64_t now;
	LONG64 previous;

	if (fs == NULL)
		return false;

	now = GetTickCount64();
	previous = InterlockedCompareExchange64(
		&fs->pressure_last_scavenge_tick, 0, 0);
	if (previous > 0 &&
		now >= (uint64_t)previous &&
		now - (uint64_t)previous < MEMFS_AUTO_REFRESH_INTERVAL_MS) {
		return false;
	}

	return InterlockedCompareExchange64(
		&fs->pressure_last_scavenge_tick,
		(LONG64)now,
		previous) == previous;
}

static void memfs_auto_pressure_scavenge(Memfs* fs) {
	if (fs == NULL || !fs->capacity_auto)
		return;
	if (!memfs_auto_pressure_scavenge_due(fs))
		return;

	(void)memfs_allocator_scavenge(&fs->allocator);
}

static bool memfs_auto_capacity_allows(Memfs* fs, uint64_t request) {
	uint64_t available;
	uint64_t allowance;

	if (fs == NULL || !fs->capacity_auto)
		return true;
	if (request == 0)
		return true;

	available = memfs_auto_capacity_available_bytes(fs, false);
	allowance = memfs_auto_allowance_for_available(fs, available);

	/*
	 * Soft pressure is a reclaim hint, not an allocation failure. Reclaim only
	 * allocator-owned idle backing (empty slabs and cached area blocks), then
	 * recompute the hard allowance. If the request still cannot fit above the
	 * hard reserve, report NO_SPACE without touching file data.
	 */
	if (available <= MEMFS_AUTO_SOFT_MARGIN_BYTES || request > allowance) {
		memfs_auto_pressure_scavenge(fs);
		available = memfs_auto_capacity_available_bytes(fs, true);
		allowance = memfs_auto_allowance_for_available(fs, available);
	}

	return request <= allowance;
}

static bool memfs_capacity_allows(Memfs* fs, uint64_t request) {
	uint64_t used;
	uint64_t capacity;

	if (fs == NULL)
		return false;
	if (request == 0)
		return true;

	used = (uint64_t)fs->used_bytes;
	capacity = fs->capacity;

	if (fs->capacity_auto)
		return memfs_auto_capacity_allows(fs, request);

	return used <= capacity && request <= capacity - used;
}

static void memfs_dir_hash_free(MemfsDirHash* hash) {
	if (hash == NULL)
		return;

	if (hash->slots)
		memfs_allocator_free(hash->owner, hash->slots, (size_t)hash->capacity * sizeof(*hash->slots));
	memfs_allocator_free(hash->owner, hash, sizeof(*hash));
}

static void memfs_dir_destroy(MemfsDir* dir) {
	if (dir == NULL)
		return;

	if (dir->hash) {
		memfs_dir_hash_free(dir->hash);
		dir->hash = NULL;
	}
}
// Caller holds lifetime_lock, or all filesystem callers have quiesced.
static void memfs_orphan_insert(Memfs* fs, MemfsNode* node) {
	// orphan 已经不在 namespace treap 中，复用 tree_left/tree_right
	// 作为 prev/next，避免给每个普通节点额外保存一套全局链指针。
	node->tree_left = NULL;
	node->tree_right = fs->orphan_head;
	node->tree_parent = NULL;

	if (fs->orphan_head)
		fs->orphan_head->tree_left = node;

	fs->orphan_head = node;
}

static void memfs_orphan_remove(Memfs* fs, MemfsNode* node) {
	MemfsNode* prev = node->tree_left;
	MemfsNode* next = node->tree_right;

	if (prev)
		prev->tree_right = next;
	else if (fs->orphan_head == node)
		fs->orphan_head = next;

	if (next)
		next->tree_left = prev;

	node->tree_left = NULL;
	node->tree_right = NULL;
	node->tree_parent = NULL;
}
typedef struct MemfsPageAad {
	uint64_t node_index;
	uint64_t storage_index;
	uint64_t nonce_sequence;
	uint16_t plain_size;
	uint8_t flags;
	uint8_t reserved[5];
} MemfsPageAad;

static void memfs_build_xchacha_nonce(
	Memfs* fs,
	uint64_t sequence,
	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]) {
	memcpy(nonce, fs->encryption_nonce_prefix, MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE);
	memcpy(nonce + MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE, &sequence, sizeof(sequence));
}

static void memfs_build_aes_gcm_nonce(
	uint64_t sequence,
	uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES]) {
	/*
	 * AES-GCM uses a per-mount derived key, so nonce uniqueness only needs
	 * to hold inside that derived-key domain. Keep a fixed 32-bit domain
	 * prefix and the monotonic 64-bit sequence.
	 */
	memset(nonce, 0, crypto_aead_aes256gcm_NPUBBYTES);
	memcpy(nonce + crypto_aead_aes256gcm_NPUBBYTES - sizeof(sequence),
		   &sequence, sizeof(sequence));
}

static bool memfs_derive_aes_gcm_key(
	const uint8_t master_key[MEMFS_ENCRYPTION_KEY_SIZE],
	const uint8_t nonce_prefix[MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE],
	uint8_t derived_key[MEMFS_ENCRYPTION_KEY_SIZE]) {
	static const uint8_t domain[] = "memfs-aes-gcm-v1";
	uint8_t input[(sizeof(domain) - 1U) + MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE];

	memcpy(input, domain, sizeof(domain) - 1U);
	memcpy(input + sizeof(domain) - 1U,
		   nonce_prefix, MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE);

	if (crypto_generichash(derived_key, MEMFS_ENCRYPTION_KEY_SIZE,
						   input, sizeof(input),
						   master_key, MEMFS_ENCRYPTION_KEY_SIZE) != 0) {
		sodium_memzero(input, sizeof(input));
		return false;
	}

	sodium_memzero(input, sizeof(input));
	return true;
}

/* Rotate the AES-GCM subkey every 2^20 encrypted blobs/pages. */
#define MEMFS_AES_GCM_EPOCH_SHIFT 20U

static bool memfs_aes_gcm_epoch_key(
	Memfs* fs,
	uint64_t sequence,
	bool cache_on_miss,
	uint8_t epoch_key[MEMFS_ENCRYPTION_KEY_SIZE]) {
	static const char context[crypto_kdf_CONTEXTBYTES] = {
		'M', 'F', 'S', 'A', 'E', 'S', '0', '1'
	};
	uint64_t epoch;

	if (fs == NULL || sequence == 0 || epoch_key == NULL)
		return false;

	epoch = (sequence - 1ULL) >> MEMFS_AES_GCM_EPOCH_SHIFT;

	AcquireSRWLockShared(&fs->encryption_aes_epoch_lock);
	if (fs->encryption_aes_epoch_valid &&
		fs->encryption_aes_epoch == epoch) {
		memcpy(epoch_key, fs->encryption_aes_epoch_key,
			   MEMFS_ENCRYPTION_KEY_SIZE);
		ReleaseSRWLockShared(&fs->encryption_aes_epoch_lock);
		return true;
	}
	ReleaseSRWLockShared(&fs->encryption_aes_epoch_lock);

	if (crypto_kdf_derive_from_key(
			epoch_key, MEMFS_ENCRYPTION_KEY_SIZE,
			epoch, context, fs->encryption_aes_key) != 0)
		return false;

	if (cache_on_miss) {
		AcquireSRWLockExclusive(&fs->encryption_aes_epoch_lock);
		if (!fs->encryption_aes_epoch_valid ||
			epoch > fs->encryption_aes_epoch) {
			memcpy(fs->encryption_aes_epoch_key, epoch_key,
				   MEMFS_ENCRYPTION_KEY_SIZE);
			fs->encryption_aes_epoch = epoch;
			fs->encryption_aes_epoch_valid = true;
		}
		ReleaseSRWLockExclusive(&fs->encryption_aes_epoch_lock);
	}

	return true;
}

_Static_assert(crypto_aead_xchacha20poly1305_ietf_ABYTES ==
			   crypto_aead_aes256gcm_ABYTES,
			   "supported AEADs must use the same tag size");

#define MEMFS_NONCE_SEQUENCE_BLOCK_SIZE 256ULL

typedef struct MemfsNonceSequenceCache {
	Memfs* fs;
	uint8_t nonce_prefix[MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE];
	uint64_t next;
	uint64_t end;
} MemfsNonceSequenceCache;

static __declspec(thread) MemfsNonceSequenceCache g_memfs_nonce_sequence_cache;

static bool memfs_nonce_sequence_next(Memfs* fs, uint64_t* sequence) {
	MemfsNonceSequenceCache* cache = &g_memfs_nonce_sequence_cache;

	if (fs == NULL || sequence == NULL)
		return false;

	if (cache->fs != fs ||
		memcmp(cache->nonce_prefix,
			   fs->encryption_nonce_prefix,
			   MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE) != 0 ||
		cache->next >= cache->end) {
		LONG64 reserved_end = InterlockedAdd64(
			&fs->encryption_nonce_counter,
			(LONG64)MEMFS_NONCE_SEQUENCE_BLOCK_SIZE);
		uint64_t end;
		uint64_t start;

		/*
		 * Sequence zero is intentionally unused. A signed wrap means the
		 * 64-bit sequence space is exhausted; fail closed rather than reuse
		 * a nonce. Reserving in blocks may leave at most 255 terminal values
		 * unused, which is immaterial relative to the 2^63 sequence space.
		 */
		if (reserved_end <= 0 ||
			(uint64_t)reserved_end < MEMFS_NONCE_SEQUENCE_BLOCK_SIZE) {
			return false;
		}

		end = (uint64_t)reserved_end;
		start = end - MEMFS_NONCE_SEQUENCE_BLOCK_SIZE + 1ULL;

		cache->fs = fs;
		memcpy(cache->nonce_prefix,
			   fs->encryption_nonce_prefix,
			   MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE);
		cache->next = start;
		cache->end = end + 1ULL;
	}

	*sequence = cache->next++;
	return true;
}

#if !defined(NDEBUG)
bool memfs_test_next_nonce_sequence(Memfs* fs, uint64_t* sequence) {
	return memfs_nonce_sequence_next(fs, sequence);
}
#endif

static void memfs_security_release(MemfsSecurity* security);

#define MEMFS_PAGE_RAW_TAG ((uintptr_t)1U)
#define MEMFS_PAGE_RAW_TAG_MASK ((uintptr_t)1U)
_Static_assert((MEMFS_ALLOC_MIN_ALIGNMENT & MEMFS_PAGE_RAW_TAG_MASK) == 0,
			   "raw-page pointer tag requires allocator minimum alignment to keep bit 0 clear");

static bool memfs_page_is_raw(const MemfsPage* page) {
	return page != NULL &&
		   (((uintptr_t)page & MEMFS_PAGE_RAW_TAG_MASK) == MEMFS_PAGE_RAW_TAG);
}

static uint8_t* memfs_page_raw_data(MemfsPage* page) {
	return (uint8_t*)((uintptr_t)page & ~MEMFS_PAGE_RAW_TAG_MASK);
}

static const uint8_t* memfs_page_raw_const_data(const MemfsPage* page) {
	return (const uint8_t*)((uintptr_t)page & ~MEMFS_PAGE_RAW_TAG_MASK);
}

static MemfsPage* memfs_page_tag_raw(void* allocation) {
	if (allocation == NULL ||
		((uintptr_t)allocation & MEMFS_PAGE_RAW_TAG_MASK) != 0) {
		return NULL;
	}
	return (MemfsPage*)((uintptr_t)allocation | MEMFS_PAGE_RAW_TAG);
}

static MemfsPage* memfs_page_alloc_raw(MemfsNode* node) {
	void* allocation;
	MemfsPage* page;

	if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_PAGE))
		return NULL;

	allocation = memfs_allocator_alloc_uninit(&node->fs->allocator, MEMFS_PAGE_SIZE);
	if (allocation == NULL)
		return NULL;

	page = memfs_page_tag_raw(allocation);
	if (page == NULL) {
		memfs_allocator_free(&node->fs->allocator, allocation, MEMFS_PAGE_SIZE);
		return NULL;
	}

	return page;
}

static size_t memfs_page_heap_size(const MemfsPage* page) {
	if (page == NULL)
		return 0;
	if (memfs_page_is_raw(page))
		return MEMFS_PAGE_SIZE;
	return sizeof(*page) + page->stored_size;
}

static void memfs_page_free(MemfsNode* node, MemfsPage* page) {
	size_t bytes;
	void* allocation;

	if (page == NULL)
		return;

	bytes = memfs_page_heap_size(page);
	allocation = memfs_page_is_raw(page)
		? (void*)memfs_page_raw_data(page)
		: (void*)page;
	memfs_allocator_free(&node->fs->allocator, allocation, bytes);
}
/* memfs_core.c heap migration marker: CRT heap calls removed; allocator/VirtualAlloc paths active. */

static uint64_t memfs_atomic_load_u64(volatile LONG64* value) {
	return (uint64_t)InterlockedCompareExchange64(value, 0, 0);
}

static void memfs_atomic_sub_clamped(volatile LONG64* value, uint64_t delta) {
	for (;;) {
		uint64_t current = memfs_atomic_load_u64(value);
		uint64_t next = delta > current ? 0 : current - delta;

		if ((uint64_t)InterlockedCompareExchange64(value, (LONG64)next, (LONG64)current) == current) {
			return;
		}
	}
}

static bool memfs_atomic_reserve(volatile LONG64* value, uint64_t capacity, uint64_t delta) {
	for (;;) {
		uint64_t current = memfs_atomic_load_u64(value);
		uint64_t next;

		if (current > capacity || delta > capacity - current)
			return false;

		next = current + delta;
		if ((uint64_t)InterlockedCompareExchange64(value, (LONG64)next, (LONG64)current) == current) {
			return true;
		}
	}
}

static void memfs_resident_add(MemfsNode* node, uint64_t bytes) {
	if (bytes == 0)
		return;

	(void)InterlockedAdd64(&node->fs->resident_bytes, (LONG64)bytes);
}

static void memfs_resident_sub(MemfsNode* node, uint64_t bytes) {
	if (bytes == 0)
		return;

	memfs_atomic_sub_clamped(&node->fs->resident_bytes, bytes);
}

static bool memfs_buffer_is_zero(const uint8_t* data, uint32_t size) {
	uint32_t i = 0;

	while (i + sizeof(uint64_t) <= size) {
		uint64_t value;

		memcpy(&value, data + i, sizeof(value));
		if (value)
			return false;
		i += sizeof(uint64_t);
	}

	while (i < size) {
		if (data[i])
			return false;
		i++;
	}

	return true;
}

#define MEMFS_COMPRESSION_SKIP_SCORE 4
#define MEMFS_COMPRESSION_PROBE_MASK 15ULL

static int8_t memfs_storage_get_compression_score(MemfsNode* node) {
	return node ? node->compression_score : 0;
}

static void memfs_storage_adjust_compression_score(MemfsNode* node, bool useful) {
	if (node == NULL)
		return;
	if (useful) {
		if (node->compression_score > -8)
			node->compression_score--;
	} else if (node->compression_score < 8) {
		node->compression_score++;
	}
}

static uint32_t memfs_compression_home_lane(void) {
	uint32_t value = (uint32_t)GetCurrentThreadId();

	value ^= value >> 16;
	value *= 0x7feb352dU;
	value ^= value >> 15;
	value *= 0x846ca68bU;
	value ^= value >> 16;
	return value & (MEMFS_COMPRESSION_CONTEXT_LANES - 1U);
}

static void* memfs_create_compression_context(void) {
	return ZSTD_createCCtx();
}

static void* memfs_create_decompression_context(void) {
	return ZSTD_createDCtx();
}

static void* memfs_codec_lane_acquire(MemfsCompressionLane* lanes, void* (*create)(void),
									  uint32_t* lane_index) {
	uint32_t home;
	uint32_t probe;

	if (lanes == NULL || lane_index == NULL)
		return NULL;

	home = memfs_compression_home_lane();
	for (probe = 0; probe < MEMFS_COMPRESSION_CONTEXT_LANES; probe++) {
		uint32_t index = (home + probe) & (MEMFS_COMPRESSION_CONTEXT_LANES - 1U);
		MemfsCompressionLane* lane = &lanes[index];

		if (!TryAcquireSRWLockExclusive(&lane->lock))
			continue;

		if (lane->context == NULL)
			lane->context = create();

		if (lane->context != NULL) {
			*lane_index = index;
			return lane->context;
		}

		ReleaseSRWLockExclusive(&lane->lock);
	}

	/*
	 * All lanes are busy (or lazy allocation raced with memory pressure).
	 * Block only on this thread's home lane, never on one global codec
	 * lock. This preserves FINE-guard parallel I/O across independent files.
	 */
	AcquireSRWLockExclusive(&lanes[home].lock);
	if (lanes[home].context == NULL)
		lanes[home].context = create();

	if (lanes[home].context == NULL) {
		ReleaseSRWLockExclusive(&lanes[home].lock);
		return NULL;
	}

	*lane_index = home;
	return lanes[home].context;
}

static ZSTD_CCtx* memfs_compression_context_acquire(Memfs* fs, uint32_t* lane_index) {
	if (fs == NULL)
		return NULL;
	return (ZSTD_CCtx*)memfs_codec_lane_acquire(
		fs->compression_lanes, memfs_create_compression_context, lane_index);
}

static void memfs_compression_context_release(Memfs* fs, uint32_t lane_index) {
	ReleaseSRWLockExclusive(&fs->compression_lanes[lane_index].lock);
}

/*
 * ZSTD_decompress() heap-allocates and initializes a whole DCtx (~100 KiB+)
 * per call in zstd's default heap mode; every compressed 4 KiB page read paid
 * for it. Reuse pooled contexts exactly like the compression lanes.
 */
static size_t memfs_decompress_payload(Memfs* fs, void* dst, size_t dst_capacity,
									   const void* src, size_t src_size) {
	uint32_t lane_index;
	ZSTD_DCtx* context = (ZSTD_DCtx*)memfs_codec_lane_acquire(
		fs->decompression_lanes, memfs_create_decompression_context, &lane_index);
	size_t result;

	if (context == NULL)
		return ZSTD_decompress(dst, dst_capacity, src, src_size);

	result = ZSTD_decompressDCtx(context, dst, dst_capacity, src, src_size);
	ReleaseSRWLockExclusive(&fs->decompression_lanes[lane_index].lock);
	return result;
}

static size_t memfs_compress_payload(Memfs* fs, void* dst, size_t dst_capacity,
									 const void* src, size_t src_size) {
	uint32_t lane_index;
	ZSTD_CCtx* context;
	size_t result;

	context = memfs_compression_context_acquire(fs, &lane_index);
	if (context == NULL) {
		/*
		 * Keep the old allocation-on-demand path as an OOM fallback. A failure
		 * to allocate a reusable lane must not turn a writable page into an
		 * application-visible compression error.
		 */
		return ZSTD_compress(dst, dst_capacity, src, src_size, fs->compression_level);
	}

	result = ZSTD_compressCCtx(
		context, dst, dst_capacity, src, src_size, fs->compression_level);
	memfs_compression_context_release(fs, lane_index);
	return result;
}

static void memfs_compression_contexts_destroy(Memfs* fs) {
	uint32_t i;

	if (fs == NULL)
		return;

	for (i = 0; i < MEMFS_COMPRESSION_CONTEXT_LANES; i++) {
		if (fs->compression_lanes[i].context != NULL) {
			ZSTD_freeCCtx((ZSTD_CCtx*)fs->compression_lanes[i].context);
			fs->compression_lanes[i].context = NULL;
		}
		if (fs->decompression_lanes[i].context != NULL) {
			ZSTD_freeDCtx((ZSTD_DCtx*)fs->decompression_lanes[i].context);
			fs->decompression_lanes[i].context = NULL;
		}
	}
}

static bool memfs_compression_should_try(MemfsNode* node, uint64_t storage_index, uint16_t plain_size) {
	if (!node->fs->compression_enabled || plain_size < 128U)
		return false;

	if (memfs_storage_get_compression_score(node) < MEMFS_COMPRESSION_SKIP_SCORE)
		return true;

	// Tiny blobs are cheap and infrequently rewritten, so always sample them.
	// For paged files with poor compression history, probe one page out of 16.
	if (storage_index == UINT64_MAX)
		return true;

	return 0 == (storage_index & MEMFS_COMPRESSION_PROBE_MASK);
}

static void memfs_compression_feedback(MemfsNode* node, bool useful) {
	memfs_storage_adjust_compression_score(node, useful);
}

static MemfsResult memfs_page_encode(MemfsNode* node, uint64_t storage_index, const uint8_t* plain, uint16_t plain_size,
									 MemfsPage** out_page) {
	uint8_t compressed[ZSTD_COMPRESSBOUND(MEMFS_PAGE_SIZE)];
	const uint8_t* payload = plain;
	size_t payload_size = plain_size;
	uint8_t flags = 0;
	size_t stored_size;
	bool compression_useful = false;
	MemfsPage* page;

	*out_page = NULL;

	if (plain_size == 0 || memfs_buffer_is_zero(plain, plain_size))
		return MEMFS_OK;

	if (plain_size == MEMFS_PAGE_SIZE &&
		!node->fs->compression_enabled &&
		!node->fs->encryption_enabled) {
		MemfsPage* raw_page = memfs_page_alloc_raw(node);
		if (raw_page == NULL)
			return MEMFS_ERR_NO_MEMORY;

		memcpy(memfs_page_raw_data(raw_page), plain, MEMFS_PAGE_SIZE);
		*out_page = raw_page;
		return MEMFS_OK;
	}

	if (memfs_compression_should_try(node, storage_index, plain_size)) {
		size_t compressed_size;

		compressed_size = memfs_compress_payload(node->fs, compressed, sizeof(compressed), plain, plain_size);

		if (!ZSTD_isError(compressed_size) && compressed_size + 32U < plain_size) {
			payload = compressed;
			payload_size = compressed_size;
			flags |= MEMFS_PAGE_COMPRESSED;
			compression_useful = true;
		}

		memfs_compression_feedback(node, compression_useful);
	}

	if (node->fs->encryption_enabled) {
		stored_size = sizeof(uint64_t) + payload_size + crypto_aead_xchacha20poly1305_ietf_ABYTES;
	} else {
		stored_size = payload_size;
	}

	if (stored_size > UINT16_MAX)
		return MEMFS_ERR_NO_MEMORY;

	if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_PAGE))
		return MEMFS_ERR_NO_MEMORY;

	page = memfs_allocator_alloc_uninit(&node->fs->allocator, sizeof(*page) + stored_size);
	if (page == NULL)
		return MEMFS_ERR_NO_MEMORY;

	page->stored_size = (uint16_t)stored_size;
	page->plain_size = plain_size;
	page->flags = flags;
	memset(page->reserved, 0, sizeof(page->reserved));

	if (node->fs->encryption_enabled) {
		MemfsPageAad aad;
		uint8_t* sequence_data = page->data;
		uint8_t* cipher = page->data + sizeof(uint64_t);
		unsigned long long cipher_size = 0;
		uint64_t sequence;
		int crypto_result;

		if (!memfs_nonce_sequence_next(node->fs, &sequence)) {
			memfs_page_free(node, page);
			return MEMFS_ERR_DATA;
		}

		page->flags |= MEMFS_PAGE_ENCRYPTED;
		if (node->fs->encryption_aes_gcm)
			page->flags |= MEMFS_PAGE_AES_GCM;

		memcpy(sequence_data, &sequence, sizeof(sequence));

		memset(&aad, 0, sizeof(aad));
		aad.node_index = memfs_node_index_number(node);
		aad.storage_index = storage_index;
		aad.nonce_sequence = sequence;
		aad.plain_size = plain_size;
		aad.flags = page->flags;

		if (node->fs->encryption_aes_gcm) {
			uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
			uint8_t epoch_key[MEMFS_ENCRYPTION_KEY_SIZE];

			if (!memfs_aes_gcm_epoch_key(
					node->fs, sequence, true, epoch_key)) {
				memfs_page_free(node, page);
				return MEMFS_ERR_DATA;
			}
			memfs_build_aes_gcm_nonce(sequence, nonce);
			crypto_result = crypto_aead_aes256gcm_encrypt(
				cipher, &cipher_size,
				payload, (unsigned long long)payload_size,
				(const unsigned char*)&aad, sizeof(aad),
				NULL, nonce, epoch_key);
			sodium_memzero(epoch_key, sizeof(epoch_key));
			sodium_memzero(nonce, sizeof(nonce));
		} else {
			uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
			memfs_build_xchacha_nonce(node->fs, sequence, nonce);
			crypto_result = crypto_aead_xchacha20poly1305_ietf_encrypt(
				cipher, &cipher_size,
				payload, (unsigned long long)payload_size,
				(const unsigned char*)&aad, sizeof(aad),
				NULL, nonce, node->fs->encryption_key);
			sodium_memzero(nonce, sizeof(nonce));
		}

		if (crypto_result != 0 ||
			cipher_size != payload_size + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
			memfs_page_free(node, page);
			return MEMFS_ERR_DATA;
		}
	} else {
		memcpy(page->data, payload, payload_size);
	}

	*out_page = page;
	return MEMFS_OK;
}
static MemfsResult memfs_page_decode(MemfsNode* node, uint64_t storage_index, const MemfsPage* page, uint8_t* plain,
									 uint16_t expected_plain_size) {
	uint8_t stage[MEMFS_PAGE_SIZE];
	const uint8_t* payload;
	size_t payload_size;
	uint16_t plain_size;

	if (expected_plain_size > MEMFS_PAGE_SIZE)
		return MEMFS_ERR_INVALID;

	memset(plain, 0, expected_plain_size);

	if (page == NULL)
		return MEMFS_OK;

	if (memfs_page_is_raw(page)) {
		if (expected_plain_size != MEMFS_PAGE_SIZE)
			return MEMFS_ERR_DATA;
		memcpy(plain, memfs_page_raw_const_data(page), MEMFS_PAGE_SIZE);
		return MEMFS_OK;
	}

	if ((page->flags & MEMFS_PAGE_AES_GCM) &&
		!(page->flags & MEMFS_PAGE_ENCRYPTED))
		return MEMFS_ERR_DATA;

	plain_size = page->plain_size;
	if (plain_size != expected_plain_size)
		return MEMFS_ERR_DATA;

	payload = page->data;
	payload_size = page->stored_size;

	if (page->flags & MEMFS_PAGE_ENCRYPTED) {
		MemfsPageAad aad;
		unsigned long long decoded_size = 0;
		uint64_t sequence;
		const uint8_t* cipher;
		size_t cipher_size;
		uint8_t* target;
		int crypto_result;

		if (!node->fs->encryption_enabled)
			return MEMFS_ERR_DATA;

		if (payload_size < sizeof(uint64_t) + crypto_aead_xchacha20poly1305_ietf_ABYTES)
			return MEMFS_ERR_DATA;

		memcpy(&sequence, payload, sizeof(sequence));
		cipher = payload + sizeof(sequence);
		cipher_size = payload_size - sizeof(sequence);
		/* An uncompressed page decrypts straight into the caller's buffer. */
		target = !(page->flags & MEMFS_PAGE_COMPRESSED) &&
			cipher_size - crypto_aead_xchacha20poly1305_ietf_ABYTES == expected_plain_size ?
			plain : stage;

		memset(&aad, 0, sizeof(aad));
		aad.node_index = memfs_node_index_number(node);
		aad.storage_index = storage_index;
		aad.nonce_sequence = sequence;
		aad.plain_size = page->plain_size;
		aad.flags = page->flags;

		if (page->flags & MEMFS_PAGE_AES_GCM) {
			uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
			uint8_t epoch_key[MEMFS_ENCRYPTION_KEY_SIZE];

			if (!crypto_aead_aes256gcm_is_available())
				return MEMFS_ERR_DATA;
			if (!memfs_aes_gcm_epoch_key(
					node->fs, sequence, false, epoch_key))
				return MEMFS_ERR_DATA;

			memfs_build_aes_gcm_nonce(sequence, nonce);
			crypto_result = crypto_aead_aes256gcm_decrypt(
				target, &decoded_size, NULL,
				cipher, (unsigned long long)cipher_size,
				(const unsigned char*)&aad, sizeof(aad),
				nonce, epoch_key);
			sodium_memzero(epoch_key, sizeof(epoch_key));
			sodium_memzero(nonce, sizeof(nonce));
		} else {
			uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

			memfs_build_xchacha_nonce(node->fs, sequence, nonce);
			crypto_result = crypto_aead_xchacha20poly1305_ietf_decrypt(
				target, &decoded_size, NULL,
				cipher, (unsigned long long)cipher_size,
				(const unsigned char*)&aad, sizeof(aad),
				nonce, node->fs->encryption_key);
			sodium_memzero(nonce, sizeof(nonce));
		}

		if (crypto_result != 0 || decoded_size > sizeof(stage)) {
			memset(plain, 0, expected_plain_size);
			return MEMFS_ERR_DATA;
		}
		if (target == plain)
			return MEMFS_OK;

		payload = stage;
		payload_size = (size_t)decoded_size;
	} else if (node->fs->encryption_enabled) {
		return MEMFS_ERR_DATA;
	}

	if (page->flags & MEMFS_PAGE_COMPRESSED) {
		size_t decoded = memfs_decompress_payload(node->fs, plain, expected_plain_size,
												  payload, payload_size);

		if (payload == stage)
			sodium_memzero(stage, payload_size);
		if (ZSTD_isError(decoded) || decoded != expected_plain_size)
			return MEMFS_ERR_DATA;

		return MEMFS_OK;
	}

	if (payload_size != expected_plain_size)
		return MEMFS_ERR_DATA;

	memcpy(plain, payload, expected_plain_size);
	return MEMFS_OK;
}
static uint32_t memfs_popcount64(uint64_t value) {
#if defined(_MSC_VER)
	return (uint32_t)__popcnt64(value);
#else
	return (uint32_t)__builtin_popcountll(value);
#endif
}

static bool memfs_group_has(const MemfsPageGroup* group, uint32_t slot) {
	uint32_t word = slot >> 6;
	uint32_t bit = slot & 63U;

	return 0 != (group->bitmap[word] & (1ULL << bit));
}

static uint32_t memfs_group_rank(const MemfsPageGroup* group, uint32_t slot) {
	uint32_t word = slot >> 6;
	uint32_t bit = slot & 63U;
	uint32_t rank = 0;
	uint32_t i;

	for (i = 0; i < word; i++)
		rank += memfs_popcount64(group->bitmap[i]);

	if (bit) {
		uint64_t mask = (1ULL << bit) - 1ULL;
		rank += memfs_popcount64(group->bitmap[word] & mask);
	}

	return rank;
}

static MemfsPage* memfs_group_page_at_rank(const MemfsPageGroup* group, uint32_t rank) {
	if (group == NULL || rank >= group->page_count)
		return NULL;

	if (group->page_capacity == 1U)
		return rank == 0 ? group->inline_page : NULL;

	return group->pages[rank];
}

MemfsPage* memfs_page_group_page(const MemfsPageGroup* group, uint32_t position) {
	return memfs_group_page_at_rank(group, position);
}

static MemfsPage* memfs_group_get(const MemfsPageGroup* group, uint32_t slot) {
	if (group == NULL || !memfs_group_has(group, slot))
		return NULL;

	return memfs_group_page_at_rank(group, memfs_group_rank(group, slot));
}

static MemfsResult memfs_group_reserve(MemfsNode* node, MemfsPageGroup* group, uint32_t required) {
	MemfsPage** pages;
	uint32_t capacity;

	if (required <= group->page_capacity)
		return MEMFS_OK;
	if (required > MEMFS_PAGES_PER_GROUP)
		return MEMFS_ERR_INVALID;

	if (required == 1U) {
		group->inline_page = NULL;
		group->page_capacity = 1U;
		return MEMFS_OK;
	}

	capacity = group->page_capacity >= 2U ? group->page_capacity : 2U;
	while (capacity < required) {
		if (capacity >= MEMFS_PAGES_PER_GROUP / 2U) {
			capacity = MEMFS_PAGES_PER_GROUP;
			break;
		}
		capacity <<= 1;
	}

	if (group->page_capacity <= 1U) {
		MemfsPage* inline_page = group->page_count == 1U ? group->inline_page : NULL;

		pages = memfs_allocator_alloc_uninit(
			&node->fs->allocator, (size_t)capacity * sizeof(*pages));
		if (pages == NULL)
			return MEMFS_ERR_NO_MEMORY;

		if (inline_page != NULL)
			pages[0] = inline_page;
	} else {
		pages = memfs_allocator_realloc(
			&node->fs->allocator,
			group->pages,
			(size_t)group->page_capacity * sizeof(*pages),
			(size_t)capacity * sizeof(*pages));
		if (pages == NULL)
			return MEMFS_ERR_NO_MEMORY;
	}

	group->pages = pages;
	group->page_capacity = (uint16_t)capacity;
	return MEMFS_OK;
}

static void memfs_group_try_shrink(MemfsNode* node, MemfsPageGroup* group) {
	MemfsPage** pages;
	uint32_t target;

	if (group->page_count == 0) {
		if (group->page_capacity >= 2U && group->pages != NULL) {
			memfs_allocator_free(
				&node->fs->allocator,
				group->pages,
				(size_t)group->page_capacity * sizeof(*group->pages));
		}
		group->inline_page = NULL;
		group->page_capacity = 0;
		return;
	}

	if (group->page_count == 1U) {
		if (group->page_capacity >= 2U) {
			MemfsPage* inline_page = group->pages[0];

			memfs_allocator_free(
				&node->fs->allocator,
				group->pages,
				(size_t)group->page_capacity * sizeof(*group->pages));
			group->inline_page = inline_page;
			group->page_capacity = 1U;
		}
		return;
	}

	if (group->page_capacity <= 2U ||
		group->page_count * 2U > group->page_capacity) {
		return;
	}

	target = 2U;
	while (target < group->page_count)
		target <<= 1;

	pages = memfs_allocator_realloc(
		&node->fs->allocator,
		group->pages,
		(size_t)group->page_capacity * sizeof(*group->pages),
		(size_t)target * sizeof(*group->pages));
	if (pages) {
		group->pages = pages;
		group->page_capacity = (uint16_t)target;
	}
}

static MemfsStorageMeta* memfs_storage_meta(MemfsNode* node) {
	if (node == NULL || !node->paged_storage)
		return NULL;
	return node->storage_meta;
}

static MemfsStorageMeta* memfs_storage_meta_get_or_create(MemfsNode* node) {
	MemfsStorageMeta* meta;

	if (node == NULL || MEMFS_NODE_IS_DIRECTORY(node) || node->small_capacity != 0)
		return NULL;

	meta = memfs_storage_meta(node);
	if (meta != NULL)
		return meta;

	if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_METADATA))
		return NULL;

	meta = memfs_allocator_alloc_zero(&node->fs->allocator, sizeof(*meta));
	if (meta == NULL)
		return NULL;

	node->storage_meta = meta;
	node->paged_storage = true;
	return meta;
}

static uint32_t memfs_storage_group_count(const MemfsNode* node) {
	MemfsStorageMeta* meta = memfs_storage_meta((MemfsNode*)node);
	return meta ? meta->count : 0;
}

static uint32_t memfs_storage_group_capacity(const MemfsNode* node) {
	MemfsStorageMeta* meta = memfs_storage_meta((MemfsNode*)node);
	return meta ? meta->capacity : 0;
}

static MemfsPageGroupEntry* memfs_storage_groups(MemfsNode* node) {
	MemfsStorageMeta* meta = memfs_storage_meta(node);
	return meta ? meta->groups : NULL;
}

static void memfs_storage_set_group_count(MemfsNode* node, uint32_t value) {
	MemfsStorageMeta* meta = memfs_storage_meta(node);

	if (meta != NULL)
		meta->count = value;
}

static void memfs_storage_clear_group_array(MemfsNode* node) {
	MemfsStorageMeta* meta;

	if (node == NULL)
		return;

	meta = memfs_storage_meta(node);
	if (meta != NULL) {
		if (meta->groups)
			memfs_allocator_free(&node->fs->allocator, meta->groups, (size_t)meta->capacity * sizeof(*meta->groups));
		memfs_allocator_free(&node->fs->allocator, meta, sizeof(*meta));
	}

	node->storage_meta = NULL;
	node->paged_storage = false;
}

static MemfsPageGroup* memfs_storage_group_at(const MemfsNode* node, uint32_t position) {
	MemfsPageGroupEntry* entries = memfs_storage_groups((MemfsNode*)node);

	if (entries == NULL || position >= memfs_storage_group_count(node))
		return NULL;

	return entries[position].group;
}

static uint64_t memfs_storage_group_index_at(MemfsNode* node, uint32_t position) {
	MemfsPageGroupEntry* entries = memfs_storage_groups(node);

	if (entries == NULL || position >= memfs_storage_group_count(node))
		return UINT64_MAX;

	return entries[position].index;
}

static void memfs_storage_group_set(MemfsNode* node, uint32_t position, uint64_t group_index, MemfsPageGroup* group) {
	MemfsPageGroupEntry* entries = memfs_storage_groups(node);

	if (entries == NULL || position >= memfs_storage_group_capacity(node))
		return;

	entries[position].index = group_index;
	entries[position].group = group;
}

uint32_t memfs_node_page_group_count(const MemfsNode* node) {
	return memfs_storage_group_count(node);
}

uint32_t memfs_node_page_group_capacity(const MemfsNode* node) {
	return memfs_storage_group_capacity(node);
}

uint64_t memfs_node_page_group_index(const MemfsNode* node, uint32_t position) {
	return memfs_storage_group_index_at((MemfsNode*)node, position);
}

MemfsPageGroup* memfs_node_page_group(const MemfsNode* node, uint32_t position) {
	return memfs_storage_group_at(node, position);
}

int8_t memfs_node_compression_score(const MemfsNode* node) {
	return node ? node->compression_score : 0;
}

static uint32_t memfs_storage_group_position(MemfsNode* node, uint64_t group_index, bool* found) {
	MemfsPageGroupEntry* entries = memfs_storage_groups(node);
	uint32_t lo = 0;
	uint32_t hi = memfs_storage_group_count(node);

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2U;
		uint64_t current = entries[mid].index;

		if (current < group_index)
			lo = mid + 1U;
		else
			hi = mid;
	}

	if (found)
		*found = lo < memfs_storage_group_count(node) && entries[lo].index == group_index;

	return lo;
}

static MemfsPageGroup* memfs_storage_group(MemfsNode* node, uint64_t group_index) {
	bool found;
	uint32_t pos = memfs_storage_group_position(node, group_index, &found);

	return found ? memfs_storage_group_at(node, pos) : NULL;
}

static MemfsResult memfs_storage_group_reserve(MemfsNode* node, uint32_t required) {
	MemfsStorageMeta* meta;
	MemfsPageGroupEntry* entries;
	uint32_t capacity;

	if (required <= memfs_storage_group_capacity(node))
		return MEMFS_OK;

	meta = memfs_storage_meta_get_or_create(node);
	if (meta == NULL)
		return MEMFS_ERR_NO_MEMORY;

	capacity = meta->capacity ? meta->capacity : 1U;
	while (capacity < required) {
		if (capacity > UINT32_MAX / 2U) {
			capacity = required;
			break;
		}
		capacity <<= 1;
	}

	if ((size_t)capacity > SIZE_MAX / sizeof(*entries))
		return MEMFS_ERR_NO_MEMORY;

	entries = memfs_allocator_realloc(&node->fs->allocator, meta->groups,
									  (size_t)meta->capacity * sizeof(*entries),
									  (size_t)capacity * sizeof(*entries));
	if (entries == NULL) {
		if (meta->count == 0 && meta->capacity == 0)
			memfs_storage_clear_group_array(node);
		return MEMFS_ERR_NO_MEMORY;
	}

	meta->groups = entries;
	meta->capacity = capacity;
	return MEMFS_OK;
}

static void memfs_storage_group_try_shrink(MemfsNode* node) {
	MemfsStorageMeta* meta = memfs_storage_meta(node);
	MemfsPageGroupEntry* entries;
	uint32_t target;

	if (meta == NULL)
		return;

	if (meta->count == 0) {
		memfs_storage_clear_group_array(node);
		return;
	}

	if (meta->capacity <= 1U || meta->count * 2U > meta->capacity)
		return;

	target = 1U;
	while (target < meta->count)
		target <<= 1;

	entries = memfs_allocator_realloc(&node->fs->allocator, meta->groups,
									  (size_t)meta->capacity * sizeof(*entries),
									  (size_t)target * sizeof(*entries));
	if (entries != NULL) {
		meta->groups = entries;
		meta->capacity = target;
	}
}

static MemfsPage* memfs_storage_page(MemfsNode* node, uint64_t page_index) {
	uint64_t group_index = page_index >> MEMFS_PAGE_GROUP_SHIFT;
	MemfsPageGroup* group = memfs_storage_group(node, group_index);

	if (group == NULL)
		return NULL;

	return memfs_group_get(group, (uint32_t)(page_index & MEMFS_PAGE_GROUP_MASK));
}

#if !defined(NDEBUG)
bool memfs_test_page_info(MemfsNode* node,
						  uint64_t page_index,
						  bool* is_raw,
						  size_t* heap_bytes,
						  uintptr_t* allocation_address) {
	MemfsPage* page;

	if (node == NULL)
		return false;

	page = memfs_storage_page(node, page_index);
	if (page == NULL)
		return false;

	if (is_raw)
		*is_raw = memfs_page_is_raw(page);
	if (heap_bytes)
		*heap_bytes = memfs_page_heap_size(page);
	if (allocation_address) {
		*allocation_address = memfs_page_is_raw(page)
			? (uintptr_t)memfs_page_raw_data(page)
			: (uintptr_t)page;
	}

	return true;
}
#endif

static MemfsResult memfs_storage_ensure_group(MemfsNode* node, uint64_t group_index, MemfsPageGroup** out_group) {
	MemfsPageGroupEntry* entries;
	bool found;
	uint32_t pos = memfs_storage_group_position(node, group_index, &found);
	uint32_t count;
	MemfsPageGroup* group;
	MemfsResult result;

	if (found) {
		*out_group = memfs_storage_group_at(node, pos);
		return MEMFS_OK;
	}

	group = memfs_allocator_alloc_page_group(&node->fs->allocator);
	if (group == NULL)
		return MEMFS_ERR_NO_MEMORY;

	count = memfs_storage_group_count(node);
	result = memfs_storage_group_reserve(node, count + 1U);
	if (result != MEMFS_OK) {
		memfs_allocator_free_page_group(&node->fs->allocator, group);
		return result;
	}

	entries = memfs_storage_groups(node);
	memmove(entries + pos + 1U, entries + pos, (size_t)(count - pos) * sizeof(*entries));
	memfs_storage_group_set(node, pos, group_index, group);
	memfs_storage_set_group_count(node, count + 1U);

	*out_group = group;
	return MEMFS_OK;
}

static void memfs_storage_remove_group(MemfsNode* node, uint64_t group_index) {
	MemfsPageGroupEntry* entries;
	bool found;
	uint32_t pos = memfs_storage_group_position(node, group_index, &found);
	uint32_t count;
	MemfsPageGroup* group;

	if (!found)
		return;

	group = memfs_storage_group_at(node, pos);
	if (group->page_capacity >= 2U && group->pages != NULL) {
		memfs_allocator_free(
			&node->fs->allocator,
			group->pages,
			(size_t)group->page_capacity * sizeof(*group->pages));
	}
	memfs_allocator_free_page_group(&node->fs->allocator, group);

	count = memfs_storage_group_count(node);
	entries = memfs_storage_groups(node);
	memmove(entries + pos, entries + pos + 1U, (size_t)(count - pos - 1U) * sizeof(*entries));
	memfs_storage_set_group_count(node, count - 1U);
	memfs_storage_group_try_shrink(node);
}

/*
 * allow_shrink=false keeps the group's pointer vector at its reserved size, so
 * a multi-page commit never gives back capacity that a later page in the same
 * commit still needs (which could fail and leave a half-applied write).
 */
static MemfsResult memfs_storage_replace_page_ex(MemfsNode* node, MemfsPageGroup* group, uint32_t slot,
												 MemfsPage* new_page, bool allow_shrink) {
	bool had_old = memfs_group_has(group, slot);
	uint32_t rank = memfs_group_rank(group, slot);
	MemfsPage* old_page = had_old ? memfs_group_page_at_rank(group, rank) : NULL;
	size_t old_size = memfs_page_heap_size(old_page);
	size_t new_size = memfs_page_heap_size(new_page);
	uint32_t word = slot >> 6;
	uint32_t bit = slot & 63U;
	MemfsResult result;

	if (!had_old && new_page == NULL)
		return MEMFS_OK;

	if (!had_old && new_page) {
		result = memfs_group_reserve(node, group, (uint32_t)group->page_count + 1U);
		if (result != MEMFS_OK)
			return result;

		if (group->page_capacity == 1U) {
			group->inline_page = new_page;
		} else {
			memmove(group->pages + rank + 1U, group->pages + rank,
					(size_t)(group->page_count - rank) * sizeof(*group->pages));
			group->pages[rank] = new_page;
		}

		group->bitmap[word] |= 1ULL << bit;
		group->page_count++;
	} else if (had_old && new_page) {
		if (group->page_capacity == 1U)
			group->inline_page = new_page;
		else
			group->pages[rank] = new_page;
	} else {
		if (group->page_capacity == 1U) {
			group->inline_page = NULL;
		} else {
			memmove(group->pages + rank, group->pages + rank + 1U,
					(size_t)(group->page_count - rank - 1U) * sizeof(*group->pages));
		}

		group->bitmap[word] &= ~(1ULL << bit);
		group->page_count--;
		if (allow_shrink)
			memfs_group_try_shrink(node, group);
	}

	if (old_size)
		memfs_resident_sub(node, old_size);
	if (new_size)
		memfs_resident_add(node, new_size);

	memfs_page_free(node, old_page);
	return MEMFS_OK;
}

static MemfsResult memfs_storage_replace_page(MemfsNode* node, MemfsPageGroup* group, uint32_t slot,
											  MemfsPage* new_page) {
	return memfs_storage_replace_page_ex(node, group, slot, new_page, true);
}

/* Drops groups left empty in [first_group, last_group] and trims the others. */
static void memfs_storage_settle_groups(MemfsNode* node, uint64_t first_group, uint64_t last_group) {
	uint64_t group_index;

	for (group_index = first_group; group_index <= last_group; group_index++) {
		MemfsPageGroup* group = memfs_storage_group(node, group_index);

		if (group == NULL)
			continue;
		if (group->page_count == 0)
			memfs_storage_remove_group(node, group_index);
		else
			memfs_group_try_shrink(node, group);
	}
}
static bool memfs_small_inline_eligible(MemfsNode* node, uint32_t capacity) {
	return capacity != 0 && capacity <= sizeof(node->small_inline_data) && !node->fs->encryption_enabled;
}

static MemfsResult memfs_storage_decode_small(MemfsNode* node, uint8_t* plain, uint32_t plain_capacity) {
	if (plain_capacity < node->small_capacity)
		return MEMFS_ERR_INVALID;

	if (node->small_capacity == 0)
		return MEMFS_OK;

	if (node->small_inline) {
		memcpy(plain, node->small_inline_data, node->small_capacity);
		return MEMFS_OK;
	}

	return memfs_page_decode(node, UINT64_MAX, node->small_page, plain, (uint16_t)node->small_capacity);
}

static void memfs_storage_replace_small(MemfsNode* node, MemfsPage* new_page, uint32_t new_capacity) {
	MemfsPage* old_page = node->small_inline ? NULL : node->small_page;
	size_t old_size = memfs_page_heap_size(old_page);
	size_t new_size = memfs_page_heap_size(new_page);

	node->small_page = new_page;
	node->small_capacity = new_capacity;
	node->small_inline = false;

	if (old_size)
		memfs_resident_sub(node, old_size);
	if (new_size)
		memfs_resident_add(node, new_size);

	memfs_page_free(node, old_page);
}

static void memfs_storage_replace_small_inline(MemfsNode* node, const uint8_t* plain, uint32_t capacity) {
	MemfsPage* old_page = node->small_inline ? NULL : node->small_page;
	size_t old_size = memfs_page_heap_size(old_page);

	if (old_size)
		memfs_resident_sub(node, old_size);
	memfs_page_free(node, old_page);

	memset(node->small_inline_data, 0, sizeof(node->small_inline_data));

	if (plain && capacity) {
		memcpy(node->small_inline_data, plain, capacity);
	}

	node->small_capacity = capacity;
	node->small_inline = capacity != 0;
}

static void memfs_storage_destroy_pages(MemfsNode* node) {
	MemfsPageGroupEntry* entries = memfs_storage_groups(node);
	uint32_t count = memfs_storage_group_count(node);
	uint32_t entry_index;

	for (entry_index = 0; entry_index < count; entry_index++) {
		MemfsPageGroup* group = entries[entry_index].group;
		uint32_t i;

		for (i = 0; i < group->page_count; i++) {
			MemfsPage* page = memfs_group_page_at_rank(group, i);

			memfs_resident_sub(node, memfs_page_heap_size(page));
			memfs_page_free(node, page);
		}

		if (group->page_capacity >= 2U && group->pages != NULL) {
			memfs_allocator_free(
				&node->fs->allocator,
				group->pages,
				(size_t)group->page_capacity * sizeof(*group->pages));
		}
		memfs_allocator_free_page_group(&node->fs->allocator, group);
	}

	memfs_storage_clear_group_array(node);
}

static void memfs_storage_destroy(MemfsNode* node) {
	if (memfs_storage_group_count(node) != 0 || node->paged_storage) {
		memfs_storage_destroy_pages(node);
		return;
	}

	if (node->small_capacity) {
		if (!node->small_inline && node->small_page) {
			memfs_resident_sub(node, memfs_page_heap_size(node->small_page));
			memfs_page_free(node, node->small_page);
		}

		memset(node->small_inline_data, 0, sizeof(node->small_inline_data));
		node->small_capacity = 0;
		node->small_inline = false;
	}
}

static uint32_t memfs_small_capacity(uint64_t required_end) {
	uint64_t aligned;

	if (required_end == 0)
		return 0;
	if (required_end > MEMFS_SMALL_LIMIT)
		return 0;

	// 1B 文件不再为了增长策略强制占 8B payload。
	// 1/2/4/8 采用 tiny class；之后保持原有 8B granule，
	// 避免大一点的小文件每增长 1B 都 realloc。
	if (required_end <= 1U)
		return 1U;
	if (required_end <= 2U)
		return 2U;
	if (required_end <= 4U)
		return 4U;
	if (required_end <= 8U)
		return 8U;

	aligned = (required_end + MEMFS_SMALL_GRANULE - 1U) & ~((uint64_t)MEMFS_SMALL_GRANULE - 1U);

	if (aligned > MEMFS_SMALL_LIMIT)
		return 0;

	return (uint32_t)aligned;
}

static MemfsResult memfs_storage_promote(MemfsNode* node) {
	uint8_t plain[MEMFS_PAGE_SIZE];
	uint8_t old_inline_data[sizeof(node->small_inline_data)];
	MemfsPage* new_page = NULL;
	MemfsPage* old_page;
	MemfsPageGroup* group;
	MemfsResult result;
	uint32_t old_capacity;
	bool old_inline;
	size_t old_page_size;

	if (node->small_capacity == 0)
		return MEMFS_OK;

	memset(plain, 0, sizeof(plain));

	result = memfs_storage_decode_small(node, plain, sizeof(plain));
	if (result != MEMFS_OK)
		return result;

	result = memfs_page_encode(node, 0, plain, MEMFS_PAGE_SIZE, &new_page);
	if (result != MEMFS_OK)
		return result;

	old_capacity = node->small_capacity;
	old_inline = node->small_inline;
	old_page = old_inline ? NULL : node->small_page;
	old_page_size = memfs_page_heap_size(old_page);

	if (old_inline)
		memcpy(old_inline_data, node->small_inline_data, sizeof(old_inline_data));

	// small storage 与 storage_meta 共用 union。切换到 paged mode 前先把
	// 旧状态保存在局部变量中；StorageMeta 在首次 group 分配时按需创建。
	memset(node->small_inline_data, 0, sizeof(node->small_inline_data));
	node->small_capacity = 0;
	node->small_inline = false;
	node->paged_storage = false;
	node->storage_meta = NULL;

	if (new_page) {
		result = memfs_storage_ensure_group(node, 0, &group);
		if (result != MEMFS_OK)
			goto rollback;

		result = memfs_storage_replace_page(node, group, 0, new_page);
		if (result != MEMFS_OK) {
			memfs_storage_remove_group(node, 0);
			goto rollback;
		}

		new_page = NULL; // ownership moved into group
	}

	if (old_page_size)
		memfs_resident_sub(node, old_page_size);
	memfs_page_free(node, old_page);
	return MEMFS_OK;

rollback:
	if (memfs_storage_group_count(node) != 0 || node->paged_storage)
		memfs_storage_destroy_pages(node);
	else {
		memfs_storage_clear_group_array(node);
	}

	if (old_inline)
		memcpy(node->small_inline_data, old_inline_data, sizeof(old_inline_data));
	else
		node->small_page = old_page;

	node->small_capacity = (uint16_t)old_capacity;
	node->small_inline = old_inline;
	node->paged_storage = false;
	memfs_page_free(node, new_page);
	return result;
}
static MemfsResult memfs_storage_trim_small(MemfsNode* node, uint64_t new_size) {
	uint8_t plain[MEMFS_SMALL_LIMIT];
	uint32_t target = memfs_small_capacity(new_size);
	MemfsPage* new_page = NULL;
	MemfsResult result;

	if (node->small_capacity == 0) {
		node->small_capacity = target;
		return MEMFS_OK;
	}

	/* The resident head already ends inside the new EOF (for example after
	 * sparse growth past MEMFS_SMALL_LIMIT); bytes beyond it read as zero. */
	if (new_size >= node->small_capacity)
		return MEMFS_OK;

	if (target == 0) {
		memfs_storage_replace_small(node, NULL, 0);
		return MEMFS_OK;
	}

	memset(plain, 0, sizeof(plain));

	result = memfs_storage_decode_small(node, plain, sizeof(plain));
	if (result != MEMFS_OK)
		return result;

	if (new_size < target) {
		memset(plain + new_size, 0, (size_t)(target - new_size));
	}

	if (memfs_small_inline_eligible(node, target)) {
		memfs_storage_replace_small_inline(node, plain, target);
		return MEMFS_OK;
	}

	result = memfs_page_encode(node, UINT64_MAX, plain, (uint16_t)target, &new_page);
	if (result != MEMFS_OK)
		return result;

	memfs_storage_replace_small(node, new_page, target);
	return MEMFS_OK;
}

static MemfsResult memfs_storage_trim_pages(MemfsNode* node, uint64_t new_size) {
	uint64_t first_free_page = (new_size + MEMFS_PAGE_MASK) >> MEMFS_PAGE_SHIFT;
	uint64_t tail_page = new_size >> MEMFS_PAGE_SHIFT;
	uint32_t entry_index = 0;

	if ((new_size & MEMFS_PAGE_MASK) != 0) {
		uint64_t group_index = tail_page >> MEMFS_PAGE_GROUP_SHIFT;
		MemfsPageGroup* group = memfs_storage_group(node, group_index);

		if (group) {
			uint32_t slot = (uint32_t)(tail_page & MEMFS_PAGE_GROUP_MASK);
			MemfsPage* old_page = memfs_group_get(group, slot);

			if (old_page) {
				uint8_t plain[MEMFS_PAGE_SIZE];
				MemfsPage* new_page = NULL;
				MemfsResult result;
				uint32_t in_page = (uint32_t)(new_size & MEMFS_PAGE_MASK);

				result = memfs_page_decode(node, tail_page, old_page, plain, MEMFS_PAGE_SIZE);
				if (result != MEMFS_OK)
					return result;

				memset(plain + in_page, 0, MEMFS_PAGE_SIZE - in_page);

				result = memfs_page_encode(node, tail_page, plain, MEMFS_PAGE_SIZE, &new_page);
				if (result != MEMFS_OK)
					return result;

				result = memfs_storage_replace_page(node, group, slot, new_page);
				if (result != MEMFS_OK) {
					memfs_page_free(node, new_page);
					return result;
				}
			}
		}
	}

	while (entry_index < memfs_storage_group_count(node)) {
		uint64_t group_index = memfs_storage_group_index_at(node, entry_index);
		MemfsPageGroup* group = memfs_storage_group_at(node, entry_index);
		uint32_t slot;

		for (slot = 0; slot < MEMFS_PAGES_PER_GROUP; slot++) {
			uint64_t page_index = (group_index << MEMFS_PAGE_GROUP_SHIFT) | slot;
			MemfsPage* page;
			MemfsResult result;

			if (page_index < first_free_page)
				continue;

			page = memfs_group_get(group, slot);
			if (page == NULL)
				continue;

			result = memfs_storage_replace_page(node, group, slot, NULL);
			if (result != MEMFS_OK)
				return result;
		}

		if (group->page_count == 0) {
			memfs_storage_remove_group(node, group_index);
			continue;
		}

		entry_index++;
	}

	return MEMFS_OK;
}

static void memfs_storage_try_demote(MemfsNode* node, uint64_t new_size) {
	uint32_t target;
	uint8_t plain[MEMFS_SMALL_LIMIT];
	MemfsPage* new_page = NULL;
	MemfsPage* first_page;
	MemfsResult result;

	if (memfs_storage_group_count(node) == 0 || new_size > MEMFS_SMALL_LIMIT) {
		return;
	}

	target = memfs_small_capacity(new_size);
	if (target == 0 && new_size != 0)
		return;

	memset(plain, 0, sizeof(plain));

	first_page = memfs_storage_page(node, 0);
	if (first_page) {
		result = memfs_page_decode(node, 0, first_page, plain, MEMFS_PAGE_SIZE);
		if (result != MEMFS_OK)
			return;
	}

	if (target && !memfs_small_inline_eligible(node, target)) {
		result = memfs_page_encode(node, UINT64_MAX, plain, (uint16_t)target, &new_page);
		if (result != MEMFS_OK)
			return;
	}

	memfs_storage_destroy_pages(node);

	if (memfs_small_inline_eligible(node, target)) {
		memfs_storage_replace_small_inline(node, plain, target);
	} else {
		memfs_storage_replace_small(node, new_page, target);
	}
}

static MemfsResult memfs_storage_trim_data(MemfsNode* node, uint64_t new_size) {
	MemfsResult result;

	if (memfs_storage_group_count(node) != 0) {
		result = memfs_storage_trim_pages(node, new_size);
		if (result != MEMFS_OK)
			return result;

		memfs_storage_try_demote(node, new_size);
		return MEMFS_OK;
	}

	return memfs_storage_trim_small(node, new_size);
}

static MemfsResult memfs_storage_read_range(MemfsNode* node, uint8_t* buffer, uint64_t offset, uint64_t length) {
	uint64_t done = 0;

	if (length == 0)
		return MEMFS_OK;

	if (memfs_storage_group_count(node) == 0) {
		uint64_t available = 0;
		uint8_t plain[MEMFS_SMALL_LIMIT];
		MemfsResult result;

		memset(buffer, 0, (size_t)length);

		if (node->small_capacity == 0 || offset >= node->small_capacity) {
			return MEMFS_OK;
		}

		memset(plain, 0, sizeof(plain));
		result = memfs_storage_decode_small(node, plain, sizeof(plain));
		if (result != MEMFS_OK)
			return result;

		available = node->small_capacity - offset;
		if (available > length)
			available = length;

		memcpy(buffer, plain + offset, (size_t)available);
		return MEMFS_OK;
	}

	while (done < length) {
		uint64_t pos = offset + done;
		uint64_t page_index = pos >> MEMFS_PAGE_SHIFT;
		uint32_t in_page = (uint32_t)(pos & MEMFS_PAGE_MASK);
		uint32_t span = MEMFS_PAGE_SIZE - in_page;
		MemfsPage* page = memfs_storage_page(node, page_index);

		if (span > length - done)
			span = (uint32_t)(length - done);

		if (page == NULL) {
			memset(buffer + done, 0, span);
		} else if (memfs_page_is_raw(page)) {
			memcpy(buffer + done,
				   memfs_page_raw_const_data(page) + in_page, span);
		} else if (page->flags == 0 &&
				   page->plain_size == MEMFS_PAGE_SIZE &&
				   page->stored_size == MEMFS_PAGE_SIZE) {
			memcpy(buffer + done, page->data + in_page, span);
		} else {
			uint8_t plain[MEMFS_PAGE_SIZE];
			MemfsResult result = memfs_page_decode(node, page_index, page, plain, MEMFS_PAGE_SIZE);

			if (result != MEMFS_OK)
				return result;

			memcpy(buffer + done, plain + in_page, span);
		}

		done += span;
	}

	return MEMFS_OK;
}

static MemfsResult memfs_storage_write_small(MemfsNode* node, const uint8_t* buffer, uint64_t offset, uint64_t length) {
	uint64_t end = offset + length;
	/* A short overwrite must keep the resident tail beyond this write. */
	uint32_t target = memfs_small_capacity(end > node->small_capacity ? end : node->small_capacity);
	uint8_t plain[MEMFS_SMALL_LIMIT];
	MemfsPage* new_page = NULL;
	MemfsResult result;

	if (target == 0)
		return MEMFS_ERR_INVALID;

	memset(plain, 0, sizeof(plain));

	if (node->small_capacity) {
		result = memfs_storage_decode_small(node, plain, sizeof(plain));
		if (result != MEMFS_OK)
			return result;
	}

	memcpy(plain + offset, buffer, (size_t)length);

	if (memfs_small_inline_eligible(node, target)) {
		memfs_storage_replace_small_inline(node, plain, target);
		return MEMFS_OK;
	}

	result = memfs_page_encode(node, UINT64_MAX, plain, (uint16_t)target, &new_page);
	if (result != MEMFS_OK)
		return result;

	memfs_storage_replace_small(node, new_page, target);
	return MEMFS_OK;
}

static bool memfs_storage_range_all_raw(MemfsNode* node,
									 uint64_t offset,
									 uint64_t length) {
	uint64_t end = offset + length;
	uint64_t first_page = offset >> MEMFS_PAGE_SHIFT;
	uint64_t last_page = (end - 1U) >> MEMFS_PAGE_SHIFT;
	uint64_t page_index;

	for (page_index = first_page; page_index <= last_page; page_index++) {
		MemfsPage* page = memfs_storage_page(node, page_index);
		if (page == NULL || !memfs_page_is_raw(page))
			return false;
	}

	return true;
}

static MemfsResult memfs_storage_write_existing_raw_pages(
	MemfsNode* node,
	const uint8_t* buffer,
	uint64_t offset,
	uint64_t length) {
	uint64_t done = 0;

	while (done < length) {
		uint64_t pos = offset + done;
		uint64_t page_index = pos >> MEMFS_PAGE_SHIFT;
		uint32_t in_page = (uint32_t)(pos & MEMFS_PAGE_MASK);
		uint32_t span = MEMFS_PAGE_SIZE - in_page;
		MemfsPage* page = memfs_storage_page(node, page_index);

		if (page == NULL || !memfs_page_is_raw(page))
			return MEMFS_ERR_DATA;
		if (span > length - done)
			span = (uint32_t)(length - done);

		memcpy(memfs_page_raw_data(page) + in_page, buffer + done, span);
		done += span;
	}

	return MEMFS_OK;
}
static MemfsResult memfs_storage_write_encoded_pages(MemfsNode* node, const uint8_t* buffer, uint64_t offset,
													 uint64_t length) {
	uint64_t end = offset + length;
	uint64_t first_page = offset >> MEMFS_PAGE_SHIFT;
	uint64_t last_page = (end - 1U) >> MEMFS_PAGE_SHIFT;
	uint64_t page_count = last_page - first_page + 1U;
	MemfsPage** replacements;
	size_t replacements_bytes;
	uint64_t i;
	MemfsResult result = MEMFS_OK;

	if (page_count > SIZE_MAX / sizeof(*replacements)) {
		return MEMFS_ERR_NO_MEMORY;
	}

	replacements_bytes = (size_t)page_count * sizeof(*replacements);
	replacements = memfs_allocator_alloc_zero(&node->fs->allocator, replacements_bytes);
	if (replacements == NULL)
		return MEMFS_ERR_NO_MEMORY;

	for (i = 0; i < page_count; i++) {
		uint64_t page_index = first_page + i;
		uint64_t page_start = page_index << MEMFS_PAGE_SHIFT;
		uint64_t write_start = offset > page_start ? offset : page_start;
		uint64_t page_end = page_start + MEMFS_PAGE_SIZE;
		uint64_t write_end = end < page_end ? end : page_end;
		uint32_t in_page = (uint32_t)(write_start - page_start);
		uint32_t span = (uint32_t)(write_end - write_start);
		const uint8_t* source = buffer + (write_start - offset);

		// 整页覆盖不需要先 decrypt/decompress 旧页。
		if (in_page == 0 && span == MEMFS_PAGE_SIZE) {
			result = memfs_page_encode(node, page_index, source, MEMFS_PAGE_SIZE, &replacements[i]);
		} else {
			uint8_t plain[MEMFS_PAGE_SIZE];
			MemfsPage* old_page = memfs_storage_page(node, page_index);

			result = memfs_page_decode(node, page_index, old_page, plain, MEMFS_PAGE_SIZE);
			if (result == MEMFS_OK) {
				memcpy(plain + in_page, source, span);

				result = memfs_page_encode(node, page_index, plain, MEMFS_PAGE_SIZE, &replacements[i]);
			}
		}

		if (result != MEMFS_OK)
			goto exit;
	}

	// 预创建 group 并为本次新增 page pointer 一次性 reserve，
	// commit 阶段因此不会再因为 pointer-vector realloc 失败而半提交。
	{
		uint64_t first_group = first_page >> MEMFS_PAGE_GROUP_SHIFT;
		uint64_t last_group = last_page >> MEMFS_PAGE_GROUP_SHIFT;
		uint64_t group_index;

		for (group_index = first_group; group_index <= last_group; group_index++) {
			uint64_t group_first = group_index << MEMFS_PAGE_GROUP_SHIFT;
			uint64_t group_last = group_first + MEMFS_PAGES_PER_GROUP - 1U;
			uint64_t begin = first_page > group_first ? first_page : group_first;
			uint64_t finish = last_page < group_last ? last_page : group_last;
			MemfsPageGroup* group = memfs_storage_group(node, group_index);
			uint32_t additions = 0;
			uint64_t page_index;

			for (page_index = begin; page_index <= finish; page_index++) {
				uint64_t replacement_index = page_index - first_page;
				uint32_t slot = (uint32_t)(page_index & MEMFS_PAGE_GROUP_MASK);

				if (replacements[replacement_index] && (group == NULL || !memfs_group_has(group, slot))) {
					additions++;
				}
			}

			if (additions == 0)
				continue;

			if (group == NULL) {
				result = memfs_storage_ensure_group(node, group_index, &group);
				if (result != MEMFS_OK)
					goto exit;
			}

			result = memfs_group_reserve(node, group, (uint32_t)group->page_count + additions);
			if (result != MEMFS_OK)
				goto exit;
		}
	}

	// 所有编码和 metadata 分配都成功以后才提交替换。
	// Commit without shrinking or removing groups: a group can be empty only
	// temporarily (zero prefix, data tail), and the reserved pointer capacity
	// must stay available until every page of this write is in place.
	for (i = 0; i < page_count; i++) {
		uint64_t page_index = first_page + i;
		uint64_t group_index = page_index >> MEMFS_PAGE_GROUP_SHIFT;
		uint32_t slot = (uint32_t)(page_index & MEMFS_PAGE_GROUP_MASK);
		MemfsPageGroup* group = memfs_storage_group(node, group_index);

		if (group) {
			result = memfs_storage_replace_page_ex(node, group, slot, replacements[i], false);
			if (result != MEMFS_OK)
				goto exit;

			replacements[i] = NULL;
		}
	}

exit:
	/* Also reclaims a group created during preparation if a later step failed. */
	memfs_storage_settle_groups(node, first_page >> MEMFS_PAGE_GROUP_SHIFT,
								last_page >> MEMFS_PAGE_GROUP_SHIFT);
	for (i = 0; i < page_count; i++)
		memfs_page_free(node, replacements[i]);
	memfs_allocator_free(&node->fs->allocator, replacements, replacements_bytes);
	return result;
}
static MemfsResult memfs_storage_write_range(MemfsNode* node, const uint8_t* buffer, uint64_t offset, uint64_t length) {
	uint64_t end = offset + length;
	MemfsResult result;

	if (length == 0)
		return MEMFS_OK;

	if (end <= MEMFS_SMALL_LIMIT && memfs_storage_group_count(node) == 0) {
		return memfs_storage_write_small(node, buffer, offset, length);
	}

	result = memfs_storage_promote(node);
	if (result != MEMFS_OK)
		return result;

	if (!node->fs->compression_enabled &&
		!node->fs->encryption_enabled &&
		memfs_storage_range_all_raw(node, offset, length)) {
		return memfs_storage_write_existing_raw_pages(
			node, buffer, offset, length);
	}

	return memfs_storage_write_encoded_pages(node, buffer, offset, length);
}
static void memfs_node_free(MemfsNode* node) {
	Memfs* fs;
	MemfsNode* stream_owner;

	if (node == NULL)
		return;

	fs = node->fs;
	stream_owner = node->named_stream ? node->parent : NULL;

	if (MEMFS_NODE_IS_DIRECTORY(node)) {
		memfs_dir_destroy(node->dir);
		memfs_object_free_dir(fs, node->dir);
	} else {
		memfs_storage_destroy(node);
	}

	memfs_atomic_sub_clamped(&fs->used_bytes, node->file_size);
	if (!node->named_stream)
		memfs_security_release(node->security);

	memfs_object_free_name(fs, node->name);
	memfs_object_free_node(fs, node);
	if (stream_owner != NULL && !fs->destroying)
		memfs_node_close(stream_owner);
}
static void memfs_dir_remove(MemfsNode* node);

static void memfs_destroy_namespace_tree(MemfsNode* root) {
	MemfsNode* current = root;

	/*
	 * Destruction must not depend on the process stack depth. Walk downward
	 * through non-empty directories and use the namespace parent link to
	 * return after the current directory becomes empty. Leaves are detached
	 * through the normal treap/hash removal path before being freed.
	 */
	while (current != NULL) {
		MemfsNode* child = NULL;
		MemfsNode* parent;

		if (MEMFS_NODE_IS_DIRECTORY(current)) {
			child = current->dir->root;
			while (child != NULL && child->tree_left != NULL)
				child = child->tree_left;
		}

		if (child != NULL) {
			if (MEMFS_NODE_IS_DIRECTORY(child) &&
			    child->dir != NULL &&
			    child->dir->root != NULL) {
				current = child;
				continue;
			}

			memfs_dir_remove(child);
			memfs_node_free(child);
			continue;
		}

		if (current == root) {
			memfs_node_free(current);
			return;
		}

		parent = current->parent;
		memfs_dir_remove(current);
		memfs_node_free(current);
		current = parent;
	}
}

static MemfsResult memfs_security_create(MemfsAllocator* allocator, PSECURITY_DESCRIPTOR security, MemfsSecurity** out_security) {
	DWORD size, revision;
	SECURITY_DESCRIPTOR_CONTROL control;
	MemfsSecurity* shared;

	if (out_security != NULL)
		*out_security = NULL;
	if (allocator == NULL || security == NULL || out_security == NULL ||
		!IsValidSecurityDescriptor(security) ||
		!GetSecurityDescriptorControl(security, &control, &revision))
		return MEMFS_ERR_INVALID;

	/* An absolute SD contains borrowed pointers. Never memcpy those into
	 * persistent node storage: normalize to one self-contained allocation. */
	if (control & SE_SELF_RELATIVE) {
		size = GetSecurityDescriptorLength(security);
	} else {
		size = 0;
		if (MakeSelfRelativeSD(security, NULL, &size) ||
			GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			return MEMFS_ERR_INVALID;
	}
	if (size < sizeof(SECURITY_DESCRIPTOR_RELATIVE))
		return MEMFS_ERR_INVALID;

	if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_SECURITY))
		return MEMFS_ERR_NO_MEMORY;

	shared = memfs_allocator_alloc_uninit(allocator, sizeof(*shared) + size);
	if (shared == NULL)
		return MEMFS_ERR_NO_MEMORY;

	shared->ref_count = 1;
	shared->size = size;
	shared->owner = allocator;
	if (control & SE_SELF_RELATIVE) {
		memcpy(shared->data, security, size);
	} else if (!MakeSelfRelativeSD(security, shared->data, &size)) {
		memfs_allocator_free(allocator, shared, sizeof(*shared) + shared->size);
		return MEMFS_ERR_INVALID;
	}

	*out_security = shared;
	return MEMFS_OK;
}

static void memfs_security_retain(MemfsSecurity* security) {
	if (security)
		InterlockedIncrement(&security->ref_count);
}

static void memfs_security_release(MemfsSecurity* security) {
	if (security == NULL)
		return;

	if (InterlockedDecrement(&security->ref_count) == 0) {
		MemfsAllocator* owner = security->owner;
		size_t bytes = sizeof(*security) + security->size;
		SecureZeroMemory(security->data, security->size);
		memfs_allocator_free(owner, security, bytes);
	}
}

static bool memfs_security_equal(const MemfsSecurity* shared, PSECURITY_DESCRIPTOR security) {
	DWORD size, revision;
	SECURITY_DESCRIPTOR_CONTROL control;

	if (shared == NULL || security == NULL || !IsValidSecurityDescriptor(security) ||
		!GetSecurityDescriptorControl(security, &control, &revision) ||
		!(control & SE_SELF_RELATIVE))
		return false;

	size = GetSecurityDescriptorLength(security);
	return size == shared->size && 0 == memcmp(shared->data, security, size);
}

static MemfsResult memfs_default_security(MemfsAllocator* allocator, MemfsSecurity** out_security) {
	PSECURITY_DESCRIPTOR descriptor = NULL;
	ULONG size = 0;
	MemfsResult result;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(MEMFS_DEFAULT_SDDL, SDDL_REVISION_1, &descriptor,
															  &size)) {
		return MEMFS_ERR_ACCESS;
	}

	result = memfs_security_create(allocator, descriptor, out_security);
	LocalFree(descriptor);
	return result;
}

/*
 * Names are case-insensitive and case-preserving, like NTFS: lookup,
 * collision checks, ordering and hashing all use the system upcase mapping
 * (RtlUpcaseUnicodeChar, the table NTFS and FsRtl use) on UTF-16 code units.
 */
static wchar_t g_memfs_upcase[65536];
static INIT_ONCE g_memfs_upcase_once = INIT_ONCE_STATIC_INIT;

typedef WCHAR (NTAPI* MemfsRtlUpcaseUnicodeCharFn)(WCHAR);

static BOOL CALLBACK memfs_upcase_init(PINIT_ONCE once, PVOID parameter, PVOID* context) {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	MemfsRtlUpcaseUnicodeCharFn upcase = NULL;
	uint32_t c;

	(void)once;
	(void)parameter;
	(void)context;
	if (ntdll != NULL)
		upcase = (MemfsRtlUpcaseUnicodeCharFn)(void*)GetProcAddress(ntdll, "RtlUpcaseUnicodeChar");
	for (c = 0; c < 65536U; c++) {
		wchar_t value = (wchar_t)c;
		if (upcase != NULL)
			value = upcase(value);
		else if (c >= L'a' && c <= L'z')
			value = (wchar_t)(c - L'a' + L'A');
		g_memfs_upcase[c] = value;
	}
	return TRUE;
}

static void memfs_upcase_ensure(void) {
	(void)InitOnceExecuteOnce(&g_memfs_upcase_once, memfs_upcase_init, NULL, NULL);
}

static int memfs_name_compare(const wchar_t* left, const wchar_t* right) {
	uint16_t a;
	uint16_t b;

	for (;;) {
		a = (uint16_t)g_memfs_upcase[(uint16_t)*left];
		b = (uint16_t)g_memfs_upcase[(uint16_t)*right];
		if (a != b || *left == L'\0' || *right == L'\0')
			break;
		left++;
		right++;
	}
	if (a == b)
		return 0;
	return a < b ? -1 : 1;
}

static uint32_t memfs_name_hash(const wchar_t* name) {
	uint32_t hash = 2166136261U;

	while (*name) {
		uint32_t c = (uint16_t)g_memfs_upcase[(uint16_t)*name++];
		hash ^= c;
		hash *= 16777619U;
	}

	return hash;
}

static uint32_t memfs_dir_hash_probe_distance(const MemfsDirHash* hash, const MemfsNode* node, uint32_t slot) {
	uint32_t mask = hash->capacity - 1U;
	uint32_t ideal = node->name_hash & mask;

	return (slot - ideal) & mask;
}

static MemfsNode* memfs_dir_hash_lookup(MemfsDirHash* hash, const wchar_t* name) {
	uint32_t name_hash = memfs_name_hash(name);
	uint32_t mask = hash->capacity - 1U;
	uint32_t slot = name_hash & mask;
	uint32_t distance = 0;

	for (;;) {
		MemfsNode* node = hash->slots[slot];
		uint32_t node_distance;

		if (node == NULL)
			return NULL;

		node_distance = memfs_dir_hash_probe_distance(hash, node, slot);
		if (node_distance < distance)
			return NULL;

		if (node->name_hash == name_hash && memfs_name_compare(node->name, name) == 0) {
			return node;
		}

		slot = (slot + 1U) & mask;
		distance++;

		if (distance >= hash->capacity)
			return NULL;
	}
}

static bool memfs_dir_hash_insert_node(MemfsDirHash* hash, MemfsNode* node) {
	uint32_t mask = hash->capacity - 1U;
	uint32_t slot = node->name_hash & mask;
	uint32_t distance = 0;
	MemfsNode* candidate = node;

	for (;;) {
		MemfsNode* current = hash->slots[slot];

		if (current == NULL) {
			hash->slots[slot] = candidate;
			hash->count++;
			return true;
		}

		if (current == candidate)
			return true;

		{
			uint32_t current_distance = memfs_dir_hash_probe_distance(hash, current, slot);

			if (current_distance < distance) {
				hash->slots[slot] = candidate;
				candidate = current;
				distance = current_distance;
			}
		}

		slot = (slot + 1U) & mask;
		distance++;

		if (distance >= hash->capacity)
			return false;
	}
}

static bool memfs_dir_hash_remove_node(MemfsDirHash* hash, MemfsNode* node) {
	uint32_t mask = hash->capacity - 1U;
	uint32_t slot = node->name_hash & mask;
	uint32_t distance = 0;

	for (;;) {
		MemfsNode* current = hash->slots[slot];

		if (current == NULL)
			return false;

		if (current == node)
			break;

		if (memfs_dir_hash_probe_distance(hash, current, slot) < distance)
			return false;

		slot = (slot + 1U) & mask;
		distance++;
		if (distance >= hash->capacity)
			return false;
	}

	// Backward-shift deletion keeps the Robin Hood invariant and eliminates
	// tombstones, which is important for long-lived create/delete workloads.
	for (;;) {
		uint32_t next = (slot + 1U) & mask;
		MemfsNode* current = hash->slots[next];

		if (current == NULL || memfs_dir_hash_probe_distance(hash, current, next) == 0) {
			hash->slots[slot] = NULL;
			break;
		}

		hash->slots[slot] = current;
		slot = next;
	}

	hash->count--;
	return true;
}

static void memfs_dir_hash_fill_tree(MemfsDirHash* hash, MemfsNode* node, bool* ok) {
	if (node == NULL || !*ok)
		return;

	memfs_dir_hash_fill_tree(hash, node->tree_left, ok);

	if (*ok && !memfs_dir_hash_insert_node(hash, node))
		*ok = false;

	memfs_dir_hash_fill_tree(hash, node->tree_right, ok);
}

static bool memfs_dir_hash_rebuild(MemfsDir* dir, uint32_t capacity) {
	MemfsAllocator* allocator;
	MemfsDirHash* hash;
	bool ok = true;

	if (capacity < 128U)
		capacity = 128U;

	if (capacity & (capacity - 1U))
		return false;

	allocator = dir->hash ? dir->hash->owner : (dir->root ? &dir->root->fs->allocator : NULL);
	if (allocator == NULL)
		return false;

	hash = memfs_allocator_alloc_zero(allocator, sizeof(*hash));
	if (hash == NULL)
		return false;
	hash->owner = allocator;

	hash->slots = memfs_allocator_alloc_zero(allocator, (size_t)capacity * sizeof(*hash->slots));
	if (hash->slots == NULL) {
		memfs_allocator_free(allocator, hash, sizeof(*hash));
		return false;
	}

	hash->capacity = capacity;
	memfs_dir_hash_fill_tree(hash, dir->root, &ok);

	if (!ok || hash->count != dir->child_count) {
		memfs_dir_hash_free(hash);
		return false;
	}

	if (dir->hash)
		memfs_dir_hash_free(dir->hash);

	dir->hash = hash;
	return true;
}

static void memfs_dir_hash_disable(MemfsDir* dir) {
	if (dir->hash == NULL)
		return;

	memfs_dir_hash_free(dir->hash);
	dir->hash = NULL;
}

static uint32_t memfs_dir_hash_capacity_for_count(uint32_t count) {
	uint32_t capacity = 128U;

	while ((uint64_t)count * 100ULL > (uint64_t)capacity * MEMFS_DIR_HASH_LOAD_PERCENT) {
		if (capacity > UINT32_MAX / 2U)
			return capacity;
		capacity <<= 1;
	}

	return capacity;
}

static void memfs_dir_hash_after_insert(MemfsDir* dir, MemfsNode* node) {
	MemfsDirHash* hash = dir->hash;

	if (hash == NULL) {
		if (dir->child_count >= MEMFS_DIR_HASH_THRESHOLD) {
			uint32_t capacity = memfs_dir_hash_capacity_for_count(dir->child_count);

			(void)memfs_dir_hash_rebuild(dir, capacity);
		}
		return;
	}

	if ((uint64_t)(hash->count + 1U) * 100ULL > (uint64_t)hash->capacity * MEMFS_DIR_HASH_LOAD_PERCENT) {
		if (hash->capacity <= UINT32_MAX / 2U && memfs_dir_hash_rebuild(dir, hash->capacity << 1)) {
			return;
		}
	}

	hash = dir->hash;
	if (!memfs_dir_hash_insert_node(hash, node))
		memfs_dir_hash_disable(dir);
}

static void memfs_dir_hash_before_remove(MemfsDir* dir, MemfsNode* node) {
	if (dir->hash)
		(void)memfs_dir_hash_remove_node(dir->hash, node);
}

static void memfs_dir_hash_after_remove(MemfsDir* dir) {
	MemfsDirHash* hash = dir->hash;

	if (hash == NULL)
		return;

	if (dir->child_count < MEMFS_DIR_HASH_THRESHOLD / 2U) {
		memfs_dir_hash_disable(dir);
		return;
	}

	{
		uint32_t target = memfs_dir_hash_capacity_for_count(dir->child_count);

		if (target < hash->capacity)
			(void)memfs_dir_hash_rebuild(dir, target);
	}
}

static uint32_t memfs_treap_priority(const MemfsNode* node) {
	uint64_t x = (uint64_t)(uintptr_t)node ^
				 node->fs->treap_seed ^
				 0xd1b54a32d192ed03ULL;

	x = memfs_mix64(x);
	return (uint32_t)(x ^ (x >> 32));
}

static void memfs_tree_replace_parent_child(MemfsDir* dir, MemfsNode* parent, MemfsNode* old_child,
											MemfsNode* new_child) {
	if (parent == NULL) {
		dir->root = new_child;
	} else if (parent->tree_left == old_child) {
		parent->tree_left = new_child;
	} else {
		parent->tree_right = new_child;
	}

	if (new_child)
		new_child->tree_parent = parent;
}

static void memfs_tree_rotate_left(MemfsDir* dir, MemfsNode* node) {
	MemfsNode* right = node->tree_right;
	MemfsNode* parent = node->tree_parent;

	node->tree_right = right->tree_left;
	if (right->tree_left)
		right->tree_left->tree_parent = node;

	right->tree_left = node;
	node->tree_parent = right;

	memfs_tree_replace_parent_child(dir, parent, node, right);
}

static void memfs_tree_rotate_right(MemfsDir* dir, MemfsNode* node) {
	MemfsNode* left = node->tree_left;
	MemfsNode* parent = node->tree_parent;

	node->tree_left = left->tree_right;
	if (left->tree_right)
		left->tree_right->tree_parent = node;

	left->tree_right = node;
	node->tree_parent = left;

	memfs_tree_replace_parent_child(dir, parent, node, left);
}

static void memfs_dir_insert(MemfsNode* parent, MemfsNode* node) {
	MemfsDir* dir = parent->dir;
	MemfsNode* current = dir->root;
	MemfsNode* tree_parent = NULL;
	int cmp = 0;

	node->tree_left = NULL;
	node->tree_right = NULL;
	node->tree_parent = NULL;

	while (current) {
		tree_parent = current;
		cmp = memfs_name_compare(node->name, current->name);
		current = cmp < 0 ? current->tree_left : current->tree_right;
	}

	node->tree_parent = tree_parent;
	if (tree_parent == NULL) {
		dir->root = node;
	} else if (cmp < 0) {
		tree_parent->tree_left = node;
	} else {
		tree_parent->tree_right = node;
	}

	while (node->tree_parent && memfs_treap_priority(node->tree_parent) > memfs_treap_priority(node)) {
		if (node->tree_parent->tree_left == node)
			memfs_tree_rotate_right(dir, node->tree_parent);
		else
			memfs_tree_rotate_left(dir, node->tree_parent);
	}

	dir->child_count++;
	node->parent = parent;
	memfs_dir_hash_after_insert(dir, node);
}

static void memfs_dir_remove(MemfsNode* node) {
	MemfsNode* parent = node->parent;
	MemfsDir* dir;

	if (!MEMFS_NODE_IS_DIRECTORY(parent))
		return;

	dir = parent->dir;
	memfs_dir_hash_before_remove(dir, node);

	while (node->tree_left || node->tree_right) {
		if (node->tree_left == NULL) {
			memfs_tree_rotate_left(dir, node);
		} else if (node->tree_right == NULL) {
			memfs_tree_rotate_right(dir, node);
		} else if (memfs_treap_priority(node->tree_left) < memfs_treap_priority(node->tree_right)) {
			memfs_tree_rotate_right(dir, node);
		} else {
			memfs_tree_rotate_left(dir, node);
		}
	}

	memfs_tree_replace_parent_child(dir, node->tree_parent, node, NULL);

	if (dir->child_count)
		dir->child_count--;

	memfs_dir_hash_after_remove(dir);

	node->tree_left = NULL;
	node->tree_right = NULL;
	node->tree_parent = NULL;
	node->parent = NULL;
}
static void memfs_touch_directory(MemfsNode* dir) {

	if (dir == NULL)
		return;

	memfs_node_set_change_time(dir, memfs_now());
}

static MemfsResult memfs_node_alloc(Memfs* fs, MemfsNode* parent, const wchar_t* name, bool directory,
									uint32_t attributes, PSECURITY_DESCRIPTOR security, MemfsNode** out_node) {
	const wchar_t* source_name = name ? name : L"";
	MemfsNode* node;
	MemfsResult result;

	if (fs == NULL || out_node == NULL)
		return MEMFS_ERR_INVALID;

	*out_node = NULL;

	node = memfs_object_alloc_node(fs);
	if (node == NULL)
		return MEMFS_ERR_NO_MEMORY;

	node->fs = fs;

	if (directory) {
		node->dir = memfs_object_alloc_dir(fs);
		if (node->dir == NULL) {
			memfs_object_free_node(fs, node);
			return MEMFS_ERR_NO_MEMORY;
		}
		attributes |= FILE_ATTRIBUTE_DIRECTORY;
	} else {
		attributes &= ~FILE_ATTRIBUTE_DIRECTORY;
		if (attributes == 0)
			attributes = FILE_ATTRIBUTE_NORMAL;
	}

	node->name = memfs_object_dup_name(fs, source_name);
	if (node->name == NULL) {
		if (directory)
			memfs_object_free_dir(fs, node->dir);
		memfs_object_free_node(fs, node);
		return MEMFS_ERR_NO_MEMORY;
	}

	node->name_hash = memfs_name_hash(node->name);

	if (security) {
		MemfsSecurity* inherited = parent ? memfs_node_get_security(parent) : NULL;

		if (inherited && memfs_security_equal(inherited, security)) {
			node->security = inherited;
			memfs_security_retain(node->security);
			result = MEMFS_OK;
		} else {
			result = memfs_security_create(&fs->allocator, security, &node->security);
		}
	} else if (parent && memfs_node_get_security(parent)) {
		node->security = memfs_node_get_security(parent);
		memfs_security_retain(node->security);
		result = MEMFS_OK;
	} else {
		result = memfs_default_security(&fs->allocator, &node->security);
	}

	if (result != MEMFS_OK) {
		memfs_object_free_name(fs, node->name);
		if (directory)
			memfs_object_free_dir(fs, node->dir);
		memfs_object_free_node(fs, node);
		return result;
	}

	node->attributes = attributes;
	node->creation_time = memfs_now();
	node->last_access_time = node->creation_time;
	node->last_write_time = node->creation_time;
	node->change_time = node->creation_time;

	*out_node = node;
	return MEMFS_OK;
}

static MemfsResult memfs_resize_allocation(MemfsNode* node, uint64_t allocation_size) {
	uint64_t old_size = node->allocation_size;
	MemfsResult result;

	if (allocation_size == old_size)
		return MEMFS_OK;

	if (allocation_size < old_size) {
		result = memfs_storage_trim_data(node, allocation_size);
		if (result != MEMFS_OK)
			return result;
	}

	node->allocation_size = allocation_size;
	return MEMFS_OK;
}

static MemfsResult memfs_account_file_size(MemfsNode* node, uint64_t old_size, uint64_t new_size) {
	Memfs* fs = node->fs;

	/* Block backing: a file size is a virtual disk extent, not data. Only
	 * resident pages count (checked by the block layer before each write). */
	if (new_size == old_size || fs->block_backing)
		return MEMFS_OK;

	if (new_size > old_size) {
		uint64_t delta = new_size - old_size;
		uint64_t reserve_limit = fs->capacity_auto ? (uint64_t)INT64_MAX : fs->capacity;

		/* Auto capacity is governed by the current system-memory allowance, not
		 * fs->capacity (which is intentionally zero in auto mode). Keep the
		 * logical used_bytes update atomic, but only apply the fixed byte quota
		 * when capacity_auto is disabled. */
		if (!memfs_capacity_allows(fs, delta) ||
			!memfs_atomic_reserve(&fs->used_bytes, reserve_limit, delta)) {
			return MEMFS_ERR_NO_SPACE;
		}
	} else {
		memfs_atomic_sub_clamped(&fs->used_bytes, old_size - new_size);
	}

	return MEMFS_OK;
}

uint64_t memfs_now(void) {
	FILETIME ft;
	ULARGE_INTEGER value;

	/*
	 * Windows 10+ guarantees GetSystemTimePreciseAsFileTime. The precise
	 * system clock is useful for build/cache workloads where multiple writes
	 * can otherwise collapse onto the same coarse filesystem timestamp.
	 */
	GetSystemTimePreciseAsFileTime(&ft);
	value.LowPart = ft.dwLowDateTime;
	value.HighPart = ft.dwHighDateTime;
	return value.QuadPart;
}

uint64_t memfs_align_allocation(uint64_t size) {
	uint64_t mask = MEMFS_ALLOCATION_UNIT - 1U;

	if (size > UINT64_MAX - mask)
		return UINT64_MAX;
	return (size + mask) & ~mask;
}

uint64_t memfs_free_bytes(Memfs* fs) {
	uint64_t used;

	if (fs == NULL)
		return 0;

	if (fs->capacity_auto)
		return memfs_auto_allowance_bytes(fs);

	used = memfs_atomic_load_u64(&fs->used_bytes);
	return used <= fs->capacity ? fs->capacity - used : 0;
}

uint64_t memfs_committed_bytes(Memfs* fs) {
	if (fs == NULL)
		return 0;

	return memfs_allocator_committed_bytes(&fs->allocator);
}

uint64_t memfs_physical_bytes(Memfs* fs) {
	return memfs_committed_bytes(fs);
}

void memfs_get_runtime_stats(Memfs* fs, MemfsRuntimeStats* stats) {
	MemfsAllocatorStats allocator_stats;
	uint64_t used;

	if (stats == NULL)
		return;

	memset(stats, 0, sizeof(*stats));
	if (fs == NULL)
		return;

	memfs_allocator_get_stats(&fs->allocator, &allocator_stats);
	used = memfs_atomic_load_u64(&fs->used_bytes);

	stats->logical_used_bytes = used;
	stats->resident_bytes = memfs_atomic_load_u64(&fs->resident_bytes);
	stats->capacity_bytes = fs->capacity;
	stats->capacity_auto = fs->capacity_auto;
	stats->auto_hard_margin_bytes = MEMFS_AUTO_HARD_MARGIN_BYTES;
	stats->auto_soft_margin_bytes = MEMFS_AUTO_SOFT_MARGIN_BYTES;
	stats->auto_allowance_bytes = fs->capacity_auto
		? memfs_auto_allowance_bytes(fs)
		: 0;
	stats->free_bytes = fs->capacity_auto
		? stats->auto_allowance_bytes
		: (used <= fs->capacity ? fs->capacity - used : 0);

	stats->allocator_live_bytes = allocator_stats.live_bytes;
	stats->allocator_live_objects = allocator_stats.live_objects;
	stats->allocator_reserved_bytes = allocator_stats.reserved_bytes;
	stats->allocator_committed_bytes = allocator_stats.committed_bytes;
	stats->allocator_physical_bytes = allocator_stats.physical_bytes;
	stats->allocator_scavenged_bytes = allocator_stats.scavenged_bytes;
	stats->allocator_scavenge_count = allocator_stats.scavenge_count;
	stats->slab_count = allocator_stats.slab_count;
	stats->area_count = allocator_stats.dedicated_count;
	stats->area_cached_count = allocator_stats.area_cached_count;
	stats->area_cached_bytes = allocator_stats.area_cached_bytes;
}

uint64_t memfs_resident_bytes(Memfs* fs) {
	if (fs == NULL)
		return 0;

	return memfs_atomic_load_u64(&fs->resident_bytes);
}

uint64_t memfs_node_resident_bytes(const MemfsNode* node) {
	uint64_t resident = 0;
	uint32_t entry_index;

	if (node == NULL)
		return 0;

	if (node->small_capacity && !node->small_inline)
		resident += memfs_page_heap_size(node->small_page);

	for (entry_index = 0; entry_index < memfs_storage_group_count(node); entry_index++) {
		const MemfsPageGroup* group = memfs_storage_group_at(node, entry_index);
		uint32_t i;

		if (group == NULL)
			continue;

		for (i = 0; i < group->page_count; i++)
			resident += memfs_page_heap_size(memfs_group_page_at_rank(group, i));
	}

	return resident;
}

MemfsResult memfs_create_ex(const MemfsOptions* options, Memfs** out_fs) {
	Memfs* fs;
	MemfsNode* root;
	MemfsResult result;
	const wchar_t* volume_label;
	size_t label_chars;
	uint8_t encryption_master_key[MEMFS_ENCRYPTION_KEY_SIZE] = {0};

	if (options == NULL || out_fs == NULL || (!options->capacity_auto && options->capacity == 0) ||
		options->capacity > INT64_MAX) {
		return MEMFS_ERR_INVALID;
	}
	/* Every name comparison below depends on the upcase table. */
	memfs_upcase_ensure();

	if (options->encryption_key && options->encryption_key_size != MEMFS_ENCRYPTION_KEY_SIZE) {
		return MEMFS_ERR_INVALID;
	}

	if (sodium_init() < 0)
		return MEMFS_ERR_ACCESS;

	fs = memfs_allocator_alloc_control(sizeof(*fs));
	if (fs == NULL)
		return MEMFS_ERR_NO_MEMORY;

	if (!memfs_allocator_init(&fs->allocator, sizeof(MemfsNode), sizeof(MemfsDir), sizeof(MemfsPageGroup))) {
		memfs_allocator_free_control(fs, sizeof(*fs));
		return MEMFS_ERR_NO_MEMORY;
	}
	if (options->capacity_auto && options->auto_reserve_bytes != 0 &&
		!memfs_allocator_set_reserve(&fs->allocator, options->auto_reserve_bytes)) {
		memfs_allocator_destroy(&fs->allocator);
		memfs_allocator_free_control(fs, sizeof(*fs));
		return MEMFS_ERR_NO_SPACE;
	}

	for (uint32_t i = 0; i < MEMFS_COMPRESSION_CONTEXT_LANES; i++) {
		InitializeSRWLock(&fs->compression_lanes[i].lock);
		fs->compression_lanes[i].context = NULL;
		InitializeSRWLock(&fs->decompression_lanes[i].lock);
		fs->decompression_lanes[i].context = NULL;
	}

	fs->capacity = options->capacity;
	fs->capacity_auto = options->capacity_auto;
	fs->block_backing = options->block_backing;
	InitializeSRWLock(&fs->lifetime_lock);
	fs->pressure_last_scavenge_tick = 0;
	InitializeSRWLock(&fs->auto_available_refresh_lock);
	fs->auto_available_cached_bytes = 0;
	fs->auto_available_cached_commit_total = 0;
	fs->auto_available_sample_qpc = 0;
	fs->auto_available_cache_deadline_qpc = 0;
	fs->auto_available_cache_interval_qpc = 0;
	{
		LARGE_INTEGER frequency;
		if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0) {
			fs->auto_available_cache_interval_qpc =
				(uint64_t)frequency.QuadPart / (1000000ULL / MEMFS_AUTO_AVAILABLE_CACHE_INTERVAL_US);
			if (fs->auto_available_cache_interval_qpc == 0)
				fs->auto_available_cache_interval_qpc = 1;
		}
	}
	randombytes_buf(&fs->treap_seed, sizeof(fs->treap_seed));
	if (fs->treap_seed == 0)
		fs->treap_seed = 0x9e3779b97f4a7c15ULL;
	fs->compression_enabled = options->compression_enabled;
	fs->compression_level = options->compression_level ? options->compression_level : 1;

	if (fs->compression_enabled) {
		if (fs->compression_level < ZSTD_minCLevel())
			fs->compression_level = ZSTD_minCLevel();
		if (fs->compression_level > ZSTD_maxCLevel())
			fs->compression_level = ZSTD_maxCLevel();
	}

	fs->encryption_enabled = options->encryption_enabled || options->encryption_key != NULL;
	fs->encryption_aes_gcm = false;

	if (fs->encryption_enabled) {
		bool aes_available;

		if (options->encryption_key) {
			memcpy(encryption_master_key,
				   options->encryption_key,
				   MEMFS_ENCRYPTION_KEY_SIZE);
		} else {
			randombytes_buf(encryption_master_key, MEMFS_ENCRYPTION_KEY_SIZE);
		}

		/*
		 * Keep the master key for XChaCha pages and derive an independent
		 * mount-specific AES root key. This lets the decoder honor each
		 * page's authenticated algorithm flag even if the preferred
		 * algorithm changes while the mount is alive.
		 */
		memcpy(fs->encryption_key,
			   encryption_master_key,
			   MEMFS_ENCRYPTION_KEY_SIZE);
		memset(fs->encryption_aes_key, 0, sizeof(fs->encryption_aes_key));
		InitializeSRWLock(&fs->encryption_aes_epoch_lock);
		fs->encryption_aes_epoch = 0;
		memset(fs->encryption_aes_epoch_key, 0,
			   sizeof(fs->encryption_aes_epoch_key));
		fs->encryption_aes_epoch_valid = false;
		randombytes_buf(fs->encryption_nonce_prefix,
						MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE);
		fs->encryption_nonce_counter = 0;

		aes_available = crypto_aead_aes256gcm_is_available() != 0;
		if (aes_available &&
			!memfs_derive_aes_gcm_key(
				encryption_master_key,
				fs->encryption_nonce_prefix,
				fs->encryption_aes_key)) {
			sodium_memzero(encryption_master_key,
						   sizeof(encryption_master_key));
			sodium_memzero(fs->encryption_key,
						   MEMFS_ENCRYPTION_KEY_SIZE);
			sodium_memzero(fs->encryption_aes_key,
						   MEMFS_ENCRYPTION_KEY_SIZE);
			sodium_memzero(fs->encryption_nonce_prefix,
						   MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE);
			memfs_allocator_destroy(&fs->allocator);
			memfs_allocator_free_control(fs, sizeof(*fs));
			return MEMFS_ERR_ACCESS;
		}

		fs->encryption_aes_gcm = aes_available;
#if !defined(NDEBUG)
		if (InterlockedCompareExchange(
				&g_memfs_test_force_xchacha, 0, 0) != 0)
			fs->encryption_aes_gcm = false;
#endif

		sodium_memzero(encryption_master_key, sizeof(encryption_master_key));
		(void)sodium_mlock(fs->encryption_key, MEMFS_ENCRYPTION_KEY_SIZE);
		(void)sodium_mlock(fs->encryption_aes_key,
						  MEMFS_ENCRYPTION_KEY_SIZE);
		(void)sodium_mlock(fs->encryption_aes_epoch_key,
						  MEMFS_ENCRYPTION_KEY_SIZE);
	}

	volume_label = options->volume_label;
	if (volume_label == NULL || *volume_label == L'\0')
		volume_label = L"MEMFS";

	label_chars = wcslen(volume_label);
	if (label_chars > 31)
		label_chars = 31;

	memcpy(fs->volume_label, volume_label, label_chars * sizeof(wchar_t));
	fs->volume_label[label_chars] = L'\0';
	fs->volume_label_bytes = (uint16_t)(label_chars * sizeof(wchar_t));

	result = memfs_node_alloc(fs, NULL, L"", true, FILE_ATTRIBUTE_DIRECTORY, NULL, &root);
	if (result != MEMFS_OK) {
		if (fs->encryption_enabled) {
			sodium_memzero(fs->encryption_key, MEMFS_ENCRYPTION_KEY_SIZE);
			sodium_memzero(fs->encryption_aes_key, MEMFS_ENCRYPTION_KEY_SIZE);
			sodium_memzero(fs->encryption_aes_epoch_key,
						   MEMFS_ENCRYPTION_KEY_SIZE);
			(void)sodium_munlock(fs->encryption_key, MEMFS_ENCRYPTION_KEY_SIZE);
			(void)sodium_munlock(fs->encryption_aes_key,
							 MEMFS_ENCRYPTION_KEY_SIZE);
			(void)sodium_munlock(fs->encryption_aes_epoch_key,
							 MEMFS_ENCRYPTION_KEY_SIZE);
		}
		memfs_allocator_destroy(&fs->allocator);
		memfs_allocator_free_control(fs, sizeof(*fs));
		return result;
	}

	fs->root = root;
	*out_fs = fs;
	return MEMFS_OK;
}

MemfsResult memfs_create(uint64_t capacity, const wchar_t* volume_label, Memfs** out_fs) {
	MemfsOptions options;

	memset(&options, 0, sizeof(options));
	options.capacity = capacity;
	options.capacity_auto = false;
	options.volume_label = volume_label;
	return memfs_create_ex(&options, out_fs);
}
void memfs_destroy(Memfs* fs) {
	MemfsNode* node;

	if (fs == NULL)
		return;

    /* Quiescent teardown: streams can pin both linked and orphan owners.
     * Drain the index before freeing owners, and suppress pin releases while
     * destroying so orphan order never dereferences an already-freed owner. */
    fs->destroying = true;
    for (unsigned i = 0; i < 64; ++i) {
        while ((node = fs->stream_buckets[i]) != NULL) {
            fs->stream_buckets[i] = node->tree_left;
            memfs_node_free(node);
        }
    }
	node = fs->root;
	fs->root = NULL;
	memfs_destroy_namespace_tree(node);

	while ((node = fs->orphan_head) != NULL) {
		memfs_orphan_remove(fs, node);
		memfs_node_free(node);
	}

	if (fs->encryption_enabled) {
		sodium_memzero(fs->encryption_key, MEMFS_ENCRYPTION_KEY_SIZE);
		sodium_memzero(fs->encryption_aes_key, MEMFS_ENCRYPTION_KEY_SIZE);
		sodium_memzero(fs->encryption_aes_epoch_key,
					   MEMFS_ENCRYPTION_KEY_SIZE);
		sodium_memzero(fs->encryption_nonce_prefix, MEMFS_ENCRYPTION_NONCE_PREFIX_SIZE);
		(void)sodium_munlock(fs->encryption_key, MEMFS_ENCRYPTION_KEY_SIZE);
		(void)sodium_munlock(fs->encryption_aes_key,
						 MEMFS_ENCRYPTION_KEY_SIZE);
		(void)sodium_munlock(fs->encryption_aes_epoch_key,
						 MEMFS_ENCRYPTION_KEY_SIZE);
	}

	memfs_compression_contexts_destroy(fs);
	memfs_allocator_destroy(&fs->allocator);
	memfs_allocator_free_control(fs, sizeof(*fs));
}

MemfsNode* memfs_dir_lookup(MemfsNode* dir_node, const wchar_t* name) {
	MemfsNode* node;

	if (!MEMFS_NODE_IS_DIRECTORY(dir_node) || name == NULL)
		return NULL;

	if (dir_node->dir->hash) {
		node = memfs_dir_hash_lookup(dir_node->dir->hash, name);
		if (node)
			return node->deleted ? NULL : node;
	}

	node = dir_node->dir->root;
	while (node) {
		int cmp = memfs_name_compare(name, node->name);

		if (cmp == 0)
			return node->deleted ? NULL : node;

		node = cmp < 0 ? node->tree_left : node->tree_right;
	}

	return NULL;
}

MemfsNode* memfs_dir_first(MemfsNode* dir_node) {
	MemfsNode* node;

	if (!MEMFS_NODE_IS_DIRECTORY(dir_node))
		return NULL;

	node = dir_node->dir->root;
	if (node == NULL)
		return NULL;

	while (node->tree_left)
		node = node->tree_left;

	return node;
}

MemfsNode* memfs_dir_upper_bound(MemfsNode* dir_node, const wchar_t* marker) {
	MemfsNode* node;
	MemfsNode* candidate = NULL;

	if (!MEMFS_NODE_IS_DIRECTORY(dir_node) || marker == NULL) {
		return NULL;
	}

	node = dir_node->dir->root;
	while (node) {
		int cmp = memfs_name_compare(node->name, marker);

		if (cmp > 0) {
			candidate = node;
			node = node->tree_left;
		} else {
			node = node->tree_right;
		}
	}

	return candidate;
}

MemfsNode* memfs_dir_next(MemfsNode* node) {
	MemfsNode* parent;

	if (node == NULL)
		return NULL;

	if (node->tree_right) {
		node = node->tree_right;
		while (node->tree_left)
			node = node->tree_left;
		return node;
	}

	parent = node->tree_parent;
	while (parent && parent->tree_right == node) {
		node = parent;
		parent = parent->tree_parent;
	}
	return parent;
}
static MemfsResult memfs_lookup_path_span(Memfs* fs,
                                          const wchar_t* path,
                                          const wchar_t* end,
                                          MemfsNode** out_node) {
	const wchar_t* p;
	MemfsNode* node;
	wchar_t component[MEMFS_MAX_NAME + 1];

	if (out_node != NULL)
		*out_node = NULL;

	if (fs == NULL || path == NULL || end == NULL || out_node == NULL ||
		path[0] != L'\\' || end < path) {
		return MEMFS_ERR_INVALID;
	}

	node = fs->root;
	p = path;

	while (p < end) {
		size_t len = 0;

		while (p < end && *p == L'\\')
			p++;
		if (p >= end)
			break;

		while (p + len < end && p[len] != L'\\') {
			if (len >= MEMFS_MAX_NAME)
				return MEMFS_ERR_INVALID;
			component[len] = p[len];
			len++;
		}
		component[len] = L'\0';

		if (wcscmp(component, L".") == 0) {
			p += len;
			continue;
		}
		if (wcscmp(component, L"..") == 0) {
			if (node->parent)
				node = node->parent;
			p += len;
			continue;
		}

		if (!MEMFS_NODE_IS_DIRECTORY(node))
			return MEMFS_ERR_NOT_DIRECTORY;

		node = memfs_dir_lookup(node, component);
		if (node == NULL)
			return MEMFS_ERR_NOT_FOUND;

		p += len;
	}

	*out_node = node;
	return MEMFS_OK;
}

static MemfsResult memfs_stream_path_parts(Memfs* fs, const wchar_t* path,
    MemfsNode** owner, wchar_t name[MEMFS_MAX_NAME + 1], bool* named) {
    const wchar_t* colon = path != NULL ? wcschr(path, L':') : NULL;
    const wchar_t* end;
    const wchar_t* type;
    size_t chars;
    *owner = NULL;
    name[0] = L'\0';
    *named = false;
    if (colon == NULL || wcschr(colon, L'\\') != NULL || wcschr(colon, L'/') != NULL)
        return MEMFS_ERR_INVALID;
    type = wcschr(colon + 1, L':');
    if (type != NULL && _wcsicmp(type, L":$DATA") != 0)
        return MEMFS_ERR_INVALID;
    end = type != NULL ? type : path + wcslen(path);
    chars = (size_t)(end - colon - 1);
    if (chars > MEMFS_MAX_NAME || (chars == 0 && type == NULL))
        return MEMFS_ERR_INVALID;
    memcpy(name, colon + 1, chars * sizeof(wchar_t));
    name[chars] = L'\0';
    *named = chars != 0;
    return memfs_lookup_path_span(fs, path, colon, owner);
}

MemfsResult memfs_lookup_stream_parent(Memfs* fs, const wchar_t* path,
    MemfsNode** owner, wchar_t name[MEMFS_MAX_NAME + 1]) {
    bool named;
    MemfsResult result;
    if (owner == NULL || name == NULL) return MEMFS_ERR_INVALID;
    result = memfs_stream_path_parts(fs, path, owner, name, &named);
    return result != MEMFS_OK ? result : named ? MEMFS_OK : MEMFS_ERR_INVALID;
}

MemfsResult memfs_lookup_path(Memfs* fs, const wchar_t* path, MemfsNode** out_node) {
	const wchar_t* end;

	if (out_node != NULL)
		*out_node = NULL;
	if (fs == NULL || path == NULL || out_node == NULL || path[0] != L'\\')
		return MEMFS_ERR_INVALID;

    if (wcschr(path, L':') != NULL) {
        MemfsNode* owner;
        wchar_t name[MEMFS_MAX_NAME + 1];
        bool named;
        MemfsResult result = memfs_stream_path_parts(fs, path, &owner, name, &named);
        if (result != MEMFS_OK) return result;
        *out_node = named ? memfs_stream_lookup(owner, name) : owner;
        return *out_node != NULL ? MEMFS_OK : MEMFS_ERR_NOT_FOUND;
    }
	end = path + wcslen(path);
	return memfs_lookup_path_span(fs, path, end, out_node);
}

MemfsResult memfs_lookup_parent(Memfs* fs, const wchar_t* path, MemfsNode** out_parent,
								wchar_t name[MEMFS_MAX_NAME + 1]) {
	const wchar_t* end;
	const wchar_t* sep;
	size_t name_len;
	MemfsNode* parent;
	MemfsResult result;

	if (out_parent != NULL)
		*out_parent = NULL;
	if (name != NULL)
		name[0] = L'\0';

	if (fs == NULL || path == NULL || out_parent == NULL || name == NULL || path[0] != L'\\')
		return MEMFS_ERR_INVALID;

	end = path + wcslen(path);
	while (end > path + 1 && end[-1] == L'\\')
		end--;

	sep = end;
	while (sep > path && sep[-1] != L'\\')
		sep--;

	if (sep == end)
		return MEMFS_ERR_INVALID;

	name_len = (size_t)(end - sep);
	if (name_len == 0 || name_len > MEMFS_MAX_NAME)
		return MEMFS_ERR_INVALID;

	memcpy(name, sep, name_len * sizeof(wchar_t));
	name[name_len] = L'\0';

	if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0)
		return MEMFS_ERR_INVALID;

	/*
	 * Resolve the parent directly against the original path span. This avoids
	 * allocating/copying a temporary NUL-terminated parent path on every
	 * Create/Rename while preserving the same component semantics as
	 * memfs_lookup_path().
	 */
	result = memfs_lookup_path_span(fs, path, sep, &parent);
	if (result != MEMFS_OK)
		return MEMFS_ERR_PATH_NOT_FOUND;

	if (!MEMFS_NODE_IS_DIRECTORY(parent))
		return MEMFS_ERR_NOT_DIRECTORY;

	*out_parent = parent;
	return MEMFS_OK;
}

static bool memfs_component_name_valid(const wchar_t* name) {
	size_t length = 0;

	if (name == NULL || *name == L'\0')
		return false;

	while (name[length] != L'\0') {
		if (length >= MEMFS_MAX_NAME)
			return false;
		if (name[length] == L'\\' || name[length] == L'/' || name[length] == L':')
			return false;
		length++;
	}

	if ((length == 1U && name[0] == L'.') ||
		(length == 2U && name[0] == L'.' && name[1] == L'.'))
		return false;

	return true;
}

MemfsResult memfs_node_create(Memfs* fs, MemfsNode* parent, const wchar_t* name, bool directory, uint32_t attributes,
							  PSECURITY_DESCRIPTOR security, uint64_t allocation_size, MemfsNode** out_node) {
	MemfsNode* node;
	MemfsResult result;

	if (out_node != NULL)
		*out_node = NULL;

	if (fs == NULL || !MEMFS_NODE_IS_DIRECTORY(parent) || out_node == NULL ||
		parent->fs != fs || parent->deleted || !memfs_component_name_valid(name)) {
		return MEMFS_ERR_INVALID;
	}

	if (memfs_dir_lookup(parent, name))
		return MEMFS_ERR_EXISTS;

	result = memfs_node_alloc(fs, parent, name, directory, attributes, security, &node);
	if (result != MEMFS_OK)
		return result;

	if (!directory && allocation_size) {
		result = memfs_resize_allocation(node, allocation_size);
		if (result != MEMFS_OK) {
			memfs_node_free(node);
			return result;
		}
	}

	node->open_count = 1;
	memfs_dir_insert(parent, node);
	memfs_touch_directory(parent);

	*out_node = node;
	return MEMFS_OK;
}

void memfs_node_open(MemfsNode* node) {
	Memfs* fs;
	if (node == NULL)
		return;
	fs = node->fs;
	AcquireSRWLockExclusive(&fs->lifetime_lock);
	node->open_count++;
	ReleaseSRWLockExclusive(&fs->lifetime_lock);
}

void memfs_node_close(MemfsNode* node) {
	Memfs* fs;
	bool dispose = false;
	if (node == NULL)
		return;
	fs = node->fs;
	AcquireSRWLockExclusive(&fs->lifetime_lock);
	if (node->open_count) {
		node->open_count--;
		if (node->deleted && node->open_count == 0) {
			memfs_orphan_remove(fs, node);
			dispose = true;
		}
	}
	ReleaseSRWLockExclusive(&fs->lifetime_lock);
	/* Only the final valid reference reaches destruction. Keep potentially
	 * expensive allocator/security/storage cleanup outside the lifetime lock. */
	if (dispose)
		memfs_node_free(node);
}

static void memfs_node_retire_unlinked(MemfsNode* node) {
	Memfs* fs = node->fs;
	bool dispose;
	/* Namespace removal and timestamps must be complete before publication:
	 * a concurrent final Close can destroy the node as soon as we unlock. */
	AcquireSRWLockExclusive(&fs->lifetime_lock);
	node->deleted = true;
	dispose = node->open_count == 0;
	if (!dispose)
		memfs_orphan_insert(fs, node);
	ReleaseSRWLockExclusive(&fs->lifetime_lock);
	if (dispose)
		memfs_node_free(node);
}

static unsigned memfs_stream_bucket(MemfsNode* owner) {
    return (unsigned)(memfs_mix64((uint64_t)(uintptr_t)owner) & 63U);
}

MemfsNode* memfs_stream_first(MemfsNode* owner) {
    MemfsNode* node;
    owner = memfs_node_metadata(owner);
    if (owner == NULL) return NULL;
    for (node = owner->fs->stream_buckets[memfs_stream_bucket(owner)];
         node != NULL; node = node->tree_left)
        if (node->parent == owner) return node;
    return NULL;
}

MemfsNode* memfs_stream_next(MemfsNode* stream) {
    MemfsNode* node;
    if (stream == NULL || !stream->named_stream || stream->deleted) return NULL;
    for (node = stream->tree_left; node != NULL; node = node->tree_left)
        if (node->parent == stream->parent) return node;
    return NULL;
}

MemfsNode* memfs_stream_lookup(MemfsNode* owner, const wchar_t* name) {
    if (owner == NULL || name == NULL || owner->deleted) return NULL;
    for (MemfsNode* node = memfs_stream_first(owner); node; node = memfs_stream_next(node))
        if (memfs_name_compare(node->name, name) == 0) return node;
    return NULL;
}

static bool memfs_stream_name_valid(const wchar_t* name) {
    size_t size = name != NULL ? wcslen(name) : 0;
    if (size == 0 || size > MEMFS_MAX_NAME) return false;
    for (size_t i = 0; i < size; ++i)
        if (name[i] == L':' || name[i] == L'\\' || name[i] == L'/') return false;
    return true;
}

MemfsResult memfs_stream_create(MemfsNode* owner, const wchar_t* name,
    uint64_t allocation_size, MemfsNode** out_node) {
    MemfsNode* node;
    MemfsResult result;
    if (out_node != NULL) *out_node = NULL;
    if (owner == NULL || owner->named_stream || owner->deleted ||
        out_node == NULL || !memfs_stream_name_valid(name)) return MEMFS_ERR_INVALID;
    if (memfs_stream_lookup(owner, name)) return MEMFS_ERR_EXISTS;
    result = memfs_node_alloc(owner->fs, owner, name, false, FILE_ATTRIBUTE_NORMAL, NULL, &node);
    if (result != MEMFS_OK) return result;
    result = memfs_resize_allocation(node, allocation_size);
    if (result != MEMFS_OK) { memfs_node_free(node); return result; }
    /* A stream shares the CURRENT base SD, not a retained obsolete copy. */
    memfs_security_release(node->security);
    node->security = NULL;
    node->named_stream = true;
    node->stream_active_opens = 1;
    node->parent = owner;
    node->open_count = 1;
    memfs_node_open(owner);
    unsigned bucket = memfs_stream_bucket(owner);
    node->tree_left = owner->fs->stream_buckets[bucket];
    owner->fs->stream_buckets[bucket] = node;
    memfs_node_set_change_time(owner, memfs_now());
    *out_node = node;
    return MEMFS_OK;
}

static void memfs_stream_unlink(MemfsNode* node) {
    MemfsNode* owner = node->parent;
    MemfsNode** cursor = &node->fs->stream_buckets[memfs_stream_bucket(owner)];
    while (*cursor != NULL && *cursor != node) cursor = &(*cursor)->tree_left;
    if (*cursor != node) return;
    *cursor = node->tree_left;
    node->tree_left = node->tree_right = node->tree_parent = NULL;
    memfs_node_set_change_time(owner, memfs_now());
    memfs_node_retire_unlinked(node);
}

void memfs_stream_unlink_all(MemfsNode* owner, bool only_closed) {
    MemfsNode* node;
    if (owner == NULL || owner->named_stream) return;
    node = memfs_stream_first(owner);
    while (node != NULL) {
        MemfsNode* next = memfs_stream_next(node);
        bool remove = true;
        if (only_closed) {
            AcquireSRWLockShared(&owner->fs->lifetime_lock);
            /* Close can be delayed after the final user handle closes.
             * FINE + owner I/O guard serializes this with stream Cleanup.
             * Core-only callers still use open_count without a frontend. */
            remove = node->open_count == 0 ||
                InterlockedCompareExchange(&node->stream_active_opens, 0, 0) == 0;
            ReleaseSRWLockShared(&owner->fs->lifetime_lock);
        }
        if (remove) memfs_stream_unlink(node);
        node = next;
    }
}

MemfsResult memfs_stream_rename(MemfsNode* node, MemfsNode* owner,
    const wchar_t* name, bool replace) {
    MemfsNode* existing;
    wchar_t* copy;
    if (node == NULL || !node->named_stream || node->deleted || owner == NULL ||
        owner != node->parent || owner->deleted || !memfs_stream_name_valid(name))
        return MEMFS_ERR_INVALID;
    existing = memfs_stream_lookup(owner, name);
    if (existing != NULL && existing != node && !replace) return MEMFS_ERR_EXISTS;
    copy = memfs_object_dup_name(node->fs, name);
    if (copy == NULL) return MEMFS_ERR_NO_MEMORY;
    if (existing != NULL && existing != node) memfs_stream_unlink(existing);
    memfs_object_free_name(node->fs, node->name);
    node->name = copy;
    node->name_hash = memfs_name_hash(copy);
    memfs_node_set_change_time(owner, memfs_now());
    return MEMFS_OK;
}

bool memfs_node_is_directory(const MemfsNode* node) {
	return MEMFS_NODE_IS_DIRECTORY(node);
}

bool memfs_node_is_ancestor(const MemfsNode* ancestor, const MemfsNode* node) {
	for (; node; node = node->parent) {
		if (node == ancestor)
			return true;
	}
	return false;
}

MemfsResult memfs_node_unlink(MemfsNode* node) {
	MemfsNode* parent;

	if (node == NULL || node->fs == NULL || node == node->fs->root)
		return MEMFS_ERR_ACCESS;
	if (node->deleted)
		return MEMFS_OK;
	if (node->named_stream) {
		memfs_stream_unlink(node);
		return MEMFS_OK;
	}
	if (MEMFS_NODE_IS_DIRECTORY(node) && node->dir->child_count)
		return MEMFS_ERR_NOT_EMPTY;

	memfs_stream_unlink_all(node, false);
	parent = node->parent;
	memfs_dir_remove(node);
	memfs_node_set_change_time(node, memfs_now());
	memfs_touch_directory(parent);
	memfs_node_retire_unlinked(node);

	return MEMFS_OK;
}

MemfsResult memfs_node_rename(MemfsNode* node, MemfsNode* new_parent, const wchar_t* new_name, bool replace_if_exists) {
	MemfsNode* existing;
	MemfsNode* old_parent;
	wchar_t* new_name_copy;

	if (node == NULL || node->fs == NULL || node->named_stream || !MEMFS_NODE_IS_DIRECTORY(new_parent) ||
		new_parent->fs != node->fs || node->deleted || new_parent->deleted ||
		!memfs_component_name_valid(new_name)) {
		return MEMFS_ERR_INVALID;
	}
	if (node == node->fs->root)
		return MEMFS_ERR_ACCESS;
	if (memfs_node_is_ancestor(node, new_parent))
		return MEMFS_ERR_ACCESS;

	existing = memfs_dir_lookup(new_parent, new_name);
	if (existing == node) {
		if (wcscmp(node->name, new_name) == 0)
			return MEMFS_OK;
	} else if (existing) {
		if (!replace_if_exists)
			return MEMFS_ERR_EXISTS;
		if (memfs_node_is_directory(existing) != memfs_node_is_directory(node))
			return MEMFS_ERR_ACCESS;
		if (MEMFS_NODE_IS_DIRECTORY(existing) && existing->dir->child_count)
			return MEMFS_ERR_NOT_EMPTY;
	}

	new_name_copy = memfs_object_dup_name(node->fs, new_name);
	if (new_name_copy == NULL)
		return MEMFS_ERR_NO_MEMORY;

	if (existing && existing != node) {
		MemfsNode* existing_parent = existing->parent;

		memfs_stream_unlink_all(existing, false);
		memfs_dir_remove(existing);
		memfs_touch_directory(existing_parent);
		memfs_node_retire_unlinked(existing);
	}

	old_parent = node->parent;
	memfs_dir_remove(node);

	memfs_object_free_name(node->fs, node->name);

	node->name = new_name_copy;
	node->name_hash = memfs_name_hash(node->name);
	memfs_dir_insert(new_parent, node);

	memfs_node_set_change_time(node, memfs_now());
	memfs_touch_directory(old_parent);
	if (new_parent != old_parent)
		memfs_touch_directory(new_parent);

	return MEMFS_OK;
}

MemfsResult memfs_node_set_allocation_size(MemfsNode* node, uint64_t new_size) {
	MemfsResult result;

	if (node == NULL)
		return MEMFS_ERR_INVALID;
	if (MEMFS_NODE_IS_DIRECTORY(node))
		return MEMFS_ERR_IS_DIRECTORY;

	// Windows requires FileSize <= AllocationSize, so truncate EOF first.
	// Internal allocation_size stays byte-granular; WinFsp reports it aligned to 512B.
	if (new_size < node->file_size) {
		result = memfs_node_set_file_size(node, new_size);
		if (result != MEMFS_OK)
			return result;
	}

	result = memfs_resize_allocation(node, new_size);
	if (result == MEMFS_OK)
		memfs_node_set_change_time(node, memfs_now());

	return result;
}

MemfsResult memfs_node_set_file_size(MemfsNode* node, uint64_t new_size) {
	uint64_t old_file_size;
	MemfsResult result;

	if (node == NULL)
		return MEMFS_ERR_INVALID;
	if (MEMFS_NODE_IS_DIRECTORY(node))
		return MEMFS_ERR_IS_DIRECTORY;

	old_file_size = node->file_size;
	if (new_size == old_file_size)
		return MEMFS_OK;

	if (new_size < old_file_size) {
		result = memfs_storage_trim_data(node, new_size);
		if (result != MEMFS_OK)
			return result;
	}

	result = memfs_account_file_size(node, old_file_size, new_size);
	if (result != MEMFS_OK)
		return result;

	if (new_size > node->allocation_size)
		node->allocation_size = new_size;

	node->file_size = new_size;
	memfs_node_set_change_time(node, memfs_now());
	return MEMFS_OK;
}

bool memfs_block_capacity_allows(Memfs* fs, uint64_t stored_pages, uint64_t new_pages) {
	if (fs == NULL)
		return false;
	if (new_pages == 0)
		return true;
	/* Worst case per new page: a full page plus header, AEAD tag and the
	 * allocator class it lands in (4224 bytes). */
	if (fs->capacity_auto)
		return new_pages <= UINT64_MAX / (MEMFS_PAGE_SIZE + 128U) &&
			   memfs_auto_capacity_allows(fs, new_pages * (MEMFS_PAGE_SIZE + 128U));
	/* Fixed capacity counts stored data, not heap bytes: with a disk no larger
	 * than the capacity the disk then fills before the capacity does, so
	 * NTFS sees "disk full" and never a device error. */
	return stored_pages <= fs->capacity / MEMFS_PAGE_SIZE &&
		   new_pages <= fs->capacity / MEMFS_PAGE_SIZE - stored_pages;
}

MemfsResult memfs_node_punch_hole(MemfsNode* node, uint64_t offset, uint64_t length) {
	static const uint8_t zeros[MEMFS_PAGE_SIZE];
	uint64_t end;
	uint64_t first_page;
	uint64_t end_page;
	uint32_t position;
	bool found;
	MemfsResult result;

	if (node == NULL)
		return MEMFS_ERR_INVALID;
	if (MEMFS_NODE_IS_DIRECTORY(node))
		return MEMFS_ERR_IS_DIRECTORY;
	end = offset + length;
	if (end < offset)
		return MEMFS_ERR_INVALID;
	if (end > node->file_size)
		end = node->file_size;
	if (offset >= end)
		return MEMFS_OK;

	/* Tiny/inline storage holds data only below small_capacity; the rest is
	 * implicitly zero. Zero-fill that part (encode drops all-zero data). */
	if (!node->paged_storage) {
		if (end > node->small_capacity)
			end = node->small_capacity;
		while (offset < end) {
			uint64_t chunk = end - offset < MEMFS_PAGE_SIZE ? end - offset : MEMFS_PAGE_SIZE;

			result = memfs_storage_write_range(node, zeros, offset, chunk);
			if (result != MEMFS_OK)
				return result;
			offset += chunk;
		}
		return MEMFS_OK;
	}

	first_page = (offset + MEMFS_PAGE_MASK) >> MEMFS_PAGE_SHIFT;
	end_page = end >> MEMFS_PAGE_SHIFT;

	/* Partial edge pages: read-modify-write zeros; an all-zero result frees it. */
	if (first_page > end_page) {
		return memfs_storage_write_range(node, zeros, offset, end - offset);
	}
	if ((offset & MEMFS_PAGE_MASK) != 0) {
		result = memfs_storage_write_range(node, zeros, offset, (first_page << MEMFS_PAGE_SHIFT) - offset);
		if (result != MEMFS_OK)
			return result;
	}
	if ((end & MEMFS_PAGE_MASK) != 0 && (end_page << MEMFS_PAGE_SHIFT) >= offset) {
		result = memfs_storage_write_range(node, zeros, end_page << MEMFS_PAGE_SHIFT, end & MEMFS_PAGE_MASK);
		if (result != MEMFS_OK)
			return result;
	}
	if (first_page >= end_page)
		return MEMFS_OK;

	/* Whole pages: visit only groups that exist in the sorted group array. */
	position = memfs_storage_group_position(node, first_page >> MEMFS_PAGE_GROUP_SHIFT, &found);
	while (position < memfs_storage_group_count(node)) {
		uint64_t group_index = memfs_storage_group_index_at(node, position);
		MemfsPageGroup* group = memfs_storage_group_at(node, position);
		uint64_t group_first = group_index << MEMFS_PAGE_GROUP_SHIFT;
		uint32_t slot = 0;
		uint32_t slot_end = MEMFS_PAGES_PER_GROUP;

		if (group_first >= end_page)
			break;
		if (first_page > group_first)
			slot = (uint32_t)(first_page - group_first);
		if (end_page < group_first + MEMFS_PAGES_PER_GROUP)
			slot_end = (uint32_t)(end_page - group_first);

		for (; slot < slot_end && group->page_count != 0; slot++) {
			if (!memfs_group_has(group, slot))
				continue;
			result = memfs_storage_replace_page(node, group, slot, NULL);
			if (result != MEMFS_OK)
				return result;
		}

		if (group->page_count == 0) {
			memfs_storage_remove_group(node, group_index);
			continue;
		}
		position++;
	}
	return MEMFS_OK;
}

uint64_t memfs_node_count_pages(MemfsNode* node, uint64_t offset, uint64_t length) {
	uint64_t end;
	uint64_t first_page;
	uint64_t end_page;
	uint64_t count = 0;
	uint32_t position;
	bool found;

	if (node == NULL || MEMFS_NODE_IS_DIRECTORY(node) || length == 0)
		return 0;
	end = offset + length;
	if (end < offset || end > node->file_size)
		end = node->file_size;
	if (offset >= end)
		return 0;
	if (!node->paged_storage)
		return node->small_page != NULL && offset < node->small_capacity ? 1U : 0U;

	first_page = offset >> MEMFS_PAGE_SHIFT;
	end_page = (end + MEMFS_PAGE_MASK) >> MEMFS_PAGE_SHIFT;
	position = memfs_storage_group_position(node, first_page >> MEMFS_PAGE_GROUP_SHIFT, &found);
	for (; position < memfs_storage_group_count(node); position++) {
		uint64_t group_first = memfs_storage_group_index_at(node, position) << MEMFS_PAGE_GROUP_SHIFT;
		const MemfsPageGroup* group = memfs_storage_group_at(node, position);
		uint32_t slot = first_page > group_first ? (uint32_t)(first_page - group_first) : 0U;
		uint32_t slot_end = end_page < group_first + MEMFS_PAGES_PER_GROUP
			? (uint32_t)(end_page - group_first) : MEMFS_PAGES_PER_GROUP;

		if (group_first >= end_page)
			break;
		if (slot == 0 && slot_end == MEMFS_PAGES_PER_GROUP) {
			count += group->page_count;
			continue;
		}
		for (; slot < slot_end; slot++)
			count += memfs_group_has(group, slot) ? 1U : 0U;
	}
	return count;
}

MemfsResult memfs_node_read(MemfsNode* node, void* buffer, uint64_t offset, uint32_t length, uint32_t* bytes_read) {
	uint64_t end;

	if (node == NULL || buffer == NULL || bytes_read == NULL)
		return MEMFS_ERR_INVALID;
	if (MEMFS_NODE_IS_DIRECTORY(node))
		return MEMFS_ERR_IS_DIRECTORY;

	*bytes_read = 0;
	if (length == 0)
		return MEMFS_OK;
	if (offset >= node->file_size)
		return MEMFS_ERR_NOT_FOUND;

	end = offset + length;
	if (end < offset)
		return MEMFS_ERR_INVALID;
	if (end > node->file_size)
		end = node->file_size;

	{
		MemfsResult result = memfs_storage_read_range(node, buffer, offset, end - offset);

		if (result != MEMFS_OK)
			return result;
	}

	*bytes_read = (uint32_t)(end - offset);
	memfs_node_set_last_access_time(node, memfs_now());
	return MEMFS_OK;
}

MemfsResult memfs_node_write(MemfsNode* node, const void* buffer, uint64_t offset, uint32_t length, bool write_to_end,
							 bool constrained_io, uint32_t* bytes_written) {
	uint64_t end;
	uint64_t write_length;
	uint64_t old_allocation;
	uint64_t old_file_size;
	bool allocation_grew = false;
	bool file_size_reserved = false;
	MemfsResult result;

	if (node == NULL || buffer == NULL || bytes_written == NULL)
		return MEMFS_ERR_INVALID;
	if (MEMFS_NODE_IS_DIRECTORY(node))
		return MEMFS_ERR_IS_DIRECTORY;

	*bytes_written = 0;
	old_allocation = node->allocation_size;
	old_file_size = node->file_size;

	if (length == 0)
		return MEMFS_OK;

	if (write_to_end)
		offset = node->file_size;

	end = offset + length;
	if (end < offset)
		return MEMFS_ERR_INVALID;

	if (constrained_io) {
		if (offset >= node->file_size)
			return MEMFS_OK;

		if (end > node->file_size)
			end = node->file_size;
	} else {
		if (end > old_file_size) {
			result = memfs_account_file_size(node, old_file_size, end);
			if (result != MEMFS_OK)
				return result;

			file_size_reserved = true;
		}

		if (end > node->allocation_size) {
			result = memfs_resize_allocation(node, end);
			if (result != MEMFS_OK) {
				if (file_size_reserved) {
					(void)memfs_account_file_size(node, end, old_file_size);
				}
				return result;
			}

			allocation_grew = true;
		}
	}

	write_length = end - offset;
	result = memfs_storage_write_range(node, (const uint8_t*)buffer, offset, write_length);
	if (result != MEMFS_OK) {
		if (allocation_grew)
			(void)memfs_resize_allocation(node, old_allocation);

		if (file_size_reserved) {
			(void)memfs_account_file_size(node, end, old_file_size);
		}
		return result;
	}

	if (!constrained_io && end > old_file_size)
		node->file_size = end;

	*bytes_written = (uint32_t)write_length;
	memfs_node_set_last_write_time(node, memfs_now());
	memfs_node_set_change_time(node, memfs_node_get_last_write_time(node));
	/* NORMAL is only valid alone. */
	memfs_node_metadata(node)->attributes = (memfs_node_metadata(node)->attributes & ~FILE_ATTRIBUTE_NORMAL) | FILE_ATTRIBUTE_ARCHIVE;
	return MEMFS_OK;
}

MemfsResult memfs_node_replace_security(MemfsNode* node, PSECURITY_DESCRIPTOR security, uint32_t security_size) {
	MemfsSecurity* replacement;
	MemfsSecurity* old;
	MemfsResult result;

	node = memfs_node_metadata(node);
	if (node == NULL || security == NULL || security_size == 0 ||
		!IsValidSecurityDescriptor(security)) {
		return MEMFS_ERR_INVALID;
	}

	if (GetSecurityDescriptorLength(security) != security_size)
		return MEMFS_ERR_INVALID;

	if (memfs_security_equal(memfs_node_get_security(node), security))
		return MEMFS_OK;

	result = memfs_security_create(&node->fs->allocator, security, &replacement);
	if (result != MEMFS_OK)
		return result;

	old = node->security;
	node->security = replacement;
	memfs_security_release(old);

	memfs_node_set_change_time(node, memfs_now());
	return MEMFS_OK;
}
