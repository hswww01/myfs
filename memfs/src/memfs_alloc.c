#include "memfs_alloc.h"
#include "memfs_vm.h"

#include <Windows.h>
#include <stdint.h>
#include <string.h>

#define MEMFS_SLAB_MAGIC 0x4D46534CU
#define MEMFS_ALLOC_STATE_MAGIC 0x4D464153U
#define MEMFS_AREA_MAGIC 0x4D464152U
#define MEMFS_AREA_CACHED_MAGIC 0x4D464143U
#define MEMFS_AREA_CACHE_MAX_BLOCKS 32U
#define MEMFS_AREA_CACHE_MAX_BYTES (4U * 1024U * 1024U)
#define MEMFS_AREA_CACHE_MAX_BLOCK_BYTES (256U * 1024U)
#define MEMFS_AREA_CACHE_LARGE_BLOCK_BYTES (64U * 1024U)
#define MEMFS_AREA_CACHE_BLOCKS_PER_SHARD (MEMFS_AREA_CACHE_MAX_BLOCKS / MEMFS_POOL_SHARD_COUNT)
#define MEMFS_AREA_CACHE_BYTES_PER_SHARD (MEMFS_AREA_CACHE_MAX_BYTES / MEMFS_POOL_SHARD_COUNT)
#define MEMFS_MIN_SLAB_BYTES (4U * 1024U)
#define MEMFS_MAX_SLAB_BYTES (64U * 1024U)
#define MEMFS_POOL_SHARD_COUNT 16U
/* Stronger internal payload-base alignment; not a public return guarantee. */
#define MEMFS_ALLOC_INTERNAL_ALIGNMENT 16U

_Static_assert((MEMFS_POOL_SHARD_COUNT & (MEMFS_POOL_SHARD_COUNT - 1U)) == 0,
               "pool shard count must be a power of two");
_Static_assert(MEMFS_AREA_CACHE_MAX_BLOCKS % MEMFS_POOL_SHARD_COUNT == 0,
               "area cache block bound must divide evenly across shards");
_Static_assert(MEMFS_AREA_CACHE_MAX_BYTES % MEMFS_POOL_SHARD_COUNT == 0,
               "area cache byte bound must divide evenly across shards");

typedef struct MemfsFreeObject {
    struct MemfsFreeObject* next;
} MemfsFreeObject;

typedef struct MemfsPool MemfsPool;
typedef struct MemfsPoolShard MemfsPoolShard;
typedef struct MemfsSlab MemfsSlab;
typedef struct MemfsAreaBlock MemfsAreaBlock;
typedef struct MemfsAreaShard MemfsAreaShard;

struct MemfsPoolShard {
    MemfsSlab* slabs;
    MemfsSlab* available;
    SRWLOCK lock;
    uint64_t live_objects;
    uint64_t live_bytes;
    uint64_t reserved_bytes;
    uint64_t committed_bytes;
    uint32_t slab_count;
};

struct MemfsPool {
    MemfsAllocatorState* state;
    size_t object_size;
    size_t slab_bytes;
    volatile LONG available_shard_mask;
    MemfsPoolShard shards[MEMFS_POOL_SHARD_COUNT];
};

struct MemfsSlab {
    MemfsSlab* next;
    MemfsSlab* prev;
    MemfsSlab* available_next;
    MemfsSlab* available_prev;
    MemfsPool* owner;
    MemfsPoolShard* shard;
    MemfsFreeObject* free_list;
    size_t region_bytes;
    uint32_t capacity;
    uint32_t free_count;
    uint32_t magic;
    uint32_t reserved;
};

struct MemfsAreaBlock {
    MemfsAreaBlock* next;
    MemfsAreaBlock* prev;
    MemfsAllocatorState* owner;
    MemfsAreaShard* shard;
    uint64_t requested_bytes;
    uint64_t region_bytes;
    uint32_t magic;
    uint32_t reserved;
};

struct MemfsAreaShard {
    MemfsAreaBlock* active;
    MemfsAreaBlock* cached;
    SRWLOCK lock;
    uint64_t active_count;
    uint64_t live_bytes;
    uint64_t reserved_bytes;
    uint64_t committed_bytes;
    uint64_t cached_bytes;
    uint32_t cached_count;
};

struct MemfsAllocatorState {
    uint32_t magic;
    uint32_t class_count;
    size_t allocation_granularity;
    uint64_t region_bytes;
    volatile LONG64 committed_total_bytes;
    volatile LONG64 gross_commit_total_bytes;
    MemfsPool pools[MEMFS_ALLOC_CLASS_COUNT];

    MemfsAreaShard area_shards[MEMFS_POOL_SHARD_COUNT];
};

static const size_t g_class_sizes[MEMFS_ALLOC_CLASS_COUNT] = {
    8U, 16U, 24U, 32U, 48U, 64U, 96U, 128U, 192U, 256U,
    384U, 512U, 768U, 1024U, 1536U, 2048U, 3072U, 4096U, 8192U
};

static INIT_ONCE g_control_allocator_once = INIT_ONCE_STATIC_INIT;
static MemfsAllocator g_control_allocator;

static void state_add_committed(MemfsAllocatorState* state, uint64_t bytes) {
    if (state == NULL || bytes == 0)
        return;
    InterlockedAdd64(&state->gross_commit_total_bytes, (LONG64)bytes);
    InterlockedAdd64(&state->committed_total_bytes, (LONG64)bytes);
}

static void state_sub_committed(MemfsAllocatorState* state, uint64_t bytes) {
    if (state == NULL || bytes == 0)
        return;
    InterlockedAdd64(&state->committed_total_bytes, -(LONG64)bytes);
}

static uint64_t state_committed_bytes(MemfsAllocatorState* state) {
    if (state == NULL)
        return 0;
    return (uint64_t)InterlockedCompareExchange64(
        &state->committed_total_bytes, 0, 0);
}

#if !defined(NDEBUG)
static volatile LONG g_memfs_alloc_fail_point = MEMFS_ALLOC_FAIL_NONE;
static volatile LONG g_memfs_alloc_fail_skip;
static volatile LONG g_memfs_alloc_fail_remaining;

void memfs_allocator_test_fail_after(MemfsAllocFailPoint point,
                                     uint32_t successful_calls_before_failure,
                                     uint32_t failure_count) {
    InterlockedExchange(&g_memfs_alloc_fail_point, MEMFS_ALLOC_FAIL_NONE);
    InterlockedExchange(&g_memfs_alloc_fail_skip, (LONG)successful_calls_before_failure);
    InterlockedExchange(&g_memfs_alloc_fail_remaining, (LONG)failure_count);
    InterlockedExchange(&g_memfs_alloc_fail_point, (LONG)point);
}

void memfs_allocator_test_clear_failures(void) {
    InterlockedExchange(&g_memfs_alloc_fail_point, MEMFS_ALLOC_FAIL_NONE);
    InterlockedExchange(&g_memfs_alloc_fail_skip, 0);
    InterlockedExchange(&g_memfs_alloc_fail_remaining, 0);
}

bool memfs_allocator_test_should_fail(MemfsAllocFailPoint point) {
    LONG current;
    LONG value;

    if (point == MEMFS_ALLOC_FAIL_NONE)
        return false;

    current = InterlockedCompareExchange(&g_memfs_alloc_fail_point, 0, 0);
    if (current != (LONG)point)
        return false;

    for (;;) {
        value = InterlockedCompareExchange(&g_memfs_alloc_fail_skip, 0, 0);
        if (value <= 0)
            break;
        if (InterlockedCompareExchange(&g_memfs_alloc_fail_skip, value - 1, value) == value)
            return false;
    }

    for (;;) {
        value = InterlockedCompareExchange(&g_memfs_alloc_fail_remaining, 0, 0);
        if (value <= 0)
            return false;
        if (InterlockedCompareExchange(&g_memfs_alloc_fail_remaining, value - 1, value) == value)
            return true;
    }
}
#endif

static size_t align_up(size_t value, size_t alignment) {
    if (alignment == 0 || (alignment & (alignment - 1U)) != 0)
        return 0;
    if (value > SIZE_MAX - (alignment - 1U))
        return 0;
    return (value + alignment - 1U) & ~(alignment - 1U);
}

static int class_index(size_t bytes) {
    int i;

    if (bytes == 0 || bytes > MEMFS_ALLOC_AREA_THRESHOLD)
        return -1;

    for (i = 0; i < MEMFS_ALLOC_CLASS_COUNT; i++) {
        if (bytes <= g_class_sizes[i])
            return i;
    }
    return -1;
}

static size_t slab_bytes_for_object(size_t object_size) {
    if (object_size <= 128U)
        return 4U * 1024U;
    if (object_size <= 256U)
        return 8U * 1024U;
    if (object_size <= 512U)
        return 16U * 1024U;
    if (object_size <= 1024U)
        return 32U * 1024U;
    return 64U * 1024U;
}

#if !defined(NDEBUG)
bool memfs_allocator_test_class_layout(size_t bytes,
                                       size_t* class_bytes,
                                       size_t* slab_bytes) {
    int index = class_index(bytes);

    if (class_bytes)
        *class_bytes = 0;
    if (slab_bytes)
        *slab_bytes = 0;
    if (index < 0)
        return false;

    if (class_bytes)
        *class_bytes = g_class_sizes[index];
    if (slab_bytes)
        *slab_bytes = slab_bytes_for_object(g_class_sizes[index]);
    return true;
}

size_t memfs_allocator_test_class_size(uint32_t class_index_value) {
    if (class_index_value >= MEMFS_ALLOC_CLASS_COUNT)
        return 0;
    return g_class_sizes[class_index_value];
}
#endif

static uint32_t pool_shard_index(void) {
    uint32_t value = (uint32_t)GetCurrentThreadId();

    /*
     * Windows thread ids have low-bit patterns, so mix before masking. This
     * preserves one logical size-class pool while spreading hot threads over
     * independent slab lanes inside that pool.
     */
    value ^= value >> 16;
    value *= 0x7feb352dU;
    value ^= value >> 15;
    value *= 0x846ca68bU;
    value ^= value >> 16;
    return value & (MEMFS_POOL_SHARD_COUNT - 1U);
}

static void available_insert(MemfsPoolShard* shard, MemfsSlab* slab) {
    bool was_empty;
    uint32_t shard_index;

    if (shard == NULL || slab == NULL || slab->owner == NULL)
        return;

    was_empty = shard->available == NULL;
    slab->available_prev = NULL;
    slab->available_next = shard->available;
    if (shard->available)
        shard->available->available_prev = slab;
    shard->available = slab;

    if (was_empty) {
        shard_index = (uint32_t)(shard - slab->owner->shards);
        InterlockedOr(&slab->owner->available_shard_mask,
                      (LONG)(1U << shard_index));
    }
}

static void available_remove(MemfsPoolShard* shard, MemfsSlab* slab) {
    bool linked;
    uint32_t shard_index;

    if (shard == NULL || slab == NULL || slab->owner == NULL)
        return;

    linked = slab->available_prev != NULL ||
             slab->available_next != NULL ||
             shard->available == slab;
    if (!linked)
        return;

    if (slab->available_prev)
        slab->available_prev->available_next = slab->available_next;
    else if (shard->available == slab)
        shard->available = slab->available_next;

    if (slab->available_next)
        slab->available_next->available_prev = slab->available_prev;

    slab->available_prev = NULL;
    slab->available_next = NULL;

    if (shard->available == NULL) {
        shard_index = (uint32_t)(shard - slab->owner->shards);
        InterlockedAnd(&slab->owner->available_shard_mask,
                       (LONG)~(1U << shard_index));
    }
}

static void all_insert(MemfsPoolShard* shard, MemfsSlab* slab) {
    slab->prev = NULL;
    slab->next = shard->slabs;
    if (shard->slabs)
        shard->slabs->prev = slab;
    shard->slabs = slab;
}

static void all_remove(MemfsPoolShard* shard, MemfsSlab* slab) {
    if (slab->prev)
        slab->prev->next = slab->next;
    else
        shard->slabs = slab->next;

    if (slab->next)
        slab->next->prev = slab->prev;

    slab->prev = NULL;
    slab->next = NULL;
}

static MemfsSlab* slab_create(MemfsPool* pool, MemfsPoolShard* shard) {
    const size_t data_offset = align_up(sizeof(MemfsSlab), MEMFS_ALLOC_INTERNAL_ALIGNMENT);
    MemfsSlab* slab;
    uint8_t* data;
    uint32_t capacity;
    uint32_t i;

    if (pool == NULL || shard == NULL ||
        data_offset == 0 || pool->slab_bytes <= data_offset) {
        return NULL;
    }

    capacity = (uint32_t)((pool->slab_bytes - data_offset) / pool->object_size);
    if (capacity == 0)
        return NULL;

    if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_SLAB))
        return NULL;

    slab = memfs_vm_reserve_commit(pool->slab_bytes);
    if (slab == NULL)
        return NULL;

    memset(slab, 0, data_offset);
    slab->owner = pool;
    slab->shard = shard;
    slab->capacity = capacity;
    slab->free_count = capacity;
    slab->region_bytes = memfs_vm_region_bytes(slab);
    slab->magic = MEMFS_SLAB_MAGIC;

    data = (uint8_t*)slab + data_offset;
    for (i = 0; i < capacity; i++) {
        MemfsFreeObject* object =
            (MemfsFreeObject*)(data + (size_t)i * pool->object_size);
        object->next = slab->free_list;
        slab->free_list = object;
    }

    all_insert(shard, slab);
    available_insert(shard, slab);
    shard->slab_count++;
    shard->reserved_bytes += slab->region_bytes;
    shard->committed_bytes += slab->region_bytes;
    state_add_committed(pool->state, slab->region_bytes);
    return slab;
}

static MemfsSlab* slab_from_object(MemfsAllocatorState* state, void* ptr) {
    uintptr_t address;
    uintptr_t granularity;

    if (state == NULL || ptr == NULL)
        return NULL;

    granularity = (uintptr_t)state->allocation_granularity;
    if (granularity == 0 || (granularity & (granularity - 1U)) != 0)
        return NULL;

    address = (uintptr_t)ptr;
    return (MemfsSlab*)(address & ~(granularity - 1U));
}

static MemfsFreeObject* pool_take_available_locked(
    MemfsPool* pool,
    MemfsPoolShard* shard,
    size_t requested_bytes) {
    MemfsSlab* slab;
    MemfsFreeObject* object;

    if (pool == NULL || shard == NULL)
        return NULL;

    slab = shard->available;
    if (slab == NULL)
        return NULL;
    if (slab->magic != MEMFS_SLAB_MAGIC ||
        slab->owner != pool ||
        slab->shard != shard ||
        slab->free_list == NULL ||
        slab->free_count == 0) {
        return NULL;
    }

    object = slab->free_list;
    slab->free_list = object->next;
    slab->free_count--;
    shard->live_objects++;
    shard->live_bytes += requested_bytes;

    if (slab->free_count == 0)
        available_remove(shard, slab);

    return object;
}

static void* pool_alloc_from_home(MemfsPool* pool,
                                  size_t requested_bytes,
                                  bool zero_memory,
                                  uint32_t home_index) {
    uint32_t offset;
    LONG available_mask;
    MemfsPoolShard* shard;
    MemfsSlab* slab;
    MemfsFreeObject* object = NULL;

    if (pool == NULL || requested_bytes == 0 ||
        requested_bytes > pool->object_size ||
        home_index >= MEMFS_POOL_SHARD_COUNT) {
        return NULL;
    }

    shard = &pool->shards[home_index];

    /*
     * Fast path: stay on the current thread's shard while it has capacity.
     * This preserves the low-contention lane behavior for the normal case.
     */
    AcquireSRWLockExclusive(&shard->lock);
    object = pool_take_available_locked(pool, shard, requested_bytes);
    ReleaseSRWLockExclusive(&shard->lock);

    /*
     * Slow path: before committing another slab, reuse free capacity already
     * present in another lane of the same logical size-class pool. We hold at
     * most one shard lock at a time, so this cannot introduce lock cycles.
     * A VM allocation is far more expensive than these bounded 15 probes.
     */
    if (object == NULL) {
        available_mask = InterlockedCompareExchange(
            &pool->available_shard_mask, 0, 0);
        available_mask &= (LONG)~(1U << home_index);

        if (available_mask != 0) {
            for (offset = 1U; offset < MEMFS_POOL_SHARD_COUNT; ++offset) {
                uint32_t index =
                    (home_index + offset) & (MEMFS_POOL_SHARD_COUNT - 1U);
                LONG bit = (LONG)(1U << index);
                MemfsPoolShard* donor;

                if ((available_mask & bit) == 0)
                    continue;

                donor = &pool->shards[index];
                AcquireSRWLockExclusive(&donor->lock);
                object = pool_take_available_locked(
                    pool, donor, requested_bytes);
                ReleaseSRWLockExclusive(&donor->lock);

                if (object != NULL)
                    break;
            }
        }
    }

    /*
     * No reusable object exists anywhere. Recheck the home shard after the
     * scan because a concurrent free may have arrived, then grow only there.
     */
    if (object == NULL) {
        shard = &pool->shards[home_index];
        AcquireSRWLockExclusive(&shard->lock);

        object = pool_take_available_locked(pool, shard, requested_bytes);
        if (object == NULL) {
            slab = slab_create(pool, shard);
            if (slab != NULL)
                object = pool_take_available_locked(
                    pool, shard, requested_bytes);
        }

        ReleaseSRWLockExclusive(&shard->lock);
    }

    if (object == NULL)
        return NULL;

    if (zero_memory)
        memset(object, 0, requested_bytes);
    return object;
}

static void* pool_alloc(MemfsPool* pool,
                        size_t requested_bytes,
                        bool zero_memory) {
    return pool_alloc_from_home(
        pool, requested_bytes, zero_memory, pool_shard_index());
}

static void pool_adjust_live_bytes(
    MemfsPool* pool,
    void* ptr,
    size_t old_bytes,
    size_t new_bytes) {
    MemfsSlab* slab;
    MemfsPoolShard* shard;

    if (pool == NULL || ptr == NULL || old_bytes == new_bytes)
        return;

    slab = slab_from_object(pool->state, ptr);
    if (slab == NULL || slab->owner != pool || slab->shard == NULL)
        return;

    shard = slab->shard;
    AcquireSRWLockExclusive(&shard->lock);

    if (slab->magic == MEMFS_SLAB_MAGIC &&
        slab->owner == pool &&
        slab->shard == shard) {
        if (new_bytes >= old_bytes)
            shard->live_bytes += new_bytes - old_bytes;
        else if (shard->live_bytes >= old_bytes - new_bytes)
            shard->live_bytes -= old_bytes - new_bytes;
        else
            shard->live_bytes = 0;
    }

    ReleaseSRWLockExclusive(&shard->lock);
}

static void pool_free(MemfsPool* pool, void* ptr, size_t requested_bytes) {
    MemfsFreeObject* object = (MemfsFreeObject*)ptr;
    MemfsSlab* slab;
    MemfsPoolShard* shard;
    bool release_slab = false;
    uint64_t release_bytes = 0;

    if (pool == NULL || ptr == NULL)
        return;

    slab = slab_from_object(pool->state, ptr);
    if (slab == NULL || slab->owner != pool || slab->shard == NULL)
        return;

    shard = slab->shard;
    AcquireSRWLockExclusive(&shard->lock);

    if (slab->magic != MEMFS_SLAB_MAGIC ||
        slab->owner != pool ||
        slab->shard != shard) {
        ReleaseSRWLockExclusive(&shard->lock);
        return;
    }

    if (slab->free_count == 0)
        available_insert(shard, slab);

    object->next = slab->free_list;
    slab->free_list = object;
    slab->free_count++;

    if (shard->live_objects)
        shard->live_objects--;
    if (shard->live_bytes >= requested_bytes)
        shard->live_bytes -= requested_bytes;
    else
        shard->live_bytes = 0;

    /*
     * Each shard releases its final slab when it becomes idle. This prevents
     * the concurrency lanes from turning into permanent per-thread caches.
     */
    if (slab->free_count == slab->capacity &&
        (shard->slab_count > 1U || shard->live_objects == 0)) {
        available_remove(shard, slab);
        all_remove(shard, slab);
        shard->slab_count--;
        shard->reserved_bytes -= slab->region_bytes;
        shard->committed_bytes -= slab->region_bytes;
        release_bytes = slab->region_bytes;
        slab->magic = 0;
        release_slab = true;
    }

    ReleaseSRWLockExclusive(&shard->lock);

    if (release_slab) {
        memfs_vm_release(slab);
        state_sub_committed(pool->state, release_bytes);
    }
}

static uint64_t pool_scavenge(MemfsPool* pool) {
    uint64_t released = 0;
    uint32_t shard_index;

    if (pool == NULL)
        return 0;

    for (shard_index = 0;
         shard_index < MEMFS_POOL_SHARD_COUNT;
         ++shard_index) {
        MemfsPoolShard* shard = &pool->shards[shard_index];
        MemfsSlab* slab;

        AcquireSRWLockExclusive(&shard->lock);

        slab = shard->slabs;
        while (slab) {
            MemfsSlab* next = slab->next;

            if (slab->free_count == slab->capacity) {
                uint64_t bytes = slab->region_bytes;
                available_remove(shard, slab);
                all_remove(shard, slab);
                shard->slab_count--;
                shard->reserved_bytes -= bytes;
                shard->committed_bytes -= bytes;
                slab->magic = 0;
                memfs_vm_release(slab);
                released += bytes;
                state_sub_committed(pool->state, bytes);
            }

            slab = next;
        }

        ReleaseSRWLockExclusive(&shard->lock);
    }

    return released;
}

static void pool_destroy(MemfsPool* pool) {
    uint32_t shard_index;

    if (pool == NULL)
        return;

    for (shard_index = 0;
         shard_index < MEMFS_POOL_SHARD_COUNT;
         ++shard_index) {
        MemfsPoolShard* shard = &pool->shards[shard_index];
        MemfsSlab* slab;

        AcquireSRWLockExclusive(&shard->lock);

        slab = shard->slabs;
        while (slab) {
            MemfsSlab* next = slab->next;
            slab->magic = 0;
            memfs_vm_release(slab);
            slab = next;
        }

        shard->slabs = NULL;
        shard->available = NULL;
        shard->live_objects = 0;
        shard->live_bytes = 0;
        shard->reserved_bytes = 0;
        shard->committed_bytes = 0;
        shard->slab_count = 0;

        ReleaseSRWLockExclusive(&shard->lock);
    }
    InterlockedExchange(&pool->available_shard_mask, 0);
}

static void pool_add_stats(MemfsPool* pool, MemfsAllocatorStats* stats) {
    uint32_t shard_index;

    if (pool == NULL || stats == NULL)
        return;

    for (shard_index = 0;
         shard_index < MEMFS_POOL_SHARD_COUNT;
         ++shard_index) {
        MemfsPoolShard* shard = &pool->shards[shard_index];

        AcquireSRWLockShared(&shard->lock);
        stats->reserved_bytes += shard->reserved_bytes;
        stats->committed_bytes += shard->committed_bytes;
        stats->live_bytes += shard->live_bytes;
        stats->live_objects += shard->live_objects;
        stats->slab_count += shard->slab_count;
        ReleaseSRWLockShared(&shard->lock);
    }
}

static size_t area_header_size(void) {
    return align_up(sizeof(MemfsAreaBlock), MEMFS_ALLOC_INTERNAL_ALIGNMENT);
}

static void area_list_insert(MemfsAreaBlock** head, MemfsAreaBlock* block) {
    block->prev = NULL;
    block->next = *head;
    if (*head)
        (*head)->prev = block;
    *head = block;
}

static void area_list_remove(MemfsAreaBlock** head, MemfsAreaBlock* block) {
    if (block->prev)
        block->prev->next = block->next;
    else
        *head = block->next;
    if (block->next)
        block->next->prev = block->prev;
    block->next = NULL;
    block->prev = NULL;
}

static MemfsAreaShard* area_current_shard(MemfsAllocatorState* state) {
    return &state->area_shards[pool_shard_index()];
}

static void* area_alloc(MemfsAllocatorState* state, size_t bytes, bool zero_memory) {
    MemfsAreaShard* shard;
    MemfsAreaBlock* block;
    MemfsAreaBlock* best = NULL;
    size_t header_size;
    size_t total_size;
    uint64_t max_region;

    if (state == NULL || bytes == 0)
        return NULL;

    header_size = area_header_size();
    if (header_size == 0 || bytes > SIZE_MAX - header_size)
        return NULL;
    total_size = header_size + bytes;
    max_region = total_size <= UINT64_MAX / 2U
        ? (uint64_t)total_size * 2U
        : UINT64_MAX;

    if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_DEDICATED))
        return NULL;

    shard = area_current_shard(state);
    AcquireSRWLockExclusive(&shard->lock);
    for (block = shard->cached; block; block = block->next) {
        if (block->magic != MEMFS_AREA_CACHED_MAGIC ||
            block->owner != state ||
            block->shard != shard ||
            block->region_bytes < total_size ||
            block->region_bytes > max_region) {
            continue;
        }
        if (best == NULL || block->region_bytes < best->region_bytes)
            best = block;
    }

    if (best != NULL) {
        area_list_remove(&shard->cached, best);
        if (shard->cached_count)
            shard->cached_count--;
        if (shard->cached_bytes >= best->region_bytes)
            shard->cached_bytes -= best->region_bytes;
        else
            shard->cached_bytes = 0;

        best->requested_bytes = bytes;
        best->magic = MEMFS_AREA_MAGIC;
        area_list_insert(&shard->active, best);
        shard->active_count++;
        shard->live_bytes += bytes;
        ReleaseSRWLockExclusive(&shard->lock);
        if (zero_memory)
            memset((uint8_t*)best + header_size, 0, bytes);
        return (uint8_t*)best + header_size;
    }
    ReleaseSRWLockExclusive(&shard->lock);

    block = memfs_vm_reserve_commit(total_size);
    if (block == NULL)
        return NULL;

    memset(block, 0, header_size);
    block->owner = state;
    block->shard = shard;
    block->requested_bytes = bytes;
    block->region_bytes = memfs_vm_region_bytes(block);
    block->magic = MEMFS_AREA_MAGIC;
    state_add_committed(state, block->region_bytes);

    AcquireSRWLockExclusive(&shard->lock);
    area_list_insert(&shard->active, block);
    shard->active_count++;
    shard->live_bytes += bytes;
    shard->reserved_bytes += block->region_bytes;
    shard->committed_bytes += block->region_bytes;
    ReleaseSRWLockExclusive(&shard->lock);

    if (zero_memory)
        memset((uint8_t*)block + header_size, 0, bytes);
    return (uint8_t*)block + header_size;
}

static uint32_t area_cache_block_limit(uint64_t region_bytes) {
    if (region_bytes > MEMFS_AREA_CACHE_LARGE_BLOCK_BYTES)
        return 1U;
    return MEMFS_AREA_CACHE_BLOCKS_PER_SHARD;
}

static void area_free(MemfsAllocatorState* state, void* ptr) {
    MemfsAreaBlock* block;
    MemfsAreaShard* shard;
    size_t header_size;
    uint32_t cache_block_limit;
    bool cache_block;

    if (state == NULL || ptr == NULL)
        return;

    header_size = area_header_size();
    block = (MemfsAreaBlock*)((uint8_t*)ptr - header_size);
    if (block->magic != MEMFS_AREA_MAGIC || block->owner != state || block->shard == NULL)
        return;

    shard = block->shard;
    AcquireSRWLockExclusive(&shard->lock);

    if (block->magic != MEMFS_AREA_MAGIC ||
        block->owner != state ||
        block->shard != shard) {
        ReleaseSRWLockExclusive(&shard->lock);
        return;
    }

    area_list_remove(&shard->active, block);
    if (shard->active_count)
        shard->active_count--;
    if (shard->live_bytes >= block->requested_bytes)
        shard->live_bytes -= block->requested_bytes;
    else
        shard->live_bytes = 0;

    cache_block_limit = area_cache_block_limit(block->region_bytes);
    cache_block =
        block->region_bytes <= MEMFS_AREA_CACHE_MAX_BLOCK_BYTES &&
        shard->cached_count < cache_block_limit &&
        block->region_bytes <= MEMFS_AREA_CACHE_BYTES_PER_SHARD &&
        shard->cached_bytes <= MEMFS_AREA_CACHE_BYTES_PER_SHARD - block->region_bytes;

    if (cache_block) {
        block->requested_bytes = 0;
        block->magic = MEMFS_AREA_CACHED_MAGIC;
        area_list_insert(&shard->cached, block);
        shard->cached_count++;
        shard->cached_bytes += block->region_bytes;
        ReleaseSRWLockExclusive(&shard->lock);
        return;
    }

    if (shard->reserved_bytes >= block->region_bytes)
        shard->reserved_bytes -= block->region_bytes;
    else
        shard->reserved_bytes = 0;
    if (shard->committed_bytes >= block->region_bytes)
        shard->committed_bytes -= block->region_bytes;
    else
        shard->committed_bytes = 0;

    {
        uint64_t release_bytes = block->region_bytes;
        block->magic = 0;
        ReleaseSRWLockExclusive(&shard->lock);
        memfs_vm_release(block);
        state_sub_committed(state, release_bytes);
    }
}

static void area_destroy_list(MemfsAreaBlock* block) {
    while (block) {
        MemfsAreaBlock* next = block->next;
        block->magic = 0;
        memfs_vm_release(block);
        block = next;
    }
}

static void area_destroy_all(MemfsAllocatorState* state) {
    uint32_t i;

    if (state == NULL)
        return;

    for (i = 0; i < MEMFS_POOL_SHARD_COUNT; i++) {
        MemfsAreaShard* shard = &state->area_shards[i];
        MemfsAreaBlock* active;
        MemfsAreaBlock* cached;

        AcquireSRWLockExclusive(&shard->lock);
        active = shard->active;
        cached = shard->cached;
        shard->active = NULL;
        shard->cached = NULL;
        shard->active_count = 0;
        shard->live_bytes = 0;
        shard->reserved_bytes = 0;
        shard->committed_bytes = 0;
        shard->cached_bytes = 0;
        shard->cached_count = 0;
        ReleaseSRWLockExclusive(&shard->lock);

        area_destroy_list(active);
        area_destroy_list(cached);
    }
}

static void area_add_stats(MemfsAllocatorState* state, MemfsAllocatorStats* stats) {
    uint32_t i;

    if (state == NULL || stats == NULL)
        return;

    for (i = 0; i < MEMFS_POOL_SHARD_COUNT; i++) {
        MemfsAreaShard* shard = &state->area_shards[i];

        AcquireSRWLockShared(&shard->lock);
        stats->dedicated_count += (uint32_t)shard->active_count;
        stats->dedicated_live_bytes += shard->live_bytes;
        stats->dedicated_reserved_bytes += shard->reserved_bytes;
        stats->dedicated_committed_bytes += shard->committed_bytes;
        stats->area_cached_count += shard->cached_count;
        stats->area_cached_bytes += shard->cached_bytes;

        stats->live_objects += shard->active_count;
        stats->live_bytes += shard->live_bytes;
        stats->reserved_bytes += shard->reserved_bytes;
        stats->committed_bytes += shard->committed_bytes;
        ReleaseSRWLockShared(&shard->lock);
    }
}

static uint64_t area_scavenge(MemfsAllocatorState* state) {
    uint64_t released = 0;
    uint32_t i;

    if (state == NULL)
        return 0;

    for (i = 0; i < MEMFS_POOL_SHARD_COUNT; i++) {
        MemfsAreaShard* shard = &state->area_shards[i];
        MemfsAreaBlock* cached;
        uint64_t shard_released;

        AcquireSRWLockExclusive(&shard->lock);
        cached = shard->cached;
        shard_released = shard->cached_bytes;
        shard->cached = NULL;
        shard->cached_count = 0;
        shard->cached_bytes = 0;

        if (shard->reserved_bytes >= shard_released)
            shard->reserved_bytes -= shard_released;
        else
            shard->reserved_bytes = 0;
        if (shard->committed_bytes >= shard_released)
            shard->committed_bytes -= shard_released;
        else
            shard->committed_bytes = 0;
        ReleaseSRWLockExclusive(&shard->lock);

        area_destroy_list(cached);
        released += shard_released;
        state_sub_committed(state, shard_released);
    }

    return released;
}

static MemfsAllocatorState* state_create(void) {
    MemfsAllocatorState* state;
    MemfsVmSystemInfo vm_info;
    uint32_t shard_index;
    int i;

    if (memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_BOOTSTRAP))
        return NULL;

    state = memfs_vm_reserve_commit(sizeof(*state));
    if (state == NULL)
        return NULL;

    memset(state, 0, sizeof(*state));
    if (!memfs_vm_get_system_info(&vm_info)) {
        memfs_vm_release(state);
        return NULL;
    }

    state->magic = MEMFS_ALLOC_STATE_MAGIC;
    state->class_count = MEMFS_ALLOC_CLASS_COUNT;
    state->allocation_granularity = vm_info.allocation_granularity;
    state->region_bytes = memfs_vm_region_bytes(state);
    state->committed_total_bytes = (LONG64)state->region_bytes;
    state->gross_commit_total_bytes = (LONG64)state->region_bytes;
    for (shard_index = 0; shard_index < MEMFS_POOL_SHARD_COUNT; ++shard_index)
        InitializeSRWLock(&state->area_shards[shard_index].lock);

    if (state->allocation_granularity < MEMFS_MAX_SLAB_BYTES ||
        (state->allocation_granularity & (state->allocation_granularity - 1U)) != 0) {
        memfs_vm_release(state);
        return NULL;
    }

    for (i = 0; i < MEMFS_ALLOC_CLASS_COUNT; i++) {
        MemfsPool* pool = &state->pools[i];
        pool->state = state;
        pool->object_size = g_class_sizes[i];
        pool->slab_bytes = slab_bytes_for_object(pool->object_size);
        for (shard_index = 0;
             shard_index < MEMFS_POOL_SHARD_COUNT;
             ++shard_index) {
            InitializeSRWLock(&pool->shards[shard_index].lock);
        }
    }

    return state;
}

static void state_destroy(MemfsAllocatorState* state) {
    int i;

    if (state == NULL || state->magic != MEMFS_ALLOC_STATE_MAGIC)
        return;

    for (i = 0; i < MEMFS_ALLOC_CLASS_COUNT; i++)
        pool_destroy(&state->pools[i]);

    area_destroy_all(state);
    state->magic = 0;
    memfs_vm_release(state);
}

static void* allocator_alloc_internal(
    MemfsAllocator* allocator,
    size_t bytes,
    bool zero_memory) {
    int index;

    if (allocator == NULL || allocator->state == NULL || bytes == 0)
        return NULL;

    index = class_index(bytes);
    if (index >= 0)
        return pool_alloc(&allocator->state->pools[index], bytes, zero_memory);

    return area_alloc(allocator->state, bytes, zero_memory);
}

static void allocator_free_internal(MemfsAllocator* allocator, void* ptr, size_t bytes) {
    int index;

    if (allocator == NULL || allocator->state == NULL || ptr == NULL)
        return;

    index = class_index(bytes);
    if (index >= 0)
        pool_free(&allocator->state->pools[index], ptr, bytes);
    else
        area_free(allocator->state, ptr);
}

bool memfs_allocator_init(MemfsAllocator* allocator,
                          size_t node_size,
                          size_t dir_size,
                          size_t page_group_size) {
    MemfsAllocatorState* state;

    if (allocator == NULL || node_size == 0 || dir_size == 0 || page_group_size == 0)
        return false;

    memset(allocator, 0, sizeof(*allocator));
    state = state_create();
    if (state == NULL)
        return false;

    allocator->state = state;
    allocator->node_size = node_size;
    allocator->dir_size = dir_size;
    allocator->page_group_size = page_group_size;
    return true;
}

void memfs_allocator_destroy(MemfsAllocator* allocator) {
    if (allocator == NULL)
        return;

    state_destroy(allocator->state);
    memset(allocator, 0, sizeof(*allocator));
}

void* memfs_allocator_alloc_node(MemfsAllocator* allocator) {
    if (allocator == NULL || memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_NODE))
        return NULL;
    return allocator_alloc_internal(allocator, allocator->node_size, true);
}

void memfs_allocator_free_node(MemfsAllocator* allocator, void* ptr) {
    if (allocator)
        allocator_free_internal(allocator, ptr, allocator->node_size);
}

void* memfs_allocator_alloc_dir(MemfsAllocator* allocator) {
    if (allocator == NULL || memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_DIR))
        return NULL;
    return allocator_alloc_internal(allocator, allocator->dir_size, true);
}

void memfs_allocator_free_dir(MemfsAllocator* allocator, void* ptr) {
    if (allocator)
        allocator_free_internal(allocator, ptr, allocator->dir_size);
}

void* memfs_allocator_alloc_page_group(MemfsAllocator* allocator) {
    if (allocator == NULL || memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_GROUP))
        return NULL;
    return allocator_alloc_internal(allocator, allocator->page_group_size, true);
}

void memfs_allocator_free_page_group(MemfsAllocator* allocator, void* ptr) {
    if (allocator)
        allocator_free_internal(allocator, ptr, allocator->page_group_size);
}

void* memfs_allocator_alloc_name(MemfsAllocator* allocator, size_t bytes) {
    if (allocator == NULL || bytes == 0 ||
        memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_NAME))
        return NULL;
    return allocator_alloc_internal(allocator, bytes, false);
}

void memfs_allocator_free_name(MemfsAllocator* allocator, void* ptr, size_t bytes) {
    allocator_free_internal(allocator, ptr, bytes);
}

void* memfs_allocator_alloc(MemfsAllocator* allocator, size_t bytes) {
    if (allocator == NULL || bytes == 0 ||
        memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_GENERIC))
        return NULL;
    return allocator_alloc_internal(allocator, bytes, true);
}

void* memfs_allocator_alloc_uninit(MemfsAllocator* allocator, size_t bytes) {
    if (allocator == NULL || bytes == 0 ||
        memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_GENERIC))
        return NULL;
    return allocator_alloc_internal(allocator, bytes, false);
}

void* memfs_allocator_alloc_zero(MemfsAllocator* allocator, size_t bytes) {
    if (allocator == NULL || bytes == 0 ||
        memfs_allocator_test_should_fail(MEMFS_ALLOC_FAIL_GENERIC))
        return NULL;
    return allocator_alloc_internal(allocator, bytes, true);
}

void memfs_allocator_free(MemfsAllocator* allocator, void* ptr, size_t bytes) {
    allocator_free_internal(allocator, ptr, bytes);
}

void* memfs_allocator_realloc(MemfsAllocator* allocator,
                              void* ptr,
                              size_t old_bytes,
                              size_t new_bytes) {
    void* next;
    size_t copy_bytes;
    int old_index;
    int new_index;

    if (allocator == NULL)
        return NULL;

    if (ptr == NULL)
        return memfs_allocator_alloc(allocator, new_bytes);

    if (new_bytes == 0) {
        memfs_allocator_free(allocator, ptr, old_bytes);
        return NULL;
    }

    old_index = class_index(old_bytes);
    new_index = class_index(new_bytes);

    if (old_index >= 0 && old_index == new_index) {
        pool_adjust_live_bytes(&allocator->state->pools[old_index], ptr, old_bytes, new_bytes);
        return ptr;
    }

    next = memfs_allocator_alloc(allocator, new_bytes);
    if (next == NULL)
        return NULL;

    copy_bytes = old_bytes < new_bytes ? old_bytes : new_bytes;
    memcpy(next, ptr, copy_bytes);
    memfs_allocator_free(allocator, ptr, old_bytes);
    return next;
}

#if !defined(NDEBUG)
void* memfs_allocator_test_alloc_from_shard(MemfsAllocator* allocator,
                                            size_t bytes,
                                            uint32_t shard_index) {
    int index;

    if (allocator == NULL || allocator->state == NULL ||
        shard_index >= MEMFS_POOL_SHARD_COUNT) {
        return NULL;
    }

    index = class_index(bytes);
    if (index < 0)
        return NULL;

    return pool_alloc_from_home(
        &allocator->state->pools[index], bytes, false, shard_index);
}

uint32_t memfs_allocator_test_shard_count(void) {
    return MEMFS_POOL_SHARD_COUNT;
}
#endif

uint64_t memfs_allocator_commit_total_bytes(MemfsAllocator* allocator) {
    if (allocator == NULL || allocator->state == NULL)
        return 0;
    return (uint64_t)InterlockedCompareExchange64(
        &allocator->state->gross_commit_total_bytes, 0, 0);
}

uint64_t memfs_allocator_committed_bytes(MemfsAllocator* allocator) {
    if (allocator == NULL || allocator->state == NULL)
        return 0;
    return state_committed_bytes(allocator->state);
}

void memfs_allocator_get_stats(MemfsAllocator* allocator, MemfsAllocatorStats* stats) {
    MemfsAllocatorState* state;
    int i;

    if (stats == NULL)
        return;

    memset(stats, 0, sizeof(*stats));
    if (allocator == NULL || allocator->state == NULL)
        return;

    state = allocator->state;
    stats->reserved_bytes += state->region_bytes;
    stats->committed_bytes += state->region_bytes;

    for (i = 0; i < MEMFS_ALLOC_CLASS_COUNT; i++)
        pool_add_stats(&state->pools[i], stats);

    area_add_stats(state, stats);
    stats->physical_bytes = stats->committed_bytes;
    stats->scavenged_bytes = (uint64_t)InterlockedCompareExchange64(&allocator->scavenged_bytes, 0, 0);
    stats->scavenge_count = (uint64_t)InterlockedCompareExchange64(&allocator->scavenge_count, 0, 0);
}

uint64_t memfs_allocator_scavenge(MemfsAllocator* allocator) {
    uint64_t released = 0;
    int i;

    if (allocator == NULL || allocator->state == NULL)
        return 0;

    for (i = 0; i < MEMFS_ALLOC_CLASS_COUNT; i++)
        released += pool_scavenge(&allocator->state->pools[i]);

    released += area_scavenge(allocator->state);

    if (released)
        InterlockedAdd64(&allocator->scavenged_bytes, (LONG64)released);
    InterlockedIncrement64(&allocator->scavenge_count);
    return released;
}

static BOOL CALLBACK control_allocator_init_once(PINIT_ONCE once,
                                                 PVOID parameter,
                                                 PVOID* context) {
    (void)once;
    (void)parameter;
    (void)context;

    /*
     * The control allocator is process-wide and exists only to allocate
     * objects that precede a per-filesystem allocator (currently Memfs).
     * It uses the exact same size-class/slab/area machinery as every other
     * allocation; the dummy typed sizes are never used by this path.
     */
    return memfs_allocator_init(&g_control_allocator, 1U, 1U, 1U)
        ? TRUE
        : FALSE;
}

static bool control_allocator_ready(void) {
    return !!InitOnceExecuteOnce(&g_control_allocator_once,
                                 control_allocator_init_once,
                                 NULL,
                                 NULL);
}


void* memfs_allocator_alloc_control(size_t bytes) {
    if (bytes == 0 || !control_allocator_ready())
        return NULL;
    return allocator_alloc_internal(&g_control_allocator, bytes, true);
}

void memfs_allocator_free_control(void* ptr, size_t bytes) {
    if (ptr == NULL)
        return;
    if (!control_allocator_ready())
        return;
    allocator_free_internal(&g_control_allocator, ptr, bytes);
}
