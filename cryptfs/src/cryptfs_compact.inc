#include <stdio.h>

/*
 * Compaction and worker lifecycle for cryptfs_store.c.
 * Included at the end of that translation unit so the implementation can use
 * the store's private graph and WAL helpers without exporting them.
 */

static void cf_compact_poison(CF_STORE *s, DWORD error) {
    if (error == ERROR_SUCCESS)
        error = ERROR_CRC;
    cf_set_error(s, error);
    s->poisoned = true;
}

static bool cf_compact_read_page(CF_STORE *s, CF_PAGE *page,
    uint8_t payload[CF_PAYLOAD_SIZE]) {
    uint8_t disk[CF_PAGE_SIZE];
    uint64_t record_id = 0;
    bool valid;
    memset(disk, 0, sizeof(disk));
    memset(payload, 0, CF_PAYLOAD_SIZE);
    if (!page || !page->registered ||
        (page->slot == CF_ROOT_SLOT ? page != s->root_page :
            (page->slot == 0 || page->slot >= s->slot_capacity ||
                !s->slots || s->slots[page->slot] != page))) {
        cf_wipe(disk, sizeof(disk));
        cf_wipe(payload, CF_PAYLOAD_SIZE);
        cf_compact_poison(s, ERROR_CRC);
        return false;
    }
    /* A physical read error is retryable by the worker. Authentication and
     * identity checks below still fail closed. */
    if (!cf_read_physical(s, page->slot, disk)) {
        cf_wipe(disk, sizeof(disk));
        cf_wipe(payload, CF_PAYLOAD_SIZE);
        return false;
    }
    valid = cf_page_decrypt(s, page->slot, disk, page->type,
        page->record_id, payload, &record_id) && record_id == page->record_id;
    cf_wipe(disk, sizeof(disk));
    if (!valid) {
        cf_wipe(payload, CF_PAYLOAD_SIZE);
        cf_compact_poison(s, ERROR_CRC);
    }
    return valid;
}

static void cf_compact_poison_tx_invariant(CF_TX *tx, CF_RESULT result) {
    if (!tx || !tx->store || tx->store->poisoned ||
        result == CF_IO_ERROR || result == CF_NO_MEMORY || result == CF_NO_SPACE)
        return;
    cf_compact_poison(tx->store,
        result == CF_DATA_ERROR ? ERROR_CRC : ERROR_INVALID_DATA);
}

static uint64_t cf_compact_eof_for_highest(uint64_t highest_slot) {
    return CF_PAGES_OFFSET + highest_slot * CF_PAGE_SIZE;
}

/* Caller holds s->lock exclusively. Performs at most one page move or one EOF shrink. */
static CF_RESULT cf_store_compact_locked(CF_STORE *s, bool *progress) {
    uint64_t high = 0, low = 0, i, highest_after;
    uint64_t target_eof;
    CF_PAGE *moving, *owner;
    CF_TX tx;
    bool tx_started = false;
    uint8_t moving_payload[CF_PAYLOAD_SIZE];
    uint8_t owner_payload[CF_PAYLOAD_SIZE];
    uint8_t moved_bytes[CF_PAGE_SIZE];
    uint64_t pointer_value;
    CF_RESULT result = CF_OK;

    if (progress)
        *progress = false;
    if (!s || !progress)
        return CF_INVALID;
    if (s->poisoned || s->stopping)
        return CF_IO_ERROR;

    /* Find the highest registered page and the first hole below it. Root is fixed. */
    for (i = s->slot_count; i > 0; --i) {
        if (i < s->slot_capacity && s->slots[i]) {
            high = i;
            break;
        }
    }
    if (high != 0) {
        for (i = cf_free_floor(s, high); i < high; ++i) {
            if (i >= s->slot_capacity || !s->slots[i]) {
                low = i;
                break;
            }
        }
    }

    if (low != 0) {
        moving = s->slots[high];
        if (!moving || !moving->registered || moving->slot != high ||
            moving->slot == CF_ROOT_SLOT || !moving->owner ||
            moving->owner == moving || moving->owner_offset >
                CF_PAYLOAD_SIZE - sizeof(uint64_t)) {
            cf_compact_poison(s, ERROR_CRC);
            return CF_DATA_ERROR;
        }
        owner = moving->owner;
        if (!owner->registered || (owner->slot == CF_ROOT_SLOT && owner != s->root_page) ||
            (owner->slot != CF_ROOT_SLOT &&
                (owner->slot == 0 || owner->slot >= s->slot_capacity ||
                    s->slots[owner->slot] != owner))) {
            cf_compact_poison(s, ERROR_CRC);
            return CF_DATA_ERROR;
        }
        memset(moving_payload, 0, sizeof(moving_payload));
        memset(owner_payload, 0, sizeof(owner_payload));
        memset(moved_bytes, 0, sizeof(moved_bytes));
        if (!cf_compact_read_page(s, moving, moving_payload) ||
            !cf_compact_read_page(s, owner, owner_payload)) {
            result = s->poisoned ? CF_DATA_ERROR : CF_IO_ERROR;
            goto move_done;
        }
        pointer_value = cf_get_u64(owner_payload + moving->owner_offset);
        if (pointer_value != high ||
            !cf_page_encrypt(s, low, moving->type, moving->record_id,
                moving_payload, moved_bytes)) {
            cf_compact_poison(s, ERROR_CRC);
            result = CF_DATA_ERROR;
            goto move_done;
        }
        cf_put_u64(owner_payload + moving->owner_offset, low);
        if (!cf_tx_begin(s, &tx)) {
            result = CF_NO_MEMORY;
            goto move_done;
        }
        tx_started = true;
        if (!cf_tx_add_raw(&tx, low, moved_bytes) ||
            !cf_tx_add_payload(&tx, owner->slot, owner->type,
                owner->record_id, owner_payload)) {
            result = CF_NO_MEMORY;
            goto move_done;
        }

        /* Keep the old EOF for this move. The pointer rewrite and destination
         * page are committed together; the following bounded step performs a
         * zero-image shrink after the source slot has been freed. */
        tx.final_eof = s->eof;
        if (!cf_tx_commit(&tx)) {
            result = cf_tx_failure_result(&tx, CF_IO_ERROR);
            cf_compact_poison_tx_invariant(&tx, result);
            goto move_done;
        }

        /* WAL commit is durable; now publish the same relocation in RAM. */
        s->slots[low] = moving;
        s->slots[high] = NULL;
        moving->slot = low;
        ++s->compact_moves;
        /* This is deliberately synchronous and rechecks s->slots[high] under
         * the same lock. A failed punch is nonfatal: the next step trims EOF. */
        if (!cf_punch_hole_locked(s, high)) {
            DWORD punch_error = GetLastError();
            if (punch_error == ERROR_SUCCESS)
                punch_error = ERROR_GEN_FAILURE;
            cf_set_error(s, punch_error);
            fprintf(stderr,
                "CryptFS: sparse page reclamation failed (Win32 %lu); tail trimming will continue.\n",
                (unsigned long)punch_error);
        }
        *progress = true;
        result = CF_OK;
move_done:
        if (tx_started)
            cf_tx_dispose(&tx);
        cf_wipe(moving_payload, sizeof(moving_payload));
        cf_wipe(owner_payload, sizeof(owner_payload));
        cf_wipe(moved_bytes, sizeof(moved_bytes));
        return result;
    }

    /* There are no internal holes. A zero-image transaction safely truncates
     * any unused tail, including the root-only case. */
    highest_after = high;
    target_eof = cf_compact_eof_for_highest(highest_after);
    if (target_eof < CF_MIN_EOF || target_eof > s->eof) {
        cf_compact_poison(s, ERROR_CRC);
        return CF_DATA_ERROR;
    }
    if (target_eof == s->eof)
        return CF_OK;
    if (!cf_tx_begin(s, &tx))
        return CF_NO_MEMORY;
    tx.final_eof = target_eof;
    if (!cf_tx_commit(&tx)) {
        result = cf_tx_failure_result(&tx, CF_IO_ERROR);
        cf_compact_poison_tx_invariant(&tx, result);
    } else {
        *progress = true;
    }
    cf_tx_dispose(&tx);
    return result;
}

static DWORD WINAPI cf_worker_proc(LPVOID parameter) {
    CF_STORE *s = (CF_STORE *)parameter;
    HANDLE waits[2];
    if (!s || !s->worker_stop || !s->worker_wake || !s->worker_idle)
        return ERROR_INVALID_PARAMETER;
    waits[0] = s->worker_stop;
    waits[1] = s->worker_wake;
    for (;;) {
        DWORD wait_result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0)
            break;
        if (wait_result != WAIT_OBJECT_0 + 1) {
            DWORD error = GetLastError();
            AcquireSRWLockExclusive(&s->lock);
            cf_compact_poison(s, error);
            SetEvent(s->worker_idle);
            ReleaseSRWLockExclusive(&s->lock);
            return error;
        }
        for (;;) {
            bool progress = false;
            CF_RESULT result;
            AcquireSRWLockExclusive(&s->lock);
            if (s->stopping || s->poisoned) {
                SetEvent(s->worker_idle);
                ReleaseSRWLockExclusive(&s->lock);
                break;
            }
            result = cf_store_compact_locked(s, &progress);
            if (result != CF_OK || !progress) {
                if (result != CF_OK && !s->poisoned) {
                    if (result == CF_NO_MEMORY) {
                        cf_set_error(s, ERROR_NOT_ENOUGH_MEMORY);
                    } else if (result == CF_NO_SPACE) {
                        cf_set_error(s, ERROR_DISK_FULL);
                    } else if (result == CF_IO_ERROR) {
                        if (s->last_error == ERROR_SUCCESS)
                            cf_set_error(s, ERROR_GEN_FAILURE);
                    } else {
                        cf_compact_poison(s, result == CF_DATA_ERROR ?
                            ERROR_CRC : ERROR_INVALID_DATA);
                    }
                }
                if (result != CF_OK) {
                    DWORD error = s->last_error;
                    if (error == ERROR_SUCCESS)
                        error = ERROR_GEN_FAILURE;
                    fprintf(stderr,
                        "CryptFS: background compaction paused (%s; Win32 %lu); retry on a later wake.\n",
                        cf_result_text(result), (unsigned long)error);
                }
                /* Set idle while still holding the same lock used by commits
                 * to reset idle and queue wake, avoiding a lost notification. */
                SetEvent(s->worker_idle);
                ReleaseSRWLockExclusive(&s->lock);
                break;
            }
            ReleaseSRWLockExclusive(&s->lock);
            Sleep(0);
        }
        if (WaitForSingleObject(s->worker_stop, 0) == WAIT_OBJECT_0)
            break;
    }
    SetEvent(s->worker_idle);
    return ERROR_SUCCESS;
}

static CF_RESULT cf_start_worker(CF_STORE *s) {
    if (!s)
        return CF_INVALID;
    if (s->worker_thread)
        return CF_OK;
    s->worker_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    s->worker_idle = CreateEventW(NULL, TRUE, TRUE, NULL);
    s->worker_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!s->worker_wake || !s->worker_idle || !s->worker_stop) {
        DWORD error = GetLastError();
        if (s->worker_stop) CloseHandle(s->worker_stop);
        if (s->worker_idle) CloseHandle(s->worker_idle);
        if (s->worker_wake) CloseHandle(s->worker_wake);
        s->worker_stop = s->worker_idle = s->worker_wake = NULL;
        cf_set_error(s, error);
        return CF_IO_ERROR;
    }
    s->worker_thread = CreateThread(NULL, 0, cf_worker_proc, s, 0, NULL);
    if (!s->worker_thread) {
        DWORD error = GetLastError();
        CloseHandle(s->worker_stop);
        CloseHandle(s->worker_idle);
        CloseHandle(s->worker_wake);
        s->worker_stop = s->worker_idle = s->worker_wake = NULL;
        cf_set_error(s, error);
        return CF_IO_ERROR;
    }
    /* Existing containers can already have holes after recovery or a crash. */
    ResetEvent(s->worker_idle);
    SetEvent(s->worker_wake);
    return CF_OK;
}

CF_RESULT cf_store_compact_step(CF_STORE *s, bool *progress) {
    CF_RESULT result;
    if (progress)
        *progress = false;
    if (!s || !progress)
        return CF_INVALID;
    AcquireSRWLockExclusive(&s->lock);
    result = cf_store_compact_locked(s, progress);
    ReleaseSRWLockExclusive(&s->lock);
    return result;
}

CF_RESULT cf_store_wait_idle(CF_STORE *s, DWORD timeout_ms) {
    DWORD wait_result;
    bool poisoned;
    if (!s)
        return CF_INVALID;
    if (!s->worker_thread)
        return CF_OK;
    AcquireSRWLockExclusive(&s->lock);
    if (s->stopping) {
        ReleaseSRWLockExclusive(&s->lock);
        return CF_IO_ERROR;
    }
    if (WaitForSingleObject(s->worker_idle, 0) == WAIT_OBJECT_0) {
        poisoned = s->poisoned;
        ReleaseSRWLockExclusive(&s->lock);
        return poisoned ? CF_IO_ERROR : CF_OK;
    }
    ReleaseSRWLockExclusive(&s->lock);
    wait_result = WaitForSingleObject(s->worker_idle, timeout_ms);
    if (wait_result == WAIT_OBJECT_0) {
        AcquireSRWLockExclusive(&s->lock);
        poisoned = s->poisoned;
        ReleaseSRWLockExclusive(&s->lock);
        return poisoned ? CF_IO_ERROR : CF_OK;
    }
    if (wait_result == WAIT_TIMEOUT) {
        AcquireSRWLockExclusive(&s->lock);
        cf_set_error(s, ERROR_TIMEOUT);
        ReleaseSRWLockExclusive(&s->lock);
        return CF_IO_ERROR;
    }
    AcquireSRWLockExclusive(&s->lock);
    cf_compact_poison(s, GetLastError());
    ReleaseSRWLockExclusive(&s->lock);
    return CF_IO_ERROR;
}

void cf_store_close(CF_STORE *s) {
    if (!s)
        return;
    if (s->worker_thread) {
        AcquireSRWLockExclusive(&s->lock);
        s->stopping = true;
        ReleaseSRWLockExclusive(&s->lock);
        SetEvent(s->worker_stop);
        SetEvent(s->worker_wake);
        WaitForSingleObject(s->worker_thread, INFINITE);
        CloseHandle(s->worker_thread);
        s->worker_thread = NULL;
    }
    cf_store_dispose(s);
}
