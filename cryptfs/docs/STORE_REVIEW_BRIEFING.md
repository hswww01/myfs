# CryptFS store review briefing

## Objective and scope

Focused source review for the store's high-risk persistence paths: crash recovery, resize atomicity, page ownership, orphan cleanup, rename, and compaction. This is not a full project audit. Production files were read-only in this review; only `tests/test_store.c` and this briefing were in scope for edits.

## Confirmed implementation facts

- `src/cryptfs_store.c::cf_node_resize` now stages an optional partial-block rewrite, inode size/timestamps/logical usage, and map truncation in one `CF_TX`. The boundary block is encoded before the transaction; its new fragment pages are reserved, then the node/map RAM state is changed to assemble the transaction images. `cf_tx_commit` writes and flushes the journal before the COMMITTED marker, then home pages, final EOF, and EMPTY marker.
- A precommit failure restores the boundary block pointer, map count/next/head/tail, file size/timestamps, and logical usage. Unregistered boundary pages and block state are wiped and freed. On successful commit, new pages are registered and linked into the owner graph before the old boundary block and trimmed pages are unregistered and freed. A post-COMMITTED I/O failure poisons the store; reopening is required to resolve the durable outcome.
- Tail-map removal with `keep == 0` snapshots the predecessor and serializes its updated `next == 0` link in the same transaction. Rollback restores the old predecessor link. For sequential block writes, the first map reaches its 125-entry capacity before the next map is created, so the 130-to-125 regression exercises that removal path.
- Appending a new map page now also includes the prior tail map as a transaction afterimage. Without that link update, the new map and inode size could commit while the predecessor's persisted `next` pointer remained zero; reopen then silently treated the appended blocks as sparse. The 130-block tail-value fixture exposed this and is retained alongside the cross-map truncate tests.
- `cf_page_unregister_tree` in `src/cryptfs_store.c` uses an iterative owner-return traversal rather than recursive descent. It detaches a child before descending, saves the parent pointer before freeing the current page, and returns using that saved pointer. It requires the registered ownership relation to remain an acyclic single-owner tree.
- `cf_reclaim_orphans` gathers an orphan subtree before committing its unlink from the orphan list, then unregisters physical pages and frees the associated node/map/block objects. If the transaction fails, the prior orphan link and page owner are restored.
- `cf_node_rename` in `src/cryptfs_store.c` updates namespace links, parent/name metadata, and any replacement target's orphan link in one transaction. It saves and restores sibling links and node metadata on precommit failure. After commit it refreshes physical child-page owners, updates the in-memory child index and subtree depths, and reclaims an unreferenced replacement target.
- `src/cryptfs_compact.inc::cf_store_compact_locked` moves at most one page per step. It writes the relocated page and rewritten owner page in one transaction, then updates the in-memory slot map and attempts to punch the old hole. Punch failure records the Win32 error and emits a warning while preserving the committed move; when no internal hole remains, a later step performs a zero-image EOF-trim transaction. Worker execution and public compact-step execution serialize through the store's exclusive SRW lock.

## Regression added

`tests/test_store.c` adds a child-process resize crash test for phases 1–5. Each phase starts from a flushed file containing a deterministic full 64 KiB block and shrinks it to 1024 bytes. After the child exits at the selected durable phase, the parent remounts:

- Phase 1 must recover the old 64 KiB size and original tail bytes.
- Phases 2–5 must recover size 1024; the test regrows to 64 KiB and checks that the truncated tail is zero while the retained prefix is intact.

The test is dispatched with the private `--resize-crash` child mode and creates phase-specific containers under the test executable directory. It does not use `%TEMP%`.

Additional focused tests now cover: a damaged second raw fragment page with exact `CF_DATA_ERROR`, no-write hash, and pristine sparse-container reopen; postcommit page-registration failure while replacing a block followed by poisoned-store close and remount verification of the committed new byte; injected page-allocation failure during a partial shrink with `CF_NO_SPACE`, unchanged size/data/host-file hash and successful remount; aligned truncate-to-zero and unlink while the allocation-failure hook is armed; and reclaim-hook failure after zero-reference unlink or rename-replace, checking successful namespace results and recovery/reclaim on remount. A map-chain truncate crash test covers phases 1–5 while trimming a 130-block file across its two map pages, then checks recovery, regrowth, and zeroed tail. Host-I/O fault cases exercise precommit journal write/flush failure, commit-marker write failure, committed-marker flush failure, EOF failure, and a short authenticated marker prefix; replacement-block write cases check precommit RAM rollback and old-block recovery. Deferred reclaim tests inject journal and marker failures after durable unlink. Compaction tests inject sparse-punch failure and WAL/marker/home-page/EOF failures in both page-move and zero-image EOF-trim transactions; precommit failures must leave the graph/EOF intact and allow a successful retry. Child-process phase 1–5 tests cover open-file unlink, replacement rename, and compaction page moves. These hooks simulate deterministic failures; the allocation hook is not evidence of actual exhaustion at the four-million-page limit.

Earlier regressions in the same test file cover constrained writes at EOF, directory basic-info persistence, partial truncate then regrow, rename replacement/open handles, map-chain tail removal/remount, orphan cleanup, malformed authenticated graphs, and WAL/page tampering no-write behavior.

## Validation evidence and limits

- Validation evidence below comes from the coordinated root runs and the project-local logs/results inspected for this briefing; this reviewer did not independently run builds or tests.
- Debug: all 7/7 CTest cases passed. `cryptfs_store_test` took 216.22 seconds; total was 216.98 seconds. Root reported completion at 13:44:10.
- Release: all 7/7 CTest cases passed. `cryptfs_store_test` took 79.51 seconds; total was 80.13 seconds.
- Strict ASan build used `/MT /Zi /Od /W4 /WX`; it completed with `store tests passed` and no ASan errors. Leak detection was disabled, so this does not establish absence of leaks.
- The final map append-link fix and its 130-block live-tail reopen check are included in the passing suite. The map-chain truncate/reopen regression covers the 130-to-125 boundary. The five resize crash phases and 15 namespace unlink/rename/compaction crash cases are included and passed. Historical sparse-copy fixture, poisoned lookup expectation, double-close cleanup, and append-link defects are resolved history, not current pending failures.
- Final Release mount/integration result `build/integration/867f16e5b42a4a64b3842a4bbe40737f/result.json` reports `passed: true`, including multi-map resize, sparse allocation, and wrong-password no-write checks. GUI integration `build/gui-integration/6bed43c8dad645c79cccdc537ce50f0e/result.json` reports `passed: true`; its runtime module inventory was inspected, and the owned-window PrintWindow screenshot was inspected by root, all reported PASS.
- Final Release executable SHA-256: `35DDD40AAF9893C101456A40DF3392C4B4C8F7255DF6E5D94A31766AC038FA75`.
- Sol completed the final focused architecture acceptance in `docs/ARCHITECTURE_REVIEW.md`, accepting the v1 milestone within its documented validation boundaries. The Release package is at `dist/cryptfs-x64`; its executable identity, static imports, embedded resources, and all manifest payload hashes/sizes were checked by root.

## Unknowns and candidate concerns

- Actual power-loss durability, disk-full behavior, and device/filesystem cache guarantees are not established by process-crash or injected-I/O tests.
- Behavior at the four-million-page limit (4096 bytes per physical page) and 65,536-node scale remains unverified; the allocation hook does not simulate true exhaustion at that limit.
- Large-container latency and memory/leak behavior remain unmeasured. ASan leak detection was disabled.
- The documented v1 format does not detect replay of an old valid whole container or an authenticated old record at the same slot and identifier. Rollback freshness is an accepted product boundary, not a passing security test.
- Physical sparse-space recovery depends on the filesystem's `FSCTL_SET_ZERO_DATA` behavior; the deterministic punch-failure test confirms logical continuation and later trimming, not physical reclamation on every filesystem.

## Escalation decision and outcome

The escalation requested review of three persistence boundaries: (1) the resize transaction's staged RAM mutation, WAL image set, rollback, and postcommit ownership release; (2) iterative owner-return destruction plus orphan/rename rebinding and unique ownership; and (3) one-page compaction transactions, owner-pointer rewrites, hole punching, and later zero-image EOF trimming. The final review accepted the implemented invariants and the completed deterministic fault/crash tests without a new blocker. Its source scope, test evidence and remaining untested operating conditions are recorded in `docs/ARCHITECTURE_REVIEW.md`; acceptance does not establish durability under every real storage failure.
