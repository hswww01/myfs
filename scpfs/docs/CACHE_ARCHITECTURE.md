# Session read cache and Linux change notifications

Decision date: 2026-10-03 (Asia/Shanghai).

Status: implemented and accepted through focused architecture review, final Debug/Release tests and a production-host temporary mount. See CACHE_VALIDATION.md for package identity and the explicit service-state boundary.

The user requested reuse across requests, selected session lifetime without a TTL, and then requested server-side change notifications. A Luna investigation confirmed repeated adapter stat/list commands and whole-file downloads on each payload Open. A Sol Ultra architecture review approved the following bounded design because notification ordering, cache admission, and dirty-write protection cross concurrency and protocol boundaries.

## Cache boundary

Only the SCPFS adapter caches successful reads. Backend stat, mutation preflight, upload conflict comparison, inbox execution, and authentication remain fresh operations. Keep per-open mutable working files, open-handle guards, snapshot semantics, timestamp preservation, and recovery manifests unchanged. Cache entries never own active or dirty/recovery files. Do not refill cache from delayed Cleanup/Close.

Cache stat and directory lists in bounded metadata storage (8 MiB and 4096 entries), and immutable payload copies in the existing private session directory. The user's final capacity decision is `--cache-max-mib 0` by default: zero means unlimited payload capacity, and caching stays enabled. Positive values from 1..16384 MiB enable payload LRU capacity enforcement. Files larger than a configured positive bound still work through the existing working-file path. Case-sensitive keys and independent copies prevent aliases or writes from corrupting cached bytes. Errors and negative results are not cached.

Local mutations invalidate clean entries before/after potentially changing operations; global invalidation is acceptable in v1. Inbox execution clears all clean entries before and after dispatch, including failed or uncertain outcomes. It never deletes recovery data.

## Notification connection

Use a second SSH connection with the same strict host-key checks and public-key authentication. A single monitor owner thread alone accesses that connection. It executes an embedded Python 3 standard-library helper using ctypes/inotify. No remotely installed daemon, additional listening port, or third-party Windows DLL is needed. Production Python 3.12.3 was confirmed by a read-only check; missing Python/helper support degrades to uncached remote reads.

The helper watches a requested file/directory plus every ancestor to the configured root, with acknowledgement before cache admission. This covers directory-entry replacement and file-inode/hard-link events. Reject symlinks, cross-device traversal and unsupported/network/pseudo filesystems for cache admission; the initial native-filesystem allowlist is ext4, xfs, btrfs, tmpfs and overlay. These restrictions affect caching, not the existing remote filesystem operations.

Protocol v1 uses bounded ASCII lines and hex-encoded UTF-8 virtual paths, monotonically increasing numeric request IDs, and an explicit version greeting. Requests: `W id F|D hexpath`, `B id`, `Q`. Responses: `A id OK|UNSUPPORTED|ERROR`, `E maskhex`, `X reason`. A barrier drains pending inotify events before its acknowledgement. Add a bounded heartbeat/liveness exchange so a stalled connection cannot keep cache eligibility indefinitely. Malformed/overlong input, overflow, watch exhaustion/loss or disconnect invalidates monitoring health and both generations.

Monitor API: start(options), ensure(virtual_path, directory), barrier(), snapshot(healthy, metadata_epoch, content_epoch), stop(). Its owner thread only updates monitor state; it never calls into the adapter or takes its SRW lock. The existing adapter SRW lock may remain held during ensure/barrier. Stop/join must occur outside that lock. Reconnection starts with empty subscriptions and invalid cache, and lazily acknowledges new coverage.

## Admission and invalidation

Content/namespace events (MODIFY, CLOSE_WRITE, CREATE, DELETE, MOVED_FROM/TO, DELETE_SELF, MOVE_SELF) advance both global epochs. ATTRIB always advances metadata. A pure regular-file ACCESS event is sampled against one verified stat baseline per inotify watch descriptor: unchanged metadata is quiet; actual atime/ctime or other sampled metadata changes advance metadata; a sampled size/mtime change advances content. Missing or ambiguous inode identity fails monitoring closed. ACCESS is not subscribed on directories. Hard-link aliases share a descriptor and must not reset its baseline. V1 may invalidate all clean entries for a content/namespace event. Queue overflow, IN_IGNORED, protocol errors or lost connectivity mark the monitor unhealthy and advance both epochs; reads bypass cache until monitoring and path coverage are ready again. The bounded access-event repair and its race constraints are recorded in [CACHE_ACCESS_DECISION.md](CACHE_ACCESS_DECISION.md).

Before a cold fetch, establish coverage and capture epochs. Fetch remotely, issue a monitor barrier, and publish only if the relevant epoch and healthy connection remain stable. At most one retry is allowed; otherwise return the fetched result without caching. Hot hits check epochs/health locally and issue no SSH request.

GNU touch uses `-c` to restore timestamps without creating or opening files for writing; the previous form emitted CLOSE_WRITE and defeated payload admission. Explicit timestamp changes remain observable as ATTRIB, and ordinary reads can produce ACCESS even when atime stays unchanged. Keep payload bytes across a metadata event only after a fresh stat matches their post-download provenance: type, device, inode, size, mtime, mode, uid, gid and ctime. Internal GNU stat/find records include uid/gid/ctime for this purpose. The baseline is the final stat after atime restoration. Cold payload admission also requires exact atime equality at its final verification, so it cannot publish a stale timestamp under a new metadata generation. Warm revalidation may update atime while retaining proven immutable bytes. Missing fields, stat failure or changed byte provenance evicts bytes. Keep the backend's existing conflict comparator unchanged because restoring atime itself changes ctime.

This is eventual notification-driven invalidation, not linearizable multi-client storage. Existing open handles retain their established snapshots and writeback guards. Inotify has limitations for mmap changes, mount-root replacement and nonlocal filesystems; unsupported paths bypass caching. Do not claim arbitrary remote changes are synchronously visible before their notification arrives.

## Acceptance gates

- Deterministic cache tests count underlying stat/list/download calls, prove warm hits cause no calls, and cover case-sensitive keys, limits/LRU, failure retry and monitor fallback.
- Helper/monitor tests cover acknowledged coverage, barriers, external content and metadata events, rename/delete/hard links, malformed/overflow/disconnect handling and recovery.
- Actual WSL SSH/WinFsp mount tests cover external changes after warming, own-atime notifications, existing CRUD/inbox/conflict/recovery behavior and graceful teardown.
- clang-cl Debug/Release suites, static import and runtime-module checks, GUI capacity option, final package identity and production acceptance remain separate gates.

No memfs source, shared frontend behavior or existing M: service is in scope.

## Final review refinement

The final Sol review identified a subscription/admission race when a namespace event arrives during a W request: an acknowledgement can otherwise reintroduce a subscription for the old inode after the event clears it. Cache admission must compare the content generation from before ensure through its barrier; a changed generation causes bypass or a bounded retry. The monitor must not retain a W subscription if content generation changed during that exchange. The helper revalidates watched identity after draining events and before acknowledgement. These checks supplement the existing fetch/barrier generation checks; a build or passing steady-state tests does not establish this ordering property.

The monitor receives a copy of the main backend's canonical root, and its connection refuses a different canonicalization result. This prevents two independently connected sessions from silently reading one symlink target while monitoring another. Borrowed payload paths are acquired only after the final cache-invalidating synchronization; no invalidating operation may run between that acquisition and the local copy.

The final focused architecture re-review accepted these ordering, lifetime, root identity and locking changes with no remaining must-fix finding. Runtime acceptance is recorded separately. The user subsequently clarified that the default capacity must be zero/unlimited and caching always enabled; this changes capacity policy only, preserving metadata memory bounds and notification admission/fallback rules.

A further focused Sol review accepted the zero/unlimited implementation, `touch -c` timestamp restoration and file-only ACCESS metadata notifications. The latter were validated against actual GNU touch/inotify behavior and retain post-restore provenance verification. Runtime Debug/Release and production-host evidence remain separate from architecture acceptance.
