# Session cache and server notifications: release acceptance

Date: 2026-10-03 (Asia/Shanghai). **Historical milestone:** this records the earlier `439A...` notification-cache release. The later root `/` cache regression and final `CDA91...` Release with the running R: service are recorded in [CACHE_ACCESS_FIX.md](CACHE_ACCESS_FIX.md). Hashes and service state below belong to this historical milestone. Accepted for the focused source, actual mount, GUI, SCM fixture and production-host temporary-mount scope below. This is not a whole-filesystem conformance or security audit.

## Current deliverable

- Source: `D:\work\fs\scp`.
- Published executable: `D:\work\fs\scp\dist\scpfs-x64\scpfs.exe`.
- Release SHA-256: `439A0166B873E14C9A3B6E7AFA9C27DD4918ACC620B8E1A5397E66608FD0ABCD`.
- Size: 5,388,288 bytes; Windows x64; clang-cl/C17; static CRT, WinFsp, libssh2, OpenSSL and zlib through the existing vcpkg configuration.
- The previous GUI-only binary is preserved as `scpfs-before-cache-20261003.exe` with SHA-256 `9C2E82DC052228E511C1C17EE44C0311E910A164C194B1BEF2FA8013B741EE2C`. The older `scpfs-before-gui-20261003.exe` remains preserved as well.
- Command line, GUI and service default: `--cache-max-mib 0`, meaning no payload capacity limit. Caching remains enabled. Positive values 1..16384 MiB apply payload LRU capacity enforcement. The metadata memory/index bound remains 8 MiB / 4096 entries.
- Cache lifetime is the mount session, with no TTL. The Linux inotify helper is embedded in the EXE and started through a separately authenticated, strictly pinned SSH connection. No remote daemon installation or extra listening port is required; Python 3 is required for monitoring. Unsupported or unavailable monitoring bypasses cache reuse.

## Final build and test evidence

Both presets use clang-cl and `D:\vcpkg`, triplet `x64-windows-static`. Final commands:

```powershell
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure
cmake --build --preset x64-release
ctest --preset x64-release --output-on-failure
```

- Debug: **12/12 passed**, zero skips, 46.41 seconds.
- Release: **12/12 passed**, zero skips, 45.51 seconds.
- Original evidence: each build directory's `Testing/Temporary/LastTest.log`; copied release records accompany this document.

The suites cover CLI defaults/bounds/rejection, exact-case cache keys, stat/list copy isolation, zero/unlimited and positive capacity behavior, provenance validation and epochs, LRU/handle stability, embedded helper bootstrap/protocol/barriers, external writes and metadata changes, rename/delete/hardlinks, old-inode-surviving replacement, unsupported paths, malformed protocol and overflow handling. Actual WinFsp fixtures verify zero/unlimited caching, warm stat/list/payload hits, helper termination/reconnection, external change visibility, CRUD, case sensitivity, timestamps, dirty conflict/recovery and the existing `.in.txt` protocol.

GUI tests verify idle no-argument startup, probe output, forwarded nondefault capacity, actual mount/unmount and zero child exit. The UI was also visually checked with the new default `0` and the label `0=不限`; controls were visible without clipping. SCM tests use unique fixture services, preserve unrelated services and verify nondefault capacity in the registered command line, automatic startup configuration, protected logs, recovery and uninstall.

PE tests cover normal and delay imports. GUI, hostname-based mount and the real production-host temporary process inventories contain only the executable and Windows system/WinSxS modules. No third-party DLL is shipped. The signed embedded WinFsp driver provenance remains unchanged.

## Production-host temporary mount

The final executable above was tested against `root@cn.tqdream.com`, remote root `/`, on the unused temporary drive **V:**. Authentication reused the existing Ed25519 key and strict known-host pin. The capacity option was omitted to prove the new default zero/unlimited. The test supplied its own temporary directory on D: without changing the user's environment or M: contents.

For a 65,543-byte file in a unique owned directory under `/tmp`, the six observed reads took **390.50, 353.61, 588.51, 185.97, 1.23 and 0.82 ms**. The early reads include monitor startup, admission and metadata validation; the final two illustrate steady cache reuse. These are individual observations, not a throughput or latency guarantee. Teardown recorded 3 payload hits, 2 recorded payload misses, 14 stat hits, 7 invalidations and 28 monitor-bypass observations; bypass operations are accounted separately from normal cache misses.

An independent SSH write became visible to the mounted client in **644.47 ms** in this run. External rename also became visible. The temporary process's runtime module check passed, it stopped normally, V: was released, and the test removed exactly its owned files and directory. Machine-readable evidence: `PRODUCTION-CACHE-ACCEPTANCE.json`; module paths: `RUNTIME-MODULES-CACHE-PRODUCTION.json`.

The existing **Scpfs** service was observed stopped normally by SCM at `2026-10-03T00:48:32Z`, with exit code zero, during development. This cache task did not issue that stop and preserved the stopped state. Its existing delayed automatic LocalSystem/R:/remote-root-`/` configuration and 60000-ms command timeout remain in place; next service start loads the updated canonical EXE. No production-service restart or reboot is claimed by this acceptance.

**MemfsC** remained running at PID 68440 throughout the final checks. The memfs release hash remains `3A3F1A5ACE667AA17F70331BD4B1253D37895CDFC3BB5240CF778269A0AD9488`; `memfs_old.exe` remains `4B9110ABE89D1DC05E3AE57DFE53F0E166D4093099F7B5C12154AD2FA242E09B`. This task made no memfs or shared-frontend source changes and did not restart M:.

## Corrections and review boundary

Actual tests exposed GNU stat's `regular empty file` classification and GNU touch's writable-close notification. Empty regular files now use the normal file path; timestamp restoration uses `touch -c`, with file-only ACCESS metadata notifications and post-restore provenance checks. Copying reusable payloads occurs before opening the restrictive writable working handle.

Focused Sol architecture reviews accepted pre-ensure/content-generation checks, post-fetch barriers, stale-ACK rejection, identity revalidation, canonical-root pinning, borrowed-path lifetime ordering, cache/monitor locking, zero/unlimited capacity and the timestamp-notification refinements. Review decisions and limits are recorded in `CACHE_ARCHITECTURE.md`.

An intermediate GUI test closed the window before its mount child had finished teardown; it now waits for explicit child completion and checks zero exit. An intermediate Release cache run captured empty stderr while using a parent temporary log file on the volatile M: filesystem; an immediate rerun passed, so its original cause was not proved. Test logs are now explicitly on D:, and the cache summary uses the same wide-stream output convention as existing diagnostics. The final full runs above passed after these corrections.

## Remaining limits

Notifications provide eventual invalidation, not a distributed transaction. Existing open handles retain their snapshots; mutation preflight/conflict checks remain fresh backend operations. Directory/content invalidation is conservative and may clear unrelated clean entries. Monitoring is limited to supported local Linux filesystems and supported non-symlink/same-device paths; inotify does not cover every mmap or mount-replacement case. Metadata bounds can still evict clean entries even when the payload byte limit is unlimited.

No arbitrary multi-client concurrent-editing guarantee, exhaustive Windows filesystem conformance, large-file throughput benchmark, real reboot or fresh-machine driver installation was tested. No commit or push was performed. The SCP project has no Git repository; the pre-change source snapshot remains under `build/cache-baseline-20261003-075652`.
