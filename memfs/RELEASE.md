# Release verification

Verified on 2026-09-30 on Windows x64.

## Build inputs

- memfs repository: `D:\work\memfs`
- WinFsp Git repository: `D:\src\winfsp`
- signed embedded drivers from the same WinFsp SxS release:
  - x64: `C:\Program Files (x86)\WinFsp\SxS\sxs.20251221T124141Z\bin\winfsp-x64.sys`
  - ARM64: `C:\Program Files (x86)\WinFsp\SxS\sxs.20251221T124141Z\bin\winfsp-a64.sys`
- both driver FileVersions: `2.1.25156.ddca7bd`
- matching WinFsp source commit: `ddca7bd` (tag `v2.1`)
- embedded driver SHA-256:
  - x64: `03553FFFACD362F4A9A08C00B4F236A82354A183BC6028494FB32055386E13C9`
  - ARM64: `BF3B1BF90A7C070D456FC43C8552CCF8BE85CDDDEF4F3B19091B4A64AE4E686C`
- generated matching static worktree: `D:\src\winfsp-memfs-static`
- compiler: `clang-cl 22.1.3` (`e9846648fd6183ee6d8cbdb4502213fcf902a211`)
- vcpkg builtin baseline: `6d332a018c433fad20822ff4b536e4ccdc3413bd`
- release triplet: `x64-windows-static`

The package's machine-readable `BUILD_PROVENANCE.json` is authoritative for the exact memfs Git commit, full WinFsp commit, WinFsp patch diff hash, static-library hash, both SYS hashes/PE machines/Authenticode signer, compiler binary hash/version, vcpkg commit/baseline/triplet hash, dependency versions and final EXE hash.

Run this before a clean build:

```powershell
.\scripts\prepare-winfsp-static.ps1
```

The script reads the installed signed driver's FileVersion, extracts its Git revision,
creates a detached worktree at that exact commit, applies the minimal static-user-mode
support, and builds both Debug and Release `winfsp-static-x64.lib` archives.

This avoids mixing a newer user-mode runtime with an older signed kernel driver.

## Static WinFsp version contract

The build now enforces WinFsp provenance at several independent levels:

1. CMake reads `MyCanonicalVersion` from the selected WinFsp source tree.
2. CMake requires both SYS files to have the same complete FileVersion and the expected major/minor.
3. `verify-winfsp-drivers.ps1` requires x64 SYS = `IMAGE_FILE_MACHINE_AMD64`, ARM64 SYS = `IMAGE_FILE_MACHINE_ARM64`, a `Valid` Authenticode signature, the Microsoft Windows Hardware Compatibility Publisher signer, and the same signer certificate for both drivers.
4. `memfs_winfsp_version_test` calls `FspVersion()` from the linked static archive and verifies the encoded version at runtime.
5. `memfs_resource_test` parses the PE headers of the actual embedded resources and verifies their machine architecture.

A deliberate negative configure test using WinFsp v2.2 static source with the v2.1
signed driver fails with:

```text
WinFsp version mismatch: static runtime expects 2.2,
but embedded driver ... is 2.1.25156.ddca7bd
```

The supplied presets use:

- `VCPKG_TARGET_TRIPLET=x64-windows-static`
- `MEMFS_STATIC_WINFSP=ON`
- `WINFSP_SOURCE_ROOT=D:/src/winfsp-memfs-static`

When a source root is supplied, CMake forcibly selects that tree's
configuration-matched static archive. This prevents an old CMake cache from silently
linking a different WinFsp static library.

## Build and test matrix

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure

cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release --output-on-failure
```

The current test registration contains 20 cases. The generated acceptance report records the executed revision, each result and all failures; source documentation is not a substitute for a passing report.

1. `memfs_capacity_snapshot_test`
2. `memfs_lifetime_test`
3. `memfs_mt_stress_test`
4. `memfs_core_test`
5. `memfs_soak_smoke`
6. `memfs_no_crt_heap_guard`
7. `memfs_no_crt_heap_guard_good_fixture`
8. `memfs_no_crt_heap_guard_bad_fixture`
9. `memfs_driver_test`
10. `memfs_cli_test`
11. `memfs_static_winfsp_no_dll_import`
12. `memfs_static_winfsp_version`
13. `memfs_winfsp_dispatcher_state`
14. `memfs_cli_help`
15. `memfs_cli_reject_negative_size`
16. `memfs_cli_reject_oversized_size`
17. `memfs_cli_reject_thread_one`
18. `memfs_cli_reject_thread_over_limit`
19. `memfs_embedded_winfsp_resources`
20. `memfs_winfsp_driver_provenance`

## Real mounted-drive integration

The Release executable passed the real WinFsp integration test in all four modes:

- plain: PASS
- `--compress`: PASS
- `--encrypt`: PASS
- `--compress --encrypt`: PASS

Each run mounted R:, exercised normal Windows file APIs, binary I/O, sparse-file
zero-fill, rename/move/enumeration/delete, and unmounted cleanly.

## Static WinFsp verification

Matching v2.1 static libraries:

- Debug:
  `D:\src\winfsp-memfs-static\build\VStudio\build\Debug\winfsp-static-x64.lib`
  SHA-256:
  `EB66B092EAC94C973ED929C6CACE2F3254EADE8DF48E7FECC20DB2CED6A104B1`
- Release:
  `D:\src\winfsp-memfs-static\build\VStudio\build\Release\winfsp-static-x64.lib`
  SHA-256:
  `7064859CC5085A4F68BD8A1F9C53B852263257E7B3CD57FDD785BECD313568E2`


`memfs_static_winfsp_no_dll_import` verifies that the final EXE has no WinFsp DLL
import or delay-import dependency.

The Release EXE therefore does not require `winfsp-x64.dll` at runtime.

## Embedded driver behavior

The x64 user-mode executable embeds both signed kernel drivers from the matching WinFsp SxS release:

```text
x64:   winfsp-x64.sys  FileVersion 2.1.25156.ddca7bd
ARM64: winfsp-a64.sys  FileVersion 2.1.25156.ddca7bd
```

CMake requires both SYS files to be the exact same signed WinFsp release as the statically linked x64 user-mode runtime. The shipping user-mode binary is always x64. On normal AMD64 Windows it selects the x64 SYS; on Windows 11 ARM64 running the x64 EXE under emulation, `IsWow64Process2` reports the native ARM64 machine and memfs selects the ARM64 SYS. No 32-bit user-mode or driver path is supported.

memfs first attempts normal `FspFileSystemCreate`. If a compatible official driver is already available, it reuses it and does not install a parallel fallback service. Only when the driver is missing/unloadable does memfs extract the architecture-matched embedded signed SYS, register/start its private fallback filesystem-driver service, and retry `FspFileSystemCreate`.

The extraction path compares an existing file byte-for-byte before replacing it.

## Windows Service verification

The final Release `memfs.exe` was verified through the real Service Control Manager as
LocalSystem.

Successful lifecycle:

```text
sc create
sc start
STATE: RUNNING
mount R:
create/write/read/delete
sc stop
STATE: STOPPED
sc delete
```

A real file round-trip returned:

```text
READBACK=service-release-ok
```

The helper is also verified end-to-end:

```powershell
.\scripts\memfs-service.ps1 install -Exe .\build\x64-release\memfs.exe -Mount R: -Size 64M -StartType demand
.\scripts\memfs-service.ps1 start
.\scripts\memfs-service.ps1 stop
.\scripts\memfs-service.ps1 delete
```

`stop` and `delete` now handle an already-absent service cleanly.

Abnormal-termination recovery is also verified with `tests\service-recovery.ps1`. The service was started as LocalSystem on R:, its process was forcibly terminated, and SCM restarted it with a new PID:

```text
old_pid=13196
new_pid=46288
readback=service-recovery-ok
```

The remounted filesystem was correctly empty after the crash (volatile data did not survive process death), new I/O succeeded, no private WinFsp fallback was created while the official SxS driver was available, and the test cleaned up `MemfsC` afterward. Reboot recovery remains a separate clean-machine/manual validation because this test intentionally does not reboot the development machine.

Service startup failures preserve the underlying WinFsp NTSTATUS in
`SERVICE_EXIT_CODE`. For example, deliberately trying to mount an already-existing
normal directory produced:

```text
WIN32_EXIT_CODE    : 1066  (0x42a)
SERVICE_EXIT_CODE  : 3221225525  (0xc0000035)
```

rather than losing the root cause behind a generic 1066.

## Allocator design verification

Allocator policy is:

- business APIs converge by allocation size, not object type;
- small allocations use adaptive slab backing: 4K / 8K / 16K / 32K / 64K;
- allocations above the small-object threshold use area allocations;
- core/storage code does not call VirtualAlloc directly;
- VM primitives are isolated behind `memfs_vm`.

The current size-class pool contains 16 internal concurrency lanes. These are not
separate node/name/generic pools; they partition slab ownership to avoid a single hot
lock, and empty slabs are still returned immediately to the VM backend.

A three-run A/B benchmark against the previous 8-lane layout showed that at 16 threads
64-byte alloc/free throughput improved by about 114% and 4 KiB throughput by about
209%, with effectively flat single-thread performance. The cost is approximately
12 KiB of additional allocator-state metadata per filesystem.

The allocator also has an explicit uninitialized fast path for buffers that are
completely overwritten before first read. Typed node/dir/page-group allocations and
the normal zeroed APIs retain their zero-initialization contract. Reused slab and area
blocks are covered by tests to ensure zeroed callers never observe stale data.

Per-node metadata was subsequently reduced from 136 to 128 bytes without packing or removing the cached directory-name hash. This moves every `MemfsNode` from the allocator's 192-byte class into the 128-byte class, saving 64 slab bytes per live file/directory node. The former stored 64-bit `index_number` was replaced by a per-filesystem-seeded stable opaque ID derived from the node address; file IDs stay stable for the node lifetime and encryption AAD uses the same derived identity. Debug/Release tests, a 10-second soak, and real mounted plain/compression/encryption/combined integration all pass.

Plain uncompressed full pages were also redesigned so a logical 4 KiB page consumes the allocator's 4096-byte class directly instead of storing an 8-byte `MemfsPage` header beside 4096 bytes of data and rounding the 4104-byte request into the 8192-byte class. Raw pages use a tagged aligned pointer representation; compressed/encrypted pages retain the structured `MemfsPage` object. Existing raw pages overwrite in place, full-zero writes remain sparse, and new-page writes use two-phase encode/commit for rollback safety. The measured resident backing for one plain full page is now 4096 bytes rather than 8192 bytes.

To keep the 16 slab lanes from increasing allocator high-water across repeated identical workloads, a size-class pool now exposes an atomic available-shard bitmap. Allocation stays on the thread's home shard while it has capacity; before growing a new slab it probes only lanes advertised as having free objects and reuses that capacity across shards. At most one shard lock is held at a time. An 8-round fragmentation/reuse benchmark now keeps slab backing stable, final scavenging returns to baseline, allocator MT benchmarks report zero errors, and a 10-second soak reports zero committed/private drift.

Area-cache retention is size-aware rather than uniformly keeping two idle regions per lane. Small area blocks retain the two-slot lane cache, while VM regions larger than 64 KiB retain at most one cached block per lane. In the 64 KiB allocation benchmark this reduced 16-thread retained cached backing from about 1,392,640 bytes to a three-run median of 696,320 bytes (zeroed) / 765,952 bytes (uninitialized). Uninitialized 16-thread throughput stayed effectively flat at about 38.4M ops/s versus a 38.7M baseline, while zeroed throughput remained within a few percent. Debug/Release tests, a 10-second soak, and real mounted integration all pass.

## Auto-capacity available-memory sample cache

The final task-66 review corrected three issues before accepting this optimization:

- A forced refresh could overwrite sample fields while an old deadline remained valid. The entire snapshot is now read/published under the same SRW lock, not as unrelated atomic fields.
- The former net-commit baseline was taken after the OS query. Gross successful commitments are now sampled before it; growth during the query and free/reallocate churn are conservatively debited.
- The TTL now begins before the OS query. Normal Debug no longer bypasses the cache; a separate NDEBUG test executable deterministically exercises the real production path without enabling test hooks in memfs.exe.

Five Release measurements on 2026-10-01:

| metric | before final correctness fix | after final correctness fix |
| --- | ---: | ---: |
| auto growth median | 63.9 ns | 62.6 ns |
| fixed growth median | 27.8 ns | 27.7 ns |
| original uncached auto growth (historical baseline) | 347.3 ns | — |

The small before/after difference is within normal microbenchmark variation; the correctness changes preserve the cache's performance benefit rather than claiming another material speedup. Public allowance queries still use a live OS sample. System memory can change between observation and allocation, so the cache is not a hard reservation against unrelated processes.

Debug and Release now pass 19/19 CTest cases. The dedicated production-path test includes 200,000 cached reads racing 20,000 publications, and deterministic tests for expiry/forced refresh/slow-query aging, gross-commit debit, pressure rejection without data loss, and pressure relief.

Mounted integration now checks multi-page byte-for-byte I/O, a cross-page rewrite, truncate/regrow zero filling, sparse holes, case-insensitive lookup and wildcard enumeration. It launches without a console and reports PASS only after graceful zero-exit shutdown and DOS-device removal. Forced termination is cleanup, not a passing result. A deliberately invalid CLI launch was confirmed to fail the integration harness rather than produce a false PASS.

## Final lifetime correctness review

The extended acceptance run on 2026-10-01 first found an intermittent mounted
combined-mode directory failure. A bounded fresh-child reproduction subsequently
captured a native access violation in a security-descriptor copy. The original
failed report and crash dump are retained; successful retries are not a fix.

WinFsp FINE allows shared FILE_OPEN callbacks and delivers Close asynchronously
without the namespace operation guard. The previous plain `open_count++/--` and
shared orphan-list mutation were therefore unsafe. A newly added regression on
the old core immediately observed only 44,528 references instead of 160,001.

A dedicated 8-byte per-filesystem lifetime SRW lock now coordinates handle counts,
unlink/replacement retirement, and orphan removal. Node size remains 128 bytes;
ordinary file data reads/writes do not acquire this lock. Destruction happens
outside it, after the final valid reference and namespace ownership are gone.
The MT test now exercises unlink-before-close rather than incorrectly avoiding
orphan transitions. A test that read a node after its final close was corrected.

SetSecurity/GetSecurity callbacks additionally use exclusive/shared protection
against FINE's namespace descriptor borrowers. GetSecurityByName must not acquire
the guard recursively because Create/Open already holds it. The callback test
checks a blocked descriptor replacement and 2,000 replacements racing 20,000
validating reads. The lifecycle test checks exact concurrent counts plus final
close, unlink/close and replacement/close races with baseline allocator live bytes.
Fresh mounted repetitions and full acceptance must pass on the fixed revision
before this build is promoted. This fixes confirmed synchronization defects; it
does not assert that tests prove the absence of every possible filesystem bug.

## Hardware AES-GCM encryption fast path

Encrypted pages now select AES-256-GCM automatically when libsodium reports hardware AES-GCM support, with XChaCha20-Poly1305 retained as the portable fallback. The per-page `MEMFS_PAGE_AES_GCM` flag is part of AEAD AAD, and decoding follows that authenticated page flag rather than the current encoder preference.

A fixed/reused master key remains safe across mounts: every mount creates a random 128-bit prefix; AES-GCM derives an independent mount root key from the master key plus that prefix, and derives a new epoch key every 2^20 encrypted blobs/pages. The global 64-bit nonce sequence remains monotonic and unique across all encryption writers. XChaCha keeps the master key and uses the 128-bit mount prefix plus the same sequence as its 192-bit nonce.

Tests cover hardware auto-selection, forced XChaCha fallback, mixed AES/XChaCha pages in one mount, algorithm-flag tampering, ciphertext tampering, mount-key separation, rewrite/truncate/regrow, compression+encryption and concurrent nonce allocation.

Release `memfs_bench --encryption` on this machine, five runs, compared with the pre-change XChaCha baseline recorded immediately before the change:

| workload | XChaCha baseline | AES-GCM median | change |
| --- | ---: | ---: | ---: |
| 4 KiB create+write | 196,507 ops/s | 306,789 ops/s | +56.1% / 1.56x |
| random 4 KiB rewrite | 64,993 ops/s | 133,763 ops/s | +105.8% / 2.06x |

The dedicated encrypted-rewrite benchmark was also rebuilt from the exact pre-change commit `af3dc50` and compared against the current AES-GCM path on the same machine:

| threads | XChaCha `af3dc50` | AES-GCM | speedup |
| ---: | ---: | ---: | ---: |
| 1 | 175,527 ops/s | 578,177 ops/s | 3.29x |
| 2 | 328,743 ops/s | 1,023,758 ops/s | 3.11x |
| 4 | 651,550 ops/s | 2,057,334 ops/s | 3.16x |
| 8 | 969,836 ops/s | 2,869,890 ops/s | 2.96x |
| 16 | 1,480,658 ops/s | 3,821,251 ops/s | 2.58x |

All MT runs reported zero errors. To avoid paying a KDF on every write without retaining an unbounded key set, the filesystem keeps only the newest AES epoch key in one SRWLOCK-protected cache. Old-epoch reads derive a temporary key on demand; there is no thread-local or multi-epoch key cache.

## Repeatable deployment verification

`scripts\verify-deployment.ps1` separates safe development-machine checks from the destructive clean-machine fallback path.

Current x64 development-machine verification:

```powershell
.\scripts\verify-deployment.ps1 -Scenario All -Report .agent\deployment-current.json
```

Result on 2026-09-30:

- release executable/CLI gate: PASS;
- driver/static-version/no-WinFsp-DLL-import/resource CTest gate: PASS;
- no `MemfsC` service: PASS;
- no private `WinFsp+MemfsC` fallback service/file before mount: PASS;
- real mounted-drive smoke using official `WinFsp+20251221T124141Z`: PASS;
- no private fallback service/file after official-driver mount: PASS;
- private-fallback execution: SKIP by default.

The guard was also tested explicitly:

```powershell
.\scripts\verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback
```

On this machine it fails closed because an official WinFsp SxS driver is present. The script will not remove, stop, overwrite, or repoint an official WinFsp installation merely to exercise the fallback.

The remaining clean-VM validation is therefore explicit and reproducible rather than simulated. On a disposable elevated Windows VM with no WinFsp installation:

```powershell
.\scripts\verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback -Report C:\temp\memfs-private-fallback.json
```

The harness verifies private service creation, MemfsC-owned driver filename/path, a real mounted-drive I/O smoke test, and uninstall cleanup. It refuses to run this scenario if an official WinFsp driver is detected.

## Current binaries

Do not use a hardcoded EXE hash from this source document. The current package's
`dist/memfs-x64/BUILD_PROVENANCE.json` and `SHA256SUMS.txt` bind the exact source
revision, toolchain, embedded driver inputs and executable. A package is accepted
only when a passing report for that revision also verifies those hashes. A failed
acceptance remains failed even when subsequent isolated reproductions pass.

## Portable validation handoff

`scripts/package-validation-kit.py` produces a diagnostic kit only from an actual
passing acceptance report and identical accepted build/package EXEs. The kit can
run the corresponding 20 Release tests without CMake, vcpkg or a compiler. It
contains the signed driver reference files, test binaries, scripts, source-guard
inputs, a strict SHA-256 manifest and copied host acceptance/provenance records.
See `docs/PORTABLE_VALIDATION.zh-CN.md` for clean-guest and ARM64 instructions.

A later documentation/handoff-only revision may be paired with the original full
run using `--extended-report`, but only after a new current-HEAD acceptance passes,
the EXE hashes match, test registration is unchanged, and no compiled/runtime/build
input changed. Both original reports are retained with their own revision; the
old run is never relabeled. A failed extended run cannot be used for a kit.

## Release packaging

`scripts\package-release.ps1` creates the single x64 user-mode release directory `dist\memfs-x64` with:

That same package is the Windows 11 ARM64 package; there is no separate ARM64 user-mode build.

- `memfs.exe`
- `BUILD_PROVENANCE.json`
- `THIRD_PARTY_NOTICES.md`
- `licenses/WinFsp-License.txt`
- `licenses/libsodium.txt`
- `licenses/zstd.txt`
- `SHA256SUMS.txt`

Packaging is a release gate, not a copy step. It rejects tracked-dirty source trees, requires a Release/x64-static CMake cache, rebuilds the build directory, runs the complete CTest suite, writes `BUILD_PROVENANCE.json`, immediately verifies it against the current files/toolchain, and only then atomically publishes the staging directory.

The package intentionally includes the original third-party license texts rather
than paraphrasing them as the authoritative legal terms. The static WinFsp build
also has an explicit release gate in `THIRD_PARTY_NOTICES.md`: the WinFsp
FLOSS exception in the local source tree names platform DLL linking, while this
build statically links user-mode WinFsp code. Proprietary distribution therefore
requires an appropriate licensing decision before release.

## Remaining productization items

Before broad external distribution, separately validate:

- code-signing policy for the final EXE;
- final WinFsp distribution-license decision for static linking (for proprietary distribution, obtain appropriate commercial permission or use distribution terms compatible with the applicable WinFsp/GPLv3 obligations);
- Windows 10 and Windows 11 clean-machine installation;
- Windows 11 ARM64 validation of the single x64 `memfs.exe` under x64 emulation, including selection/install of the embedded ARM64 kernel driver;
- coexistence testing against materially older/newer official WinFsp installations, while preserving the private-service isolation rules already implemented;
- service recovery across a real OS reboot (abnormal process termination is now covered automatically);
- clean-machine embedded-driver fallback with no WinFsp installation present, using the now-checked-in `verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback` harness.
