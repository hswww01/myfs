# memfs

A high-performance volatile Windows memory file system written in C17 on top of the native WinFsp API.

## Features

- Pure C17, CMake, Ninja, clang-cl and vcpkg.
- Native WinFsp API; no FUSE layer.
- Case-sensitive lookup with case-preserved names; entries that differ only by case can coexist.
- Adaptive directory index: intrusive treap plus a lazy open-addressing hash for large directories.
- Create/open/read/write/truncate/rename/move/delete and directory enumeration.
- Sparse file storage with 4 KiB logical pages.
- Tiny-file storage with 8-byte plaintext granularity.
- Optional per-page Zstd compression.
- Optional per-page authenticated encryption: hardware AES-256-GCM when available, with XChaCha20-Poly1305 fallback.
- Windows file attributes, timestamps and ACL/security descriptors.
- WinFsp FINE operation guard so different files can perform I/O concurrently.
- Thread-safe global capacity and resident-memory accounting.

All file-system contents are volatile. Unmounting or terminating the process loses all files.

## Filename comparison

Names use exact, case-sensitive UTF-16 code-unit comparison throughout lookup, collision checks, directory ordering, wildcard filtering, rename and deletion. For example, `Readme.txt` and `README.TXT` are separate entries, and a lookup using another spelling does not resolve either one. Names are case-preserved, and Unicode names are compared as supplied without case folding or normalization.

Case sensitivity is selected when WinFsp creates a volume, so an already-mounted instance keeps its existing behavior. Validate a rebuilt version on a newly mounted, unused volume; do not stop a live volatile volume unless its contents may be discarded.

## Prerequisites

- Windows 10/11 x64, or Windows 11 ARM64 running the x64 user-mode executable under Windows x64 emulation. 32-bit Windows and Windows 10 ARM64 are not supported.
- WinFsp Git source tree at `D:\\src\\winfsp`; `scripts\\prepare-winfsp-static.ps1` derives the exact source commit from the installed signed driver and prepares `D:\\src\\winfsp-memfs-static`.
- Visual Studio C/C++ build tools.
- LLVM/clang-cl.
- CMake + Ninja.
- vcpkg at `D:\vcpkg` for the supplied presets.

The vcpkg manifest installs `zstd` and `libsodium`. Before the first build, run `scripts\\prepare-winfsp-static.ps1`. It reads the installed signed WinFsp driver's FileVersion, resolves the matching Git commit, creates `D:\\src\\winfsp-memfs-static`, applies the minimal static-user-mode support, and builds Debug/Release static libraries from that exact source version. The supplied presets then link that matching static runtime, so `memfs.exe` does not require `winfsp-x64.dll` at runtime.

Both signed WinFsp kernel drivers (`winfsp-x64.sys` and `winfsp-a64.sys`) are embedded into the single x64 `memfs.exe`. CMake requires the two SYS files to come from the same signed WinFsp release and to match the statically linked x64 user-mode runtime. The build additionally validates each SYS PE machine (`AMD64` / `ARM64`), requires a valid Microsoft Windows Hardware Compatibility Publisher Authenticode signature, and requires the two drivers to share the same signer. At runtime memfs uses `IsWow64Process2` to determine the native Windows machine architecture: AMD64 hosts use the x64 SYS, while Windows 11 ARM64 hosts running the x64 EXE under emulation use the ARM64 SYS. Kernel drivers are never emulated. CTest also calls `FspVersion()` from the linked static library, parses the embedded SYS PE headers, reruns the driver provenance gate, and parses the built PE import/delay-import tables, so stale/mismatched WinFsp inputs or a reintroduced `winfsp*.dll` dependency fail verification. If no compatible official WinFsp driver is available, an elevated memfs process installs/starts the matching embedded signed fallback driver and retries `FspFileSystemCreate`.

## Build

```powershell
cd D:\work\fs\memfs

.\scripts\prepare-winfsp-static.ps1

cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug

cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release
```

## Release package and third-party notices

Create the current x64 release package with:

```powershell
.\scripts\package-release.ps1
```

The package contains `memfs.exe`, `BUILD_PROVENANCE.json`, `THIRD_PARTY_NOTICES.md`, SHA-256 sums, and the authoritative license texts for WinFsp, libsodium and zstd. Packaging is intentionally strict: the tracked Git tree must be clean, the Release build is rebuilt, the full CTest suite must pass, and the generated provenance is verified before the staging directory is published. `BUILD_PROVENANCE.json` records the exact memfs/WinFsp commits, WinFsp patch diff hash, static-library and SYS hashes, PE architecture/signature evidence, compiler binary/version, vcpkg Git commit/builtin baseline/triplet hash, dependency versions, and final EXE hash.

This same x64 package is used on Windows 11 ARM64. Windows runs `memfs.exe` under x64 emulation, while memfs selects the embedded native ARM64 WinFsp kernel driver when a fallback driver is required.

The current build statically links WinFsp user-mode code. WinFsp's local
`License.txt` states GPLv3 and its FLOSS special exception explicitly covers
linking with the platform WinFsp DLLs, not a general static-linking exception.
Before proprietary distribution, obtain appropriate WinFsp commercial
permission or otherwise ensure the chosen distribution terms satisfy the
applicable WinFsp/GPLv3 obligations. See `THIRD_PARTY_NOTICES.md`.

## Run

Run `memfs.exe` with no arguments, or pass `--gui`, to open the native configuration window. Use **挂载** to start a temporary console-mode mount owned by that window and **卸载临时挂载** to stop only that instance. The **安装并启动服务** and **卸载服务** actions use the selected service name; uninstall requires only that name. Mount settings include capacity, label, dispatcher threads, compression, encryption, debug logging, and runtime statistics. The GUI accepts an environment-variable name for an existing 64-hex key but never asks for or displays the key itself. LocalSystem service installation rejects environment keys; choose **随机临时密钥** or disable encryption for that action.

Basic 512 MiB RAM disk:

```powershell
.\build\x64-release\memfs.exe --mount R:
```

Custom capacity and label:

```powershell
.\build\x64-release\memfs.exe --mount R: --size 1G --label FASTRAM
```

Compression:

```powershell
.\build\x64-release\memfs.exe --mount R: --compress
.\build\x64-release\memfs.exe --mount R: --compression-level 3
```

Encryption with a random process-lifetime key:

```powershell
.\build\x64-release\memfs.exe --mount R: --encrypt
```

For a caller-supplied 256-bit key, prefer an environment variable so the key does not appear in the command line:

```powershell
$env:MEMFS_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
.\build\x64-release\memfs.exe --mount R: --compress --key-env MEMFS_KEY
```

`--key-hex <64hex>` is also supported for testing, but command-line arguments may be visible to other processes or diagnostic tools.

Options:

```text
--mount <path>          Drive letter or directory mount point
--size <bytes|auto>     Capacity 1..INT64_MAX; K/M/G suffix supported
--label <name>          Volume label
--threads <n>           Dispatcher threads; 0 = automatic, otherwise 2..64
--compress              Enable Zstd compression at level 1
--compression-level <n> Enable Zstd level 1..22
--encrypt               Use a random 256-bit key; hardware AES-256-GCM when available, else XChaCha20-Poly1305
--key-hex <64hex>       Use a fixed 256-bit key
--key-env <name>        Read a 64-hex key from an environment variable
--debug                 Enable WinFsp debug logging
--service               Run under the Windows Service Control Manager
--service-name <name>   Service name; default: MemfsC
--log-file <path>       Absolute path for the protected service log
--install               Install and start an automatic LocalSystem service
--uninstall             Bounded-stop and remove only the named service
--uninstall-private-driver  Remove only MemfsC-owned private WinFsp fallback service/files
--stats                 Print a human-readable runtime snapshot at mount and stop
--stats-json            Print stable one-line JSON runtime snapshots at mount and stop
--help
```

Stop with Ctrl+C.

## Windows Service

The native installer creates a `SERVICE_WIN32_OWN_PROCESS` service named `MemfsC`, configures automatic start and bounded restart recovery, and starts it immediately. The service runs as LocalSystem. Its protected log defaults to `%ProgramData%\MemfsC\MemfsC.log`; its DACL grants access only to SYSTEM and the installing user's SID. Pass `--log-file` to select another absolute log path. The executable handles STOP and SHUTDOWN controls and stops the WinFsp dispatcher before tearing down the filesystem and allocator.

Run these commands from an elevated shell:

```powershell
.\build\x64-release\memfs.exe --install --mount R: --size 512M --label MEMFS
sc.exe queryex MemfsC
.\build\x64-release\memfs.exe --uninstall
```

Use `--service-name MemfsFrontendTest` to install a separate service for testing; pass the same name to `--uninstall`. Repeating an identical install is idempotent. An install that changes the registered executable or service arguments is rejected. Native install rejects `--key-hex` and `--key-env`, because a LocalSystem service cannot safely inherit a user's key argument or environment; `--encrypt` remains available and generates a fresh key at startup. Manual `--service` mode and the `scripts\memfs-service.ps1` helper remain available for existing SCM workflows.

A helper that still uses `sc.exe` for all service control is included:

```powershell
.\scripts\memfs-service.ps1 install -Exe .\build\x64-release\memfs.exe -Mount R: -Size 512M
.\scripts\memfs-service.ps1 start
.\scripts\memfs-service.ps1 query
.\scripts\memfs-service.ps1 stop
.\scripts\memfs-service.ps1 delete
.\scripts\memfs-service.ps1 purge-driver -Exe .\build\x64-release\memfs.exe
```

The service runs as LocalSystem by default. The first driver installation requires administrator rights. If a compatible official WinFsp SxS driver is already installed, memfs reuses it and does not create a parallel driver service. If the driver is missing or unloadable, memfs extracts the embedded signed WinFsp SYS resource, registers it through SCM, starts it, and retries `FspFileSystemCreate`.

Abnormal service recovery is covered by a destructive-but-self-cleaning integration test:

```powershell
.\tests\service-recovery.ps1 -Exe .\build\x64-release\memfs.exe -Drive R: -Size 64M
```

The test installs `MemfsC` with the configured SCM restart policy, starts it, writes a sentinel file, forcibly terminates the service process, waits for SCM to restart it with a new PID and remount a fresh volatile filesystem, verifies post-restart I/O, and finally stops/deletes the service. On a machine with official WinFsp installed it also asserts that no private `WinFsp+MemfsC` fallback driver appears.

If Service initialization fails, `sc.exe query MemfsC` preserves the underlying WinFsp/NTSTATUS value in `SERVICE_EXIT_CODE` instead of exposing only the generic Windows service error 1066.

### Deployment verification harness

`scripts\verify-deployment.ps1` provides repeatable deployment checks without silently modifying an official WinFsp installation.

On a development machine with official WinFsp already installed:

```powershell
.\scripts\verify-deployment.ps1 -Scenario All -Report .agent\deployment.json
```

This runs the release deployment gate tests, verifies the no-`MemfsC` service state, mounts a real filesystem through the installed official WinFsp driver, exercises normal file I/O, and confirms that no private `WinFsp+MemfsC` fallback service or `memfs-winfsp-*.sys` file was created.

The embedded private-driver path requires a genuinely clean VM with no official WinFsp SxS driver installed. It is intentionally opt-in:

```powershell
.\scripts\verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback -Report C:\temp\memfs-private-fallback.json
```

That scenario requires administrator rights, refuses to run if an official WinFsp driver is detected, mounts memfs to force the embedded fallback path, validates that the private driver points only to MemfsC-owned filenames, and removes the private service/files afterward unless `-KeepPrivateDriver` is specified.

## Directory design

MemfsDir allocates no hash table for small directories. Every child is stored in an intrusive treap, which is the authoritative ordered index and provides expected O(log n) insertion/deletion/lookup plus naturally sorted enumeration.

At 256 children memfs lazily adds a Robin Hood open-addressing hash accelerator. The hash targets an 85% maximum load, uses backward-shift deletion instead of tombstones, and is discarded again when the directory falls below half the activation threshold. The treap remains authoritative, so a hash allocation failure never corrupts the namespace.

Directory/file metadata is packed aggressively:

- MemfsNode is 128 bytes on x64 and is compile-time pinned to the allocator's 128-byte class; the previous 136-byte layout rounded up to a 192-byte slab slot, so every live file/directory node now consumes 64 fewer slab bytes (33.3% less node-slot memory).
- directory state, tiny-file storage and paged-file storage are mutually exclusive and share one pointer-width union;
- node, optional directory state and name storage are deliberately separate size-class allocations: the 128-byte node already exactly fills its class, so co-allocating a name would push the common object into the 192-byte class and increase physical backing;
- inherited ACLs are reference-counted and shared;
- nodes removed from the namespace reuse treap links for the orphan/open-handle list.
- the WinFsp `IndexNumber` is derived from the stable node address through a per-filesystem seeded 64-bit permutation instead of storing another 8-byte field; it remains stable across rename/unlink while the node is alive.

Local A/B benchmark with 50,000 files in one directory:

| metric | 26638fb baseline | current |
|---|---:|---:|
| create 50k | ~32.9-33.8 ms | ~21.9-23.7 ms |
| lookup 50k | ~11.6-13.7 ms | ~6.9-9.8 ms |
| enumerate 50k | ~1.35-1.91 ms | ~0.6-1.6 ms |
| process private-memory delta / entry | ~457-458 B | ~220 B |
| hash slots at 50k | 131,072 | 65,536 |

The current test suite also removes half of a large Robin Hood table, validates positive/negative lookups, reinserts new names and re-enumerates the ordered treap to exercise backward-shift deletion.

## File storage

Windows-visible AllocationSize, internal quota accounting and actual RAM residency are intentionally separate.

### Tiny files

Files up to 4 KiB use an encoded small representation. Plaintext capacity uses exact 1/2/4/8-byte tiny classes and then 8-byte granularity. Uncompressed/unencrypted data up to 8 bytes is stored directly inside the inode union, so it performs no additional heap allocation at all.

The WinFsp volume still uses 512-byte sectors, therefore the AllocationSize reported to Windows is rounded to 512 bytes. Internally, quota accounting is byte-granular: a 1-byte file consumes 1 byte of configured memfs capacity, not 512 bytes.

Uncompressed/unencrypted local measurements:

| file size | Windows AllocationSize | internal quota | tracked data resident |
|---:|---:|---:|---:|
| 1 B | 512 B | 1 B | 0 B |
| 7 B | 512 B | 7 B | 0 B |
| 8 B | 512 B | 8 B | 0 B |
| 9 B | 512 B | 9 B | 24 B |
| 100 B | 512 B | 100 B | 112 B |
| 500 B | 512 B | 500 B | 512 B |
| 1024 B | 1024 B | 1024 B | 1032 B |

With encryption enabled a 1-byte file uses 33 bytes of tracked encoded storage: 8-byte blob header + 8-byte nonce sequence + 1 byte payload + 16-byte AEAD authentication tag.

resident_bytes tracks encoded data blobs/pages and intentionally excludes host allocator bookkeeping and namespace metadata.
### Allocator v2 and auto capacity

The allocator v2 backend is size-class based rather than object-type based. Node, directory, page-group, name and generic allocation APIs all converge on the same rounded-size class, so there is one **logical size-class pool** rather than separate node/name/generic pools. Internally, each class uses 16 concurrency lanes to avoid a single hot SRW lock; these lanes partition synchronization/slab ownership only and are not business-type pools or permanent per-thread arenas. The local lane is always the fast path. If it has no free object, an atomic available-lane mask lets the allocator reuse partial free capacity from another lane of the same size class before committing a new slab; when no lane has capacity, the scan is skipped entirely. Empty slabs still return immediately to the VM backend. This keeps the memory semantics of one shared size-class pool without putting every allocation behind one global lock. A three-run A/B benchmark against the former 8-lane layout showed the largest gains at high concurrency: at 16 threads, 64-byte alloc/free throughput improved by about 114% and 4 KiB alloc/free throughput by about 209%, while single-thread throughput stayed effectively flat. The extra allocator-state metadata is about 12 KiB per filesystem.

The process-wide control allocation used for `Memfs` itself goes through the same size-class/slab/area machinery; only allocator-state bootstrap reaches the VM backend directly. Small allocations use adaptive slab backing (4 KiB / 8 KiB / 16 KiB / 32 KiB / 64 KiB according to object size); allocations above the small-object threshold use area allocations. `reserved_bytes` is address-space reservation only; `committed_bytes` is the real OS-backed committed memory, and `physical_bytes` is an alias for `committed_bytes`, not a separate source. `live_bytes` is the caller-visible payload/object bytes currently allocated.

The allocator's public pointer-alignment contract is **at least 8 bytes** for every non-NULL returned allocation. This is intentional: the small-object table includes 8-byte and 24-byte classes to avoid wasting space, so promising 16-byte alignment for every slot would be false unless those classes were padded. Internally the first slab payload and area payload header are aligned more strongly (currently 16 bytes), but callers must rely only on the 8-byte minimum unless a specific API documents more.

Zero-initialized typed allocations (`node`, `dir`, `page_group`) keep their existing safety contract. A separate `memfs_allocator_alloc_uninit()` fast path is used only where the caller immediately overwrites the complete requested payload (encoded page blobs, copied security descriptors, temporary path buffers and copied names). This avoids redundant memset traffic without exposing stale bytes to code that expects zero-filled objects. The allocator contention benchmark reports both `zero` and `uninit` modes.

`capacity_auto=true` makes memfs derive its writable allowance from current system memory and allocator backing instead of using a fixed user capacity. `memfs_auto_allowance_bytes()` reports the current allowance, while `used_bytes`, `resident_bytes`, `committed_bytes` and `physical_bytes` remain separate measurements: logical quota, resident payload, and allocator physical backing. The benchmark reports these separately so high-water checks do not confuse allocator backing with logical file usage.

The auto-capacity **growth hot path** keeps a 1 ms cache of the OS available-memory sample. Public allowance/stats APIs remain live queries. One SRW lock protects the complete snapshot (available bytes, gross-commit baseline and timestamp/deadline), including forced refreshes: individually atomic fields with a deadline published last did not prevent mixing an old live snapshot with a new sample. The gross successful-commit counter is captured before the OS query, then all subsequent commitments are debited, even if freed/reallocated regions leave net committed bytes unchanged. The TTL begins before the query; a slow OS call cannot make an old sample look fresh. Near pressure or on a request larger than the allowance, the cache is refreshed after scavenging.

Normal Debug uses the same cache. Only legacy explicit pressure overrides bypass it. `memfs_capacity_snapshot_test` separately compiles the production core with `NDEBUG` plus test-only OS/clock providers, exercising expiry, forced refresh, slow queries, clock failure/rollback, in-query growth, free/reallocate debit, atomic pressure failures, and concurrent publication. These providers are not compiled into the shipping executable. An OS memory sample is an observation, not a reservation against other processes; allocation failures must still be handled.

Runtime diagnostics are opt-in and do not start a sampling thread. `memfs_get_runtime_stats()` returns a **lock-safe approximate aggregate** containing logical used/free bytes, resident bytes, allocator live/reserved/committed/physical bytes, slab/area/cache counts, scavenger totals, and the current auto-capacity allowance plus its 256 MiB hard and 512 MiB soft pressure margins. Allocator shards and scalar counters are sampled sequentially, so under concurrent I/O/allocation the fields can represent slightly different instants; collect stats while the filesystem is quiescent when an exact baseline or exact cross-field equality is required.

For interactive diagnostics:

```powershell
.\build\x64-release\memfs.exe --mount R: --size auto --stats
.\build\x64-release\memfs.exe --mount R: --size auto --stats-json
```

`--stats` prints a stable **format** of `key=value` fields after mount and immediately before shutdown. `--stats-json` suppresses the normal mount banner and emits one JSON object per sample with `type=memfs_stats` and `phase=mounted|stopping`, making redirected stdout suitable for machine parsing. The values follow the same approximate-concurrent semantics described above; the stopping sample is normally quiescent and therefore suitable as an exact cleanup baseline. The API is also available to service/control-plane code without enabling any background sampler.

### Sparse paged files

Files that grow past 4 KiB, or receive a high-offset write, use sparse 4 KiB logical pages:

- one logical group covers 1 MiB (256 pages);
- a group has a 256-bit presence bitmap and a compact pointer vector containing only pages that actually exist;
- top-level group entries are a compact sorted array of {group_index, group*} and are binary-searched;
- very high sparse offsets therefore do not allocate a giant intermediate pointer array;
- absent pages read as zero.

Extending an empty file reserves byte-granular memfs quota but allocates no data pages. The aligned 512-byte AllocationSize exists only at the WinFsp reporting boundary.

Truncation releases encoded pages and empty groups. A file that shrinks below 4 KiB can demote back to the compact tiny representation.

The original whole-file realloc implementation took about 1.4 seconds to append 32 MiB in 64 KiB writes on the current machine. Sparse paged storage reduced the same benchmark to roughly 9 ms.

## Compression

Compression is optional and local to each tiny blob or 4 KiB page. memfs uses Zstd and keeps the compressed representation only when it saves enough bytes to justify the metadata and CPU cost.

Compression is adaptive per file. Repeatedly incompressible pages raise a small score; after the score crosses the skip threshold, paged files only probe one page out of 16 for renewed compressibility. A successful probe lowers the score again. Tiny blobs remain cheap enough to probe on every rewrite.

For 16 MiB of highly compressible repeated data in the current build:

| mode | tracked resident | resident/logical | write time (local run) |
|---|---:|---:|---:|
| raw | 16.03 MiB | 100.195% | ~4.4 ms |
| Zstd | 108 KiB | 0.659% | ~19-31 ms |
| encryption only | 16.13 MiB | 100.781% | ~15.6-16.3 ms |
| Zstd + encryption | 204 KiB | 1.245% | ~11.5-11.7 ms |

Compression is not enabled by default because truly incompressible workloads would otherwise spend CPU without reducing memory.

## Encryption

Encryption is optional and local to each non-zero blob/page. The encoding order is:

1. optional Zstd compression;
2. authenticated encryption.

On CPUs where libsodium reports AES-256-GCM hardware support, new encrypted pages use AES-256-GCM. Otherwise they use XChaCha20-Poly1305. The algorithm is recorded in the page flags and that flag is itself authenticated as AAD, so reads select the decoder from each stored page rather than from the current encoder preference. This also keeps mixed-algorithm pages readable if the preferred encoder changes during a mount.

Every memfs instance creates a random 128-bit mount prefix and keeps the caller/random 256-bit master key for XChaCha. AES-GCM derives a separate mount-specific root key from the master key plus that prefix. Every encoded rewrite then obtains a globally unique monotonically increasing 64-bit sequence. XChaCha combines the 128-bit prefix with the sequence for its 192-bit nonce. AES-GCM uses the sequence in its 96-bit nonce under the independent mount key and derives a new epoch subkey every 2^20 encrypted blobs/pages. Only the 8-byte sequence is stored with each blob/page.

AEAD additional authenticated data binds ciphertext to the node identity, storage/page index (or tiny-blob sentinel), nonce sequence, plaintext size and all codec/algorithm flags. Normal reads therefore detect ciphertext, metadata or algorithm-selector tampering.

The master/XChaCha key, derived AES root key, and one filesystem-wide cached current AES epoch key are held in dedicated in-memory fields and locked with `sodium_mlock` on a best-effort basis. The epoch cache is protected by an SRW lock and only retains the newest epoch; old-epoch reads derive a temporary key on demand instead of growing a key cache. Scratch epoch keys and nonce buffers are explicitly zeroed after use, and all retained keys plus the mount nonce prefix are zeroed/unlocked during teardown.

Encryption protects the stored page representation in the memfs heap. It is not process-memory isolation: plaintext necessarily exists transiently in application I/O buffers and small stack work buffers during reads, writes, compression and decompression.

All-zero pages remain implicit sparse holes and allocate no ciphertext.

## Concurrency

memfs uses WinFsp's FINE operation guard. WinFsp protects namespace operations with its shared/exclusive namespace lock, while I/O to different files can execute concurrently. The FSD continues to synchronize operations on each individual file.

Cross-file capacity and resident accounting use Interlocked atomics rather than a global filesystem lock. The normal file-data path therefore has no memfs-wide mutex.

The core test suite includes concurrent writes to multiple files with compression and encryption enabled.

## Handle lifetime and deletion

WinFsp uses the node pointer as `FileContext`. Open/create increments the node's open count. Delete-on-cleanup removes the node from the namespace, but the node remains alive until the final close.

## Long-run memory drift soak

`memfs_soak_bench` runs a mixed core workload with compression and encryption enabled. Each cycle covers tiny-file create/read/rename/unlink, a 256 KiB large-file write with truncate/regrow and zero-fill verification, and a 64 MiB high-offset sparse write/read/truncate/regrow. Every sample reports logical/resident bytes, allocator live/reserved/committed/physical bytes, process private bytes, slab/area/cache counts, and the final summary reports linear private/committed drift slopes.

The default mode is intentionally short for CI:

```powershell
.\build\x64-release\memfs_soak_bench.exe
.\build\x64-release\memfs_soak_bench.exe --seconds 10 --sample-ms 1000
```

Long soak mode is explicit and accepts 10 through 60 minutes:

```powershell
.\build\x64-release\memfs_soak_bench.exe --soak 10
.\build\x64-release\memfs_soak_bench.exe --soak 60 --sample-ms 5000
```

Before measurement the benchmark warms all workload shapes and codec/crypto paths. At exit it scavenges allocator caches and requires logical used, resident, allocator live objects/bytes, reserved, committed, physical, slab and area state to return to the post-warmup baseline. The private-byte slope is reported separately because Windows/runtime libraries may retain process-private bookkeeping that is not memfs allocator backing.

## Integration test

The integration test mounts a real WinFsp drive and exercises normal Windows file APIs, sparse writes, rename/move/enumeration/delete:

```powershell
& .\tests\integration.ps1 -Exe .\build\x64-release\memfs.exe -Drive R:
& .\tests\integration.ps1 -Exe .\build\x64-release\memfs.exe -Drive R: -ExtraArgs @("--compress")
```

The current test suite has also been run successfully in plain, compression-only, encryption-only and compression+encryption mount modes.

## Source layout

```text
src/
  main.c            command-line mount process
  memfs_core.h      tree/storage/codec API and structures
  memfs_core.c      directory index, sparse data, compression, encryption
  memfs_winfsp.h    WinFsp adapter API
  memfs_winfsp.c    WinFsp callbacks

tests/
  memfs_core_test.c      unit/stress/concurrency/codec tests
  integration.ps1       real mounted-drive integration test
  service-recovery.ps1  SCM abnormal-termination restart/remount integration test
scripts/
  prepare-winfsp-static.ps1 derive/build a static WinFsp runtime matching the signed driver
  memfs-service.ps1         install/start/query/stop/delete wrapper around sc.exe
  verify-deployment.ps1     repeatable official/no-service/private-fallback deployment harness
```

## Planned next steps

- Global security-descriptor interning beyond the current parent/inherited ACL sharing.
- Named streams, reparse points and extended attributes.
- Persistence/snapshot support.
- Password-based key derivation if persistent encrypted images are introduced.
- More rename/delete/open race stress tests.
- Continue profiling unified size-class shard counts, slab sizing and the slab/area threshold under real workloads; do not introduce object-type-specific physical pools.

## Release-candidate acceptance and portable handoff

Run `scripts/verify-release-acceptance.ps1` to record a bounded, fail-closed matrix
for the actual revision; see `docs/RELEASE_ACCEPTANCE.md`. The current CTest
registration includes 20 cases. The lifecycle regression covers shared opens and
asynchronous final Close, which WinFsp FINE does not serialize. A separate short
lifetime lock protects references/orphans without serializing ordinary data I/O.
Security descriptor replacement and borrowed snapshots have compatible guards.

After a passing extended report, create a portable kit with:

```powershell
python .\scripts\package-validation-kit.py --report .agent\<acceptance-run>\acceptance.json
```

The generated kit has a strict manifest and can run the matching Release tests
on another Windows machine without a development environment. Follow
`docs/PORTABLE_VALIDATION.zh-CN.md`; clean-VM installation, Win11 ARM64 execution,
actual OS reboot, publisher signing and distribution licensing remain separate
acceptance gates. The kit does not automatically enable Sandbox, resume or reset
an existing VM, reboot the host, or certify those unexecuted gates.
