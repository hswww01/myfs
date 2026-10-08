# SCPFS validation and delivery

Date: 2026-10-03 (Asia/Shanghai). The current R: cache repair, final executable hash, 13-test suites and actual service acceptance are documented in [CACHE_ACCESS_FIX.md](CACHE_ACCESS_FIX.md). [CACHE_VALIDATION.md](CACHE_VALIDATION.md) retains the earlier notification-cache milestone. The sections below retain historical evidence for the earlier implementation, shared frontend, GUI and native service milestones; their old executable hashes and production process IDs must not be treated as the current package or service state. These are focused implementation and runtime records, not a full Windows filesystem conformance or security audit.

## Deliverables and build

- Source project: `D:\work\fs\scp`.
- Release executable: `D:\work\fs\scp\dist\scpfs-x64\scpfs.exe`.
- Version: 0.1.0; x64; C17; clang-cl and CMake/Ninja.
- Static dependencies: vcpkg `D:\vcpkg`, `x64-windows-static`, libssh2 1.11.1, OpenSSL 3.6.0 and zlib; static CRT; static WinFsp source/library reused from `D:\src\winfsp-memfs-static`.
- Embedded kernel drivers are signed, architecture/version checked and covered by `WINFSP-DRIVER-PROVENANCE.json` in the package. No DLL is included in the package.
- The historical GUI-only Release executable SHA-256 was `9C2E82DC052228E511C1C17EE44C0311E910A164C194B1BEF2FA8013B741EE2C` (5,355,008 bytes). Its milestone did not restart the service: the then-running PID 82124 used the prior executable `F20505BE1A4250CD7F43B909FCEA271F6D07232C39CAA3A29AE309F90B385698`, preserved as `scpfs-before-gui-20261003.exe`. Current delivery and service-state evidence is in CACHE_ACCESS_FIX.md.
- README, architecture/command protocol, third-party notices and exact dependency licenses accompany the delivery. WinFsp's upstream FLOSS exception explicitly concerns DLL linking; the static build does not rely on that exception. Project licensing was not changed or granted on the user's behalf.

## Confirmed acceptance evidence

Commands used for Debug and Release validation:

```powershell
cmake --build --preset x64-debug
ctest --preset x64-debug --timeout 300
cmake --build --preset x64-release
ctest --preset x64-release --timeout 300
```

After the shared GUI layout and output-capture fixes, the final Debug and Release suites each passed **8/8**, with no skipped integration tests or failures. The final runs took 33.16 and 25.67 seconds respectively. They cover help, invalid CLI options, version, normal/delay PE imports, real SSH integration, real WinFsp mount integration, no-argument GUI and native SCM service integration. The SSH test uses a test-only `TMP`/`TEMP` directory under `build/gui-validation-tmp`: the first unredirected run inherited the user's volatile `M:\tmp` and failed to write its temporary probe file with Win32 error 112. The scoped override avoids changing global/user environment or M: contents. Logs are `build/x64-debug/Testing/Temporary/LastTest.log` and `build/x64-release/Testing/Temporary/LastTest.log`.

The GUI test opens the no-argument window and verifies it remains idle, inspects the running GUI process module inventory, fills the native fields from an isolated localhost OpenSSH fixture, launches a real strict host-key/SCP probe, verifies the captured success output in the GUI, and launches an actual mount on X:. It uses key and strict known-host files under a path containing spaces and an existing cache directory whose value ends in a backslash. The test clicks Mount, confirms the GUI-owned temporary unmount action and verifies X: is released. GUI runtime modules are recorded in `RUNTIME-MODULES-GUI-RELEASE.json`; they are the executable plus Windows system/WinSxS modules only, with no third-party runtime DLLs.

The SSH fixture starts a dedicated WSL Ubuntu GNU/OpenSSH daemon with test-only generated keys, an isolated loopback port and unique directories. It verifies actual SCP upload/download byte equality, stat/rename/delete, strict unknown/mismatched host-key rejection and unauthorized-key rejection. Its client key is an actual unencrypted OpenSSH Ed25519 key. Default `HOME/.ssh/id_ed25519`, `USERPROFILE` fallback with `HOME` absent, explicit identity precedence and missing-default-key errors all pass. Source review confirms host verification precedes the only public-key authentication API call; there is no password or keyboard-interactive fallback.

Known-host regressions also cover no-comment LF and CRLF lines, a valid unrelated host before the pinned entry, EOF without a newline, and rejection of a wrong same-host pin. The loader terminates each line span during libssh2 parsing; it does not change host-key algorithms or trust policy.

The final SSH gate also supplies a fixture-owned `OPENSSL_CONF` that activates a nonexistent provider and points `OPENSSL_MODULES` at an empty directory. Both rebuilt configurations still complete the SCP probe, because `OPENSSL_INIT_NO_LOAD_CONFIG` runs before libssh2/OpenSSL use. As a negative control, the earlier packaged binary failed that same assertion with status `0xC0000001`; the regression detects the previously implicit configuration loading.

Real mounted tests verify ASCII and quoted Unicode paths; random reads/writes and truncation; directory and file creation, rename and deletion; independent `Test.txt`/`test.txt` contents, wrong-case rejection, case-only rename and independent deletion; symlink rejection; existing nanosecond atime/mtime preservation on read and payload write; explicit Windows file-time updates; and observed external-writer conflict rejection with the original remote data and local dirty cache/recovery manifest retained.

The mount tests omit `--cache-dir`, supply a fixture-owned `%TMP%`, and verify that SCPFS creates a unique `%TMP%\scpfs\session-{GUID}` directory and its recovery manifest. They inspect the running process's module paths. Earlier IP-only inventories missed Bonjour's `mdnsNSP.dll` loaded through Winsock name resolution on the production hostname. The corrected hostname regression and final production process contain the EXE plus Windows DLLs only, including built-in DNSAPI/IP Helper. The production process inventory contains 35 modules and no Bonjour or dynamic third-party runtime DLL. PE validation independently passes both normal and delay imports. The package includes `RUNTIME-MODULES-RELEASE.json`, and `PRODUCTION-SERVICE-ACCEPTANCE.json` records the production inventory.

The command inbox tests cover Close submission after multiple Flush calls, no command execution at Flush, rename to the exact `.in.txt`, result replacement, containing-directory cwd, combined stdout/stderr, UTF-8 BOM/CRLF input, nonzero exit output, bounded timeout, input removal and the ordinary `.IN.TXT` case variant including immediate deletion. No polling or startup scan is used. The test timeout is shortened to 1500 ms; the product default is 30000 ms and maximum is 540000 ms.

An additional real-mount lifecycle gate passed **100 immediate create/close/read-close/delete iterations**, checking local and remote absence after each iteration, without sleeps. After temporary successful-callback tracing was removed, two standalone fresh Debug mounts passed, followed by the Debug full-suite mount and Release full-suite mount. Test logging uses files so a full stdout/stderr pipe cannot stall a filesystem callback.

The native SCM fixture creates a unique service, installs without `--identity` using its fixture-owned home directory, and checks the captured absolute Ed25519 key path. It verifies automatic LocalSystem startup, global mount access, protected SYSTEM/installer log ACLs, both actual stdout/stderr marker records, identical-install idempotence and rejection of a different configuration. It performs real mounted SCP transfer, poisons only its test SSH session, observes service error 1066 and SCM restart into a fresh PID, then tests stop/start, native uninstall and service absence. The fixture preserves the existing driver and unrelated services; retained mutation state is not replayed. The mount suite also repeats exact `os.utime`/immediate external nanosecond-stat/delete four times and exercises a held metadata handle across rename/recreation, without sleeps or retry-based synchronization of those assertions.

## Production service evidence

The Release `--install` created and immediately started `Scpfs` for `root@cn.tqdream.com`, remote `/`, global R:, command timeout 60000 ms. The invocation omitted `--identity`; ImagePath contains the installing user's resolved absolute `C:\Users\Administrator\.ssh\id_ed25519`, the existing strictly verified known-hosts path and installer SID. SCM configuration is delayed automatic LocalSystem startup, recovery restarts after 1/5/30 seconds followed by no action, reset period 86400 seconds and noncrash-failure recovery enabled. The protected log is `C:\ProgramData\Scpfs\Scpfs.log`, with SYSTEM and the installer only, and contains both redirected diagnostic markers.

The final Release service was RUNNING as PID 82124, with R: visible and remote `/` accessible. A unique directory under remote `/tmp` passed independent `Case.txt`/`case.txt` contents, wrong-case miss, rename/read/delete, explicit representable file times followed by immediate deletion, and an ordinary `.IN.TXT` file. Both direct Close and rename into `.in.txt` produced exact marker output and the containing directory's cwd in `.out.txt`; each input was consumed. All created files and the directory were removed. Evidence is `PRODUCTION-MOUNT-ACCEPTANCE.json`. The protected log and OS-only process inventory also passed on this final process; SCM/runtime/ACL evidence is `PRODUCTION-SERVICE-ACCEPTANCE.json`. Automatic startup is configured; no actual reboot was performed.

## Resolved implementation defects

- Per-open cache handles originally used WinFsp's default stable file-node context. Setting `UmFileContextIsUserContext2=1` selects the required descriptor context and fixes stale-pointer invalid-handle failures on reopen/rename.
- Multiple dispatcher workers could dequeue Cleanup and Open in queue order but acquire the backend lock in the opposite order, making the active-cache guard falsely reject immediate delete. One dispatcher worker preserves processing order while retaining the strict single-cache contract. `scpfs_start(..., 0)` selects one; counts above one are rejected.
- WinFsp's automatic Cleanup last-write hint originally replaced the original remote mtime. Payload-only overwrite/write/truncation now retains snapshot time; explicit SetBasicInfo times still apply.
- Reusing the remote command builder without clearing it originally appended publication to an executed command. Independent builders now publish `.out.txt` correctly; cleanup failures retain their stage and claim/recovery information.
- OpenSSL's implicit environment configuration loading is disabled before crypto initialization. CLI help escapes literal `%TMP%` correctly.
- Hostname lookup now uses Windows DNSAPI A/AAAA queries rather than Winsock namespace providers, preventing the optional Bonjour DLL load without changing machine provider configuration or host-key verification. Heap query state and caller/callback references survive cancellation; DNS and TCP connection share one finite deadline.
- Both products now use the same static frontend for all 31 WinFsp operation wrappers, mounting/dispatcher teardown and native SCM hosting/installation. Original backend contexts and file-context modes are retained; registry locks are not held across backend calls.
- Actual SCM stdout/stderr streams were initially unbound or invalid. The service host initializes CRT streams on NUL after SCM registration, duplicates the protected append-log handle onto their descriptors, checks each operation and verifies actual stdout/stderr records.
- Native SCP installation initially required an explicit identity too early. The installer now resolves the default user key before capturing the internal service arguments; only the internal SCM entry requires the captured explicit paths and SID.
- A no-comment known-host line could lose its final Base64 character because libssh2 examined the delimiter beyond the supplied line span. Temporarily NUL-terminating that span fixes LF/CRLF/EOF parsing without weakening pin checks.
- Every regular-file Open originally downloaded a payload cache, including attribute/time/delete-only handles. Delayed Cleanup of those contexts caused intermittent immediate remote timestamp mismatch and sharing violations after `os.utime`. Existing-file Open now uses granted payload rights to create cache-less metadata contexts; metadata-only SetBasicInfo commits synchronously and reports backend failure. Repeated exact nanosecond time updates followed by immediate remote stat and deletion run without sleeps or test retries.
- Clean metadata contexts can outlive rename/delete. Namespace changes now invalidate affected clean peers so later mutation or inbox processing cannot address a recreated pathname. A real held FILE_WRITE_ATTRIBUTES handle was tested across rename and old-name recreation: SetFileTime on the stale handle fails, and the replacement's remote timestamps remain unchanged after that call and Close. Dirty/recovery contexts remain guarded; Create and the one-payload-cache restriction are preserved.

Focused independent reviews covered backend authentication/rooted command quoting/atomic upload and inbox state, CLI/static build settings, adapter lifecycle and the reused static driver bootstrap. The final lead decisions and consistency boundaries are recorded in `ARCHITECTURE.md`.

## Limits and checks not performed

The supported remote is Linux with GNU tools and OpenSSH. File data is cached as whole files; one regular-file cache is active at a time and the backend/dispatcher is serialized. The tree should have one writer. Fingerprint comparison plus rename is best-effort conflict detection, not distributed compare-and-swap or a remote crash-durable fsync guarantee.

Metadata-only contexts do not own payload caches. Mutation through an old metadata context after namespace change is rejected; reopen the new path. This initial backend does not preserve a live mutable metadata descriptor across rename/delete. Concurrent active payload editing remains unsupported, and unresolved dirty or command recovery state continues to block conflicting operations.

Linux birthtime cannot be preserved by atomic temporary-file replacement. Remote POSIX ACLs are not mapped to persistent Windows ACLs. Memory-mapped I/O, exhaustive Win32/NTFS conformance and large-file throughput were not tested. Production evidence is limited to the configured service and the temporary-directory operations described above.

The shell inbox runs with the configured remote account's permissions; cwd is not a sandbox. Fault injection for network loss after command launch, remote crashes and unknown-outcome recovery was not performed. The implementation preserves claim/cache/recovery state and does not blindly replay commands. Extreme configured operation timeouts/adverse latency within the overall WinFsp IRP budget were not runtime-proven.

Tests reused a compatible already-running WinFsp driver. Fresh-machine embedded-driver installation and driver upgrade were not runtime-tested. No running driver was stopped/replaced and the user's existing M: mount was not restarted.

## Related memfs delivery

The memfs case-sensitivity results below describe an earlier backend milestone, not the current GUI-enabled memfs package. That milestone passed Debug and Release suites at **23/23** and used SHA-256 `E3137FFEA855F5EF4BA981BAEAE006A00D6BBFB53419A17A5EDEB2EF77571BBB`; this is historical evidence only. The current GUI-enabled memfs package identity and its 24-test evidence are recorded in the memfs package provenance.

`memfs_old.exe` was preserved. The running MemfsC/M: remains the user's earlier process, PID 68440; case-sensitive behavior applies to new mounts started with the new executable. The dirty memfs checkout was preserved, and its package provenance records that state and its diff hash rather than claiming a clean-tree packaging run. No commit or push was performed.




