# SCPFS

SCPFS mounts an existing Linux directory as a Windows filesystem through WinFsp. C17 code uses the installed WinFsp user-mode API and libssh2. SCP transfers file contents; SSH commands using GNU/Linux tools read and update remote metadata and directory entries. The configured server must provide OpenSSH, GNU `find`, `stat`, and the standard file utilities.

WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos. See the [WinFsp project](https://github.com/winfsp/winfsp) and the accompanying `License.txt` for license terms.

The static shared frontend in `D:\work\fs\frontend` owns versioned callback forwarding for all 31 WinFsp operations, filesystem mount and dispatcher lifetime, native SCM service plumbing, and protected service logging. SCPFS supplies its operation table, volume settings, create-failure recovery hook, cache, and SSH backend. The release build statically links WinFsp and the SSH dependencies; it embeds the version-verified, signed x64 and ARM64 WinFsp kernel drivers and does not extract or load a WinFsp DLL. It uses an already installed compatible WinFsp driver when available. It never updates or stops a running driver. The SDK/static library source and standard WinFsp installation are required to build.

The dispatcher runs four callback workers; remote lookups and downloads run outside the adapter lock, and an Open or Rename that races a Cleanup still queued on another worker waits briefly for it. SCPFS allows one cached payload handle per remote file. Opens with only metadata rights use no payload cache, and their explicit metadata updates are committed synchronously. A metadata handle invalidated by rename, delete, or consumed inbox input keeps its saved information for queries but cannot mutate the old path or a replacement object. Before initializing libssh2, SCPFS disables OpenSSL configuration autoload so ambient `OPENSSL_CONF` and `OPENSSL_MODULES` provider settings do not alter its SSH crypto setup.

## Build

The presets use clang-cl, Ninja, vcpkg at `D:\vcpkg`, the `x64-windows-static` triplet, and the WinFsp static library in `D:\src\winfsp-memfs-static`. Static C runtime linkage is enabled. CMake verifies the embedded signed drivers' provenance, architecture, and matching version. The PE import gate rejects non-Windows DLLs in both normal and delay-import tables.

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --timeout 180

cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release --timeout 180
```

The vcpkg manifest installs static libssh2, OpenSSL, and zlib. The SSH integration test starts a dedicated OpenSSH server in WSL Ubuntu with generated test-only Ed25519 client and RSA host keys and an isolated directory under `/tmp`; it checks a real SCP upload/download round trip, byte equality, rename/delete, unknown and mismatched host-key rejection, unauthorized-key rejection, default identity lookup through test-only `HOME` and `USERPROFILE` profiles, and strict host verification across no-comment LF/CRLF, unrelated preceding host records, and files without a final newline. The mount integration test exercises a real WinFsp mount using `localhost` when an unused drive letter is available. It records loaded module paths after hostname resolution and checks they are limited to the Windows directory and the tested executable. The GUI integration test opens the no-argument configuration window without connecting, then fills the form, mounts a local SSH fixture and stops only that window's mount. GUI and mount integration tests return CTest's skipped status if their reserved drive is already occupied.

## Configuration window

Run `scpfs.exe` without arguments to open the native configuration window. It starts idle: the SSH host and account are blank, and no network connection or mount begins until an action is selected. Enter the remote root and mount drive, then choose the SSH private-key file and strict `known_hosts` file. The key and pin-file fields start with absolute paths under the launching Windows user's profile, so an elevated service action keeps the same credential paths. SCPFS sends the key path to the child process but never puts private-key contents in logs or command arguments.

The **测试连接** action verifies the pinned SSH host and performs an SCP upload/download round trip with a random temporary file under the configured remote root. **挂载** starts a temporary mount owned by that window; **卸载临时挂载** confirms and stops only that window's mount. Service name and log path are configurable for **安装并启动服务** and **卸载服务**. GUI service actions request elevation when needed. The GUI command-timeout field starts at 60000 ms; the command-line default remains 30000 ms. The cache field may be left blank to use the normal temporary cache location; a custom cache directory must already exist.

## Probe a connection

Use an OpenSSH `known_hosts` file with the server key already verified out of band. SCPFS uses public-key authentication only. If `--identity` is omitted, it reads `%HOME%\.ssh\id_ed25519` when `HOME` is set; otherwise it uses `%USERPROFILE%\.ssh\id_ed25519` (falling back to the Windows profile known folder). A missing default key is an error. An explicit `--identity` takes precedence. The key must be readable and unencrypted; SSH account passwords are not accepted.

```powershell
build\x64-debug\scpfs.exe --probe `
  --host files.example.net --user files --port 22 `
  --remote-root /srv/files `
  --known-hosts $env:USERPROFILE\.ssh\known_hosts
```

`--probe` refuses unknown or changed host keys. It creates a random temporary file beneath the configured root, transfers it with SCP, checks the downloaded bytes, renames and deletes it, and attempts cleanup if an intermediate step fails. Run it against a directory where that account may create and remove files.

## Mount

```powershell
build\x64-debug\scpfs.exe --mount R: `
  --host files.example.net --user files --port 22 `
  --remote-root /srv/files `
  --known-hosts $env:USERPROFILE\.ssh\known_hosts
```

Press Ctrl+C to stop the mount cleanly. The connection requires an explicit host, account, absolute remote root, and known-hosts file. Use `--timeout-ms` to adjust the finite per-operation timeout. `--cache-dir` can point to an existing writable directory for local file contents; without it, SCPFS creates a unique session directory under `%TMP%` (falling back to the Windows temporary directory when `%TMP%` is unset).

## Install as a Windows service

Run `--install` from an elevated terminal with the same mount and SSH settings. SCPFS first runs its strict host-key and SCP round-trip probe, then registers the current executable as the `Scpfs` LocalSystem service, configures delayed automatic startup and bounded SCM restart actions, and starts it. For example:

```powershell
build\x64-release\scpfs.exe --install --mount R: `
  --host cn.tqdream.com --user root --port 22 `
  --remote-root / `
  --known-hosts $env:USERPROFILE\.ssh\known_hosts `
  --command-timeout-ms 60000
```

When `--identity` is omitted, installation resolves `%HOME%\.ssh\id_ed25519` when `HOME` is set or `%USERPROFILE%\.ssh\id_ed25519` otherwise, then stores that absolute path in the SCM configuration.

The service stores absolute credential paths and the installing user's SID in its configuration. LocalSystem must be able to read both the private key and known-hosts file; the private-key contents are never put in the service command line or copied by SCPFS. The mount is global and grants access to SYSTEM plus the installer SID. Service diagnostics go to a protected log under `%ProgramData%\Scpfs`; `--log-file FILE` selects another absolute log path. Use `--service-name NAME` when running an isolated test service; the default production name is `Scpfs`. Repeating `--install` with identical settings is safe; different settings for an existing name are rejected without stopping or rewriting it.

```powershell
build\x64-release\scpfs.exe --uninstall
```

Uninstall stops and removes only that named SCPFS user-mode service. It does not remove the WinFsp driver, cache/recovery data, credentials, or remote files. A fatal SSH transport/protocol failure ends the service so SCM can start a fresh process; pending cache data is preserved for manual recovery and mutations are not replayed. The actual reboot path depends on Windows service startup and was not exercised by the test suite.

## Remote command inbox

Closing a file whose exact remote name is `.in.txt`, or renaming a file to that exact name, submits its UTF-8 contents as a shell script to the configured Linux account. Commands run with the containing remote directory as their working directory. After the server has safely claimed the input, SCPFS removes `.in.txt` and writes combined standard output and standard error to the sibling `.out.txt`. A nonzero exit or timeout still produces output; the exit status is reported in the mount process log. Set `--command-timeout-ms` to change the default 30-second bound (maximum 540 seconds).

The inbox accepts UTF-8 with LF or CRLF line endings and an optional UTF-8 BOM; empty input is a valid empty script. NUL bytes, invalid UTF-8, bare CR, or content larger than 1 MiB is consumed without execution and receives an explanatory `.out.txt`. Output is capped at 8 MiB with a truncation marker. If the SSH result is ambiguous after the server claims the script, SCPFS does not retry automatically; inspect the cache session's `recovery.manifest.txt` and any retained claim path before deciding what to run again. Treat this inbox like remote shell access: only mount roots and provide credentials that you intend to authorize for command execution.

## Read cache and server change notifications

Read caching is always enabled. The default `--cache-max-mib 0` means no payload capacity limit; positive values (1..16384 MiB) set a limit. The configuration window's **读取缓存上限** field uses the same meaning and starts at zero. Cached file attributes, directory lists and clean file contents are reused across requests and close/reopen cycles during the current mount, without a time-based expiry. The metadata index retains its own 64 MiB / 131072-entry memory bound. Least-recently-used clean entries can be evicted when an applicable bound is reached; active working files and failed-write recovery files are separate from those bounds. An unavailable or failed cache never substitutes incomplete data for a remote read.

A separate, strictly verified public-key SSH connection runs the embedded Linux notification helper with Python 3. It uses only Python's standard library and Linux inotify, requires no installed daemon and opens no extra server port. The helper answers stats, directory listings, reads and writes of files up to 8 MiB, and mkdir/rename/delete/attribute changes in one round trip each, and it watches the ancestors of every path it answered about (not the whole tree). Each change it then sees is reported for that path only, so a busy log directory elsewhere on the server does not flush the cache. Repeated hits need no SSH round trip. Missing Python, unsupported monitoring or a lost connection fall back to normal remote operations until monitoring recovers; all other remote commands share one persistent shell channel.

Content and namespace changes drop the affected entries (and the parent listing); attribute-only changes keep cached file contents. Local mutations drop their own paths immediately, and an inbox command clears the cache even when command completion fails or is uncertain. `.in.txt` and `.out.txt` use fresh reads. Reading a file may advance its remote access time, like any other Linux reader.

The service logs its actual cache session directory at startup. A LocalSystem service normally uses `C:\Windows\Temp\scpfs\session-{GUID}` when no cache directory is specified, even when the interactive user's `%TMP%` is elsewhere. Retained clean payloads are named `read-{GUID}.cache`; `file-*.cache` are per-open working copies. The cache is private to the current mount and is discarded at a normal stop. Consult the protected service log to locate the current session rather than selecting an old directory by name.

Notifications provide eventual invalidation, not a transaction spanning Windows and Linux. Existing open handles retain their snapshots. Monitoring is limited to supported native Linux filesystems; network and pseudo-filesystem paths bypass read caching, as do unsupported cross-device/symlink watch paths. Inotify cannot report every possible mutation, including some mmap changes or mount replacement. Remounting discards the session cache. See [CACHE_ARCHITECTURE.md](docs/CACHE_ARCHITECTURE.md) for the protocol, failure handling and validation boundary.

The 2026-10-03 root `/` cache repair and actual R: results are recorded in [CACHE_ACCESS_FIX.md](docs/CACHE_ACCESS_FIX.md), including the current Release hash and before/after observations.

## Consistency and recovery

SCP has no random-write or compare-and-swap operation. SCPFS downloads each regular file to a local cache, services Windows reads/writes against that cached copy, and commits it through an atomic remote sibling upload when flushed or closed. It allows one cached open handle for a regular file at a time and assumes this mount is the only writer of its remote tree. External concurrent writers can be detected from the saved mode, size, nanosecond modification time, device, and inode before replacement, but the check and rename are not a distributed transaction. Do not use the mount for multi-client concurrent editing or depend on remote crash-durable `fsync` semantics.

Cache session directories are named `session-{GUID}`. A failed dirty commit keeps its `file-*.cache` file and appends the remote path, cache path, observed snapshot, operation, and status to `recovery.manifest.txt`. The mount prints its session path at startup. If a close-time commit fails, inspect that manifest and preserve the named cache file before clearing temporary files. To recover manually, verify the remote path and account, then copy the cache file to that destination with a trusted SCP client; take any needed remote backup first. `%TMP%` is temporary storage and is not guaranteed to survive cleanup tools, sign-out, reboot, or disk failure, so save the cache file elsewhere when recovery matters.

Linux names are case-sensitive. Symlinks, special files, traversal, alternate streams, control characters, and components that Windows cannot represent are rejected. The configured remote root must exist and be an absolute directory. Ancestor validation cannot prevent a remote account from concurrently replacing a path while an operation is underway.

When the remote server supplies device and inode values, SCPFS uses them for the Windows file ID. Otherwise, it generates a synthetic ID from the path; that fallback remains stable for an open handle but can change after the file is closed and reopened. Existing-file content writes and truncation preserve the remote access/modification-time snapshot taken when the file was opened; explicit Windows `SetFileTime` updates are applied after upload. New-file timestamps come from the local cache file. Windows time updates have 100-nanosecond resolution, while unchanged Linux timestamps are retained at nanosecond resolution. Linux birth time is not preserved by the temporary-file-and-rename upload model. Timestamp updates require GNU `touch` after the SCP transfer.
