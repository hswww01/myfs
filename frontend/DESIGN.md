# Shared filesystem frontend

Decision date: 2026-10-02. Updated: 2026-10-03. Status: shared frontend, native service lifecycle and production SCP runtime accepted for the tested scope.

## Objective and confirmed facts

The user requests a shared frontend including WinFsp file-operation dispatch, with separate memory and SCP storage backends. Both programs must create and immediately start an automatic Windows service through their own `--install` command. They must remain static clang-cl C17 executables with only operating-system DLL dependencies. The existing MemfsC service and M: volume must remain running during integration and tests.

The existing memfs callbacks use stable MemfsNode contexts. SCPFS uses per-open descriptors, `UmFileContextIsUserContext2=1`, and exactly one dispatcher worker to preserve close/open ordering. These are backend contracts and must survive the refactor unchanged. Fake WinFsp objects in memfs state tests use `UserContext` directly. A poisoned SCP SSH session currently produces operation errors without stopping its dispatcher; service health therefore needs an explicit transport-failure signal.

## Accepted boundary

Build `fs_frontend` as a static library from this directory into both programs. Its versioned, size-checked C header hosts WinFsp creation, mounting, typed callback forwarding, dispatcher status and shutdown, plus SCM controls, logging, native installation and uninstallation. Product CLI parsing and storage operations remain backend-specific. This is an internal frontend contract; it does not introduce a new storage protocol or reinterpret existing file contexts.

Keep `FSP_FILE_SYSTEM.UserContext` equal to the backend's original context. Find a frontend instance through a registry keyed by the WinFsp object. Forward every supported non-null operation with unchanged arguments; preserve unsupported null callbacks and reject nonzero reserved/unknown slots. Never hold the registry lock during a backend callback. Register before dispatcher startup. Stop and join the dispatcher, delete the WinFsp object, and only then unregister, while the backend context remains alive. `DispatcherStopped` may notify the backend observer before publishing the common result and event.

Copy volume parameters unchanged. Preserve memfs node semantics, guard strategy, worker configuration and callback return behavior. Preserve SCP descriptor semantics, case sensitivity, one-worker constraint, dirty-cache handling and command-trigger rules. Let a product-provided create-failure resolver choose its existing driver recovery statuses and error mappings. The frontend must never stop or replace a loaded driver supporting another volume.

## Service behavior

The shared service host owns SCM registration, status/checkpoints, stop events, final error reporting and protected logs. Its product callback constructs the backend, mounts and starts it, then reports RUNNING. It waits for stop, dispatcher termination and any backend fatal-event signal before orderly destruction. An unexpected dispatcher or transport termination reports a nonzero service failure. There is no in-process reconnect or automatic replay of uploads, namespace mutations or command submissions.

Installation uses the absolute current executable and correctly quoted exact arguments. Create a LocalSystem automatic service, configure delayed automatic startup and bounded SCM recovery, then start it. Existing services are accepted only when the executable, complete arguments, account, automatic-start type and recovery policy match; a different configuration is rejected without stopping or rewriting it. Uninstall verifies the named service is an own-process service registered to the currently executing binary, stops it within a bounded wait, then deletes that registration. It does not remove drivers, cache/recovery data, SSH credentials or another product's service. A moved installation must be uninstalled using its registered executable path.

Each product resolves an absolute default log path for `--service` as well as `--install`, so existing manual service command lines without `--log-file` remain supported. The shared host requires a protected log and also appends backend stdout/stderr diagnostics there.

## Native configuration window

The shared static library also exposes the internal, versioned `fs_frontend_gui.h` API. A product provides its localized field schema and a callback that maps a selected action and a snapshot of field values to existing CLI argument tokens. The common window owns native controls, file and directory pickers, child-process creation, stdout/stderr capture, and action status. Product CLI parsing remains authoritative; the GUI adds no storage or transport behavior.

An empty command line opens the window, and `--gui` is the explicit route used by the elevation handoff. Service actions requested from a non-elevated window start the same executable with the Windows runas verb, `--gui`, the selected action, and the current form values. The elevated process restores those values into the same schema before running the action. No action starts automatically on ordinary startup, and the GUI never writes field values to persistent configuration. The internal action handoff is issued only in response to a confirmed service button click.

Each temporary mount is a hidden child process with captured stdout/stderr and a unique per-session `Local\FSF-GUI-{GUID}` stop event. Stop, Unmount, and closing a busy window signal that event and wait for the child to finish normal cleanup; the UI never forcibly terminates a child. The unmount button is disabled unless this window owns a running mount. A timer reads bounded output chunks and checks process completion without blocking the window. Action timeouts update status but do not abandon or terminate a still-running child. The mounted status appears only after the child emits its successful mount banner. Unmount and service removal use native confirmations with the default button set to No; products may provide a data-loss warning for their temporary volume.

For stable UI automation, child controls use IDs 1000+i (field inputs), 2000+i (action buttons), 3000+i (browse buttons), 4000 (fallback Stop), 5000 (status), and 5001 (captured output), where i follows schema/action order. The reusable argv builder exposes append, indexed-read, and Windows command-line construction helpers so product tests can verify difficult quoting cases without duplicating the implementation.

GUI acceptance is bounded to native no-argument launch and field validation, actual temporary mounts on unique free drives with graceful child shutdown, action-builder/Windows-argv round-trip tests, Debug and Release suites, static import/module gates, and visual review at supported DPI and window sizes. Existing M: and R: services are not test targets.

Memfs native installation rejects `--key-hex` and `--key-env`: a plaintext encryption key must not be persisted in SCM ImagePath, and the installing user's environment is not the LocalSystem environment. Existing encrypted console/manual-service modes remain supported. Protected service credential storage is outside this change.

SCP production configuration is `root@cn.tqdream.com`, remote `/`, global R:, and command timeout 60000 ms. Resolve the installing user's default identity and known_hosts to explicit absolute paths before installation because LocalSystem has a different home directory. `--install` accepts an omitted identity; the internal `--service` entry requires the captured absolute identity. Preserve host-key verification and public-key-only authentication. Grant mounted-file and log access to SYSTEM and the installing user's validated SID; never grant Everyone access to the authenticated root account. No private-key contents are printed or copied into the service command line.

On the first poisoned SCP session, set a manual-reset failure event and expose its read-only NTSTATUS. A fresh SCM-started process creates a new backend; retained caches are recovery artifacts and are not replayed automatically. Boot ordering is handled by delayed startup and SCM failure actions, not by mutation retries.

## Alternatives and limits

A service-only shared wrapper was rejected by the user's explicit request to share WinFsp operations too. A new universal node/storage abstraction would change working backend ownership and conflict behavior, so this implementation forwards the existing typed WinFsp operations instead. No runtime DLL, driver service rewrite, authentication fallback or remote helper installation is introduced.

Acceptance requires both Debug and Release builds and tests, actual isolated WinFsp mounts for each backend, isolated native SCM install/start/stop/uninstall checks, static import/module checks, and actual production SCP native installation plus read-only root access. Test services use unique names and free drive letters. A configured automatic startup type is evidence of configuration, not evidence of a reboot. A focused frontend review is not a full project audit.

## Ownership

- Design worker: shared header and frontend implementation, narrow SCP backend health signal.
- SCP worker: SCP adapter, CLI, CMake, service fixture, documentation and package.
- memfs worker: memfs adapter, CLI, CMake, isolated service tests, documentation and package.
- Coordinator: architecture decision, integration review, production installation, evidence and limits.

The decision follows the compact Luna briefing covering callback ownership, registry lifetime, volume context modes, service status, ACLs and backend poisoning. The separate reviewer slot was unavailable; the coordinator records and enforces this bounded decision, with independent cross-worker review and runtime validation still required.

## Integration evidence and final DNS boundary

The shared library forwards all 31 operations supported by the reused WinFsp interface. Both product adapters retain their original backend context and file-context modes. Focused independent review and real native SCM fixtures cover actual stdout/stderr logging, identical-install idempotence, mismatched-install rejection, bounded stop/uninstall and preservation of the loaded driver. Memfs Debug and Release each passed 23/23 tests at the earlier backend milestone. SCP final Debug and Release each pass 8/8 with no skips, including the no-argument GUI fixture.

Historical production SCP backend/service acceptance used executable SHA-256 `F20505BE1A4250CD7F43B909FCEA271F6D07232C39CAA3A29AE309F90B385698`; that image remains mapped by the still-running `Scpfs` service, PID 82124. Its original strict SSH/SCP probe and native install/start passed without an explicit identity, and R: remained visible to the installing user. A unique temporary remote directory passed case-sensitive create/read/rename/delete, explicit time update followed by immediate delete, ordinary `.IN.TXT`, and both Close- and Rename-triggered `.in.txt` execution with correct cwd and `.out.txt`; the test files and directory were removed. Separately, the published GUI-enabled SCP executable is SHA-256 `9C2E82DC052228E511C1C17EE44C0311E910A164C194B1BEF2FA8013B741EE2C` (5,355,008 bytes); its final Debug and Release suites each passed 8/8, including actual GUI probe output capture and temporary mount start/graceful-stop. This GUI build was not installed into or restarted as the production service. The existing MemfsC/M: process, PID 68440, was preserved.

The production hostname path exposed an additional dependency: Winsock `getaddrinfo` loads a registered Bonjour namespace-provider DLL on this machine. Direct and delay PE imports and an IP-only module fixture had not detected that runtime load. Replace only hostname resolution with built-in Windows DNSAPI A/AAAA queries and numeric IPv4/IPv6 parsing. Preserve the original SSH hostname for strict host-key checks, use the Windows DNS client/cache/hosts behavior, share a finite deadline with TCP connect, and retain asynchronous query storage until completion even after cancellation. No namespace-provider registry or system installation is changed. The module regression must connect using a hostname, and the final production process must also be inventoried.

The corrected hostname fixture and final production process contain the tested EXE plus Windows DLLs only. The production inventory contains 35 modules, with no Bonjour, WinFsp, libssh2, OpenSSL, zlib or dynamic MSVC runtime DLL. Windows DNSAPI/IP Helper are explicit OS imports. Query lifetime/cancellation and the narrow metadata-only/stale-context ownership change received independent read-only review; exact timestamp and held-metadata rename/recreate regressions are included in the real mount suite. `D:\work\fs\scp\docs\PRODUCTION-SERVICE-ACCEPTANCE.json` and `PRODUCTION-MOUNT-ACCEPTANCE.json` record current hash, SCM/runtime/ACL and filesystem evidence.

The protected service log redirects actual CRT stdout/stderr descriptors after the SCM handshake. It first establishes valid CRT streams on NUL, then duplicates the protected append handle; it checks each initialization and emits verified stdout/stderr markers. Starting `--service` interactively still reports errors to the console. Automatic-start configuration and SCM recovery are validated; no reboot was performed.

