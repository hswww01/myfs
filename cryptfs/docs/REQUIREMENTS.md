# CryptFS requirements and implementation scope

Date: 2026-10-03 (Asia/Shanghai).

The user requested a new Windows filesystem in `D:\work\fs\cryptfs`, reusing the existing frontend in `D:\work\fs\frontend`. It must encrypt and compress persistent filesystem data inside one container file, allocate sparsely, grow with writes and reclaim storage as files shrink or disappear. The user selected password unlocking and background automatic compaction that also shortens the container file.

The build uses C17 and clang-cl, with external dependencies provided by vcpkg at `D:\vcpkg`. Follow the existing products' static-runtime and operating-system-DLL delivery pattern. Preserve the existing memfs and SCPFS checkouts, credentials and services; use isolated test files and unused drive letters. No commit or push is authorized.

The reusable frontend owns WinFsp forwarding and mount/dispatcher lifetime. The new backend owns the persistent namespace, data blocks, authenticated container format, allocation, transactions, recovery and compaction. Passwords must not appear in process command lines, logs, service registration or ordinary files. The no-argument configuration interface needs a masked password field and a secret-safe child input path if it uses the existing launcher.

Because this is a new encrypted persistent format, implementation followed a focused architecture/security decision after the read-only Luna investigation. The disk-format and transaction rules were recorded in ARCHITECTURE.md before backend implementation. Key acceptance gates are authenticated rejection, crash recovery, sparse allocation, compression, background EOF shrink, actual WinFsp CRUD and lifecycle tests, GUI password handling, Debug/Release builds and runtime dependency verification. Final evidence and untested limits are recorded in VALIDATION.md.

Service auto-unlock, password changes, cross-platform readers, NTFS feature parity and multi-process container access were not requested. Their inclusion or limits must be explicit in the implementation design and final validation record.
