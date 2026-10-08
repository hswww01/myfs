# Build layout and shared frontend

The initial source-free scaffold has been replaced by product targets. Debug
and Release presets use clang-cl C17, static CRT, vcpkg x64-windows-static,
libsodium and zstd. There is no CRYPTFS_BUILD_PRODUCT gate. Actual validation
is recorded in VALIDATION.md; source presence and configuration alone are not
working-filesystem acceptance.

| Source | Role |
| --- | --- |
| src/main.c | CLI, native GUI schema, secret input and process lifecycle |
| src/cryptfs_backend.c | WinFsp callbacks mapped to the store API |
| src/cryptfs_store.c | Parser, graph, WAL, persistent namespace/data and compaction |
| src/cryptfs_crypto.c | libsodium and zstd helpers |
| src/cryptfs_format.h | Serialized offsets and bounds |
| src/cryptfs_driver.c | Embedded signed WinFsp driver bootstrap |

The project links the reusable frontend in ../frontend. Its lifecycle API is
include/fs_frontend.h: FSF_WINFSP_CONFIG and create/object/mount/start/
stopped-event/dispatcher-result/stop/destroy. WinFsp callbacks forward to the
CryptFS context. Native GUI schemas use include/fs_frontend_gui.h and
fsf_gui_run.

The GUI ABI remains version 1. Additive FSF_GUI_FIELD_PASSWORD creates a masked
edit control; fsf_gui_argv_set_stdin stores a copied, bounded secret blob. The
launcher passes only explicitly selected handles and wipes owned secret
buffers. Passwords cannot be restored from relaunch command-line values.
Existing memfs/SCPFS schemas continue to use the same public layout.

Static WinFsp reuses D:/src/winfsp-memfs-static and its Debug/Release archives.
This project does not clone or rebuild a driver. CMake embeds matching signed
WinFsp 2.1 x64 and ARM64 SYS resources and checks provenance using
scripts/verify-winfsp-drivers.ps1 and scripts/provenance-common.ps1. The checks
require correct architecture, valid signatures and the Windows Hardware
Compatibility Publisher signer. The executable is Windows x64; the ARM64
resource does not make it an ARM64 build.

References are the existing memfs WinFsp adapter, CLI/GUI and zstd/libsodium
paths, plus SCPFS static linkage and driver bootstrap. The persistent format
and recovery protocol are documented in ARCHITECTURE.md and FORMAT.md.

The compression and encryption reference is `D:/work/memfs/src/memfs_core.c`:
its block encoder uses ZSTD compression with raw fallback, and its encrypted
payload path supports libsodium XChaCha20-Poly1305. CryptFS uses the same
libraries and the compress-before-encrypt order. A persistent container also
needs password-derived key wrapping, authenticated namespace pages, WAL
recovery and relocation-aware page authentication; those are implemented in
the CryptFS store rather than copied from the volatile memfs storage model.
