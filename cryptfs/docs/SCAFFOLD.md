# 构建布局与共享前端

最初不含源码的脚手架已替换为实际产品构建目标。Debug 和 Release presets 使用 clang-cl C17、静态 CRT、vcpkg `x64-windows-static` triplet、libsodium 和 zstd。项目不再使用 `CRYPTFS_BUILD_PRODUCT` 门控。实际验证结果记录在 `VALIDATION.md`；仅有源码或配置并不代表文件系统已通过验收。

| 源文件 | 职责 |
| --- | --- |
| `src/main.c` | CLI、原生 GUI 字段定义、密码输入和进程生命周期 |
| `src/cryptfs_backend.c` | 将 WinFsp 回调映射到存储层 API |
| `src/cryptfs_store.c` | 格式解析、对象图、WAL、持久化命名空间/数据和整理 |
| `src/cryptfs_crypto.c` | libsodium 和 zstd 辅助函数 |
| `src/cryptfs_format.h` | 序列化偏移及边界定义 |
| `src/cryptfs_driver.c` | 内嵌签名 WinFsp 驱动的启动逻辑 |

项目链接 `../frontend` 中的可复用前端。其生命周期 API 位于 `include/fs_frontend.h`，包括 `FSF_WINFSP_CONFIG` 以及 create/object/mount/start/stopped-event/dispatcher-result/stop/destroy 等操作。WinFsp 回调会转发到 CryptFS 上下文。原生 GUI 字段定义使用 `include/fs_frontend_gui.h` 和 `fsf_gui_run`。

GUI ABI 仍为版本 1。新增的 `FSF_GUI_FIELD_PASSWORD` 会创建遮罩输入框；`fsf_gui_argv_set_stdin` 会复制并保存有长度上限的密码数据。启动器只传递显式选定的句柄，并清除其拥有的密码缓冲区。重新启动 GUI 时，不会从命令行参数恢复密码。现有 memfs/SCPFS 字段定义继续使用相同的公开布局。

静态 WinFsp 复用 `D:/src/winfsp-memfs-static` 及其中的 Debug/Release 库。本项目不会克隆或重新构建驱动。CMake 会嵌入版本匹配的签名 WinFsp 2.1 x64 和 ARM64 SYS 资源，并通过 `scripts/verify-winfsp-drivers.ps1` 和 `scripts/provenance-common.ps1` 检查来源。检查要求架构正确、签名有效，且签名者为 Windows Hardware Compatibility Publisher。最终可执行文件是 Windows x64；包含 ARM64 驱动资源并不意味着程序本身是 ARM64 构建。

实现参考了现有 memfs WinFsp 适配器、CLI/GUI 和 zstd/libsodium 路径，以及 SCPFS 的静态链接和驱动启动方式。持久化格式和恢复协议见 `ARCHITECTURE.md`、`FORMAT.md`。

压缩和加密实现参考 `D:/work/memfs/src/memfs_core.c`：数据块编码器使用 ZSTD 压缩，无法压缩时回退到原始编码；加密负载路径支持 libsodium XChaCha20-Poly1305。CryptFS 使用相同的库，并先压缩、后加密。持久化容器还需要密码派生密钥封装、带认证的命名空间页、WAL 恢复和支持位置迁移的页面认证；这些机制实现在 CryptFS 存储层中，并非照搬易失性 memfs 的存储模型。
