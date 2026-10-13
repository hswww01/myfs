# Windows 文件系统项目集

本仓库包含一个可复用的 WinFsp 前端，以及三个以 C17 实现的 Windows 文件系统：内存盘 `memfs`、SSH/SCP 远程文件系统 `scpfs` 和加密压缩容器文件系统 `cryptfs`。它们共用配置界面、WinFsp 操作转发和 Windows 服务生命周期；存储、远端访问和容器格式分别由各自后端负责。

## 项目

| 目录 | 项目 | 用途 | 数据位置 |
| --- | --- | --- | --- |
| [`frontend/`](frontend/) | 共享前端 | 配置界面、WinFsp 回调转发、挂载生命周期和服务支持 | 不保存文件数据 |
| [`memfs/`](memfs/) | MemFS | 可配置容量的高速内存文件系统，支持稀疏文件、压缩和可选加密 | 内存；卸载或进程退出后数据丢失 |
| [`scpfs/`](scpfs/) | SCPFS | 通过 SSH 访问 Linux 目录，以 SCP 传输文件内容，并提供本地读取缓存和远端变更通知 | 远端服务器 |
| [`cryptfs/`](cryptfs/) | CryptFS | 单文件稀疏容器，按块压缩并认证加密，支持后台整理和收缩 | 本地容器文件 |

### 选择文件系统

- 需要临时高速盘、可以接受卸载后数据消失：选择 **memfs**。
- 需要把 Linux 主机上的目录映射为 Windows 盘符：选择 **scpfs**。它仅支持 SSH 公钥认证并要求验证服务器主机密钥。远程目录中的 `.in.txt` 会在关闭或改名提交时作为命令脚本执行；请只挂载你愿意授予命令执行权限的远端目录。
- 需要把数据保存在本地单文件容器中，并在容器内加密和压缩：选择 **cryptfs**。密码遗失无法恢复；同一个容器同一时间只能由一个进程打开。

## 构建环境

项目面向 Windows，使用 C17、CMake、Ninja 和 clang-cl。构建需要 Visual Studio C/C++ 工具、Windows SDK、WinFsp 和 vcpkg 静态依赖。各子项目独立配置和测试；仓库根目录没有统一的 CMake 构建目标。

本机配置的 presets 使用以下路径：

- vcpkg：`D:\vcpkg`
- 匹配版本的静态 WinFsp 源码/库：`D:\src\winfsp-memfs-static`
- 共享前端：`D:\work\fs\frontend`

因此，在其他位置克隆时，需检查并按本机环境调整各子项目的 `CMakePresets.json` 和 WinFsp/共享前端路径。WinFsp 版本、静态用户态库和嵌入的签名驱动必须相互匹配。

## 构建与测试

在 PowerShell 中进入对应子项目目录，分别配置、构建和运行测试：

```powershell
# 内存文件系统
Set-Location D:\work\fs\memfs
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug

# SSH/SCP 文件系统
Set-Location D:\work\fs\scpfs
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --timeout 180

# 加密容器文件系统
Set-Location D:\work\fs\cryptfs
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --timeout 900
```

发布构建将 `x64-debug` 替换为 `x64-release`。`scpfs` 的 SSH、挂载、GUI 和服务集成测试需要相应的 WSL/OpenSSH、WinFsp、空闲盘符等条件；测试可能按 CTest 规则跳过不具备条件的集成项。`cryptfs` 的存储回归会反复启动子进程模拟事务中断，Debug 测试耗时较长。

## 目录结构

```text
frontend/   共享 WinFsp、GUI 和服务前端
memfs/      易失性内存文件系统
scpfs/      SSH/SCP 远程文件系统
cryptfs/    加密压缩容器文件系统
```

各项目的命令行参数、配置界面、数据格式、恢复行为和已知限制，以对应目录的 README 与 `docs/` 文档为准：

- [MemFS 使用与构建](memfs/README.md)
- [SCPFS 使用与构建](scpfs/README.md)
- [CryptFS 使用与构建](cryptfs/README.md)
- [共享前端设计](frontend/DESIGN.md)

## 依赖与分发

各子项目的 vcpkg manifest、构建门禁和第三方依赖不同，请查看对应的 `vcpkg.json`、README 和第三方声明。静态链接用户态依赖不代表不需要 WinFsp 内核驱动；分发和许可证义务应以项目中的第三方声明及依赖许可证为准。
