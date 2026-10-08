# CryptFS

Windows 上的加密压缩文件系统，复用 `D:\work\fs\frontend` 的配置界面、
WinFsp 文件操作转发和挂载生命周期。所有持久化状态保存在一个稀疏容器文件中。

- 密码解锁，Argon2id 派生密钥，XChaCha20-Poly1305 认证加密。
- 文件内容、文件名、目录、属性和时间戳加密保存；文件名区分大小写。
- 每个 64 KiB 数据块独立压缩；不可压缩的块采用原始编码后加密。
- 空洞不分配数据块；写入时扩展；删除、截断后后台自动搬迁并缩短容器。
- 容器内事务日志支持进程中断后的恢复；挂载前验证全部存活数据。
- 单个程序文件交付，静态链接用户态依赖。挂载仍使用 Windows 的 WinFsp
  内核驱动，程序内嵌匹配的签名驱动资源。

## 使用

直接运行 `cryptfs.exe` 显示配置界面。输入容器路径、空闲盘符和密码，
首次创建时选中“创建新容器”，随后挂载。在界面中卸载会关闭挂载进程并释放容器。
已有容器必须取消创建选项；创建操作不会覆盖已有文件。

命令行创建并挂载：

```powershell
.\cryptfs.exe --container "D:\vault.cfs" --mount "T:" --create
```

再次挂载：

```powershell
.\cryptfs.exe --container "D:\vault.cfs" --mount "T:"
```

控制台会以隐藏输入方式读取密码。前台运行时按 Ctrl+C 卸载。自动化场景
可以使用 `--password-stdin` 从标准输入读取一行 UTF-8 密码；请由调用程序
通过管道发送，不要把真实密码写在命令行、脚本或日志中。

检查容器的解锁和完整性：

```powershell
.\cryptfs.exe --container "D:\vault.cfs" --check
```

运行 `cryptfs.exe --help` 查看当前版本支持的参数。容量以字节计，默认
`1099511627776`（1 TiB），也是本版的逻辑容量上限；创建时可以指定较小的
`--capacity`。压缩等级默认 3，
可通过 `--compression-level` 指定。

## 当前范围

容器必须位于支持稀疏文件控制的本地文件系统中；本项目在 NTFS 上验证。
一个容器同时只能由一个进程打开。密码遗失无法恢复，本版不提供密码更改、
服务自动解锁、多容器并发共享、硬链接、备用数据流或持久化 Windows ACL。
Windows 访问权限由挂载进程和合成安全描述符控制。

默认逻辑容量与实际物理存储预算不同。本版最多 65,536 个节点、目录深度 64、
4,000,000 个物理页（约 15.3 GiB，加固定头部和日志）。压缩率会影响这些物理页
能够保存的文件内容总量。卷可用空间还受宿主磁盘
剩余空间限制。挂载会认证所有存活页，因此开锁时间随已用容量增长。
后台整理在前台写入之间执行；持续新增数据时，容器可能继续增长。
物理页已用满时，非 64 KiB 对齐的截断可能因需要新的边界数据页而返回空间不足，
失败时保留原文件内容和大小；可先删除文件或按 64 KiB 边界截断，整理后再重试。

加密保护容器中的数据，不隐藏容器格式、KDF 参数、总长度和粗略分配模式。
内存中的解密数据及 Windows 页面文件不在容器加密保护范围内；本版也不保证
已删除内容的安全擦除。认证加密不能检测旧的有效容器或同位置、同标识的
有效加密记录被重放，本版不提供回滚检测。

格式和恢复协议见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，具体字节布局见
[docs/FORMAT.md](docs/FORMAT.md)，本次实际执行的检查和限制见
[docs/VALIDATION.md](docs/VALIDATION.md)。重要数据应有独立备份。

## 构建与验证

依赖 Visual Studio Windows SDK、clang-cl、CMake/Ninja、`D:\vcpkg`，以及现有
静态 WinFsp 树 `D:\src\winfsp-memfs-static`。外部依赖通过 vcpkg manifest
安装 libsodium 和 zstd，使用 `x64-windows-static` 和静态 CRT。

```powershell
.\scripts\build.ps1 -Configuration Debug
.\scripts\build.ps1 -Configuration Release
python .\tests\mount_integration.py --exe .\build\x64-release\cryptfs.exe --drive X:
```

挂载测试只使用空闲 X: 和项目内新建的测试目录。构建脚本仅为本次构建
设置项目内的临时目录，完成后恢复原环境，不更改系统 TEMP/TMP。

发布目录为 `dist\cryptfs-x64`。生产发布包不包含测试密码、测试容器、
构建目录或第三方 DLL。
