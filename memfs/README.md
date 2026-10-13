# memfs

基于原生 WinFsp API、使用 C17 编写的高性能易失性 Windows 内存文件系统。

## 功能

- 纯 C17、CMake、Ninja、clang-cl 和 vcpkg。
- 使用原生 WinFsp API，不经过 FUSE。
- 文件名按 NTFS 语义比较：不区分大小写，但保留创建时的大小写。
- 自适应目录索引：基础为侵入式 treap，大目录按需增加开放寻址哈希表。
- 支持创建、打开、读、写、截断、改名、移动、删除和目录枚举。
- 稀疏文件使用 4 KiB 逻辑页。
- 小文件以 8 字节明文粒度存储。
- 可选的逐页 Zstd 压缩。
- 可选的逐页认证加密：支持硬件加速时使用 AES-256-GCM，否则回退到 XChaCha20-Poly1305。
- 支持 Windows 文件属性、时间戳、ACL 和安全描述符。
- 使用 WinFsp FINE 操作保护，不同文件可并发执行 I/O。
- 全局容量和驻留内存统计支持线程安全并发访问。

文件系统中的全部内容都是易失数据。卸载或终止进程后，文件都会丢失。

## 文件名比较规则

文件名与 NTFS 一样不区分大小写、但保留大小写。查找、冲突检查、目录排序、通配符过滤、改名和删除，会先用系统大写映射（`RtlUpcaseUnicodeChar`）转换 UTF-16 代码单元再比较。`Readme.txt` 和 `README.TXT` 指向同一条目，并保留创建时的拼写；只改变大小写的改名会更新该拼写。不执行 Unicode 规范化。

大小写行为在 WinFsp 创建卷时确定，已挂载实例会继续使用原有行为。验证重新构建的版本时，应挂载一个新的、未占用的卷；除非允许丢弃卷中数据，否则不要停止正在运行的易失卷。

## 依赖

- Windows 10/11 x64，或在 Windows x64 仿真下运行 x64 用户态程序的 Windows 11 ARM64。32 位 Windows 和 Windows 10 ARM64 不支持。
- WinFsp Git 源码位于 `D:\src\winfsp`。`scripts\prepare-winfsp-static.ps1` 会根据已安装的签名驱动确定准确源码提交，并准备 `D:\src\winfsp-memfs-static`。
- Visual Studio C/C++ 构建工具。
- 编译器：LLVM/clang-cl。
- CMake 和 Ninja。
- 提供的 presets 使用位于 `D:\vcpkg` 的 vcpkg。

vcpkg manifest 会安装 `zstd` 和 `libsodium`。首次构建前运行 `scripts\prepare-winfsp-static.ps1`。该脚本读取已安装签名 WinFsp 驱动的 FileVersion，解析对应 Git 提交，创建 `D:\src\winfsp-memfs-static`，应用最小静态用户态支持，并从完全匹配的源码版本构建 Debug/Release 静态库。之后 presets 会链接该匹配的静态运行库，所以运行 `memfs.exe` 不需要 `winfsp-x64.dll`。

匹配版本的签名 WinFsp 内核驱动（`winfsp-x64.sys` 和 `winfsp-a64.sys`）会嵌入单个 x64 `memfs.exe`。CMake 要求两个 SYS 来自同一个已签名 WinFsp 版本，并与静态链接的 x64 用户态运行库匹配。构建还会检查每个 SYS 的 PE 架构（`AMD64` / `ARM64`）、Microsoft Windows Hardware Compatibility Publisher Authenticode 签名有效性，以及两个驱动是否由同一签名者签署。

运行时，memfs 使用 `IsWow64Process2` 判断 Windows 原生架构：AMD64 主机使用 x64 SYS；在 x64 仿真下运行 x64 EXE 的 Windows 11 ARM64 主机则使用 ARM64 SYS。内核驱动不会经仿真运行。CTest 也会调用静态库中的 `FspVersion()`，解析嵌入 SYS 的 PE 头，重新检查驱动来源，并解析构建后 PE 的普通导入和延迟导入表；因此，WinFsp 输入过期/不匹配或重新引入 `winfsp*.dll` 依赖都会导致验证失败。若没有兼容的官方 WinFsp 驱动，提升权限运行的 memfs 进程会安装并启动匹配的嵌入签名备用驱动，再重试 `FspFileSystemCreate`。

## 构建

```powershell
Set-Location D:\work\fs\memfs

.\scripts\prepare-winfsp-static.ps1

cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug

cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release
```

## 发布包和第三方声明

运行以下命令创建当前 x64 发布包：

```powershell
.\scripts\package-release.ps1
```

发布包包含 `memfs.exe`、`BUILD_PROVENANCE.json`、`THIRD_PARTY_NOTICES.md`、SHA-256 校验和，以及 WinFsp、libsodium 和 zstd 的权威许可证文本。打包门禁刻意采用严格模式：Git 跟踪树必须干净、重新构建 Release、完整 CTest 套件必须通过，并且生成的来源记录必须校验成功，之后才发布暂存目录。

`BUILD_PROVENANCE.json` 记录确切的 memfs/WinFsp 提交、WinFsp 补丁差异哈希、静态库和 SYS 哈希、PE 架构/签名证据、编译器二进制及版本、vcpkg Git 提交/内置 baseline/triplet 哈希、依赖版本和最终 EXE 哈希。

同一个 x64 包也用于 Windows 11 ARM64：Windows 在 x64 仿真下运行 `memfs.exe`，需要备用驱动时 memfs 会选择嵌入的原生 ARM64 WinFsp 内核驱动。

当前构建静态链接 WinFsp 用户态代码。WinFsp 本地 `License.txt` 声明 GPLv3，其 FLOSS 特别例外明确涵盖与平台 WinFsp DLL 链接，并不是对任意静态链接的通用例外。用于专有软件分发前，应获得适当的 WinFsp 商业许可，或确保分发条款符合适用的 WinFsp/GPLv3 要求。详见 `THIRD_PARTY_NOTICES.md`。

## 运行

不带参数运行 `memfs.exe`，或传入 `--gui`，即可打开原生配置窗口。点击 **挂载** 会启动由该窗口拥有的临时控制台挂载；点击 **卸载临时挂载** 只停止此实例。**安装并启动服务** 和 **卸载服务** 使用选定的服务名；卸载时只需指定服务名。挂载设置包括容量、卷标、dispatcher 线程数、压缩、加密、调试日志和运行时统计。

GUI 可以接收一个已存在的 64 位十六进制密钥环境变量名，但不会索要或显示密钥内容。LocalSystem 服务安装拒绝使用环境密钥；该操作可选择 **随机临时密钥** 或关闭加密。

基本 512 MiB 内存盘：

```powershell
.\build\x64-release\memfs.exe --mount R:
```

自定义容量和卷标：

```powershell
.\build\x64-release\memfs.exe --mount R: --size 1G --label FASTRAM
```

启用压缩：

```powershell
.\build\x64-release\memfs.exe --mount R: --compress
.\build\x64-release\memfs.exe --mount R: --compression-level 3
```

使用进程生命周期内随机密钥加密：

```powershell
.\build\x64-release\memfs.exe --mount R: --encrypt
```

使用调用方提供的 256 位密钥时，建议通过环境变量传入，避免密钥出现在命令行：

```powershell
$env:MEMFS_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
.\build\x64-release\memfs.exe --mount R: --compress --key-env MEMFS_KEY
```

测试时也可使用 `--key-hex <64hex>`，但其他进程或诊断工具可能看到命令行参数。

参数：

```text
--mount <path>          盘符或目录挂载点
--size <bytes|auto>     容量 1..INT64_MAX；支持 K/M/G 后缀
--reserve <bytes>       配合 --size auto 使用：启动时预留的内存提交额度（默认 1G，0 = 关闭）
--mkdir <path>          挂载前创建目录（可重复，允许嵌套路径）
--label <name>          卷标
--threads <n>           Dispatcher 线程数；0 = 自动，否则为 2..64
--compress              启用 Zstd 等级 1 压缩
--compression-level <n> 启用 Zstd 等级 1..22 压缩
--encrypt               使用随机 256 位密钥；支持时使用硬件 AES-256-GCM，否则使用 XChaCha20-Poly1305
--key-hex <64hex>       使用固定的 256 位密钥
--key-env <name>        从环境变量读取 64 位十六进制密钥
--debug                 启用 WinFsp 调试日志
--service               在 Windows 服务控制管理器（SCM）下运行
--service-name <name>   服务名；默认：MemfsC
--log-file <path>       受保护服务日志的绝对路径
--install               安装并启动 LocalSystem 自动服务
--uninstall             在有界等待内停止并仅删除指定服务
--uninstall-private-driver  仅移除 MemfsC 所拥有的 WinFsp 备用驱动服务/文件
--stats                 挂载和停止时输出易读的运行时快照
--stats-json            挂载和停止时输出稳定的单行 JSON 运行时快照
--help                  显示帮助
```

按 Ctrl+C 停止。

## Windows 服务

原生安装器会创建名为 `MemfsC` 的 `SERVICE_WIN32_OWN_PROCESS` 服务，配置自动启动和有界重启恢复，然后立即启动。服务以 LocalSystem 运行。受保护日志默认位于 `%ProgramData%\MemfsC\MemfsC.log`，其 DACL 只允许 SYSTEM 和安装用户 SID 访问。可通过 `--log-file` 指定其他绝对日志路径。可执行文件处理 STOP 和 SHUTDOWN 控制，并在拆除文件系统和分配器前先停止 WinFsp dispatcher。

MemfsC 进程意外失败时，SCM 会按设置在 1、5 和 30 秒后重启；失败次数在 24 小时后清零。由于这是易失文件系统，每次重启都会创建新的空 M: 卷，并重新创建诸如 `tmp` 的配置启动目录。

在提升权限的 shell 中运行：

```powershell
.\build\x64-release\memfs.exe --install --mount R: --size 512M --label MEMFS
sc.exe queryex MemfsC
.\build\x64-release\memfs.exe --uninstall
```

测试时可使用 `--service-name MemfsFrontendTest` 安装独立服务，卸载时传入相同名称。重复执行相同配置的安装是幂等的；若可执行文件或服务参数与已注册配置不同，则拒绝安装。原生安装拒绝 `--key-hex` 和 `--key-env`，因为 LocalSystem 服务无法安全继承用户的密钥参数或环境变量；仍可使用 `--encrypt`，它会在每次启动时生成新密钥。现有 SCM 工作流仍可使用手动 `--service` 模式和 `scripts\memfs-service.ps1`。

项目仍提供一个使用 `sc.exe` 执行全部服务控制操作的辅助脚本：

```powershell
.\scripts\memfs-service.ps1 install -Exe .\build\x64-release\memfs.exe -Mount R: -Size 512M
.\scripts\memfs-service.ps1 start
.\scripts\memfs-service.ps1 query
.\scripts\memfs-service.ps1 stop
.\scripts\memfs-service.ps1 delete
.\scripts\memfs-service.ps1 purge-driver -Exe .\build\x64-release\memfs.exe
```

服务默认以 LocalSystem 运行。首次安装驱动需要管理员权限。如果已安装兼容的官方 WinFsp SxS 驱动，memfs 会复用它，不会创建平行驱动服务。如果驱动缺失或无法加载，memfs 会解出内嵌的签名 WinFsp SYS 资源，经 SCM 注册并启动，然后重试 `FspFileSystemCreate`。

以下破坏性但会自行清理的集成测试覆盖服务异常恢复：

```powershell
.\tests\service-recovery.ps1 -Exe .\build\x64-release\memfs.exe -Drive R: -Size 64M
```

测试安装配置好 SCM 重启策略的 `MemfsC`，启动服务并写入标记文件，然后强制结束服务进程。接着等待 SCM 使用新 PID 重启服务、重新挂载空的易失文件系统，验证重启后的 I/O，最后停止并删除服务。若机器已安装官方 WinFsp，测试还会断言没有创建私有 `WinFsp+MemfsC` 备用驱动服务。

服务初始化失败时，`sc.exe query MemfsC` 会在 `SERVICE_EXIT_CODE` 中保留底层 WinFsp/NTSTATUS 值，而不是只显示通用 Windows 服务错误 1066。

### 部署验证工具

`scripts\verify-deployment.ps1` 提供可重复的部署检查，不会悄悄修改官方 WinFsp 安装。

在已安装官方 WinFsp 的开发机上：

```powershell
.\scripts\verify-deployment.ps1 -Scenario All -Report .agent\deployment.json
```

该脚本运行 Release 部署门禁测试，验证不存在 `MemfsC` 服务，通过已安装的官方 WinFsp 驱动挂载真实文件系统并执行常规文件 I/O，同时确认没有创建私有 `WinFsp+MemfsC` 备用驱动服务或 `memfs-winfsp-*.sys` 文件。

内嵌私有驱动路径需要一台真正干净、没有安装官方 WinFsp SxS 驱动的虚拟机，因此必须显式选择：

```powershell
.\scripts\verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback -Report C:\temp\memfs-private-fallback.json
```

该场景需要管理员权限；若检测到官方 WinFsp 驱动会拒绝运行。它会挂载 memfs 以强制走内嵌备用驱动路径，验证私有驱动只引用 MemfsC 所拥有的文件名，然后移除私有服务和文件，除非指定 `-KeepPrivateDriver`。

## 目录结构

小目录的 MemfsDir 不分配哈希表。每个子项存放于侵入式 treap 中；treap 是权威有序索引，插入/删除/查找的期望复杂度为 O(log n)，并天然支持排序枚举。

子项达到 256 个时，memfs 会按需增加 Robin Hood 开放寻址哈希加速器。哈希表目标最大负载率为 85%，删除时使用向后位移而不是墓碑；目录子项降到启动阈值的一半以下时会丢弃该表。treap 始终是权威索引，因此哈希分配失败不会破坏命名空间。

目录/文件元数据采用紧凑布局：

- x64 上 MemfsNode 为 128 字节，并在编译期固定到分配器的 128 字节等级。旧的 136 字节布局会被提升到 192 字节 slab 槽位；现在每个活动文件/目录节点节省 64 字节 slab 空间（节点槽内存减少 33.3%）。
- 目录状态、小文件存储和分页文件存储互斥，复用一个指针宽度的 union。
- 节点、可选目录状态和名称使用独立的 size-class 分配：128 字节节点刚好占满所在等级，与名称合并会把常见对象推到 192 字节等级，增加物理内存占用。
- 继承的 ACL 使用引用计数共享。
- 从命名空间移除的节点会复用 treap 链接，进入孤儿/打开句柄链表。
- WinFsp `IndexNumber` 通过每个文件系统独立播种的 64 位置换函数，从稳定节点地址派生；不再单独占用 8 字节。节点存活期间，该值在改名/unlink 前后保持稳定。

当前构建在单个目录中创建 50,000 个文件的本机 A/B 基准：

| 指标 | 基线 26638fb | 当前 |
|---|---:|---:|
| 创建 50k | ~32.9–33.8 ms | ~21.9–23.7 ms |
| 查找 50k | ~11.6–13.7 ms | ~6.9–9.8 ms |
| 枚举 50k | ~1.35–1.91 ms | ~0.6–1.6 ms |
| 每条目进程私有内存增量 | ~457–458 B | ~220 B |
| 50k 条目时哈希槽位数 | 131,072 | 65,536 |

当前测试套件还会删除大型 Robin Hood 表的一半条目、检查正/负查找、重新插入名称，并重新枚举有序 treap，以覆盖向后位移删除。

## 文件存储

Windows 可见的 AllocationSize、内部配额统计和实际 RAM 驻留量是不同指标，刻意分别处理。

### 小文件

不超过 4 KiB 的文件使用编码后的小型表示。明文容量使用精确的 1/2/4/8 字节小等级，此后按 8 字节粒度增长。未压缩、未加密且不超过 8 字节的数据直接存放在 inode union 中，不产生额外堆分配。

WinFsp 卷仍使用 512 字节扇区，因此向 Windows 报告的 AllocationSize 会按 512 字节取整。内部配额按字节精确统计：1 字节文件只占 1 字节 memfs 配置容量，不是 512 字节。

未压缩、未加密的本机测量：

| 文件大小 | Windows AllocationSize | 内部配额 | 跟踪的数据驻留量 |
|---:|---:|---:|---:|
| 1 B | 512 B | 1 B | 0 B |
| 7 B | 512 B | 7 B | 0 B |
| 8 B | 512 B | 8 B | 0 B |
| 9 B | 512 B | 9 B | 24 B |
| 100 B | 512 B | 100 B | 112 B |
| 500 B | 512 B | 500 B | 512 B |
| 1024 B | 1024 B | 1024 B | 1032 B |

启用加密时，1 字节文件的跟踪编码空间为 33 字节：8 字节 blob 头部 + 8 字节 nonce 序号 + 1 字节负载 + 16 字节 AEAD 认证 tag。

`resident_bytes` 跟踪编码数据 blob/页，但刻意不包括宿主分配器记账和命名空间元数据。

### 分配器 v2 与自动容量

分配器 v2 按大小等级组织，而不是按对象类型组织。节点、目录、页组、名称和通用分配 API 最终都进入相同的取整后大小等级，所以只有一个**逻辑大小等级池**，而不是节点/名称/通用对象分池。

内部每个等级使用 16 个并发 lane，避免单把 SRW 锁成为热点；lane 仅用于拆分同步和 slab 所有权，不是业务对象类型池，也不是永久的每线程 arena。本地 lane 始终是最快路径。若本地 lane 没有空闲对象，分配器会通过原子可用 lane 掩码，优先复用同一大小等级中其他 lane 的部分空闲容量，再提交新 slab；若没有任何 lane 可用则完全跳过扫描。空 slab 仍立即归还 VM 后端。这样既保留单一共享大小等级池的内存语义，又避免所有分配都经过一个全局锁。

与之前的 8-lane 布局进行三轮 A/B 基准后发现，并发越高收益越明显：16 线程下，64 字节分配/释放吞吐提高约 114%，4 KiB 分配/释放吞吐提高约 209%，单线程吞吐基本持平。每个文件系统增加的分配器状态元数据约为 12 KiB。

`Memfs` 本身使用的进程级控制分配也经过同一套大小等级/slab/area 机制；只有分配器状态的启动引导直接访问 VM 后端。小分配根据对象大小使用自适应 slab（4/8/16/32/64 KiB）；超过小对象阈值的分配使用 area。`reserved_bytes` 仅表示地址空间预留；`committed_bytes` 是操作系统实际提交的内存，`physical_bytes` 是 `committed_bytes` 的别名，不是另一种来源。`live_bytes` 是当前调用方可见、已分配的负载/对象字节数。

分配器的公开指针保证是：所有非 NULL 分配至少 8 字节对齐。这是有意规定的：小对象表包含 8 字节和 24 字节等级以减少浪费，若不填充这些等级就承诺所有槽位都 16 字节对齐是不准确的。内部首个 slab 负载和 area 负载头目前有更强的 16 字节对齐，但除非具体 API 另有说明，调用方只能依赖至少 8 字节对齐。

零初始化的类型化分配（`node`、`dir`、`page_group`）保留原有安全契约。单独的 `memfs_allocator_alloc_uninit()` 快路径只用于调用方马上覆盖全部申请负载的场合（编码页 blob、复制的安全描述符、临时路径缓冲区和复制后的名称）。这样避免重复 memset，又不会让要求零填充对象的代码看到残留数据。分配器竞争基准会分别报告 `zero` 和 `uninit` 模式。

`capacity_auto=true` 让 memfs 根据当前系统内存和分配器后备内存推导可写额度，而不是使用固定用户容量。

自动容量以**预留额度**（`--reserve`，默认 1 GiB）启动。挂载时分配器会提交相应的地址空间额度但不触碰，因此只增加系统提交量，不占物理内存。每次分配器提交新的后备内存时，会先从预留中释放同等额度；后备内存释放后再补回预留。因此即便其他程序耗尽系统内存，卷仍可使用约等于预留值的提交额度。超出预留后，卷仍像之前一样随系统可用内存增长；报告的可用空间是未使用预留额度加系统允许额度。若启动时系统无法提交预留额度，挂载失败。

预留保证的是内存提交额度，不保证常驻：系统内存压力下 Windows 仍可将数据换出。`memfs_auto_allowance_bytes()` 报告当前允许额度；`used_bytes`、`resident_bytes`、`committed_bytes`、`physical_bytes` 分别表示逻辑配额、驻留负载和分配器物理后备等不同指标。基准会分别报告这些数据，避免把分配器高水位后备内存误认为逻辑文件用量。

自动容量**增长热路径**缓存操作系统可用内存样本 1 ms；公开额度/统计 API 仍执行实时查询。一把 SRW 锁保护完整快照（可用字节、总提交基线和时间戳/截止时间），包括强制刷新。此前尝试将独立原子字段的截止时间最后发布，仍无法阻止将旧实时快照与新样本混合。操作系统查询前先读取总成功提交计数，此后发生的全部提交都会扣减，即便释放后重新分配导致净提交字节数没变。TTL 从查询前开始；慢速 OS 调用不会让旧样本看起来很新。接近压力阈值或请求超过当前额度时，会先清理缓存，再刷新样本。

常规 Debug 使用相同缓存。只有旧式显式压力覆盖会绕过它。`memfs_capacity_snapshot_test` 通过 `NDEBUG` 和仅测试使用的 OS/时钟提供者单独编译生产核心，覆盖过期、强制刷新、慢查询、时钟故障/回拨、查询期间增长、释放后重新分配的扣减、原子压力失败和并发快照发布。这些提供者不会编进交付 EXE。OS 内存样本只是一次观测，不能为其他进程预留资源；仍必须处理分配失败。

运行时诊断默认关闭，不启动采样线程。`memfs_get_runtime_stats()` 返回**由锁保护的近似汇总**，包括逻辑已用/可用字节、驻留字节、分配器 live/reserved/committed/physical 字节、slab/area/cache 数量、清理器累计值，以及当前自动容量额度和 256 MiB 硬压力/512 MiB 软压力余量。

分配器分片和标量计数按顺序采样，因此并发 I/O/分配时各字段可能代表略有差异的时刻。要求精确基线或字段间精确相等时，应在文件系统静止后收集统计信息。

交互式诊断：

```powershell
.\build\x64-release\memfs.exe --mount R: --size auto --stats
.\build\x64-release\memfs.exe --mount R: --size auto --stats-json
```

`--stats` 在挂载后和关闭前以稳定的 `key=value` 格式打印字段。`--stats-json` 不输出常规挂载横幅，每次采样打印一个 JSON 对象，含 `type=memfs_stats` 和 `phase=mounted|stopping`，便于将标准输出重定向后由程序解析。其值遵循上文所述的并发近似语义；停止阶段的采样通常处于静止状态，可作为精确清理基线。服务/控制面代码也可直接调用该 API，无需启用后台采样器。

### 稀疏分页文件

超过 4 KiB 或发生高偏移写入的文件使用 4 KiB 稀疏逻辑页：

- 每个逻辑组覆盖 1 MiB（256 页）。
- 每组具有 256 位存在位图和紧凑指针向量，只保存实际存在的页面。
- 顶层组索引是按 `{group_index, group*}` 排序的紧凑数组，通过二分查找。
- 因此，高稀疏偏移不会分配巨大的中间指针数组。
- 不存在的页面读取为零。

扩展空文件会按字节精度预留 memfs 配额，但不分配数据页。512 字节对齐的 AllocationSize 只在向 WinFsp 报告时使用。

截断会释放编码页和空页组。文件缩小到 4 KiB 以下时，可以退化回紧凑的小文件表示。

本机旧版整文件 realloc 实现以 64 KiB 块追加 32 MiB 约需 1.4 秒。稀疏分页存储将相同基准缩短到约 9 ms。

## 压缩

压缩是可选的，分别应用于每个小文件 blob 或 4 KiB 页面。memfs 使用 Zstd；只有节省的字节足以抵消元数据和 CPU 成本时才保留压缩表示。

压缩按文件自适应。反复遇到不可压缩页会提高一个较小的评分；超过跳过阈值后，分页文件只抽取 16 页中的 1 页重新探测是否恢复可压缩性。探测成功会降低评分。小 blob 的探测成本足够低，因此每次改写仍会尝试。

当前构建对 16 MiB 高度可压缩的重复数据进行测量：

| 模式 | 跟踪的驻留量 | 驻留/逻辑大小 | 写入耗时（本机运行） |
|---|---:|---:|---:|
| 原始 | 16.03 MiB | 100.195% | ~4.4 ms |
| Zstd | 108 KiB | 0.659% | ~19–31 ms |
| 仅加密 | 16.13 MiB | 100.781% | ~15.6–16.3 ms |
| Zstd + 加密 | 204 KiB | 1.245% | ~11.5–11.7 ms |

默认不启用压缩，避免不可压缩负载花费 CPU 却没有减少内存占用。

## 加密

加密是可选的，对每个非零 blob/页独立处理。编码顺序如下：

1. 可选的 Zstd 压缩；
2. 认证加密。

若 CPU 支持且 libsodium 检测到 AES-256-GCM 硬件加速，新加密页面使用 AES-256-GCM；否则使用 XChaCha20-Poly1305。算法记录在页面标志中，标志本身也作为 AAD 认证。因此读取时根据每个已存页面的标志选择解码算法，而非依据当前编码器偏好。若挂载期间首选编码算法变化，混合算法的旧页面仍可读。

每个 memfs 实例生成随机 128 位挂载前缀，并保留调用方/随机生成的 256 位 XChaCha 主密钥。AES-GCM 会用主密钥和挂载前缀派生独立的挂载根密钥。每次编码改写都会取得全局唯一、单调递增的 64 位序号。XChaCha 将 128 位前缀与该序号组合成 192 位 nonce。AES-GCM 在独立挂载密钥下使用该序号组成 96 位 nonce，并每处理 `2^20` 个加密 blob/页派生新的 epoch 子密钥。每个 blob/页只保存 8 字节序号。

AEAD 附加认证数据将密文绑定到节点标识、存储/页索引（或 tiny-blob 哨兵）、nonce 序号、明文大小及所有 codec/算法标志。常规读取会检测密文、元数据或算法选择器被篡改。

主/XChaCha 密钥、派生的 AES 根密钥和文件系统范围内缓存的当前 AES epoch 密钥存放在专用内存字段，并尽力使用 `sodium_mlock` 锁定。epoch 缓存由 SRW 锁保护，只保留最新 epoch；读取旧 epoch 时按需派生临时密钥，而不无限增长密钥缓存。临时 epoch 密钥和 nonce 缓冲区用后显式清零；卸载时清零/解锁全部保留密钥及挂载 nonce 前缀。

加密保护 memfs 堆中保存的页面表示，但不隔离进程内存：读取、写入、压缩和解压期间，明文必然会短暂存在于应用 I/O 缓冲区和较小的栈工作缓冲区。

全零页始终视为隐式稀疏空洞，不分配密文。

## 并发

memfs 使用 WinFsp FINE 操作保护。WinFsp 使用共享/独占命名空间锁保护命名空间操作，不同文件的 I/O 可并发执行。FSD 仍负责同步同一文件上的操作。

跨文件容量与驻留统计使用 Interlocked 原子操作，而非全局文件系统锁。因此正常文件数据路径没有 memfs 范围的互斥锁。

核心测试套件包含在启用压缩和加密时对多个文件并发写入的测试。

## 句柄生命周期与删除

WinFsp 使用节点指针作为 `FileContext`。Open/Create 会增加节点打开计数。Cleanup 时执行 delete 会将节点从命名空间移除，但节点仍保持存活，直到最后一个句柄关闭。

## 长时间内存漂移压力测试

`memfs_soak_bench` 在启用压缩和加密的情况下运行混合核心负载。每轮包括小文件创建/读取/改名/unlink、256 KiB 大文件写入和截断/扩展并验证零填充，以及在高偏移处对 64 MiB 文件进行稀疏写入/读取/截断/扩展。每次采样报告逻辑/驻留字节、分配器 live/reserved/committed/physical 字节、进程私有字节及 slab/area/cache 数量；最终汇总报告进程私有/提交内存漂移的线性斜率。

默认模式刻意保持较短，适用于 CI：

```powershell
.\build\x64-release\memfs_soak_bench.exe
.\build\x64-release\memfs_soak_bench.exe --seconds 10 --sample-ms 1000
```

长时间压力测试需显式指定，时长可为 10 到 60 分钟：

```powershell
.\build\x64-release\memfs_soak_bench.exe --soak 10
.\build\x64-release\memfs_soak_bench.exe --soak 60 --sample-ms 5000
```

测量前基准会预热所有负载形态以及 codec/密码学路径。退出时会清理分配器缓存，并要求逻辑已用、驻留、分配器 live 对象/字节、reserved、committed、physical、slab 和 area 状态都回到预热后基线。进程私有字节斜率单独报告，因为 Windows/运行库可能保留不属于 memfs 分配器后备内存的进程私有记账。

## 集成测试

集成测试会挂载真实 WinFsp 盘符，并使用常规 Windows 文件 API 测试稀疏写入、改名/移动/枚举/删除：

```powershell
& .\tests\integration.ps1 -Exe .\build\x64-release\memfs.exe -Drive R:
& .\tests\integration.ps1 -Exe .\build\x64-release\memfs.exe -Drive R: -ExtraArgs @("--compress")
```

当前测试套件也已在纯模式、仅压缩、仅加密、压缩+加密四种挂载配置下成功运行。

## 源码布局

```text
src/
  main.c            命令行挂载进程
  memfs_core.h      树/存储/codec API 与结构
  memfs_core.c      目录索引、稀疏数据、压缩、加密
  memfs_winfsp.h    WinFsp 适配器 API
  memfs_winfsp.c    WinFsp 回调

tests/
  memfs_core_test.c      单元/压力/并发/codec 测试
  integration.ps1       真实挂载盘集成测试
  service-recovery.ps1  SCM 异常终止、重启和重新挂载集成测试
scripts/
  prepare-winfsp-static.ps1  准备与签名驱动匹配的静态 WinFsp 运行库
  memfs-service.ps1          sc.exe 的安装/启动/查询/停止/删除包装脚本
  verify-deployment.ps1      可重复验证官方驱动/无服务/私有备用驱动部署
```

## 计划中的后续工作

- 在当前父 ACL/继承 ACL 共享之外，增加全局安全描述符驻留池。
- 命名数据流、重解析点和扩展属性。
- 持久化/快照支持。
- 如果引入持久加密镜像，则增加基于密码的密钥派生。
- 增加改名/删除/打开竞争压力测试。
- 继续在真实负载下分析统一大小等级的 shard 数量、slab 大小及 slab/area 阈值；不要引入按对象类型拆分的物理池。

## 发布候选验收与便携式交接

运行 `scripts/verify-release-acceptance.ps1`，为当前实际版本生成有界且失败即关闭的验证矩阵，详情见 `docs/RELEASE_ACCEPTANCE.md`。当前 CTest 注册了 20 个用例。生命周期回归覆盖共享打开和异步最终 Close，因为 WinFsp FINE 不会串行化这一过程。单独的短生命周期锁保护引用计数/孤儿节点，不串行化普通数据 I/O。安全描述符替换和借用快照使用兼容的 guard。

扩展验证报告通过后，可创建便携包：

```powershell
python .\scripts\package-validation-kit.py --report .agent\<acceptance-run>\acceptance.json
```

生成包包含严格 manifest，可在没有开发环境的其他 Windows 机器上运行匹配的 Release 测试。请按 `docs/PORTABLE_VALIDATION.zh-CN.md` 操作。干净虚拟机安装、Win11 ARM64 运行、真实操作系统重启、发布者签名和分发许可属于独立验收门槛。便携包不会自动启用 Sandbox、恢复或重置已有虚拟机、重启宿主机，也不会为未执行的门槛签发通过结论。
