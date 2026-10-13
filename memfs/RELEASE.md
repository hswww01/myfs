# 发布验证记录

2026-09-30 在 Windows x64 上验证。

## 构建输入

- memfs 仓库：`D:\work\memfs`
- WinFsp Git 仓库：`D:\src\winfsp`
- 同一 WinFsp SxS 版本中的签名嵌入驱动：
  - x64：`C:\Program Files (x86)\WinFsp\SxS\sxs.20251221T124141Z\bin\winfsp-x64.sys`
  - ARM64：`C:\Program Files (x86)\WinFsp\SxS\sxs.20251221T124141Z\bin\winfsp-a64.sys`
- 两个驱动 FileVersion：`2.1.25156.ddca7bd`
- 匹配的 WinFsp 源码提交：`ddca7bd`（tag `v2.1`）
- 嵌入驱动 SHA-256：
  - x64：`03553FFFACD362F4A9A08C00B4F236A82354A183BC6028494FB32055386E13C9`
  - ARM64：`BF3B1BF90A7C070D456FC43C8552CCF8BE85CDDDEF4F3B19091B4A64AE4E686C`
- 生成的匹配静态工作树：`D:\src\winfsp-memfs-static`
- 编译器：`clang-cl 22.1.3`（`e9846648fd6183ee6d8cbdb4502213fcf902a211`）
- vcpkg builtin baseline：`6d332a018c433fad20822ff4b536e4ccdc3413bd`
- 发布 triplet：`x64-windows-static`

安装包中的机器可读 `BUILD_PROVENANCE.json` 是准确来源信息的权威记录，包含 memfs 精确 Git 提交、完整 WinFsp 提交、WinFsp 补丁差异哈希、静态库哈希、两个 SYS 哈希/PE 架构/Authenticode 签名者、编译器二进制哈希/版本、vcpkg 提交/baseline/triplet 哈希、依赖版本和最终 EXE 哈希。

全新构建前运行：

```powershell
.\scripts\prepare-winfsp-static.ps1
```

脚本读取已安装签名驱动的 FileVersion，提取对应 Git revision，在该精确提交创建 detached worktree，应用最小静态用户态支持，并构建 Debug 和 Release 两份 `winfsp-static-x64.lib`。这样可避免新用户态运行库与旧签名内核驱动混用。

## 静态 WinFsp 版本契约

构建会在多个独立层级验证 WinFsp 来源：

1. CMake 从所选 WinFsp 源码树读取 `MyCanonicalVersion`。
2. CMake 要求两个 SYS 文件的完整 FileVersion 一致，并符合预期 major/minor。
3. `verify-winfsp-drivers.ps1` 要求 x64 SYS 为 `IMAGE_FILE_MACHINE_AMD64`、ARM64 SYS 为 `IMAGE_FILE_MACHINE_ARM64`、Authenticode 状态为 `Valid`、签名者为 Microsoft Windows Hardware Compatibility Publisher，且两个驱动证书签名者相同。
4. `memfs_winfsp_version_test` 调用链接静态库中的 `FspVersion()`，并运行时校验编码版本。
5. `memfs_resource_test` 解析实际嵌入资源的 PE 头并验证机器架构。

使用 WinFsp v2.2 静态源码搭配 v2.1 签名驱动的负向配置测试会失败，并显示：

```text
WinFsp version mismatch: static runtime expects 2.2,
but embedded driver ... is 2.1.25156.ddca7bd
```

提供的 presets 使用：

- `VCPKG_TARGET_TRIPLET=x64-windows-static`
- `MEMFS_STATIC_WINFSP=ON`
- `WINFSP_SOURCE_ROOT=D:/src/winfsp-memfs-static`

提供源码根目录后，CMake 会强制选择该源码树中与配置匹配的静态库，避免旧 CMake 缓存静默链接到其他 WinFsp 静态库。

## 构建与测试矩阵

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure

cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release --output-on-failure
```

当前注册 20 个测试。生成的验收报告记录实际运行 revision、逐项结果和全部失败；源码文档不能替代通过的报告。

1. `memfs_capacity_snapshot_test`
2. `memfs_lifetime_test`
3. `memfs_mt_stress_test`
4. `memfs_core_test`
5. `memfs_soak_smoke`
6. `memfs_no_crt_heap_guard`
7. `memfs_no_crt_heap_guard_good_fixture`
8. `memfs_no_crt_heap_guard_bad_fixture`
9. `memfs_driver_test`
10. `memfs_cli_test`
11. `memfs_static_winfsp_no_dll_import`
12. `memfs_static_winfsp_version`
13. `memfs_winfsp_dispatcher_state`
14. `memfs_cli_help`
15. `memfs_cli_reject_negative_size`
16. `memfs_cli_reject_oversized_size`
17. `memfs_cli_reject_thread_one`
18. `memfs_cli_reject_thread_over_limit`
19. `memfs_embedded_winfsp_resources`
20. `memfs_winfsp_driver_provenance`

## 真实挂载盘集成

Release 可执行文件在四种配置下均通过真实 WinFsp 集成测试：

- 纯模式：通过
- `--compress`：通过
- `--encrypt`：通过
- `--compress --encrypt`：通过

每次测试均挂载 R:，通过常规 Windows 文件 API 测试二进制 I/O、稀疏文件零填充、改名/移动/枚举/删除，并正常卸载。

## 静态 WinFsp 验证

匹配 v2.1 的静态库：

- Debug：
  `D:\src\winfsp-memfs-static\build\VStudio\build\Debug\winfsp-static-x64.lib`
  SHA-256：`EB66B092EAC94C973ED929C6CACE2F3254EADE8DF48E7FECC20DB2CED6A104B1`
- Release：
  `D:\src\winfsp-memfs-static\build\VStudio\build\Release\winfsp-static-x64.lib`
  SHA-256：`7064859CC5085A4F68BD8A1F9C53B852263257E7B3CD57FDD785BECD313568E2`

`memfs_static_winfsp_no_dll_import` 确认最终 EXE 不导入或延迟导入 WinFsp DLL，因此运行时不需要 `winfsp-x64.dll`。

## 嵌入式驱动行为

x64 用户态可执行文件内嵌匹配 WinFsp SxS 版本的两个签名内核驱动：

```text
x64:   winfsp-x64.sys  FileVersion 2.1.25156.ddca7bd
ARM64: winfsp-a64.sys  FileVersion 2.1.25156.ddca7bd
```

CMake 要求两个 SYS 与静态链接的 x64 用户态运行库来自完全相同且已签名的 WinFsp 版本。发布的用户态程序始终为 x64。在 AMD64 Windows 上选择 x64 SYS；在 x64 仿真下运行 x64 EXE 的 Windows 11 ARM64 上，`IsWow64Process2` 会返回原生 ARM64 机器架构，memfs 因而选择 ARM64 SYS。不支持 32 位用户态或驱动路径。

memfs 首先尝试常规 `FspFileSystemCreate`。若系统已有兼容官方驱动，则复用它，不安装平行备用服务。只有驱动缺失/无法加载时，才解出架构匹配的嵌入签名 SYS，通过 SCM 注册并启动私有备用文件系统驱动服务，再重试 `FspFileSystemCreate`。

替换前会逐字节比较已存在的提取文件。

## Windows 服务验证

最终 Release `memfs.exe` 已通过真实 Service Control Manager 以 LocalSystem 验证。

成功生命周期：

```text
sc create
sc start
STATE: RUNNING
mount R:
create/write/read/delete
sc stop
STATE: STOPPED
sc delete
```

真实文件读写往返结果：

```text
READBACK=service-release-ok
```

服务辅助脚本也已端到端验证：

```powershell
.\scripts\memfs-service.ps1 install -Exe .\build\x64-release\memfs.exe -Mount R: -Size 64M -StartType demand
.\scripts\memfs-service.ps1 start
.\scripts\memfs-service.ps1 stop
.\scripts\memfs-service.ps1 delete
```

现在服务已不存在时，`stop` 和 `delete` 也能正常处理。

还通过 `tests\service-recovery.ps1` 验证异常终止恢复：服务以 LocalSystem 身份在 R: 启动后，强制结束其进程；SCM 用新 PID 重启服务：

```text
old_pid=13196
new_pid=46288
readback=service-recovery-ok
```

崩溃后重新挂载的文件系统正确为空（易失数据不随进程死亡保留），新 I/O 成功；官方 SxS 驱动可用时没有创建私有 WinFsp 备用驱动；测试之后清理了 `MemfsC`。重启恢复是单独的干净机器/人工验证项，因为本测试不会重启开发机。

服务启动失败时，底层 WinFsp NTSTATUS 会保留在 `SERVICE_EXIT_CODE`。例如尝试挂载已存在的普通目录时返回：

```text
WIN32_EXIT_CODE    : 1066  (0x42a)
SERVICE_EXIT_CODE  : 3221225525  (0xc0000035)
```

不会将根因丢失为通用的 1066。

## 分配器设计验证

分配器策略：

- 业务 API 按分配大小归类，而不是按对象类型归类。
- 小分配使用自适应 slab 后备：4K/8K/16K/32K/64K。
- 超过小对象阈值的分配使用 area。
- 核心/存储代码不直接调用 VirtualAlloc。
- VM 原语集中封装在 `memfs_vm` 后端。

当前大小等级池有 16 个内部并发 lane。它们不是独立节点/名称/通用池，而是划分 slab 所有权以避免单热点锁；空 slab 仍会立即归还 VM 后端。

与此前 8-lane 布局进行三轮 A/B 基准，16 线程时 64 字节分配/释放吞吐提高约 114%，4 KiB 吞吐提高约 209%，单线程性能基本不变；代价是每个文件系统增加约 12 KiB 分配器状态元数据。

分配器另有未初始化快速路径，供首次读取前会完整覆盖的缓冲区使用。类型化 node/dir/page_group 分配和常规清零 API 仍保证零初始化。测试确保 slab/area 重用不会让要求清零的调用方看到旧数据。

之后将每节点元数据由 136 字节降为 128 字节，没有打包字段或移除缓存目录名称哈希。这使每个 `MemfsNode` 从 192 字节等级降至 128 字节等级，每个活动文件/目录节点节省 64 slab 字节。原存储的 64 位 `index_number` 改为每个文件系统独立播种、由节点地址派生的稳定不透明 ID；节点生命周期内文件 ID 稳定，加密 AAD 使用同一派生标识。Debug/Release 测试、10 秒压力测试，以及纯/压缩/加密/组合实际挂载集成都通过。

未压缩的普通整页也已重构：逻辑 4 KiB 页直接使用分配器 4096 字节等级，不再为 4096 字节数据加 8 字节 `MemfsPage` 头部，导致 4104 字节请求被提升到 8192 字节等级。原始页用带 tag 的对齐指针表示；压缩/加密页仍使用结构化 `MemfsPage`。现有原始页可原位覆盖；全零写仍为稀疏；新页使用两阶段编码/提交以保证回滚安全。一个普通整页的驻留后备现为 4096 字节，而此前为 8192 字节。

为避免 16 个 slab lane 在重复相同负载时抬高分配器高水位，大小等级池新增原子可用分片位图。线程优先使用本地 home shard；本地无可用容量而准备新 slab 前，只探测声明有空闲对象的 lane，并跨 shard 复用容量。同一时刻最多持有一把 shard 锁。8 轮碎片/复用基准不再增加 slab 后备；最终 scavenging 回到基线；分配器多线程基准错误数为零；10 秒压力测试提交/私有内存漂移为零。

Area cache 保留策略按大小区分，不再让每 lane 统一保留两个空闲区。小 area 块仍保留两槽 lane cache；超过 64 KiB 的 VM 区域每 lane 至多缓存一个块。在 64 KiB 分配基准中，16 线程保留的缓存后备从约 1,392,640 字节降至三轮中位数：清零模式 696,320 字节、未初始化模式 765,952 字节。未初始化模式 16 线程吞吐基本持平，约 38.4M ops/s，基线为 38.7M；清零吞吐变化在几个百分点内。Debug/Release 测试、10 秒压力测试和真实挂载集成都通过。

## 自动容量可用内存样本缓存

最终 task-66 审查在接受该优化前修正三项问题：

- 强制刷新可能在旧 deadline 仍有效时覆盖样本字段。现在完整快照都由同一 SRW 锁读取/发布，不再使用无关的原子字段。
- 旧的净提交基线在 OS 查询后采样。现在先采样总成功提交量；查询期间增长以及释放/重分配流量会保守扣减。
- TTL 现在从 OS 查询前开始。常规 Debug 也使用缓存；另建独立 NDEBUG 测试程序确定性覆盖真实生产路径，不在 memfs.exe 中启用测试钩子。

2026-10-01 的五次 Release 测量：

| 指标 | 最终正确性修复前 | 最终正确性修复后 |
| --- | ---: | ---: |
| 自动容量增长中位数 | 63.9 ns | 62.6 ns |
| 固定容量增长中位数 | 27.8 ns | 27.7 ns |
| 原先未缓存的自动容量增长（历史基线） | 347.3 ns | — |

修复前后的小差异处于正常微基准波动范围；正确性修复保留缓存带来的性能收益，并不声称又取得明显加速。公开额度查询仍使用实时 OS 样本。系统内存会在样本读取与分配之间变化，因此缓存不是对无关进程的硬性内存预留。

Debug/Release 均通过 19/19 CTest。专用生产路径测试包含 200,000 次缓存读取与 20,000 次发布的并发竞争，以及过期/强制刷新/慢查询老化、总提交扣减、无数据丢失的压力拒绝和压力缓解的确定性测试。

挂载集成现在检查多页逐字节 I/O、跨页覆盖、截断/扩展零填充、稀疏空洞、不区分大小写的查找和通配符枚举。测试无控制台启动，并且只有正常关闭、退出码为零、DOS 设备已删除才报告 PASS。强制终止只作为清理，不算通过。另确认故意错误的 CLI 启动会让集成测试失败，不会产生假 PASS。

## 最终生命周期正确性审查

2026-10-01 的扩展验收首先发现组合模式真实挂载偶发目录故障。之后通过有限的新子进程复现，捕获到安全描述符复制中的原生访问冲突。原失败报告和崩溃转储均保留；成功重试不算修复。

WinFsp FINE 允许共享 FILE_OPEN 回调，并且 Close 可异步到达，不受命名空间操作 guard 保护。因此先前普通的 `open_count++/--` 和共享孤儿链表修改存在竞态。新加入的旧核心回归立即观察到引用数仅为 44,528，而预期为 160,001。

现由每文件系统专用的 8 字节生命周期 SRW 锁协调句柄计数、unlink/替换回收和孤儿链表移除。节点仍为 128 字节；普通文件数据读写不获取这把锁。只有最终有效引用释放且命名空间所有权已消失后才会在锁外销毁。多线程测试现在会执行 unlink-before-close，而不是错误地避开孤儿转换。此前一个在最终 Close 后读取节点的测试也已修正。

SetSecurity/GetSecurity 回调还使用独占/共享保护，避免与 FINE 下的命名空间描述符借用冲突。Create/Open 已持有 guard 时，GetSecurityByName 不得递归获取 guard。回调测试覆盖被阻塞的描述符替换，以及 2,000 次替换与 20,000 次校验读竞争。生命周期测试验证精确并发计数，以及最终 close、unlink/close、replace/close 竞争后分配器 live 字节回到基线。

修复版本晋升前，仍须在新鲜挂载上重复运行并通过完整验收。上述改动修复了已确认的同步缺陷，但不代表测试能证明不存在所有可能的文件系统缺陷。

## 硬件 AES-GCM 加密快速路径

libsodium 报告支持硬件 AES-GCM 时，加密页现在自动使用 AES-256-GCM；否则保留 XChaCha20-Poly1305 作为可移植回退。逐页 `MEMFS_PAGE_AES_GCM` 标志纳入 AEAD AAD；解码依据经过认证的页面标志，而不是当前编码器偏好选择算法。

固定/复用主密钥可安全跨挂载：每次挂载生成随机 128 位前缀；AES-GCM 使用主密钥及该前缀派生独立挂载根密钥，并且每加密 `2^20` 个 blob/页后派生新 epoch 密钥。全局 64 位 nonce 序号在所有加密写入者间保持单调且唯一。XChaCha 保留主密钥，并将 128 位挂载前缀与同一序号组成 192 位 nonce。

测试覆盖硬件自动选择、强制 XChaCha 回退、单次挂载中混合 AES/XChaCha 页面、算法标志篡改、密文篡改、挂载密钥隔离、覆盖/截断/扩展、压缩+加密及并发 nonce 分配。

本机 Release `memfs_bench --encryption` 五轮，与改动前立即记录的 XChaCha 基线比较：

| 负载 | XChaCha 基线 | AES-GCM 中位数 | 变化 |
| --- | ---: | ---: | ---: |
| 4 KiB 创建+写入 | 196,507 ops/s | 306,789 ops/s | +56.1% / 1.56x |
| 随机 4 KiB 覆盖 | 64,993 ops/s | 133,763 ops/s | +105.8% / 2.06x |

专用加密改写基准还从精确的改动前提交 `af3dc50` 重建 XChaCha 版本，并在同一机器和当前 AES-GCM 路径比较：

| 线程数 | XChaCha `af3dc50` | AES-GCM | 加速比 |
| ---: | ---: | ---: | ---: |
| 1 | 175,527 ops/s | 578,177 ops/s | 3.29x |
| 2 | 328,743 ops/s | 1,023,758 ops/s | 3.11x |
| 4 | 651,550 ops/s | 2,057,334 ops/s | 3.16x |
| 8 | 969,836 ops/s | 2,869,890 ops/s | 2.96x |
| 16 | 1,480,658 ops/s | 3,821,251 ops/s | 2.58x |

所有多线程运行错误数为零。为避免每次写入都执行 KDF 且避免无限保留密钥，文件系统只在一把 SRWLOCK 保护的缓存中保留最新 AES epoch 密钥。读取旧 epoch 时按需派生临时密钥；没有线程本地或多 epoch 密钥缓存。

## 可重复部署验证

`scripts\verify-deployment.ps1` 将安全的开发机检查与具有破坏性的干净机器备用驱动检查分开。

当前 x64 开发机验证命令：

```powershell
.\scripts\verify-deployment.ps1 -Scenario All -Report .agent\deployment-current.json
```

2026-09-30 的结果：

- Release 可执行文件/CLI 门禁：通过；
- 驱动/静态版本/无 WinFsp DLL 导入/资源 CTest 门禁：通过；
- 不存在 `MemfsC` 服务：通过；
- 挂载前不存在私有 `WinFsp+MemfsC` 备用服务/文件：通过；
- 使用官方 `WinFsp+20251221T124141Z` 的真实挂载盘冒烟测试：通过；
- 使用官方驱动挂载后不存在私有备用服务/文件：通过；
- 私有备用驱动执行：默认跳过。

还显式验证了防护逻辑：

```powershell
.\scripts\verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback
```

本机因为检测到官方 WinFsp SxS 驱动而 fail closed。脚本不会仅为测试回退路径，就删除、停止、覆盖或重定向官方 WinFsp 安装。

剩余的干净虚拟机验证必须明确执行，不以模拟结果替代。在未安装 WinFsp 的一次性提升权限 Windows 虚拟机上运行：

```powershell
.\scripts\verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback -Report C:\temp\memfs-private-fallback.json
```

测试工具会验证私有服务创建、MemfsC 所有的驱动文件名/路径、真实挂载盘 I/O 冒烟测试和卸载清理。若检测到官方 WinFsp 驱动则拒绝运行该场景。

## 当前二进制

不要使用本文硬编码的 EXE 哈希。当前包中的 `dist/memfs-x64/BUILD_PROVENANCE.json` 和 `SHA256SUMS.txt` 绑定精确源码 revision、工具链、嵌入驱动输入和可执行文件。只有该 revision 对应的通过报告也验证这些哈希后，包才可接受。即使之后独立复现成功，失败的验收仍保留为失败记录。

## 便携式验证交接

`scripts/package-validation-kit.py` 仅在真实验收报告通过，且验收构建 EXE 与包中 EXE 完全一致时，才生成诊断包。该包可在另一台没有 CMake、vcpkg 或编译器的 Windows 机器上运行对应的 20 项 Release 测试。内容包括签名驱动参考文件、测试二进制、脚本、源码守卫输入、严格 SHA-256 manifest，以及复制的宿主验收/来源记录。干净客体和 ARM64 说明见 `docs/PORTABLE_VALIDATION.zh-CN.md`。

后续仅文档/交接修改的 revision 可通过 `--extended-report` 与原完整验收关联，但必须先在当前 HEAD 通过新的验收、EXE 哈希匹配、测试注册不变，并确认未更改任何编译/运行/构建输入。两个报告都保留各自 revision，不能重新标注旧运行。失败的扩展运行不能用于生成验证包。

## 发布打包

`scripts\package-release.ps1` 创建单一 x64 用户态发布目录 `dist\memfs-x64`，包含：

该 x64 包也用于 Windows 11 ARM64；没有单独的 ARM64 用户态构建。

- `memfs.exe`
- `BUILD_PROVENANCE.json`
- `THIRD_PARTY_NOTICES.md`
- `licenses/WinFsp-License.txt`
- `licenses/libsodium.txt`
- `licenses/zstd.txt`
- `SHA256SUMS.txt`

打包是发布门禁，不是简单复制。它拒绝受跟踪文件有改动的源码树，要求 Release/x64-static CMake 缓存，重建构建目录、运行完整 CTest 套件、写入 `BUILD_PROVENANCE.json` 并立即根据当前文件/工具链校验；全部通过后才原子发布暂存目录。

安装包刻意附带第三方许可证原文，而不是以改写文本取代权威法律条款。静态 WinFsp 构建也受 `THIRD_PARTY_NOTICES.md` 中的发布门禁约束：本地 WinFsp 源码树中的 FLOSS 例外只说明平台 DLL 链接，而此构建静态链接 WinFsp 用户态代码。专有分发前必须作出适当许可决定。

## 仍待完成的产品化事项

广泛对外分发前还需独立验证：

- 最终 EXE 的代码签名策略；
- 静态链接场景下的最终 WinFsp 分发许可决策（专有分发应取得合适的商业许可，或采用符合适用 WinFsp/GPLv3 义务的分发条款）；
- Windows 10/Windows 11 干净机器安装；
- 在 Windows 11 ARM64 上通过 x64 仿真运行单一 x64 `memfs.exe`，包括选择/安装内嵌 ARM64 内核驱动；
- 与明显更旧/更新的官方 WinFsp 安装共存，同时保留现有私有服务隔离规则；
- 真实操作系统重启后的服务恢复（异常进程终止已由自动测试覆盖）；
- 无 WinFsp 安装的干净机器上验证内嵌驱动回退，可使用已纳入版本控制的 `verify-deployment.ps1 -Scenario PrivateFallback -ExercisePrivateFallback`。
