# NTFS 临时目录兼容性与部署记录

日期：2026-10-14。此文记录已实现功能、实际测试以及仍存在的边界；不是完整 NTFS 实现声明。

## 当前版本（2026-10-14 后续升级）

当前已升级至 WinFsp 2.2 Beta5 私有内嵌驱动，旧安装已卸载，MemfsC 已重新部署并验收。此次服务重启没有恢复任何文件；旧内核映像残留尚待后续 Windows 正常重启后复查。最新状态、37 项 Debug/Release 测试、来源和限制见 [WinFsp 2.2 升级说明](WINFSP_2_2_UPGRADE.md)。下面的 08:32 部署、旧哈希、恢复文件及 2.1 驱动信息是此前阶段的历史记录，不代表当前配置。

## 历史部署状态（08:32）

新版已替换 `C:\Windows\System32\memfs.exe` 并重启 `MemfsC`。本次切换于本机时间 2026-10-14 08:32:15–08:32:19（UTC+08:00）完成；原进程 60080，新进程 52420。

保留原服务配置：

```text
"C:\Windows\System32\memfs.exe" --service --mount M: --size auto --compress --mkdir tmp
```

部署的 EXE SHA-256：

```text
4B94C2BA3EAFA7C801EC391BECCC59ABDCF20CB6C67EF553122D14400C956418
```

运行时实测文件系统名称 `NTFS`，能力标志 `0x0004000e`（包括持久 ACL 与命名流）。原有用户级 TEMP/TMP 保持 `M:\tmp`；机器级 TEMP/TMP 仍为 `C:\WINDOWS\TEMP`。此次没有修改环境变量，也没有安装、更换或重新启动全局 WinFsp 内核驱动。

生产挂载重启后，使用实际 `M:\tmp` 下的唯一测试子目录再次执行原生探针：734 项检查通过；Python 严格路径解析、ZIP 解压、SQLite WAL 和子进程临时目录测试通过。根目录文件 `moe_ue_all.h` 已从备份恢复，其 SHA-256 与重启前完全一致。

## 1. “无法识别文件系统”并不只是名称问题

卷名由 `MEMFS-C` 改为准确的 `NTFS`，兼容部分程序的文件系统名称检查。但实际 Python 工作负载进一步复现了：名称已经是 NTFS 时，`Path.resolve(strict=True)` 仍报 WinError 1005。

原因是 WinFsp 的普通 `X:` 挂载使用 DOS device link，并未注册到 Windows Mount Manager。现在 `memfs_winfsp_mount` 将裸盘符挂载转换成 WinFsp 的 `\\.\X:` 挂载形式，使用 Mount Manager 注册卷。保持外部 CLI `--mount M:` 不变；目录挂载及已经显式指定的挂载形式没有做这种自动转换。

该模式创建全局可见盘符，需要提升权限或 LocalSystem。没有在失败时静默退回无法通过路径解析的旧模式。测试明确检查 `GetVolumeNameForVolumeMountPointW`、`GetFinalPathNameByHandleW` 的 DOS/GUID 形式，以及 Python 严格路径解析。

官方说明：<https://github.com/winfsp/winfsp/issues/410>。

## 2. ACL 与描述符

项目本来已有 ACL 回调，但默认权限、自动继承和所有者回写存在缺口。现在根目录和内部 `--mkdir` 引导目录使用：

```text
O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)(A;;0x1201bf;;;AU)
```

SYSTEM、Administrators 获得可继承完全控制；CREATOR OWNER 为创建者生成子对象权限；Authenticated Users 仅在共享引导目录获得读、遍历、创建等权限，不把这一授权传播到别人的普通文件。没有用 Everyone 全卷完全控制替代权限实现。

普通 WinFsp 创建通过原始客户端描述符和令牌调用 `CreatePrivateObjectSecurityEx`，启用 DACL/SACL 自动继承，并把实际保存的描述符回填到 WinFsp 创建响应，避免内核缓存旧式继承结果。显式权限、受保护 DACL、继承标记和拒绝 ACE 均有测试。

核心存储验证描述符并将 absolute SD 转为独立拥有的 self-relative SD；不会保存调用者提供的外部指针。保留共享引用计数和分配失败时的原子替换行为。

对相同所有者的原值回写识别为无效变更，修复 1307 错误；句柄本身仍必须满足 Windows 的权限检查。`Get-Acl` / `Set-Acl` 原所有者和组回写，以及 `icacls` 传播、保护、reset、verify、save/restore 均通过。

**不同所有者 SID 的实际转移仍有限制。** 当前 WinFsp 2.1 SET_SECURITY 请求不带客户端令牌，本实现没有使用服务 SYSTEM 身份或关闭所有者检查来假装成功。这类请求仍可能得到 `ERROR_INVALID_OWNER`（1307）。

## 3. Zone.Identifier / ADS

现在真正实现命名 `$DATA` 流，而不是忽略 Zone 请求或清除下载来源标记。支持 `file:Zone.Identifier`、大小写别名、显式 `:$DATA` 后缀、默认流 `file::$DATA`、目录数据流和创建流时隐式创建主文件。

流共享所属文件的 ACL、时间戳、属性与对外文件 ID，拥有独立内容、长度、分配大小和压缩/加密存储。主文件大小不包含 ADS；改名文件或祖先目录会保留流；删除流不删除主文件；删除主文件会正确处理全部流。

实现保留普通 `MemfsNode` 的 128 字节布局。流索引位于文件系统对象的 64 个桶中，以稳定的所属节点身份索引，而不是依赖文件名；只有实际存在 ADS 时才需要额外节点。流节点持有所属节点的引用，以支持删除主文件后旧流句柄继续读写。流的 ACL 始终引用所属对象当前的描述符，不保留过时 ACL 副本。

覆盖主文件时，NTFS 会删除已关闭的流；仍打开的流处于删除等待状态，依旧可枚举和通过已有句柄读取，新打开会被拒绝，最后 Cleanup 后消失。新增活动打开计数区分 Cleanup 与可能延迟的 Close，并关闭 `PostCleanupWhenModifiedOnly` 优化以跟踪只读句柄的 Cleanup。测试覆盖缓存过期后旧流不得复活。

同一所属文件及其流共用 I/O 锁，不同所属文件仍可并发。补充 WinFsp `GetStreamInfo`，不把 ADS 混入普通目录枚举。

测试使用 Windows `PersistentZoneIdentifier` COM 对象实际保存并重新加载 Internet 区域标记 `ZoneId=3`。还验证 NTFS → memfs → NTFS 双向复制精确保留 Zone.Identifier 与主数据，覆盖 PowerShell `-Stream`、`Get-Item -Stream *` 和 `dir /r`。没有关闭或规避 SmartScreen、附件管理器或区域检查。

## 4. 实测结果与重现

本机：Windows 11 专业版 x64，10.0.26300；clang-cl 22.1.3、CMake/Ninja、静态 CRT/vcpkg；匹配 WinFsp 2.1 静态运行库与已安装签名驱动 2.1.25156.ddca7bd。

| 验证 | 结果 |
| --- | --- |
| `build/acl-release` 完整 CTest | 36/36 通过，无跳过 |
| `build/acl-debug` 完整 CTest | 36/36 通过，无跳过 |
| 原生临时目录探针 | 普通、压缩、压缩加密及独立 LocalSystem 挂载均通过 |
| 已部署的 M: 生产服务 | 734 项原生断言通过，并通过 Python/SQLite 工作负载 |
| 原有实际挂载 I/O 集成测试 | 普通、压缩、压缩加密三种模式通过 |
| NTFS 差分 | 23 类比较，19 类结果完全一致，4 类明确的签名驱动边界，无未解释差异 |
| ADS 生命周期压力 | 每种构建/存储模式 8 线程、1,024 次创建/写入/改名/删除/孤儿句柄读取循环 |

探针还覆盖临时文件名、CREATE_NEW 冲突、共享冲突、字节范围锁、ReplaceFile、删除时机、稀疏文件、截断/扩展零填充、内存映射、EXE 运行、DLL 加载、受限令牌隔离、8 线程 800 次流写读，以及 300 次 ACL 替换与 600 次并发 ACL 查询。

真实工作负载包含 ZIP 解压并逐字节校验 16 个文件、两个 SQLite WAL 连接写入/读取 1,000 行、`integrity_check` 和 checkpoint，以及子进程 TEMP/TMP 发现。

差分程序默认严格要求 NTFS 相同；CTest 显式传入 `--allow-known-winfsp-limits` 接受下节列出的精确已知差异。新增结果或错误仍失败，报告中 `strict_ntfs_match` 为 false。**CTest 全通过不表示已经与 NTFS 完全等价。**

```powershell
cmake --build build/acl-release -j 8
ctest --test-dir build/acl-release --output-on-failure
cmake --build build/acl-debug -j 8
ctest --test-dir build/acl-debug --output-on-failure
```

测试盘符现在可由 CMake cache 配置，避免不同构建树并行测试互相占用。本次 acl-* 构建使用 Q:/P:/S:/O:，原有 I/O 脚本使用 L:；默认仍为 T:/U:/V:/W:。测试不停止现有生产卷，独立服务名称带 GUID；未运行官方 WinFsp 驱动或不具备所需服务权限时明确跳过。

报告：

```text
build/acl-release/tests.xml
build/acl-debug/tests.xml
build/acl-release/ads-differential-{plain,compressed,encrypted}.json
build/acl-debug/ads-differential-{plain,compressed,encrypted}.json
build/acl-release/integration-summary.log
build/acl-release/NTFS_TEMP_VALIDATION.json
```

## 5. 尚存的明确边界

NTFS 差分记录的四项差异：

1. 使用原生 FileRenameInformation 重命名 ADS，NTFS 成功，当前 WinFsp 签名驱动拒绝；仅加入用户态回调无法解除内核限制。
2. ADS 句柄仍打开时改名主文件，部分 NTFS 成功的情形在 WinFsp 2.1 返回拒绝访问。
3. 某些 255 字符流名在 NTFS 成功，但 WinFsp 2.1 将 `base:stream[:$DATA]` 合计计入末尾组件长度而拒绝；测试没有虚报更大的文件名能力来绕过。
4. 无效流类型均被拒绝，但 WinFsp 返回错误 123，NTFS 返回错误 87。

此外，本轮未实现完整重解析点、符号链接/junction、硬链接等 NTFS 功能；不同所有者转移限制见上文。交互式 UAC、实际 MSI 安装器、所有 AppContainer/低完整性沙箱及开机前期服务依赖尚未全部验证。安全标签存取通过不等于所有沙箱行为通过。

**依赖安全问题仍需单独处理。** 此次未升级 WinFsp 2.1 内核。WinFsp 官方 2026 版本发布记录列出了 CVE-2026-3006、CVE-2026-7162 等安全修复；这些不是本轮用户态改动能修复的漏洞。不能把功能测试通过视为驱动漏洞修复。升级需要匹配静态运行库、x64/ARM64 签名驱动和项目来源门禁，并评估对机器上其他 WinFsp 挂载的影响。

官方发布记录：<https://github.com/winfsp/winfsp/releases>。

所有卷内容仍易失，服务停止、异常或重启后消失。需要跨重启继续安装、回滚、恢复的数据不适合放在此卷。未修改机器级 TEMP 或开机服务依赖，因此不能声称所有系统服务从开机起都能使用 M:。

## 6. 备份、恢复和回滚资料

本次受保护备份目录：

```text
D:\work\fs\memfs\build\deployment-20261014-082659-1542ee92
```

包含旧 EXE、新版已验证 EXE、服务和环境快照、可读取的旧卷文件、备份日志、部署记录以及生产挂载复测日志。

备份复制了 1,881 个文件（约 735.89 MiB）。**58 个被程序独占的临时文件/日志无法复制（错误 32），所以这不是完整备份或一致性快照。** 未强制结束持有文件的客户端进程。旧 `tmp` 的可读内容保留在磁盘备份中，没有把旧的错误 ACL 和全部缓存重新铺回新卷；需要的旧文件可从 `volume\tmp` 查找。任何未备份且仅位于旧 RAM 卷的内容会随本次已授权重启丢失。

根目录非临时文件 `moe_ue_all.h` 已恢复并恢复其 DACL，重启前后 SHA-256 均为：

```text
E0174E9E00158FD71ABF93DA8F5390A36D4D17333EF3EDC3F6941154D2F88328
```

部署脚本只停止/启动 `MemfsC`，保留服务命令行，不重装共享驱动。它在切换前检查旧 PID、旧 EXE 和重要文件哈希，隔离自身进程的临时目录；新版本启动或复测失败时提供旧 EXE 回滚路径。此次结果为 `deployed-and-validated`，没有触发回滚。

正在运行的软件不能把旧卷句柄自动转换成新卷句柄。重启后仍遇到临时文件错误的软件，需要关闭并重新打开。


## 7. 部署后的独立复核

另在 `build/ntfs-release`、`build/ntfs-debug` 两套构建中运行完整 CTest，均为 36/36 通过且没有跳过。跨进程测试盘互斥用于避免不同构建树的验证相互占盘。运行时的 NTFS 差分仍明确记录 19/23 完全一致、4 项精确已知驱动差异；没有把这些差异标为 NTFS 等价。

切换前的 PID/EXE 快照保护发现同一维护期间服务已被部署流程更新到 PID 52420，因此独立部署步骤在停止服务前安全退出，没有重复清空 M:。随后直接验证现有生产服务：734 项原生检查、2,048 次多线程 ADS 生命周期循环、NTFS 双向 Zone 数据复制及 Python/SQLite 工作负载均通过。该复核使用唯一测试子目录，并在结束时删除这些测试文件，没有修改生产目录的 ACL。

额外复核资料：

```text
build/ntfs-release/LIVE_NTFS_VALIDATION.json
build/ntfs-release/tests.xml
build/ntfs-debug/tests.xml
build/service-backup-20261014-083026/live-ntfs-differential.json
build/service-backup-20261014-083026/live-full-probe.log
build/service-backup-20261014-083026/live-workloads.log
```

独立的受保护备份位于 `build/service-backup-20261014-083026`：该次快照复制了 1,881 个文件，另有 56 个临时文件因共享冲突未复制。与部署流程记录的 58 个失败文件是不同时间的快照，不应把两份非一致性快照拼成“完整备份”。两份备份中的根目录头文件与目前 M: 上的文件 SHA-256 一致。
