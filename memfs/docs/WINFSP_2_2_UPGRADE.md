# WinFsp 2.2 Beta5 内嵌驱动升级与验收

日期：2026-10-14。此记录取代 TEMP_COMPATIBILITY.md 中关于当前 WinFsp 2.1 部署状态的描述；早前的功能设计与历史测试记录仍保留。

## 当前结论

MemfsC 已部署使用 WinFsp 2026 Beta5（2.2.26286.14d6e02）的新版 EXE，正式 M: 卷通过上线后的功能验收。官方 WinFsp 2025 MSI、旧共享驱动的服务注册和 Launcher 已卸载，新 MSI 没有安装。现在使用 memfs.exe 内嵌的 Microsoft 签名 SYS，以及从完全匹配源码重新编译的静态用户态运行库。

**仍需区分“卸载注册”与“旧映像完全离开内核内存”。** 最终 EnumDeviceDrivers 检查还能枚举到旧 SxS 驱动映像，同时也能看到新的私有 SYS。旧服务已不存在，新 MemfsC 使用绑定的私有设备，不再使用旧全局驱动。旧映像可能仍受旧文件对象等引用影响，本次没有确诊引用持有者，也没有强制结束其他应用。要彻底清理旧映像，后续正常重启 Windows 后应再次检查；本次没有重启操作系统，不能把旧映像残留描述成“已完全卸载出内存”。详见验收目录的 loaded-driver-modules.json。

用户已明确允许内存卷在服务重启时清空，此次没有备份或恢复 M: 中任何文件。新服务启动时根目录只有 tmp；早前的 moe_ue_all.h 未恢复。运行中的应用之后可能重新创建临时文件，所以不承诺卷会持续为空。

## 版本与来源

| 项目 | 值 |
| --- | --- |
| 官方发行 | WinFsp 2026 Beta5，标签 v2.2B5，预发布版 |
| 官方发布时间 | 2026-10-13 |
| 完全匹配源码提交 | 14d6e0280ae15e2550c44d6dbc476be51649727f |
| x64 / ARM64 SYS FileVersion | 2.2.26286.14d6e02 |
| 运行时版本 | FspVersion() = 0x00020002，即 2.2 |
| 私有 SxS 标识 | MemfsC |
| 用户态构建 | clang-cl 22.1.3，x64 静态 WinFsp，Debug / Release |
| 内核 SYS | 直接使用官方签名二进制，未改写、未自行重签 |

SYS 源文件位于 dist/winfsp-2.2.26286-beta5/drivers/。

```text
winfsp-x64.sys
SHA256 0A91FC3429FD5ADF8B9C65976AC0C4AE924702BE2CFBED856D90D2A7D99B0390

winfsp-a64.sys
SHA256 0214FA19EA744F6C3BC795EA3937D42D43CBCAB089F781EC038393E3B3420204
```

两个 SYS 的架构、版本和 Microsoft Windows Hardware Compatibility Publisher Authenticode 签名均已验证。这里的“重新编译 WinFsp”指重编译静态用户态运行库，不以无官方签名的自编 SYS 替代内核驱动。

源码工作树：

```text
D:\src\winfsp-memfs-2.2B5-private-092109
```

此工作树 HEAD 为上述官方提交；本地适配包括 FSP_API 静态链接、FspVersion 静态版本、私有 SxS 绑定，以及 FUSE3 中 struct fuse_args 的文件作用域前置声明。没有改写上游文件系统安全检查或内核代码。

上游代码有 MSVC 接受而 clang-cl 22 默认当成错误的 DWORD/UINT32、typed-pointer/void-pointer 输出参数诊断。构建脚本仅为第三方 WinFsp 构建保留 `-Wincompatible-pointer-types` 为警告（`/clang:-Wno-error=incompatible-pointer-types`），并保留日志；不是无警告构建。memfs 本身的原有编译选项没有因此放宽。

## 私有驱动加载路径

```text
C:\Windows\System32\memfs.exe
  ├─ 静态 WinFsp 2.2 用户态运行库
  ├─ RCDATA 102：官方 x64 SYS
  └─ RCDATA 103：官方 ARM64 SYS
           ↓ 首次提取、注册、启动
C:\Windows\System32\drivers\memfs-winfsp-x64.sys
           ↓
WinFsp+MemfsC（SERVICE_FILE_SYSTEM_DRIVER / 按需启动）
```

所谓内嵌 SYS 是由 EXE 携带并在需要时提取为驱动文件，再交由 Windows SCM 加载；不是把内核驱动当作普通用户态 DLL 直接从内存执行。

静态运行库的 FspSxsIdent 返回 MemfsC，对服务名、控制设备名和版本查询进行一致绑定；不会枚举并选择机器上其他 WinFsp 版本。memfs 启动路径及静态版本单元测试均验证这一标识。正常服务重启复用已经加载的匹配私有驱动，不需要 WinFsp MSI、Launcher 或 winfsp-x64.dll。

CMake 配置还验证源码提交与 SYS FileVersion 中的提交后缀一致，两种架构的 SYS 版本与签名匹配。预设固定本地源码和内嵌 SYS 输入，因此卸载旧 WinFsp 安装包后仍能编译。

## 实际切换过程

1. 编译匹配的 WinFsp Debug/Release 静态库与 memfs。先完成不挂载卷的 27 项测试。
2. 尝试并行加载新版时得到 STATUS_OBJECT_NAME_COLLISION（0xC0000035）。源码检查确认新旧驱动会建立同名全局控制设备符号链接，不能同时活动。
3. 停止旧 MemfsC，按用户要求丢弃旧卷，不恢复文件。
4. 通过原 MSI ProductCode `{C79D9B29-3AF0-45B3-9DB9-226F3C2D2204}` 执行静默卸载、禁止自动重启。msiexec 返回 0；旧共享驱动服务及 Launcher 消失。
5. 使用带嵌入资源的 memfs_winfsp_probe 成功创建/销毁测试卷，私有 SYS 成功启动，SxS 标识为 MemfsC。SYS 文件哈希与 EXE 资源逐字节来源一致。
6. 在新的私有驱动上完成 Debug / Release 全部 37 项 CTest。
7. 部署已验收 Release EXE，启动正式 MemfsC。在实际 M:\tmp 上重复原生与应用工作负载验收。
8. 检查运行中 EXE 模块，没有加载任何 winfsp*.dll。额外检查内核模块列表，记录旧映像残留，不隐瞒这一边界。

此次最终部署完成于本机时间 2026-10-14 09:34:51（UTC+08:00）。最终验收时 MemfsC PID 为 32688；后续服务重启会改变 PID，应以实时 SCM 查询为准。

已部署 EXE 的 SHA256：

```text
A7FC36EBC2D06278C9ED547BBACFA2ED280BDA53B904C37A83F488321823E1E0
```

服务参数保持：

```text
"C:\Windows\System32\memfs.exe" --service --mount M: --size auto --compress --mkdir tmp
```

用户级 TEMP/TMP 仍为 M:\tmp；机器级仍为 C:\WINDOWS\TEMP。构建和切换期间仅为运维子进程临时指定磁盘上的 TEMP/TMP，没有修改系统或用户环境变量注册表。

## 验收结果

| 验证 | 结果 |
| --- | --- |
| Release CTest | 37/37，通过，0 跳过 |
| Debug CTest | 37/37，通过，0 跳过 |
| 正式 M: 原生探针 | 734 检查，0 失败 |
| 普通、压缩、压缩加密卷 | 均通过临时目录及 ADS 测试 |
| LocalSystem 隔离服务 | 创建、停止、重启、卸载与 I/O 通过 |
| Zone.Identifier | 读写、枚举、双向 NTFS 复制、Windows COM 持久化通过 |
| ACL | 自动继承、保护、拒绝 ACE、权限撤销、并发查询/修改、原所有者回写通过 |
| 路径/映像 | Mount Manager GUID、最终路径、Python 严格解析、EXE 运行、DLL 加载通过 |
| 应用负载 | ZIP 16 文件哈希验证，SQLite WAL 1000 行/双连接/完整性检查/checkpoint，子进程 TEMP 发现通过 |
| ADS 差分 | 23 类比较：19 类完全相同，4 类已知精确差异，无意外差异 |
| ADS 生命周期压力 | 各构建/各模式 8 线程、1024 次循环，通过 |

挂载验收不再依赖“机器已安装官方 WinFsp”这一旧条件，而是检查已运行的私有服务，其配置的 SYS 哈希必须与被测 EXE 的嵌入资源一致，并验证 Microsoft 签名。测试本身不会安装、升级或停止驱动。未准备好私有驱动时明确返回 77，不能冒充已经通过。

文件哈希和配置路径本身不是对内核内存的哈希。此次还记录了成功启动新私有服务的过程、绑定的 SxS 标识和内核已加载模块路径，避免只看到文件更新就宣布运行版本已更新。

## 保留的兼容性与安全边界

Beta5 中重新实测，以下四项差异没有因升级而消失：数据流原生重命名、部分主文件在数据流句柄打开时的改名、255 字符流名与主文件名合并长度限制、非法数据流类型的错误码。差分测试中按精确预期单独报告；默认严格差分仍会将这些差异视作不等价。

不同 SID 的实际所有权转移仍有上一轮记录的限制；memfs 尚未实现完整重解析点、符号链接/junction 等功能。没有实测所有第三方安装器、全部沙箱和交互式 UAC，因此不是完整 NTFS 兼容保证。

官方 Beta5 发布说明包含 CVE-2026-3006、CVE-2026-7162 等修复，以及内存压力缓存写入、并发改名通知、强制卸载命名流的死锁修复。版本本身仍是预发布版。该信息不等于本项目对所有漏洞进行了独立复现或审计，也不等于旧内核映像残留已经消失。

## 构建与证据位置

```text
build\private-beta5-release\memfs.exe
build\private-beta5-debug\memfs.exe
build\private-beta5-release\tests.xml
build\private-beta5-debug\tests.xml
build\winfsp22-upgrade-final\UPGRADE_VERIFICATION.json
build\winfsp-upgrade-20261014-092750\before.json
build\winfsp-upgrade-20261014-092750\uninstall-winfsp21.log
build\winfsp-upgrade-20261014-092750\acceptance.json
build\winfsp-upgrade-20261014-092750\loaded-driver-modules.json
build\winfsp-upgrade-20261014-092750\production-probe.log
build\winfsp-upgrade-20261014-092750\production-workloads.log
```

在 x64 Visual Studio 开发者环境中使用 CMakePresets；本次使用额外构建目录以保留历史产物：

```powershell
cmake --preset x64-release -B build/private-beta5-release `
  -DFS_FRONTEND_SOURCE_DIR=D:/work/fs/frontend `
  -DVCPKG_INSTALLED_DIR=D:/work/fs/memfs/build/x64-release/vcpkg_installed `
  -DMEMFS_TEMP_TEST_DRIVE=Q: -DMEMFS_TEMP_SERVICE_TEST_DRIVE=P: `
  -DMEMFS_ADS_TEST_DRIVE=S: -DMEMFS_INSTALL_TEST_DRIVE=O:
cmake --build build/private-beta5-release -j 8
ctest --test-dir build/private-beta5-release --output-on-failure
```

源码准备脚本会拒绝自动删除已存在的工作树。重新创建同一路径必须显式传 `-ReplaceWorktree`，并先自行保留需要的修改；它不应在普通增量构建前反复执行。新建另一个工作树可用 `-Worktree` 指定不同目录，并同步修改 CMake 输入。

## 后续服务重启约定

本项目此次维护后的运维默认：经用户授权重启 MemfsC 时允许清空内存卷，不执行卷文件备份或恢复；保留 --mkdir tmp 在启动阶段创建可用临时目录。其他应用持有的旧句柄不能迁移到新卷，必要时由用户正常重启这些应用。未经新的授权不自动重启 Windows，不强制结束用户其他应用。

官方参考：[WinFsp v2.2B5 发布说明](https://github.com/winfsp/winfsp/releases/tag/v2.2B5)。

## 最终复核补充

最终安装的 EXE 与 `build/private-beta5-release/memfs.exe` 的 SHA-256 相同。附加独立复核报告 `build/winfsp22-upgrade-final/UPGRADE_VERIFICATION.json` 记录安装产物、四组构建验收、实际 CMake 源码/静态库输入及内核已加载模块路径。

旧官方服务在 SCM/CIM 中已删除，但注册表仍保留 `DeleteFlag=1`、`Start=4` 的待清理项。旧驱动专属控制设备 `WinFsp.Disk+20251221T124141Z` 已不能打开（Win32 2），新 `WinFsp.Disk+MemfsC` 可打开；模块枚举仍能看到旧 SYS，故不能宣称旧映像已经完全从内核移除。MSI 日志还记录了延迟到重启的文件清理。当前 memfs 已使用新版驱动，不必为其功能生效立即重启；为了彻底清理旧组件，应在用户正常重启 Windows 后复核。本次不自行重启 Windows。

## 2026-10-14 下午更新部署（LastWriteTime 修复）

- 部署源码：`9da5bd8`（含 `55f8296` 的 LastWriteTime 修复；块设备模式需显式参数启用，正式服务参数未变）。
- 本机时间 2026-10-14 16:03:52 停止 MemfsC、替换 `C:\Windows\System32\memfs.exe` 并启动，M: 卷按授权清空，`M:\tmp` 由 `--mkdir tmp` 重建。旧 EXE（a7fc36…）备份于 `D:\tmp\memfs-deploy\memfs-a7fc36.exe`。
- 新 EXE SHA256：`DC4127C6CD26062650E8223B1F34F10D201E5012FBD9DE294565891B3DCC56C7`。
- 修复内容：写句柄未关闭时由其他句柄显式设置的 LastWriteTime，在写句柄清理时不再被覆盖为当前时间（与 NTFS 一致；SFTP 服务端 utime 上传场景）。部署后在 M:\tmp 上复验该行为，并以 M: 为 TEMP 通过 scrt 原生网络测试（含上传时间戳断言）。
- Release CTest：35 项通过；`memfs_temp_service`（8）与 `memfs_native_service_install`（37）超时。逐行跟踪确认两者卡在测试脚本的 `Get-CimInstance Win32_Service` 查询，本机该 WMI 类查询整体无响应（`sc.exe`、`Win32_SystemDriver`、`Win32_Process` 正常），重启 Windows 与重建 WmiPrvSE 后依旧；改动前的 `03905ce` 结果相同。该 WMI 问题尚未定位，两项需在 WMI 恢复后重跑。
