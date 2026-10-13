# 本地发布验收

发布验收脚本会将最终本机检查整理为一次可复现、失败即关闭的运行。脚本不会把跳过的检查、测试证书或无法使用 ARM64/干净虚拟机的环境视为生产就绪证据。

## 扩展本地运行

在已配置的 Windows x64 开发检出目录中，使用 64 位 PowerShell 执行：

```powershell
.\tests\release_acceptance_test.ps1
.\scripts\verify-release-acceptance.ps1 `
    -RepeatCount 50 -SoakMinutes 10 `
    -IncludeMounted -IncludeServiceRecovery -Package
```

挂载测试要求 DOS 设备 R: 空闲。服务恢复测试要求管理员权限、可用的官方 WinFsp 驱动，并且预先不存在 `MemfsC` 服务。如果目标挂载/服务已存在，测试会拒绝接管。服务测试只会故意终止**本次新建的测试服务**；文件系统是易失的，因此恢复后的存储应为空。脚本不会重启主机、修改 Windows 测试签名策略或给 EXE 签名。

验证范围包括：

1. Debug/Release 构建及完整注册的 CTest 套件。测试集为空视为错误，且必须注册生产容量快照测试。
2. 重复运行 Release 核心、多线程压力、生产容量快照、共享节点生命周期/孤儿状态转换和 WinFsp 安全快照测试。后两项是首次完整验收中发现的间歇性挂载崩溃的强制回归；仅靠重试不能算修复。
3. 运行 7 次容量微基准，记录每次结果及中位数。
4. 先运行短时间固定容量压力测试，再运行要求的 **10–60 分钟自动容量**压力测试。两者都使用已有压缩/加密混合负载；长时间测试会显式启用 `--auto-capacity`，覆盖缓存刷新和累计 VM 提交扣减，而不是误测固定容量。
5. 指定 `-IncludeMounted` 时，执行真实挂载的纯、压缩、加密、压缩+加密、自动容量 I/O。
6. 指定 `-IncludeServiceRecovery` 时，执行 SCM 崩溃/重启/重新挂载/清理测试。
7. 验收期间 Git HEAD 和 Release EXE 必须保持不变；指定 `-Package` 时，之后进行严格打包/来源验证，并校验每项 SHA-256 manifest。

第二个验收运行器不能同时占用 `.agent/release-acceptance.lock`。运行期间不要从其他会话编辑/提交受跟踪源码或重建已验收 EXE。运行器会主动失败，而不是把不同的源码 revision 或可执行文件错误地标记到测试报告中。

## 快速脚本验证

```powershell
.\scripts\verify-release-acceptance.ps1 -Quick -RepeatCount 1
```

此模式保留构建/测试/缓存检查，但只执行 10 秒冒烟压力测试。报告会标记为 `quick-smoke`，不能当作扩展耐久测试结果。开关未包含的挂载、服务或打包检查会记录为带原因的 `SKIP`。辅助测试独立检查原生命令行引用、并发 stdout/stderr、非零退出、子进程超时清理、脚本参数数组/开关和失败报告状态；它不会启动真实文件系统或修改驱动。

## 证据文件

每次运行都会在 `.agent/acceptance-*` 下新建目录。显式指定的 `-ReportDir` 必须尚不存在；验证器不会清空已有报告目录。产物包括 `acceptance.json`、Debug/Release JUnit XML 和每条原生命令的 stdout/stderr 日志。JSON 会在每个阶段后更新，失败时也会更新。命令失败/超时属于异常，不是警告。

`all_requested_checks_passed=true` 表示本次调用要求执行的检查全部通过，**不表示已验证所有受支持操作系统**。`externally_release_ready` 仍为 false：该运行器没有证明在干净 Win10/Win11 安装环境下的行为、Windows 11 ARM64 仿真运行、真实重启恢复、生产签名身份或 WinFsp 再分发许可决策。

`-RequireSignedExe` 增加 EXE 签名门禁；未签名程序和自签测试证书都会失败。这只是验证：脚本不会选择证书、读取/导出私钥或执行签名。

压力测试报告的私有内存和提交内存斜率，只是该有限负载/运行中的观测。斜率为零或最终分配器基线通过，都不能证明所有负载下没有泄漏。系统可用内存采样只是建议值，不能阻止其他进程同时分配内存。

## 平台与发布的独立决策

产品仍为单个 x64 `memfs.exe`，并内嵌官方签名的 x64/ARM64 SYS 资源。本验证器不增加原生 ARM64 EXE 或 32 位产品。干净 Windows 客体、ARM64 硬件/虚拟机和实际重启都需要单独证据；对应测试真实运行前，应将这些任务保持为未完成/阻塞状态。官方签名 WinFsp 2.1 的 `FSCTL_QUERY_ALLOCATED_RANGES` 限制独立于内部稀疏存储正确性，仍是已记录的功能缺口。
