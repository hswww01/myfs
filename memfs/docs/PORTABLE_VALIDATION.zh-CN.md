# memfs 便携验收工具包

这不是另一套 ARM64 程序，也不是“已经通过所有机器验证”的发行许可。它包含本次同一个 x64 memfs.exe、对应的 Release 测试程序、源文件守卫输入和 x64/ARM64 官方签名驱动参考文件。没有编译器、CMake、Git、vcpkg 的 Windows 机器也能执行对应的 20 项测试。

**运行前：**将整个工具包解压到可写的本地目录，例如 `C:\memfs-validation`。使用 64 位 Windows PowerShell 或 PowerShell 7。请保留 `SHA256SUMS.txt`、`KIT_INFO.json` 和 `BUILD_PROVENANCE.json`，不要只复制 EXE。哈希用于检查传输/文件一致性，不代替发布者签名或第三方许可。

## 1. 只检查文件完整性，不安装驱动、不挂载

```powershell
cd C:\memfs-validation
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-VALIDATION.ps1 -Scenario Integrity
```

程序检查完整清单、源提交和 EXE 哈希是否与构建记录一致。`results\run-*\result.json` 保存机器架构和结果。EXE 尚未具有公开发布签名时，不应把原有 WDK 测试证书当作面向用户的代码签名证书。

## 2. 运行对应的 20 项 Release 测试

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-VALIDATION.ps1 -Scenario Runtime
```

包含文件句柄/孤儿节点生命周期并发回归，以及实际 Release 路径的缓存并发/到期/内存压力测试、核心文件系统、多线程、短时 soak、内存调用守卫、驱动策略、命令行、静态 WinFsp 版本和导入表、dispatcher 状态、内嵌双 SYS，以及驱动签名来源检查。

负向命令行测试必须返回预定错误码，不会把“EXE 根本启动不了”当作成功。测试子进程具有超时，输出分别保存在当前 `results\run-*`。驱动签名验证可能需要系统已有正确的根证书/证书链；失败时不应关闭校验来凑通过。

这些测试不会主动安装 WinFsp 驱动或创建 MemfsC 服务。它们不是实际内核挂载验证的替代品。

## 3. 已安装官方 WinFsp 的机器：实际挂载、读写、卸载

确保 R: 等测试盘符未被占用，再执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-VALIDATION.ps1 -Scenario OfficialInstalled
```

该场景要求检测到官方 WinFsp，且不存在 MemfsC 私有 fallback。完成分页读写、跨页重写、截断后扩展的零填充、稀疏洞、目录操作之后，必须正常停止进程、返回 0、移除 DOS 设备映射，才报告通过。不会为了测试删除或替换官方 WinFsp。

## 4. 真正干净的 Windows 10/11 x64 虚拟机：内嵌驱动首次部署

**只在可丢弃的干净测试虚拟机内，以管理员运行。**该场景会安装并启动内嵌的私有文件系统驱动，然后测试卸载清理。不要在保存着个人工作、其他应用或未保存数据的主机上使用。

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-VALIDATION.ps1 -Scenario PrivateFallback -ExercisePrivateFallback -ExpectedNativeMachine AMD64
```

存在官方 WinFsp 服务/驱动/安装目录时脚本拒绝执行，不会替你“清理环境”。成功的 `deployment.json` 应证明真实挂载、创建的是 `WinFsp+MemfsC`、载荷使用 `memfs-winfsp-x64.sys`，并在结束时卸载私有服务/文件。需要重启的文件清理状态不得当作立即清理成功。

当前开发机上的此场景未执行；工具包准备好，不等于干净虚拟机验收完成。

## 5. Windows 11 ARM64：同一个 x64 EXE + ARM64 SYS

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-VALIDATION.ps1 -Scenario Runtime -ExpectedNativeMachine ARM64
```

`result.json` 必须记录 `native_machine=ARM64`。检查最终 EXE 仍是 x64，这正是既定产品方案，不需要构建 ARM64 用户态程序。

已装官方 WinFsp 时运行 `OfficialInstalled`。干净可丢弃的 ARM64 虚拟机以管理员运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\RUN-VALIDATION.ps1 -Scenario PrivateFallback -ExercisePrivateFallback -ExpectedNativeMachine ARM64
```

请额外核对 `deployment.json` 中私有 service 的 `PathName` 指向 `memfs-winfsp-a64.sys`（或它的 .alt.sys），以及文件 PE machine 是 ARM64。AMD64 开发机不能代替这项真实硬件/系统验证，指定错误的 `ExpectedNativeMachine` 会失败。

## 6. 服务跨真实重启：手动两阶段验收

以下只在一次性测试虚拟机中执行；工具包不会自动重启电脑。先完成上面的实际挂载场景，再以管理员执行：

```powershell
$exe = (Resolve-Path .\memfs.exe).Path
$beforeBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
@{ before_boot=$beforeBoot.ToUniversalTime().ToString('o'); exe_sha256=(Get-FileHash $exe -Algorithm SHA256).Hash } | ConvertTo-Json | Set-Content .\results\before-reboot.json
.\scripts\memfs-service.ps1 install -Exe $exe -Mount R: -Size 64M -StartType auto
.\scripts\memfs-service.ps1 start
[IO.File]::WriteAllText('R:\volatile-before-reboot.txt','must disappear after reboot')
sc.exe query MemfsC
```

然后由操作者确认并重启这台测试虚拟机。开机后不要手动启动服务，以确认确实是 SCM 自动启动：

```powershell
$before = Get-Content .\results\before-reboot.json -Raw | ConvertFrom-Json
$afterBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if ($afterBoot.ToUniversalTime().ToString('o') -eq $before.before_boot) { throw '尚未发生真实系统重启' }
if ((Get-Service MemfsC).Status -ne 'Running') { throw '服务未自动运行' }
if (-not (Test-Path 'R:\')) { throw '启动后没有重新挂载' }
if (Test-Path 'R:\volatile-before-reboot.txt') { throw '易失内存盘数据不应跨系统重启保留' }
[IO.File]::WriteAllText('R:\after-reboot.txt','reboot-io-ok')
if ([IO.File]::ReadAllText('R:\after-reboot.txt') -ne 'reboot-io-ok') { throw '重启后读写失败' }
sc.exe query MemfsC
.\scripts\memfs-service.ps1 stop
.\scripts\memfs-service.ps1 delete
```

清理私有驱动前确认所有 memfs 实例均已停止。仅针对工具创建的私有 fallback 使用 `memfs-service.ps1 purge-driver -Exe .\memfs.exe`；不要删除官方 WinFsp。保存前后 boot time、文件哈希、service 查询和读写结果，才足以关闭“实际 reboot”任务。进程被强杀后自动重启已经有独立测试，但不能代替这项 OS 重启验收。

## 尚未被本工具包自动解决的事项

正式 EXE 签名身份/证书及时间戳策略、WinFsp 静态链接的分发许可决策、干净 Win10/11 和 ARM64 的实际运行记录、真实 OS 重启记录仍需各自验收。当前官方签名 WinFsp 2.1 的 `FSCTL_QUERY_ALLOCATED_RANGES` 限制也没有因工具包而消失。内部稀疏页可工作，不等于 Windows 复制/备份工具能查询这些已分配范围。

所有生成的结果都带明确场景与机器架构。`externally_release_ready=false` 是有意保留的：单机/单场景通过不代表所有分发条件已完成。
