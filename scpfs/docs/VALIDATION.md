# SCPFS 验证与交付记录

日期：2026-10-03（Asia/Shanghai）。当前 R: 缓存修复、最终可执行文件哈希、13 项测试套件和实际服务验收见 [CACHE_ACCESS_FIX.md](CACHE_ACCESS_FIX.md)。早期通知缓存里程碑见 [CACHE_VALIDATION.md](CACHE_VALIDATION.md)。本文后续章节保留更早实现、共享前端、GUI 和原生服务里程碑的历史证据；其中旧可执行文件哈希及生产进程 PID 不得当作当前包或服务状态。本文记录的是专项实现/运行验证，不是完整 Windows 文件系统一致性或安全审计。

## 交付物与构建

- 源码项目：`D:\work\fs\scp`。
- Release 可执行文件：`D:\work\fs\scp\dist\scpfs-x64\scpfs.exe`。
- 版本：0.1.0；x64；C17；clang-cl、CMake/Ninja。
- 静态依赖：`D:\vcpkg` 中的 vcpkg、`x64-windows-static`、libssh2 1.11.1、OpenSSL 3.6.0 和 zlib；静态 CRT；复用 `D:\src\winfsp-memfs-static` 中的 WinFsp 静态源码/库。
- 内嵌的内核驱动已签名，并经过架构/版本校验；来源证据随包中的 `WINFSP-DRIVER-PROVENANCE.json` 提供。安装包不包含 DLL。
- 历史 GUI-only Release 可执行文件 SHA-256 为 `9C2E82DC052228E511C1C17EE44C0311E910A164C194B1BEF2FA8013B741EE2C`（5,355,008 字节）。该里程碑没有重启服务；当时运行 PID 82124 使用旧版可执行文件 `F20505BE1A4250CD7F43B909FCEA271F6D07232C39CAA3A29AE309F90B385698`，并保存为 `scpfs-before-gui-20261003.exe`。当前交付和服务状态证据见 `CACHE_ACCESS_FIX.md`。
- 交付物附带 README、架构/命令协议、第三方声明和准确依赖许可证。WinFsp 上游 FLOSS 特别例外明确针对 DLL 链接；静态构建不依赖该例外。没有替用户修改或授予项目许可证。

## 已确认的验收证据

Debug 与 Release 验证使用以下命令：

```powershell
cmake --build --preset x64-debug
ctest --preset x64-debug --timeout 300
cmake --build --preset x64-release
ctest --preset x64-release --timeout 300
```

共享 GUI 布局和输出捕获修正后，最终 Debug/Release 套件各 **8/8 全部通过**，没有集成测试跳过或失败；最终运行分别用时 33.16 秒和 25.67 秒。测试包括 help、非法 CLI 参数、版本、PE 普通/延迟导入、真实 SSH 集成、真实 WinFsp 挂载、无参数 GUI 和原生 SCM 服务集成。SSH 测试使用仅供测试的 `%TMP%`/`%TEMP%`，路径位于 `build/gui-validation-tmp`：第一次未设置重定向时继承了用户的易失 `M:\tmp`，无法写入临时探测文件并返回 Win32 错误 112。测试专用环境覆盖避免更改全局/用户环境或 M: 内容。日志位于 `build/x64-debug/Testing/Temporary/LastTest.log` 和 `build/x64-release/Testing/Temporary/LastTest.log`。

GUI 测试打开无参数窗口并确认保持空闲，检查 GUI 进程模块清单，通过隔离的 localhost OpenSSH 夹具填写原生字段，执行真实的严格主机密钥/SCP 探测，验证 GUI 中捕获的成功输出，再在 X: 执行真实挂载。密钥和严格 known-hosts 文件位于含空格的路径；缓存目录预先存在且路径以反斜杠结尾。测试点击 Mount，执行 GUI 所拥有的临时卸载操作，并确认 X: 已释放。GUI 运行时模块记录于 `RUNTIME-MODULES-GUI-RELEASE.json`，只有可执行文件及 Windows 系统/WinSxS 模块，不含第三方运行时 DLL。

SSH 夹具在 WSL Ubuntu 中启动专用 GNU/OpenSSH daemon，生成测试密钥，使用隔离 loopback 端口和唯一目录。它验证真实 SCP 上传/下载字节一致、stat/rename/delete、拒绝未知/不匹配主机密钥及未授权密钥。客户端密钥是真正未加密的 OpenSSH Ed25519 密钥。默认 `HOME/.ssh/id_ed25519`、未设置 `HOME` 时回退到 `USERPROFILE`、显式 identity 优先，以及默认密钥缺失报错均通过。源码审查确认主机校验先于唯一的公钥认证 API 调用；没有密码或 keyboard-interactive 回退。

known-hosts 回归还覆盖无注释 LF/CRLF 行、有效条目前有无关主机、EOF 没有换行符，以及拒绝同一主机的错误固定密钥。加载器在交给 libssh2 解析前会正确终止每行 span；不改变主机密钥算法或信任策略。

最终 SSH 门禁还会设置夹具自有 `OPENSSL_CONF`，令其尝试启用不存在的 provider，并将 `OPENSSL_MODULES` 指向空目录。两个重建配置仍能完成 SCP 探测，因为在调用 libssh2/OpenSSL 前已执行 `OPENSSL_INIT_NO_LOAD_CONFIG`。作为负向对照，早期安装包在同一断言下以 `0xC0000001` 失败；该回归检测了先前隐式加载配置的问题。

真实挂载测试覆盖 ASCII 和正确引用的 Unicode 路径、随机读写和截断、目录/文件创建、改名和删除、`Test.txt`/`test.txt` 独立内容、错误大小写查找失败、仅大小写改名、独立删除、拒绝符号链接、读取/写入负载时保留已有纳秒 atime/mtime、显式 Windows 文件时间更新，以及外部写者冲突检测；冲突时原远端数据和本地脏缓存/恢复 manifest 均保留。

挂载测试省略 `--cache-dir`，设置夹具自有 `%TMP%`，验证 SCPFS 创建唯一 `%TMP%\scpfs\session-{GUID}` 目录及恢复 manifest，并检查运行进程的模块路径。早期仅用 IP 地址的清单漏掉了生产主机名路径通过 Winsock 加载的 Bonjour `mdnsNSP.dll`。修正后的主机名回归及最终生产进程仅包含 EXE 和 Windows DLL（含内置 DNSAPI/IP Helper）。生产进程模块清单有 35 项，没有 Bonjour 或动态第三方运行时 DLL。PE 普通/延迟导入分别通过校验。安装包包含 `RUNTIME-MODULES-RELEASE.json`；`PRODUCTION-SERVICE-ACCEPTANCE.json` 记录生产模块清单。

命令 inbox 测试覆盖多次 Flush 后由 Close 提交、Flush 不触发执行、改名为精确 `.in.txt`、替换结果文件、以所在目录为 cwd、合并 stdout/stderr、UTF-8 BOM/CRLF、非零退出输出、有界超时、输入删除，以及立即删除时 `.IN.TXT` 仍为普通文件。没有轮询或启动扫描。测试将超时缩短为 1500 ms；产品默认 30000 ms、最大 540000 ms。

额外的真实挂载生命周期门禁通过 **100 轮立即创建/关闭/读后关闭/删除**，每轮都检查本地与远端条目不存在，不使用 sleep。移除临时成功回调跟踪后，两个独立的新 Debug 挂载通过，随后 Debug 完整套件挂载和 Release 完整套件挂载均通过。测试日志写入文件，避免完整 stdout/stderr 管道阻塞文件系统回调。

原生 SCM 夹具创建唯一测试服务，不传 `--identity`，而通过夹具自有 home 验证捕获的 Ed25519 密钥绝对路径。它检查 LocalSystem 自动启动、全局挂载权限、SYSTEM/安装用户受保护日志 ACL、实际 stdout/stderr 标记记录、相同安装幂等和不同配置拒绝。测试执行真实挂载 SCP 传输，只 poison 测试 SSH 会话，观察服务错误 1066 及 SCM 以新 PID 重启，然后检查 stop/start、原生卸载和服务不存在。夹具保留现有驱动及无关服务；不会重放保留的修改状态。挂载套件还在无 sleep/重试同步的条件下，重复四次精确 `os.utime`/外部纳秒 stat/立即删除，并测试持有 metadata 句柄时 rename/recreate。

## 生产服务证据

Release 的 `--install` 为 `root@cn.tqdream.com`、远端 `/`、全局 R:、命令超时 60000 ms 创建并立即启动 `Scpfs`。调用省略 `--identity`；ImagePath 中包含安装用户解析出的绝对路径 `C:\Users\Administrator\.ssh\id_ed25519`、已严格验证的 known-hosts 路径和安装用户 SID。SCM 配置为 LocalSystem 延迟自动启动，故障后 1/5/30 秒重启，再无动作；重置周期 86400 秒，并启用非崩溃失败恢复。受保护日志为 `C:\ProgramData\Scpfs\Scpfs.log`，仅授予 SYSTEM 和安装用户，且包含重定向的两个诊断标记。

最终 Release 服务以 PID 82124 运行，R: 可见且远端 `/` 可访问。远端 `/tmp` 下唯一目录通过独立的 `Case.txt`/`case.txt` 内容、错误大小写查找、rename/read/delete、显式可表示时间后立即删除，以及普通 `.IN.TXT` 文件测试。直接 Close 和改名为 `.in.txt` 都产生精确标记输出，并将命令目录作为 `.out.txt` 中的 cwd；每个输入都被消费。所有创建文件和目录均已删除。挂载证据为 `PRODUCTION-MOUNT-ACCEPTANCE.json`；最终进程的受保护日志和仅 OS 模块清单也通过；SCM/运行时/ACL 证据为 `PRODUCTION-SERVICE-ACCEPTANCE.json`。已配置自动启动，但未实际重启 Windows。

## 已解决的实现缺陷

- 每次 Open 的缓存句柄原先使用 WinFsp 默认的稳定文件节点上下文。设置 `UmFileContextIsUserContext2=1` 后使用所需的描述符上下文，修复 reopen/rename 后偶发的 stale-pointer invalid-handle。
- 多个 dispatcher worker 可以按队列顺序取出 Cleanup/Open，却以相反顺序获取后端锁，导致活动缓存 guard 错误拒绝立即删除。单 dispatcher worker 保证处理顺序，同时保留严格的单缓存契约。`scpfs_start(..., 0)` 选择一个；大于 1 的数量会被拒绝。
- WinFsp 自动生成的 Cleanup 最后写入时间提示原先会覆盖远端 mtime。现在只改写负载的覆盖/写入/截断保留快照时间；显式 `SetBasicInfo` 时间仍会应用。
- 复用远端命令构造器但不清空，曾把结果发布步骤追加到已执行命令中。现使用独立构造器正确发布 `.out.txt`；清理失败时保留阶段和认领/恢复信息。
- 在密码学初始化前禁用 OpenSSL 隐式加载环境配置。CLI help 也已正确转义字面量 `%TMP%`。
- 主机名查找改用 Windows DNSAPI A/AAAA 查询，而非 Winsock namespace provider，避免加载可选 Bonjour DLL，同时不修改机器 provider 配置或主机密钥校验。堆上的查询状态及调用方/回调引用会跨取消保持有效；DNS 与 TCP 连接共用一个有限截止时间。
- 两个产品现在共用同一个静态前端，处理全部 31 个 WinFsp 操作包装、挂载/dispatcher 关闭和原生 SCM 服务/安装。后端上下文及文件上下文模式保持不变；不会在调用后端时持有注册表锁。
- 最初 SCM stdout/stderr 流未绑定或状态无效。服务宿主会在 SCM 注册后先在 NUL 上初始化 CRT 流，再将受保护追加日志句柄复制到其描述符，并检查每步操作且验证实际 stdout/stderr 记录。
- SCP 原生安装最初过早要求显式 identity。现在由安装器先解析默认用户密钥，再捕获内部服务参数；只有内部 `--service` 入口要求捕获后的显式路径和 SID。
- 无注释 known-hosts 行可能因 libssh2 检查行 span 外的分隔符而丢失最后一个 Base64 字符。临时将该 span 以 NUL 终止，修复 LF/CRLF/EOF 解析，不削弱固定主机密钥校验。
- 原先每个普通文件 Open 都下载负载缓存，包括只请求属性/时间/删除的句柄。这些句柄的延迟 Cleanup 会导致立即时间戳冲突和 `os.utime` 后偶发共享冲突。现在根据授予访问权限创建无负载缓存的 metadata-only 上下文；metadata-only `SetBasicInfo` 同步提交并返回后端失败。精确纳秒时间更新后立即远端 stat 并删除，反复运行无需 sleep/测试重试。
- 干净 metadata 上下文可能在 rename/delete 后仍存活。命名空间变更现在会使相关干净 peer 失效，避免之后的修改或 inbox 处理触及重新创建的同名路径。真实测试持有 FILE_WRITE_ATTRIBUTES 句柄跨 rename 和旧名重建：旧句柄 SetFileTime 失败，替换文件在该调用及 Close 后远端时间戳不变。脏/恢复上下文仍受保护；Create 和单负载缓存限制保持不变。

专项独立审查覆盖后端认证/根路径命令引用/原子上传和 inbox 状态、CLI/静态构建设置、适配器生命周期和复用的静态驱动启动流程。最终决策和一致性边界见 `ARCHITECTURE.md`。

## 限制与未执行检查

支持的远端环境为带 GNU 工具和 OpenSSH 的 Linux。文件数据以整文件为单位缓存；每个普通文件至多一个活动缓存，后端/dispatcher 串行化。假设远端树只有一个写者。指纹比较加 rename 只是尽力冲突检测，不是分布式 compare-and-swap 或远端崩溃持久的 fsync 保证。

Metadata-only 上下文不持有负载缓存。命名空间变更后，旧 metadata 上下文的修改会被拒绝；调用方应重新打开新路径。初始后端不在 rename/delete 后保留可变 metadata 描述符。不支持同时编辑同一文件的多个活动负载句柄；未解决的脏数据或命令恢复状态仍会阻止冲突操作。

临时文件原子替换无法保留 Linux birthtime。远端 POSIX ACL 不映射为持久 Windows ACL。未测试 memory-mapped I/O、完整 Win32/NTFS 一致性和大文件吞吐量。生产证据仅覆盖配置中的服务和上述临时目录操作。

Shell inbox 以配置的远端账户权限运行；cwd 不是安全沙箱。未注入命令启动后网络断开、远端崩溃和结果未知恢复故障。实现保留认领/缓存/恢复状态，不会盲目重放命令。极端命令超时和恶劣网络延迟是否满足 WinFsp 整体 IRP 时间预算，尚未通过运行时验证。

测试复用了已经运行且兼容的 WinFsp 驱动。未在新机器上测试嵌入驱动安装或驱动升级。没有停止/替换运行中驱动，也没有重启用户已有 M: 挂载。

## 相关 memfs 交付记录

以下 memfs 大小写敏感结果属于较早的后端里程碑，不是当前启用 GUI 的 memfs 包。该里程碑 Debug/Release 各通过 23/23 项，哈希为 `E3137FFEA855F5EF4BA981BAEAE006A00D6BBFB53419A17A5EDEB2EF77571BBB`，仅供历史参考。当前 GUI 版 memfs 包身份和 24 项测试证据记录在 memfs 包来源信息中。

已保留 `memfs_old.exe`。运行中的 MemfsC/M: 仍是用户原有进程 PID 68440；大小写敏感行为只适用于用新可执行文件启动的新挂载。memfs 脏工作树已保留，包来源信息记录其状态和 diff 哈希，并未声称打包时工作树干净。此历史验证当时未提交或推送。
