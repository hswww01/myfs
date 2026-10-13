# SCPFS

SCPFS 通过 WinFsp 将现有 Linux 目录挂载为 Windows 文件系统。程序使用 C17、已安装的 WinFsp 用户态 API 和 libssh2。文件内容通过 SCP 传输；远端元数据和目录项通过 SSH 执行 GNU/Linux 命令读取和更新。服务器必须提供 OpenSSH、GNU `find`、`stat` 及标准文件工具。

WinFsp - Windows File System Proxy，版权所有 © Bill Zissimopoulos。许可条款见 [WinFsp 项目](https://github.com/winfsp/winfsp)及其附带的 `License.txt`。

位于 `D:\work\fs\frontend` 的共享静态前端负责版本化转发全部 31 项 WinFsp 操作、文件系统挂载与 dispatcher 生命周期、原生 SCM 服务接入和受保护服务日志。SCPFS 提供操作表、卷设置、创建失败恢复钩子、缓存和 SSH 后端。Release 构建静态链接 WinFsp 及 SSH 依赖；内嵌版本已验证并签名的 x64/ARM64 WinFsp 内核驱动，不会解包或加载 WinFsp DLL。若系统已有兼容的 WinFsp 驱动则直接复用，绝不更新或停止正在运行的驱动。构建需要 SDK/静态库源码和标准 WinFsp 安装。

Dispatcher 使用四个回调 worker。远端查找和下载在适配器锁外运行；如果 Open 或 Rename 与另一个 worker 尚在队列中的 Cleanup 冲突，会短暂等待 Cleanup。每个远端文件最多有一个带缓存的内容句柄。仅请求元数据权限的打开不创建内容缓存；显式元数据更新会同步提交。若 rename、delete 或已消费 inbox 输入使 metadata 句柄失效，该句柄保留原快照供查询，但不能修改旧路径或替换后的对象。初始化 libssh2 前，SCPFS 禁止 OpenSSL 自动加载配置，避免环境变量 `OPENSSL_CONF` 和 `OPENSSL_MODULES` 指定的 provider 改变 SSH 密码学配置。

## 构建

Presets 使用 clang-cl、Ninja、位于 `D:\vcpkg` 的 vcpkg、`x64-windows-static` triplet，以及位于 `D:\src\winfsp-memfs-static` 的 WinFsp 静态库，并启用静态 C 运行库。CMake 会验证嵌入签名驱动的来源、架构和版本匹配。PE 导入门禁会同时检查普通导入和延迟导入，拒绝非 Windows DLL。

```powershell
cmake --preset x64-debug
cmake --build --preset x64-debug
ctest --preset x64-debug --timeout 180

cmake --preset x64-release
cmake --build --preset x64-release
ctest --preset x64-release --timeout 180
```

vcpkg manifest 安装静态 libssh2、OpenSSL 和 zlib。SSH 集成测试会在 WSL Ubuntu 中启动专用 OpenSSH 服务器，生成仅供测试的 Ed25519 客户端密钥和 RSA 主机密钥，并创建隔离的 `/tmp` 目录。测试真实 SCP 上传/下载往返及字节一致性、改名/删除、拒绝未知或不匹配的主机密钥、拒绝未授权密钥、通过测试专用 `HOME`/`USERPROFILE` 配置查找默认 identity，以及严格主机验证（覆盖无注释的 LF/CRLF、前置无关主机记录、文件末尾无换行符等情况）。

挂载集成测试会在存在空闲盘符时使用 `localhost` 执行真实 WinFsp 挂载；它会记录主机名解析后的已加载模块路径，并确认模块仅来自 Windows 目录和被测程序。GUI 集成测试会先在不连接网络的情况下打开无参数配置窗口，再填写表单、挂载本地 SSH 夹具，并仅停止由该窗口拥有的挂载。如果保留的盘符已被占用，GUI 和挂载集成测试会按 CTest 规则报告跳过。

## 配置窗口

不带参数运行 `scpfs.exe` 会打开原生配置窗口。窗口初始为空闲状态：SSH 主机和账户为空，选择操作前不会连接网络或开始挂载。输入远端根目录和挂载盘符，然后选择 SSH 私钥文件和严格校验用的 `known_hosts` 文件。私钥和主机密钥文件字段默认指向启动 Windows 用户配置目录下的绝对路径，因此提权执行服务操作时仍使用相同凭据路径。SCPFS 只将私钥路径传给子进程，绝不会把私钥内容写入日志或命令行参数。

**测试连接**会验证固定的 SSH 主机密钥，并在配置的远端根目录内创建随机临时文件，执行一次 SCP 上传/下载往返。**挂载**启动由该窗口拥有的临时挂载；**卸载临时挂载**会确认并只停止该窗口自己的挂载。**安装并启动服务**和**卸载服务**可配置服务名称和日志路径。GUI 服务操作需要时会请求提权。GUI 命令超时字段默认 60000 ms；命令行默认值为 30000 ms。缓存目录可以留空以使用默认临时目录；自定义缓存目录必须预先存在。

## 连接探测

使用服务器密钥已通过带外方式核验过的 OpenSSH `known_hosts` 文件。SCPFS 只支持公钥认证。

省略 `--identity` 时，如果设置了 `HOME`，程序读取 `%HOME%\.ssh\id_ed25519`；否则读取 `%USERPROFILE%\.ssh\id_ed25519`（若该环境变量不可用，则回退到 Windows 用户配置目录）。默认密钥不存在时视为错误。显式指定 `--identity` 优先。密钥必须可读且未加密；不支持 SSH 账户密码认证。

```powershell
build\x64-debug\scpfs.exe --probe `
  --host files.example.net --user files --port 22 `
  --remote-root /srv/files `
  --known-hosts $env:USERPROFILE\.ssh\known_hosts
```

`--probe` 会拒绝未知或已变化的主机密钥。它会在配置根目录下创建随机临时文件，通过 SCP 传输、校验下载字节、改名并删除；中途失败时会尝试清理。请在账户有权限创建和删除文件的目录中执行。

## 挂载

```powershell
build\x64-debug\scpfs.exe --mount R: `
  --host files.example.net --user files --port 22 `
  --remote-root /srv/files `
  --known-hosts $env:USERPROFILE\.ssh\known_hosts
```

按 Ctrl+C 可正常停止挂载。连接时必须显式指定主机、账户、绝对远端根目录和 known-hosts 文件。可通过 `--timeout-ms` 调整每项操作的有限超时。`--cache-dir` 可指向已存在且可写的本地内容缓存目录；不指定时，SCPFS 会在 `%TMP%` 下创建唯一会话目录；若未设置 `%TMP%`，则回退到 Windows 临时目录。

## 安装为 Windows 服务

在提升权限的终端中，使用与挂载相同的 SSH 和卷参数运行 `--install`。SCPFS 会先严格验证主机密钥并执行 SCP 往返探测，然后把当前可执行文件注册为 LocalSystem `Scpfs` 服务，配置延迟自动启动和有界 SCM 重启动作，并立即启动：

```powershell
build\x64-release\scpfs.exe --install --mount R: `
  --host cn.tqdream.com --user root --port 22 `
  --remote-root / `
  --known-hosts $env:USERPROFILE\.ssh\known_hosts `
  --command-timeout-ms 60000
```

省略 `--identity` 时，安装会在 `HOME` 已设置时解析 `%HOME%\.ssh\id_ed25519`，否则解析 `%USERPROFILE%\.ssh\id_ed25519`，并将绝对路径保存到 SCM 配置。

服务配置保存绝对凭据路径和安装用户 SID。LocalSystem 必须能读取私钥和 known-hosts 文件；SCPFS 不会把私钥内容放进服务命令行，也不会复制私钥。挂载是全局的，访问权限只授予 SYSTEM 和安装者 SID。服务诊断默认写入 `%ProgramData%\Scpfs` 下的受保护日志；使用 `--log-file FILE` 可指定其他绝对日志路径。隔离测试服务可指定 `--service-name NAME`；生产默认服务名为 `Scpfs`。重复使用相同配置执行 `--install` 是安全的；同名服务若配置不同，则拒绝修改且不会停止或重写现有服务。

```powershell
build\x64-release\scpfs.exe --uninstall
```

卸载只停止并删除指定名称的 SCPFS 用户态服务，不会移除 WinFsp 驱动、缓存/恢复数据、凭据或远端文件。发生致命 SSH 传输/协议故障时，服务进程退出，由 SCM 启动新进程；待恢复缓存会保留供人工恢复，不会自动重放修改。测试套件没有实际重启 Windows，因此真实重启启动路径尚未验证。

## 远程命令收件箱

关闭远端精确文件名为 `.in.txt` 的文件，或将文件改名为该名称，会把其 UTF-8 内容作为 shell 脚本提交给配置的 Linux 账户。命令的工作目录是该文件所在的远端目录。服务器安全认领输入后，SCPFS 会删除 `.in.txt`，并将标准输出和标准错误合并写入同目录的 `.out.txt`。命令以非零状态退出或超时仍会生成输出；退出码单独写入挂载进程日志。可用 `--command-timeout-ms` 调整默认 30 秒超时，最大为 540 秒。

收件箱接受 UTF-8、LF 或 CRLF 换行，可带 UTF-8 BOM；空输入视为空脚本。输入若含 NUL、无效 UTF-8、裸 CR 或超过 1 MiB，会被消费但不执行，并在 `.out.txt` 写入说明。输出上限为 8 MiB，超限时附加截断标记。若服务器认领脚本后 SSH 结果不确定，SCPFS 不会自动重试；应检查缓存会话中的 `recovery.manifest.txt` 和保留的认领路径，再决定是否重新执行。请把该功能视同远程 shell 访问：只挂载你愿意授权命令执行的目录并提供相应凭据。

## 读取缓存与服务器变更通知

读取缓存始终启用。默认 `--cache-max-mib 0` 表示不限制负载缓存容量；正值（1..16384 MiB）设置容量上限。配置窗口中的**读取缓存上限**含义相同，默认值为零。当前挂载期间，文件属性、目录列表和未修改文件内容会跨请求及关闭/重开复用，不按时间过期。元数据索引自身仍限制为 64 MiB / 131072 项。达到适用上限时，可淘汰最近最少使用的干净缓存项；活动工作文件和写入失败的恢复文件不计入这些上限。缓存不可用或失败时，绝不会用不完整缓存替代远端读取。

另有一条独立、严格验证公钥的 SSH 连接，用于运行内嵌的 Linux 变更通知 helper。helper 需要 Python 3，只使用 Python 标准库和 Linux inotify；无需安装常驻守护进程，也不开放额外服务器端口。统计、目录列表、读取/写入最多 8 MiB 的文件，以及 mkdir/rename/delete/属性修改，均可在一次往返中响应。它只监视曾经服务过的路径及其祖先，而非整棵目录树；之后观察到的变更也只针对相应路径报告，因此服务器其他繁忙日志目录不会清空本地缓存。重复命中无需 SSH 往返。若缺少 Python、监控不受支持或连接丢失，会回退到常规远端操作，直至监控恢复；其他远端命令仍共用一个持久 shell 通道。

内容或命名空间变更会丢弃受影响条目和父目录列表；仅属性变化会保留文件内容缓存。本地修改会立即使对应路径失效；收件箱命令即使失败或结果不确定，也会清空缓存。`.in.txt` 和 `.out.txt` 使用新读取。读取文件可能更新远端访问时间，与 Linux 上其他读取行为相同。

服务启动时会在日志中记录真实缓存会话目录。若未指定缓存目录，LocalSystem 服务通常使用 `C:\Windows\Temp\scpfs\session-{GUID}`，即使交互用户的 `%TMP%` 指向其他位置。保留的干净负载以 `read-{GUID}.cache` 命名；`file-*.cache` 是每次打开使用的工作副本。缓存仅属于当前挂载，正常停止时会丢弃。应从受保护服务日志中查找当前会话路径，不要按名称随意选取旧目录。

通知只提供最终一致的失效机制，不能形成跨 Windows/Linux 的事务。已打开句柄保留原快照。监控仅支持原生 Linux 文件系统；网络/伪文件系统路径、跨设备路径和不受支持的符号链接监控会绕过读取缓存。Inotify 不能报告所有可能的变化，包括部分 mmap 修改或挂载替换。重新挂载会丢弃会话缓存。协议、故障处理和验证边界见 [CACHE_ARCHITECTURE.md](docs/CACHE_ARCHITECTURE.md)。

2026-10-03 根目录 `/` 缓存修复及真实 R: 测量结果见 [CACHE_ACCESS_FIX.md](docs/CACHE_ACCESS_FIX.md)，其中记录当前 Release 哈希及修复前后观测。

## 一致性与恢复

SCP 不提供随机写入或 compare-and-swap 操作。SCPFS 会将每个普通文件下载到本地缓存，Windows 读写均在该副本上处理；Flush 或 Close 时，通过远端同目录临时文件上传并原子替换提交。每个普通文件最多允许一个带缓存的打开句柄，并假定本挂载是远端树的唯一写入者。替换前会根据已保存的 mode、大小、纳秒修改时间、device 和 inode 检测外部并发写入，但检查与改名不是分布式事务。不要将该挂载用于多客户端并发编辑，也不要依赖远端崩溃后 `fsync` 持久性。

缓存会话目录名为 `session-{GUID}`。脏数据提交失败时，`file-*.cache` 会保留，并将远端路径、缓存路径、已观察快照、操作和状态追加到 `recovery.manifest.txt`。挂载启动时会打印会话路径。Close 时提交失败，应检查 manifest，并在清理临时文件前保存所列缓存文件。人工恢复时先核实远端路径和账户，再使用可信 SCP 客户端将缓存文件复制到目标位置；必要时先备份远端文件。`%TMP%` 属于临时存储，不保证能经受清理工具、注销、重启或磁盘故障；重要恢复文件应另存到其他位置。

Linux 文件名区分大小写。符号链接、特殊文件、路径遍历、备用数据流、控制字符和 Windows 无法表示的组件会被拒绝。配置的远端根目录必须存在并且是绝对目录。祖先路径校验无法阻止远端账户在操作期间并发替换路径。

如果远端提供 device 和 inode，SCPFS 会据此生成 Windows 文件 ID；否则从路径生成合成 ID。合成 ID 在句柄打开期间稳定，但关闭后重新打开可能改变。已有文件的内容写入和截断会保留打开时取得的远端访问/修改时间快照；显式 Windows `SetFileTime` 更新会在上传后应用。新文件时间来自本地缓存文件。Windows 时间更新分辨率为 100 纳秒；未修改的 Linux 时间保持纳秒精度。临时文件加改名的上传方式无法保留 Linux birthtime。应用时间戳更新需要 SCP 传输后再执行 GNU `touch`。
