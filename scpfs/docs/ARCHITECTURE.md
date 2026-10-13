# SCPFS 架构决策

日期：2026-10-03（Asia/Shanghai）。

新增用户要求：SCP/缓存传输必须以纳秒精度保留已有远端文件修改时间和访问时间，并应用显式 `SetFileTime` 更新。提交已有文件时保留打开时的时间快照；新文件使用缓存文件时间。SCP 自身只能设置秒级时间，次秒精度通过 GNU `touch` 补齐。采用临时文件原子替换无法保留 Linux birthtime，此限制已记录。

状态：截至 2026-10-03，在已测试范围内，SCPFS 实现、共享 WinFsp 前端、原生服务生命周期和生产 SCP 运行均已接受。准确证据/限制见 `VALIDATION.md`；共享前端边界见 `D:\work\fs\frontend\DESIGN.md`。

## 目标与已确认的基础

提供可挂载为 Windows 盘符、读写远端文件的文件系统，文件负载使用传统 SCP 协议。用户确认服务器为 Linux/GNU，并要求复用 `D:\work\memfs` 框架以尽快完成项目。Luna 调查确认，memfs 的 C17/clang-cl/CMake、WinFsp 回调和 dispatcher 生命周期可作为框架。直接复用这些源码模式，包括 dispatcher 停止状态报告，并将存储回调改为 SCP 后端。用户要求 EXE 仅依赖操作系统 DLL，因此复用 memfs 的 WinFsp 静态库和仅嵌入 SYS 的驱动框架，静态链接 libssh2/OpenSSL/zlib 和静态 CRT。静态构建不得解包或加载第三方运行时 DLL。系统已加载且兼容的驱动应复用；不得停止或替换正为现有卷服务的驱动。

在调用 libssh2 或任何 OpenSSL API 之前显式使用 `OPENSSL_INIT_NO_LOAD_CONFIG` 初始化 OpenSSL。否则静态 OpenSSL 库可能读取 `OPENSSL_CONF` 并加载外部 provider DLL。产品使用静态链接的默认密码实现，忽略外部 OpenSSL 配置/provider 激活；需验证环境指定的错误 provider 配置不能让原本成功的 SSH 探测失败。PE 普通/延迟导入检查与真实进程模块清单是互相独立的验收门禁。

主机名解析必须使用 Windows 自带 DNSAPI，而不是 Winsock namespace provider 查询。生产路径中 `getaddrinfo` 曾加载 Bonjour 的 `mdnsNSP.dll`，尽管 PE 导入表仅包含 OS DLL。数字 IPv4/IPv6 地址直接解析；主机名 A/AAAA 查询使用 Windows DNS 客户端/缓存/hosts 行为，并设置 DNS/TCP 绝对截止时间及生命周期安全的异步取消。严格主机密钥校验仍使用用户配置的原始主机名。此改动只增加操作系统 `Dnsapi.dll`，不修改系统 provider。主机名夹具和生产进程模块清单都是发布门禁。

两个产品都链接静态 C17 库 `fs_frontend`。它拥有全部 31 项 WinFsp 操作分派包装、挂载/dispatcher 生命周期、共享 SCM 宿主、受保护日志和原生安装/卸载。现有存储回调及各产品文件上下文语义保持不变。原生安装会捕获凭据绝对路径和安装用户 SID，配置 LocalSystem 延迟自动启动及有界恢复动作，然后立即启动。完全相同的安装配置必须幂等；不同配置会被拒绝，不重写现有服务。卸载会核实已注册的可执行文件，并只删除指定用户态服务。已运行的共享驱动及无关挂载必须保留。

## 主要架构决策

精简 Luna 简报将新缓存/回写边界列为数据完整性重点审查。初始设计接受整文件本地缓存，并明确一致性限制。SCP 不提供随机写、目录查询或 compare-and-swap 原语。文件通过 libssh2 SCP 下载并在本地缓存编辑；元数据/命名空间操作在同一认证 SSH 会话中执行安全引用的 GNU 命令。不提供 SFTP 回退。基本文件系统操作不依赖 Python；通知辅助的读取缓存复用由 `CACHE_ARCHITECTURE.md` 所述内嵌 Python 3 helper 实现，无需安装服务端 daemon。

Linux 文件名区分大小写。用户后来将大小写敏感设为强制要求，因此设置 `CaseSensitiveSearch=1` 和 `CasePreservedNames=1`，命名空间和缓存都使用精确比较，并以真实挂载测试 `Test.txt` 与 `test.txt` 的不同内容、目录枚举、独立删除及仅大小写改名。拒绝 Windows 无法表示的组件、路径遍历、备用数据流、控制字符、符号链接和特殊文件。配置根目录必须已存在且为绝对目录，后端还要验证规范路径及每次操作的祖先路径。这是面向可信远端账户/目录的路径映射，不是防止该账户并发替换祖先目录的安全沙箱。禁止改名或删除挂载根目录。

初始实现中，一个文件系统实例会串行化回调/后端访问；每个普通文件最多一个活动缓存句柄。WinFsp Cleanup 表示用户最后一个句柄已关闭，即使缓存引用导致后续 Close 延迟，也会从路径 guard 中释放干净句柄；仍有未解决脏元数据/数据的句柄继续阻止另一个打开。多个目录句柄可独立使用。该限制是刻意设计，必须写入 README：需要同时打开并编辑同一文件的应用可能收到 sharing violation，目的是避免每句柄快照分叉。若目录有活动后代句柄，拒绝改名/删除；若目标文件仍活动，拒绝替换。文件成功改名后更新缓存路径/状态。脏内容必须保留至提交成功；不得覆盖重载脏缓存。

打开已有普通文件时，须根据 WinFsp 授予的访问掩码区分负载访问与仅元数据访问。如果 stat、属性/时间或仅删除访问的上下文不含 `FILE_READ_DATA`、`FILE_WRITE_DATA`、`FILE_APPEND_DATA`、`FILE_EXECUTE`，则不下载或拥有负载缓存。干净 metadata-only 上下文等待 Cleanup 时不阻塞路径/缓存 guard；脏元数据、删除失败或尚未解决的 inbox/恢复状态仍须阻塞。不得在已有活动负载上下文时并行提交 metadata-only 变更，也不得绕过未解决的脏负载。metadata-only `SetBasicInfo` 同步提交并返回后端错误；Create 和负载句柄回写语义不变。负载回调应防御性拒绝没有缓存的 metadata 上下文。该边界保证至多一个活动负载缓存，并避免延迟的 metadata/stat Close 被误当成另一个文件编辑者。必须反复测试精确纳秒级 `SetFileTime` 后立即删除，不得使用 sleep 或测试重试掩盖竞态。

无缓存 metadata 上下文可能在命名空间变化后仍存活，因此成功的 rename/delete 和命令输入消费都必须将受影响的干净 metadata 对等句柄标记为 stale，包括目录后代和被替换目标。Stale 上下文可返回保存的文件信息快照，但必须拒绝远端元数据/rename/delete 修改，并跳过 Cleanup/Close 提交或 inbox 触发。改名前同时检查源和目标是否存在其他活动负载或未解决上下文。不得将旧目标描述符重定向到替换对象，也不得允许旧路径上下文修改新建文件。初始后端不支持命名空间变化后保留可变 metadata 描述符；调用方必须重新打开新路径。这种有限失效机制避免引入共享文件节点存储或额外负载缓存。

删除校验和实际 Cleanup 删除都要检查其他活动上下文。干净 metadata-only 上下文的 Close/Cleanup 遇到活动负载所有者时不启动命令，将触发留给负载所有者的 Close；不得创建会阻塞负载所有者的恢复锁存，也不得在 Cleanup 完成后由 Close 再次尝试。其他活动/未解决冲突在分派前记录为“未启动”的恢复失败。显式 Rename 在同路径 inbox 分支之前先检查源 guard，避免跳过冲突命令却报告成功。不引入延迟重试状态。同步 metadata 提交成功后清除 `modified_after_cleanup`；只有真正干净的 metadata 上下文才可失效。

缓存对象是每次打开的独立描述符，因此卷必须设置 `UmFileContextIsUserContext2=1`。WinFsp 默认上下文是文件节点；只要内核仍保留该节点，各次打开的上下文必须完全相同（见 `inc/winfsp/winfsp.h` 接口文档）。在该默认模式下使用每次新分配的 SCPFS 句柄，曾在真实挂载 close/reopen 和 rename 测试中间歇性出现 invalid handle。选择描述符语义，而不把缓存重构为共享文件节点；修复后须重复 close/reopen/rename/delete 和 inbox 提交测试。

初始实现只支持一个 WinFsp dispatcher worker。`scpfs_start(..., 0)` 选择单 worker；请求更多 worker 时拒绝启动。Luna 专项调查发现活动缓存 guard 存在真实 close-to-delete 失败：下一个 Open 执行时，干净描述符的 `cleaned_up` 仍为 0。WinFsp 本地源码会把 Cleanup 与 Create/Open 放入队列尾部，但默认按 CPU 亲和性扩展的 workers 可能以不同顺序取出请求并获取 SCPFS 锁（`src/sys/cleanup.c`、`src/sys/create.c`、`src/sys/ioq.c`、`src/dll/fs.c`）。因此选择单 worker 保证回调处理顺序，同时保留严格单缓存和冲突保护。后端本身已经串行化网络访问。不得用 sleep/重试代替，也不得放开互相冲突的并行写缓存。发布前须无延迟地重复 close/read/reopen/delete，并重跑完整挂载套件。

在显式 Flush 以及框架允许的 Cleanup/Close 上提交。干净和只读句柄也会收到 Cleanup（`PostCleanupWhenModifiedOnly=0`），因为 Cleanup 表示用户最后关闭，且可能触发精确 `.in.txt` inbox 协议；只有 Cleanup 未执行时，Close 才是备用触发。上传到密码学随机、唯一的同级临时名称，并保留现有 mode。SCP 完整协议交换并确认成功后，在替换临时文件前，将目标当前大小、纳秒 mtime、mode、device、inode 与初始快照比较。新目标必须仍不存在。发现冲突时返回失败。这只是尽力冲突检测，外部写者仍可能在比较/改名前竞态写入。正常使用假定本挂载是远端树唯一写入者；不得声称具有分布式 CAS、多客户端一致访问或崩溃持久的远端 fsync。

精确 basename `.in.txt` 保留用于远端 shell 命令提交。Cleanup 成功提交后，后端原子认领并执行一次；改名为该精确名称时，先完成提交/改名，再按新路径执行。普通 Flush 和目录遍历永不触发命令。句柄记录 attempted/consumed/unknown 状态，避免自动重放；提交失败或结果不确定时，保留本地缓存和恢复 manifest。这是以认证账户权限执行用户提供 shell 文本的功能，不是 shell 沙箱；完整限制见 `docs/COMMAND_PROTOCOL.md`。

所有可返回的回调失败都必须返回 NTSTATUS。用户最终指定使用 `%TMP%`，取代短暂讨论的 M: 盘缓存。应在 `%TMP%\scpfs` 下创建唯一会话子目录；绝不清理其他会话或用户拥有的文件。Cleanup/Close 无法返回错误：应记录明确路径和错误，保留失败的脏缓存及恢复元数据，并提供受支持的恢复步骤。Flush 失败时不得将节点标记为干净。unlink 成功后删除不再需要的缓存；删除失败应记录，且不得静默使活动状态失效。dispatcher 和 worker 完全结束后才销毁缓存。

认证前须使用显式指定的 OpenSSH known_hosts 文件验证主机密钥。本地挂载安全描述符明确设置 owner/group，只向启动用户的 TokenUser SID 和 SYSTEM 授权；不向 Everyone 共享已认证的远端账户。未知/不匹配密钥必须 fail closed。只支持公钥认证，不允许密码或 keyboard-interactive 回退。显式 identity 覆盖默认的 home/.ssh/id_ed25519；默认密钥缺失时明确失败。若支持私钥解密口令，它也不属于远端密码认证。每个连接/通道操作必须有有限超时。SSH 输出有界并使用 NUL 帧分隔。逐个引用命令参数；不得解析依赖 locale 的 `ls` 输出。上传临时文件名不可预测，也不得覆盖无关临时文件。断开/超时后返回错误，不盲目重放修改。

命令超时默认为 30 秒，上限 540000 ms。卷使用 WinFsp 最大 600000 ms IRP 超时，为终止命令和发布结果留出时间。极端超时配置及恶劣网络延迟是否满足该驱动总体预算尚未通过运行时证明；回调无法完成时必须保留恢复状态。

## 分工与实现任务

- Luna 设计任务：`src/scpfs.h`、`src/scpfs.c`、WinFsp 回调/缓存/生命周期适配；记录来自 memfs 的源码沿用依据。
- Luna 传输任务：`src/scp_backend.h`、`src/scp_backend.c`，实现 SSH/SCP/认证/元数据和远端变更 helper。
- Luna 构建/CLI 任务：CMake/presets/vcpkg/main/scripts/tests/README；clang-cl Debug/Release 构建、隔离 WSL OpenSSH 夹具和 WinFsp 挂载检查。
- 协调者：整合独立审查，记录证据和剩余限制。该历史决策当时未授权提交/推送。

## 运行时门禁与未知项

会话读取缓存和服务器通知扩展由 [CACHE_ARCHITECTURE.md](CACHE_ARCHITECTURE.md) 约束。读取缓存保持启用；用户最终选择的默认容量为零/不限容量，正的 MiB 数值应用负载 LRU 上限。独立、不可变的复用副本不能替代每次打开的可写描述符或恢复文件。监控使用第二条 SSH 会话，固定到主后端的规范根目录；helper 以一次往返回答查找和小文件传输，并按路径报告变化；外部变更会最终使干净读取缓存失效。这不改变变更操作的单写入者/冲突边界。

必须验证：Debug/Release clang-cl 构建；CLI 校验；拒绝错误/未知主机密钥；在隔离 loopback WSL sshd 上执行真实 SCP 下载/上传和 GNU 元数据操作；真实 Windows 挂载 CRUD/随机读写/截断/改名/删除/Unicode/参数引用路径；在故障注入允许时验证冲突拒绝和脏缓存保留；Ctrl+C 后 dispatcher 正常关闭。编译和后端测试不等同于挂载验收。当前证据必须与要求分别记录。网络故障持久性、性能、大文件吞吐、恶意并发替换祖先路径及多客户端一致性不在初始验收范围，必须明确列为限制。
