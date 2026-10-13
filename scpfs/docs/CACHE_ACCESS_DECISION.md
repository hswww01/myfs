# SCPFS 缓存：文件访问事件决策

日期：2026-10-03（Asia/Shanghai）。范围：生产主机远端根目录 `/` 的缓存回归，以及下文所述的有限源码改动。这是一项架构决策和实现门禁，不代表验收已经通过。

## 目标与已确认行为

远端 helper 会对每个受监控普通文件订阅 `IN_ACCESS`（`server/scpfs_watch.py:151-160`）。当前事件处理会对每个访问事件直接发送 `E 2`，不检查任何缓存元数据是否变化（`server/scpfs_watch.py:172-191`）。客户端收到 `E 2` 后递增全局元数据 generation（`src/scp_watch.c:211-228`）；适配器随后使所有缓存 stat 和目录列表失效（`src/scpfs.c:610-648`）。根目录 `/` 的列表会监控普通系统文件，所以 SSH 对 `/etc/group`、`/etc/passwd`、`/etc/login.defs` 和 `/etc/bash.bashrc` 的无关读取，会反复使其他未变化文件可复用负载所需的元数据失效。

生产主机的有限观察记录 `build/cache-access-trace/23637e4eeac3da05/result.json` 显示，读取 R: 上六个文件期间监控了 `/etc` 中的 106 个普通文件；期间记录了数百个无关文件的 `IN_ACCESS`，没有 modify 或 attribute 事件。在该次观察中，读取耗时为 858–2098 ms。这证明该次运行的事件来源及性能问题，不构成完整正确性证明。更早的独立 V: 结果 `build/cache-live-diagnose/f0de69da08521fe3/result.json` 显示，列出 `/etc` 后、原负载仍在缓存中的读取耗时为 840–1032 ms。

Linux 将 `IN_ACCESS` 定义为文件访问事件，包括 `read(2)` 和 `execve(2)`；该事件不表示时间戳已改变。`IN_ATTRIB` 表示元数据更新，包括时间戳改变。即使显式 `utimensat(2)` 最终将请求的 atime 和 mtime 恢复为原值，ctime 仍会变化。参考：[inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html) 和 [utimensat(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html)。项目的实际 helper 夹具观察到文件读取会产生 `IN_ACCESS`，`touch -c -a` 会产生 `E 2`。

## 决策

保留协议 v1、全局 generation、已确认的 watch 和 barrier，以及现有缓存容量和 fail-closed 策略。Linux helper **仅过滤受监控普通文件 inode 的纯 `IN_ACCESS` 事件**。只有新的 `lstat` 样本证明该 watch descriptor 最近一次已验证样本以来相关元数据没有变化，才抑制 `E 2`。至少比较 device、inode、文件类型/mode、uid、gid、大小、纳秒 atime、纳秒 mtime 和纳秒 ctime。

每个 watch descriptor 保存一个样本，而不是每个路径保存一个：inotify 按 inode 报告事件，硬链接别名可能共用同一 watch descriptor。添加或确保另一个别名时，不得重置现有样本，也不得消耗该 inode 上尚未处理的事件。

atime 或 ctime 确实改变时，发送 `E 2` 并更新已验证样本。处理访问事件时若发现大小或 mtime 改变，应保守地发送内容事件 `E 1`。若 inode 身份变化、路径不存在/已替换、对象不受支持、样本不可用或 watch descriptor 映射不明确，则监控必须 fail closed。样本完全相同的纯访问事件不发送任何通知。包含 `IN_ATTRIB` 的事件仍无条件发送 `E 2`，因为样本字段之外的元数据也可能变化。`IN_MODIFY`、`IN_CLOSE_WRITE`、命名空间事件和监控丢失/溢出继续使用现有内容 generation 或 fail-closed 处理。报告文件事件后刷新 descriptor 样本，避免之后的未变化读取产生重复元数据事件。helper 不得读取文件内容或修改远端时间戳来完成此判断。

用于 `lstat` 的路径必须在不跟随符号链接的情况下仍指向该 descriptor 记录的 inode。继续保留现有 4096 个 watch 上限、规范根目录检查、重新验证的 `W` 确认、barrier 顺序和重连失效行为。如果硬链接 inode 没有安全可用的路径，应标记监控不健康，而不是猜测访问无害。

在 `src/scpfs.c` 中，**只对冷缓存负载准入的最终 stat 比较增加 atime 相等检查**。目前该比较排除了 atime（`scpfs_cache_stat_provenance_mismatch_mask`，`src/scpfs.c:650-664`），因此最终验证 stat 前发生的 atime 改变，可能导致缓存以新的元数据 generation 发布负载，却保留旧 atime（`src/scpfs.c:1547-1585`）。若出现此不匹配，应返回已抓取字节，但不发布这组过期的元数据/负载；之后的 Open 可再次尝试。

`src/scp_cache.c:478-505` 中用于字节来源校验的 comparator 继续排除 atime：发生真实元数据事件后，若新 stat 与稳定 barrier 显示 type、device、inode、size、mtime、mode、uid、gid、ctime 仍一致，则可保留不可变字节，同时用新 atime 更新缓存 stat。不要为了这次缓存修复而改变后端修改冲突比较器。

这是处理已观察读取问题且保留时间戳可见性的最小修复。改为按路径报告事件会改变线上格式、监控 API、目录列表和硬链接依赖关系簿记及竞态证明；除非测量表明有限的 v1 修复达不到根目录 `/` 工作负载要求，否则延后该方案。直接丢弃所有 `IN_ACCESS` 被否决，因为真实读取可能推进 atime，挂载元数据必须反映这一变化。

## 必需实现与验证门禁

1. 使用真实 inotify 夹具证明：atime/ctime 不变的重复读取不产生 `E 2`；会推进 atime 的读取和显式仅更新 atime 的时间戳操作会触发元数据失效。测试在 barrier 前将 atime 从 B 恢复为 A，确认 ctime 可阻止错误抑制。即使样本 tuple 看似相同，`IN_ATTRIB` 仍须无条件通知。
2. 覆盖两个硬链接路径共用同一 watch descriptor、删除或替换其中一个别名、采样/确认期间 watch 身份改变、`IN_Q_OVERFLOW`、`IN_IGNORED` 和 stat 失败。必须按现有规则失效或 fail closed；不得将旧 inode 的确认用于替换后的路径。
3. 验证冷准入谓词会拒绝稳定 generation 下，下载后恢复 atime 的 stat 与最终 stat 不同的情形。若真实 atime 变化通知、元数据 generation 拒绝、热缓存 atime 重验和最终挂载门禁都通过，不强制要求确定性命中这一狭窄运行时竞态分支；但必须明确记录该限制。覆盖热缓存元数据过期重验：字节来源未变时保留负载并返回新 atime；来源改变时淘汰负载。
4. 重跑真实 WinFsp 文件夹具：在文件 A 冷读和热读期间，频繁读取其他受监控文件，并统计 helper 事件、barrier、stat/list 调用和负载命中。验证 A 热读恢复到本地副本路径，同时真实外部 atime、mode、内容和改名变化仍能被观察到。生产主机的临时挂载和 R: 服务行为须分开报告；开发期间不得影响运行中的 R: 服务。
5. 对候选版本运行项目 clang-cl/vcpkg Debug 和 Release 套件，以及静态导入/运行时模块检查。专项夹具通过不代表生产验收；声称回归已修复前，须比较最终打包 EXE 哈希并重做根目录 `/` 有界测量。

## 限制与交接

访问事件快照是保守的事件驱动缓存失效方法，依赖受支持的本地 Linux 文件系统、inotify 事件可用、inode 身份已验证及时间戳/来源变化可检测；它不是线性一致快照。前提不满足时，监控必须失效或绕过缓存，而不是返回未经验证的条目。本决策尚未测试 strictatime/noatime 挂载模式矩阵，也没有完成修复后的生产计时。

实现范围是 helper 中的 watch-descriptor 样本管理，以及适配器冷缓存准入检查。Windows 监控协议解析器、后端时间戳恢复、冲突规则、共享前端、服务状态和无关文件不属于本修复。后续执行者应按上述边界实现并运行门禁；在扩大协议前，若发现 inode 身份或事件顺序方面仍有未解决问题，应提交新的架构决策。
