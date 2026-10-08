# R: 读取缓存失效修复

日期：2026-10-03。范围：SCPFS 的 Linux 文件读取通知、冷缓存准入、诊断和相关回归。memfs、CryptFS 和通用前端没有在本次修复中改动。

## 根因与修改

R: 已开启缓存，容量默认值 `0` 也正确表示不限制文件内容缓存容量。问题出在通知处理：Linux 的 `IN_ACCESS` 表示文件被读取，并不保证文件属性发生变化。旧 helper 把每次普通读取都报告成元数据变化，客户端随即使全部属性缓存失效。挂载根目录 `/` 并列出 `/etc` 后，SSH 读取 `/etc/passwd`、`/etc/group`、`/etc/login.defs` 和 `/etc/bash.bashrc` 的行为持续触发这条路径，既阻止部分冷数据进入缓存，也使已有内容每次打开都走远端重验。

修复前的真实 R: 观察和 V: 隔离复测均复现了问题。事件级观察记录到上述系统文件的大量纯 `IN_ACCESS`，没有内容或属性修改事件。旧 R: 服务正常停止时的累计统计为 `payload_hit=0`、`payload_miss=22`、`stat_miss=13948`、`invalidations=27871`，进一步确认缓存未被有效复用。

新 helper 为每个 inotify watch descriptor 保存已核实的 inode 属性样本，包含 dev、ino、mode、uid、gid、size、atime_ns、mtime_ns 和 ctime_ns。只有纯 `IN_ACCESS` 且样本完全不变时才不发失效通知。真实时间戳或权限变化仍刷新元数据；内容、改名、删除等事件仍失效内容缓存。硬链接共享同一 descriptor 的基线，新 alias 不会吞掉待处理事件；路径身份无法核实时停止缓存准入，按原有机制读取远端。

冷缓存最终检查还要求 atime 一致，防止在新的元数据代次下发布旧时间戳。暖缓存重验保留原有字节来源比较规则：只改变 atime 时可以更新属性并保留已经核实的文件内容。新增诊断计数记录准入被拒绝的原因；服务启动日志记录实际缓存目录和容量。

Linux 事件语义参考 [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html) 与 [utimensat(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html)。设计和聚焦审查见 [CACHE_ACCESS_DECISION.md](CACHE_ACCESS_DECISION.md) 与 [CACHE_ACCESS_REVIEW.md](CACHE_ACCESS_REVIEW.md)。

## 测试与临时盘验证

- clang-cl + `D:\vcpkg`、静态 CRT/WinFsp/libssh2/OpenSSL/zlib：Debug 13/13 通过，无跳过；Release 13/13 通过，无跳过。Debug 的完整测试在删除一个未引用函数的机械清理前运行，Release 在清理后的最终源码运行，编译没有警告。
- 真 inotify 回归覆盖未改变时间戳的读取、真实 atime 更新、atime B→A 恢复但 ctime 改变、硬链接 alias、stat 失败、旧 inode 被替换、溢出及既有协议错误场景。未改变 atime 的读取用例在旧 helper 上实际失败，新版本通过。
- Debug/Release 压力测试分别观察到另一个文件的 728/729 次真实读取通知，目标文件各命中内容缓存 20 次，并保留同一份内容副本；`warm_metadata_stale=0`。测试随后检查真实 atime 变化和外部内容变化仍可见。
- 现有 SSH、公钥/主机密钥、CRUD、大小写、时间戳、冲突、命令收件箱、GUI、系统服务和静态导入检查全部通过。挂载和 GUI 运行时模块检查通过，只加载被测 EXE 与 Windows 模块。
- 相同服务器 `root@cn.tqdream.com`、远程 `/`、临时 V: 的旧版复现：列出 `/etc` 后后续读取约 840–1032 ms；同样场景的最终 Release 为 1.580–2.240 ms，内容一致、同一 11 字节 `read-{GUID}.cache` 保留。最终统计 `payload_hit=17`、`payload_miss=1`、`warm_metadata_stale=0`、`monitor_bypass=0`。39 个运行时模块符合 Windows-only 规则。临时挂载正常退出，V: 已释放。

构建证据：`build/cache-fix-validation/x64-debug-ctest.txt`、`x64-release-ctest.txt`；压力证据：`build/x64-debug/cache-access-integration/cache-access-results.json` 与对应 Release 路径；真实服务器临时盘证据：`build/cache-live-diagnose/389a25e065c52447/result.json` 和 `stderr.txt`。

## 当前发布身份和 R: 验证

最终 Release 已发布为 `D:\work\fs\scp\dist\scpfs-x64\scpfs.exe`，5,397,504 字节，SHA-256：

`CDA91BC8EBA4B8EF59F4E0CF6D69DE6D6592BDAA4D182E940BB1B11EE6306CEA`

2026-10-03 15:33:39–15:33:41（Asia/Shanghai）通过正常 SCM 停启更新了 Scpfs，原程序保留为 `scpfs-before-cache-access-fix-20261003-153338.exe`。服务配置保持原值：LocalSystem、自动启动、R:、远端 `/`、原公钥及 known_hosts 路径、命令超时 60000 ms。原配置窗口进程保留；停启当时 MemfsC/M: 保持运行。

当前 R: 进程 PID 为 47320。启动日志显示本次挂载的缓存目录：

`C:\Windows\Temp\scpfs\session-{2B9201F3-D967-4E0B-B53B-495BD1032D62}`

R: 的更新后只读验收已通过：三个阶段共读取 `/etc/debian_version` 18 次（初次、列出根目录后、列出 `/etc` 后），每次内容散列一致，并保留同一份 `read-{12A9FD75-C3F1-43CE-978E-EF5568C94440}.cache`。列出 `/etc` 后的 6 次读取为 2.724、3.109、3.916、2.666、2.490、4.110 ms；后 5 次中位数 3.109 ms。对应旧 R: 同一文件的三个干净记录为 1107.73、1788.82、2040.81 ms。当前服务的 39 个模块仅来自 EXE 和 Windows 目录。实际缓存目录中已确认该 11 字节内容副本在关闭文件后仍然存在。

R: 证据位于 `build/cache-r-verify/3feb61d1bb669fac/result.json`，正常停启和哈希校验位于 `build/cache-service-update-20261003-153338/result.json`。发布包的最新机器可读记录以 `CACHE_ACCESS_*.json` 为准，此前的接受记录保留为历史证据。旧配置窗口仍使用已经载入的旧镜像；以后重新打开配置窗口会载入新的 `scpfs.exe`。

收尾状态核对又发现：Windows Application 1000/1001 和 SCM 7034 在 15:45:46–15:45:50 记录了原 MemfsC 进程 68440 的 `memfs.exe` 访问异常 `0xc0000005`，偏移 `0xC7409`。随后 MemfsC 为 Stopped、M: 不可用，而 Scpfs 仍为 Running、PID 47320、R: 可用。本次没有停止/重启 MemfsC 或更换其程序；此异常的原因及与当前系统负载的关系尚未调查，不能将停启时的 M: 状态表述为收尾时仍正常。事件证据保存在 `build/cache-fix-validation/memfs-incidental-crash.json`。此次 SCPFS 交付没有包含 memfs 崩溃修复。

## 证据边界

此次是针对实际复现场景的聚焦修复，未进行全项目审计。未直接运行命中狭窄的 `cold_atime_mismatch` 分支，也未运行 strictatime/noatime 文件系统挂载模式矩阵或 Windows 重启验收。聚焦架构审查接受显式冷准入条件、真实 atime/ctime 通知、暖缓存 atime 回归及实际挂载的组合证据，不把零次诊断命中当作该分支已覆盖。

通知继续提供最终失效语义，已有打开句柄保持其快照。真实内容/命名空间变化仍采用 v1 全局失效，可能影响其他文件；不支持的远端文件系统、symlink/cross-device 监控路径或通知故障按原规则绕过缓存。首次读取仍需要 SCP 下载整个文件，每次打开使用独立工作副本；本次小文件结果不代表大文件首次传输或所有工作负载的速度。
