# SCPFS 文件访问缓存修复：专项验收审查

日期：2026-10-03（Asia/Shanghai）。审查范围：`server/scpfs_watch.py`、`src/scpfs.c` 的冷/热缓存准入路径、`src/scp_cache.c` 未改变的字节来源契约，以及该修复对应的有限 Debug/Release、V: 和 R: 证据。本审查核对 `CACHE_ACCESS_DECISION.md` 中的决策，不是全项目审计、完整负载基准或重启验收。

## 状态

**最终专项验收：修复后的访问事件缓存行为及生产主机实测 V:/R: 场景满足既定门槛；本范围内没有具体阻断项。** 根任务执行了构建、测试、服务更新和挂载检查。本审查独立回读了保存的证据以及相关源码/二进制哈希。本次读取到的源码哈希为：

- `server/scpfs_watch.py`：`2483a7ac5d19b7e686c2b0a0599586d9fddca1214fa1473954a5da3a0a5774bd`
- `src/scpfs.c`：`4dedba996aa804d2ec6e25163c4bcc9c588c7e1220740f34d97115958327f819`
- `src/scp_cache.c`：`2d190bf0996d1355c507d10361d1cd817221b988b8b302bc756d91acf6a46bf6`

首次读取后适配器哈希发生变化，原因只是删除了已无用的 `scpfs_cache_stat_provenance_equal` 包装函数。我从保存的基线中提取该函数 408 字节，并在内存中插回当前源码；重建后的 SHA-256 与先前审查过的适配器哈希 `c7480b60a4759aa4fe543467aa97776ffa8ac6207e7126eccbf50c426e8807a1` 完全相同。当前失配掩码和冷缓存 atime 谓词分别位于 `src/scpfs.c:652-666` 和 `src/scpfs.c:1574-1583`。上述三个当前源码哈希也与发布包中的 `dist/scpfs-x64/SOURCE-SHA256.json` 匹配。后续若源码再改，保留本结论前必须重新审查改动区域。

## 源码检查结果

1. helper 的 `FileSnapshot` 记录 dev/inode/mode/uid/gid/size/atime_ns/mtime_ns/ctime_ns。`classify_inotify_event` 对所有内容掩码发送 `E 1`，对任何 `IN_ATTRIB` 发送 `E 2`；只有精确的 `IN_ACCESS` 会进入快照分类。对该访问事件，身份/类型变化会引发 `WatchError`，大小或 mtime 变化发送 `E 1`，其他样本元数据变化发送 `E 2`，tuple 完全相同则抑制通知。这保留 v1 协议及对真实更新的保守处理（`server/scpfs_watch.py` 中的 `FileSnapshot`、`classify_access_snapshot`、`classify_inotify_event`）。
2. `Watcher.ensure` 为每个 inotify watch descriptor 保存一个样本；硬链接别名返回同一 descriptor 时保留旧样本。安装新 watch 前后会比较 stat，因此安装期间发生时间戳/身份变化时 fail closed，不会用未经证明的基线准入缓存。`_verified_file_snapshot` 不跟随符号链接或跨越已记录设备，验证所有祖先后只接受叶路径仍指向被监控 inode 的已记录别名；找不到有效别名或别名样本不一致都会引发 `WatchError`。`drain_events` 将队列溢出、监控丢失和未知 descriptor 视为致命情况，并在已分类的文件事件后更新样本（`server/scpfs_watch.py` 中的 `ensure`、`_verified_file_snapshot`、`drain_events`）。
3. 现有 `W` 流程先排空事件、重新验证覆盖范围再确认；`B` 会在确认前排空事件。一个硬链接别名删除后，只要另一个已记录别名仍指向同一 inode，就可以跳过已删除别名。这本身不会接受陈旧命名空间数据：被监控的父目录会提供删除/改名内容事件，之后针对替换路径的 `W` 会因身份不符而失败。helper 回归夹具明确覆盖了该所有权情况。若新测试发现命名空间事件可能跨 barrier 丢失，发布前必须重新审查这一例外。
4. 冷负载缓存准入现在要求内容来源未变，并且后端恢复时间戳后的 stat 与稳定 barrier/generation 后的验证 stat 具有完全相同的 atime（`src/scpfs.c` 的 `scpfs_cache_stat_provenance_mismatch_mask` 和冷路径 `same_stat` 分支）。因此不会在新元数据 epoch 下发布仍携带旧 atime 的字节副本。热缓存 metadata-stale 路径仍会重新取 stat、执行验证 barrier 和字节来源检查；`scp_cache_validate_payload` 随后用新 stat 更新保存的来源信息。字节比较器仍排除 atime，但会校验 type/dev/inode/size/mtime/mode/uid/gid/ctime（`src/scpfs.c` 热路径 `scp_cache_validate_payload` 分支；`src/scp_cache.c` 的 `scp_cache_same_payload_provenance`）。后端冲突比较器不属于此次修改。

## 测试与运行证据

源码比较基线为 `build/cache-fix-baseline-20261003-144150`。helper worker 的自有 WSL 夹具以退出码 0 完成；`build/cache-fix-validation/watch-helper.log` 记录了 atime 不变时抑制事件、覆盖范围确认、metadata/content 掩码、改名/删除、不支持路径、错误帧和溢出均通过。保存的 clang-cl Debug/Release 运行结果 `build/cache-fix-validation/x64-debug-ctest.txt` 与 `x64-release-ctest.txt` 均报告 **13/13 通过、零跳过**（分别用时 72.33 和 90.98 秒）。Debug 在删除无用包装函数之前构建；Release 编译了最终源码。两个运行的 WinFsp 压力结果位于 `build/x64-debug/cache-access-integration/cache-access-results.json` 和 Release 对应文件中，记录了 728/729 次后台远端读取及相同数量的 `IN_ACCESS`。每次运行中，文件 A 有 20 次负载命中，`warm_metadata_stale=0`，没有冷缓存来源或 atime 失配。这些夹具通过真实 inotify 和 WinFsp 覆盖普通访问回归；套件的其他用例在自有夹具中覆盖修改、时间戳、改名、冲突和回退行为。

生产主机只读候选 V: 记录 `docs/CACHE_ACCESS_V_ACCEPTANCE.json` 使用 Release 可执行文件，SHA-256 为 `CDA91BC8EBA4B8EF59F4E0CF6D69DE6D6592BDAA4D182E940BB1B11EE6306CEA`。它列出 248 个 `/etc` 条目后，连续六次读取同一 11 字节文件，耗时 **1.580–2.240 ms**，且始终复用同一缓存负载名。保存的 stderr 报告 17 次负载命中、1 次负载未命中、`warm_metadata_stale=0`、1 次冷写入尝试和 0 次监控绕过。临时进程退出码为 0，V: 已释放。39 个模块的清单没有意外或禁止路径。旧二进制的 V: 隔离观察中，列出 `/etc` 后首次读取耗时 4,741 ms，之后五次为 820–1,032 ms。该对比证明此次测量路径上的修复效果，不是通用延迟保证。

服务更新记录 `docs/CACHE_ACCESS_SERVICE_UPDATE.json` 确认服务正常停止、发布并重新启动，且没有回滚。原可执行文件保存为 `dist/scpfs-x64/scpfs-before-cache-access-fix-20261003-153338.exe`，SHA-256 为 `439A0166B873E14C9A3B6E7AFA9C27DD4918ACC620B8E1A5397E66608FD0ABCD`。我独立计算了该备份、测试 Release 候选和正式 `dist/scpfs-x64/scpfs.exe` 的哈希：后两者大小均为 5,397,504 字节且逐字节一致，SHA-256 即上面的候选值。`build/cache-service-update-20261003-153338/service-before.json` 和 `service-after.json` 显示 R: 的 Automatic/LocalSystem 配置及命令行一致；PID 从 61772 变为 47320。这证明 R: 检查所用的可执行文件和服务配置，不代表完成了重启验证。

实际 R: 结果 `docs/CACHE_ACCESS_R_ACCEPTANCE.json` 报告正在运行的 Scpfs 服务（PID 47320）`passed=true`。初始、根目录列表和 `/etc` 列表各阶段的全部 18 次读取都返回 11 字节、内容 SHA-256 相同；句柄关闭后，同一负载 `read-{12A9FD75-C3F1-43CE-978E-EF5568C94440}.cache` 仍存在。列出 `/etc` 后的六次读取耗时 **2.490–4.110 ms**，后五次中位数为 **3.109 ms**。服务报告缓存目录 `C:\\Windows\\Temp\\scpfs\\session-{2B9201F3-D967-4E0B-B53B-495BD1032D62}` 和 `cache_max_mib=0`。R: 保存的模块清单包含 39 个模块，全部位于可执行文件、Windows/WinSxS 路径内，没有意外或禁止模块。这些观测完成了针对小文件和当前服务会话的 R: 在线回归门禁，但没有覆盖所有文件大小、负载、远端文件系统或 Linux atime 挂载模式。

## 冷 atime 竞态门禁

新的冷缓存准入条件明确要求：稳定的监控 generation 后，只有全部字节来源字段**以及** `handle->current.atime_ns == fresh_stat.atime_ns` 成立时才发布负载（`src/scpfs.c:1574-1583`）。独立计数器 `cold_atime_mismatch` 只有在后端最终恢复时间戳后的 stat 与下载后第一次 barrier 之间发生 atime 变化时才会递增；此时 `after` 已包含其 `E 2`，但后续验证 stat 才看到新 atime。若变化更晚，第二次 barrier 会先拒绝该 generation。因此真实 atime 前进通常会覆盖元数据 generation 拒绝路径，而不是这个狭窄计数器。

**架构验收决定：**此次有限修复不要求通过确定性适配器夹具强行命中这一特定时序窗口。直接源码谓词、helper 中 atime 改变和 ctime 阻止 `B -> A` 恢复掩盖变化的测试、热缓存 atime 单元回归、真实 Debug/Release 缓存压力测试，以及 V:/R: 主机检查共同满足该专项门禁。保存的运行记录中没有命中独立的 `cold_atime_mismatch`（bit 9）分支；不得将其宣称为已通过运行时覆盖。可以再用自有文件尝试命中此竞态，且不得改变通知行为或注入陈旧数据；但未命中并不推翻已有 generation 拒绝证据或源码谓词。该验收范围小于确定性的竞态证明，也不证明时间戳快照具有线性一致性。

若后续故障表明必须直接覆盖该路径，最小内部设计是在适配器和专项单元夹具中共用一个私有冷准入谓词，输入两份 stat 快照及 generation 状态。保持测试缝隙为内部接口；不得添加公开监控协议、关闭事件报告，也不得仅为命中计数器而向生产路径注入陈旧数据。

## 剩余边界

本审查只接受已测根目录 `/` 负载和现有夹具矩阵。生产主机 V:/R: 检查是只读操作；外部修改及时间戳可见性由自有 WSL/WinFsp 夹具验证，没有修改宿主系统文件。观测到的 11 字节热读耗时不是所有文件大小的吞吐量/延迟保证。未测试 strictatime/noatime 组合、服务长期运行或 Windows 重启。根任务保存的验证结果证明构建、发布和运行行为；本专项架构审查不会取代那些检查，也不扩展为全文件系统审计。
