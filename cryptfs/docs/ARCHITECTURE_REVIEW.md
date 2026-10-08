# CryptFS v1 持久化架构审查（2026-10-03）

## 结论与范围

**状态：v1 持久化架构在下述已验证边界内验收通过，没有新的阻断性架构问题。** 固定 WAL、双状态标记、恢复前整图认证、单页后台搬迁及新增 map 链前驱 afterimage 符合既定格式。此前发现的两项 P1 所有权错误、命名空间提交后回收返回语义、后台故障分类及跨 map 追加丢数据路径均已修复。最终 Debug、Release、严格 ASan、实际 WinFsp 挂载及 GUI 回归已完成。此结论是限定范围的架构验收，不是对真实断电、设备缓存、磁盘写满或大规模容量的运行认证；重要数据仍需独立备份。

本审查只覆盖 `src/cryptfs_store.c` 中的打开/恢复、图加载、事务、写块、resize、orphan、rename、页销毁，以及 `src/cryptfs_compact.inc` 的搬迁和 worker；密码学辅助函数只检查了与上述边界直接相关的调用。没有做全项目审计、修改生产源码、独立编译或独立运行测试。审查者直接读取了项目内最终日志和 Release 挂载/GUI 结果；测试执行及进程退出码由协调方提供。对应源码 SHA-256：`cryptfs_store.c` 为 `AA28A6434F0B92785A739FF19972EDBE56EFB1094F28DCB3FCD5AD693D4EFB5A`，`cryptfs_compact.inc` 为 `F24C82A50D73E8C7FA981B7A6FD5E7CA977C22001F1C60C7FB8FA3A8C6E09A58`。最终 Release `cryptfs.exe` SHA-256 为 `35DDD40AAF9893C101456A40DF3392C4B4C8F7255DF6E5D94A31766AC038FA75`。

## 已确认的设计对齐

- `cf_tx_commit` 先写并 flush 完整加密 journal，再尝试 COMMITTED 标记；从尝试写 COMMITTED 标记起，只要失败就 poison store。随后写 home afterimages、flush、设置并 flush EOF，最后写并 flush EMPTY 标记（`cryptfs_store.c:1953-2121`）。下一事务只在该函数成功后进入。
- `cf_store_open` 先解封 superblock、认证状态标记并读取已提交 journal；`cf_graph_validate` 用 afterimage 覆盖 home 页，对所有可达 inode、map、fragment 及完整解码块验证成功后，才调用 `cf_recover_committed` 写回（`cryptfs_store.c:2439-2573`）。因此，对挂载前已损坏的**可达**页，源码顺序支持“认证失败不改容器字节”的原则。整图成本是 O(存活页)，大容器开锁时间尚无证据。
- `cf_node_resize` 将边界块重写、map 截断和 inode 大小放进同一事务；提交前回滚恢复 map 链、边界指针、大小和时间，提交后才移除旧页（`cryptfs_store.c:3718-3957`）。`keep == 0` 时序列化前驱 map 的断链；五个持久化阶段的跨 map 截断与重新增长已进入最终存储测试。
- `cf_page_unregister_tree` 从父页 owner 列表摘下子页，迭代下降，先保存返回父页再释放当前页；在“每页单 owner、无环”不变量成立时避免深递归与父页提前释放（`cryptfs_store.c:517-544`）。`cf_reclaim_orphans` 在 WAL 提交前保留 orphan 链的回滚路径，提交后才销毁页和节点（`2257-2363`）。
- `cf_store_compact_locked` 选最高存活槽 H 和较低空槽 L，验密后用新 nonce 重加密页，连同 owner 页的指针改写在一个 WAL 事务提交；提交成功后才更新 RAM 槽表，随后单独执行可持久恢复的零图像 EOF 缩短事务（`cryptfs_compact.inc:62-200`）。源页与目标页的唯一 owner 约束使这一步不需要新建父链，支持净容量稳定时逐步收敛。worker 每步释放锁，停止时在锁外 join（`203-266`，销毁见 `cryptfs_store.c:2173-2219`）。

## 历史发现与当前解决状态

1. **[P1 已修，最终套件通过] 损坏片段的打开失败清理。** 当前 `cf_graph_load_maps` 在 `map->blocks[i] = block` 之前完成可独立释放的检查；挂入后由 map 独占块，片段读取/认证等后续失败不再局部 `free(block)`（`cryptfs_store.c:1205-1295`）。有效 map 指向受损片段的精确 `CF_DATA_ERROR`、容器无写、pristine 复开和 ASan 安全退出已通过；完整严格 ASan 存储套件也通过。

2. **[P1 已修，最终套件通过] 写块提交后页注册失败。** `cf_node_write_block` 在 WAL 成功时设置 `committed`；`done` 只对 `!committed` 执行 map/size 回滚（`cryptfs_store.c:3415-3419`、`3467-3499`）。提交后注册失败仍 poison，但不会把 map 恢复为指向已释放旧块的状态。单次注册失败注入、poison 后关闭、重挂载读取新提交字节及 ASan 均通过。

## 事务语义和回收边界

- **[已修，最终套件通过] 命名空间提交后的回收结果。** `cf_node_unlink` 与替换式 `cf_node_rename` 在命名空间 WAL 成功后，即使后续 `cf_reclaim_orphans` 失败也保留该操作的成功结果，并以 `cf_record_reclaim_failure` 记录诊断；提交点不确定时 store 仍由 `cf_tx_commit` poison（`cryptfs_store.c:3977-4047`、`4154-4360`）。回收内存/journal/marker 故障注入与重挂载状态检查已进入最终套件并通过。
- **接受的 v1 产品边界：**非 64 KiB 对齐的缩小在提交新边界页前先从空闲槽申请全部新 fragment（`cryptfs_store.c:3767-3810`）。物理页预算耗尽时，缩小文件可以返回 `CF_NO_SPACE`，条件是该次操作未进入 COMMITTED、旧大小/边界明文/map 链与磁盘字节保持完整，重挂载后也不改变。README 已披露此行为；0 长度、64 KiB 对齐截断和 unlink 在相同注入失败条件下仍可释放空间。后台回收产生空槽后可重试。本版不引入旧槽原位复用，以保持“提交前旧 home 完整存在”的恢复边界。
- **[已修，最终套件通过] 稀疏 punch 失败可见。** 搬迁提交后源槽 `FSCTL_SET_ZERO_DATA` 失败会保存 Win32 错误并发出警告；该失败不撤销已提交的 owner 指针和目标页，后续 EOF trim 继续（`cryptfs_compact.inc:153-170`）。一次性 punch 故障下逻辑数据与后续尾部收缩已验证；实际宿主文件系统的长期 punch 行为仍未测试。
- **[新增数据丢失路径已修，最终套件和实际挂载通过] 追加第二个 map 页必须同时提交前驱链接。** 130 个逻辑块的原先实现曾在内存中正确写出尾块，但重挂载读成稀疏零页，因为前一 map 的 `next` 只在 RAM 改变。现在 `cf_node_write_block` 标记 `appended_map_after_previous`，把前驱 map 与新 map 一同写入 WAL（`cryptfs_store.c:3372-3375`、`3407-3411`）；`FORMAT.md` 也记录此不变量。严格 ASan `--map-tests` 的五个 crash phase、完整 Debug/Release/ASan，以及最终 Release WinFsp 挂载的 130 块卸载/重挂载全文比较均通过。

## 最终运行证据

协调方以 clang-cl、`D:\vcpkg` 静态依赖执行下列命令，并报告三个进程均以退出码 0 结束。审查者直接核对了对应项目日志；`cryptfs_store_test` 内含多个故障注入和子进程崩溃用例，CTest 的七组数量不代表仅七次文件操作。

| 执行 | 结果 | 项目内证据 |
| --- | --- | --- |
| `scripts/build.ps1 -Configuration Debug` | CTest 7/7 PASS；store 216.22 秒，总 216.98 秒 | `build/validation/debug.txt`、`build/x64-debug/Testing/Temporary/LastTest.log` |
| `scripts/build.ps1 -Configuration Release` | CTest 7/7 PASS；store 79.51 秒，总 80.13 秒 | `build/validation/release.txt` |
| `scripts/test-store-asan.ps1` | 严格 ASan 存储套件通过全部阶段，输出 `store tests passed`，没有 ASan 内存访问错误；注入的 sparse punch Win32 50 警告为预期 | `build/validation/asan.txt` |

最终存储套件覆盖普通写块和 partial resize 的持久化阶段、130 块跨 map 追加/截断及零尾重增、open-unlink、替换 rename、单页搬迁与独立 zero-image EOF 截断的子进程 crash phase 1–5。它还覆盖写入/flush/EOF/短认证标记/punch 故障、提交前旧状态回滚、提交点不确定后的 poison、提交后回收失败、损坏片段和认证有效但结构非法的图、WAL/page 篡改与无写拒绝。测试用例和阶段输出位于 `tests/test_store.c`、`build/validation/asan.txt`；这属于确定性故障注入及进程退出验证，不等同于真实断电。Windows ASan 未启用泄漏检测，其通过结果不证明无资源泄漏。

最终 Release 实际 WinFsp 挂载运行 `tests/mount_integration.py`，`build/integration/867f16e5b42a4a64b3842a4bbe40737f/result.json` 的 `passed` 为 true。挂载用例写入 130 个各 64 KiB 的不同块，共 8,519,680 字节，卸载重挂载后与原字节串全文比较通过；还覆盖 8 GiB 逻辑稀疏文件、四线程 I/O、时间戳和错误密码时容器哈希不变。该次容器 EOF 从 7,118,848 降到 4,882,432 字节，宿主分配量从 3,080,192 降到 851,968 字节，测得约 0.101 秒的收缩；这些是单次小规模本机观测。

最终 Release GUI 运行 `tests/gui_integration.py`，`build/gui-integration/6bed43c8dad645c79cccdc537ce50f0e/result.json` 的 `passed` 为 true；证据包括遮蔽密码字段、继承管道传密、子进程参数无密码、字段清空、正常卸载后盘符消失，以及挂载进程仅加载系统目录运行模块。协调方人工检查了对应 `configuration.png` 截图。共享前端 memfs/SCPFS 回归及驱动来源/静态导入检查记录在 `docs/VALIDATION.md`。

## 保留的边界和后续验证

- 真实断电、主机崩溃、宿主磁盘写满、设备缓存异常、长期稳定性以及真实达到 4,000,000 页或 65,536 节点均未测试。确定性钩子验证相应错误分支，不能替代这些运行条件。
- 解锁需要认证全部存活页，大容器延迟与接近容量上限时的后台收缩进展仍需量测。单次本机 EOF 收缩不能外推到大卷或其他文件系统。
- 格式明确不提供旧的完整有效容器或同槽同标识旧有效记录的回滚检测；这是已记录的 v1 安全边界。加密容器也不承诺删除数据安全擦除。
- 后台整理遇到可恢复的提交前故障会停止本轮并记录错误，前台继续可用，等待后续 wake。`cf_store_wait_idle` 只证明 worker 空闲，不证明空间已经回收；使用统计或显式 compact-step 结果核对目标 EOF。

## 最终架构决策

**接受决策 B，并接受本次 v1 持久化里程碑。** `cf_tx_commit` 在首次尝试写 COMMITTED 标记前若因内存、journal 写入或首个 flush 失败，旧 EMPTY 标记仍是权威状态，旧 home 页和 EOF 未改；后台本轮停止、记录错误，前台可继续。自 COMMITTED 标记首次尝试写入起，任何失败都属结果不确定，必须 poison 并要求重挂载；AEAD、owner 指针或页图不变量错误也必须 poison。搬迁和零图像截尾的当前分类见 `cryptfs_compact.inc:16-55`、`147-150`、`193-196`、`231-256`，最终故障注入套件已通过。

当前证据不要求改变公共 API、v1 序列化格式或并发边界。上述未测项目应作为独立运行验收与后续研发任务保留；若真实断电、满容量或大卷测试推翻已验证前提，应重新审查相应事务、恢复或容量设计，不能把本次限定范围接受当作这些条件已获证明。
