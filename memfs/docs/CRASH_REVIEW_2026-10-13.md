# Memfs 崩溃与 auto 容量修复

日期：2026-10-13（Asia/Shanghai）。范围：`D:\work\fs\memfs` 的同节点并发崩溃、auto 容量统计和现有 MemfsC 服务恢复。

## 崩溃根因与修复

Windows Application 事件 1000/1001 记录了 00:41:25 的 `memfs.exe` `0xc0000005`。故障的 System32 映像 SHA-256 为 `100B3B6A1CC3094B25B3DF0728CE626E9D69F3BEE187E131298EB0289E1549DC`。CDB 转储显示 `memfs_storage_replace_page_ex` 插入页指针时，`rank=52`、`page_count=51`。32 位的 `page_count-rank` 下溢，将 `memmove` 长度算成约 32 GiB，随后越界读取。原服务转储没有 page group 堆内容，不能从中直接读取位图和指针数组。

已在隔离 V: 上用旧 System32 镜像复现：`\\?\V:\fixture\x.bin` 与 `\\?\V:\fixture\.\x.bin` 报告相同的 memfs 文件索引。四个 writer 并发向该文件的同一稀疏 page group 写入时，旧映像在第 29 轮访问异常退出，退出码 `0xC0000005`。WinFsp 对这些路径分别建立的文件名上下文不能保证同一后端节点的写入互斥；页组位图与 `page_count` 使用普通读改写，因而可以丢失并发更新。

修复在 WinFsp 适配层增加 64 个按 memfs 节点索引散列的读写锁。同一后端节点的读、写、EOF、属性快照和覆盖操作使用同一把锁，不同节点仍可并行处理。修复没有改变 `MemfsNode` 大小、公开文件格式或 WinFsp callback ABI。

修复后的 Release 对相同的 V: extended-path 负载连续 64 轮通过：子进程退出码为 0，所有页读回的数据完整，临时卷正常卸载。Debug `memfs_winfsp_state_test` 并发用例也通过。调试器显示 `final_names` 查询返回 WinFsp `ERROR_UNRECOGNIZED_VOLUME`，因此该测试将两条路径映射到相同后端索引和压力下的数据完整性作为证据，没有声称 GetFinalPathName 成功。

历史 M: 转储中的 bitmap 本体不可读；隔离复现证明这条同节点并发写路径可以产生同类访问异常，修复已阻止该触发场景。报告不将 Windows 旧转储缺失的堆内容表述为已直接验证。

## auto 容量修复

`GlobalMemoryStatusEx` 给出系统当前可用的物理内存和提交额度；已有的 memfs 分配已反映在这些 OS 数值中。旧公式再次扣除 memfs 的 allocator committed bytes，并在 `resident_bytes` 越过剩余额度时把系统增长额度清零，重复扣减导致可用空间突降。修复只从 OS available 中扣除原有 hard margin；未使用的 committed reserve、快照期间新增 commitment 扣减、回收逻辑和写失败回滚保持原状。

旧公式新增回归在修改前 5 项失败。Release 原生 V: 测试在默认 1 GiB reserve 下，分别完整写入及读回 1.5 GiB 原始数据、高度可压缩数据和启用压缩的随机数据。每阶段使用单次 `GetDiskFreeSpaceExW` 快照；`total - free` 与文件长度误差不超过 512 字节。删除后已用量归零，V: 正常释放。数据在：

- `build/auto-20261013-evidence/raw-9cc4c92b1c6d/result.json`
- `build/auto-20261013-evidence/compressible-6b78ba9d1f8e/result.json`
- `build/auto-20261013-evidence/compressed-random-66c1c8fea5d6/result.json`

## SCM 自动恢复

此前 MemfsC 没有 SCM failure actions。当前生产服务已配置服务意外失败后延时 1 秒、5 秒和 30 秒重启，86400 秒后重置失败计数，并对非崩溃失败启用恢复。隔离服务验证只终止本测试临时创建的服务：SCM 用新 PID 重启、重新挂载并通过读写校验；生产 MemfsC 的 PID 在测试前后不变。

## 构建与部署

Debug、Release 两套 CTest 均 **26/26 通过，0 failures，0 skips**；Release 编译日志没有 warning 或 error，PE 导入检查通过。候选 SHA-256 为 `FE3F80B681820CD02730531D35839F784AE60F7F4CBBDFBDB7726401B95F15C9`。

按用户要求，候选已替换到服务使用的 `C:\Windows\System32\memfs.exe` 并正常重启。PID 从 19836 改为 60080，Running/Automatic/LocalSystem 状态和 SCM 命令行保持不变，M: 与 `M:\tmp` 已恢复可用。原映像作为 `C:\Windows\System32\memfs-before-restart-fix-20261013-061303.exe` 保留，SHA-256 为 `100B3B6A1CC3094B25B3DF0728CE626E9D69F3BEE187E131298EB0289E1549DC`。部署及服务状态记录在 `build/auto-20261013-evidence/MemfsC-autofix-deployment.json`，恢复策略记录在 `MemfsC-recovery-policy.json`。

M: 是易失性内存盘；重启后，旧 M: 文件已清空，`tmp` 目录由服务启动参数重新创建。