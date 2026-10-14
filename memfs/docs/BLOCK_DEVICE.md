# 块设备模式（`--block`）

memfs 默认通过 WinFsp 提供文件系统。WinFsp 在内核驱动中拒绝硬链接（`src/sys/fileinfo.c` 对 `FileLinkInformation` 直接返回 `STATUS_NOT_SUPPORTED`），也不转发 TRIM、清零等 FSCTL，因此无法提供完整的 NTFS 语义。

块设备模式改为提供一块虚拟磁盘，由 Windows 自带的 NTFS 驱动格式化和管理。硬链接、USN 日志、对象 ID、事务等全部由 `ntfs.sys` 实现，语义完整；memfs 只负责保存扇区数据。

## 依赖：Arsenal Image Mounter

虚拟磁盘由 [Arsenal Image Mounter](https://github.com/ArsenalRecon/Arsenal-Image-Mounter)（AIM）的已签名驱动提供：

- `phdskmnt.sys`：Storport 虚拟 SCSI 适配器；
- `deviodrv.sys`：把磁盘 I/O 转发给用户态进程（DevIoDrv 模式）。

memfs 只实现 ImDisk/DevIoDrv 公开代理协议（`imdproxy.h`，MIT 许可，结构在 `src/memfs_devio.c` 中重新声明），不链接任何 AIM 代码。AIM 驱动与命令行工具 `aim_ll.exe` 单独安装，memfs 以独立进程调用 `aim_ll`。AIM 本身为 AGPL v3 / 商业双许可，分发时需单独遵守其条款。

安装（管理员）：

```powershell
aim_ll --install <DriverFiles 解压目录>
Start-Service deviodrv
```

## 用法

```powershell
memfs.exe --block --mount X: --size auto --compress --encrypt
memfs.exe --block --mount X: --size 8G --disk-size 64G --aim-ll D:\tools\aim_ll.exe
```

| 参数 | 说明 |
| --- | --- |
| `--block` | 启用块设备模式；可在控制台运行，也可用 `--install` 安装为服务 |
| `--mkdir <路径>` | 格式化并分配盘符后创建目录（可重复、可多级），例如给 TEMP 用的 `tmp` |
| `--label` | 卷标，1～32 个字符，不能含空格（`aim_ll` 把格式化参数整体放在一对引号里传给 format） |
| `--mount X:` | 盘符 |
| `--size` | 固定值：可存储的数据上限（页数 × 4 KiB，实际内存另加 1%～3% 页头开销）；`auto`：随可用内存变化 |
| `--disk-size` | 虚拟磁盘大小；默认等于 `--size`，`auto` 时等于物理内存总量 |
| `--aim-ll` | `aim_ll.exe` 路径；默认在 memfs.exe 同目录，然后查 PATH |
| `--block-name` | DevIoDrv 对象名；默认 `memfs-block-<pid>` |
| `--block-threads` | I/O 工作线程数 1..64，默认 4 |
| `--compress` / `--encrypt` / `--key-*` | 与文件系统模式相同，按 4 KiB 页压缩、认证加密 |
| `--stats` / `--stats-json` | 挂载和停止时输出驻留内存与 I/O 统计 |
| `--stop-event` | 命名事件，触发后正常卸载退出 |

启动流程：创建内存存储 → 打开 `\\?\DevIoDrv\<名称>` 作为服务端 → `aim_ll -a -t file -o par,fix` 挂载并快速格式化 NTFS、分配盘符。停止时按设备号 `aim_ll -d -u <设备号>` 卸载（`aim_ll` 按挂载点查找设备号在卷卸下后会出错），再关闭服务端。

## 以服务运行

```powershell
memfs.exe --install --block --service-name MemfsBlock --mount X: --size 8G --compress --mkdir tmp --aim-ll D:\tools\aim_ll.exe
memfs.exe --uninstall --service-name MemfsBlock
```

- 服务以 LocalSystem 运行，开机自动（延迟）启动，盘符是全局的，提权程序也能看到。
- 安装时把 `aim_ll` 解析为绝对路径写进服务命令行（LocalSystem 的 PATH 与安装者不同），并声明依赖 `deviodrv`、`phdskmnt` 两个驱动服务。
- 挂载和格式化期间向 SCM 报告启动进度，盘可用（含 `--mkdir`）后才报告 RUNNING。
- 停止时与控制台模式相同：按设备号卸盘，再关闭 DevIoDrv 服务端，从不取消挂起请求。服务接受 PRESHUTDOWN，关机时有足够时间卸盘。
- 盘被外部卸下时服务以退出码 8 结束，SCM 故障恢复会在 1 秒后重启服务并重新挂载（实测约 2 秒恢复）。
- 用作 TEMP 时建议固定 `--size`（`--disk-size` 不大于它），不要用 `auto`：内存不足时块设备只能返回 I/O 错误。

2026-10-14 用独立服务名实测：安装、依赖、NTFS、`--mkdir`、硬链接、停止（约 260 ms，退出码 0，无残留设备）、再次启动、重启、外部卸盘后自动恢复、卸载均通过。尚未在真实关机/开机流程中验证。

## 内存与容量

- 数据按 1 MiB 分条，分布到 16 个内部节点，每个节点一把锁，不同分条的 I/O 并行。
- 只保存写入过的 4 KiB 页；全零页不存储。虚拟盘大小只是声明，不占用内存，也不计入配额（`MemfsOptions.block_backing`）。
- TRIM/UNMAP 与清零请求通过 `memfs_node_punch_hole()` 立即释放页。它只遍历实际存在的页组，格式化时对整盘的 TRIM 也很快。NTFS 删除文件后会批量发送 TRIM，通常在十几秒内回收；`Optimize-Volume -ReTrim` 可立即回收。
- 容量只对写入新增的页计费，改写已存储的页不需要容量（NTFS 会原地改写日志和元数据）。固定容量按已存储页数 × 4 KiB 计算，因此 `--disk-size` 不大于 `--size`（默认相等）时，磁盘总是先于容量写满，NTFS 得到的是"磁盘已满"而不是设备错误；`auto` 按每个新页的最坏内存占用询问可用内存。写入在修改任何数据前检查容量，容量不足的写入不会只写一半。
- 早期版本按驻留堆字节计算固定容量：加密页每页多 32 字节以上，盘大于约 2.6 GB 时会在写满前触发容量不足，写入（包括原地改写）失败并在系统日志中记录磁盘 154 号"硬件错误"事件。2026-10-14 已修复，4 GB 加密盘写满实测无设备错误。
- **固有限制**：块设备无法向 NTFS 报告"空间已满"。内存不足时写入只能返回 I/O 错误（驱动把任何非零 `errorno` 映射为 `STATUS_IO_DEVICE_ERROR`）。请为 `--size auto` 保留足够余量（`auto` 的默认盘大小等于物理内存总量，通常大于可用内存），或用固定 `--size` 并让 `--disk-size` 不大于它。

## 安全注意（重要）

**不要对 DevIoDrv 的挂起请求调用 `CancelIo`/`CancelIoEx`。** 虚拟盘卸下后，`deviodrv.sys` 的取消回调会解引用已释放（为 NULL）的队列，导致蓝屏 `0xD1 DRIVER_IRQL_NOT_LESS_OR_EQUAL`（2026-10-14 实测，调用栈 `NtCancelIoFileEx → IoCancelIrp → deviodrv+0x3608`）。AIM 官方服务也从不取消请求。memfs 停止时只关闭服务端句柄，由驱动在清理阶段完成挂起请求，工作线程等锁定请求完成后才释放缓冲区。

## 验证

- `tests/memfs_block_test.c`（CTest `memfs_block_test`）：1 TiB 稀疏盘、跨分条读写、末扇区、非对齐 TRIM、整盘 TRIM 用时、固定容量拒绝写入、压缩/加密往返、8 线程并发。
- `tests/block_device.ps1`：需要管理员与已安装的 AIM。普通与压缩+加密两种模式下验证 NTFS、硬链接、写入使内存增长、绕过缓存读回校验、删除后经 TRIM 回收内存、正常卸载无残留设备，以及多轮挂载/卸载。

```powershell
.\tests\block_device.ps1 -MemfsExe .\build\x64-release\memfs.exe -AimLl D:\tools\aim_ll.exe
```

2026-10-14 实测（Windows 11 26300，AIM 驱动 2026-04-22 版，Release）：普通模式写入 400 MB 随机数据，进程内存 33→462 MB，删除后自动回到 34 MB；压缩+加密模式 20→448 MB，删除后回到 20 MB；多轮挂载/卸载全部干净退出，无残留设备，无蓝屏。

同时修正了分配器：加密的满页（4128 字节）和压缩失败的页（4104 字节）原本落入 8192 字节档位，内存占用接近翻倍；新增 4224 字节档位后，上述压缩+加密测试的内存增长从约 917 MB 降到约 428 MB。该修正同样作用于文件系统模式。
