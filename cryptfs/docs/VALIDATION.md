# CryptFS v1 验证记录

日期：2026-10-03。此文件记录实际执行证据，不将源代码存在、配置成功或某个局部测试通过视为完整交付验收。

## 构建环境

- Windows x64，clang-cl 22.1.3，C17，CMake/Ninja。
- vcpkg：`D:\vcpkg`；`x64-windows-static`，libsodium 1.0.21、zstd 1.5.7。
- 程序和第三方用户态依赖使用静态 CRT/静态链接。
- WinFsp 2.1 用户态静态库来自 `D:\src\winfsp-memfs-static`；内嵌 x64/ARM64 签名驱动资源，程序本身为 x64。
- 构建脚本仅在进程中将 TEMP/TMP 设为项目 `build\tool-temp`，退出后恢复，不改变系统环境。

## 最终构建与存储测试

最终 Debug 与 Release 构建和 CTest 均为七组全部通过。Debug（ltools `j002`，退出码 0）存储组 216.22 秒，总测试时间 216.98 秒；Release（`j004`，退出码 0）存储组 79.51 秒，总测试时间 80.13 秒。完整 ASan 存储测试也通过（`j003`，退出码 0，结束输出 `store tests passed`），没有检测到内存访问错误。完整日志在 `build\validation\release.txt`、`asan.txt`、`debug.txt`；另直接核对项目自身的 CTest `Testing\Temporary\LastTest.log`，最终 Debug 结束于 2026-10-03 13:44:10。

早期失败记录用于定位问题，不作为最终发布版的通过证据。最终源代码修复了两条错误清理路径、已提交 namespace 与后续回收的返回语义、后台整理的提交前可恢复错误处理，以及跨越 125-entry map 边界时漏写前驱 map 链接的持久化错误。后者由 130-block 文件重新挂载后的完整内容断言复现，并由同一回归验证修复。测试程序自身的重复关闭已经修正；最终 PASS 使用修正后的测试程序。

复现命令：

```powershell
.\scripts\build.ps1 -Configuration Debug
.\scripts\build.ps1 -Configuration Release
.\scripts\test-store-asan.ps1
```

CTest 包括静态导入、嵌入资源、WinFsp 版本、驱动来源、密码学/压缩、存储引擎和命令行生命周期七组测试。存储测试还包含多个独立用例和崩溃子进程，七组不是七次简单文件操作。

存储测试覆盖页/片段认证篡改、认证有效但结构非法的自环和父节点不匹配、已提交 WAL 篡改，均要求精确错误和容器字节不变；测试拷贝保留稀疏标记并先验证有效基线。页注册失败后的 poison/关闭/重挂载，页分配失败的原大小/内容/容器 hash 不变，以及已提交 unlink/rename 后的回收失败也已覆盖。

受控 host I/O 测试包含 journal 写入与首个 flush、COMMITTED marker 写入/flush、EOF 设置、后续 home/EMPTY 写入、112 字节认证 marker 前缀的短写和稀疏 punch 失败。提交前失败保持旧逻辑状态，marker 写入尝试后的失败停止后续写入并在重挂载恢复；可恢复后台整理错误不 poison，手动重试成功。测试中的 Win32 50 punch 警告是预期注入结果，后续 EOF 收缩成功。

子进程在五个持久化阶段退出，检查普通写块、部分块截断、跨 map 链截断、unlink、rename 替换和单页搬迁的旧/新状态；另外覆盖零图像 EOF 收缩的阶段 2/3/4 和多个打开后删除的 orphan 恢复。这些断言检查重新挂载后的路径、大小、内容和尾部零填充，而不是只检查退出阶段命中。

密码学与压缩测试覆盖 XChaCha20-Poly1305、SHA-256、HMAC 已知答案、KDF 参数边界、UTF-8 密码校验、压缩回退和有界解码。Argon2id 经 libsodium 接口验证参数与调用结果；没有完成含 secret/AAD 和多 lane 参数的 RFC 9106 完整已知答案用例。

AddressSanitizer 使用 `/MT /Zi /Od /W4 /WX` 与 Release 静态库，因为 clang-cl 的 ASan 不支持 Debug CRT。Windows 下未开启泄漏检测；其通过结果只证明执行用例未出现 ASan 检测到的内存访问错误，不证明没有资源泄漏。

## 实际挂载与界面

已执行 Debug 实际挂载测试：

```powershell
python .\tests\mount_integration.py --exe .\build\x64-debug\cryptfs.exe --drive X:
python .\tests\gui_integration.py --exe .\build\x64-debug\cryptfs.exe --drive X:
```

挂载证据：`build\integration\5f4fe3bff90444f5a8f1f36920567b46\result.json`。
覆盖大小写敏感命名、创建/读写/改名/删除、四线程并发、压缩内容和随机数据、8 GiB 逻辑空洞、修改时间保存、重新挂载、错误密码不改容器、正常停止后盘符消失。

| 该次 Debug 测量 | 结果 |
| --- | ---: |
| 逻辑稀疏文件大小 | 8,589,934,608 字节 |
| 存在额外随机数据文件时的容器 EOF | 6,574,080 字节 |
| 删除该文件并后台整理后的 EOF | 4,337,664 字节 |
| 分配空间（删除前 / 后） | 2,555,904 / 327,680 字节 |
| 观察到 EOF 收缩的时间 | 约 0.101 秒 |

这些数字来自单次小规模本机用例，不能据此推断大容器或所有磁盘的性能。

有效界面证据：`build\gui-integration\78f2974498c248ee93a85afbb06ca160`。测试使用该 GUI 自身窗口的 PrintWindow 捕获，避免桌面其他窗口遮挡；截图已经人工检查。密码字段具有掩码，挂载后清空，通过继承管道发送，子进程命令行及输出不含密码；实测写入/读取和卸载均通过。挂载进程运行模块记录为系统目录 DLL，没有 WinFsp/libsodium/zstd/VC runtime 等第三方 DLL。

最终修复后的 Release 实际验证也已通过（两个脚本退出码均为 0）：

```powershell
python .\tests\mount_integration.py --exe .\build\x64-release\cryptfs.exe --drive X:
python .\tests\gui_integration.py --exe .\build\x64-release\cryptfs.exe --drive X:
```

挂载证据：`build\integration\867f16e5b42a4a64b3842a4bbe40737f\result.json`。除前述项目外，还检查一个 8,519,680 字节文件的 130 个不同 64 KiB 块，在挂载时及重新挂载后完整逐字节相等，跨过 map 边界。

| 最终 Release 单次测量 | 结果 |
| --- | ---: |
| 存在额外随机数据文件时的容器 EOF | 7,118,848 字节 |
| 删除该文件并后台整理后的 EOF | 4,882,432 字节 |
| 分配空间（删除前 / 后） | 3,080,192 / 851,968 字节 |
| 观察到 EOF 收缩的时间 | 约 0.101 秒 |

该容器同时保留跨 map 文件与 8 GiB 稀疏文件，所以最终数值与早期 Debug 小用例不同。它仍不是基准测试或大容器性能承诺。

最终 GUI 证据：`build\gui-integration\6bed43c8dad645c79cccdc537ce50f0e`。`result.json`、`runtime-modules.json` 和人工检查过的 `configuration.png` 证明实际界面密码处理、子进程传输、读写、停止与 OS DLL 范围。最终 Release 文件为 1,445,376 字节，SHA-256：`35DDD40AAF9893C101456A40DF3392C4B4C8F7255DF6E5D94A31766AC038FA75`。发布包包含同一 Release 文件，包内各文件的身份记录在 `MANIFEST.sha256`。

## 共享前端回归与环境边界

共享前端增加了密码字段及受控标准输入传递。已协调执行 memfs Debug 的五组前端/静态检查，以及 SCPFS Debug 的五组检查（含实际 GUI 集成），均通过。对应项目原发布目录及服务配置未被 CryptFS 测试替换。

所有挂载测试使用原本空闲的 X: 和项目内新建测试目录。开始和最终检查时 MemfsC 均为 Running/Automatic，Scpfs 为 Stopped/Automatic；没有停止、重装或重新配置它们。最终 X: 已释放，没有遗留本次测试的挂载进程。`git diff --check` 和直接覆盖未跟踪源码/文档的尾随空白扫描均通过；没有创建提交或推送。

## 限制和未执行项目

- 没有进行真实断电、主机系统崩溃、宿主磁盘完全写满、设备缓存异常、长时间稳定性或大容器性能验收。故障钩子和进程终止只能证明所注入路径。
- 没有实际填满 4,000,000 个物理页或创建到 65,536 节点；页分配失败钩子验证对应失败路径，不能冒充真实满容量测试。
- 非 64 KiB 对齐的缩小可能需要新的边界数据页，物理槽耗尽时返回空间不足并保持旧文件；零长度和块对齐截断可释放空间。
- 单容器独占打开；v1 没有硬链接、备用数据流、持久化 Windows ACL、密码更改或服务自动解锁。
- 文件名、内容、元数据经过认证加密，但旧的有效容器或同槽同标识旧页重放不可检测；没有安全擦除和内存/页面文件加密承诺。
- 挂载认证全部存活页，开锁时间随实际已用容量增长。后台缩短在存储净增长稳定时逐步收敛；持续新增数据没有固定收缩时限。

## 架构审查

格式与事务协议先经过架构决策，关键所有权、恢复和后台整理边界由独立审查者复核。`ARCHITECTURE_REVIEW.md` 已记录最终限定范围验收通过，无新的阻断性架构问题；架构接受仅覆盖记录的 v1 范围，不代替真实断电、设备缓存或满容量验收。
