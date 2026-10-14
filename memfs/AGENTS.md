# memfs 项目维护约定

## 服务重启与数据

用户于 2026-10-14 明确确认：在任务已授权重启 `MemfsC` 的情况下，内存卷可以清空，不需要备份或恢复卷内文件。不要照旧部署脚本恢复 `moe_ue_all.h` 或整个 tmp。保留 `--mkdir tmp`，确保新卷的临时目录在启动时存在。

这不是无条件重启服务、强制关闭其他用户程序或重启 Windows 的授权。需要重启操作系统或结束其他应用时，仍须单独取得用户授权。服务重启不能保留旧文件句柄。

## 当前驱动与验证

只使用 WinFsp 2.2（用户 2026-10-14 要求）。memfs、scpfs、cryptfs 共享同一份驱动和静态运行库：官方 WinFsp v2.2B5 源码提交 `14d6e0280ae15e2550c44d6dbc476be51649727f` 构建的静态用户态运行库（`D:\src\winfsp-fs-2.2B5`，由 `scripts/prepare-winfsp-static.ps1 -Worktree D:\src\winfsp-fs-2.2B5 -PrivateDriverIdent FsC` 生成），配合同版本 Microsoft 签名 x64/ARM64 SYS（纳入 git：`frontend/winfsp/2.2.26286-beta5/`）。构建配置统一来自 `frontend/WinFspPresets.json`。静态运行库绑定 `FsC` SxS 标识，私有内核服务为 `WinFsp+FsC`（驱动文件 `fs-winfsp-x64.sys`），常量定义在 `frontend/include/fs_frontend_driver.h`，不得静默复用其他 WinFsp 安装。升级 SYS 必须三个产品一起升；卸载某一产品时不要删除共享驱动。

MemfsC 正式服务自 2026-10-14 起使用块设备模式（Arsenal Image Mounter，2 GB 固定容量），不再依赖 WinFsp 驱动；参数与验证见 `docs/BLOCK_DEVICE.md`。

替换驱动时同时核对源码提交、SYS 版本/签名/哈希、静态运行库版本和实际使用的设备。不能只看到磁盘文件被更新就声称内核已切换。不同 Windows 环境的完整 NTFS 兼容性不能由测试通过推定。

当前详细记录见 `docs/WINFSP_2_2_UPGRADE.md`。2026-10-14 验收中旧安装和旧服务已卸载，但内核模块列表仍有旧映像残留；后续正常重启 Windows 后应复查，不应假称已完全卸载出内存。

使用纯 C、clang-cl、CMake/Ninja 和静态 vcpkg。修改后运行 Debug/Release CTest、独立挂载兼容性测试与实际服务冒烟测试。驱动准备脚本不得未经显式参数销毁已有源码工作树。
