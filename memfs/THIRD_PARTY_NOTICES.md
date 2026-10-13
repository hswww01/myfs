# 第三方软件声明

本产品使用第三方软件。发布包中附带的权威许可证原文位于 `licenses/` 目录。以下说明为中文摘要；如有差异，以相应许可证原文为准。

## WinFsp 许可证

- 项目：WinFsp - Windows File System Proxy
- 版权所有：© Bill Zissimopoulos
- 当前 x64 静态运行库所用源码：WinFsp v2.1，提交 `ddca7bd`（为匹配内嵌签名驱动而选择）。
- 许可证原文：`licenses/WinFsp-License.txt`

本项目所用 WinFsp 源码树声明 WinFsp 以 GPLv3 授权。其 FLOSS 特别例外明确允许与平台专用 WinFsp DLL 链接，并在所述条件下再分发未修改的 WinFsp 安装程序。该例外没有声明通用的静态链接豁免。

本构建将 WinFsp 用户态运行库静态链接到 `memfs.exe`。进行分发时，应确保所选分发条款符合适用的 WinFsp/GPLv3 义务；如拟专有分发，应先取得 WinFsp 版权持有方另行提供的商业许可。

本声明是工程发布门禁，不构成法律意见。

项目主页：https://github.com/winfsp/winfsp

## libsodium 许可证

- 项目：libsodium
- 许可证：ISC
- 许可证原文：`licenses/libsodium.txt`

项目通过 vcpkg 静态链接。

## Zstandard（zstd）

- 项目：Zstandard
- 上游软件包可选许可证：BSD 或 GPLv2
- 本产品再分发时选择 BSD 许可证选项。
- 许可证原文：`licenses/zstd.txt`

项目通过 vcpkg 静态链接。

## Windows 系统库

最终可执行文件还会导入常规 Windows 系统库。memfs 发布包不会再分发这些系统库。
