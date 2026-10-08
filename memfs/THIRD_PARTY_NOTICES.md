# Third-Party Notices

This product is built with third-party software. The authoritative license
texts shipped in the release package are under the `licenses/` directory.

## WinFsp

- Project: WinFsp - Windows File System Proxy
- Copyright: Copyright (C) Bill Zissimopoulos
- Source used for the current x64 static runtime: WinFsp v2.1 source at commit
  `ddca7bd` (selected to match the embedded signed driver).
- License text: `licenses/WinFsp-License.txt`

The WinFsp source tree used by this project states that WinFsp is licensed
under GPLv3. Its FLOSS special exception explicitly grants permission to link
with the platform-specific WinFsp DLLs and to redistribute unmodified WinFsp
installers under the stated conditions. The exception text does not state a
general static-linking exception.

Because this build statically links the WinFsp user-mode runtime into
`memfs.exe`, distributors should ensure that their chosen distribution terms
satisfy the applicable WinFsp/GPLv3 obligations, or obtain separate commercial
permission from the WinFsp copyright holder before proprietary distribution.

This notice is an engineering release gate, not legal advice.

Repository: https://github.com/winfsp/winfsp

## libsodium

- Project: libsodium
- License: ISC
- License text: `licenses/libsodium.txt`

The project is statically linked through vcpkg.

## Zstandard (zstd)

- Project: Zstandard
- License choice in the upstream package: BSD or GPLv2
- This product uses the BSD license option for redistribution.
- License text: `licenses/zstd.txt`

The project is statically linked through vcpkg.

## Windows system libraries

The final executable also imports normal Windows system libraries. They are not
redistributed by the memfs release package.
