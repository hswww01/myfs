[CmdletBinding()]
param([string[]]$TestArguments = @())
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$devShell = 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1'
if (-not $env:VSCMD_VER) {
    & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
}
$compiler = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe'
$asanRuntime = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\lib\clang\22\lib\windows'
$installed = Join-Path $projectRoot 'build\x64-release\vcpkg_installed\x64-windows-static'
$testBuild = Join-Path $projectRoot 'build\store-asan'
$buildTemp = Join-Path $projectRoot 'build\tool-temp'
New-Item -ItemType Directory -Path $testBuild, $buildTemp -Force | Out-Null
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$previousPath = $env:PATH
$previousAsan = $env:ASAN_OPTIONS
$env:TEMP = $buildTemp
$env:TMP = $buildTemp
$env:PATH = $asanRuntime + ';' + $previousPath
$env:ASAN_OPTIONS = 'detect_leaks=0:halt_on_error=1'
Push-Location -LiteralPath $testBuild
try {
    # clang-cl AddressSanitizer requires the non-Debug CRT. Keep source debug
    # information and disabled optimization while linking the matching /MT libs.
    & $compiler /nologo /std:c17 /MT /Zi /Od /W4 /WX /utf-8 /fsanitize=address `
        /DCRYPTFS_TESTING /D_CRT_SECURE_NO_WARNINGS `
        ('/I' + (Join-Path $projectRoot 'src')) ('/I' + (Join-Path $installed 'include')) `
        (Join-Path $projectRoot 'tests\test_store.c') `
        (Join-Path $projectRoot 'src\cryptfs_crypto.c') `
        (Join-Path $projectRoot 'src\cryptfs_store.c') `
        ('/Fe:' + (Join-Path $testBuild 'cryptfs_store_asan.exe')) `
        /link (Join-Path $installed 'lib\libsodium.lib') `
        (Join-Path $installed 'lib\zstd.lib') bcrypt.lib advapi32.lib
    if ($LASTEXITCODE) { throw "AddressSanitizer build failed ($LASTEXITCODE)" }
    & (Join-Path $testBuild 'cryptfs_store_asan.exe') @TestArguments
    if ($LASTEXITCODE) { throw "AddressSanitizer tests failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    $env:PATH = $previousPath
    $env:ASAN_OPTIONS = $previousAsan
}
