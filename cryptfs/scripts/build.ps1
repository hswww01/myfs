[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$devShell = 'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\Launch-VsDevShell.ps1'
if (-not $env:VSCMD_VER) {
    if (-not (Test-Path -LiteralPath $devShell)) { throw "Visual Studio developer shell not found: $devShell" }
    & $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
}
$preset = 'x64-' + $Configuration.ToLowerInvariant()
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$buildTemp = Join-Path $projectRoot 'build\tool-temp'
New-Item -ItemType Directory -Path $buildTemp -Force | Out-Null
$env:TEMP = $buildTemp
$env:TMP = $buildTemp
Push-Location -LiteralPath $projectRoot
try {
    & cmake --preset $preset
    if ($LASTEXITCODE) { throw "Configuration failed ($LASTEXITCODE)" }
    & cmake --build --preset $preset
    if ($LASTEXITCODE) { throw "Build failed ($LASTEXITCODE)" }
    if (-not $SkipTests) {
        & ctest --preset $preset
        if ($LASTEXITCODE) { throw "Tests failed ($LASTEXITCODE)" }
    }
} finally {
    Pop-Location
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
}
