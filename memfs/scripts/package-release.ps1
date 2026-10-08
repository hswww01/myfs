param(
    [string]$BuildDir = "",
    [string]$OutputDir = "",
    [string]$WinFspSourceRoot = "D:\src\winfsp"
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "provenance-common.ps1")

$repoRoot = Split-Path $PSScriptRoot -Parent
$repoRoot = [IO.Path]::GetFullPath($repoRoot)
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $repoRoot "build\x64-release"
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $repoRoot "dist\memfs-x64"
}
$BuildDir = [IO.Path]::GetFullPath($BuildDir)
$distRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "dist"))
$OutputDir = [IO.Path]::GetFullPath($OutputDir)

function Assert-SafeReleaseOutput {
    param([string]$Path)

    $rootPrefix = $distRoot.TrimEnd('\') + '\'
    if ($Path -eq $distRoot -or
        -not $Path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputDir must be a child of the managed release root: $distRoot"
    }

    if (Test-Path -LiteralPath $distRoot) {
        $rootItem = Get-Item -LiteralPath $distRoot -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Managed release root must not be a reparse point: $distRoot"
        }
    }

    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer) {
            throw "OutputDir exists but is not a directory: $Path"
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "OutputDir must not be a reparse point: $Path"
        }
    }
}

Assert-SafeReleaseOutput -Path $OutputDir

$trackedDirty = @(Get-GitTrackedDirty -Repo $repoRoot)
if ($trackedDirty.Count -ne 0) {
    throw "Refusing to package a tracked-dirty memfs tree: $($trackedDirty -join '; ')"
}

$cachePath = Join-Path $BuildDir "CMakeCache.txt"
if (-not (Test-Path -LiteralPath $cachePath -PathType Leaf)) {
    throw "Release CMake cache not found: $cachePath"
}
$buildType = Get-CMakeCacheValue -CachePath $cachePath -Name "CMAKE_BUILD_TYPE"
if ($buildType -ne "Release") {
    throw "Release packaging requires CMAKE_BUILD_TYPE=Release; got '$buildType'"
}
$triplet = Get-CMakeCacheValue -CachePath $cachePath -Name "VCPKG_TARGET_TRIPLET"
if ($triplet -ne "x64-windows-static") {
    throw "Release packaging requires x64-windows-static; got '$triplet'"
}

& cmake --build $BuildDir
if ($LASTEXITCODE -ne 0) {
    throw "Release build failed with exit code $LASTEXITCODE"
}

& ctest --test-dir $BuildDir --output-on-failure
if ($LASTEXITCODE -ne 0) {
    throw "Release CTest failed with exit code $LASTEXITCODE"
}
$exe = Join-Path $BuildDir "memfs.exe"
$notice = Join-Path $repoRoot "THIRD_PARTY_NOTICES.md"
$winfspLicense = Join-Path $WinFspSourceRoot "License.txt"
$sodiumLicense = Join-Path $BuildDir "vcpkg_installed\x64-windows-static\share\libsodium\copyright"
$zstdLicense = Join-Path $BuildDir "vcpkg_installed\x64-windows-static\share\zstd\copyright"

foreach ($required in @($exe, $notice, $winfspLicense, $sodiumLicense, $zstdLicense)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required release input not found: $required"
    }
}

New-Item -ItemType Directory -Path $distRoot -Force | Out-Null

$token = [Guid]::NewGuid().ToString("N")
$stagingDir = Join-Path $distRoot (".memfs-stage-" + $token)
$backupDir = Join-Path $distRoot (".memfs-backup-" + $token)
$stagingLicenses = Join-Path $stagingDir "licenses"
$published = $false

try {
    New-Item -ItemType Directory -Path $stagingLicenses -Force | Out-Null

    Copy-Item -LiteralPath $exe -Destination (Join-Path $stagingDir "memfs.exe")
    Copy-Item -LiteralPath $notice -Destination (Join-Path $stagingDir "THIRD_PARTY_NOTICES.md")
    Copy-Item -LiteralPath $winfspLicense -Destination (Join-Path $stagingLicenses "WinFsp-License.txt")
    Copy-Item -LiteralPath $sodiumLicense -Destination (Join-Path $stagingLicenses "libsodium.txt")
    Copy-Item -LiteralPath $zstdLicense -Destination (Join-Path $stagingLicenses "zstd.txt")
    $stagingProvenance = Join-Path $stagingDir "BUILD_PROVENANCE.json"
    $provenanceScript = Join-Path $PSScriptRoot "build-provenance.ps1"

    $provenanceArgs = @{
        Mode = "Write"
        SourceDir = $repoRoot
        BuildDir = $BuildDir
        ExePath = $exe
        OutputPath = $stagingProvenance
        RequireClean = $true
    }
    & $provenanceScript @provenanceArgs
    $provenanceArgs.Mode = "Verify"
    & $provenanceScript @provenanceArgs


    $stagingManifest = Join-Path $stagingDir "SHA256SUMS.txt"
    $files = Get-ChildItem -LiteralPath $stagingDir -File -Recurse |
        Where-Object { $_.FullName -ne $stagingManifest } |
        Sort-Object FullName

    $lines = foreach ($file in $files) {
        $relative = $file.FullName.Substring($stagingDir.Length).TrimStart('\').Replace('\','/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    }
    [IO.File]::WriteAllLines($stagingManifest, $lines, [Text.UTF8Encoding]::new($false))

    if (Test-Path -LiteralPath $OutputDir) {
        Move-Item -LiteralPath $OutputDir -Destination $backupDir
    }

    try {
        Move-Item -LiteralPath $stagingDir -Destination $OutputDir
        $published = $true
    }
    catch {
        if (Test-Path -LiteralPath $backupDir -PathType Container) {
            Move-Item -LiteralPath $backupDir -Destination $OutputDir
        }
        throw
    }

    if (Test-Path -LiteralPath $backupDir -PathType Container) {
        Remove-Item -LiteralPath $backupDir -Recurse -Force
    }
}
finally {
    if (-not $published -and (Test-Path -LiteralPath $stagingDir)) {
        Remove-Item -LiteralPath $stagingDir -Recurse -Force
    }
}

$manifestPath = Join-Path $OutputDir "SHA256SUMS.txt"

Write-Output "Packaged release: $OutputDir"
Write-Output ""
Write-Output "IMPORTANT: this build statically links WinFsp user-mode code."
Write-Output "Review THIRD_PARTY_NOTICES.md and the WinFsp license before distribution."
Get-Content $manifestPath
