param(
    [ValidateSet("Write", "Verify")]
    [string]$Mode = "Write",
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][string]$BuildDir,
    [Parameter(Mandatory=$true)][string]$ExePath,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [switch]$RequireClean
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "provenance-common.ps1")

$SourceDir = [IO.Path]::GetFullPath($SourceDir)
$BuildDir = [IO.Path]::GetFullPath($BuildDir)
$ExePath = [IO.Path]::GetFullPath($ExePath)
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

$cache = Join-Path $BuildDir "CMakeCache.txt"
if (-not (Test-Path -LiteralPath $cache -PathType Leaf)) {
    throw "CMakeCache.txt not found: $cache"
}
if (-not (Test-Path -LiteralPath $ExePath -PathType Leaf)) {
    throw "memfs.exe not found: $ExePath"
}

$buildType = Get-CMakeCacheValue -CachePath $cache -Name "CMAKE_BUILD_TYPE"
$compiler = Get-CMakeCacheValue -CachePath $cache -Name "CMAKE_C_COMPILER"
$toolchain = Get-CMakeCacheValue -CachePath $cache -Name "CMAKE_TOOLCHAIN_FILE"
$triplet = Get-CMakeCacheValue -CachePath $cache -Name "VCPKG_TARGET_TRIPLET"
$winfspSource = Get-CMakeCacheValue -CachePath $cache -Name "WINFSP_SOURCE_ROOT"
$winfspStatic = Get-CMakeCacheValue -CachePath $cache -Name "WINFSP_STATIC_LIBRARY"
$driverX64Path = Get-CMakeCacheValue -CachePath $cache -Name "WINFSP_DRIVER_X64"
$driverArm64Path = Get-CMakeCacheValue -CachePath $cache -Name "WINFSP_DRIVER_ARM64"

$memfsHead = Get-GitHead -Repo $SourceDir
$trackedDirty = @(Get-GitTrackedDirty -Repo $SourceDir)
if ($RequireClean -and $trackedDirty.Count -ne 0) {
    throw "Refusing release provenance from a tracked-dirty memfs tree: $($trackedDirty -join '; ')"
}

$driverX64 = Get-WinFspDriverEvidence -Path $driverX64Path -ExpectedMachine 0x8664
$driverArm64 = Get-WinFspDriverEvidence -Path $driverArm64Path -ExpectedMachine 0xAA64
if ($driverX64.file_version -ne $driverArm64.file_version) {
    throw "Embedded driver FileVersion mismatch."
}
if ($driverX64.signer_thumbprint -ne $driverArm64.signer_thumbprint) {
    throw "Embedded driver signer mismatch."
}

$winfspSource = (Resolve-Path -LiteralPath $winfspSource).Path
$winfspHead = Get-GitHead -Repo $winfspSource
$winfspDiffHash = Get-GitDiffSha256 -Repo $winfspSource

if ($driverX64.file_version -notmatch '\.([0-9a-fA-F]{7,40})$') {
    throw "Cannot derive WinFsp source commit suffix from driver FileVersion: $($driverX64.file_version)"
}
$driverCommitSuffix = $Matches[1].ToLowerInvariant()
if (-not $winfspHead.ToLowerInvariant().StartsWith($driverCommitSuffix)) {
    throw "WinFsp source HEAD $winfspHead does not match driver revision $driverCommitSuffix"
}

$compiler = [IO.Path]::GetFullPath($compiler)
$compilerVersionLines = @(& $compiler --version)
if ($compilerVersionLines.Count -eq 0) {
    throw "Cannot query compiler version: $compiler"
}
$compilerVersion = $compilerVersionLines[0].Trim()

$vcpkgRoot = Resolve-VcpkgRootFromToolchain -ToolchainPath $toolchain
$vcpkgHead = Get-GitHead -Repo $vcpkgRoot
$manifestPath = Join-Path $SourceDir "vcpkg.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$baseline = [string]$manifest.'builtin-baseline'
if (-not $baseline) {
    throw "vcpkg.json must define builtin-baseline"
}
$baselineObject = (& git -C $vcpkgRoot cat-file -t $baseline 2>$null | Select-Object -First 1)
if ($baselineObject -ne "commit") {
    throw "vcpkg builtin-baseline is not available in local vcpkg repository: $baseline"
}

$tripletPath = Get-VcpkgTripletPath -VcpkgRoot $vcpkgRoot -Triplet $triplet
$statusPath = Join-Path $BuildDir "vcpkg_installed\vcpkg\status"
$deps = @(
    (Get-VcpkgInstalledPackage -StatusPath $statusPath -Package "libsodium" -Architecture $triplet),
    (Get-VcpkgInstalledPackage -StatusPath $statusPath -Package "zstd" -Architecture $triplet)
)

$cmakeVersion = (& cmake --version | Select-Object -First 1).Trim()
$ninjaVersion = (& ninja --version | Select-Object -First 1).Trim()

$evidence = [ordered]@{
    schema_version = 1
    source = [ordered]@{
        memfs_git_commit = $memfsHead
        memfs_tracked_clean = ($trackedDirty.Count -eq 0)
        winfsp_git_commit = $winfspHead
        winfsp_driver_commit_suffix = $driverCommitSuffix
        winfsp_patch_diff_sha256 = $winfspDiffHash
    }
    build = [ordered]@{
        build_type = $buildType
        target_triplet = $triplet
        exe_path = $ExePath
        exe_size = [Int64](Get-Item -LiteralPath $ExePath).Length
        exe_sha256 = Get-Sha256Hex -Path $ExePath
        compiler_path = $compiler
        compiler_sha256 = Get-Sha256Hex -Path $compiler
        compiler_version = $compilerVersion
        cmake_version = $cmakeVersion
        ninja_version = $ninjaVersion
    }
    winfsp = [ordered]@{
        static_library_path = (Resolve-Path -LiteralPath $winfspStatic).Path
        static_library_sha256 = Get-Sha256Hex -Path $winfspStatic
        driver_x64 = $driverX64
        driver_arm64 = $driverArm64
    }
    vcpkg = [ordered]@{
        root = $vcpkgRoot
        git_commit = $vcpkgHead
        builtin_baseline = $baseline
        triplet_path = $tripletPath
        triplet_sha256 = Get-Sha256Hex -Path $tripletPath
        dependencies = $deps
    }
}

function Compare-Field {
    param([string]$Name, $Expected, $Actual)
    if ([string]$Expected -ne [string]$Actual) {
        throw "Build provenance mismatch for $($Name): recorded='$Expected' current='$Actual'"
    }
}

if ($Mode -eq "Write") {
    $parent = Split-Path $OutputPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $doc = [ordered]@{
        generated_at = (Get-Date).ToUniversalTime().ToString("o")
        evidence = $evidence
    }
    [IO.File]::WriteAllText(
        $OutputPath,
        ($doc | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
    Write-Output "Wrote build provenance: $OutputPath"
    return
}

if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
    throw "Build provenance sidecar not found: $OutputPath"
}
$recorded = Get-Content -LiteralPath $OutputPath -Raw | ConvertFrom-Json
$r = $recorded.evidence

Compare-Field "memfs_git_commit" $r.source.memfs_git_commit $evidence.source.memfs_git_commit
Compare-Field "memfs_tracked_clean" $r.source.memfs_tracked_clean $evidence.source.memfs_tracked_clean
Compare-Field "winfsp_git_commit" $r.source.winfsp_git_commit $evidence.source.winfsp_git_commit
Compare-Field "winfsp_driver_commit_suffix" $r.source.winfsp_driver_commit_suffix $evidence.source.winfsp_driver_commit_suffix
Compare-Field "winfsp_patch_diff_sha256" $r.source.winfsp_patch_diff_sha256 $evidence.source.winfsp_patch_diff_sha256
Compare-Field "build_type" $r.build.build_type $evidence.build.build_type
Compare-Field "target_triplet" $r.build.target_triplet $evidence.build.target_triplet
Compare-Field "exe_size" $r.build.exe_size $evidence.build.exe_size
Compare-Field "exe_sha256" $r.build.exe_sha256 $evidence.build.exe_sha256
Compare-Field "compiler_sha256" $r.build.compiler_sha256 $evidence.build.compiler_sha256
Compare-Field "compiler_version" $r.build.compiler_version $evidence.build.compiler_version
Compare-Field "static_library_sha256" $r.winfsp.static_library_sha256 $evidence.winfsp.static_library_sha256
Compare-Field "driver_x64_sha256" $r.winfsp.driver_x64.sha256 $evidence.winfsp.driver_x64.sha256
Compare-Field "driver_arm64_sha256" $r.winfsp.driver_arm64.sha256 $evidence.winfsp.driver_arm64.sha256
Compare-Field "driver_signer" $r.winfsp.driver_x64.signer_thumbprint $evidence.winfsp.driver_x64.signer_thumbprint
Compare-Field "vcpkg_git_commit" $r.vcpkg.git_commit $evidence.vcpkg.git_commit
Compare-Field "vcpkg_builtin_baseline" $r.vcpkg.builtin_baseline $evidence.vcpkg.builtin_baseline
Compare-Field "vcpkg_triplet_sha256" $r.vcpkg.triplet_sha256 $evidence.vcpkg.triplet_sha256

foreach ($pkg in @("libsodium", "zstd")) {
    $ra = @($r.vcpkg.dependencies | Where-Object { $_.package -eq $pkg }) | Select-Object -First 1
    $ea = @($evidence.vcpkg.dependencies | Where-Object { $_.package -eq $pkg }) | Select-Object -First 1
    if (-not $ra -or -not $ea) { throw "Missing dependency provenance: $pkg" }
    Compare-Field "$pkg version" $ra.version $ea.version
    Compare-Field "$pkg architecture" $ra.architecture $ea.architecture
}

Write-Output "Build provenance verified: $OutputPath"
