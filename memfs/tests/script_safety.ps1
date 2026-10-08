param(
    [string]$RepoRoot = "",
    [string]$WinFspRepo = "D:\src\winfsp"
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
}
$RepoRoot = [IO.Path]::GetFullPath($RepoRoot)

$package = Join-Path $RepoRoot "scripts\package-release.ps1"
$prepare = Join-Path $RepoRoot "scripts\prepare-winfsp-static.ps1"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("memfs-script-safety-" + [Guid]::NewGuid().ToString("N"))
$sentinel = Join-Path $tempRoot "KEEP.txt"

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
Set-Content -LiteralPath $sentinel -Value "do-not-delete" -Encoding ASCII

try {
    $rejected = $false
    try {
        & $package -OutputDir $tempRoot
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "package-release.ps1 accepted an unmanaged OutputDir"
    }
    if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
        throw "package-release.ps1 modified/deleted unmanaged OutputDir"
    }

    $rejected = $false
    try {
        & $prepare -WinFspRepo $WinFspRepo -Worktree $tempRoot
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "prepare-winfsp-static.ps1 accepted an unregistered existing Worktree"
    }
    if (-not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
        throw "prepare-winfsp-static.ps1 modified/deleted unregistered Worktree"
    }

    Write-Output "script safety PASS"
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
