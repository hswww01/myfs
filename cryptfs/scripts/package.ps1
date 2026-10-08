[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$packageRoot = Join-Path $projectRoot 'dist\cryptfs-x64'

$releaseRoot = Join-Path $projectRoot 'build\x64-release'
$vcpkgShare = Join-Path $releaseRoot 'vcpkg_installed\x64-windows-static\share'

$packageFiles = @(
    [pscustomobject]@{ Source = (Join-Path $releaseRoot 'cryptfs.exe'); Destination = 'cryptfs.exe' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'README.md'); Destination = 'README.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\FORMAT.md'); Destination = 'docs\FORMAT.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\ARCHITECTURE.md'); Destination = 'docs\ARCHITECTURE.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\ARCHITECTURE_REVIEW.md'); Destination = 'docs\ARCHITECTURE_REVIEW.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\VALIDATION.md'); Destination = 'docs\VALIDATION.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\REQUIREMENTS.md'); Destination = 'docs\REQUIREMENTS.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\CRYPTO.md'); Destination = 'docs\CRYPTO.md' },
    [pscustomobject]@{ Source = (Join-Path $projectRoot 'docs\SCAFFOLD.md'); Destination = 'docs\SCAFFOLD.md' },
    [pscustomobject]@{ Source = (Join-Path $vcpkgShare 'libsodium\copyright'); Destination = 'licenses\libsodium-copyright.txt' },
    [pscustomobject]@{ Source = (Join-Path $vcpkgShare 'zstd\copyright'); Destination = 'licenses\zstd-copyright.txt' },
    [pscustomobject]@{ Source = 'D:\src\winfsp-memfs-static\License.txt'; Destination = 'licenses\winfsp-license.txt' },
    [pscustomobject]@{ Source = (Join-Path $releaseRoot 'winfsp-driver-provenance.json'); Destination = 'provenance\winfsp-driver-provenance.json' }
)

# Preflight the exact allowlist before creating or changing the package tree.
$missing = @($packageFiles | Where-Object { -not (Test-Path -LiteralPath $_.Source -PathType Leaf) })
if ($missing.Count -gt 0) {
    $paths = ($missing | ForEach-Object { $_.Source }) -join [Environment]::NewLine
    throw "Packaging inputs are missing; no package files were copied:`n$paths"
}

if (Test-Path -LiteralPath $packageRoot) {
    if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
        throw "Package destination exists and is not a directory: $packageRoot"
    }
    $existing = @(Get-ChildItem -LiteralPath $packageRoot -Force)
    if ($existing.Count -gt 0) {
        throw "Package destination is not empty; refusing to overwrite or remove files: $packageRoot"
    }
} else {
    New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
}

foreach ($entry in $packageFiles) {
    $destination = Join-Path $packageRoot $entry.Destination
    $destinationDirectory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }
    Copy-Item -LiteralPath $entry.Source -Destination $destination
}

# The manifest covers every copied payload file, but not itself.
$manifestPath = Join-Path $packageRoot 'MANIFEST.sha256'
$manifestLines = @(
    '# SHA-256 and byte size for each package payload file; this manifest excludes itself.'
)
$payloadFiles = @(Get-ChildItem -LiteralPath $packageRoot -File -Recurse |
    Sort-Object { $_.FullName.Substring($packageRoot.Length).TrimStart('\') })
foreach ($file in $payloadFiles) {
    $relativePath = $file.FullName.Substring($packageRoot.Length).TrimStart('\').Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestLines += "$hash`t$($file.Length)`t$relativePath"
}
[System.IO.File]::WriteAllLines($manifestPath, [string[]]$manifestLines,
    [System.Text.UTF8Encoding]::new($false))

Write-Host "Package created: $packageRoot"
foreach ($file in $payloadFiles) {
    $relativePath = $file.FullName.Substring($packageRoot.Length).TrimStart('\').Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ("{0}  {1} bytes  {2}" -f $hash, $file.Length, $relativePath)
}
$manifestItem = Get-Item -LiteralPath $manifestPath
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ("{0}  {1} bytes  MANIFEST.sha256 (self-hash; excluded from manifest entries)" -f $manifestHash, $manifestItem.Length)
