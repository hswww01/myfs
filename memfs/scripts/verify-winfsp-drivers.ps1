param(
    [Parameter(Mandatory=$true)][string]$X64Path,
    [Parameter(Mandatory=$true)][string]$Arm64Path,
    [string]$OutputJson = ""
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "provenance-common.ps1")

$x64 = Get-WinFspDriverEvidence -Path $X64Path -ExpectedMachine 0x8664
$arm64 = Get-WinFspDriverEvidence -Path $Arm64Path -ExpectedMachine 0xAA64

if ($x64.file_version -ne $arm64.file_version) {
    throw "WinFsp SYS FileVersion mismatch: x64=$($x64.file_version), ARM64=$($arm64.file_version)"
}
if ($x64.signer_thumbprint -ne $arm64.signer_thumbprint) {
    throw "WinFsp SYS signer mismatch: x64=$($x64.signer_thumbprint), ARM64=$($arm64.signer_thumbprint)"
}
if ($x64.signer_subject -ne $arm64.signer_subject) {
    throw "WinFsp SYS signer subject mismatch."
}

$result = [ordered]@{
    policy = [ordered]@{
        required_signature_status = "Valid"
        required_signer_cn = "Microsoft Windows Hardware Compatibility Publisher"
        require_same_file_version = $true
        require_same_signer = $true
        x64_machine = "AMD64"
        arm64_machine = "ARM64"
    }
    x64 = $x64
    arm64 = $arm64
}

$json = $result | ConvertTo-Json -Depth 8
if ($OutputJson) {
    $full = [IO.Path]::GetFullPath($OutputJson)
    $parent = Split-Path $full -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($full, $json + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false))
}

Write-Output $json
