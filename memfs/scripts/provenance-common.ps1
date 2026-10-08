Set-StrictMode -Version Latest

function Get-Sha256Hex {
    param([Parameter(Mandatory=$true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-PeMachine {
    param([Parameter(Mandatory=$true)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 0x40) {
            throw "PE file too small: $Path"
        }

        $stream.Position = 0
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "Missing MZ header: $Path"
        }

        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or ($peOffset + 6) -gt $stream.Length) {
            throw "Invalid PE header offset in $Path"
        }

        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Missing PE signature: $Path"
        }

        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-PeMachineName {
    param([Parameter(Mandatory=$true)][UInt16]$Machine)
    switch ($Machine) {
        0x8664 { return "AMD64" }
        0xAA64 { return "ARM64" }
        0x014C { return "I386" }
        default { return ("0x{0:X4}" -f $Machine) }
    }
}

function Get-WinFspDriverEvidence {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][UInt16]$ExpectedMachine
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $machine = Get-PeMachine -Path $resolved
    if ($machine -ne $ExpectedMachine) {
        throw "Unexpected PE machine for $($resolved): expected $(Get-PeMachineName $ExpectedMachine), got $(Get-PeMachineName $machine)"
    }

    $signature = Get-AuthenticodeSignature -FilePath $resolved
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signature is not valid for $($resolved): $($signature.Status) $($signature.StatusMessage)"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "Authenticode signer certificate missing for $resolved"
    }

    $subject = $signature.SignerCertificate.Subject
    if ($subject -notmatch 'CN=Microsoft Windows Hardware Compatibility Publisher') {
        throw "Unexpected driver signer for $($resolved): $subject"
    }

    $item = Get-Item -LiteralPath $resolved
    return [ordered]@{
        path = $resolved
        file_version = $item.VersionInfo.FileVersion
        size = [Int64]$item.Length
        sha256 = Get-Sha256Hex -Path $resolved
        pe_machine = Get-PeMachineName -Machine $machine
        pe_machine_code = ("0x{0:X4}" -f $machine)
        signature_status = $signature.Status.ToString()
        signer_subject = $subject
        signer_thumbprint = $signature.SignerCertificate.Thumbprint
        signer_not_before = $signature.SignerCertificate.NotBefore.ToString("o")
        signer_not_after = $signature.SignerCertificate.NotAfter.ToString("o")
        timestamp_subject = if ($signature.TimeStamperCertificate) {
            $signature.TimeStamperCertificate.Subject
        } else {
            $null
        }
    }
}

function Get-GitHead {
    param([Parameter(Mandatory=$true)][string]$Repo)
    $head = (& git -C $Repo rev-parse HEAD 2>$null | Select-Object -First 1)
    if (-not $head) {
        throw "Cannot read Git HEAD: $Repo"
    }
    return $head.Trim()
}

function Get-GitTrackedDirty {
    param([Parameter(Mandatory=$true)][string]$Repo)
    $lines = @(& git -C $Repo status --porcelain --untracked-files=no 2>$null)
    return @($lines | Where-Object { $_ -and $_.Trim() })
}

function Get-BytesSha256Hex {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($sha.ComputeHash($Bytes)))
    }
    finally {
        $sha.Dispose()
    }
}

function Get-GitDiffSha256 {
    param([Parameter(Mandatory=$true)][string]$Repo)
    $text = (& git -C $Repo diff --binary --no-ext-diff -- 2>$null | Out-String)
    return Get-BytesSha256Hex -Bytes ([Text.Encoding]::UTF8.GetBytes($text))
}

function Get-CMakeCacheValue {
    param(
        [Parameter(Mandatory=$true)][string]$CachePath,
        [Parameter(Mandatory=$true)][string]$Name
    )

    $prefix = $Name + ":"
    foreach ($line in Get-Content -LiteralPath $CachePath) {
        if ($line.StartsWith($prefix, [StringComparison]::Ordinal)) {
            $idx = $line.IndexOf("=")
            if ($idx -lt 0) { break }
            return $line.Substring($idx + 1)
        }
    }
    throw "CMake cache key not found: $Name in $CachePath"
}

function Resolve-VcpkgRootFromToolchain {
    param([Parameter(Mandatory=$true)][string]$ToolchainPath)
    $p = [IO.Path]::GetFullPath($ToolchainPath)
    $parent = Split-Path $p -Parent
    $parent = Split-Path $parent -Parent
    return Split-Path $parent -Parent
}

function Get-VcpkgTripletPath {
    param(
        [Parameter(Mandatory=$true)][string]$VcpkgRoot,
        [Parameter(Mandatory=$true)][string]$Triplet
    )
    foreach ($candidate in @(
        (Join-Path $VcpkgRoot ("triplets\" + $Triplet + ".cmake")),
        (Join-Path $VcpkgRoot ("triplets\community\" + $Triplet + ".cmake"))
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "vcpkg triplet not found: $Triplet"
}

function Get-VcpkgInstalledPackage {
    param(
        [Parameter(Mandatory=$true)][string]$StatusPath,
        [Parameter(Mandatory=$true)][string]$Package,
        [Parameter(Mandatory=$true)][string]$Architecture
    )

    if (-not (Test-Path -LiteralPath $StatusPath -PathType Leaf)) {
        throw "vcpkg status file not found: $StatusPath"
    }

    $raw = [IO.File]::ReadAllText($StatusPath)
    $blocks = [Regex]::Split($raw, "(?:\r?\n){2,}")
    foreach ($block in $blocks) {
        $fields = @{}
        foreach ($line in [Regex]::Split($block, "\r?\n")) {
            $idx = $line.IndexOf(": ")
            if ($idx -gt 0) {
                $fields[$line.Substring(0, $idx)] = $line.Substring($idx + 2)
            }
        }
        if ($fields["Package"] -eq $Package -and
            $fields["Architecture"] -eq $Architecture) {
            return [ordered]@{
                package = $Package
                version = $fields["Version"]
                architecture = $Architecture
            }
        }
    }

    throw "vcpkg package not installed: $($Package):$Architecture"
}
