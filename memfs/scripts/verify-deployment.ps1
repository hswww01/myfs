param(
    [ValidateSet("Audit", "NoService", "OfficialInstalled", "PrivateFallback", "All")]
    [string]$Scenario = "All",
    [string]$Exe = "",
    [string]$Drive = "",
    [string]$Size = "64M",
    [switch]$ExercisePrivateFallback,
    [switch]$KeepPrivateDriver,
    [string]$Report = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$privateDriverService = "WinFsp+MemfsC"
$memfsService = "MemfsC"

$nativeType = [System.Management.Automation.PSTypeName]'MemfsTest.NativeMethods'
if ($null -eq $nativeType.Type) {
    Add-Type -TypeDefinition @"
using System.Text;
using System.Runtime.InteropServices;
namespace MemfsTest {
    public static class NativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint QueryDosDevice(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            int ucchMax);
    }
}
"@
}

function Test-DosDeviceExists {
    param([string]$Device)
    $name = $Device.TrimEnd('\')
    $buffer = [Text.StringBuilder]::new(4096)
    return [MemfsTest.NativeMethods]::QueryDosDevice(
        $name, $buffer, $buffer.Capacity) -ne 0
}

if (-not $Exe) {
    $Exe = Join-Path $repoRoot "build\x64-release\memfs.exe"
}
$Exe = [IO.Path]::GetFullPath($Exe)

$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet("PASS", "FAIL", "SKIP", "INFO")]
        [string]$Status,
        [string]$Detail
    )
    $item = [pscustomobject]@{
        time = (Get-Date).ToString("s")
        scenario = $Name
        status = $Status
        detail = $Detail
    }
    $script:results.Add($item)
    Write-Host ("[{0}] {1}: {2}" -f $Status, $Name, $Detail)
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required for the private fallback scenario."
    }
}

function Get-PrivateDriver {
    @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $privateDriverService }) | Select-Object -First 1
}

function Get-MemfsService {
    @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $memfsService }) | Select-Object -First 1
}

function Get-OfficialWinFspDrivers {
    @(
        Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ne $privateDriverService -and (
                $_.PathName -match '(?i)\\WinFsp\\SxS\\' -or
                $_.Name -match '^WinFsp\+\d'
            )
        }
    )
}

function Get-PrivateDriverFiles {
    $driverDir = Join-Path $env:WINDIR "System32\drivers"
    @(
        Join-Path $driverDir "memfs-winfsp-x64.sys"
        Join-Path $driverDir "memfs-winfsp-x64.alt.sys"
        Join-Path $driverDir "memfs-winfsp-a64.sys"
        Join-Path $driverDir "memfs-winfsp-a64.alt.sys"
    )
}

function Get-FreeDrive {
    param([string]$Preferred)
    if ($Preferred) {
        if ($Preferred -notmatch '^[A-Za-z]:$') {
            throw "-Drive must be a drive letter such as R:"
        }
        if (-not (Test-DosDeviceExists $Preferred)) {
            return $Preferred.ToUpperInvariant()
        }
        throw "Requested drive is already in use: $Preferred"
    }

    foreach ($letter in @("R","W","V","U","T","S","Q","P","O","N","M")) {
        $candidate = "$letter" + ":"
        if (-not (Test-DosDeviceExists $candidate)) {
            return $candidate
        }
    }
    throw "No free drive letter found for integration test."
}

function Assert-NoPrivateFallback {
    param([string]$Context)
    $driver = Get-PrivateDriver
    $files = @(Get-PrivateDriverFiles | Where-Object { Test-Path -LiteralPath $_ })
    if ($driver -or $files.Count -ne 0) {
        $details = @()
        if ($driver) { $details += "service=$($driver.Name) state=$($driver.State)" }
        if ($files.Count) { $details += "files=$($files -join ',')" }
        throw "$Context unexpectedly created/retained the private fallback: $($details -join '; ')"
    }
}

function Invoke-CtestGate {
    $ctest = Get-Command ctest.exe -ErrorAction SilentlyContinue
    if (-not $ctest) {
        Add-Result "audit.ctest" "SKIP" "ctest.exe not found"
        return
    }

    Push-Location $repoRoot
    try {
        & $ctest.Source --preset x64-release --output-on-failure -R "memfs_driver_test|memfs_static_winfsp_no_dll_import|memfs_static_winfsp_version|memfs_cli_help|memfs_embedded_winfsp_resources"
        if ($LASTEXITCODE -ne 0) {
            throw "release deployment gate tests failed with exit code $LASTEXITCODE"
        }
        Add-Result "audit.ctest" "PASS" "driver/static-version/no-DLL-import/CLI/resource gates passed"
    }
    finally {
        Pop-Location
    }
}

function Invoke-MountedSmoke {
    param([string]$Context)
    $integration = Join-Path $repoRoot "tests\integration.ps1"
    $mount = Get-FreeDrive $Drive
    & $integration -Exe $Exe -Drive $mount -Size $Size
    $integrationSucceeded = $?
    if (-not $integrationSucceeded) {
        throw "$Context integration PowerShell script failed"
    }
    Add-Result $Context "PASS" "mounted filesystem smoke passed on $mount"
}

function Test-Audit {
    if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
        throw "memfs.exe not found: $Exe"
    }

    & $Exe --help *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "memfs.exe --help failed with exit code $LASTEXITCODE"
    }
    Add-Result "audit.exe" "PASS" "release executable starts and CLI help succeeds"

    Invoke-CtestGate

    $official = @(Get-OfficialWinFspDrivers)
    if ($official.Count) {
        $summary = ($official | ForEach-Object {
            "$($_.Name) state=$($_.State) path=$($_.PathName)"
        }) -join " | "
        Add-Result "audit.official-driver" "INFO" $summary
    }
    else {
        Add-Result "audit.official-driver" "INFO" "no official WinFsp SxS driver detected"
    }

    $private = Get-PrivateDriver
    if ($private) {
        Add-Result "audit.private-driver" "INFO" "service=$($private.Name) state=$($private.State) path=$($private.PathName)"
    }
    else {
        Add-Result "audit.private-driver" "INFO" "private fallback service absent"
    }
}

function Test-NoService {
    $service = Get-MemfsService
    if ($service) {
        throw "NoService scenario requires MemfsC to be absent; current state=$($service.State)"
    }
    Add-Result "no-service.memfs" "PASS" "MemfsC service is absent"

    $private = Get-PrivateDriver
    if (-not $private) {
        Add-Result "no-service.private-driver" "PASS" "private fallback service is absent"
    }
    else {
        Add-Result "no-service.private-driver" "INFO" "private fallback exists independently: state=$($private.State)"
    }
}

function Test-OfficialInstalled {
    $official = @(Get-OfficialWinFspDrivers)
    if (-not $official.Count) {
        Add-Result "official-installed" "SKIP" "no official WinFsp SxS driver detected"
        return
    }

    Assert-NoPrivateFallback "official-installed precondition"
    Invoke-MountedSmoke "official-installed.mount"
    Assert-NoPrivateFallback "official-installed postcondition"
    Add-Result "official-installed.no-private-fallback" "PASS" "official WinFsp was reused; no MemfsC private driver/service/file was created"
}

function Test-PrivateFallback {
    if (-not $ExercisePrivateFallback) {
        Add-Result "private-fallback" "SKIP" "requires explicit -ExercisePrivateFallback on a clean VM"
        return
    }

    Assert-Admin

    $official = @(Get-OfficialWinFspDrivers)
    if ($official.Count) {
        throw "PrivateFallback refuses to run while an official WinFsp driver is installed/running. Use a genuinely clean VM."
    }

    $service = Get-MemfsService
    if ($service) {
        throw "PrivateFallback requires MemfsC service to be absent first."
    }

    Assert-NoPrivateFallback "private-fallback precondition"
    Invoke-MountedSmoke "private-fallback.mount"

    $private = Get-PrivateDriver
    if (-not $private) {
        throw "mount succeeded but private fallback driver service was not created"
    }

    $files = @(Get-PrivateDriverFiles | Where-Object { Test-Path -LiteralPath $_ })
    if (-not $files.Count) {
        throw "private driver service exists but no private payload file was found"
    }

    if ($private.PathName -match '(?i)\\WinFsp\\SxS\\|Program Files') {
        throw "private driver unexpectedly points into an official WinFsp installation: $($private.PathName)"
    }

    Add-Result "private-fallback.install" "PASS" "private service=$($private.Name) state=$($private.State); payload=$($files -join ',')"

    if (-not $KeepPrivateDriver) {
        & $Exe --uninstall-private-driver
        if ($LASTEXITCODE -ne 0) {
            throw "private driver cleanup failed with exit code $LASTEXITCODE"
        }

        Start-Sleep -Milliseconds 500
        if (Get-PrivateDriver) {
            throw "private driver service still exists after uninstall"
        }

        $remaining = @(Get-PrivateDriverFiles | Where-Object { Test-Path -LiteralPath $_ })
        if ($remaining.Count) {
            Add-Result "private-fallback.cleanup" "INFO" "payload removal is reboot-pending: $($remaining -join ',')"
        }
        else {
            Add-Result "private-fallback.cleanup" "PASS" "private service and payload files removed"
        }
    }
}

$failed = $false
try {
    if ($Scenario -in @("Audit","All")) { Test-Audit }
    if ($Scenario -in @("NoService","All")) { Test-NoService }
    if ($Scenario -in @("OfficialInstalled","All")) { Test-OfficialInstalled }
    if ($Scenario -in @("PrivateFallback","All")) { Test-PrivateFallback }
}
catch {
    $failed = $true
    Add-Result $Scenario "FAIL" $_.Exception.Message
}
finally {
    $reportObject = [pscustomobject]@{
        generated_at = (Get-Date).ToString("s")
        machine = $env:COMPUTERNAME
        exe = $Exe
        scenario = $Scenario
        exercise_private_fallback = [bool]$ExercisePrivateFallback
        results = @($results)
    }

    if ($Report) {
        $fullReport = [IO.Path]::GetFullPath($Report)
        $parent = Split-Path $fullReport -Parent
        if ($parent -and -not (Test-Path $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        $reportObject | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath $fullReport -Encoding UTF8
        Write-Host "Report: $fullReport"
    }
}

if ($failed) { exit 1 }
Write-Host "deployment verification PASS"
