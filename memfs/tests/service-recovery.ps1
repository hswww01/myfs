param(
    [string]$Exe = "",
    [string]$Drive = "R:",
    [string]$Size = "64M",
    [int]$TimeoutSeconds = 40
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$serviceHelper = Join-Path $repoRoot "scripts\memfs-service.ps1"
$serviceName = "MemfsC"
$privateDriverName = "WinFsp+MemfsC"

if (-not $Exe) {
    $Exe = Join-Path $repoRoot "build\x64-release\memfs.exe"
}
$Exe = [IO.Path]::GetFullPath($Exe)

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required."
    }
}

function Get-ServiceRow {
    Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
}

function Get-PrivateDriver {
    @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $privateDriverName }) | Select-Object -First 1
}

function Get-OfficialDriver {
    @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ne $privateDriverName -and (
                $_.PathName -match '(?i)\\WinFsp\\SxS\\' -or
                $_.Name -match '^WinFsp\+\d'
            )
        }) | Select-Object -First 1
}

function Wait-RunningNewPid {
    param([uint32]$OldPid)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $row = Get-ServiceRow
        if ($row -and $row.State -eq "Running" -and
            $row.ProcessId -ne 0 -and $row.ProcessId -ne $OldPid) {
            return $row
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "SCM did not restart $serviceName with a new PID within $TimeoutSeconds seconds."
}

function Wait-Mount {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path "$Drive\") {
            return
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "mount $Drive did not appear within $TimeoutSeconds seconds."
}

Assert-Admin

if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
    throw "memfs.exe not found: $Exe"
}
if ($Drive -notmatch '^[A-Za-z]:$') {
    throw "-Drive must be a drive letter such as R:"
}
if (Test-Path "$Drive\") {
    throw "drive is already in use: $Drive"
}
if (Get-ServiceRow) {
    throw "$serviceName already exists; remove it before running recovery test."
}
if (-not (Get-OfficialDriver)) {
    throw "This recovery test expects an installed official WinFsp driver."
}
if (Get-PrivateDriver) {
    throw "Private fallback driver already exists before recovery test."
}

$installed = $false
try {
    & $serviceHelper install -Exe $Exe -Mount $Drive -Size $Size -StartType demand
    $installed = $true
    & $serviceHelper start
    Wait-Mount

    $before = Get-ServiceRow
    if (-not $before -or $before.State -ne "Running" -or $before.ProcessId -eq 0) {
        throw "service did not reach RUNNING with a valid PID"
    }
    $oldPid = [uint32]$before.ProcessId

    [IO.File]::WriteAllText("$Drive\before-crash.txt", "volatile-before-crash")
    if ([IO.File]::ReadAllText("$Drive\before-crash.txt") -ne "volatile-before-crash") {
        throw "pre-crash readback mismatch"
    }

    Write-Host "Killing MemfsC PID $oldPid to simulate abnormal termination..."
    Stop-Process -Id $oldPid -Force

    $after = Wait-RunningNewPid -OldPid $oldPid
    $newPid = [uint32]$after.ProcessId
    Wait-Mount

    if (Test-Path "$Drive\before-crash.txt") {
        throw "volatile data unexpectedly survived process restart"
    }

    [IO.File]::WriteAllText("$Drive\after-restart.txt", "service-recovery-ok")
    $readback = [IO.File]::ReadAllText("$Drive\after-restart.txt")
    if ($readback -ne "service-recovery-ok") {
        throw "post-restart readback mismatch"
    }

    if (Get-PrivateDriver) {
        throw "service recovery unexpectedly created private WinFsp fallback"
    }

    Write-Host "SERVICE_RECOVERY_PASS old_pid=$oldPid new_pid=$newPid readback=$readback"
}
finally {
    if ($installed) {
        try { & $serviceHelper stop } catch { Write-Warning $_ }
        try { & $serviceHelper delete } catch { Write-Warning $_ }
    }
}

if (Get-ServiceRow) {
    throw "$serviceName still exists after cleanup"
}
if (Get-PrivateDriver) {
    throw "private WinFsp fallback exists after recovery test"
}
