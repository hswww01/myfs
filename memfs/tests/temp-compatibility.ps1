param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$Probe,
    [Parameter(Mandatory=$true)][string]$Dll,
    [ValidatePattern('^[A-Za-z]:$')][string]$Drive = 'T:',
    [switch]$Compress,
    [switch]$Encrypt
)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$Probe = (Resolve-Path -LiteralPath $Probe).Path
$Dll = (Resolve-Path -LiteralPath $Dll).Path
# Do not exercise the executable's automatic driver-install fallback in tests.
. (Join-Path $PSScriptRoot 'private-driver-preflight.ps1')
if (-not (Test-MemfsPrivateDriver $Exe)) {
    Write-Output 'SKIP: a matching private driver must already be running; this test never installs drivers.'
    exit 77
}
if (-not ('MemfsTempDosDevice' -as [type])) {
    Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class MemfsTempDosDevice {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint QueryDosDevice(string name, StringBuilder target, int size);
}
'@
}
function Test-Device {
    $buffer = [Text.StringBuilder]::new(4096)
    if ([MemfsTempDosDevice]::QueryDosDevice($Drive, $buffer, $buffer.Capacity)) { return $true }
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($errorCode -ne 2) { throw "QueryDosDevice failed: $errorCode" }
    return $false
}
function Quote-Arg([string]$Value) {
    if ($Value.Length -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}
# Coordinate test mounts across separate CTest/build invocations.
$testMutex = [Threading.Mutex]::new($false, ('Local\MemfsTestDrive-' + $Drive.Substring(0,1).ToUpperInvariant()))
$ownsTestMutex = $false
try {
    try { $ownsTestMutex = $testMutex.WaitOne(60000) }
    catch [Threading.AbandonedMutexException] { $ownsTestMutex = $true }
    if (-not $ownsTestMutex) { throw 'Timed out waiting for the private test drive mutex.' }
if (Test-Device) { throw "Refusing occupied drive $Drive; production volumes are never touched." }
$token = [Guid]::NewGuid().ToString('N')
$logDir = Join-Path (Split-Path $Probe) "temp-test-$token"
[IO.Directory]::CreateDirectory($logDir) | Out-Null
$eventName = "Local\MemfsTempTest-$token"
$mountArgs = @('--mount', $Drive, '--size', '128M', '--mkdir', 'tmp', '--stop-event', $eventName)
if ($Compress) { $mountArgs += '--compress' }
if ($Encrypt) { $mountArgs += '--encrypt' }
$process = $null
$client = $null
try {
    $process = Start-Process -FilePath $Exe -ArgumentList (($mountArgs | ForEach-Object { Quote-Arg $_ }) -join ' ') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDir 'mount.out.log') -RedirectStandardError (Join-Path $logDir 'mount.err.log')
    $mounted = $false
    for ($i=0; $i -lt 150; ++$i) {
        if ($process.HasExited) { throw "memfs exited early: $($process.ExitCode)" }
        if (Test-Path -LiteralPath "$Drive\tmp" -PathType Container) { $mounted = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $mounted) { throw 'mount timeout' }
    $client = Start-Process -FilePath $Probe -ArgumentList ((@("$Drive\tmp", $Dll) | ForEach-Object { Quote-Arg $_ }) -join ' ') -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDir 'probe.out.log') -RedirectStandardError (Join-Path $logDir 'probe.err.log')
    if (-not $client.WaitForExit(60000)) { throw 'native probe timeout' }
    Get-Content -LiteralPath (Join-Path $logDir 'probe.out.log')
    Get-Content -LiteralPath (Join-Path $logDir 'probe.err.log')
    if ($client.ExitCode -ne 0) { throw "native probe failed: $($client.ExitCode)" }

    # Native NTFS -> RAM -> NTFS copy must preserve Mark of the Web exactly.
    $source = Join-Path $logDir 'zone-source.txt'
    $onRam = "$Drive\tmp\zone-roundtrip.txt"
    $roundTripFile = Join-Path $logDir 'zone-return.txt'
    [IO.File]::WriteAllText($source, 'benign zone roundtrip fixture')
    $zoneText = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.invalid/fixture.txt`r`n"
    Set-Content -LiteralPath $source -Stream Zone.Identifier -Value $zoneText -NoNewline -Encoding ascii
    Copy-Item -LiteralPath $source -Destination $onRam
    if ((Get-Content -LiteralPath $onRam -Stream Zone.Identifier -Raw) -cne $zoneText) { throw 'Zone.Identifier lost copying NTFS -> RAM' }
    $streams = @(Get-Item -LiteralPath $onRam -Stream *)
    if ($streams.Stream -notcontains 'Zone.Identifier') { throw 'PowerShell stream enumeration failed' }
    Copy-Item -LiteralPath $onRam -Destination $roundTripFile
    if ((Get-Content -LiteralPath $roundTripFile -Stream Zone.Identifier -Raw) -cne $zoneText) { throw 'Zone.Identifier lost copying RAM -> NTFS' }
    if ((Get-FileHash $source).Hash -ne (Get-FileHash $roundTripFile).Hash) { throw 'Main stream changed in cross-volume copy' }
    $directoryListing = (& cmd.exe /d /c "dir /r `"$onRam`"" | Out-String)
    if ($LASTEXITCODE -ne 0 -or $directoryListing -notmatch 'Zone.Identifier') { throw 'cmd dir /r stream enumeration failed' }
    Remove-Item -LiteralPath $onRam -Stream Zone.Identifier
    if (-not (Test-Path -LiteralPath $onRam)) { throw 'Removing a stream deleted the main file' }
    Remove-Item -LiteralPath $onRam
    Write-Output 'PASS PowerShell ADS and NTFS -> RAM -> NTFS Zone.Identifier preservation'
    & python.exe (Join-Path $PSScriptRoot 'temp-workloads.py') "$Drive\tmp"
    if ($LASTEXITCODE -ne 0) { throw 'Python / SQLite temp workloads failed' }

    # Real Windows ACL tools: propagation to existing descendants, protection,
    # verification, reset, and save/restore. No production paths are involved.
    $dir = "$Drive\tmp\icacls-test"
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    $file = Join-Path $dir 'existing.tmp'
    [IO.File]::WriteAllText($file, 'acl round trip')
    $roundTrip = Get-Acl -LiteralPath $file
    # Mark owner/group dirty so Set-Acl really persists them, rather than
    # optimizing an unchanged .NET FileSecurity object into a no-op.
    $roundTrip.SetOwner($roundTrip.GetOwner([Security.Principal.SecurityIdentifier]))
    $roundTrip.SetGroup($roundTrip.GetGroup([Security.Principal.SecurityIdentifier]))
    Set-Acl -LiteralPath $file -AclObject $roundTrip
    if ((Get-Acl -LiteralPath $file).Owner -ne $roundTrip.Owner) { throw 'Set-Acl owner round trip failed' }
    Write-Output 'PASS PowerShell Get-Acl / Set-Acl owner and group round trip'
    & icacls.exe $dir /grant '*S-1-1-0:(OI)(CI)(RX)' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'icacls /grant failed' }
    $rules = (Get-Acl -LiteralPath $file).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    if (-not ($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and $_.IsInherited })) { throw 'ACL did not propagate to an existing child' }
    & icacls.exe $file /inheritance:r | Out-Host
    if ($LASTEXITCODE -ne 0 -or -not (Get-Acl -LiteralPath $file).AreAccessRulesProtected) { throw 'DACL protection failed' }
    & icacls.exe $file /reset | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'icacls /reset failed' }
    & icacls.exe $dir /verify /T | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'icacls /verify failed' }
    $backup = Join-Path $logDir 'acl-backup.txt'
    & icacls.exe "$dir\*" /save $backup /T | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'icacls /save failed' }
    & icacls.exe $dir /restore $backup | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'icacls /restore failed' }
    Write-Output 'PASS icacls propagation / inheritance / reset / verify / save / restore'
    Write-Output "PASS temp compatibility; compress=$Compress encrypt=$Encrypt; logs=$logDir"
} finally {
    if ($null -ne $client) {
        if (-not $client.HasExited) { $client.Kill(); [void]$client.WaitForExit(5000) }
        $client.Dispose()
    }
    if ($null -ne $process) {
        if (-not $process.HasExited) {
            try {
                $event = [Threading.EventWaitHandle]::OpenExisting($eventName)
                try { [void]$event.Set() } finally { $event.Dispose() }
                if (-not $process.WaitForExit(15000)) { throw 'graceful unmount timeout' }
            } finally {
                # Only this test's newly created process may be terminated.
                if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(5000) }
            }
        }
        $exitCode = $process.ExitCode
        $process.Dispose()
        if ($exitCode -ne 0) { throw "test mount exited with $exitCode; logs=$logDir" }
        for ($i=0; $i -lt 50 -and (Test-Device); ++$i) { Start-Sleep -Milliseconds 100 }
        if (Test-Device) { throw "test drive remained mounted: $Drive" }
    }
}

} finally {
    if ($ownsTestMutex) { $testMutex.ReleaseMutex() }
    $testMutex.Dispose()
}
