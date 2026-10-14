param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$Probe,
    [Parameter(Mandatory=$true)][string]$Dll,
    [ValidatePattern('^[A-Za-z]:$')][string]$Drive = 'U:'
)
$ErrorActionPreference = 'Stop'
$Exe = (Resolve-Path -LiteralPath $Exe).Path
$Probe = (Resolve-Path -LiteralPath $Probe).Path
$Dll = (Resolve-Path -LiteralPath $Dll).Path
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'SKIP: LocalSystem test requires an elevated process.'
    exit 77
}
. (Join-Path $PSScriptRoot 'private-driver-preflight.ps1')
if (-not (Test-MemfsPrivateDriver $Exe)) {
    Write-Output 'SKIP: a matching private driver must already be running; this test never installs drivers.'
    exit 77
}
Add-Type @'
using System.Text;
using System.Runtime.InteropServices;
public static class MemfsServiceTestDevice {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint QueryDosDevice(string name, StringBuilder output, int size);
}
'@
# Coordinate test mounts across separate CTest/build invocations.
$testMutex = [Threading.Mutex]::new($false, ('Local\MemfsTestDrive-' + $Drive.Substring(0,1).ToUpperInvariant()))
$ownsTestMutex = $false
try {
    try { $ownsTestMutex = $testMutex.WaitOne(60000) }
    catch [Threading.AbandonedMutexException] { $ownsTestMutex = $true }
    if (-not $ownsTestMutex) { throw 'Timed out waiting for the private test drive mutex.' }
$device = [Text.StringBuilder]::new(4096)
if ([MemfsServiceTestDevice]::QueryDosDevice($Drive, $device, $device.Capacity)) { throw "Refusing occupied $Drive drive." }
if ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -ne 2) { throw "Could not safely check $Drive availability." }
$token = [Guid]::NewGuid().ToString('N')
$name = 'MemfsTempCompat_' + $token
$logDir = Join-Path (Split-Path $Probe) "temp-service-$token"
[IO.Directory]::CreateDirectory($logDir) | Out-Null
$filter = "Name='$name'"
if (Get-CimInstance Win32_Service -Filter $filter) { throw 'Generated service name already exists.' }
$attempted = $false
$client = $null
try {
    $attempted = $true
    & $Exe --install --service-name $name --mount $Drive --size 128M --compress --mkdir tmp --threads 4
    if ($LASTEXITCODE -ne 0) { throw 'Private test service install failed.' }
    $service = Get-CimInstance Win32_Service -Filter $filter
    if ($service.StartName -ne 'LocalSystem' -or $service.State -ne 'Running') { throw 'Unexpected test service identity/state.' }
    $client = Start-Process -FilePath $Probe -ArgumentList @("$Drive\tmp", ('"' + $Dll + '"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logDir 'probe.out.log') -RedirectStandardError (Join-Path $logDir 'probe.err.log')
    if (-not $client.WaitForExit(60000)) { throw 'Native LocalSystem probe timed out.' }
    Get-Content (Join-Path $logDir 'probe.out.log')
    Get-Content (Join-Path $logDir 'probe.err.log')
    if ($client.ExitCode -ne 0) { throw "Native LocalSystem probe failed: $($client.ExitCode)" }
    & python.exe (Join-Path $PSScriptRoot 'temp-workloads.py') "$Drive\tmp"
    if ($LASTEXITCODE -ne 0) { throw 'LocalSystem mount Python / SQLite workloads failed.' }
    Write-Output "PASS LocalSystem service temp compatibility; logs=$logDir"
} finally {
    if ($null -ne $client) {
        if (-not $client.HasExited) { $client.Kill(); [void]$client.WaitForExit(5000) }
        $client.Dispose()
    }
    if ($attempted -and (Get-CimInstance Win32_Service -Filter $filter)) {
        & $Exe --uninstall --service-name $name
        if ($LASTEXITCODE -ne 0) { throw "Failed to remove private test service $name" }
    }
    if (Get-CimInstance Win32_Service -Filter $filter) { throw "Private test service remains: $name" }
    if ([MemfsServiceTestDevice]::QueryDosDevice($Drive, $device, $device.Capacity)) { throw "Private test $Drive drive remains." }
}

} finally {
    if ($ownsTestMutex) { $testMutex.ReleaseMutex() }
    $testMutex.Dispose()
}
