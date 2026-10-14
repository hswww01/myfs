param([Alias("Exe")][string]$ExecutablePath)
$ErrorActionPreference = 'Stop'
function Test-MemfsPrivateDriver([string]$Executable) {
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='WinFsp+MemfsC'"
    if ($null -eq $driver -or $driver.State -ne 'Running') { return $false }
    if (-not ('MemfsDriverResource' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class MemfsDriverResource {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibraryEx(string file, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint SizeofResource(IntPtr m, IntPtr r);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr LoadResource(IntPtr m, IntPtr r);
    [DllImport("kernel32.dll")] public static extern IntPtr LockResource(IntPtr r);
    [DllImport("kernel32.dll")] public static extern bool FreeLibrary(IntPtr m);
}
'@
    }
    $Executable = (Resolve-Path -LiteralPath $Executable).Path
    $module = [MemfsDriverResource]::LoadLibraryEx($Executable, [IntPtr]::Zero, 0x22)
    if ($module -eq [IntPtr]::Zero) { throw 'Cannot read EXE resources.' }
    try {
        # This product is x64 user mode. On Windows ARM64 it embeds native A64.
        $arch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
        $id = if ($arch -eq 'ARM64') { 103 } else { 102 }
        $resource = [MemfsDriverResource]::FindResource($module, [IntPtr]$id, [IntPtr]10)
        if ($resource -eq [IntPtr]::Zero) { throw 'Embedded native driver resource is missing.' }
        $size = [MemfsDriverResource]::SizeofResource($module, $resource)
        if ($size -eq 0) { throw 'Embedded driver is empty.' }
        $pointer = [MemfsDriverResource]::LockResource([MemfsDriverResource]::LoadResource($module, $resource))
        if ($pointer -eq [IntPtr]::Zero) { throw 'Cannot map driver resource.' }
        $bytes = [byte[]]::new($size)
        [Runtime.InteropServices.Marshal]::Copy($pointer, $bytes, 0, $size)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $expected = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') }
        finally { $sha.Dispose() }
    } finally { [void][MemfsDriverResource]::FreeLibrary($module) }
    $path = $driver.PathName.Trim('"')
    if ($path.StartsWith('\??\')) { $path = $path.Substring(4) }
    if ($path.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) { $path = $env:SystemRoot + $path.Substring(11) }
    $allowed = Join-Path $env:SystemRoot 'System32\drivers'
    if ((Split-Path $path) -ine $allowed -or (Split-Path $path -Leaf) -notmatch '^memfs-winfsp-(x64|a64)(\.alt)?\.sys$') {
        throw "Unexpected private driver path: $path"
    }
    $fileStream=[IO.File]::OpenRead($path)
    $fileHash=[Security.Cryptography.SHA256]::Create()
    try { $actual=[BitConverter]::ToString($fileHash.ComputeHash($fileStream)).Replace('-', '') }
    finally { $fileHash.Dispose(); $fileStream.Dispose() }
    if ($actual -ne $expected) {
        throw 'Registered driver bytes differ from this EXE embedded SYS; refusing to test a different build.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Windows Hardware Compatibility Publisher') {
        throw 'The private SYS does not have the required valid Microsoft signature.'
    }
    # This proves configured bytes, not a staged image's load identity. The
    # deployment acceptance separately uses the bootstrapped device/version.
    return $true
}
# Dot-source for regression scripts, or invoke for Python preflight.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $ExecutablePath) { throw '-Exe is required.' }
    if (-not (Test-MemfsPrivateDriver $ExecutablePath)) { Write-Output 'SKIP: matching private driver must already be running.'; exit 77 }
    Write-Output 'PASS private driver signature and embedded resource match'
}
