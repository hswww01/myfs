param([Parameter(Mandatory=$true)][string]$Exe)
# Read-only prerequisite. Never install, start, stop or upgrade a driver here.
$ErrorActionPreference='Stop'
$Exe=(Resolve-Path -LiteralPath $Exe).Path
$driver=Get-CimInstance Win32_SystemDriver -Filter "Name='WinFsp+FsC'" -ErrorAction Stop
if ($null -eq $driver -or $driver.State -ne 'Running') {
    Write-Output 'SKIP: the product-owned WinFsp+FsC driver must already be running.'
    exit 77
}
if (-not ('MemfsEmbeddedDriverEvidence' -as [type])) {
    Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
public static class MemfsEmbeddedDriverEvidence {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr FindResource(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    public static string Hash(string path) {
        ushort processMachine,nativeMachine;
        if (!IsWow64Process2(GetCurrentProcess(),out processMachine,out nativeMachine)) throw new Win32Exception();
        int id=nativeMachine==0x8664?102:nativeMachine==0xaa64?103:0;
        if(id==0)throw new NotSupportedException("Native architecture");
        IntPtr module=LoadLibraryEx(path,IntPtr.Zero,0x22); // data/image resources only; no code executes
        if(module==IntPtr.Zero)throw new Win32Exception();
        try {
            IntPtr resource=FindResource(module,new IntPtr(id),new IntPtr(10));
            if(resource==IntPtr.Zero)throw new Win32Exception();
            uint length=SizeofResource(module,resource);
            if(length==0 || length>16*1024*1024)throw new InvalidOperationException("Invalid SYS resource length");
            IntPtr data=LockResource(LoadResource(module,resource));
            if(data==IntPtr.Zero)throw new Win32Exception();
            byte[] bytes=new byte[length]; Marshal.Copy(data,bytes,0,bytes.Length);
            using(var sha=SHA256.Create())return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","");
        } finally {FreeLibrary(module);}
    }
}
'@
}
$path=$driver.PathName.Trim('"') -replace '^\\\?\?\\',''
if ($path.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)) { $path=Join-Path $env:SystemRoot $path.Substring(12) }
$expected=[MemfsEmbeddedDriverEvidence]::Hash($Exe)
$actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
if($expected -ne $actual){throw "Running private service SYS file does not match this executable's embedded resource: $path"}
$signature=Get-AuthenticodeSignature -LiteralPath $path
if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Windows Hardware Compatibility Publisher') {
    throw "Private WinFsp driver signature invalid: $path"
}
Write-Output "PASS private driver prerequisite: $((Get-Item -LiteralPath $path).VersionInfo.FileVersion); embedded SHA256=$actual"
# File checks alone are not proof of the in-memory image. The upgrade acceptance
# separately records the stopped -> started transition and loaded module path.
exit 0
