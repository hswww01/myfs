param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [ValidatePattern('^[A-Za-z]:$')][string]$Drive = "R:",
    [string]$Size = "64M",
    [string[]]$ExtraArgs = @(),
    [string]$LogDirectory = ""
)

$ErrorActionPreference = "Stop"
$token = [Guid]::NewGuid().ToString("N")
$stopEventName = "Local\MemfsIntegration-" + $token
if ($null -eq ([System.Management.Automation.PSTypeName]'MemfsTest.NativeMethods').Type) {
    Add-Type -TypeDefinition @"
using System.Text;
using System.Runtime.InteropServices;
namespace MemfsTest {
    public static class NativeMethods {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint QueryDosDevice(string name, StringBuilder target, int size);
    }
}
"@
}

function Test-DosDeviceExists {
    param([string]$Device)
    $buffer = [Text.StringBuilder]::new(4096)
    $result = [MemfsTest.NativeMethods]::QueryDosDevice($Device, $buffer, $buffer.Capacity)
    if ($result -ne 0) { return $true }
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($errorCode -ne 2) { throw "QueryDosDevice($Device) failed: $errorCode" }
    return $false
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    # CommandLineToArgvW/CRT quoting: double backslashes before quotes and
    # before the enclosing final quote. Also works in Windows PowerShell 5.1.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
    throw "memfs executable not found: $Exe"
}
if (Test-DosDeviceExists $Drive) { throw "drive is already in use: $Drive" }
$exePath = (Resolve-Path -LiteralPath $Exe).Path
if (-not $LogDirectory) { $LogDirectory = Split-Path $exePath -Parent }
$LogDirectory = [IO.Path]::GetFullPath($LogDirectory)
[IO.Directory]::CreateDirectory($LogDirectory) | Out-Null
$stdoutPath = Join-Path $LogDirectory ("integration-" + $token + ".stdout.log")
$stderrPath = Join-Path $LogDirectory ("integration-" + $token + ".stderr.log")
$arguments = @("--mount", $Drive, "--size", $Size, "--label", "MEMTEST", "--stop-event", $stopEventName) + $ExtraArgs
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = $exePath
$info.WorkingDirectory = Split-Path $exePath -Parent
$info.Arguments = (($arguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }) -join ' ')
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$process = [Diagnostics.Process]::new()
$process.StartInfo = $info
$started = $false
$failure = $null
$stage = "launch"
$cleanupErrors = [Collections.Generic.List[string]]::new()
$stdoutTask = $null
$stderrTask = $null

try {
    if (-not $process.Start()) { throw 'Process.Start returned false' }
    $started = $true
    # Drain both pipes concurrently; never wait with an unread full pipe.
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $stage = "mount-wait"
    $mounted = $false
    for ($i = 0; $i -lt 100; $i++) {
        if ($process.HasExited) { break }
        if (Test-Path -LiteralPath "$Drive\") { $mounted = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $mounted) { throw "memfs did not mount $Drive" }

    $stage = "create-directory"
    New-Item -ItemType Directory -Path "$Drive\dir" | Out-Null
    $stage = "tiny-text-write"
    [IO.File]::WriteAllText("$Drive\hello.txt", "hello memfs")
    [IO.File]::WriteAllText("$Drive\HELLO.TXT", "upper-case twin")
    if ([IO.File]::ReadAllText("$Drive\hello.txt") -ne "hello memfs" -or
        [IO.File]::ReadAllText("$Drive\HELLO.TXT") -ne "upper-case twin") {
        throw 'case-distinct text readback mismatch'
    }
    $rootNames = @(Get-ChildItem -LiteralPath "$Drive\" | Select-Object -ExpandProperty Name)
    if ($rootNames -cnotcontains 'hello.txt' -or $rootNames -cnotcontains 'HELLO.TXT') {
        throw 'case-distinct files were not both enumerated'
    }
    if (Test-Path -LiteralPath "$Drive\HeLLo.TxT") {
        throw 'wrong-case path unexpectedly resolved'
    }
    Remove-Item -LiteralPath "$Drive\HELLO.TXT"
    if (-not (Test-Path -LiteralPath "$Drive\hello.txt") -or
        (Test-Path -LiteralPath "$Drive\HELLO.TXT")) {
        throw 'deleting one case-distinct file changed the other entry'
    }

    # Exercise real multi-page storage, not only tiny-file endpoints.
    $stage = "paged-write-read"
    $payload = New-Object byte[] (128KB + 37)
    for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = [byte](($i * 37 + 11) % 251) }
    [IO.File]::WriteAllBytes("$Drive\dir\data.bin", $payload)
    $bytes = [IO.File]::ReadAllBytes("$Drive\dir\data.bin")
    if ($bytes.Length -ne $payload.Length) { throw 'paged readback length mismatch' }
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -ne $payload[$i]) { throw "paged readback mismatch at $i" }
    }
    $stage = "paged-rewrite"
    $stream = [IO.File]::Open("$Drive\dir\data.bin", [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
    try {
        $patch = New-Object byte[] 10013
        for ($i = 0; $i -lt $patch.Length; $i++) { $patch[$i] = [byte](($i + 71) % 253) }
        $stream.Position = 4090
        $stream.Write($patch, 0, $patch.Length)
        [Array]::Copy($patch, 0, $payload, 4090, $patch.Length)
        $stream.Flush()
    }
    finally { $stream.Dispose() }
    $bytes = [IO.File]::ReadAllBytes("$Drive\dir\data.bin")
    for ($i = 0; $i -lt $payload.Length; $i++) {
        if ($bytes[$i] -ne $payload[$i]) { throw "cross-page rewrite mismatch at $i" }
    }
    $stream = [IO.File]::Open("$Drive\dir\data.bin", [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
    try { $stream.SetLength(4097); $stream.SetLength($payload.Length + 4096) }
    finally { $stream.Dispose() }
    $bytes = [IO.File]::ReadAllBytes("$Drive\dir\data.bin")
    if ($bytes.Length -ne $payload.Length + 4096) { throw 'truncate/regrow length mismatch' }
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $expected = if ($i -lt 4097) { $payload[$i] } else { 0 }
        if ($bytes[$i] -ne $expected) { throw "truncate/regrow zero-fill mismatch at $i" }
    }

    $stage = "sparse-write-read"
    $stream = [IO.File]::Open("$Drive\dir\sparse.bin", [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite)
    try {
        $stream.SetLength(8MB)
        $stream.Position = 4MB + 17
        $stream.WriteByte(0x7d)
        $stream.Position = 4MB
        $check = New-Object byte[] 32
        if ($stream.Read($check, 0, $check.Length) -ne $check.Length) { throw 'short sparse read' }
        for ($i = 0; $i -lt $check.Length; $i++) {
            $expected = if ($i -eq 17) { 0x7d } else { 0 }
            if ($check[$i] -ne $expected) { throw "sparse mismatch at $i" }
        }
    }
    finally { $stream.Dispose() }

    $stage = "rename-move"
    Rename-Item -LiteralPath "$Drive\hello.txt" -NewName "Hello.txt"
    if ((Test-Path -LiteralPath "$Drive\hello.txt") -or
        -not (Test-Path -LiteralPath "$Drive\Hello.txt")) {
        throw 'case-only rename did not preserve exact spelling'
    }
    Rename-Item -LiteralPath "$Drive\Hello.txt" -NewName "renamed.txt"
    Move-Item "$Drive\renamed.txt" "$Drive\dir\moved.txt"
    $stage = "enumeration"
    $names = @(Get-ChildItem "$Drive\dir" | Sort-Object Name | Select-Object -ExpandProperty Name)
    if (($names -join ',') -ne 'data.bin,moved.txt,sparse.bin') { throw "directory mismatch: $($names -join ',')" }
    $stage = "wildcard-enumeration"
    $wrongCaseFiltered = @(Get-ChildItem -LiteralPath "$Drive\dir" -Filter '*.TXT' | Select-Object -ExpandProperty Name)
    if ($wrongCaseFiltered.Count -ne 0) { throw 'wrong-case wildcard unexpectedly matched an entry' }
    $filtered = @(Get-ChildItem -LiteralPath "$Drive\dir" -Filter '*.txt' | Select-Object -ExpandProperty Name)
    if (($filtered -join ',') -ne 'moved.txt') { throw 'wildcard directory mismatch for exact-case pattern' }
    $stage = "delete-files"
    Remove-Item "$Drive\dir\moved.txt", "$Drive\dir\data.bin", "$Drive\dir\sparse.bin"
    $stage = "delete-directory"
    Remove-Item "$Drive\dir"
    if (@(Get-ChildItem "$Drive\").Count -ne 0) { throw 'root is not empty after I/O cleanup' }
}
catch {
    $failure = $_
    $diagnostic = [ordered]@{
        stage = $stage
        message = $_.Exception.Message
        exception_type = $_.Exception.GetType().FullName
        hresult = ('0x{0:X8}' -f $_.Exception.HResult)
        position = $_.InvocationInfo.PositionMessage
        script_stack_trace = $_.ScriptStackTrace
        inner = $(if ($_.Exception.InnerException) { $_.Exception.InnerException.ToString() } else { $null })
    }
    [IO.File]::WriteAllText((Join-Path $LogDirectory ("integration-"+$token+".failure.json")),
        ($diagnostic | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
}
finally {
    if ($started) {
        $force = $false
        if (-not $process.HasExited) {
            try {
                $stopEvent = [Threading.EventWaitHandle]::OpenExisting($stopEventName)
                try { [void]$stopEvent.Set() } finally { $stopEvent.Dispose() }
            }
            catch { $cleanupErrors.Add("graceful stop request failed: $($_.Exception.Message)"); $force = $true }
            if (-not $force -and -not $process.WaitForExit(10000)) {
                $cleanupErrors.Add('graceful stop timed out'); $force = $true
            }
            if ($force -and -not $process.HasExited) {
                try {
                    $process.Kill()
                    if (-not $process.WaitForExit(10000)) { $cleanupErrors.Add('forced cleanup timed out') }
                }
                catch { $cleanupErrors.Add("forced cleanup failed: $($_.Exception.Message)") }
            }
        }
        elseif ($null -eq $failure) { $cleanupErrors.Add('process exited before graceful stop request') }
        if ($process.HasExited -and $process.ExitCode -ne 0) {
            $cleanupErrors.Add("memfs exited with code $($process.ExitCode)")
        }
        foreach ($item in @(@($stdoutTask, $stdoutPath), @($stderrTask, $stderrPath))) {
            try {
                if ($null -ne $item[0]) {
                    if (-not $item[0].Wait(2000)) { throw 'output stream drain timed out' }
                    [IO.File]::WriteAllText($item[1], $item[0].GetAwaiter().GetResult(), [Text.UTF8Encoding]::new($false))
                }
            }
            catch { $cleanupErrors.Add("log capture failed: $($_.Exception.Message)") }
        }
        try {
            for ($i = 0; $i -lt 100; $i++) {
                if (-not (Test-DosDeviceExists $Drive)) { break }
                Start-Sleep -Milliseconds 100
            }
            if (Test-DosDeviceExists $Drive) { $cleanupErrors.Add("DOS device remains after exit: $Drive") }
        }
        catch { $cleanupErrors.Add("unmount verification failed: $($_.Exception.Message)") }
    }
    $process.Dispose()
}

if ($null -ne $failure -or $cleanupErrors.Count -ne 0) {
    $detail = if ($null -ne $failure) { $failure.Exception.Message } else { 'I/O passed but lifecycle validation failed' }
    if ($cleanupErrors.Count) { $detail += '; cleanup: ' + ($cleanupErrors -join '; ') }
    throw "stage=$stage; $detail; stdout=$stdoutPath; stderr=$stderrPath"
}
Write-Host "integration PASS: paged I/O, cross-page rewrite, truncate/regrow, sparse, namespace, graceful zero-exit unmount ($Drive)"
