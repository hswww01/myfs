param(
    [ValidateSet('Integrity','Runtime','OfficialInstalled','PrivateFallback')]
    [string]$Scenario = 'Runtime',
    [ValidateSet('Any','AMD64','ARM64')][string]$ExpectedNativeMachine = 'Any',
    [switch]$ExercisePrivateFallback
)

$ErrorActionPreference = 'Stop'
# PowerShell 5.1 launched from PowerShell 7 can inherit only the parent's
# module paths. Make this process's own built-in modules discoverable.
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + [IO.Path]::PathSeparator + $env:PSModulePath
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath($PSScriptRoot)
$results = [Collections.Generic.List[object]]::new()
$report = [ordered]@{
    schema_version = 1
    started_at = (Get-Date).ToUniversalTime().ToString('o')
    scenario = $Scenario
    status = 'running'
    source_commit = ''
    exe_sha256 = ''
    native_machine = ''
    process_machine = ''
    externally_release_ready = $false
    note = 'A kit PASS covers only the explicitly executed scenario on this machine. It is not signing, licensing, reboot or other-OS certification.'
    tests = @()
}
$runDir = Join-Path $root ('results\run-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8))
$reportPath = Join-Path $runDir 'result.json'
$hostExe = (Get-Process -Id $PID).Path

function Resolve-KitFile([string]$Relative) {
    if (-not $Relative -or [IO.Path]::IsPathRooted($Relative) -or
        $Relative -match '(^|[/\\])\.\.([/\\]|$)|:') {
        throw "Unsafe kit-relative path: $Relative"
    }
    $path = [IO.Path]::GetFullPath((Join-Path $root $Relative))
    if (-not $path.StartsWith($root.TrimEnd('\')+'\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes kit: $Relative"
    }
    $current = $path
    while ($current.Length -ge $root.Length) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse point in kit path: $Relative"
            }
        }
        $current = Split-Path $current -Parent
        if (-not $current) { break }
    }
    return $path
}

function Check-Integrity {
    $manifest = Resolve-KitFile 'SHA256SUMS.txt'
    $seen = @{}
    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw 'Malformed kit manifest' }
        $expected = $Matches[1]
        $relative = $Matches[2].Replace('\','/')
        if ($seen.ContainsKey($relative)) { throw "Duplicate manifest path: $relative" }
        $seen[$relative] = $true
        $file = Resolve-KitFile $relative
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing kit file: $relative" }
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $expected) {
            throw "Kit hash mismatch: $relative"
        }
    }
    foreach ($required in @('memfs.exe','KIT_INFO.json','BUILD_PROVENANCE.json','RUN-VALIDATION.ps1','cases.json')) {
        if (-not $seen.ContainsKey($required)) { throw "Manifest omits required file: $required" }
    }
    # Results are the only mutable directory. Extra payloads do not silently
    # become trusted simply because they were left out of the hash manifest.
    foreach ($file in Get-ChildItem -LiteralPath $root -File -Recurse) {
        $relative = $file.FullName.Substring($root.Length+1).Replace('\','/')
        if ($relative -eq 'SHA256SUMS.txt' -or $relative.StartsWith('results/')) { continue }
        if (-not $seen.ContainsKey($relative)) { throw "Unlisted kit file: $relative" }
    }
    $info = Get-Content -LiteralPath (Resolve-KitFile 'KIT_INFO.json') -Raw | ConvertFrom-Json
    $provenance = Get-Content -LiteralPath (Resolve-KitFile 'BUILD_PROVENANCE.json') -Raw | ConvertFrom-Json
    $hash = (Get-FileHash -LiteralPath (Resolve-KitFile 'memfs.exe') -Algorithm SHA256).Hash
    if ($hash -ne $info.exe_sha256 -or $hash -ne $provenance.evidence.build.exe_sha256) {
        throw 'EXE differs from kit/build provenance'
    }
    if ($info.source_commit -ne $provenance.evidence.source.memfs_git_commit) {
        throw 'Kit source revision differs from build provenance'
    }
    $report.source_commit = $info.source_commit
    $report.exe_sha256 = $hash
    return $seen.Count
}

function Quote-Arg([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $Value = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $Value = [regex]::Replace($Value, '(\\+)$', '$1$1')
    return '"' + $Value + '"'
}

function Invoke-Child {
    param([string]$Name, [string]$File, [string[]]$Arguments = @(), [int]$ExpectedExit = 0, [int]$TimeoutSeconds = 60)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.Arguments = (($Arguments | ForEach-Object { Quote-Arg ([string]$_) }) -join ' ')
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $stem = $Name -replace '[^a-zA-Z0-9_.-]', '_'
    $stdoutFile = Join-Path $runDir ($stem+'.stdout.log')
    $stderrFile = Join-Path $runDir ($stem+'.stderr.log')
    try {
        if (-not $process.Start()) { throw "Could not start $Name" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) {
            $kill = [Diagnostics.ProcessStartInfo]::new()
            $kill.FileName = Join-Path $env:WINDIR 'System32\taskkill.exe'
            $kill.Arguments = '/PID '+$process.Id+' /T /F'
            $kill.UseShellExecute = $false; $kill.CreateNoWindow = $true
            $killer = [Diagnostics.Process]::Start($kill)
            try { if (-not $killer.WaitForExit(10000)) { throw 'Owned child-tree cleanup timed out' } }
            finally { $killer.Dispose() }
            if (-not $process.WaitForExit(5000)) { throw 'Owned test process did not exit' }
        }
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw "Output drain timed out: $Name" }
        $outText = $stdout.GetAwaiter().GetResult()
        $errText = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($stdoutFile, $outText, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($stderrFile, $errText, [Text.UTF8Encoding]::new($false))
        if (-not $finished) { throw "$Name timed out; cleanup is not a passing test" }
        if ($process.ExitCode -ne $ExpectedExit) {
            throw "$Name exit=$($process.ExitCode), expected=$ExpectedExit; logs=$stdoutFile ; $stderrFile"
        }
        $results.Add([pscustomobject]@{ name=$Name; status='PASS'; exit_code=$process.ExitCode; seconds=[Math]::Round($watch.Elapsed.TotalSeconds,3) })
        Write-Host "[PASS] $Name (exit=$($process.ExitCode))"
    }
    catch {
        $results.Add([pscustomobject]@{ name=$Name; status='FAIL'; error=$_.Exception.Message })
        throw
    }
    finally { $watch.Stop(); $process.Dispose() }
}

try {
    # Reject redirected output locations before writing any report/log file.
    [void](Resolve-KitFile 'results/probe')
    [IO.Directory]::CreateDirectory($runDir) | Out-Null
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell; 32-bit validation is unsupported' }
    $count = Check-Integrity
    $results.Add([pscustomobject]@{ name='kit-integrity'; status='PASS'; checked_files=$count })
    Write-Host "[PASS] kit-integrity ($count files)"
    if ($null -eq ([System.Management.Automation.PSTypeName]'MemfsKit.Native').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace MemfsKit {
    public static class Native {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);
    }
}
"@
    }
    [UInt16]$processMachine = 0
    [UInt16]$nativeMachine = 0
    if (-not [MemfsKit.Native]::IsWow64Process2([Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$processMachine, [ref]$nativeMachine)) {
        throw 'Cannot determine native Windows architecture'
    }
    $nativeName = switch ($nativeMachine) { 0x8664 {'AMD64'}; 0xAA64 {'ARM64'}; default { throw 'Unsupported native Windows architecture' } }
    $report.native_machine = $nativeName
    $report.process_machine = ('0x{0:X4}' -f $processMachine)
    if ($ExpectedNativeMachine -ne 'Any' -and $ExpectedNativeMachine -ne $nativeName) {
        throw "Expected native $ExpectedNativeMachine but machine is $nativeName"
    }
    if ($Scenario -eq 'Runtime') {
        # PS5.1 emits a JSON array as one pipeline object; first assign its
        # value, then enumerate it, instead of wrapping the pipeline itself.
        $caseData = Get-Content -LiteralPath (Resolve-KitFile 'cases.json') -Raw | ConvertFrom-Json
        $cases = @($caseData)
        if ($cases.Count -ne 20) { throw "Expected 20 portable registered tests, got $($cases.Count)" }
        foreach ($case in $cases) {
            $file = if ($case.executable -eq '@powershell') { $hostExe } else { Resolve-KitFile $case.executable }
            $args = @($case.arguments | ForEach-Object {
                if ($_ -is [string] -and $_.StartsWith('@kit/')) { Resolve-KitFile $_.Substring(5) } else { [string]$_ }
            })
            Invoke-Child -Name $case.name -File $file -Arguments $args -ExpectedExit $case.expected_exit -TimeoutSeconds $case.timeout_seconds
        }
    }
    elseif ($Scenario -ne 'Integrity') {
        # These are explicitly requested mounted scenarios. Missing preconditions
        # are failures, not silent skips, and no installed driver is removed.
        $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.Name -match '^WinFsp' -or $_.PathName -match '(?i)winfsp.*\.sys' })
        $official = @($drivers | Where-Object { $_.Name -ne 'WinFsp+MemfsC' })
        if ($Scenario -eq 'PrivateFallback') {
            if (-not $ExercisePrivateFallback) { throw 'PrivateFallback requires explicit -ExercisePrivateFallback on a disposable clean guest' }
            if ($official.Count -ne 0) { throw 'Refusing PrivateFallback: official WinFsp is present' }
            foreach ($base in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
                if ($base -and (Test-Path -LiteralPath (Join-Path $base 'WinFsp'))) { throw 'Refusing PrivateFallback: WinFsp installation directory exists' }
            }
        }
        elseif ($official.Count -eq 0) { throw 'OfficialInstalled requires an existing official WinFsp driver' }
        $params = @{
            Scenario=$Scenario
            Exe=(Resolve-KitFile 'memfs.exe')
            Report=(Join-Path $runDir 'deployment.json')
        }
        if ($Scenario -eq 'PrivateFallback') { $params.ExercisePrivateFallback = $true }
        $entry = @{ path=(Resolve-KitFile 'scripts/verify-deployment.ps1'); parameters=$params } | ConvertTo-Json -Depth 5 -Compress
        $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($entry))
        $bootstrap = @'
$ErrorActionPreference='Stop'
try {
    $entry=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__DATA__'))|ConvertFrom-Json
    $bound=@{}
    foreach($property in $entry.parameters.PSObject.Properties) { $bound[$property.Name]=$property.Value }
    & $entry.path @bound
    exit 0
} catch { [Console]::Error.WriteLine(($_ | Out-String)); exit 1 }
'@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap.Replace('__DATA__',$data)))
        Invoke-Child -Name $Scenario -File $hostExe -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -TimeoutSeconds 180
        $deployment = Get-Content -LiteralPath (Join-Path $runDir 'deployment.json') -Raw | ConvertFrom-Json
        if (@($deployment.results | Where-Object { $_.status -in @('SKIP','FAIL') }).Count -ne 0) { throw 'Requested deployment scenario was skipped or failed' }
    }
    $report.status = 'passed'
    Write-Host "KIT_SCENARIO_PASS scenario=$Scenario native=$nativeName external_release_ready=false"
}
catch {
    $report.status = 'failed'
    $report['failure'] = $_.Exception.Message
    Write-Host ('KIT_SCENARIO_FAIL: '+$_.Exception.Message)
    throw
}
finally {
    $report['finished_at'] = (Get-Date).ToUniversalTime().ToString('o')
    $report.tests = $results.ToArray()
    if (Test-Path -LiteralPath $runDir -PathType Container) {
        [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        Write-Host "Report: $reportPath"
    }
}
