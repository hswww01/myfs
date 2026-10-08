param(
    [string]$BuildDir = "",
    [string]$DebugBuildDir = "",
    [string]$ReportDir = "",
    [ValidateRange(1, 1000)][int]$RepeatCount = 50,
    [ValidateRange(10, 60)][int]$SoakMinutes = 10,
    [switch]$Quick,
    [switch]$IncludeMounted,
    [switch]$IncludeServiceRecovery,
    [switch]$Package,
    [switch]$RequireSignedExe
)

$ErrorActionPreference = "Stop"
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if (-not $BuildDir) { $BuildDir = Join-Path $repo "build\x64-release" }
if (-not $DebugBuildDir) { $DebugBuildDir = Join-Path $repo "build\x64-debug" }
$BuildDir = [IO.Path]::GetFullPath($BuildDir)
$DebugBuildDir = [IO.Path]::GetFullPath($DebugBuildDir)
if (-not $ReportDir) {
    $ReportDir = Join-Path $repo (".agent\acceptance-" + (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + [Guid]::NewGuid().ToString("N").Substring(0,8))
}
$ReportDir = [IO.Path]::GetFullPath($ReportDir)
# Reports are append-by-new-directory artifacts; never clear a user's directory.
if (Test-Path -LiteralPath $ReportDir) { throw "ReportDir must not already exist: $ReportDir" }
New-Item -ItemType Directory -Path $ReportDir | Out-Null
$steps = [Collections.Generic.List[object]]::new()
$nativeIndex = 0
$exe = Join-Path $BuildDir "memfs.exe"
$hostExe = (Get-Process -Id $PID).Path
$reportPath = Join-Path $ReportDir "acceptance.json"
$report = [ordered]@{
    schema_version = 1
    started_at = (Get-Date).ToUniversalTime().ToString("o")
    finished_at = $null
    profile = $(if ($Quick) { "quick-smoke" } else { "extended-local" })
    source_dir = $repo
    build_dir = $BuildDir
    git_commit = ""
    exe_sha256 = ""
    status = "running"
    all_requested_checks_passed = $false
    externally_release_ready = $false
    repeat_count = $RepeatCount
    capacity_benchmark = $null
    exe_signature = $null
    external_gates_not_evaluated = @(
        "Clean Windows 10/11 embedded-driver installation/uninstallation",
        "Windows 11 ARM64 x64-emulation plus native ARM64 driver",
        "Service startup/recovery across an actual OS reboot",
        "Approved production EXE signing identity and timestamp policy",
        "WinFsp static-link distribution-license decision"
    )
    known_feature_limit = "Official signed WinFsp 2.1 does not expose FSCTL_QUERY_ALLOCATED_RANGES through the user-mode Control callback."
    steps = @()
}

function Save-Report {
    $report.steps = $steps.ToArray()
    $json = $report | ConvertTo-Json -Depth 10
    $tmp = $reportPath + ".tmp"
    [IO.File]::WriteAllText($tmp, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $tmp -Destination $reportPath -Force
}

function Quote-NativeArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    # CommandLineToArgvW/CRT quoting. No shell expansion is used.
    $Value = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $Value = [regex]::Replace($Value, '(\\+)$', '$1$1')
    return '"' + $Value + '"'
}

function Invoke-Native {
    param([string]$Name, [string]$File, [string[]]$Arguments = @(), [int]$TimeoutSeconds = 120)
    $script:nativeIndex++
    $stem = "{0:D3}-{1}" -f $script:nativeIndex, ($Name -replace '[^a-zA-Z0-9_.-]', '_')
    $stdoutPath = Join-Path $ReportDir ($stem + ".stdout.log")
    $stderrPath = Join-Path $ReportDir ($stem + ".stderr.log")
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.Arguments = (($Arguments | ForEach-Object { Quote-NativeArgument ([string]$_) }) -join " ")
    $info.WorkingDirectory = $repo
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        if (-not $process.Start()) { throw "Could not start $File" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $finished = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $finished) {
            # Kill only the process tree created by this invocation.
            $killInfo = [Diagnostics.ProcessStartInfo]::new()
            $killInfo.FileName = Join-Path $env:WINDIR "System32\taskkill.exe"
            $killInfo.Arguments = "/PID " + $process.Id + " /T /F"
            $killInfo.UseShellExecute = $false
            $killInfo.CreateNoWindow = $true
            $killInfo.RedirectStandardOutput = $true
            $killInfo.RedirectStandardError = $true
            $killer = [Diagnostics.Process]::Start($killInfo)
            try {
                $ko = $killer.StandardOutput.ReadToEndAsync()
                $ke = $killer.StandardError.ReadToEndAsync()
                [void]$killer.WaitForExit(10000)
            } finally { $killer.Dispose() }
            if (-not $process.WaitForExit(5000)) { throw "$Name timed out and process tree cleanup did not finish" }
        }
        # Bounded wait also detects descendants that kept redirected pipes open.
        if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) {
            throw "$Name output pipes did not close after process exit"
        }
        $outText = $stdout.GetAwaiter().GetResult()
        $errText = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText($stdoutPath, $outText, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($stderrPath, $errText, [Text.UTF8Encoding]::new($false))
        if (-not $finished) { throw "$Name exceeded ${TimeoutSeconds}s; see $stdoutPath and $stderrPath" }
        if ($process.ExitCode -ne 0) {
            $tail = ($outText + "`n" + $errText)
            if ($tail.Length -gt 3000) { $tail = $tail.Substring($tail.Length - 3000) }
            throw "$Name exited $($process.ExitCode):`n$tail`nLogs: $stdoutPath ; $stderrPath"
        }
        return [pscustomobject]@{ stdout = $outText; stderr = $errText; seconds = $watch.Elapsed.TotalSeconds; log = $stdoutPath }
    } finally { $watch.Stop(); $process.Dispose() }
}

function Invoke-Script {
    param([string]$Name, [string]$Path, [hashtable]$Parameters = @{}, [int]$TimeoutSeconds = 120)
    $entry = @{ path = $Path; parameters = $Parameters } | ConvertTo-Json -Depth 5 -Compress
    $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($entry))
    $bootstrap = @'
$ErrorActionPreference='Stop'
try {
    $entry = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__DATA__')) | ConvertFrom-Json
    $bound = @{}
    foreach($property in $entry.parameters.PSObject.Properties) { $bound[$property.Name] = $property.Value }
    & $entry.path @bound
    exit 0
} catch { [Console]::Error.WriteLine(($_ | Out-String)); exit 1 }
'@
    $bootstrap = $bootstrap.Replace('__DATA__', $data)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    return Invoke-Native -Name $Name -File $hostExe -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -TimeoutSeconds $TimeoutSeconds
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "[RUN] $Name"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action | Out-Null
        $steps.Add([pscustomobject]@{ name=$Name; status="PASS"; seconds=[Math]::Round($watch.Elapsed.TotalSeconds,3) })
        Write-Host "[PASS] $Name"
    } catch {
        $steps.Add([pscustomobject]@{ name=$Name; status="FAIL"; seconds=[Math]::Round($watch.Elapsed.TotalSeconds,3); error=$_.Exception.Message })
        throw
    } finally { $watch.Stop(); Save-Report }
}

function Skip-Step([string]$Name, [string]$Reason) {
    $steps.Add([pscustomobject]@{ name=$Name; status="SKIP"; reason=$Reason })
    Write-Host "[SKIP] $Name - $Reason"
    Save-Report
}

function Get-Median([double[]]$Values) {
    $sorted = @($Values | Sort-Object)
    if (-not $sorted.Count) { throw "No benchmark samples" }
    if ($sorted.Count % 2) { return $sorted[[int][Math]::Floor($sorted.Count / 2)] }
    return ($sorted[$sorted.Count / 2 - 1] + $sorted[$sorted.Count / 2]) / 2
}

$lock = $null
try {
    Save-Report
    Invoke-Step "preflight" {
        if (-not [Environment]::Is64BitProcess) { throw "Run this verifier from 64-bit PowerShell" }
        $agentDir = Join-Path $repo '.agent'
        New-Item -ItemType Directory -Path $agentDir -Force | Out-Null
        if (((Get-Item -LiteralPath $agentDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Acceptance lock directory must not be a reparse point"
        }
        $script:lock = [IO.File]::Open((Join-Path $agentDir 'release-acceptance.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        foreach($cache in @((Join-Path $BuildDir 'CMakeCache.txt'), (Join-Path $DebugBuildDir 'CMakeCache.txt'))) {
            if (-not (Test-Path -LiteralPath $cache -PathType Leaf)) { throw "Missing configured build: $cache" }
        }
        $script:cmake = (Get-Command cmake.exe -ErrorAction Stop).Source
        $script:ctest = (Get-Command ctest.exe -ErrorAction Stop).Source
        $script:git = (Get-Command git.exe -ErrorAction Stop).Source
        $report.git_commit = (Invoke-Native 'git-head' $git @('rev-parse','HEAD')).stdout.Trim()
    }
    Invoke-Step "build-debug" { Invoke-Native 'build-debug' $cmake @('--build',$DebugBuildDir) 600 }
    Invoke-Step "build-release" { Invoke-Native 'build-release' $cmake @('--build',$BuildDir) 600 }
    Invoke-Step "test-registration" {
        $catalog = (Invoke-Native 'test-catalog' $ctest @('--test-dir',$BuildDir,'--show-only=json-v1')).stdout | ConvertFrom-Json
        $names = @($catalog.tests | ForEach-Object { $_.name })
        $snapshot = @($names | Where-Object { $_ -match '^memfs_capacity_(cache|snapshot)_test$' })
        $required = @('memfs_core_test','memfs_mt_stress_test','memfs_lifetime_test','memfs_winfsp_dispatcher_state')
        if ($snapshot.Count -ne 1 -or @($required | Where-Object { $names -notcontains $_ }).Count -ne 0) {
            throw "Required core/stress/lifetime/security/production capacity-cache tests are not registered"
        }
        $script:repeatRegex = '^(' + (($required + $snapshot[0]) -join '|') + ')$'
        $report['registered_tests'] = $names
        $report.exe_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    }
    Invoke-Step "ctest-debug" {
        Invoke-Native 'ctest-debug' $ctest @('--test-dir',$DebugBuildDir,'--output-on-failure','--no-tests=error','--timeout','60','--output-junit',(Join-Path $ReportDir 'ctest-debug.xml')) 600
    }
    Invoke-Step "ctest-release" {
        Invoke-Native 'ctest-release' $ctest @('--test-dir',$BuildDir,'--output-on-failure','--no-tests=error','--timeout','60','--output-junit',(Join-Path $ReportDir 'ctest-release.xml')) 600
    }
    Invoke-Step "repeat-release" {
        Invoke-Native 'repeat-release' $ctest @('--test-dir',$BuildDir,'--output-on-failure','--no-tests=error','--timeout','60','--repeat',("until-fail:"+$RepeatCount),'-R',$repeatRegex) ([Math]::Max(180, $RepeatCount * 30))
    }
    Invoke-Step "capacity-benchmark" {
        $runs = @()
        for($i=0; $i -lt 7; $i++) {
            $result = Invoke-Native ("capacity-"+$i) (Join-Path $BuildDir 'memfs_capacity_bench.exe')
            $row = @{}
            foreach($name in @('fixed_growth_ns','auto_growth_ns','committed_query_ns','auto_allowance_query_ns')) {
                $match = [regex]::Match($result.stdout, ('(?m)^'+$name+'=([0-9.]+)\s*$'))
                if (-not $match.Success) { throw "Missing benchmark metric $name" }
                $row[$name] = [double]::Parse($match.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
            }
            $runs += [pscustomobject]$row
        }
        $medians = @{}
        foreach($name in @('fixed_growth_ns','auto_growth_ns','committed_query_ns','auto_allowance_query_ns')) {
            $medians[$name] = Get-Median @($runs | ForEach-Object { $_.$name })
        }
        $report.capacity_benchmark = @{ runs=$runs; medians=$medians; scope='Core microbenchmark on this host; not a mounted-drive throughput guarantee.' }
    }
    Invoke-Step "soak-fixed-smoke" {
        $result = Invoke-Native 'soak-fixed' (Join-Path $BuildDir 'memfs_soak_bench.exe') @('--seconds','10','--sample-ms','1000') 60
        if ($result.stdout -notmatch '(?m)^soak PASS\s*$') { throw 'Fixed-capacity soak failed final baseline' }
        $report['fixed_soak_summary'] = [regex]::Match($result.stdout,'(?m)^summary .+$').Value
    }
    Invoke-Step "soak-auto-capacity" {
        $args = if ($Quick) { @('--seconds','10','--sample-ms','1000') } else { @('--soak',([string]$SoakMinutes),'--sample-ms','5000') }
        $limit = if ($Quick) { 60 } else { $SoakMinutes * 60 + 60 }
        $args += '--auto-capacity'
        $result = Invoke-Native 'soak-auto' (Join-Path $BuildDir 'memfs_soak_bench.exe') $args $limit
        if ($result.stdout -notmatch '(?m)^capacity_mode=auto\s*$') { throw 'Long soak did not enable automatic capacity' }
        if ($result.stdout -notmatch '(?m)^soak PASS\s*$') { throw 'Soak did not report a passing final baseline' }
        $summary = [regex]::Match($result.stdout,'(?m)^summary .+$').Value
        $report['soak_summary'] = $summary
        $report['soak_log'] = $result.log
    }
    if ($IncludeMounted) {
        foreach($mode in @('plain','compress','encrypt','combined','auto')) {
            Invoke-Step ("mount-"+$mode) {
                $params = @{ Exe=$exe; Drive='R:'; Size='64M' }
                switch($mode) {
                    'compress' { $params.ExtraArgs=@('--compress') }
                    'encrypt' { $params.ExtraArgs=@('--encrypt') }
                    'combined' { $params.ExtraArgs=@('--compress','--encrypt') }
                    'auto' { $params.Size='auto' }
                }
                # The integration script rejects an occupied DOS device; it must
                # never take over an existing user's R: drive.
                $result = Invoke-Script ("mount-"+$mode) (Join-Path $repo 'tests\integration.ps1') $params 120
                if ($result.stdout -notmatch 'integration PASS') { throw "Mount test omitted success marker" }
            }
        }
    } else { Skip-Step 'mounted-matrix' 'Not requested; requires a free R: and functional WinFsp' }
    if ($IncludeServiceRecovery) {
        Invoke-Step 'service-recovery' {
            $result = Invoke-Script 'service-recovery' (Join-Path $repo 'tests\service-recovery.ps1') @{Exe=$exe;Drive='R:';Size='64M'} 180
            if ($result.stdout -notmatch 'SERVICE_RECOVERY_PASS') { throw 'Service recovery omitted success marker' }
        }
    } else { Skip-Step 'service-recovery' 'Not requested; requires administrator and absence of MemfsC test service' }
    Invoke-Step 'artifact-stability' {
        $afterHead = (Invoke-Native 'git-head-final' $git @('rev-parse','HEAD')).stdout.Trim()
        if ($afterHead -ne $report.git_commit -or (Get-FileHash $exe -Algorithm SHA256).Hash -ne $report.exe_sha256) {
            throw 'Source commit or Release executable changed during acceptance; rerun on a stable revision'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $exe
        $report.exe_signature = [string]$signature.Status
        if ($RequireSignedExe -and ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer)) {
            throw 'Production EXE signature required; unsigned/self-issued test certificate is not accepted'
        }
    }
    if ($Package) {
        Invoke-Step 'package-provenance' {
            Invoke-Script 'package' (Join-Path $PSScriptRoot 'package-release.ps1') @{BuildDir=$BuildDir} 600
            $pack = Join-Path $repo 'dist\memfs-x64'
            $packedExe = Join-Path $pack 'memfs.exe'
            if ((Get-FileHash $packedExe -Algorithm SHA256).Hash -ne $report.exe_sha256) { throw 'Packaged EXE differs from accepted binary' }
            $manifest = Get-Content -LiteralPath (Join-Path $pack 'SHA256SUMS.txt')
            foreach($line in $manifest) {
                if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { throw 'Malformed SHA256 manifest line' }
                $expected=$Matches[1]; $relative=$Matches[2]
                $target=[IO.Path]::GetFullPath((Join-Path $pack $relative))
                if (-not $target.StartsWith($pack.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path leaves package root' }
                if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $expected) { throw "Manifest mismatch: $relative" }
            }
            $report['package_dir']=$pack
        }
    } else { Skip-Step 'package-provenance' 'Not requested; run with -Package after scoped changes are committed' }
    $report.status='passed'
    $report.all_requested_checks_passed=$true
    Write-Host "LOCAL_ACCEPTANCE_PASS profile=$($report.profile) external_release_gates_still_open=true"
} catch {
    $report.status='failed'
    $report['failure']=$_.Exception.Message
    Write-Host ("LOCAL_ACCEPTANCE_FAIL: " + $_.Exception.Message)
    throw
} finally {
    $report.finished_at=(Get-Date).ToUniversalTime().ToString('o')
    Save-Report
    if ($lock) { $lock.Dispose() }
    Write-Host "Acceptance report: $reportPath"
}
