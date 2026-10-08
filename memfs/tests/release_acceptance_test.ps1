param([string]$RepoRoot = "")
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path $PSScriptRoot -Parent }
$repo = [IO.Path]::GetFullPath($RepoRoot)
$scriptPath = Join-Path $repo 'scripts\verify-release-acceptance.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
# Load only helper definitions; never execute the acceptance body in unit tests.
$required=@('Quote-NativeArgument','Invoke-Native','Invoke-Script','Get-Median')
foreach($name in $required) {
    $functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object {$_.Name -eq $name})
    if ($functions.Count -ne 1) { throw "Missing/ambiguous helper: $name" }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$ReportDir=Join-Path ([IO.Path]::GetTempPath()) ('memfs-acceptance-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $ReportDir | Out-Null
$nativeIndex=0
$hostExe=(Get-Process -Id $PID).Path
$checks=0
function Check([bool]$Condition,[string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}
function Encode([string]$Text) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text)) }
try {
    Check ((Quote-NativeArgument '') -eq '""') 'Empty native argument'
    Check ((Quote-NativeArgument 'plain') -eq 'plain') 'Plain native argument'
    Check ((Get-Median @(8.0,2.0,5.0)) -eq 5.0) 'Odd median'
    Check ((Get-Median @(8.0,2.0,5.0,3.0)) -eq 4.0) 'Even median'

    $echoPath=Join-Path $ReportDir 'echo spaced path.ps1'
    [IO.File]::WriteAllText($echoPath,'param([string]$Value) [Console]::Write($Value)')
    $value='space \"quote" trailing\'
    $output=Invoke-Native 'quote-roundtrip' $hostExe @('-NoProfile','-NonInteractive','-File',$echoPath,'-Value',$value) 30
    Check ($output.stdout -eq $value) ('Native quoting roundtrip mismatch: '+$output.stdout)

    $code="[Console]::Out.Write(('o' * 131072)); [Console]::Error.Write(('e' * 131072)); exit 0"
    $output=Invoke-Native 'large-pipes' $hostExe @('-NoProfile','-EncodedCommand',(Encode $code)) 30
    Check ($output.stdout.Length -eq 131072 -and $output.stderr.Length -eq 131072) 'Concurrent stdout/stderr pipe draining'

    $rejected=$false
    try { Invoke-Native 'exit-seven' $hostExe @('-NoProfile','-EncodedCommand',(Encode 'exit 7')) 30 | Out-Null }
    catch { $rejected=$_.Exception.Message -match 'exited 7' }
    Check $rejected 'Nonzero child exit was not rejected'

    $pidFile=Join-Path $ReportDir 'owned-child.pid'
    $escaped=$pidFile.Replace("'","''")
    $code="[IO.File]::WriteAllText('$escaped',[string]`$PID); Start-Sleep -Seconds 20"
    $rejected=$false
    try { Invoke-Native 'timeout' $hostExe @('-NoProfile','-EncodedCommand',(Encode $code)) 2 | Out-Null }
    catch { $rejected=$_.Exception.Message -match 'exceeded 2s' }
    Check $rejected 'Timed-out child was not rejected'
    Check (Test-Path -LiteralPath $pidFile) 'Timeout child did not start'
    $childId=[int](Get-Content -LiteralPath $pidFile -Raw)
    Check (-not (Get-Process -Id $childId -ErrorAction SilentlyContinue)) 'Timed-out owned child still running'

    $arrayPath=Join-Path $ReportDir 'array-args.ps1'
    [IO.File]::WriteAllText($arrayPath,'param([string[]]$ExtraArgs,[switch]$Toggle) @{args=$ExtraArgs; toggle=[bool]$Toggle} | ConvertTo-Json -Compress')
    $output=Invoke-Script 'array-binding' $arrayPath @{ExtraArgs=@('--compress','--encrypt');Toggle=$true} 30
    $data=$output.stdout | ConvertFrom-Json
    Check (($data.args -join ',') -eq '--compress,--encrypt' -and $data.toggle) 'Script array/switch binding'

    # A full-run preflight failure must leave an explicit FAILED report, not PASS.
    $probe=Join-Path $ReportDir 'expected-failure-report'
    $rejected=$false
    try {
        Invoke-Script 'failed-report' $scriptPath @{BuildDir=(Join-Path $ReportDir 'missing-build');DebugBuildDir=(Join-Path $ReportDir 'missing-debug');ReportDir=$probe;Quick=$true;RepeatCount=1} 30 | Out-Null
    } catch { $rejected=$_.Exception.Message -match 'exited 1' }
    Check $rejected 'Invalid build directory did not fail acceptance'
    $data=Get-Content -LiteralPath (Join-Path $probe 'acceptance.json') -Raw | ConvertFrom-Json
    Check ($data.status -eq 'failed' -and -not $data.all_requested_checks_passed -and -not $data.externally_release_ready) 'Failure report mislabeled readiness'
    Check (@($data.steps | Where-Object {$_.name -eq 'preflight' -and $_.status -eq 'FAIL'}).Count -eq 1) 'Failed step absent in report'
    Write-Output "release acceptance helper tests PASS checks=$checks"
} finally {
    Remove-Item -LiteralPath $ReportDir -Recurse -Force -ErrorAction SilentlyContinue
}
