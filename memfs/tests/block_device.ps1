<#
.SYNOPSIS
  End-to-end test of memfs --block (Arsenal Image Mounter DevIoDrv disk).

.DESCRIPTION
  Requires an elevated shell, the AIM drivers (phdskmnt, deviodrv) installed
  and running, and aim_ll.exe. For each mode (plain, compressed+encrypted):
  mounts an NTFS disk, checks hard links, verifies that memory follows the
  data (write grows it, delete + TRIM frees it), reads data back unbuffered,
  then detaches and checks no AIM device is left. Finally it repeats bare
  mount/unmount cycles. Exits 0 on success.

  Never cancels driver I/O and never force-removes a disk while memfs still
  serves it; a failing run leaves diagnostics in -LogDirectory.
#>
param(
	[Parameter(Mandatory = $true)][string]$MemfsExe,
	[Parameter(Mandatory = $true)][string]$AimLl,
	[string]$Drive = 'X:',
	[string]$LogDirectory = $env:TEMP,
	[int]$Cycles = 5
)

$ErrorActionPreference = 'Stop'
$failures = 0
function Check([bool]$condition, [string]$what) {
	if ($condition) { Write-Host "PASS $what" } else { Write-Host "FAIL $what"; $script:failures++ }
}

function Private-MB($process) { $process.Refresh(); [math]::Round($process.PrivateMemorySize64 / 1MB) }

function Start-Block([string[]]$extra, [string]$tag) {
	$event = "memfs-block-test-$PID-$tag"
	$log = Join-Path $LogDirectory "memfs-block-$tag.log"
	$arguments = @('--block', '--mount', $Drive, '--label', 'MEMBLKTEST', '--aim-ll', $AimLl, '--stop-event', $event) + $extra
	$process = Start-Process -FilePath $MemfsExe -ArgumentList $arguments -RedirectStandardOutput $log `
		-RedirectStandardError "$log.err" -WindowStyle Hidden -PassThru
	for ($i = 0; $i -lt 90 -and !(Test-Path "$Drive\"); $i++) {
		Start-Sleep -Milliseconds 500
		if ($process.HasExited) { break }
	}
	[pscustomobject]@{ Process = $process; Event = $event; Log = $log }
}

function Stop-Block($run) {
	$handle = [Threading.EventWaitHandle]::OpenExisting($run.Event)
	[void]$handle.Set()
	$exited = $run.Process.WaitForExit(120000)
	Check $exited "memfs exits after the stop event"
	if ($exited) { Check ($run.Process.ExitCode -eq 0) "memfs exit code is 0 (got $($run.Process.ExitCode))" }
	Check (!(Test-Path "$Drive\")) "drive $Drive is removed"
	$list = & $AimLl -l 2>&1 | Out-String
	Check ($list -match 'No virtual disks') "no AIM virtual disk is left"
}

function Write-Random([string]$path, [int]$megabytes) {
	$buffer = New-Object byte[] (1MB)
	$random = [Security.Cryptography.RandomNumberGenerator]::Create()
	$sha = [Security.Cryptography.SHA256]::Create()
	$stream = [IO.File]::OpenWrite($path)
	try {
		for ($i = 0; $i -lt $megabytes; $i++) {
			$random.GetBytes($buffer)
			$stream.Write($buffer, 0, $buffer.Length)
			[void]$sha.TransformBlock($buffer, 0, $buffer.Length, $null, 0)
		}
		$stream.Flush($true)
	} finally { $stream.Close() }
	[void]$sha.TransformFinalBlock($buffer, 0, 0)
	[BitConverter]::ToString($sha.Hash)
}

function Hash-Unbuffered([string]$path) {
	# FILE_FLAG_NO_BUFFERING: read from the disk, not the system cache.
	$stream = [IO.FileStream]::new($path, 'Open', 'Read', 'Read', 4096, [IO.FileOptions]0x20000000)
	$sha = [Security.Cryptography.SHA256]::Create()
	$buffer = New-Object byte[] (1MB)
	try {
		while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) { [void]$sha.TransformBlock($buffer, 0, $read, $null, 0) }
	} finally { $stream.Close() }
	[void]$sha.TransformFinalBlock($buffer, 0, 0)
	[BitConverter]::ToString($sha.Hash)
}

function Test-Mode([string]$tag, [string[]]$extra) {
	Write-Host "== mode $tag"
	$run = Start-Block (@('--size', '2G', '--disk-size', '8G') + $extra) $tag
	Check (Test-Path "$Drive\") "$tag disk is mounted at $Drive"
	if (!(Test-Path "$Drive\")) { Get-Content $run.Log, "$($run.Log).err" -ErrorAction SilentlyContinue; return }
	try {
		$volume = Get-Volume -DriveLetter $Drive[0]
		Check ($volume.FileSystem -eq 'NTFS') "$tag volume is NTFS"

		Set-Content "$Drive\a.txt" 'memfs block device'
		cmd /c mklink /H "$Drive\b.txt" "$Drive\a.txt" | Out-Null
		$links = @(fsutil hardlink list "$Drive\a.txt")
		Check ($links.Count -eq 2 -and (Get-Content "$Drive\b.txt") -eq 'memfs block device') "$tag hard link works"

		$base = Private-MB $run.Process
		$hash = Write-Random "$Drive\big.bin" 400
		Write-VolumeCache -DriveLetter $Drive[0]
		$grown = Private-MB $run.Process
		if ($tag -eq 'plain') { Check ($grown -ge $base + 350) "$tag memory grows with data ($base -> $grown MB)" }
		else { Check ($grown -ge $base + 300) "$tag memory grows with incompressible data ($base -> $grown MB)" }
		Check ((Hash-Unbuffered "$Drive\big.bin") -eq $hash) "$tag unbuffered read-back matches"

		[IO.File]::Delete("$Drive\big.bin")
		Write-VolumeCache -DriveLetter $Drive[0]
		# NTFS batches delete notifications (TRIM); allow time, no manual ReTrim.
		$freed = $grown
		for ($i = 0; $i -lt 60 -and $freed -gt $base + 64; $i++) { Start-Sleep 1; $freed = Private-MB $run.Process }
		Check ($freed -le $base + 64) "$tag delete frees memory through TRIM ($grown -> $freed MB)"
	} finally {
		Stop-Block $run
	}
}

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (!$identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
foreach ($service in 'phdskmnt', 'deviodrv') {
	if ((Get-Service $service -ErrorAction SilentlyContinue).Status -ne 'Running') { throw "AIM service $service is not running." }
}
if (Test-Path "$Drive\") { throw "$Drive is already in use." }
$before = Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = 1001} -MaxEvents 1 -ErrorAction SilentlyContinue

Test-Mode 'plain' @()
Test-Mode 'compressed-encrypted' @('--compress', '--encrypt')

Write-Host "== $Cycles mount/unmount cycles"
for ($cycle = 1; $cycle -le $Cycles; $cycle++) {
	$run = Start-Block @('--size', '256M', '--disk-size', '1G') "cycle$cycle"
	Check (Test-Path "$Drive\") "cycle $cycle mounted"
	Stop-Block $run
}

if ($failures) { Write-Host "$failures check(s) failed"; exit 1 }
Write-Host 'block device test passed'
exit 0
