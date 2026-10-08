param(
	[Parameter(Mandatory = $true)][string]$Exe,
	[string]$Drive = "W:"
)

$ErrorActionPreference = "Stop"
$Exe = [IO.Path]::GetFullPath($Exe)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Output "SKIP: native service lifecycle test requires an elevated process."
	exit 77
}

$Drive = $Drive.TrimEnd('\')
if ($Drive -notmatch '^[A-Za-z]:$') { throw "Drive must be a drive-letter root such as W:." }
$driveName = $Drive.Substring(0, 1)
if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
	throw "Refusing to use occupied drive $Drive."
}

$winfspDriverServices = @(Get-CimInstance Win32_SystemDriver | Where-Object {
	$_.Name -like "WinFsp+*" -and $_.PathName -match '(?i)\\WinFsp\\SxS\\'
})
$officialDriver = $winfspDriverServices | Where-Object { $_.State -eq "Running" } | Select-Object -First 1
if ($null -eq $officialDriver) {
	Write-Output "SKIP: requires an already-running official WinFsp kernel driver; this test never installs or changes a driver."
	exit 77
}
$driverSnapshot = (@($winfspDriverServices | Sort-Object Name | ForEach-Object {
	"$($_.Name)|$($_.State)|$($_.PathName)"
}) -join "`n")

$serviceName = "MemfsFrontendTest_$([Guid]::NewGuid().ToString('N'))"
$serviceFilter = "Name='$serviceName'"
$logPath = Join-Path $env:ProgramData "MemfsC\$serviceName.log"
$installArgs = @("--install", "--service-name", $serviceName,
	"--mount", $Drive, "--size", "32M", "--threads", "2")
$uninstallArgs = @("--uninstall", "--service-name", $serviceName)

function Get-TestService {
	Get-CimInstance Win32_Service -Filter $serviceFilter -ErrorAction SilentlyContinue
}

function Wait-TestServiceState([string]$Expected, [int]$TimeoutSeconds = 60) {
	$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
	do {
		$service = Get-TestService
		if ($null -ne $service -and $service.State -eq $Expected) { return $service }
		Start-Sleep -Milliseconds 250
	} while ([DateTime]::UtcNow -lt $deadline)
	throw "Service $serviceName did not reach $Expected within $TimeoutSeconds seconds."
}

function Invoke-Memfs([string[]]$Arguments, [int]$ExpectedExit = 0) {
	$output = (& $Exe @Arguments 2>&1 | Out-String)
	$actualExit = $LASTEXITCODE
	if ($actualExit -ne $ExpectedExit) {
		throw "memfs $($Arguments -join ' ') returned $actualExit, expected $ExpectedExit.`n$output"
	}
	return $output
}

try {
	if ($null -ne (Get-TestService)) { throw "Test service name unexpectedly exists." }

	Invoke-Memfs $installArgs | Out-Null
	$service = Wait-TestServiceState "Running"
	if ($service.StartMode -ne "Auto" -or $service.StartName -ne "LocalSystem") {
		throw "Installed service has unexpected start mode/account: $($service.StartMode), $($service.StartName)."
	}
	$originalPath = $service.PathName
	if ($originalPath -notmatch [Regex]::Escape($Exe) -or $originalPath -notmatch '--service') {
		throw "SCM command does not target the requested executable and service mode."
	}

	if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
		throw "Expected protected service log was not created: $logPath"
	}
	$installerSid = $identity.User.Value
	$logAcl = Get-Acl -LiteralPath $logPath
if (-not $logAcl.AreAccessRulesProtected) {
		throw "Service log DACL is not protected from inherited grants."
	}
	$allowedSids = @("S-1-5-18", $installerSid)
	$logRules = @($logAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
	foreach ($rule in $logRules) {
		if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
			$rule.IdentityReference.Value -notin $allowedSids) {
			throw "Unexpected service log ACL entry: $($rule.IdentityReference.Value) $($rule.AccessControlType)."
		}
	}
	if ($logRules.Count -eq 0 -or $logRules.IdentityReference.Value -notcontains $installerSid) {
		throw "Service log ACL does not grant the installer SID access."
	}

	# Repeating the same install must be idempotent and preserve the service registration.
	Invoke-Memfs $installArgs | Out-Null
	$service = Wait-TestServiceState "Running"
	if ($service.PathName -ne $originalPath) { throw "Idempotent install changed the service command." }

	# A different capacity is a materially different configuration and must be rejected.
	$mismatchArgs = @("--install", "--service-name", $serviceName,
		"--mount", $Drive, "--size", "64M", "--threads", "2")
	Invoke-Memfs $mismatchArgs 1 | Out-Null
	$service = Get-TestService
	if ($null -eq $service -or $service.State -ne "Running" -or $service.PathName -ne $originalPath) {
		throw "Mismatched install changed or stopped the existing service."
	}

	# Exercise case-sensitive files through the actual mounted drive.
	[IO.File]::WriteAllText("$Drive\Case.txt", "upper spelling")
	[IO.File]::WriteAllText("$Drive\case.txt", "lower spelling")
	if ([IO.File]::ReadAllText("$Drive\Case.txt") -ne "upper spelling" -or
		[IO.File]::ReadAllText("$Drive\case.txt") -ne "lower spelling") {
		throw "Case-distinct files did not retain separate contents."
	}
	if ([IO.File]::Exists("$Drive\CASE.TXT")) { throw "Wrong-case lookup unexpectedly resolved a file." }
	Remove-Item -LiteralPath "$Drive\case.txt"
	if ([IO.File]::Exists("$Drive\case.txt") -or
		[IO.File]::ReadAllText("$Drive\Case.txt") -ne "upper spelling") {
		throw "Deleting one case-distinct file changed the other entry."
	}
	Remove-Item -LiteralPath "$Drive\Case.txt"

	# Verify SCM STOP and START leave the isolated service usable before native uninstall.
	& sc.exe stop $serviceName | Out-Null
	Wait-TestServiceState "Stopped" | Out-Null
	& sc.exe start $serviceName | Out-Null
	Wait-TestServiceState "Running" | Out-Null
	if ([IO.File]::Exists("$Drive\Case.txt")) {
		throw "Volatile file unexpectedly survived a service restart."
	}
	[IO.File]::WriteAllText("$Drive\after-restart.txt", "fresh volume")
	if ([IO.File]::ReadAllText("$Drive\after-restart.txt") -ne "fresh volume") {
		throw "Mounted filesystem was not usable after service restart."
	}

	# Uninstall must bounded-stop only this service and delete its SCM registration.
	Invoke-Memfs $uninstallArgs | Out-Null
	$deadline = [DateTime]::UtcNow.AddSeconds(30)
	do {
		$service = Get-TestService
		if ($null -eq $service) { break }
		Start-Sleep -Milliseconds 250
	} while ([DateTime]::UtcNow -lt $deadline)
	if ($null -ne $service) { throw "Native uninstall did not remove $serviceName." }

	$currentDrivers = @(Get-CimInstance Win32_SystemDriver | Where-Object {
		$_.Name -like "WinFsp+*" -and $_.PathName -match '(?i)\\WinFsp\\SxS\\'
	})
	$currentSnapshot = (@($currentDrivers | Sort-Object Name | ForEach-Object {
		"$($_.Name)|$($_.State)|$($_.PathName)"
	}) -join "`n")
	if ($currentSnapshot -ne $driverSnapshot) {
		throw "Native service lifecycle changed the existing WinFsp driver state."
	}
	$privateDriver = Get-CimInstance Win32_SystemDriver -Filter "Name='WinFsp+MemfsC'" -ErrorAction SilentlyContinue
	if ($null -ne $privateDriver) { throw "Test unexpectedly created the MemfsC private WinFsp driver service." }
	Write-Output "native-service-install PASS: $serviceName on $Drive"
}
finally {
	$service = Get-TestService
	if ($null -ne $service) {
		try { Invoke-Memfs $uninstallArgs | Out-Null }
		catch { Write-Warning "Could not safely remove isolated test service ${serviceName}: $_" }
	}
}
