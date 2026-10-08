param(
    [ValidateSet("install","start","query","stop","delete","restart","purge-driver")]
    [string]$Action = "query",
    [string]$Exe = "",
    [string]$Mount = "R:",
    [string]$Size = "512M",
    [string]$Label = "MEMFS",
    [ValidateSet("auto","demand")]
    [string]$StartType = "auto"
)

$ErrorActionPreference = "Stop"
$ServiceName = "MemfsC"

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges are required."
    }
}

function Invoke-Sc {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
    & sc.exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe failed with exit code ${LASTEXITCODE}: $($Args -join ' ')"
    }
}

function Wait-ServiceState {
    param([string]$Wanted, [int]$TimeoutSeconds = 20)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $text = (& sc.exe query $ServiceName | Out-String)
        if ($text -match "STATE\s+:\s+\d+\s+$Wanted") {
            return
        }
        if ($Wanted -eq "RUNNING" -and
            $text -match "STATE\s+:\s+1\s+STOPPED") {
            throw "Service $ServiceName stopped during startup:`n$text"
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service $ServiceName did not reach state $Wanted."
}

switch ($Action) {
    "install" {
        Assert-Admin
        if (-not $Exe) {
            $Exe = Join-Path (Split-Path $PSScriptRoot -Parent) "build\x64-release\memfs.exe"
        }
        $Exe = [IO.Path]::GetFullPath($Exe)
        if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
            throw "memfs.exe not found: $Exe"
        }
        if ($Mount -notmatch '^[A-Za-z]:$') {
            throw "For the service helper, -Mount must be a drive letter such as R:."
        }

        & sc.exe query $ServiceName *> $null
        $queryExit = $LASTEXITCODE
        if ($queryExit -eq 0) {
            throw "Service $ServiceName already exists. Delete or reconfigure it first."
        }
        if ($queryExit -ne 1060) {
            throw "sc query failed with exit code $queryExit"
        }

        $binPath = '"' + $Exe + '" --service --mount ' + $Mount +
                   ' --size ' + $Size + ' --label "' + $Label.Replace('"','') + '"'
        Invoke-Sc create $ServiceName "binPath=" $binPath "start=" $StartType
        Invoke-Sc description $ServiceName "MemfsC volatile memory filesystem"
        Invoke-Sc failure $ServiceName "reset=" "86400" "actions=" "restart/5000/restart/15000/""/0"
        Invoke-Sc failureflag $ServiceName 1
        Write-Output "Installed $ServiceName"
        Invoke-Sc qc $ServiceName
    }
    "start" {
        Assert-Admin
        Invoke-Sc start $ServiceName
        Wait-ServiceState "RUNNING"
        Invoke-Sc queryex $ServiceName
    }
    "query" {
        Invoke-Sc queryex $ServiceName
        Invoke-Sc qc $ServiceName
    }
    "stop" {
        Assert-Admin
        & sc.exe query $ServiceName *> $null
        if ($LASTEXITCODE -eq 1060) {
            Write-Output "$ServiceName is not installed."
            break
        }
        if ($LASTEXITCODE -ne 0) {
            throw "sc query failed with exit code $LASTEXITCODE"
        }

        & sc.exe stop $ServiceName
        if ($LASTEXITCODE -notin 0, 1062) {
            throw "sc stop failed with exit code $LASTEXITCODE"
        }
        Wait-ServiceState "STOPPED"
        Invoke-Sc queryex $ServiceName
    }
    "delete" {
        Assert-Admin
        & sc.exe query $ServiceName *> $null
        if ($LASTEXITCODE -eq 1060) {
            Write-Output "$ServiceName is already absent."
            break
        }
        if ($LASTEXITCODE -ne 0) {
            throw "sc query failed with exit code $LASTEXITCODE"
        }

        & sc.exe stop $ServiceName *> $null
        Invoke-Sc delete $ServiceName
        Write-Output "Deleted $ServiceName"
    }
    "purge-driver" {
        Assert-Admin
        if (-not $Exe) {
            $Exe = Join-Path (Split-Path $PSScriptRoot -Parent) "build\x64-release\memfs.exe"
        }
        $Exe = [IO.Path]::GetFullPath($Exe)
        if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) {
            throw "memfs.exe not found: $Exe"
        }

        $serviceText = (& sc.exe query $ServiceName 2>&1 | Out-String)
        $queryExit = $LASTEXITCODE
        if ($queryExit -eq 0 -and $serviceText -match "STATE\s+:\s+4\s+RUNNING") {
            throw "Stop MemfsC before purging the private WinFsp driver."
        }
        if ($queryExit -notin 0, 1060) {
            throw "sc query failed with exit code $queryExit"
        }

        & $Exe --uninstall-private-driver
        if ($LASTEXITCODE -ne 0) {
            throw "memfs private driver uninstall failed with exit code $LASTEXITCODE"
        }
    }
    "restart" {
        Assert-Admin
        & sc.exe stop $ServiceName *> $null
        Wait-ServiceState "STOPPED"
        Invoke-Sc start $ServiceName
        Wait-ServiceState "RUNNING"
        Invoke-Sc queryex $ServiceName
    }
}
