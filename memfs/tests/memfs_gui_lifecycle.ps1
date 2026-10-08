param(
	[Parameter(Mandatory = $true)] [string] $Exe,
	[string] $Drive = 'W:'
)

$ErrorActionPreference = 'Stop'
$serviceName = 'MemfsGuiLifecycleTest'
$driveLetter = $Drive.TrimEnd(':').ToUpperInvariant()

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class MemfsGuiNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)]
    public struct COMBOBOXINFO {
        public int cbSize; public RECT rcItem; public RECT rcButton; public int stateButton;
        public IntPtr hwndCombo, hwndItem, hwndList;
    }
    public delegate bool EnumProc(IntPtr hwnd, IntPtr lparam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr FindWindowW(string cls, string title);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool EnumWindows(EnumProc callback, IntPtr lparam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool EnumChildWindows(IntPtr parent, EnumProc callback, IntPtr lparam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int capacity);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int GetClassNameW(IntPtr hwnd, StringBuilder text, int capacity);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool GetComboBoxInfo(IntPtr combo, ref COMBOBOXINFO info);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool SetWindowTextW(IntPtr hwnd, string text);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageW(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendTextMessage(IntPtr hwnd, uint msg, IntPtr wparam, [MarshalAs(UnmanagedType.LPWStr)] string text);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendBufferMessage(IntPtr hwnd, uint msg, IntPtr wparam, StringBuilder text);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetLogicalDrives();
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool GetVolumeInformationW(string root, StringBuilder volumeName, int volumeNameSize, out uint serial, out uint maxComponentLength, out uint flags, StringBuilder fsName, int fsNameSize);

    public static List<IntPtr> Windows() {
        var result = new List<IntPtr>();
        EnumWindows((hwnd, lp) => { result.Add(hwnd); return true; }, IntPtr.Zero);
        return result;
    }
    public static List<IntPtr> Children(IntPtr parent) {
        var result = new List<IntPtr>();
        EnumChildWindows(parent, (hwnd, lp) => { result.Add(hwnd); return true; }, IntPtr.Zero);
        return result;
    }
    public static string Text(IntPtr hwnd) {
        var b = new StringBuilder(2048); GetWindowTextW(hwnd, b, b.Capacity); return b.ToString();
    }
    public static string Class(IntPtr hwnd) {
        var b = new StringBuilder(128); GetClassNameW(hwnd, b, b.Capacity); return b.ToString();
    }
    public static uint OwnerProcess(IntPtr hwnd) {
        uint pid; GetWindowThreadProcessId(hwnd, out pid); return pid;
    }
}
'@

function Get-AppWindow([int] $ProcessId) {
	foreach ($window in [MemfsGuiNative]::Windows()) {
		if ([MemfsGuiNative]::OwnerProcess($window) -eq $ProcessId -and
			[MemfsGuiNative]::Text($window) -eq 'Memfs 配置') { return $window }
	}
	return [IntPtr]::Zero
}

function Get-Control([IntPtr] $Window, [int] $Id) {
	$control = [MemfsGuiNative]::GetDlgItem($Window, $Id)
	if ($control -eq [IntPtr]::Zero) { throw "GUI control $Id not found" }
	return $control
}

function Get-ControlText([IntPtr] $Window, [int] $Id) {
	$control = Get-Control $Window $Id
	$length = [int][MemfsGuiNative]::SendMessageW($control, 0x000E, [IntPtr]::Zero, [IntPtr]::Zero)
	$buffer = [Text.StringBuilder]::new([Math]::Max(2, $length + 1))
	[void][MemfsGuiNative]::SendBufferMessage($control, 0x000D, [IntPtr]$buffer.Capacity, $buffer)
	return $buffer.ToString()
}

function Set-Field([IntPtr] $Window, [int] $Id, [string] $Value) {
	if ([MemfsGuiNative]::SendTextMessage((Get-Control $Window $Id), 0x000C, [IntPtr]::Zero, $Value) -eq [IntPtr]::Zero) {
		throw "Could not set GUI field $Id"
	}
}

function Click-Control([IntPtr] $Window, [int] $Id) {
	$control = Get-Control $Window $Id
	if (-not [MemfsGuiNative]::PostMessageW($Window, 0x0111, [IntPtr]$Id, $control)) {
		throw "Could not post click for GUI control $Id"
	}
}

function Test-EnumDropdown([IntPtr] $Window, [int] $Id, [string] $Name, [int] $ChoiceIndex = 1) {
	$combo = Get-Control $Window $Id
	[void][MemfsGuiNative]::SendMessageW($combo, 0x014F, [IntPtr]1, [IntPtr]::Zero) # CB_SHOWDROPDOWN
	Start-Sleep -Milliseconds 100
	$info = [MemfsGuiNative+COMBOBOXINFO]::new()
	$info.cbSize = [Runtime.InteropServices.Marshal]::SizeOf([type][MemfsGuiNative+COMBOBOXINFO])
	if (-not [MemfsGuiNative]::GetComboBoxInfo($combo, [ref]$info) -or $info.hwndList -eq [IntPtr]::Zero) {
		throw "Could not inspect the open $Name dropdown"
	}
	$rect = [MemfsGuiNative+RECT]::new()
	if (-not [MemfsGuiNative]::GetWindowRect($info.hwndList, [ref]$rect)) { throw "Could not read the $Name dropdown bounds" }
	$height = $rect.bottom - $rect.top
	if ($height -lt 40) { throw "$Name dropdown is not visibly expanded (height=$height px)" }
	[void][MemfsGuiNative]::SendMessageW($combo, 0x014F, [IntPtr]0, [IntPtr]::Zero)
	$selected = [int][MemfsGuiNative]::SendMessageW($combo, 0x014E, [IntPtr]$ChoiceIndex, [IntPtr]::Zero) # CB_SETCURSEL
	$current = [int][MemfsGuiNative]::SendMessageW($combo, 0x0147, [IntPtr]::Zero, [IntPtr]::Zero) # CB_GETCURSEL
	if ($selected -ne $ChoiceIndex -or $current -ne $ChoiceIndex) { throw "$Name dropdown selection did not stick (set=$selected get=$current)" }
	Write-Host "$Name dropdown expanded to $height px and retained selection index $current."
}

function Answer-YesDialogs([int] $ProcessId) {
	foreach ($window in [MemfsGuiNative]::Windows()) {
		if ([MemfsGuiNative]::OwnerProcess($window) -ne $ProcessId -or
			[MemfsGuiNative]::Class($window) -ne '#32770') { continue }
		$yes = [MemfsGuiNative]::GetDlgItem($window, 6)
		if ($yes -ne [IntPtr]::Zero) {
			[void][MemfsGuiNative]::PostMessageW($window, 0x0111, [IntPtr]6, $yes)
		}
	}
}

function Wait-GuiStatus([System.Diagnostics.Process] $Process, [scriptblock] $Predicate, [int] $Seconds = 40, [switch] $WaitForMountStart, [switch] $WaitForActionStart) {
	$end = [DateTime]::UtcNow.AddSeconds($Seconds)
	$last = $null
	$started = -not ($WaitForMountStart -or $WaitForActionStart)
	do {
		Answer-YesDialogs $Process.Id
		$window = Get-AppWindow $Process.Id
		if ($window -ne [IntPtr]::Zero) {
			$status = [MemfsGuiNative]::Text((Get-Control $window 5000))
			if ($status -ne $last) { Write-Host "GUI status: $status"; $last = $status }
			if ($WaitForMountStart -and $status.Contains('挂载程序已报告挂载就绪')) { $started = $true }
			if ($WaitForMountStart -and $status.Contains('正在启动挂载')) { $started = $true }
			if ($WaitForActionStart -and ($status.Contains('操作正在运行') -or $status.Contains('已打开管理员窗口'))) { $started = $true }
			if (-not $started) { Start-Sleep -Milliseconds 40; continue }
			$matched = [bool](& $Predicate $status)
			if ($matched) { return $status }
			if ($status.Contains('退出代码：')) {
				$output = [MemfsGuiNative]::Text((Get-Control $window 5001))
				throw "GUI operation failed with '$status' (predicate=$matched); output: $output"
			}
		}
		Start-Sleep -Milliseconds 100
	} while ([DateTime]::UtcNow -lt $end)
	throw "Timed out waiting for GUI status; last status was '$status'"
}

function Wait-DriveState([bool] $Mounted, [int] $Seconds = 30) {
	$mask = [uint32](1 -shl ([byte][char]$driveLetter - [byte][char]'A'))
	$end = [DateTime]::UtcNow.AddSeconds($Seconds)
	do {
		$present = (([MemfsGuiNative]::GetLogicalDrives() -band $mask) -ne 0)
		if ($present -eq $Mounted) { return }
		Start-Sleep -Milliseconds 100
	} while ([DateTime]::UtcNow -lt $end)
	throw "Timed out waiting for $Drive mounted=$Mounted"
}

function Wait-ServiceRemoved([int] $Seconds = 30) {
	$end = [DateTime]::UtcNow.AddSeconds($Seconds)
	do {
		if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { return }
		Start-Sleep -Milliseconds 100
	} while ([DateTime]::UtcNow -lt $end)
	throw "Timed out waiting for service '$serviceName' removal"
}

function Start-Gui([string] $Arguments = '') {
	$proc = [Diagnostics.Process]::Start($Exe, $Arguments)
	if ($null -eq $proc) { throw 'Could not start the Memfs GUI' }
	$end = [DateTime]::UtcNow.AddSeconds(10)
	do {
		$window = Get-AppWindow $proc.Id
		if ($window -ne [IntPtr]::Zero) { return @{ Process = $proc; Window = $window } }
		Start-Sleep -Milliseconds 100
	} while ([DateTime]::UtcNow -lt $end)
	throw 'Memfs configuration window did not appear'
}

function Start-TempMount($Gui) {
	Set-Field $Gui.Window 1000 $Drive
	Set-Field $Gui.Window 1001 '64M'
	Set-Field $Gui.Window 1002 '界面 "测试" \'
	Set-Field $Gui.Window 1003 '0'
	[void][MemfsGuiNative]::SendMessageW((Get-Control $Gui.Window 1004), 0x00F1, [IntPtr]1, [IntPtr]::Zero)
	Set-Field $Gui.Window 1005 '3'
	$statsSelection = [int][MemfsGuiNative]::SendMessageW((Get-Control $Gui.Window 1009), 0x0147, [IntPtr]::Zero, [IntPtr]::Zero)
	if ($statsSelection -ne 2) { throw "JSON statistics selection changed before mount (index=$statsSelection)" }
	if ((Get-ControlText $Gui.Window 1002) -ne '界面 "测试" \') { throw "GUI label edit did not retain the requested value: '$(Get-ControlText $Gui.Window 1002)'" }
	Write-Output 'Starting temporary GUI mount.'
	Click-Control $Gui.Window 2000
	[void](Wait-GuiStatus $Gui.Process { param($s) $s.Contains('挂载就绪') } 40 -WaitForMountStart)
	Wait-DriveState $true
	$label = [Text.StringBuilder]::new(64)
	$fsName = [Text.StringBuilder]::new(32)
	[uint32]$serial = 0; [uint32]$maxComponent = 0; [uint32]$flags = 0
	if (-not [MemfsGuiNative]::GetVolumeInformationW("$Drive\", $label, $label.Capacity, [ref]$serial, [ref]$maxComponent, [ref]$flags, $fsName, $fsName.Capacity)) {
		throw "GetVolumeInformationW failed for $Drive (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
	}
	if ($label.ToString() -ne '界面 "测试" \') { throw "Volume label round-trip mismatch: '$($label.ToString())'" }
	$output = Get-ControlText $Gui.Window 5001
	if (-not $output.Contains('memfs_stats') -or -not $output.Contains('mounted')) {
		throw "JSON statistics were not captured after mount readiness: '$output'"
	}
	$path = "$Drive\memfs-gui-smoke.txt"
	[IO.File]::WriteAllText($path, 'GUI mount read/write')
	if ([IO.File]::ReadAllText($path) -ne 'GUI mount read/write') { throw 'Mounted file round-trip failed' }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	throw 'Run this UI integration test from an elevated session; it installs a uniquely named test service.'
}
if ($Drive -notmatch '^[A-Za-z]:$') { throw 'Use a drive-letter mount for this integration test.' }
if (([MemfsGuiNative]::GetLogicalDrives() -band [uint32](1 -shl ([byte][char]$driveLetter - [byte][char]'A'))) -ne 0) {
	throw "$Drive is already mounted; refusing to use it."
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
	throw "The test service '$serviceName' already exists; refusing to alter it."
}

$gui = $null
try {
	$gui = Start-Gui
	Test-EnumDropdown $gui.Window 1006 'Encryption'
	Test-EnumDropdown $gui.Window 1009 'Statistics' 2
	Start-TempMount $gui
	Click-Control $gui.Window 2001
	Write-Host 'Waiting for temporary unmount.'
	[void](Wait-GuiStatus $gui.Process { param($s) $s.Contains('退出代码：0') })
	Wait-DriveState $false

	# Exercise WM_CLOSE while this GUI owns a live mount. The dialog response is
	# posted asynchronously so the GUI message loop remains free to stop the child.
	Start-TempMount $gui
	[void][MemfsGuiNative]::PostMessageW($gui.Window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
	$end = [DateTime]::UtcNow.AddSeconds(45)
	do {
		Answer-YesDialogs $gui.Process.Id
		if ($gui.Process.WaitForExit(100)) { break }
	} while ([DateTime]::UtcNow -lt $end)
	if (-not $gui.Process.HasExited) { throw 'GUI did not close after graceful WM_CLOSE stop' }
	Wait-DriveState $false

	# Native service workflow uses its own unique name. Installation starts on W:.
	$gui = Start-Gui '--gui'
	Set-Field $gui.Window 1000 $Drive
	Set-Field $gui.Window 1001 '64M'
	Set-Field $gui.Window 1002 'Memfs GUI Service'
	Set-Field $gui.Window 1003 '0'
	Set-Field $gui.Window 1010 $serviceName
	Set-Field $gui.Window 1011 ''
	Click-Control $gui.Window 2002
	Write-Host 'Waiting for native service install.'
	[void](Wait-GuiStatus $gui.Process { param($s) $s.Contains('退出代码：0') } 90 -WaitForActionStart)
	$service = Get-Service -Name $serviceName
	if ($service.Status -ne 'Running') { throw "GUI install left service status $($service.Status)" }
	Wait-DriveState $true
	$path = "$Drive\memfs-gui-service.txt"
	[IO.File]::WriteAllText($path, 'GUI service read/write')
	if ([IO.File]::ReadAllText($path) -ne 'GUI service read/write') { throw 'Service mount round-trip failed' }

	# Uninstall must only require the selected service name; invalid unrelated
	# mount/capacity inputs prove those fields do not gate this action.
	Set-Field $gui.Window 1000 ''
	Set-Field $gui.Window 1001 'invalid-capacity'
	Click-Control $gui.Window 2003
	Write-Host 'Waiting for native service uninstall.'
	[void](Wait-GuiStatus $gui.Process { param($s) $s.Contains('退出代码：0') } 90 -WaitForActionStart)
	Wait-ServiceRemoved
	Wait-DriveState $false

	Write-Output 'PASS: temporary mount/unmount, WM_CLOSE-owned-child stop, GUI service install/start, file round-trip, and uninstall.'
}
finally {
	if ($gui -and -not $gui.Process.HasExited) {
		$window = Get-AppWindow $gui.Process.Id
		if ($window -ne [IntPtr]::Zero) {
			[void][MemfsGuiNative]::PostMessageW($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
			$end = [DateTime]::UtcNow.AddSeconds(30)
			do { Answer-YesDialogs $gui.Process.Id } while (-not $gui.Process.WaitForExit(100) -and [DateTime]::UtcNow -lt $end)
		}
	}
	if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
		$cleanup = Start-Process -FilePath $Exe -ArgumentList @('--uninstall', '--service-name', $serviceName) -WindowStyle Hidden -PassThru
		if (-not $cleanup.WaitForExit(120000) -or $cleanup.ExitCode -ne 0) {
			Write-Warning 'Could not automatically remove the GUI integration-test service.'
		}
	}
}
