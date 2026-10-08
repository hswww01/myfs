from __future__ import annotations

import argparse
import ctypes
import getpass
import json
import os
import shutil
import subprocess
import time
from ctypes import wintypes
from pathlib import Path

from wsl_sshd_fixture import WslSshdFixture


DRIVE_NO_ROOT_DIR = 1
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
BM_CLICK = 0x00F5
GUI_TITLE = "SCPFS 远程文件系统"
IDYES = 6
user32 = ctypes.WinDLL("user32", use_last_error=True)
enum_windows_callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows.restype = wintypes.BOOL
user32.EnumWindows.argtypes = [enum_windows_callback, wintypes.LPARAM]
user32.EnumChildWindows.restype = wintypes.BOOL
user32.EnumChildWindows.argtypes = [wintypes.HWND, enum_windows_callback, wintypes.LPARAM]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowEnabled.restype = wintypes.BOOL
user32.IsWindowEnabled.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextW.restype = ctypes.c_int
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetDlgItem.restype = wintypes.HWND
user32.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
user32.SendMessageW.restype = ctypes.c_ssize_t
user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.FindWindowW.restype = wintypes.HWND
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]


def wait_for_mount_child_command_line(parent_pid: int, expected_value: str,
                                      timeout: float = 15) -> str:
    deadline = time.monotonic() + timeout
    query = (
        f"Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {parent_pid} }} "
        "| Select-Object -ExpandProperty CommandLine"
    )
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query],
            check=False, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "--mount" in line and "--stop-event" in line:
                    normalized = line.replace('"', "")
                    if "--cache-max-mib" not in normalized or expected_value not in normalized:
                        raise AssertionError(
                            f"GUI mount child did not forward cache capacity {expected_value}: {line!r}"
                        )
                    return line
        time.sleep(0.2)
    raise TimeoutError("could not observe the GUI-owned mount child command line")


def drive_is_mounted(drive: str) -> bool:
    get_logical_drives = ctypes.windll.kernel32.GetLogicalDrives
    mask = get_logical_drives()
    bit = 1 << (ord(drive[0].upper()) - ord("A"))
    if not mask & bit:
        return False
    return ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") != DRIVE_NO_ROOT_DIR


def process_window(pid: int) -> int | None:
    found: list[int] = []
    enum_callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @enum_callback_type
    def callback(hwnd: int, _lparam: int) -> bool:
        window_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if window_pid.value == pid and user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            title = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, title, len(title))
            if title.value == GUI_TITLE:
                found.append(hwnd)
                return False
        return True

    user32.EnumWindows(callback, 0)
    return found[0] if found else None


def wait_for_window(process: subprocess.Popen, timeout: float = 10) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hwnd = process_window(process.pid)
        if hwnd is not None:
            return hwnd
        if process.poll() is not None:
            raise RuntimeError(f"SCPFS GUI exited early with status {process.returncode}")
        time.sleep(0.1)
    raise TimeoutError("SCPFS configuration window did not appear")


def verify_gui_modules(pid: int, executable: Path, evidence_dir: Path) -> None:
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-Process -Id {pid}).Modules | ForEach-Object {{ $_.FileName }}"],
        check=False, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cannot inspect GUI process modules: {result.stderr}")
    modules = [str(Path(line.strip()).resolve()).lower()
               for line in result.stdout.splitlines() if line.strip()]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = evidence_dir / "runtime-modules-gui.json"
    evidence.write_text(json.dumps(modules, indent=2) + "\n", encoding="utf-8")
    windows_root = os.environ.get("WINDIR", r"C:\Windows").lower().rstrip("\\") + "\\"
    exe_path = str(executable.resolve()).lower()
    outside = [path for path in modules
               if path != exe_path and not path.startswith(windows_root)]
    if outside:
        raise AssertionError(f"GUI loaded modules outside Windows/exe directory: {outside}")
    forbidden = ("winfsp", "libssh2", "libcrypto", "libssl", "zlib", "ossl-modules")
    found = [path for path in modules if any(part in path for part in forbidden)]
    found.extend(path for path in modules if os.path.basename(path).startswith(
        ("vcruntime", "msvcp")) and os.path.basename(path) != "msvcp_win.dll")
    if found:
        raise AssertionError(f"GUI loaded non-OS runtime modules: {found}")


def wait_for_drive(drive: str, expected: bool, process: subprocess.Popen,
                   timeout: float = 30, hwnd: int | None = None) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        actual = drive_is_mounted(drive)
        if actual == expected:
            return
        if process.poll() is not None:
            raise RuntimeError(f"SCPFS GUI exited while waiting for {drive} mount state")
        time.sleep(0.1)
    status = output = ""
    if hwnd is not None:
        for control_id, target in ((5000, "status"), (5001, "output")):
            control = user32.GetDlgItem(hwnd, control_id)
            length = user32.GetWindowTextLengthW(control) if control else 0
            buffer = ctypes.create_unicode_buffer(length + 1)
            if control:
                user32.GetWindowTextW(control, buffer, len(buffer))
            if target == "status":
                status = buffer.value
            else:
                output = buffer.value
    raise TimeoutError(f"drive {drive} did not reach mounted={expected}; status={status!r}; output={output!r}")


def control_text(hwnd: int, control_id: int) -> str:
    control = user32.GetDlgItem(hwnd, control_id)
    if not control:
        return ""
    length = user32.SendMessageW(control, WM_GETTEXTLENGTH, 0, 0)
    buffer = ctypes.create_unicode_buffer(length + 1)
    buffer_ptr = ctypes.cast(buffer, ctypes.c_void_p).value
    user32.SendMessageW(control, WM_GETTEXT, len(buffer), buffer_ptr)
    return buffer.value


def wait_for_probe(hwnd: int, process: subprocess.Popen, timeout: float = 45) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = control_text(hwnd, 5000)
        if status.startswith("操作已结束"):
            output = control_text(hwnd, 5001)
            if "退出代码：0" not in status:
                raise RuntimeError(f"restored GUI probe failed: status={status!r}; output={output!r}")
            if "strict host-key verification" not in output:
                raise AssertionError(f"GUI probe did not report the SCP round trip: {output!r}")
            return output
        if process.poll() is not None:
            raise RuntimeError(f"SCPFS GUI exited during restored probe with {process.returncode}")
        time.sleep(0.1)
    raise TimeoutError(f"restored GUI probe did not finish; status={control_text(hwnd, 5000)!r}")


def wait_for_action_completion(hwnd: int, process: subprocess.Popen,
                               action_name: str, timeout: float = 30) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = control_text(hwnd, 5000)
        if status.startswith("操作已结束"):
            output = control_text(hwnd, 5001)
            if "退出代码：0" not in status:
                raise RuntimeError(
                    f"{action_name} child failed: status={status!r}; output={output!r}"
                )
            return output
        if process.poll() is not None:
            raise RuntimeError(
                f"GUI exited before {action_name} child completion was reported: "
                f"exit={process.returncode}; status={status!r}"
            )
        time.sleep(0.1)
    raise TimeoutError(
        f"{action_name} child did not finish within {timeout}s after mount state changed; "
        f"status={control_text(hwnd, 5000)!r}; output={control_text(hwnd, 5001)!r}"
    )


def child_by_caption(hwnd: int, caption: str) -> int | None:
    found: list[int] = []
    enum_callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    @enum_callback_type
    def callback(child: int, _lparam: int) -> bool:
        length = user32.GetWindowTextLengthW(child)
        text = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(child, text, len(text))
        if text.value == caption:
            found.append(child)
            return False
        return True

    user32.EnumChildWindows(hwnd, callback, 0)
    return found[0] if found else None


def click_action(hwnd: int, caption: str) -> None:
    button = child_by_caption(hwnd, caption)
    if button is None or not user32.IsWindowEnabled(button):
        raise AssertionError(f"GUI action is absent or disabled: {caption}")
    if not user32.PostMessageW(button, BM_CLICK, 0, 0):
        raise OSError(ctypes.get_last_error(), f"could not click GUI action: {caption}")


def confirm_temporary_unmount(hwnd: int, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    dialog = None
    while time.monotonic() < deadline:
        dialog = user32.FindWindowW("#32770", "确认停止挂载")
        if dialog:
            break
        time.sleep(0.05)
    if not dialog:
        raise AssertionError("temporary unmount did not request confirmation")
    user32.SendMessageW(dialog, WM_COMMAND, IDYES, 0)


def close_gui(process: subprocess.Popen) -> None:
    hwnd = process_window(process.pid)
    if hwnd is not None:
        user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()
    args.build_dir.mkdir(parents=True, exist_ok=True)

    drive = "X:"
    if drive_is_mounted(drive) or ctypes.windll.kernel32.GetDriveTypeW("X:\\") != DRIVE_NO_ROOT_DIR:
        print("SKIP: X: is already occupied; the GUI integration test will not touch it")
        return 77

    idle_gui = subprocess.Popen([str(args.exe)], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    try:
        idle_hwnd = wait_for_window(idle_gui)
        verify_gui_modules(idle_gui.pid, args.exe, args.build_dir)
        if drive_is_mounted(drive):
            raise AssertionError("opening the no-argument GUI unexpectedly mounted X:")
        user32.PostMessageW(idle_hwnd, WM_CLOSE, 0, 0)
        idle_gui.wait(timeout=10)
        if idle_gui.returncode != 0:
            raise AssertionError(f"closing the idle GUI returned {idle_gui.returncode}")
    finally:
        if idle_gui.poll() is None:
            close_gui(idle_gui)

    with WslSshdFixture(args.build_dir) as fixture:
        path_dir = fixture.run_dir / "GUI paths with spaces"
        path_dir.mkdir()
        identity = path_dir / "client identity ed25519"
        known_hosts = path_dir / "strict known hosts"
        shutil.copyfile(fixture.client_key, identity)
        shutil.copyfile(fixture.known_hosts, known_hosts)
        subprocess.run(
            ["icacls.exe", str(identity), "/inheritance:r", "/grant:r",
             f"{getpass.getuser()}:(R)"], check=True, capture_output=True, text=True,
        )
        cache_dir = str(path_dir / "cache directory") + "\\"
        Path(cache_dir).mkdir()
        values = {
            "host": "localhost",
            "user": "root",
            "port": str(fixture.port),
            "remote-root": fixture.remote_root,
            "mount-drive": drive,
            "identity": str(identity),
            "known-hosts": str(known_hosts),
            "timeout-ms": "15000",
            "command-timeout-ms": "60000",
            "cache-dir": cache_dir,
            "service-name": "Scpfs GUI Fixture",
            "log-file": str(path_dir / "service log.log"),
            # This is appended field index 12; the established first 12 control IDs stay stable.
            "cache-max-mib": "16",
        }
        action_args = [str(args.exe), "--gui", "--fsf-gui-action", "probe"]
        for field_id, value in values.items():
            action_args.extend(["--fsf-gui-field", field_id, value])
        gui = subprocess.Popen(action_args, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        try:
            hwnd = wait_for_window(gui)
            wait_for_probe(hwnd, gui)
            click_action(hwnd, "挂载")
            wait_for_drive(drive, True, gui, hwnd=hwnd)
            child_command_line = wait_for_mount_child_command_line(gui.pid, "16")
            if "--cache-max-mib 16" not in child_command_line.replace('"', ""):
                raise AssertionError(f"GUI did not forward the nondefault cache bound: {child_command_line!r}")
            click_action(hwnd, "卸载临时挂载")
            confirm_temporary_unmount(hwnd)
            wait_for_drive(drive, False, gui, hwnd=hwnd)
            wait_for_action_completion(hwnd, gui, "graceful GUI unmount")
            close_gui(gui)
            if gui.returncode not in (0, None):
                raise AssertionError(f"GUI mount child returned {gui.returncode}")
        finally:
            if drive_is_mounted(drive):
                hwnd = process_window(gui.pid)
                if hwnd is not None:
                    try:
                        click_action(hwnd, "卸载临时挂载")
                        confirm_temporary_unmount(hwnd)
                    except AssertionError:
                        pass
                deadline = time.monotonic() + 10
                while drive_is_mounted(drive) and time.monotonic() < deadline:
                    time.sleep(0.1)
            if gui.poll() is None:
                close_gui(gui)

    print("PASS: idle no-argument GUI, strict-key localhost mount with spaced paths, and GUI-owned graceful stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
