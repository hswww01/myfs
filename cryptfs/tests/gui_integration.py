"""Exercise the real native form and password pipe with temporary test credentials."""
import argparse
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

U = ctypes.WinDLL('user32', use_last_error=True)
G = ctypes.WinDLL('gdi32', use_last_error=True)
# Match screenshot pixel coordinates to window geometry on scaled displays.
try:
    U.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    U.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except AttributeError:
    U.SetProcessDPIAware()
CB = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
U.EnumWindows.argtypes = [CB, W.LPARAM]
U.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
U.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, ctypes.c_int]
U.GetDlgItem.argtypes = [W.HWND, ctypes.c_int]
U.GetDlgItem.restype = W.HWND
U.SendMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
U.SendMessageW.restype = ctypes.c_ssize_t
U.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
U.GetWindowLongW.argtypes = [W.HWND, ctypes.c_int]
U.GetWindowLongW.restype = W.LONG
U.GetWindowRect.argtypes = [W.HWND, ctypes.POINTER(W.RECT)]
U.GetDC.argtypes = [W.HWND]
U.GetDC.restype = W.HDC
U.ReleaseDC.argtypes = [W.HWND, W.HDC]
U.PrintWindow.argtypes = [W.HWND, W.HDC, W.UINT]
G.CreateCompatibleDC.argtypes = [W.HDC]
G.CreateCompatibleDC.restype = W.HDC
G.CreateCompatibleBitmap.argtypes = [W.HDC, ctypes.c_int, ctypes.c_int]
G.CreateCompatibleBitmap.restype = W.HANDLE
G.SelectObject.argtypes = [W.HDC, W.HANDLE]
G.SelectObject.restype = W.HANDLE
G.DeleteObject.argtypes = [W.HANDLE]
G.DeleteDC.argtypes = [W.HDC]


class BitmapInfoHeader(ctypes.Structure):
    _fields_ = [('size', W.DWORD), ('width', W.LONG), ('height', W.LONG),
                ('planes', W.WORD), ('bit_count', W.WORD), ('compression', W.DWORD),
                ('image_size', W.DWORD), ('x_pixels', W.LONG), ('y_pixels', W.LONG),
                ('colors_used', W.DWORD), ('colors_important', W.DWORD)]


G.GetDIBits.argtypes = [W.HDC, W.HANDLE, W.UINT, W.UINT, ctypes.c_void_p,
                       ctypes.POINTER(BitmapInfoHeader), W.UINT]


def capture_window(hwnd, destination):
    """Render this process's form, unaffected by overlapping desktop windows."""
    from PIL import Image
    rect = W.RECT()
    assert U.GetWindowRect(hwnd, ctypes.byref(rect)), 'Cannot get form dimensions'
    width, height = rect.right - rect.left, rect.bottom - rect.top
    source = U.GetDC(hwnd)
    assert source, 'Cannot get form device context'
    memory = bitmap = old = None
    try:
        memory = G.CreateCompatibleDC(source)
        assert memory, 'Cannot create capture device context'
        bitmap = G.CreateCompatibleBitmap(source, width, height)
        assert bitmap, 'Cannot create capture bitmap'
        old = G.SelectObject(memory, bitmap)
        assert old, 'Cannot select capture bitmap'
        assert U.PrintWindow(hwnd, memory, 2), 'Cannot render configuration form'
        G.SelectObject(memory, old)
        old = None
        header = BitmapInfoHeader()
        header.size = ctypes.sizeof(header)
        header.width, header.height = width, -height
        header.planes, header.bit_count = 1, 32
        pixels = ctypes.create_string_buffer(width * height * 4)
        assert G.GetDIBits(memory, bitmap, 0, height, pixels,
                          ctypes.byref(header), 0) == height, 'Cannot read form bitmap'
        Image.frombytes('RGB', (width, height), pixels.raw, 'raw', 'BGRX').save(destination)
    finally:
        if old:
            G.SelectObject(memory, old)
        if bitmap:
            G.DeleteObject(bitmap)
        if memory:
            G.DeleteDC(memory)
        U.ReleaseDC(hwnd, source)


def wait_for(predicate, timeout, error):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(.1)
    raise AssertionError(error)


def window(pid):
    found = []
    @CB
    def visit(hwnd, unused):
        owner = W.DWORD()
        U.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        title = ctypes.create_unicode_buffer(256)
        U.GetWindowTextW(hwnd, title, 256)
        if owner.value == pid and title.value == 'CryptFS 加密文件系统':
            found.append(hwnd)
            return False
        return True
    U.EnumWindows(visit, 0)
    return found[0] if found else None


def accept_stop_confirmation(pid):
    found = []
    @CB
    def visit(hwnd, unused):
        owner = W.DWORD()
        U.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        title = ctypes.create_unicode_buffer(256)
        U.GetWindowTextW(hwnd, title, 256)
        if owner.value == pid and title.value == '确认停止挂载':
            found.append(hwnd)
            return False
        return True
    U.EnumWindows(visit, 0)
    if found:
        U.PostMessageW(found[0], 0x0111, 6, U.GetDlgItem(found[0], 6))
        return True
    return False


def get_text(hwnd):
    text = ctypes.create_unicode_buffer(8192)
    U.SendMessageW(hwnd, 0x000D, len(text), ctypes.cast(text, ctypes.c_void_p).value)
    return text.value


def set_text(hwnd, text):
    buffer = ctypes.create_unicode_buffer(text)
    U.SendMessageW(hwnd, 0x000C, 0, ctypes.cast(buffer, ctypes.c_void_p).value)


def processes(parent):
    query = (f'Get-CimInstance Win32_Process | Where-Object {{ $_.ParentProcessId -eq {parent} }} '
             '| Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress')
    result = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                             '-Command', query], capture_output=True, timeout=20)
    assert result.returncode == 0, 'Cannot inspect GUI child command line'
    text = result.stdout.decode('utf-8', errors='replace').strip()
    if not text:
        return []
    value = json.loads(text)
    return value if isinstance(value, list) else [value]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--exe', required=True, type=Path)
    p.add_argument('--drive', default='X:')
    p.add_argument('--work', type=Path, default=Path(r'D:\work\fs\cryptfs\build\gui-integration'))
    args = p.parse_args()
    root = Path(args.drive + '\\')
    assert not root.exists(), 'Refuse to use an occupied drive'
    run = args.work / uuid.uuid4().hex
    run.mkdir(parents=True)
    container = run / 'gui.cfs'
    secret = 'GUI-temporary-test-密码-' + uuid.uuid4().hex
    gui = subprocess.Popen([str(args.exe.resolve())])
    hwnd = None
    child_pid = None
    try:
        hwnd = wait_for(lambda: window(gui.pid), 15, 'Configuration window did not appear')
        password = U.GetDlgItem(hwnd, 1005)
        assert U.GetWindowLongW(password, -16) & 0x20, 'Password edit lacks ES_PASSWORD'
        assert U.SendMessageW(password, 0x00D2, 0, 0), 'Password mask character missing'
        set_text(U.GetDlgItem(hwnd, 1000), str(container))
        set_text(U.GetDlgItem(hwnd, 1001), args.drive)
        U.SendMessageW(U.GetDlgItem(hwnd, 1002), 0x00F1, 1, 0)  # BM_SETCHECK
        set_text(password, secret)
        capture_window(hwnd, run / 'configuration.png')
        U.PostMessageW(hwnd, 0x0111, 2000, U.GetDlgItem(hwnd, 2000))
        wait_for(lambda: root.exists(), 30, 'GUI mount failed; inspect native output')
        children = processes(gui.pid)
        assert len(children) == 1, 'Expected one GUI mount process'
        child = children[0]
        child_pid = child['ProcessId']
        command = child['CommandLine']
        assert '--password-stdin' in command and '--stop-event' in command
        assert secret not in command, 'Password exposed in child command line'
        assert get_text(password) == '', 'Password field retained after mount'
        assert secret not in get_text(U.GetDlgItem(hwnd, 5001)), 'Password exposed in output'
        (root / 'gui-proof.txt').write_text('Native masked input and inherited pipe work.', encoding='utf-8')
        assert (root / 'gui-proof.txt').read_text(encoding='utf-8').startswith('Native masked input')
        modules = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
            '-Command', f'(Get-Process -Id {child_pid}).Modules | ForEach-Object {{ $_.FileName }}'],
            capture_output=True, timeout=20)
        assert modules.returncode == 0
        paths = modules.stdout.decode('utf-8', errors='replace').splitlines()
        exe_path = str(args.exe.resolve()).lower()
        windows = os.environ.get('WINDIR', r'C:\Windows').lower().rstrip('\\') + '\\'
        outside = [path for path in paths if path.lower() != exe_path and not path.lower().startswith(windows)]
        assert not outside, f'Non-system runtime modules: {outside}'
        forbidden = ('winfsp', 'libsodium', 'libzstd', 'zstd', 'vcruntime', 'libssh2', 'libcrypto')
        assert not any(Path(path).name.lower().startswith(forbidden) for path in paths), 'Third-party runtime DLL loaded'
        (run / 'runtime-modules.json').write_text(json.dumps(paths, indent=2), encoding='utf-8')
        U.PostMessageW(hwnd, 0x0111, 4000, U.GetDlgItem(hwnd, 4000))
        wait_for(lambda: accept_stop_confirmation(gui.pid), 5, 'Unmount confirmation did not appear')
        wait_for(lambda: not root.exists(), 30, 'GUI unmount failed')
        wait_for(lambda: not processes(gui.pid), 10, 'GUI mount child survived stop')
        child_pid = None
        U.PostMessageW(hwnd, 0x0010, 0, 0)
        gui.wait(timeout=10)
        assert gui.returncode == 0
        result = {'passed': True, 'masked_password': True, 'password_stdin_pipe': True,
                  'password_absent_from_argv': True, 'normal_unmount': True,
                  'system_runtime_modules_only': True, 'test_directory': str(run)}
        (run / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
    finally:
        if gui.poll() is None:
            if hwnd:
                U.PostMessageW(hwnd, 0x0111, 4000, U.GetDlgItem(hwnd, 4000))
                time.sleep(.5)
                accept_stop_confirmation(gui.pid)
                U.PostMessageW(hwnd, 0x0010, 0, 0)
            try:
                gui.wait(timeout=10)
            except subprocess.TimeoutExpired:
                gui.terminate()
                gui.wait(timeout=10)
        if child_pid and root.exists():
            # Last resort only for this newly launched test process, never a service.
            subprocess.run(['taskkill.exe', '/PID', str(child_pid), '/T', '/F'], capture_output=True)


if __name__ == '__main__':
    main()
