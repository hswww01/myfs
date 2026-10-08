from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import secrets
import signal
import subprocess
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

from wsl_sshd_fixture import WslSshdFixture


DRIVE_NO_ROOT_DIR = 1
FILE_ATTRIBUTE_READONLY = 0x1


def choose_drive() -> str | None:
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
    # R: belongs to the independent SCPFS service fixture. Never consider the
    # production M: mount or its service-owned session in this test.
    for letter in "STUVWXYZQPON":
        bit = 1 << (ord(letter) - ord("A"))
        if not (mask & bit) and get_drive_type(f"{letter}:\\") == DRIVE_NO_ROOT_DIR:
            return f"{letter}:"
    return None


def wait_for_mount(root: str, process: subprocess.Popen, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if ctypes.windll.kernel32.GetDriveTypeW(root) != DRIVE_NO_ROOT_DIR:
            return True
        time.sleep(0.1)
    return False


def wait_for_bytes(path: Path, expected: bytes, process: subprocess.Popen,
                   timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    last_error: object = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"scpfs exited while waiting for fresh contents: {process.returncode}")
        try:
            if path.read_bytes() == expected:
                return
        except OSError as error:
            last_error = error
        time.sleep(0.1)
    raise TimeoutError(f"mounted file never showed {expected!r}; last error={last_error!r}")


def wait_for_names(root: Path, required: set[str], absent: set[str],
                   process: subprocess.Popen, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    last: set[str] = set()
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"scpfs exited while waiting for a fresh directory listing: {process.returncode}")
        try:
            last = set(os.listdir(root))
            if required.issubset(last) and not absent.intersection(last):
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"mounted directory did not converge: required={required}, absent={absent}, last={last}")


def watch_helper_pid(fixture: WslSshdFixture) -> int | None:
    script = (
        "import os,sys\n"
        "root=sys.argv[1]\n"
        "for name in os.listdir('/proc'):\n"
        " if not name.isdigit(): continue\n"
        " try: argv=open('/proc/'+name+'/cmdline','rb').read().split(b'\\0')\n"
        " except OSError: continue\n"
        " if not argv or not argv[0].endswith(b'python3'): continue\n"
        " if not any(b'scpfs_watch.py' in arg and b'compile' in arg and "
        "     b'sys.stdin.buffer.read(n)' in arg for arg in argv): continue\n"
        " if b'--root' not in argv: continue\n"
        " i=argv.index(b'--root')\n"
        " if i+1<len(argv) and argv[i+1].decode(errors='replace')==root: print(name); break\n"
    )
    output = fixture._wsl("python3", "-c", script, fixture.remote_root, check=False)
    return int(output) if output.isdigit() else None


def wait_for_watch_helper(fixture: WslSshdFixture, timeout: float = 20) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = watch_helper_pid(fixture)
        if current is not None:
            return current
        time.sleep(0.25)
    raise TimeoutError("could not find this mount's watch helper after bounded polling")


def wait_for_watch_reconnect(fixture: WslSshdFixture, old_pid: int,
                             timeout: float = 20) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = watch_helper_pid(fixture)
        if current is not None and current != old_pid:
            return current
        time.sleep(0.25)
    raise TimeoutError(f"watch helper did not reconnect after its owned process {old_pid} was terminated")


def wait_for_readonly(path: Path, expected: bool, process: subprocess.Popen,
                      timeout: float = 15) -> None:
    get_attributes = ctypes.windll.kernel32.GetFileAttributesW
    get_attributes.argtypes = [wintypes.LPCWSTR]
    get_attributes.restype = wintypes.DWORD
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("scpfs exited while waiting for an external mode change")
        attributes = get_attributes(str(path))
        if attributes != 0xFFFFFFFF and bool(attributes & FILE_ATTRIBUTE_READONLY) == expected:
            return
        time.sleep(0.1)
    raise TimeoutError(f"mounted readonly state did not become {expected}: {path}")


def stop_mount(process: subprocess.Popen, stop_handle: int,
               stdout_log, stderr_log) -> tuple[str, str]:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    kernel32.SetEvent.restype = wintypes.BOOL
    if process.poll() is None and not kernel32.SetEvent(stop_handle):
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError):
            process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise TimeoutError("cache test mount did not stop through its owned stop event")
    stdout_log.flush()
    stderr_log.flush()
    stdout_log.seek(0)
    stderr_log.seek(0)
    return stdout_log.read(), stderr_log.read()


def cache_counters(stderr: str) -> dict[str, int]:
    line = next((entry for entry in stderr.splitlines()
                 if entry.startswith("SCPFS cache stats: ")), None)
    if line is None:
        raise AssertionError(f"normal mount teardown did not emit cache counters:\n{stderr}")
    pairs = re.findall(r"([a-z_]+)=(\d+)", line)
    result = {key: int(value) for key, value in pairs}
    expected = {
        "stat_hit", "stat_miss", "list_hit", "list_miss", "payload_hit",
        "payload_miss", "evictions", "invalidations", "monitor_bypass",
    }
    if not expected.issubset(result):
        raise AssertionError(f"unexpected cache counter schema: {line!r}")
    return {key: result[key] for key in expected}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()
    drive = choose_drive()
    if drive is None:
        print("SKIP: no unused drive letter is available for cache integration")
        return 77

    args.build_dir.mkdir(parents=True, exist_ok=True)
    process: subprocess.Popen | None = None
    mounted = False
    completed = False
    stop_handle = None
    stdout_log = stderr_log = None
    performance: dict[str, object] = {}
    with WslSshdFixture(args.build_dir) as fixture:
        initial = b"cache-v1-" + secrets.token_bytes(32)
        changed = b"cache-v2-" + secrets.token_bytes(32)
        changed_again = b"cache-v3-" + secrets.token_bytes(32)
        fixture._wsl(
            "python3", "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))",
            f"{fixture.remote_root}/cache-item.bin", initial.hex(),
        )
        fixture._wsl("ln", f"{fixture.remote_root}/cache-item.bin",
                     f"{fixture.remote_root}/cache-hardlink.bin")
        fixture._wsl("touch", f"{fixture.remote_root}/cache-mode.bin")

        cli = fixture.cli(args.exe, identity=fixture.client_key)
        cli[1] = "--mount"
        cli.insert(2, drive)
        cli.extend(["--cache-max-mib", "0"])
        stop_event_name = f"Local\\scpfs-cache-{secrets.token_hex(16)}"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
        ]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        stop_handle = kernel32.CreateEventW(None, True, False, stop_event_name)
        if stop_handle in (None, wintypes.HANDLE(-1).value):
            raise OSError(ctypes.get_last_error(), "could not create cache test stop event")
        cli.extend(["--stop-event", stop_event_name])
        temp_dir = args.build_dir / f"tmp-{secrets.token_hex(8)}"
        temp_dir.mkdir()
        env = os.environ.copy()
        env["TMP"] = str(temp_dir)
        env["TEMP"] = str(temp_dir)
        stdout_log = tempfile.TemporaryFile(
            mode="w+t", encoding="utf-8", errors="replace", dir=args.build_dir)
        stderr_log = tempfile.TemporaryFile(
            mode="w+t", encoding="utf-8", errors="replace", dir=args.build_dir)
        process = subprocess.Popen(
            cli, stdout=stdout_log, stderr=stderr_log, env=env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        root = Path(drive + "\\")
        try:
            if not wait_for_mount(str(root), process):
                stdout_log.flush()
                stderr_log.flush()
                stdout_log.seek(0)
                stderr_log.seek(0)
                details = f"stdout={stdout_log.read()}\nstderr={stderr_log.read()}"
                if process.poll() is not None and "cannot mount" in details.lower():
                    print(f"SKIP: WinFsp mount unavailable: {details}")
                    return 77
                raise RuntimeError(f"cache integration mount failed on {drive}: {details}")
            mounted = True

            cached = root / "cache-item.bin"
            alias = root / "cache-hardlink.bin"
            mode_path = root / "cache-mode.bin"
            # Download each payload once. GNU atime restoration can emit ATTRIB;
            # make subsequent hit assertions after all cold downloads finish.
            names = set(os.listdir(root))
            if not {"cache-item.bin", "cache-hardlink.bin"}.issubset(names):
                raise AssertionError(f"initial remote names missing: {names}")
            cached.stat()
            first_read_start = time.perf_counter()
            first_read = cached.read_bytes()
            performance["first_payload_read_ms"] = (time.perf_counter() - first_read_start) * 1000.0
            if first_read != initial:
                raise AssertionError("initial payload differed from the WSL fixture")
            if alias.read_bytes() != initial:
                raise AssertionError("hardlink alias payload differed before mutation")
            for _ in range(4):
                names = set(os.listdir(root))
                if not {"cache-item.bin", "cache-hardlink.bin"}.issubset(names):
                    raise AssertionError(f"warm directory listing changed: {names}")
                cached.stat()
                if alias.read_bytes() != initial:
                    raise AssertionError("repeated cache hit changed hardlink contents")

            # An external ATTRIB event invalidates metadata while leaving file
            # content available for a separate provenance decision.
            fixture._wsl("chmod", "444", f"{fixture.remote_root}/cache-mode.bin")
            wait_for_readonly(mode_path, True, process)
            fixture._wsl("chmod", "644", f"{fixture.remote_root}/cache-mode.bin")
            wait_for_readonly(mode_path, False, process)

            original_helper = wait_for_watch_helper(fixture)

            # Kill only this mount's monitor helper. Change the watched file
            # during the outage, then require a fresh helper and fresh payload.
            fixture._wsl("kill", "-KILL", str(original_helper))
            fixture._wsl(
                "python3", "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))",
                f"{fixture.remote_root}/cache-item.bin", changed.hex(),
            )
            new_helper = wait_for_watch_reconnect(fixture, original_helper)
            wait_for_bytes(cached, changed, process)
            wait_for_bytes(alias, changed, process)
            if watch_helper_pid(fixture) != new_helper:
                raise AssertionError("monitor helper changed again unexpectedly during cache recovery check")

            # Prove a separate content event after the monitor recovered.
            fixture._wsl(
                "python3", "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))",
                f"{fixture.remote_root}/cache-item.bin", changed_again.hex(),
            )
            wait_for_bytes(cached, changed_again, process)
            wait_for_bytes(alias, changed_again, process)

            # Rename/create/delete are namespace events; listings must converge
            # without restarting the mount or relying on a fixed sleep.
            fixture._wsl("mv", f"{fixture.remote_root}/cache-item.bin",
                         f"{fixture.remote_root}/cache-renamed.bin")
            wait_for_names(root, {"cache-renamed.bin", "cache-hardlink.bin"},
                           {"cache-item.bin"}, process)
            fixture._wsl("python3", "-c",
                         "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(bytes.fromhex('637265617465640a'))",
                         f"{fixture.remote_root}/cache-created.txt")
            wait_for_names(root, {"cache-created.txt", "cache-renamed.bin"}, set(), process)
            fixture._wsl("rm", f"{fixture.remote_root}/cache-created.txt")
            wait_for_names(root, {"cache-renamed.bin"}, {"cache-created.txt"}, process)

            # Repeated reads after recovery prove that monitoring restored
            # cache eligibility and that own atime notifications preserve valid bytes.
            renamed = root / "cache-renamed.bin"
            repeated_read_ms = []
            for _ in range(4):
                read_start = time.perf_counter()
                repeated = alias.read_bytes()
                repeated_read_ms.append((time.perf_counter() - read_start) * 1000.0)
                if repeated != changed_again:
                    raise AssertionError("cached hardlink contents changed unexpectedly")
            for _ in range(3):
                os.listdir(root)
                renamed.stat()
            performance["repeated_payload_read_ms"] = repeated_read_ms
            if process.poll() is not None:
                raise RuntimeError("scpfs exited before cache counters could be collected")
            completed = True
        finally:
            if process.poll() is None:
                stdout_text, stderr_text = stop_mount(process, stop_handle, stdout_log, stderr_log)
            else:
                stdout_log.flush()
                stderr_log.flush()
                stdout_log.seek(0)
                stderr_log.seek(0)
                stdout_text, stderr_text = stdout_log.read(), stderr_log.read()
            if process.returncode not in (0, None):
                raise RuntimeError(
                    f"cache test mount exited {process.returncode}\nstdout:\n{stdout_text}\nstderr:\n{stderr_text}"
                )
            (args.build_dir / f"cache-{drive[0]}-stdout.log").write_text(stdout_text, encoding="utf-8")
            (args.build_dir / f"cache-{drive[0]}-stderr.log").write_text(stderr_text, encoding="utf-8")
            if stdout_log is not None:
                stdout_log.close()
            if stderr_log is not None:
                stderr_log.close()
            if stop_handle is not None:
                kernel32.CloseHandle(stop_handle)
            if mounted:
                try:
                    counters = cache_counters(stderr_text)
                    performance["cache_counters"] = counters
                    if completed:
                        for name in ("stat_hit", "list_hit", "payload_hit"):
                            if counters[name] <= 0:
                                raise AssertionError(f"cache did not record a warm {name}: {counters}")
                        if counters["payload_miss"] <= 0 or counters["invalidations"] <= 0:
                            raise AssertionError(f"cache did not show cold fetch and event invalidation: {counters}")
                except AssertionError:
                    if completed:
                        raise
            (args.build_dir / "cache-results.json").write_text(
                json.dumps(performance, indent=2) + "\n", encoding="utf-8")

    print(f"PASS: read cache warm hits, own-atime reuse, external hardlink/content and namespace invalidation on {drive}; counters={counters}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
