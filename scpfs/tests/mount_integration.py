from __future__ import annotations

import argparse
import ctypes
import json
import os
import secrets
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from ctypes import wintypes

from wsl_sshd_fixture import WslSshdFixture


DRIVE_NO_ROOT_DIR = 1


def remote_times(fixture: WslSshdFixture, path: str) -> tuple[int, int]:
    output = fixture._wsl(
        "python3", "-c",
        "import os,sys; s=os.stat(sys.argv[1], follow_symlinks=False); "
        "print(str(s.st_atime_ns)+' '+str(s.st_mtime_ns))",
        path,
    )
    atime_text, mtime_text = output.split()
    return int(atime_text), int(mtime_text)


def unix_ns_filetime(value_ns: int) -> wintypes.FILETIME:
    ticks = value_ns // 100 + 116_444_736_000_000_000
    return wintypes.FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)


def choose_drive() -> str | None:
    get_logical_drives = ctypes.windll.kernel32.GetLogicalDrives
    mask = get_logical_drives()
    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
    for letter in "RSTUVWXYZQPON":
        bit = 1 << (ord(letter) - ord("A"))
        root = f"{letter}:\\"
        if not mask & bit and get_drive_type(root) == DRIVE_NO_ROOT_DIR:
            return f"{letter}:"
    return None


def wait_for_mount(root: str, process: subprocess.Popen, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if ctypes.windll.kernel32.GetDriveTypeW(root) != DRIVE_NO_ROOT_DIR:
            return True
        time.sleep(0.1)
    return False


def verify_runtime_modules(pid: int, executable: Path, evidence_dir: Path) -> None:
    command = (
        f"(Get-Process -Id {pid}).Modules | ForEach-Object {{ $_.FileName }}"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        check=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cannot inspect mounted process modules: {result.stderr}")
    paths = [str(Path(line.strip()).resolve()).lower()
             for line in result.stdout.splitlines() if line.strip()]
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence = evidence_dir / f"runtime-modules-{executable.parent.name}.json"
    evidence.write_text(json.dumps(paths, indent=2) + "\n", encoding="utf-8")
    windows_root = os.environ.get("WINDIR", r"C:\Windows").lower().rstrip("\\") + "\\"
    exe_path = str(executable.resolve()).lower()
    outside = [path for path in paths
               if path != exe_path and not path.startswith(windows_root)]
    if outside:
        raise AssertionError(f"unexpected modules loaded outside Windows/exe directory: {outside}")
    forbidden = ("winfsp", "libssh2", "libcrypto", "libssl", "zlib", "ossl-modules")
    found = [path for path in paths if any(part in path for part in forbidden)]
    found.extend(path for path in paths if os.path.basename(path).startswith(
        ("vcruntime", "msvcp")) and os.path.basename(path) != "msvcp_win.dll")
    if found:
        raise AssertionError(f"unexpected non-OS runtime modules loaded: {found}")


def wait_for_path(path: str, process: subprocess.Popen, timeout: float = 25) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("scpfs exited while waiting for inbox output")
        if os.path.exists(path):
            return
        time.sleep(0.1)
    if process.poll() is None:
        stdout, stderr = stop_mount_for_diagnostics(process)
    else:
        stdout, stderr = read_mount_logs(process)
    raise TimeoutError(
        f"timed out waiting for {path}; mount stdout: {stdout}; mount stderr: {stderr}"
    )


def wait_for_file_content(path: str, expected: bytes, process: subprocess.Popen,
                          timeout: float = 25) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("scpfs exited while waiting for inbox output update")
        try:
            with open(path, "rb") as stream:
                content = stream.read()
            if expected in content:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {path} to contain {expected!r}")


def stop_mount_for_diagnostics(process: subprocess.Popen) -> tuple[str, str]:
    if process.poll() is None:
        try:
            stop_handle = getattr(process, "_scpfs_stop_event", None)
            if stop_handle is not None:
                ctypes.WinDLL("kernel32", use_last_error=True).SetEvent(stop_handle)
            else:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=15)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    return read_mount_logs(process)


def read_mount_logs(process: subprocess.Popen) -> tuple[str, str]:
    output = []
    for stream in process._scpfs_test_log_files:
        stream.flush()
        stream.seek(0)
        output.append(stream.read())
    return output[0], output[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--lifecycle-stress", action="store_true")
    args = parser.parse_args()

    drive = choose_drive()
    if drive is None:
        print("SKIP: no unused drive letter is available")
        return 77

    args.build_dir.mkdir(parents=True, exist_ok=True)
    process: subprocess.Popen | None = None
    stop_event_handle = None
    with WslSshdFixture(args.build_dir) as fixture:
        cli = fixture.cli(args.exe, identity=fixture.client_key)
        # Use an actual hostname so Windows name resolution is exercised while
        # the running process module inventory is captured below. The fixture
        # pins both this name and its numeric loopback address in known_hosts.
        host_index = cli.index("--host") + 1
        cli[host_index] = "localhost"
        cli[1] = "--mount"
        cli.insert(2, drive)
        cli.extend(["--command-timeout-ms", "1500"])
        stop_event_name = f"Local\\scpfs-test-{secrets.token_hex(16)}"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
        ]
        kernel32.SetEvent.restype = wintypes.BOOL
        kernel32.SetEvent.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        stop_event_handle = kernel32.CreateEventW(None, True, False, stop_event_name)
        assert stop_event_handle not in (None, wintypes.HANDLE(-1).value), (
            f"could not create child stop event: {ctypes.get_last_error()}"
        )
        cli.extend(["--stop-event", stop_event_name])
        temp_root = args.build_dir / f"tmp-{secrets.token_hex(8)}"
        temp_root.mkdir()
        test_env = os.environ.copy()
        test_env["TMP"] = str(temp_root)
        stdout_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
        stderr_log = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
        process = subprocess.Popen(
            cli,
            stdout=stdout_log,
            stderr=stderr_log,
            env=test_env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        process._scpfs_test_log_files = (stdout_log, stderr_log)
        process._scpfs_stop_event = stop_event_handle
        root = drive + "\\"
        try:
            if not wait_for_mount(root, process, 25):
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                stdout, stderr = read_mount_logs(process)
                message = f"mount failed before exposing {root}\nstdout: {stdout}\nstderr: {stderr}"
                if "cannot mount" in stderr.lower() or "device not ready" in stderr.lower():
                    print(f"SKIP: WinFsp mount unavailable: {message}")
                    return 77
                raise RuntimeError(message)

            verify_runtime_modules(process.pid, args.exe, args.build_dir)

            if args.lifecycle_stress:
                lifecycle_path = os.path.join(root, "scpfs-lifecycle-stress.bin")
                for iteration in range(100):
                    payload = f"lifecycle-{iteration}\n".encode("ascii")
                    with open(lifecycle_path, "wb") as stream:
                        stream.write(payload)
                    with open(lifecycle_path, "rb") as stream:
                        assert stream.read() == payload
                    os.remove(lifecycle_path)
                    assert not os.path.exists(lifecycle_path)
                    fixture._wsl("test", "!", "-e",
                                 f"{fixture.remote_root}/scpfs-lifecycle-stress.bin")
                print("PASS: 100 create/close/read-close/delete lifecycle iterations")
                return 0

            # Multiple explicit Flush calls must leave the inbox pending; the
            # final handle close is the trigger. Verify command cwd and the
            # combined stdout/stderr output with UTF-8 BOM and CRLF input.
            inbox = os.path.join(root, ".in.txt")
            inbox_output = os.path.join(root, ".out.txt")
            inbox_script = (
                "\ufeffpwd\r\n"
                "printf 'inbox-stdout\n'\r\n"
                "printf 'inbox-stderr\n' >&2\r\n"
                "printf 'cwd-ok' > inbox-cwd.marker\r\n"
                "exit 7\r\n"
            ).encode("utf-8")
            with open(inbox, "wb") as stream:
                stream.write(inbox_script)
                stream.flush()
                os.fsync(stream.fileno())
                stream.flush()
                fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/.out.txt")
            wait_for_path(inbox_output, process)
            inbox_output_text = open(inbox_output, "rb").read().decode("utf-8", errors="replace")
            assert "inbox-stdout" in inbox_output_text, inbox_output_text
            assert "inbox-stderr" in inbox_output_text, inbox_output_text
            assert fixture.remote_root in inbox_output_text, inbox_output_text
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/.in.txt")
            assert fixture._wsl("cat", f"{fixture.remote_root}/inbox-cwd.marker") == "cwd-ok"

            # Renaming a normal uploaded script into the exact inbox name also
            # triggers execution and atomically replaces the previous output.
            staged = os.path.join(root, "inbox-rename-stage")
            with open(staged, "wb") as stream:
                stream.write(b"printf rename-output\nprintf rename-trigger > inbox-rename.marker\n")
            try:
                os.replace(staged, inbox)
            except OSError as error:
                if process.poll() is None:
                    stdout, stderr = stop_mount_for_diagnostics(process)
                else:
                    stdout, stderr = read_mount_logs(process)
                raise RuntimeError(
                    f"rename into .in.txt failed: {error}; mount stdout: {stdout}; "
                    f"mount stderr: {stderr}"
                ) from error
            wait_for_file_content(inbox_output, b"rename-output", process)
            assert fixture._wsl("cat", f"{fixture.remote_root}/inbox-rename.marker") == "rename-trigger"
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/.in.txt")

            # A case variant stays an ordinary file and never runs as a command.
            wrong_case_inbox = os.path.join(root, ".IN.TXT")
            with open(wrong_case_inbox, "wb") as stream:
                stream.write(b"touch wrong-case-command-ran\n")
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/wrong-case-command-ran")
            assert os.path.exists(wrong_case_inbox)
            try:
                os.remove(wrong_case_inbox)
            except OSError as error:
                stdout, stderr = stop_mount_for_diagnostics(process)
                raise RuntimeError(
                    f"delete after close failed for .IN.TXT: {error}; "
                    f"mount stdout: {stdout}; mount stderr: {stderr}"
                ) from error
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/.IN.TXT")

            # The configured finite command timeout still publishes captured
            # output and consumes the input without waiting for a late effect.
            with open(inbox, "wb") as stream:
                stream.write(
                    b"printf timeout-start\nsleep 8\nprintf timeout-finished > timeout.marker\n"
                )
            wait_for_file_content(inbox_output, b"timeout-start", process)
            with open(inbox_output, "rb") as stream:
                assert b"timeout-finished" not in stream.read()
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/timeout.marker")
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/.in.txt")

            simple_path = os.path.join(root, "ascii-roundtrip.bin")
            with open(simple_path, "wb") as stream:
                stream.write(b"basic scpfs round trip\n")
            remote_simple = fixture._wsl(
                "stat", "--printf=%a %s", f"{fixture.remote_root}/ascii-roundtrip.bin"
            )
            assert remote_simple.endswith("23"), remote_simple
            try:
                with open(simple_path, "rb") as stream:
                    assert stream.read() == b"basic scpfs round trip\n"
            except OSError as error:
                acl = subprocess.run(
                    ["icacls.exe", simple_path], capture_output=True, text=True,
                    encoding="utf-8", errors="replace", check=False,
                )
                if process.poll() is None:
                    try:
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    except (OSError, ValueError):
                        process.terminate()
                if process.poll() is None:
                    stdout, stderr = stop_mount_for_diagnostics(process)
                else:
                    stdout, stderr = read_mount_logs(process)
                raise RuntimeError(
                    f"read-open of uploaded ASCII file failed: {error}; "
                    f"remote stat={remote_simple}; icacls={acl.stdout}{acl.stderr}; "
                    f"mount stdout={stdout}; mount stderr={stderr}"
                ) from error
            os.remove(simple_path)

            test_dir = os.path.join(root, "SCPFS integration space'$")
            os.mkdir(test_dir)
            source = os.path.join(test_dir, "unicode-雪 quote' dollar $.bin")
            renamed = os.path.join(test_dir, "renamed-雪 '$.bin")
            payload = bytes((i * 37 + 11) & 0xFF for i in range(4097))
            with open(source, "wb") as stream:
                stream.write(payload)
            with open(source, "rb") as stream:
                assert stream.read() == payload
                stream.seek(777)
                assert stream.read(311) == payload[777:1088]
            with open(source, "r+b") as stream:
                stream.truncate(1301)
            payload = payload[:1301]
            with open(source, "rb") as stream:
                assert stream.read() == payload
            os.replace(source, renamed)
            assert os.path.basename(renamed) in os.listdir(test_dir)
            with open(renamed, "rb") as stream:
                assert stream.read() == payload
            os.remove(renamed)
            os.rmdir(test_dir)

            # SCP transfers must preserve source timestamps to nanosecond precision;
            # explicit Windows file-time updates must reach the Linux file.
            timestamp_name = "timestamps.bin"
            timestamp_path = os.path.join(root, timestamp_name)
            seed_atime_ns = 1_700_000_000_123_456_789
            seed_mtime_ns = 1_700_000_001_987_654_321
            fixture._wsl(
                "python3", "-c",
                "import os,pathlib,sys; p=sys.argv[1]; "
                "pathlib.Path(p).write_bytes(b'timestamp seed\\n'); "
                "os.utime(p, ns=(int(sys.argv[2]),int(sys.argv[3])))",
                f"{fixture.remote_root}/{timestamp_name}",
                str(seed_atime_ns), str(seed_mtime_ns),
            )
            with open(timestamp_path, "rb") as stream:
                assert stream.read() == b"timestamp seed\n"
            post_write_times = remote_times(fixture, f"{fixture.remote_root}/{timestamp_name}")
            assert post_write_times == (seed_atime_ns, seed_mtime_ns), (
                f"timestamp preservation mismatch: expected {(seed_atime_ns, seed_mtime_ns)}, "
                f"got {post_write_times}"
            )
            with open(timestamp_path, "r+b") as stream:
                stream.seek(0)
                stream.write(b"modified timestamp seed\n")
            post_write_times = remote_times(fixture, f"{fixture.remote_root}/{timestamp_name}")
            assert post_write_times == (seed_atime_ns, seed_mtime_ns), (
                f"timestamp preservation after write mismatch: expected {(seed_atime_ns, seed_mtime_ns)}, "
                f"got {post_write_times}"
            )
            # Windows FILETIME has 100 ns precision; ask for representable values.
            # Repeat the immediate timestamp-read/delete sequence to catch stale
            # metadata-only handles without sleeps or retry-based synchronization.
            for timestamp_iteration in range(4):
                if timestamp_iteration != 0:
                    with open(timestamp_path, "wb") as stream:
                        stream.write(b"timestamp lifecycle regression\n")
                requested_atime_ns = 1_710_000_000_111_222_300 + timestamp_iteration * 100
                requested_mtime_ns = 1_710_000_002_444_555_600 + timestamp_iteration * 100
                os.utime(timestamp_path, ns=(requested_atime_ns, requested_mtime_ns))
                explicit_file_times = remote_times(
                    fixture, f"{fixture.remote_root}/{timestamp_name}"
                )
                assert explicit_file_times == (requested_atime_ns, requested_mtime_ns), (
                    f"explicit Windows file-time update mismatch on iteration "
                    f"{timestamp_iteration}: expected "
                    f"{(requested_atime_ns, requested_mtime_ns)}, got {explicit_file_times}"
                )
                os.remove(timestamp_path)
                fixture._wsl("test", "!", "-e",
                             f"{fixture.remote_root}/{timestamp_name}")

            # A held metadata-only handle must become stale after rename. Its
            # later SetFileTime and Close must not target a replacement file at
            # the old name.
            stale_source = os.path.join(root, "stale-metadata-source.bin")
            stale_renamed = os.path.join(root, "stale-metadata-renamed.bin")
            with open(stale_source, "wb") as stream:
                stream.write(b"original object\n")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
            ]
            kernel32.SetFileTime.restype = wintypes.BOOL
            kernel32.SetFileTime.argtypes = [
                wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
                ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
            ]
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            metadata_handle = kernel32.CreateFileW(
                stale_source, 0x0100, 0x0001 | 0x0002 | 0x0004,
                None, 3, 0x00000080, None,
            )
            invalid_handle = wintypes.HANDLE(-1).value
            assert metadata_handle not in (None, invalid_handle), (
                f"could not open FILE_WRITE_ATTRIBUTES handle: {ctypes.get_last_error()}"
            )
            try:
                os.rename(stale_source, stale_renamed)
                with open(stale_source, "wb") as stream:
                    stream.write(b"replacement object\n")
                baseline_ns = (1_720_000_000_000_000_000, 1_720_000_001_000_000_000)
                os.utime(stale_source, ns=baseline_ns)
                baseline_remote = remote_times(
                    fixture, f"{fixture.remote_root}/stale-metadata-source.bin"
                )
                assert baseline_remote == baseline_ns, (
                    f"replacement timestamp baseline mismatch: expected {baseline_ns}, "
                    f"got {baseline_remote}"
                )
                stale_atime = unix_ns_filetime(1_730_000_000_000_000_000)
                stale_mtime = unix_ns_filetime(1_730_000_001_000_000_000)
                set_time_succeeded = kernel32.SetFileTime(
                    metadata_handle, None, ctypes.byref(stale_atime),
                    ctypes.byref(stale_mtime),
                )
                stale_set_time_error = ctypes.get_last_error()
                assert not set_time_succeeded, (
                    "SetFileTime on a metadata handle whose file was renamed unexpectedly succeeded"
                )
            finally:
                assert kernel32.CloseHandle(metadata_handle), (
                    f"CloseHandle failed: {ctypes.get_last_error()}"
                )
            replacement_times = remote_times(
                fixture, f"{fixture.remote_root}/stale-metadata-source.bin"
            )
            assert replacement_times == baseline_ns, (
                f"stale metadata handle changed replacement timestamps after close; "
                f"SetFileTime error={stale_set_time_error}, expected {baseline_ns}, "
                f"got {replacement_times}"
            )
            os.remove(stale_source)
            os.remove(stale_renamed)

            # A remote symlink to a path outside the configured root must never be followed.
            fixture._wsl("ln", "-s", fixture.outside_sentinel,
                         f"{fixture.remote_root}/outside-link")
            try:
                with open(os.path.join(root, "outside-link"), "rb") as stream:
                    stream.read(1)
            except OSError:
                pass
            else:
                raise AssertionError("filesystem followed a remote symlink outside its root")

            # Reopen a clean file, make a local dirty edit, then race an external writer.
            # Flush must report the snapshot conflict, retain recovery data, and preserve
            # the external version on the server.
            conflict_name = "conflict-check.bin"
            conflict_local = os.path.join(root, conflict_name)
            original = b"before external change\n"
            external = "external writer version\n"
            with open(conflict_local, "wb") as stream:
                stream.write(original)
                stream.flush()
                os.fsync(stream.fileno())
            flush_failed = False
            try:
                with open(conflict_local, "r+b") as stream:
                    stream.seek(0)
                    stream.write(b"dirty cached version\n")
                    stream.flush()
                    fixture._wsl(
                        "python3", "-c",
                        "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(sys.argv[2].encode())",
                        f"{fixture.remote_root}/{conflict_name}", external,
                    )
                    try:
                        os.fsync(stream.fileno())
                    except OSError:
                        flush_failed = True
            except OSError:
                if not flush_failed:
                    raise
            if not flush_failed:
                raise AssertionError("Flush succeeded after the remote snapshot changed")
            remote_after_conflict = fixture._wsl(
                "cat", f"{fixture.remote_root}/{conflict_name}"
            )
            assert remote_after_conflict == external.rstrip("\n"), remote_after_conflict
            sessions = list((temp_root / "scpfs").glob("session-*"))
            assert len(sessions) == 1, f"expected one session cache, got {sessions!r}"
            manifest = sessions[0] / "recovery.manifest.txt"
            assert manifest.is_file(), "failed dirty flush did not write the recovery manifest"
            cache_files = list(sessions[0].glob("file-*.cache"))
            assert cache_files, "failed dirty flush did not preserve its cached file"

            # Linux names remain case-sensitive even through the WinFsp namespace.
            upper = os.path.join(root, "Test.txt")
            lower = os.path.join(root, "test.txt")
            upper_payload = b"upper-case object\n"
            lower_payload = b"lower-case object\n"
            for path, contents in ((upper, upper_payload), (lower, lower_payload)):
                with open(path, "wb") as stream:
                    stream.write(contents)
            visible = set(os.listdir(root))
            assert {"Test.txt", "test.txt"}.issubset(visible), visible
            with open(upper, "rb") as stream:
                assert stream.read() == upper_payload
            with open(lower, "rb") as stream:
                assert stream.read() == lower_payload
            try:
                open(os.path.join(root, "TEST.TXT"), "rb").close()
            except OSError:
                pass
            else:
                raise AssertionError("wrong-case lookup aliased an existing Linux file")

            case_renamed = os.path.join(root, "TEST.txt")
            os.replace(upper, case_renamed)
            visible = set(os.listdir(root))
            assert {"TEST.txt", "test.txt"}.issubset(visible), visible
            with open(case_renamed, "rb") as stream:
                assert stream.read() == upper_payload
            with open(lower, "rb") as stream:
                assert stream.read() == lower_payload
            os.remove(case_renamed)
            assert os.path.exists(lower), "deleting one case variant removed the other"
            with open(lower, "rb") as stream:
                assert stream.read() == lower_payload
            try:
                os.remove(lower)
            except OSError as error:
                stdout, stderr = stop_mount_for_diagnostics(process)
                raise RuntimeError(
                    f"delete after close failed for test.txt: {error}; "
                    f"mount stdout: {stdout}; mount stderr: {stderr}"
                ) from error

            upper_dir = os.path.join(root, "CaseDir")
            lower_dir = os.path.join(root, "casedir")
            os.mkdir(upper_dir)
            os.mkdir(lower_dir)
            assert {"CaseDir", "casedir"}.issubset(set(os.listdir(root)))
            os.rmdir(upper_dir)
            assert os.path.isdir(lower_dir), "deleting one case variant removed the other directory"
            os.rmdir(lower_dir)

            # A listing larger than one WinFsp query buffer is returned across
            # continuation pages; every name must appear exactly once.
            many_count = 1500
            many_remote = f"{fixture.remote_root}/many-entries"
            fixture._wsl(
                "python3", "-c",
                "import os,sys\n"
                "d=sys.argv[1]\n"
                "os.mkdir(d)\n"
                "for i in range(int(sys.argv[2])):\n"
                "    open(os.path.join(d, 'entry-%05d-%s.bin' % (i, 'x' * 40)), 'wb').close()\n",
                many_remote, str(many_count))
            expected_many = {f"entry-{index:05d}-{'x' * 40}.bin" for index in range(many_count)}
            listed_many = os.listdir(os.path.join(root, "many-entries"))
            assert len(listed_many) == many_count and set(listed_many) == expected_many, (
                f"multi-page listing returned {len(listed_many)} names, "
                f"{len(set(listed_many))} distinct, expected {many_count}"
            )
            fixture._wsl("rm", "-rf", "--", many_remote)
        finally:
            if process.poll() is None:
                try:
                    kernel32.SetEvent(stop_event_handle)
                except OSError:
                    try:
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                    except (OSError, ValueError):
                        process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        stdout, stderr = read_mount_logs(process)
        log_prefix = args.build_dir / f"mount-{temp_root.name}"
        log_prefix.with_suffix(".stdout.log").write_text(stdout or "", encoding="utf-8")
        log_prefix.with_suffix(".stderr.log").write_text(stderr or "", encoding="utf-8")
        stdout_log.close()
        stderr_log.close()
        if stop_event_handle is not None:
            kernel32.CloseHandle(stop_event_handle)
            stop_event_handle = None
        if process.returncode not in (0, None):
            raise RuntimeError(f"mounted scpfs did not exit cleanly: {process.returncode}\n{stdout}\n{stderr}")
    print("PASS: WinFsp CRUD/random read/truncate, case-sensitive files/directories, case-only rename, quoted Unicode paths, symlink denial, conflict preservation, and recovery manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
