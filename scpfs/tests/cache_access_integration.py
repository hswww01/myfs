from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

from cache_integration import (
    cache_counters,
    choose_drive,
    stop_mount,
    wait_for_mount,
    wait_for_names,
    wait_for_watch_helper,
)
from wsl_sshd_fixture import WslSshdFixture


def admission_diagnostics(stderr: str) -> dict[str, int]:
    line = next((entry for entry in stderr.splitlines()
                 if entry.startswith("SCPFS cache admission diag: ")), None)
    if line is None:
        raise AssertionError(f"mount teardown did not emit cache admission diagnostics:\n{stderr}")
    result = {key: int(value, 0) for key, value in
              re.findall(r"([a-z_]+)=(0x[0-9a-fA-F]+|\d+)", line)}
    expected = {
        "cold_attempt", "cold_put_attempt", "cold_verify_metadata_changed",
        "cold_atime_mismatch", "warm_candidate", "warm_metadata_stale",
        "warm_metadata_changed", "provenance_mask",
    }
    if not expected.issubset(result):
        raise AssertionError(f"unexpected cache admission diagnostic schema: {line!r}")
    return result


def find_session_directory(temp_dir: Path, process: subprocess.Popen,
                           timeout: float = 15) -> Path:
    deadline = time.monotonic() + timeout
    root = temp_dir / "scpfs"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("scpfs exited before creating its cache session")
        sessions = list(root.glob("session-*")) if root.exists() else []
        if len(sessions) == 1 and sessions[0].is_dir():
            return sessions[0]
        time.sleep(0.05)
    raise TimeoutError("the mount did not create one cache session under the test TMP")


def wait_for_payload(session_dir: Path, expected: bytes, process: subprocess.Popen,
                     timeout: float = 20) -> Path:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("scpfs exited while waiting for cached payload bytes")
        for candidate in session_dir.glob("read-*.cache"):
            try:
                if candidate.read_bytes() == expected:
                    return candidate
            except OSError:
                pass
        time.sleep(0.05)
    raise TimeoutError("the expected immutable read payload was not retained in the session cache")


def remote_stat(fixture: WslSshdFixture, path: str) -> dict[str, int]:
    script = (
        "import json,os,sys\n"
        "s=os.stat(sys.argv[1],follow_symlinks=False)\n"
        "print(json.dumps({k:getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_atime_ns','st_mtime_ns','st_ctime_ns')}))\n"
    )
    return json.loads(fixture._wsl("python3", "-c", script, path))


def atime_stress_reader(remote_path: str, duration: float = 3.0) -> subprocess.Popen:
    script = (
        "import ctypes,json,os,struct,sys,time\n"
        "libc=ctypes.CDLL(None,use_errno=True); init=libc.inotify_init1; init.argtypes=[ctypes.c_int]; init.restype=ctypes.c_int\n"
        "add=libc.inotify_add_watch; add.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32]; add.restype=ctypes.c_int\n"
        "fd_watch=init(os.O_NONBLOCK|getattr(os,'O_CLOEXEC',0))\n"
        "if fd_watch<0: raise OSError(ctypes.get_errno(),'inotify_init1')\n"
        "wd=add(fd_watch,os.fsencode(sys.argv[1]),1)\n"
        "if wd<0: raise OSError(ctypes.get_errno(),'inotify_add_watch')\n"
        "fd=os.open(sys.argv[1], os.O_RDONLY)\n"
        "deadline=time.monotonic()+float(sys.argv[2]); count=0; accesses=0; header=struct.Struct('iIII')\n"
        "while time.monotonic()<deadline:\n"
        " os.lseek(fd,0,os.SEEK_SET); os.read(fd,65536); count+=1\n"
        " while True:\n"
        "  try: data=os.read(fd_watch,65536)\n"
        "  except BlockingIOError: break\n"
        "  offset=0\n"
        "  while offset+header.size<=len(data):\n"
        "   wd_event,mask,cookie,name_len=header.unpack_from(data,offset)\n"
        "   if wd_event==wd and mask&1: accesses+=1\n"
        "   offset+=header.size+name_len\n"
        " time.sleep(0.004)\n"
        "os.close(fd); os.close(fd_watch); print(json.dumps({'reads':count,'in_access':accesses}))\n"
    )
    return subprocess.Popen(
        ["wsl.exe", "-d", "Ubuntu", "--", "python3", "-c", script,
         remote_path, str(duration)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()
    drive = choose_drive()
    if drive is None:
        print("SKIP: no unused drive letter is available for cache access integration")
        return 77

    args.build_dir.mkdir(parents=True, exist_ok=True)
    process: subprocess.Popen | None = None
    reader: subprocess.Popen | None = None
    mounted = False
    completed = False
    stop_handle = None
    stdout_log = stderr_log = None
    performance: dict[str, object] = {}
    counters: dict[str, int] = {}
    diagnostics: dict[str, int] = {}
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.CreateEventW.argtypes = [
        wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    with WslSshdFixture(args.build_dir) as fixture:
        target_bytes = b"cache-access-target-" + secrets.token_bytes(1024)
        background_bytes = b"watched-access-no-atime-" + secrets.token_bytes(4096)
        changed_bytes = b"cache-access-content-v2-" + secrets.token_bytes(1024)
        target_remote = f"{fixture.remote_root}/cache-access-target.bin"
        background_remote = f"{fixture.remote_root}/watched-access.bin"
        target_name = Path(target_remote).name
        background_name = Path(background_remote).name
        create_files = (
            "import os,sys,time\n"
            "root=sys.argv[1]; names=('cache-access-target.bin','watched-access.bin')\n"
            "for name,encoded in zip(names,sys.argv[2:4]): open(os.path.join(root,name),'wb').write(bytes.fromhex(encoded))\n"
            "now=time.time_ns(); future=((now//1000000000)+86400)*1000000000\n"
            "for name in names: p=os.path.join(root,name); s=os.stat(p); os.utime(p,ns=(future,s.st_mtime_ns))\n"
        )
        fixture._wsl("python3", "-c", create_files, fixture.remote_root,
                     target_bytes.hex(), background_bytes.hex())
        initial_background_stat = remote_stat(fixture, background_remote)

        cli = fixture.cli(args.exe, identity=fixture.client_key)
        cli[1] = "--mount"
        cli.insert(2, drive)
        cli.extend(["--cache-max-mib", "0"])
        stop_event_name = f"Local\\scpfs-access-{secrets.token_hex(16)}"
        stop_handle = kernel32.CreateEventW(None, True, False, stop_event_name)
        if stop_handle in (None, wintypes.HANDLE(-1).value):
            raise OSError(ctypes.get_last_error(), "could not create cache access test stop event")
        cli.extend(["--stop-event", stop_event_name])

        temp_dir = args.build_dir / f"cache-access-tmp-{secrets.token_hex(8)}"
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
                raise RuntimeError(f"cache access mount failed on {drive}: {details}")
            mounted = True
            wait_for_names(root, {target_name, background_name}, set(), process)
            names = set(os.listdir(root))
            if not {target_name, background_name}.issubset(names):
                raise AssertionError(f"initial fixture names missing from mount: {names}")

            target = root / target_name
            background = root / background_name
            # A stat call establishes a file watch for B; the root listing also
            # leaves the containing directory covered before concurrent reads.
            if background.stat().st_size != len(background_bytes):
                raise AssertionError("watched background file has the wrong size")
            wait_for_watch_helper(fixture)
            first = target.read_bytes()
            if first != target_bytes:
                raise AssertionError("cold target read differed from its owned WSL fixture")
            session_dir = find_session_directory(temp_dir, process)
            target_payload = wait_for_payload(session_dir, target_bytes, process)
            performance["target_payload_retained_before_pressure"] = True

            reader = atime_stress_reader(background_remote)
            read_ms: list[float] = []
            reads_during_reader = 0
            for _ in range(20):
                if reader.poll() is not None:
                    break
                started = time.perf_counter()
                observed = target.read_bytes()
                read_ms.append((time.perf_counter() - started) * 1000.0)
                if observed != target_bytes:
                    raise AssertionError("target bytes changed during unrelated watched-file reads")
                if reader.poll() is None:
                    reads_during_reader += 1
                else:
                    break
                time.sleep(0.05)
            reader_out, reader_err = reader.communicate(timeout=8)
            if reader.returncode != 0:
                raise RuntimeError(f"owned WSL access reader failed: {reader_err}")
            try:
                reader_result = json.loads(reader_out)
                remote_read_count = int(reader_result["reads"])
                in_access_count = int(reader_result["in_access"])
            except (ValueError, KeyError, TypeError) as error:
                raise RuntimeError(f"owned WSL access reader returned invalid evidence: {reader_out!r}") from error
            after_background_stat = remote_stat(fixture, background_remote)
            if after_background_stat != initial_background_stat:
                raise AssertionError(
                    "the background read changed remote metadata despite its future atime: "
                    f"before={initial_background_stat}, after={after_background_stat}"
                )
            if remote_read_count < 100:
                raise AssertionError(f"background reader did not create enough reads: {remote_read_count}")
            if in_access_count < 50:
                raise AssertionError(
                    f"background pressure did not generate enough verified IN_ACCESS events: {reader_result}"
                )
            if reads_during_reader != 20:
                raise AssertionError(
                    f"target did not complete 20 warm reads during the 3-second background stress: "
                    f"completed={reads_during_reader}, times_ms={read_ms}"
                )
            if not target_payload.is_file() or target_payload.read_bytes() != target_bytes:
                raise AssertionError("the same read-GUID payload was not retained through background pressure")
            performance["background_remote_reads"] = remote_read_count
            performance["background_in_access_events"] = in_access_count
            performance["target_warm_read_ms"] = read_ms
            performance["target_payload_retained_after_pressure"] = True

            # Change B's atime explicitly. IN_ATTRIB must remain observable and
            # the mounted stat must refresh rather than serving stale metadata.
            set_atime = (
                "import json,os,sys,time\n"
                "p=sys.argv[1]; s=os.stat(p); target=((int(time.time())+172800)//1)*1000000000\n"
                "os.utime(p,ns=(target,s.st_mtime_ns)); s=os.stat(p)\n"
                "print(json.dumps({'atime_ns':s.st_atime_ns,'atime_s':int(s.st_atime)}))\n"
            )
            changed_atime = json.loads(fixture._wsl("python3", "-c", set_atime, background_remote))
            deadline = time.monotonic() + 12
            refreshed_atime = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("scpfs exited while waiting for refreshed atime metadata")
                current = background.stat()
                if int(current.st_atime) == changed_atime["atime_s"]:
                    refreshed_atime = int(current.st_atime)
                    break
                time.sleep(0.1)
            if refreshed_atime != changed_atime["atime_s"]:
                raise AssertionError("explicit remote atime change did not refresh mounted stat metadata")

            # A real content notification must still invalidate the cached bytes.
            fixture._wsl(
                "python3", "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))",
                target_remote, changed_bytes.hex(),
            )
            deadline = time.monotonic() + 15
            observed_new_content = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("scpfs exited while waiting for content invalidation")
                try:
                    observed_new_content = target.read_bytes()
                    if observed_new_content == changed_bytes:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            if observed_new_content != changed_bytes:
                raise AssertionError("remote content change did not refresh the mounted payload")
            if process.poll() is not None:
                raise RuntimeError("scpfs exited before diagnostic counters could be collected")
            completed = True
        finally:
            if reader is not None and reader.poll() is None:
                try:
                    reader.communicate(timeout=8)
                except subprocess.TimeoutExpired:
                    reader.terminate()
                    reader.communicate(timeout=3)
            if process is not None and process.poll() is None:
                stdout_text, stderr_text = stop_mount(process, stop_handle, stdout_log, stderr_log)
            else:
                stdout_log.flush()
                stderr_log.flush()
                stdout_log.seek(0)
                stderr_log.seek(0)
                stdout_text, stderr_text = stdout_log.read(), stderr_log.read()
            if process is not None and process.returncode not in (0, None):
                raise RuntimeError(
                    f"cache access mount exited {process.returncode}\nstdout={stdout_text}\nstderr={stderr_text}"
                )
            (args.build_dir / f"cache-access-{drive[0]}-stdout.log").write_text(
                stdout_text, encoding="utf-8")
            (args.build_dir / f"cache-access-{drive[0]}-stderr.log").write_text(
                stderr_text, encoding="utf-8")
            stdout_log.close()
            stderr_log.close()
            if stop_handle is not None:
                kernel32.CloseHandle(stop_handle)
            if mounted:
                counters = cache_counters(stderr_text)
                diagnostics = admission_diagnostics(stderr_text)
                performance["cache_counters"] = counters
                performance["cache_admission_diagnostics"] = diagnostics
                (args.build_dir / "cache-access-results.json").write_text(
                    json.dumps(performance, indent=2) + "\n", encoding="utf-8")
                if completed:
                    if counters["payload_hit"] < 15:
                        raise AssertionError(f"target did not record enough warm payload hits: {counters}")
                    if diagnostics["warm_candidate"] < 20:
                        raise AssertionError(f"warm payload candidates were not observed: {diagnostics}")
                    if diagnostics["warm_metadata_stale"] > 2:
                        raise AssertionError(
                            "unrelated stable-atime B reads churned target metadata admission: "
                            f"{diagnostics}"
                        )
                    if diagnostics["warm_metadata_changed"] > 2:
                        raise AssertionError(
                            f"warm target validation raced metadata changes: {diagnostics}"
                        )

    print(
        f"PASS: {drive} kept a warm target payload during {performance.get('background_remote_reads')} "
        f"owned WSL reads; counters={counters}; admission={diagnostics}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
