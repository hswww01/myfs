"""Exercise >1 GiB auto capacity on a private WinFsp mount.

Run one mode per process. No service configuration or driver installation is
changed by this script. The child uses memfs's existing named stop event; M: and
R: are always excluded. Free-space observations are diagnostic because memory
availability changes between OS queries; logical usage and file bytes are gates.
"""

import argparse
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import time
import uuid


MIB = 1024 * 1024
GIB = 1024 * MIB
CHUNK = MIB
MIN_AVAILABLE = 4 * GIB
STAGES = (512 * MIB, GIB, 1536 * MIB)
SKIP = 77


class SkipTest(Exception):
    pass


def timestamp():
    return datetime.datetime.now(
        datetime.timezone(datetime.timedelta(hours=8))).isoformat()


def progress(message):
    print(f"[{timestamp()}] {message}", flush=True)


class MemoryStatus(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD)] + [
        (name, ctypes.c_uint64) for name in (
            "ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile",
            "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual")]


class ProcessMemory(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
            "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]


class Native:
    def __init__(self):
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.GetLogicalDrives.restype = wintypes.DWORD
        self.k32.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR,
                                            wintypes.DWORD]
        self.k32.QueryDosDeviceW.restype = wintypes.DWORD
        self.k32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MemoryStatus)]
        self.k32.GlobalMemoryStatusEx.restype = wintypes.BOOL
        self.k32.GetDiskFreeSpaceExW.argtypes = [wintypes.LPCWSTR] + [
            ctypes.POINTER(ctypes.c_uint64)] * 3
        self.k32.GetDiskFreeSpaceExW.restype = wintypes.BOOL
        self.k32.GetVolumeInformationW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
        self.k32.GetVolumeInformationW.restype = wintypes.BOOL
        self.k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL,
                                        wintypes.BOOL, wintypes.LPCWSTR]
        self.k32.CreateEventW.restype = wintypes.HANDLE
        self.k32.SetEvent.argtypes = [wintypes.HANDLE]
        self.k32.SetEvent.restype = wintypes.BOOL
        self.k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k32.CloseHandle.restype = wintypes.BOOL
        self.k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k32.OpenProcess.restype = wintypes.HANDLE
        self.k32.K32GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(ProcessMemory), wintypes.DWORD]
        self.k32.K32GetProcessMemoryInfo.restype = wintypes.BOOL

    def memory(self):
        value = MemoryStatus()
        value.dwLength = ctypes.sizeof(value)
        if not self.k32.GlobalMemoryStatusEx(ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "timestamp": timestamp(), "memory_load_percent": value.dwMemoryLoad,
            "total_physical_bytes": value.ullTotalPhys,
            "available_physical_bytes": value.ullAvailPhys,
            "available_commit_bytes": value.ullAvailPageFile,
            "available_min_bytes": min(value.ullAvailPhys, value.ullAvailPageFile),
        }

    def device_exists(self, drive):
        target = ctypes.create_unicode_buffer(32768)
        if self.k32.QueryDosDeviceW(drive, target, len(target)):
            return True
        error = ctypes.get_last_error()
        if error != 2:  # ERROR_FILE_NOT_FOUND is the documented absent-device case.
            raise ctypes.WinError(error)
        mask = self.k32.GetLogicalDrives()
        if not mask:
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(mask & (1 << (ord(drive[0]) - ord("A"))))

    def select_drive(self, requested):
        candidates = [requested.upper()] if requested else [f"{c}:" for c in "VWSTUXYZ"]
        for drive in candidates:
            if not re.fullmatch(r"[A-Z]:", drive) or drive in ("M:", "R:"):
                raise ValueError("the test drive must be a free drive letter other than M: or R:")
            if not self.device_exists(drive):
                return drive
        raise SkipTest("no unused test drive is available")

    def volume_identity(self, root):
        label = ctypes.create_unicode_buffer(261)
        fs_name = ctypes.create_unicode_buffer(261)
        serial, component, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        if not self.k32.GetVolumeInformationW(
                root, label, len(label), ctypes.byref(serial), ctypes.byref(component),
                ctypes.byref(flags), fs_name, len(fs_name)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"label": label.value, "fs_name": fs_name.value,
                "serial": serial.value, "flags": flags.value}

    def process_memory(self, pid):
        handle = self.k32.OpenProcess(0x1000 | 0x0010, False, pid)
        if not handle:
            return {"unavailable_win32_error": ctypes.get_last_error()}
        try:
            counters = ProcessMemory()
            counters.cb = ctypes.sizeof(counters)
            if not self.k32.K32GetProcessMemoryInfo(
                    handle, ctypes.byref(counters), counters.cb):
                return {"unavailable_win32_error": ctypes.get_last_error()}
            return {"private_usage_bytes": counters.PrivateUsage,
                    "working_set_bytes": counters.WorkingSetSize,
                    "peak_working_set_bytes": counters.PeakWorkingSetSize}
        finally:
            self.k32.CloseHandle(handle)

    def snapshot(self, root, expected_used, pid, file_bytes=None):
        before = self.memory()
        available, total, free = ctypes.c_uint64(), ctypes.c_uint64(), ctypes.c_uint64()
        started = time.perf_counter()
        if not self.k32.GetDiskFreeSpaceExW(
                root, ctypes.byref(available), ctypes.byref(total), ctypes.byref(free)):
            raise ctypes.WinError(ctypes.get_last_error())
        elapsed = (time.perf_counter() - started) * 1000
        after = self.memory()
        used = total.value - free.value
        result = {
            "timestamp": timestamp(), "expected_logical_used_bytes": expected_used,
            "file_stat_bytes": file_bytes, "total_bytes": total.value,
            "free_bytes": free.value, "caller_available_bytes": available.value,
            "used_bytes": used, "used_error_bytes": used - expected_used,
            "volume_query_ms": elapsed, "memory_before": before, "memory_after": after,
            "process_memory": self.process_memory(pid),
            "free_space_assertion": "diagnostic only; OS memory is volatile",
        }
        if total.value < free.value or available.value > free.value:
            raise AssertionError(f"invalid total/free/available relation: {result}")
        if abs(used - expected_used) > 512:
            raise AssertionError(f"logical used-space mismatch: {result}")
        return result


def read_stats(path):
    result = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("type") == "memfs_stats":
            result.append(value)
    return result


def ensure_child_alive(child):
    code = child.poll()
    if code is not None:
        raise RuntimeError(f"owned memfs child exited unexpectedly: {code}")


def verify_file(path, expected_size, expected_hash):
    digest = hashlib.sha256()
    read_bytes = 0
    with path.open("rb", buffering=0) as stream:
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            read_bytes += len(chunk)
            if read_bytes > expected_size:
                raise AssertionError("readback returned bytes beyond the expected file size")
            if read_bytes % (256 * MIB) == 0:
                progress(f"完整读取已验证 {read_bytes // MIB} MiB")
    if read_bytes != expected_size or digest.hexdigest() != expected_hash:
        raise AssertionError(f"full readback mismatch: bytes={read_bytes}, expected={expected_size}")
    return {"verified_bytes": read_bytes, "sha256": digest.hexdigest()}


def run(args, result, artifact):
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise SkipTest("requires 64-bit Python on Windows")
    native = Native()
    exe = Path(args.exe).resolve(strict=True)
    result.update({"exe": str(exe), "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest().upper(),
                   "mode": args.mode, "reserve_argument": "1G", "chunk_bytes": CHUNK,
                   "stages_bytes": list(STAGES), "core_stats_scope": "mounted/stopping only"})
    result["preflight_memory"] = native.memory()
    if result["preflight_memory"]["available_min_bytes"] < MIN_AVAILABLE:
        raise SkipTest("requires at least 4 GiB available physical memory and commit")
    drive = native.select_drive(args.drive)
    root = drive + "\\"
    token = uuid.uuid4().hex
    label = "MEMCAP-" + token[:16]
    event_name = "Local\\MemfsAutoCapacity-" + token
    ctypes.set_last_error(0)
    event = native.k32.CreateEventW(None, True, False, event_name)
    if not event:
        raise ctypes.WinError(ctypes.get_last_error())
    if ctypes.get_last_error() == 183:
        native.k32.CloseHandle(event)
        raise RuntimeError("unique stop event unexpectedly already exists")
    result.update({"drive": drive, "stop_event": event_name, "volume_label": label,
                   "samples": [], "cleanup_errors": []})
    child = None
    stdout_path, stderr_path = artifact / "child.stdout.log", artifact / "child.stderr.log"
    try:
        command = [str(exe), "--mount", drive, "--size", "auto", "--reserve", "1G",
                   "--label", label, "--stop-event", event_name, "--stats-json"]
        if args.mode != "raw":
            command.append("--compress")
        result["command"] = command
        # Recheck immediately before launch; never replace an occupied drive.
        if native.device_exists(drive):
            raise SkipTest("selected drive became occupied before launch")
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            child = subprocess.Popen(command, cwd=str(exe.parent), stdout=stdout, stderr=stderr,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            result["child_pid"] = child.pid
            try:
                progress(f"启动独立挂载 {drive}，模式 {args.mode}，子进程 {child.pid}")
                deadline = time.monotonic() + 45
                while True:
                    ensure_child_alive(child)
                    try:
                        identity = native.volume_identity(root)
                    except OSError:
                        identity = None
                    if identity:
                        if identity["label"] != label or identity["fs_name"] != "MEMFS-C":
                            raise RuntimeError(f"test volume identity changed: {identity}")
                        result["volume_identity"] = identity
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("owned memfs child did not mount within 45 seconds")
                    time.sleep(0.1)
                time.sleep(1.2)  # WinFsp volume information inherits the 1-second metadata TTL.
                result["samples"].append(native.snapshot(root, 0, child.pid))
                probe = Path(root) / ("auto-capacity-" + token + ".bin")
                buffer = (b"A" * CHUNK if args.mode == "compressible" else
                          random.Random(0x4D454D4653).randbytes(CHUNK))
                expected_digest = hashlib.sha256()
                written = 0
                for target in STAGES:
                    ensure_child_alive(child)
                    progress(f"{drive} 写入至 {target // MIB} MiB")
                    started = time.perf_counter()
                    with probe.open("ab", buffering=0) as stream:
                        while written < target:
                            ensure_child_alive(child)
                            count = stream.write(buffer)
                            if count != CHUNK:
                                raise RuntimeError(f"short write: {count} of {CHUNK} bytes")
                            expected_digest.update(buffer)
                            written += count
                            if written % (64 * MIB) == 0:
                                progress(f"{drive} 已写入 {written // MIB} MiB")
                        os.fsync(stream.fileno())
                    write_ms = (time.perf_counter() - started) * 1000
                    file_size = probe.stat().st_size
                    if file_size != target:
                        raise AssertionError(f"file stat mismatch: {file_size} != {target}")
                    progress(f"{drive} 完整校验 {target // MIB} MiB，并等待容量信息刷新")
                    verified = verify_file(probe, target, expected_digest.hexdigest())
                    time.sleep(1.2)
                    ensure_child_alive(child)
                    sample = native.snapshot(root, target, child.pid, file_size)
                    sample.update({"write_ms": write_ms, "readback": verified})
                    result["samples"].append(sample)
                    progress(f"{drive} 已用 {sample['used_bytes']}，可用 {sample['free_bytes']} 字节")
                probe.unlink()
                time.sleep(1.2)
                ensure_child_alive(child)
                result["samples"].append(native.snapshot(root, 0, child.pid, 0))
                progress(f"{drive} 删除后已用量已恢复至 0")
            finally:
                if child.poll() is None:
                    progress(f"请求本测试子进程 {child.pid} 正常停止")
                    if not native.k32.SetEvent(event):
                        result["cleanup_errors"].append(
                            f"SetEvent failed: {ctypes.get_last_error()}")
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        result["cleanup_errors"].append(
                            f"owned child {child.pid} did not stop; no force termination was performed")
                result["child_exit_code"] = child.poll()
        result["core_stats"] = read_stats(stdout_path)
        if child.returncode != 0:
            raise RuntimeError(f"owned memfs child did not exit normally: {child.returncode}")
        phases = {value.get("phase"): value for value in result["core_stats"]}
        for phase in ("mounted", "stopping"):
            if phase not in phases:
                raise AssertionError(f"missing --stats-json phase: {phase}")
            if not phases[phase].get("capacity_auto") or phases[phase].get("logical_used_bytes") != 0:
                raise AssertionError(f"unexpected {phase} core stats: {phases[phase]}")
        deadline = time.monotonic() + 5
        while native.device_exists(drive) and time.monotonic() < deadline:
            time.sleep(0.1)
        result["drive_removed"] = not native.device_exists(drive)
        if not result["drive_removed"] or result["cleanup_errors"]:
            raise RuntimeError(f"owned mount cleanup failed: {result['cleanup_errors']}")
    finally:
        native.k32.CloseHandle(event)
        if stdout_path.exists():
            result["core_stats"] = read_stats(stdout_path)
        result["stdout_log"] = str(stdout_path)
        result["stderr_log"] = str(stderr_path)
        if child is not None:
            result["child_exit_code"] = child.poll()
            result["drive_present_at_end"] = native.device_exists(drive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, help="exact memfs.exe candidate")
    parser.add_argument("--mode", choices=("raw", "compressible", "compressed-random"), default="raw")
    parser.add_argument("--drive", help="unused drive, auto-select V/W/S/T/U/X/Y/Z by default")
    parser.add_argument("--artifact-dir", help="parent directory for a unique result subdirectory")
    args = parser.parse_args()
    parent = Path(args.artifact_dir) if args.artifact_dir else (
        Path(__file__).resolve().parents[1] / "build" / "auto-capacity-integration")
    parent = parent.resolve()
    if parent.drive.upper() in ("M:", "R:"):
        parser.error("artifacts must not be written to the live M: or R: volume")
    artifact = parent / (args.mode + "-" + uuid.uuid4().hex[:12])
    artifact.mkdir(parents=True, exist_ok=False)
    result = {"started_at": timestamp(), "status": "running", "artifact_dir": str(artifact)}
    code = 0
    try:
        run(args, result, artifact)
        result["status"] = "passed"
    except SkipTest as error:
        result.update({"status": "skipped", "reason": str(error)})
        code = SKIP
    except (Exception, KeyboardInterrupt) as error:
        result.update({"status": "failed", "error_type": type(error).__name__, "error": str(error)})
        code = 1
    finally:
        result["finished_at"] = timestamp()
        result["exit_code"] = code
        (artifact / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        progress(f"{result['status']}：{artifact / 'result.json'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
