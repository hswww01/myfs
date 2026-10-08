from __future__ import annotations

import os
import queue
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path


def to_wsl(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if len(drive) != 1:
        raise RuntimeError(f"test source must be on a mounted drive: {resolved}")
    return f"/mnt/{drive}{resolved.as_posix()[2:]}"


def wsl(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["wsl.exe", "-d", "Ubuntu", "--", *args],
        input=input_text,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"WSL command failed ({result.returncode}): {args!r}\n{result.stderr}")
    return result.stdout.strip()


class Helper:
    def __init__(self, script: Path, root: str, *, test_mode: bool = False):
        args = ["wsl.exe", "-d", "Ubuntu", "--", "python3", "-u", to_wsl(script), "--root", root]
        if test_mode:
            args.append("--test-mode")
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.reader = threading.Thread(target=self._read_lines, daemon=True)
        self.reader.start()

    def _read_lines(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.put(line.rstrip(b"\r\n").decode("ascii", errors="strict"))
        self.lines.put(None)

    def recv(self, timeout: float = 5) -> str:
        line = self.lines.get(timeout=timeout)
        if line is None:
            stderr = self.process.stderr.read().decode("utf-8", errors="replace") if self.process.stderr else ""
            raise RuntimeError(f"watch helper exited early ({self.process.poll()}): {stderr}")
        return line

    def send(self, line: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write((line + "\n").encode("ascii"))
        self.process.stdin.flush()

    def until_ack(self, request_id: int) -> list[str]:
        received = []
        expected = f"A {request_id} OK"
        while True:
            line = self.recv()
            received.append(line)
            if line == expected:
                return received
            if line.startswith("A ") and line.endswith(" UNSUPPORTED"):
                return received
            if line.startswith("X "):
                raise AssertionError(f"monitor became unhealthy: {line}; received={received!r}")

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.send("Q")
            except (BrokenPipeError, OSError):
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process.stdin:
            self.process.stdin.close()
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()


def encode_path(value: str) -> str:
    return value.encode("utf-8").hex()


def run_snapshot_regressions(helper_script_wsl: str) -> None:
    script = r'''
import contextlib, importlib.util, io, os, pathlib, stat, sys, tempfile, time
spec = importlib.util.spec_from_file_location("scpfs_watch_test", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
Snapshot = module.FileSnapshot
base = Snapshot(7, 11, stat.S_IFREG | 0o644, 1000, 1000, 23,
                100, 200, 300)
assert module.classify_access_snapshot(base, base) == 0
assert module.classify_access_snapshot(base, base._replace(atime_ns=101)) == 2
restore_b = base._replace(atime_ns=999, ctime_ns=301)
restore_a = base._replace(ctime_ns=302)
assert restore_b.atime_ns != base.atime_ns and restore_a.atime_ns == base.atime_ns
assert module.classify_access_snapshot(base, restore_a) == 2, "ctime must detect B->A atime restoration"
assert module.classify_access_snapshot(base, base._replace(size=24)) == 1
assert module.classify_access_snapshot(base, base._replace(mtime_ns=201)) == 1
assert module.classify_inotify_event(module.IN_ATTRIB, base, base) == 2
for changed in (base._replace(device=8), base._replace(inode=12),
                base._replace(mode=stat.S_IFDIR | 0o644)):
    try:
        module.classify_access_snapshot(base, changed)
    except module.WatchError:
        pass
    else:
        raise AssertionError("an identity/type change was not rejected")

root = pathlib.Path(tempfile.mkdtemp(prefix="scpfs-watch-wd-test-"))
primary = root / "file.txt"
alias = root / "alias.txt"
primary.write_bytes(b"fixture")
os.link(primary, alias)
watcher = None
try:
    watcher = module.Watcher(str(root))
    watcher.ensure("/file.txt", False)
    wd = watcher.path_wds[str(primary)]
    baseline = watcher.wd_samples[wd]
    changed_atime = max(time.time_ns() + 10**12, baseline.atime_ns + 10**12)
    os.utime(primary, ns=(changed_atime, baseline.mtime_ns))
    watcher.ensure("/alias.txt", False)
    assert watcher.path_wds[str(alias)] == wd, "hard-link aliases did not share one wd"
    assert watcher.wd_samples[wd] == baseline, "alias ensure reset the per-wd sample"
    events = io.StringIO()
    with contextlib.redirect_stdout(events):
        watcher.drain_events()
    assert "E 2\n" in events.getvalue(), "queued inode metadata change was swallowed by alias ensure"
    assert watcher.wd_samples[wd].atime_ns == changed_atime

    alias.unlink()
    remaining = watcher._verified_file_snapshot(wd)
    assert module._file_identity(remaining) == module._file_identity(watcher.wd_samples[wd]), (
        "remaining hard-link path was not accepted as a safe sample source"
    )
    events = io.StringIO()
    with contextlib.redirect_stdout(events):
        watcher.drain_events()
    assert "E 2\n" in events.getvalue() or "E 1\n" in events.getvalue(), (
        "removing a watched hard-link alias did not invalidate the relevant state"
    )
    assert watcher.wd_samples[wd] == watcher._verified_file_snapshot(wd)

    # A pure access still reaches the monitor after relatime is suppressed.
    # If every registered alias becomes unstatable, the event must fail closed.
    original_lstat = module.os.lstat
    def denied_lstat(path, *args, **kwargs):
        if os.fspath(path) in (str(primary), str(alias)):
            raise PermissionError("injected fixture lstat failure")
        return original_lstat(path, *args, **kwargs)
    try:
        with open(primary, "rb") as stream:
            stream.read(1)
        module.os.lstat = denied_lstat
        try:
            watcher.drain_events()
        except module.WatchError as error:
            assert str(error) == "watch-path-unavailable", str(error)
        else:
            raise AssertionError("ACCESS event with no statable alias did not fail closed")
    finally:
        module.os.lstat = original_lstat

    replacement = root / "replacement"
    replacement.write_bytes(b"other")
    os.replace(replacement, primary)
    try:
        watcher._verified_file_snapshot(wd)
    except module.WatchError:
        pass
    else:
        raise AssertionError("replaced inode path was accepted for a stale wd")
    try:
        watcher.ensure("/file.txt", False)
    except module.WatchError:
        pass
    else:
        raise AssertionError("W acknowledged a replacement inode for a stale wd")
    print("PASS: access snapshot classification, ctime B->A, hard-link sample ownership and stale identity rejection")
finally:
    if watcher is not None:
        os.close(watcher.fd)
    import shutil
    shutil.rmtree(root, ignore_errors=True)
'''
    output = wsl("python3", "-c", script, helper_script_wsl)
    assert output.endswith(
        "PASS: access snapshot classification, ctime B->A, hard-link sample ownership and stale identity rejection"
    ), output


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: watch_helper_test.py <server/scpfs_watch.py>")
    helper_script = Path(sys.argv[1]).resolve()
    script_wsl = to_wsl(helper_script)
    run_snapshot_regressions(script_wsl)
    root = f"/tmp/scpfs-watch-test-{uuid.uuid4().hex}"
    wsl("python3", "-c",
        "import os,pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(); "
        "(p/'file.txt').write_text('seed'); (p/'link.txt').symlink_to(p/'file.txt')",
        root)
    try:
        # Verify the exact stdin bootstrap used by the native SSH monitor. It
        # must consume source bytes, remove the source length from argv, and
        # leave only helper arguments for argparse.
        source = helper_script.read_bytes()
        bootstrap = (
            "import sys; n=int(sys.argv[1]); sys.argv=['scpfs_watch.py']+sys.argv[2:]; "
            "b=sys.stdin.buffer.read(n); exec(compile(b,'scpfs_watch.py','exec'))"
        )
        result = subprocess.run(
            ["wsl.exe", "-d", "Ubuntu", "--", "python3", "-u", "-c", bootstrap,
             str(len(source)), "--root", root],
            input=source,
            check=False,
            capture_output=True,
            timeout=10,
        )
        assert result.stdout.startswith(b"G SCPFS-WATCH 1\n"), (
            f"stdout={result.stdout!r} stderr={result.stderr!r} exit={result.returncode}"
        )
        assert result.returncode == 0, result.stderr

        helper = Helper(helper_script, root)
        assert helper.recv() == "G SCPFS-WATCH 1"
        helper.send(f"W 1 F {encode_path('/file.txt')}")
        assert helper.until_ack(1)[-1] == "A 1 OK"
        helper.send(f"W 2 D {encode_path('/')}")
        assert helper.until_ack(2)[-1] == "A 2 OK"

        # A file access is not necessarily an atime change. Put the timestamp
        # safely in the future (which suppresses relatime updates), drain the
        # timestamp mutation itself, then prove a normal read leaves atime
        # unchanged before asserting that it emits no metadata event.
        wsl("python3", "-c",
            "import os,sys,time; p=sys.argv[1]; st=os.stat(p); "
            "os.utime(p, ns=(time.time_ns()+86400*10**9, st.st_mtime_ns))",
            f"{root}/file.txt")
        helper.send("B 20")
        future_atime_events = helper.until_ack(20)
        assert any(line == "E 2" for line in future_atime_events), future_atime_events
        read_result = wsl("python3", "-c",
            "import os,sys; p=sys.argv[1]; before=os.stat(p).st_atime_ns; "
            "open(p,'rb').read(1); after=os.stat(p).st_atime_ns; "
            "print(before, after); assert before == after, "
            "f'atime changed during ordinary read: {before} -> {after}'",
            f"{root}/file.txt")
        assert read_result, "remote read did not report its atime verification"
        helper.send("B 21")
        ordinary_read_events = helper.until_ack(21)
        helper.close()
        assert not any(line == "E 2" for line in ordinary_read_events), (
            "ordinary file read emitted a metadata event although the test "
            f"confirmed atime stayed unchanged: {ordinary_read_events!r}"
        )

        helper = Helper(helper_script, root)
        assert helper.recv() == "G SCPFS-WATCH 1"
        helper.send(f"W 22 F {encode_path('/file.txt')}")
        assert helper.until_ack(22)[-1] == "A 22 OK"
        helper.send(f"W 23 D {encode_path('/')}")
        assert helper.until_ack(23)[-1] == "A 23 OK"

        wsl("python3", "-c",
            "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text('changed')",
            f"{root}/file.txt")
        helper.send("B 3")
        events = helper.until_ack(3)
        assert any(line == "E 1" for line in events), events

        wsl("chmod", "600", f"{root}/file.txt")
        helper.send("B 4")
        events = helper.until_ack(4)
        assert any(line == "E 2" for line in events), events

        # Restore an access timestamp without opening the file for writing.
        # This must invalidate metadata, not discard all reusable payloads.
        wsl("touch", "-c", "-a", "-d", "@101", f"{root}/file.txt")
        helper.send("B 40")
        events = helper.until_ack(40)
        assert "E 2" in events and "E 1" not in events, events

        wsl("ln", f"{root}/file.txt", f"{root}/old-hardlink.txt")
        helper.send("B 5")
        hardlink_events = helper.until_ack(5)
        assert any(line == "E 1" for line in hardlink_events), hardlink_events
        wsl("python3", "-c",
            "import os,pathlib,sys; p=pathlib.Path(sys.argv[1]); q=p.with_suffix('.new'); "
            "q.write_text('replacement'); os.replace(q,p)",
            f"{root}/file.txt")
        rename_events = []
        try:
            helper.send(f"W 6 F {encode_path('/file.txt')}")
        except OSError:
            # The replacement event may already have failed the monitor closed.
            pass
        while True:
            try:
                event = helper.recv(timeout=1)
            except queue.Empty:
                if helper.process.poll() is not None:
                    break
                continue
            except RuntimeError as error:
                rename_events.append(f"EXIT {error}")
                break
            rename_events.append(event)
            if event.startswith("X "):
                break
        assert not any(event == "A 6 OK" for event in rename_events), rename_events
        assert any(event.startswith("X ") or event.startswith("EXIT ")
                   for event in rename_events), rename_events
        helper.close()

        helper = Helper(helper_script, root)
        assert helper.recv() == "G SCPFS-WATCH 1"
        helper.send(f"W 7 F {encode_path('/file.txt')}")
        assert helper.until_ack(7)[-1] == "A 7 OK"
        wsl("mkdir", f"{root}/aliases")
        wsl("ln", f"{root}/file.txt", f"{root}/aliases/hardlink.txt")
        wsl("python3", "-c",
            "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text()+'external')",
            f"{root}/aliases/hardlink.txt")
        helper.send("B 8")
        events = helper.until_ack(8)
        assert any(line == "E 1" for line in events), events
        wsl("python3", "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('new')",
            f"{root}/fresh.txt")
        helper.send("B 9")
        events = helper.until_ack(9)
        assert any(line == "E 1" for line in events), events
        wsl("mv", f"{root}/fresh.txt", f"{root}/final.txt")
        helper.send("B 10")
        events = helper.until_ack(10)
        assert any(line == "E 1" for line in events), events
        wsl("rm", f"{root}/final.txt")
        helper.send("B 11")
        events = helper.until_ack(11)
        assert any(line == "E 1" for line in events), events
        helper.send(f"W 12 F {encode_path('/link.txt')}")
        response = helper.until_ack(12)
        assert response[-1] == "A 12 UNSUPPORTED", response
        helper.close()

        malformed = Helper(helper_script, root)
        assert malformed.recv() == "G SCPFS-WATCH 1"
        malformed.send("not-a-frame")
        assert malformed.recv().startswith("X invalid-frame"), "malformed frame was accepted"
        malformed.process.wait(timeout=5)
        malformed.close()

        overflow = Helper(helper_script, root, test_mode=True)
        assert overflow.recv() == "G SCPFS-WATCH 1"
        overflow.send("T OVERFLOW")
        assert overflow.recv() == "X overflow", "test overflow did not fail closed"
        overflow.process.wait(timeout=5)
        overflow.close()

        unsupported = Helper(helper_script, "/proc")
        assert unsupported.recv().startswith("X unsupported-filesystem"), "unsupported filesystem was watched"
        unsupported.process.wait(timeout=5)
        unsupported.close()
    finally:
        wsl("python3", "-c", "import shutil,sys; shutil.rmtree(sys.argv[1], ignore_errors=True)", root)
    print("PASS: embedded bootstrap, unchanged-atime access suppression, acknowledged coverage, metadata/content masks, rename/delete, unsupported path, malformed frame and overflow fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
