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


def decode_event(line: str) -> tuple[str, str]:
    kind, _, payload = line.partition(" ")
    return kind, bytes.fromhex(payload).decode("utf-8", errors="surrogateescape")


def request(helper: Helper, line: str, request_id: int) -> tuple[list[str], list[str]]:
    """Send one request; return (events seen before the reply, reply lines)."""
    helper.send(line)
    events = []
    prefix = f"A {request_id} "
    while True:
        received = helper.recv()
        if received.startswith("X "):
            raise AssertionError(f"helper failed: {received}; events={events!r}")
        if received.startswith(prefix):
            reply = [received]
            fields = received.split(" ")
            if len(fields) == 4 and fields[2] == "L":
                reply += [helper.recv() for _ in range(int(fields[3]))]
            return events, reply
        events.append(received)


def barrier_events(helper: Helper, request_id: int) -> set[tuple[str, str]]:
    events, reply = request(helper, f"B {request_id}", request_id)
    assert reply == [f"A {request_id} OK"], reply
    return {decode_event(line) for line in events if line != "R"}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: watch_helper_test.py <server/scpfs_watch.py>")
    helper_script = Path(sys.argv[1]).resolve()
    root = f"/tmp/scpfs-watch-test-{uuid.uuid4().hex}"
    wsl("python3", "-c",
        "import os,pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(); "
        "(p/'file.txt').write_text('seed'); (p/'link.txt').symlink_to(p/'file.txt'); "
        "(p/'sub').mkdir(); (p/'sub'/'inner.txt').write_text('payload' + chr(10)); (p/'hidden').mkdir()",
        root)
    try:
        # The exact stdin bootstrap used by the native SSH monitor.
        source = helper_script.read_bytes()
        bootstrap = (
            "import sys; n=int(sys.argv[1]); sys.argv=['scpfs_watch.py']+sys.argv[2:]; "
            "b=sys.stdin.buffer.read(n); exec(compile(b,'scpfs_watch.py','exec'))"
        )
        result = subprocess.run(
            ["wsl.exe", "-d", "Ubuntu", "--", "python3", "-u", "-c", bootstrap,
             str(len(source)), "--root", root],
            input=source, check=False, capture_output=True, timeout=10,
        )
        assert result.stdout.startswith(
                b"G SCPFS-WATCH 2 " + root.encode().hex().encode() + b"\n"), (
            f"stdout={result.stdout!r} stderr={result.stderr!r} exit={result.returncode}"
        )
        assert result.returncode == 0, result.stderr

        helper = Helper(helper_script, root)
        assert helper.recv().startswith("G SCPFS-WATCH 2 ")
        _, reply = request(helper, f"S 1 {encode_path('/file.txt')}", 1)
        fields = reply[0].split(" ")
        assert fields[:3] == ["A", "1", "S"] and fields[3] == "f" and fields[5] == "4", reply
        _, reply = request(helper, f"S 2 {encode_path('/missing.txt')}", 2)
        assert reply == ["A 2 N"], reply
        _, reply = request(helper, f"S 3 {encode_path('/nope/child')}", 3)
        assert reply == ["A 3 E noent"], reply
        _, reply = request(helper, f"S 4 {encode_path('/link.txt')}", 4)
        assert reply[0].split(" ")[3] == "l", reply
        _, reply = request(helper, f"S 5 {encode_path('/file.txt/x')}", 5)
        assert reply == ["A 5 E notdir"], reply
        _, reply = request(helper, f"L 6 {encode_path('/')}", 6)
        names = {bytes.fromhex(line.split(" ")[0]).decode() for line in reply[1:]}
        assert names == {"file.txt", "link.txt", "sub", "hidden"}, reply
        _, reply = request(helper, f"L 7 {encode_path('/sub')}", 7)
        assert len(reply) == 2 and reply[0] == "A 7 L 1", reply
        helper.send(f"R 30 {encode_path('/sub/inner.txt')} 100")
        reply_line = helper.recv()
        assert reply_line.startswith("A 30 D 8 f "), reply_line
        assert helper.recv() == "payload", "raw content must follow the reply"
        _, reply = request(helper, f"R 31 {encode_path('/sub/inner.txt')} 0", 31)
        assert reply == ["A 31 U"], reply  # over the limit
        _, reply = request(helper, f"R 32 {encode_path('/link.txt')} 100", 32)
        assert reply == ["A 32 U"], reply  # never follows symlinks
        _, reply = request(helper, "F 8", 8)
        fields = reply[0].split(" ")
        assert fields[2] == "F" and int(fields[3]) >= int(fields[4]) > 0, reply

        # Content change of a listed file: the file itself is named.
        wsl("python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('changed')",
            f"{root}/file.txt")
        events = barrier_events(helper, 10)
        assert ("C", "/file.txt") in events, events
        # chmod is metadata only.
        wsl("chmod", "600", f"{root}/file.txt")
        events = barrier_events(helper, 11)
        assert ("M", "/file.txt") in events and ("C", "/file.txt") not in events, events
        # A plain read (atime unchanged or not) reports nothing.
        wsl("cat", f"{root}/file.txt")
        events = barrier_events(helper, 12)
        assert not events, events
        # Creation in a covered directory clears a cached "absent".
        wsl("touch", f"{root}/missing.txt")
        events = barrier_events(helper, 13)
        assert ("C", "/missing.txt") in events, events
        # Changes in a directory never stat'ed or listed are not reported.
        wsl("touch", f"{root}/hidden/unseen.txt")
        events = barrier_events(helper, 14)
        assert ("C", "/hidden/unseen.txt") not in events, events
        # Changes inside a listed subdirectory name the child.
        wsl("python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('yy')",
            f"{root}/sub/inner.txt")
        events = barrier_events(helper, 15)
        assert ("C", "/sub/inner.txt") in events, events
        # Moving a covered directory loses its subtree; the helper keeps running.
        wsl("mv", f"{root}/sub", f"{root}/moved")
        events = barrier_events(helper, 16)
        assert ("T", "/sub") in events, events
        wsl("touch", f"{root}/moved/inner.txt")
        events = barrier_events(helper, 17)
        assert not any(path.startswith("/sub/") for _, path in events), events
        _, reply = request(helper, f"S 18 {encode_path('/sub/inner.txt')}", 18)
        assert reply == ["A 18 E noent"], reply
        # Hard links: a change through an unwatched alias is still reported.
        wsl("ln", f"{root}/file.txt", f"{root}/hidden/alias.txt")
        barrier_events(helper, 19)
        _, reply = request(helper, f"S 20 {encode_path('/file.txt')}", 20)
        assert reply[0].split(" ")[2] == "S", reply
        wsl("python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('via alias')",
            f"{root}/hidden/alias.txt")
        events = barrier_events(helper, 21)
        assert ("C", "/file.txt") in events, events
        # Deleting a watched file does not take the helper down.
        wsl("rm", f"{root}/file.txt")
        events = barrier_events(helper, 22)
        assert ("C", "/file.txt") in events, events
        _, reply = request(helper, f"S 23 {encode_path('/file.txt')}", 23)
        assert reply == ["A 23 N"], reply

        # Mutations: write (new, replace, conflict), setmeta, mkdir, rename, remove.
        def put(request_id: int, path: str, data: bytes, expect: str) -> list[str]:
            assert helper.process.stdin is not None
            helper.process.stdin.write(
                f"P {request_id} {encode_path(path)} {len(data)} {expect} "
                f"1600000000000000000 1600000001000000000\n".encode() + data)
            helper.process.stdin.flush()
            return request(helper, f"B {request_id + 1000}", request_id + 1000)[0]

        events = put(40, "/made.txt", b"new content", "-")
        reply = next(line for line in events if line.startswith("A 40 "))
        fields = reply.split(" ")
        assert fields[2] == "S" and fields[3] == "f" and fields[5] == "11", reply
        assert fields[7] == "1600000001000000000", reply
        made = wsl("python3", "-c", "import os,sys; s=os.stat(sys.argv[1]); "
                   "print(open(sys.argv[1]).read(), oct(s.st_mode & 0o777))", f"{root}/made.txt")
        assert made.startswith("new content"), made
        events = put(41, "/made.txt", b"again", "-")
        assert any(line == "A 41 E exists" for line in events), events
        dev, ino = fields[8], fields[9]
        mode_octal = fields[4]
        expect = f"{dev}:{ino}:11:1600000001000000000:{int(mode_octal, 8)}"
        events = put(42, "/made.txt", b"replaced!", expect)
        reply = next(line for line in events if line.startswith("A 42 "))
        assert reply.split(" ")[2] == "S" and reply.split(" ")[5] == "9", reply
        events = put(43, "/made.txt", b"stale", expect)  # inode/size changed since
        assert any(line == "A 43 E conflict" for line in events), events
        assert wsl("cat", f"{root}/made.txt") == "replaced!"
        _, reply = request(helper, f"M 44 {encode_path('/made.txt')} 5 600 0 1500000000000000000", 44)
        fields = reply[0].split(" ")
        assert fields[2] == "S" and fields[4] == "600" and fields[7] == "1500000000000000000", reply
        _, reply = request(helper, f"K 45 {encode_path('/newdir')} 750", 45)
        assert reply[0].split(" ")[3:5] == ["d", "750"], reply
        _, reply = request(helper, f"K 46 {encode_path('/newdir')} 750", 46)
        assert reply == ["A 46 E exists"], reply
        _, reply = request(helper, f"N 47 {encode_path('/made.txt')} {encode_path('/newdir/moved.txt')} 0", 47)
        assert reply == ["A 47 OK"], reply
        wsl("touch", f"{root}/blocker.txt")
        _, reply = request(helper, f"N 48 {encode_path('/newdir/moved.txt')} {encode_path('/blocker.txt')} 0", 48)
        assert reply == ["A 48 E exists"], reply
        _, reply = request(helper, f"N 49 {encode_path('/newdir/moved.txt')} {encode_path('/blocker.txt')} 1", 49)
        assert reply == ["A 49 OK"], reply
        assert wsl("cat", f"{root}/blocker.txt") == "replaced!"
        _, reply = request(helper, f"X 50 {encode_path('/newdir')} F", 50)
        assert reply == ["A 50 E isdir"], reply
        wsl("touch", f"{root}/newdir/keep")
        _, reply = request(helper, f"X 51 {encode_path('/newdir')} D", 51)
        assert reply == ["A 51 E notempty"], reply
        wsl("rm", f"{root}/newdir/keep")
        _, reply = request(helper, f"X 52 {encode_path('/newdir')} D", 52)
        assert reply == ["A 52 OK"], reply
        _, reply = request(helper, f"X 53 {encode_path('/link.txt')} F", 53)
        assert reply == ["A 53 E reparse"], reply
        helper.close()

        malformed = Helper(helper_script, root)
        assert malformed.recv().startswith("G SCPFS-WATCH 2 ")
        malformed.send("not-a-frame")
        assert malformed.recv().startswith("X invalid-frame"), "malformed frame was accepted"
        malformed.process.wait(timeout=5)
        malformed.close()

        overflow = Helper(helper_script, root, test_mode=True)
        assert overflow.recv().startswith("G SCPFS-WATCH 2 ")
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
    print("PASS: bootstrap, stat/list/statfs replies, negative and error answers, "
          "per-path content/metadata/subtree events, hard links, delete survival, "
          "malformed frame, overflow and unsupported filesystem")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
