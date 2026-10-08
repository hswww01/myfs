#!/usr/bin/env python3
"""Embedded, stdio-only inotify helper for SCPFS. Protocol v1."""

from __future__ import annotations

import argparse
import os
import select
import stat
import struct
import sys
from collections import deque
from typing import NamedTuple

IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_DONT_FOLLOW = 0x02000000
IN_MASK_ADD = 0x20000000

WATCH_MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM |
              IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF |
              IN_MOVE_SELF | IN_IGNORED)
CONTENT_MASK = (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
                IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)
MAX_LINE = 16384
MAX_WATCHES = 4096
ALLOWED_FILESYSTEMS = {"ext4", "xfs", "btrfs", "tmpfs", "overlay"}
EVENT_CONTENT = 1
EVENT_METADATA = 2


class FileSnapshot(NamedTuple):
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    atime_ns: int
    mtime_ns: int
    ctime_ns: int


class WatchError(Exception):
    pass


def _file_snapshot_from_stat(item: os.stat_result) -> FileSnapshot:
    return FileSnapshot(item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                        item.st_gid, item.st_size, item.st_atime_ns,
                        item.st_mtime_ns, item.st_ctime_ns)


def _file_identity(snapshot: FileSnapshot) -> tuple[int, int, int]:
    return (snapshot.device, snapshot.inode, stat.S_IFMT(snapshot.mode))


def classify_access_snapshot(previous: FileSnapshot,
                             current: FileSnapshot) -> int:
    """Classify a pure IN_ACCESS against the last verified inode sample."""
    if _file_identity(previous) != _file_identity(current):
        raise WatchError("watch-identity-changed")
    if previous.size != current.size or previous.mtime_ns != current.mtime_ns:
        return EVENT_CONTENT
    if previous != current:
        return EVENT_METADATA
    return 0


def classify_inotify_event(mask: int, previous: FileSnapshot | None,
                           current: FileSnapshot | None) -> int:
    """Return the protocol event mask, or zero for a harmless file access."""
    if mask & CONTENT_MASK:
        return EVENT_CONTENT
    if mask & IN_ATTRIB:
        return EVENT_METADATA
    if mask == IN_ACCESS:
        if previous is None or current is None:
            raise WatchError("watch-sample-unavailable")
        return classify_access_snapshot(previous, current)
    raise WatchError("unknown-watch-event")


class Watcher:
    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        root_stat = os.lstat(self.root)
        if not os.path.isdir(self.root) or os.path.islink(self.root):
            raise WatchError("invalid-root")
        self.root_dev = root_stat.st_dev
        if self._filesystem_type(self.root) not in ALLOWED_FILESYSTEMS:
            raise WatchError("unsupported-filesystem")
        self.fd = self._inotify_init()
        self.wd_paths: dict[int, str] = {}
        self.wd_path_aliases: dict[int, set[str]] = {}
        self.wd_samples: dict[int, FileSnapshot] = {}
        self.path_wds: dict[str, int] = {}
        self.path_identities: dict[str, tuple[int, int, int]] = {}

    @staticmethod
    def _inotify_init() -> int:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        init1 = getattr(libc, "inotify_init1", None)
        if init1 is None:
            raise WatchError("inotify-unavailable")
        init1.argtypes = [ctypes.c_int]
        init1.restype = ctypes.c_int
        fd = init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if fd < 0:
            raise WatchError("inotify-unavailable")
        return fd

    @staticmethod
    def _filesystem_type(path: str) -> str:
        # Select the most-specific mountpoint from mountinfo. Mount fields use
        # octal escapes for spaces, tabs, newlines, and backslashes.
        best_len = -1
        best_type = ""
        with open("/proc/self/mountinfo", "rt", encoding="utf-8", errors="surrogateescape") as stream:
            for line in stream:
                fields = line.rstrip("\n").split(" ")
                try:
                    separator = fields.index("-")
                    mountpoint = fields[4]
                    fs_type = fields[separator + 1]
                except (ValueError, IndexError):
                    continue
                for escaped, decoded in (("\\040", " "), ("\\011", "\t"),
                                         ("\\012", "\n"), ("\\134", "\\")):
                    mountpoint = mountpoint.replace(escaped, decoded)
                if (path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/")) and len(mountpoint) > best_len:
                    best_len = len(mountpoint)
                    best_type = fs_type
        return best_type

    def _virtual_to_absolute(self, virtual_path: str) -> str:
        if not virtual_path.startswith("/") or "\x00" in virtual_path:
            raise WatchError("invalid-path")
        components = [part for part in virtual_path.split("/") if part]
        if any(part in (".", "..") for part in components):
            raise WatchError("invalid-path")
        path = os.path.join(self.root, *components)
        if os.path.commonpath((self.root, os.path.abspath(path))) != self.root:
            raise WatchError("invalid-path")
        return path

    def _validate_path(self, path: str, directory: bool) -> list[str]:
        target = self._virtual_to_absolute(path)
        candidates = []
        cursor = target
        while True:
            candidates.append(cursor)
            if cursor == self.root:
                break
            parent = os.path.dirname(cursor)
            if parent == cursor or os.path.commonpath((self.root, parent)) != self.root:
                raise WatchError("outside-root")
            cursor = parent
        candidates.reverse()
        root_device = os.lstat(self.root).st_dev
        for candidate in candidates:
            item = os.lstat(candidate)
            if os.path.islink(candidate):
                raise WatchError("symlink")
            if item.st_dev != root_device:
                raise WatchError("cross-device")
            if candidate != target and not os.path.isdir(candidate):
                raise WatchError("ancestor-not-directory")
            if candidate != self.root and self._filesystem_type(candidate) not in ALLOWED_FILESYSTEMS:
                raise WatchError("unsupported-filesystem")
        if directory and not os.path.isdir(target):
            raise WatchError("not-directory")
        if not directory and not os.path.isfile(target):
            raise WatchError("not-regular-file")
        return candidates

    def ensure(self, virtual_path: str, directory: bool) -> None:
        paths = self._validate_path(virtual_path, directory)
        for path in paths:
            if path in self.path_identities:
                current = os.lstat(path)
                identity = (current.st_dev, current.st_ino, current.st_mode)
                if identity != self.path_identities[path]:
                    raise WatchError("watch-replaced")
        unique_new = [path for path in paths if path not in self.path_wds]
        if len(self.path_wds) + len(unique_new) > MAX_WATCHES:
            raise WatchError("watch-limit")
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        add_watch = libc.inotify_add_watch
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int
        for path in unique_new:
            before = os.lstat(path)
            before_snapshot = None
            if stat.S_ISREG(before.st_mode):
                before_snapshot = _file_snapshot_from_stat(before)
            flags = WATCH_MASK | IN_DONT_FOLLOW
            if os.path.isdir(path):
                flags |= IN_ONLYDIR
            else:
                # Linux reports atime-only updates as IN_ACCESS. Include it
                # for file inodes without making directory scans invalidate
                # their own cached listings.
                flags |= IN_ACCESS
            wd = add_watch(self.fd, os.fsencode(path), flags)
            if wd < 0:
                raise WatchError("watch-add-failed")
            after = os.lstat(path)
            if ((before.st_dev, before.st_ino, before.st_mode) !=
                    (after.st_dev, after.st_ino, after.st_mode)):
                raise WatchError("watch-replaced")
            if before_snapshot is not None:
                after_snapshot = _file_snapshot_from_stat(after)
                if before_snapshot != after_snapshot:
                    raise WatchError("watch-changed-during-add")
                existing_sample = self.wd_samples.get(wd)
                if existing_sample is None:
                    self.wd_samples[wd] = before_snapshot
                elif _file_identity(existing_sample) != _file_identity(after_snapshot):
                    raise WatchError("watch-identity-changed")
            elif wd in self.wd_samples:
                raise WatchError("watch-kind-changed")
            self.path_wds[path] = wd
            self.wd_paths[wd] = path
            self.wd_path_aliases.setdefault(wd, set()).add(path)
            self.path_identities[path] = (after.st_dev, after.st_ino, after.st_mode)

    def _verified_file_snapshot(self, wd: int) -> FileSnapshot:
        previous = self.wd_samples.get(wd)
        aliases = self.wd_path_aliases.get(wd)
        if previous is None or not aliases:
            raise WatchError("watch-sample-unavailable")
        matching = []
        for path in sorted(aliases):
            try:
                absolute = os.path.abspath(path)
                if os.path.commonpath((self.root, absolute)) != self.root:
                    continue
                relative = os.path.relpath(absolute, self.root)
                components = [part for part in relative.split(os.sep) if part]
                if not components or any(part in (".", "..") for part in components):
                    continue
                cursor = self.root
                item = None
                for index, component in enumerate(components):
                    cursor = os.path.join(cursor, component)
                    item = os.lstat(cursor)
                    if stat.S_ISLNK(item.st_mode) or item.st_dev != self.root_dev:
                        item = None
                        break
                    if index + 1 < len(components) and not stat.S_ISDIR(item.st_mode):
                        item = None
                        break
                if item is None:
                    continue
            except (OSError, ValueError):
                continue
            if not stat.S_ISREG(item.st_mode):
                continue
            snapshot = _file_snapshot_from_stat(item)
            if snapshot.device != self.root_dev:
                continue
            if _file_identity(snapshot) == _file_identity(previous):
                matching.append(snapshot)
        if not matching:
            raise WatchError("watch-path-unavailable")
        if any(snapshot != matching[0] for snapshot in matching[1:]):
            raise WatchError("watch-alias-ambiguous")
        return matching[0]

    def drain_events(self) -> None:
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            if not data:
                return
            offset = 0
            while offset < len(data):
                wd, mask, _cookie, name_len = struct.unpack_from("iIII", data, offset)
                offset += 16
                offset += name_len
                if mask & IN_Q_OVERFLOW:
                    raise WatchError("overflow")
                if mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF):
                    raise WatchError("watch-lost")
                if wd not in self.wd_paths:
                    raise WatchError("unknown-watch")
                current = None
                previous = self.wd_samples.get(wd)
                if previous is not None:
                    current = self._verified_file_snapshot(wd)
                event = classify_inotify_event(mask, previous, current)
                if current is not None:
                    # Refresh on all reported file events so a later pure access
                    # compares with the latest verified inode state. A second
                    # hard-link alias never replaces this per-watch baseline.
                    self.wd_samples[wd] = current
                if event:
                    emit_event(event)


def emit(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def emit_event(mask: int) -> None:
    emit(f"E {mask:x}")


def serve(root: str, test_mode: bool) -> int:
    watcher = Watcher(root)
    emit("G SCPFS-WATCH 1")
    input_fd = sys.stdin.fileno()
    input_buffer = bytearray()
    input_lines: deque[bytes] = deque()
    while True:
        readable, _, _ = select.select((input_fd, watcher.fd), (), ())
        if watcher.fd in readable:
            try:
                watcher.drain_events()
            except WatchError as error:
                emit(f"X {error}")
                return 2
        if input_fd in readable:
            chunk = os.read(input_fd, MAX_LINE + 1)
            if not chunk:
                if input_buffer:
                    emit("X truncated-frame")
                    return 2
                return 0
            input_buffer.extend(chunk)
            while True:
                newline = input_buffer.find(b"\n")
                if newline < 0:
                    break
                if newline > MAX_LINE:
                    emit("X frame-too-large")
                    return 2
                input_lines.append(bytes(input_buffer[:newline]))
                del input_buffer[:newline + 1]
            if len(input_buffer) > MAX_LINE:
                emit("X frame-too-large")
                return 2
        while input_lines:
            line = input_lines.popleft()
            try:
                text = line.decode("ascii", errors="strict")
                fields = text.split(" ")
                if fields == ["Q"]:
                    emit("A 0 OK")
                    return 0
                if len(fields) == 4 and fields[0] == "W":
                    request_id = parse_id(fields[1])
                    if fields[2] not in ("F", "D"):
                        raise WatchError("invalid-kind")
                    if len(fields[3]) > 8192 or len(fields[3]) % 2:
                        raise WatchError("invalid-path-encoding")
                    virtual_path = bytes.fromhex(fields[3]).decode("utf-8", errors="strict")
                    try:
                        watcher.ensure(virtual_path, fields[2] == "D")
                    except WatchError as error:
                        if str(error) in (
                            "watch-limit", "watch-add-failed", "watch-replaced",
                            "watch-changed-during-add", "watch-identity-changed",
                            "watch-kind-changed",
                        ):
                            raise
                        emit(f"A {request_id} UNSUPPORTED")
                        continue
                    watcher.drain_events()
                    # A replacement during event draining must not acknowledge
                    # the inode that was installed before that replacement.
                    watcher.ensure(virtual_path, fields[2] == "D")
                    emit(f"A {request_id} OK")
                    continue
                if len(fields) == 2 and fields[0] == "B":
                    request_id = parse_id(fields[1])
                    watcher.drain_events()
                    emit(f"A {request_id} OK")
                    continue
                if test_mode and fields == ["T", "OVERFLOW"]:
                    emit("X overflow")
                    return 2
                raise WatchError("invalid-frame")
            except (UnicodeError, ValueError, WatchError) as error:
                reason = str(error) or "invalid-frame"
                emit(f"X {reason[:80]}")
                return 2


def parse_id(value: str) -> int:
    if not value.isascii() or not value.isdigit() or len(value) > 20:
        raise WatchError("invalid-id")
    return int(value)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--root", required=True)
    parser.add_argument("--test-mode", action="store_true")
    args = parser.parse_args()
    try:
        return serve(args.root, args.test_mode)
    except (OSError, WatchError) as error:
        emit(f"X {str(error)[:80]}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
