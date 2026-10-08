#!/usr/bin/env python3
"""Embedded, stdio-only inotify helper for SCPFS. Protocol v2.

The helper answers metadata questions *and* keeps the answers valid: before
it stats or lists a path it holds a directory watch on every ancestor, so any
later change to the answer is reported as an event on the same stream, after
the reply. The client caches replies and drops exactly the paths the events
name; nothing is invalidated globally except on queue overflow.

Greeting: "G SCPFS-WATCH 2 hexroot" with the resolved --root.
Requests (one ASCII line each, paths are hex-encoded raw bytes below --root):
  B id            barrier: report pending events, then "A id OK"
  S id hexpath    stat (lstat semantics, ancestors must be real directories)
  L id hexpath    list a directory with an lstat of every entry
  R id hexpath limit  content of a regular file of at most limit bytes
  F id            capacity of the root file system
  P id hexpath size expect atime_ns mtime_ns, then size raw bytes
                  atomic write through a sibling temporary; expect is "-"
                  (must not exist) or "dev:ino:size:mtime_ns:mode" of the
                  file being replaced, whose mode the result keeps
  M id hexpath flags mode atime_ns mtime_ns
                  chmod (flags & 1) and set atime (2) / mtime (4); octal mode
  K id hexpath mode   mkdir with exactly this octal mode
  X id hexpath D|F    rmdir or unlink
  N id hexold hexnew 0|1  rename; 1 replaces an existing destination
  Q               quit
Replies:
  A id OK
  A id U                    unsupported here; use the slow path
  A id N                    absent; the parent is covered, so absence is cacheable
  A id E reason             failure that must not be cached (noent/notdir/access/error;
                            mutations also exists/notempty/isdir/conflict/reparse/
                            nospace/readonly/xdev/invalid)
  A id S <stat>             <stat> = type mode size atime mtime dev ino uid gid ctime;
                            also the result of P, M and K (X and N answer OK)
  A id L count              followed by count lines "hexname <stat>"
  A id F total avail
  A id D size <stat>        followed by exactly size raw content bytes
Events:
  C hexpath   content or namespace change of path (drop it, its parent's stat
              and listing, and the grandparent's listing)
  M hexpath   metadata change of path (drop its stat and its parent's listing)
  T hexpath   subtree lost (directory moved, deleted or no longer watched)
  R           everything lost (event queue overflow)
  X reason    fatal; the helper exits
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import select
import stat
import struct
import sys
from collections import OrderedDict

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
IN_EXCL_UNLINK = 0x04000000
IN_ISDIR = 0x40000000

WATCH_MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM |
              IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF |
              IN_MOVE_SELF | IN_DONT_FOLLOW | IN_EXCL_UNLINK)
CHANGE_MASK = (IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
               IN_MOVED_FROM | IN_MOVED_TO)
GONE_MASK = IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
SELF_GONE_MASK = IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED
MAX_LINE = 16384
MAX_PATH_BYTES = 4096


class Unsupported(Exception):
    """The path cannot be covered by watches; the client uses its slow path."""


class Failure(Exception):
    """A definite, uncacheable answer (for example a missing ancestor)."""


class Fatal(Exception):
    pass


def _watch_limit() -> int:
    try:
        with open("/proc/sys/fs/inotify/max_user_watches", "rb") as stream:
            system = int(stream.read().strip())
    except (OSError, ValueError):
        system = 8192
    return max(256, min(32768, system // 2))


def _filesystem_type(path: bytes) -> str:
    """Type of the most specific mount containing path (mountinfo escapes octal)."""
    best_len = -1
    best_type = ""
    text = os.fsdecode(path)
    with open("/proc/self/mountinfo", "rt", encoding="utf-8",
              errors="surrogateescape") as stream:
        for line in stream:
            fields = line.rstrip("\n").split(" ")
            try:
                fs_type = fields[fields.index("-") + 1]
                mountpoint = fields[4]
            except (ValueError, IndexError):
                continue
            for escaped, decoded in (("\\040", " "), ("\\011", "\t"),
                                     ("\\012", "\n"), ("\\134", "\\")):
                mountpoint = mountpoint.replace(escaped, decoded)
            if ((text == mountpoint or text.startswith(mountpoint.rstrip("/") + "/"))
                    and len(mountpoint) > best_len):
                best_len = len(mountpoint)
                best_type = fs_type
    return best_type


def _unwatchable(fs_type: str) -> bool:
    """inotify only sees local changes; on these other hosts change the data."""
    return (fs_type in ("proc", "sysfs", "9p", "drvfs", "cifs", "smb3", "smbfs",
                        "ceph", "glusterfs", "lustre", "gpfs", "afs", "") or
            fs_type.startswith("nfs") or
            (fs_type.startswith("fuse.") and fs_type != "fuse.fuseblk"))


def _stat_fields(item: os.stat_result) -> str:
    mode = item.st_mode
    if stat.S_ISREG(mode):
        kind = "f"
    elif stat.S_ISDIR(mode):
        kind = "d"
    elif stat.S_ISLNK(mode):
        kind = "l"
    else:
        kind = "o"
    return (f"{kind} {stat.S_IMODE(mode):o} {item.st_size} {item.st_atime_ns} "
            f"{item.st_mtime_ns} {item.st_dev} {item.st_ino} {item.st_uid} "
            f"{item.st_gid} {item.st_ctime_ns}")


_renameat2 = None


def _rename_noreplace(old: bytes, new: bytes) -> bool:
    """renameat2(RENAME_NOREPLACE); False when the kernel/libc lacks it."""
    global _renameat2
    if _renameat2 is None:
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "renameat2", None)
        if function is not None:
            function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                                 ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
        _renameat2 = function or False
    if not _renameat2:
        return False
    at_fdcwd = -100
    if _renameat2(at_fdcwd, old, at_fdcwd, new, 1) == 0:
        return True
    error = ctypes.get_errno()
    if error in (errno.EINVAL, errno.ENOSYS, errno.ENOTSUP):
        return False  # file system without RENAME_NOREPLACE
    if error == errno.EEXIST:
        raise Failure("exists")
    raise OSError(error, os.strerror(error))


def _errno_reason(error: OSError) -> str:
    return {
        errno.ENOENT: "noent", errno.EEXIST: "exists", errno.ENOTEMPTY: "notempty",
        errno.EACCES: "access", errno.EPERM: "access", errno.ENOTDIR: "notdir",
        errno.EISDIR: "isdir", errno.ENOSPC: "nospace", errno.EDQUOT: "nospace",
        errno.EROFS: "readonly", errno.EXDEV: "xdev", errno.EINVAL: "invalid",
    }.get(error.errno, "error")


def _identity(item: os.stat_result) -> tuple[int, int, int]:
    return (item.st_dev, item.st_ino, stat.S_IFMT(item.st_mode))


class Watch:
    __slots__ = ("wd", "directory", "paths", "identity")

    def __init__(self, wd: int, directory: bool, identity: tuple[int, int, int]):
        self.wd = wd
        self.directory = directory
        self.paths: set[bytes] = set()
        self.identity = identity


class Watcher:
    def __init__(self, root: str):
        self.root = os.path.realpath(os.fsencode(root))
        item = os.lstat(self.root)
        if not stat.S_ISDIR(item.st_mode):
            raise Fatal("invalid-root")
        self.root_dev = item.st_dev
        if _unwatchable(_filesystem_type(self.root)):
            raise Fatal("unsupported-filesystem")
        self.limit = _watch_limit()
        libc = ctypes.CDLL(None, use_errno=True)
        init1 = getattr(libc, "inotify_init1", None)
        if init1 is None:
            raise Fatal("inotify-unavailable")
        init1.argtypes = [ctypes.c_int]
        init1.restype = ctypes.c_int
        self._add = libc.inotify_add_watch
        self._add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._add.restype = ctypes.c_int
        self._rm = libc.inotify_rm_watch
        self._rm.argtypes = [ctypes.c_int, ctypes.c_int]
        self._rm.restype = ctypes.c_int
        self.fd = init1(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if self.fd < 0:
            raise Fatal("inotify-unavailable")
        self.watches: dict[int, Watch] = {}
        self.path_watch: dict[bytes, Watch] = {}
        self.recent: OrderedDict[int, None] = OrderedDict()
        self.pending: OrderedDict[tuple[str, bytes], None] = OrderedDict()
        self._watch(self.root, True, item, set())

    # -- path helpers -----------------------------------------------------

    def _absolute(self, virtual: bytes) -> bytes:
        return self.root if virtual == b"/" else (
            self.root.rstrip(b"/") + virtual)

    def _virtual(self, absolute: bytes) -> bytes:
        if absolute == self.root:
            return b"/"
        prefix = self.root.rstrip(b"/")
        return absolute[len(prefix):]

    @staticmethod
    def _components(virtual: bytes) -> list[bytes]:
        if (not virtual.startswith(b"/") or b"\x00" in virtual or
                len(virtual) > MAX_PATH_BYTES):
            raise Fatal("invalid-path")
        parts = [part for part in virtual.split(b"/") if part]
        if any(part in (b".", b"..") for part in parts):
            raise Fatal("invalid-path")
        return parts

    # -- watch bookkeeping ------------------------------------------------

    def _note(self, kind: str, absolute: bytes) -> None:
        self.pending[(kind, self._virtual(absolute))] = None

    def _forget(self, watch: Watch, remove: bool) -> None:
        if self.watches.get(watch.wd) is not watch:
            return
        del self.watches[watch.wd]
        self.recent.pop(watch.wd, None)
        for path in watch.paths:
            if self.path_watch.get(path) is watch:
                del self.path_watch[path]
            self._note("T" if watch.directory else "C", path)
        if remove:
            self._rm(self.fd, watch.wd)

    def _forget_subtree(self, absolute: bytes) -> None:
        if absolute == self.root:
            raise Fatal("root-lost")
        prefix = absolute + b"/"
        doomed = {watch.wd: watch for path, watch in self.path_watch.items()
                  if path == absolute or path.startswith(prefix)}
        for watch in doomed.values():
            if watch.directory:
                self._forget(watch, True)
            else:
                # A hard-linked file keeps its other aliases.
                for path in [p for p in watch.paths
                             if p == absolute or p.startswith(prefix)]:
                    watch.paths.discard(path)
                    self.path_watch.pop(path, None)
                if not watch.paths:
                    self._forget(watch, True)

    def _evict(self, keep: set[int]) -> bool:
        for wd in self.recent:
            if wd not in keep:
                self._forget(self.watches[wd], True)
                return True
        return False

    def _watch(self, absolute: bytes, directory: bool, before: os.stat_result,
               keep: set[int]) -> os.stat_result:
        """Watch a path and return an lstat taken after the watch exists."""
        existing = self.path_watch.get(absolute)
        if existing is not None:
            if existing.identity == _identity(before):
                self.recent.move_to_end(existing.wd)
                keep.add(existing.wd)
                return before
            # Replaced underneath an old watch whose events are still queued.
            self._forget_subtree(absolute)
        while len(self.watches) >= self.limit:
            if not self._evict(keep):
                raise Unsupported()
        flags = WATCH_MASK | (IN_ONLYDIR if directory else 0)
        for _attempt in range(2):
            wd = self._add(self.fd, absolute, flags)
            if wd >= 0:
                break
            if ctypes.get_errno() != errno.ENOSPC or not self._evict(keep):
                raise Unsupported()
        else:
            raise Unsupported()
        after = os.lstat(absolute)
        if _identity(after) != _identity(before):
            if wd not in self.watches:
                self._rm(self.fd, wd)
            raise Unsupported()
        watch = self.watches.get(wd)
        if watch is None:
            watch = Watch(wd, directory, _identity(after))
            self.watches[wd] = watch
        elif watch.directory or directory:
            # The same directory inode under a second path (bind mount).
            raise Unsupported()
        watch.paths.add(absolute)
        self.path_watch[absolute] = watch
        self.recent[wd] = None
        self.recent.move_to_end(wd)
        keep.add(wd)
        return after

    def _cover_parent(self, virtual: bytes, keep: set[int]) -> bytes:
        """Watch the root and every ancestor directory; return the target path."""
        parts = self._components(virtual)
        root = self.path_watch[self.root]
        self.recent.move_to_end(root.wd)
        keep.add(root.wd)
        cursor = self.root
        for part in parts[:-1]:
            cursor = cursor.rstrip(b"/") + b"/" + part
            try:
                item = os.lstat(cursor)
            except FileNotFoundError:
                raise Failure("noent")
            except PermissionError:
                raise Failure("access")
            if stat.S_ISLNK(item.st_mode) or item.st_dev != self.root_dev:
                raise Unsupported()
            if not stat.S_ISDIR(item.st_mode):
                raise Failure("notdir")
            self._watch(cursor, True, item, keep)
        return cursor.rstrip(b"/") + b"/" + parts[-1] if parts else self.root

    # -- requests ---------------------------------------------------------

    def stat(self, virtual: bytes) -> str:
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        try:
            item = os.lstat(target)
        except FileNotFoundError:
            return "N"
        except NotADirectoryError:
            return "E notdir"
        except PermissionError:
            return "E access"
        if item.st_dev != self.root_dev and target != self.root:
            raise Unsupported()
        if stat.S_ISDIR(item.st_mode):
            # Watching the directory itself keeps its mtime current.
            item = self._watch(target, True, item, keep)
        elif stat.S_ISREG(item.st_mode) and item.st_nlink > 1:
            # Another link can change this inode outside the parent directory.
            item = self._watch(target, False, item, keep)
        return "S " + _stat_fields(item)

    def list(self, virtual: bytes) -> list[str]:
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        try:
            item = os.lstat(target)
        except FileNotFoundError:
            return ["E noent"]
        except PermissionError:
            return ["E access"]
        if stat.S_ISLNK(item.st_mode) or (
                item.st_dev != self.root_dev and target != self.root):
            raise Unsupported()
        if not stat.S_ISDIR(item.st_mode):
            return ["E notdir"]
        self._watch(target, True, item, keep)
        lines = []
        try:
            with os.scandir(target) as entries:
                for entry in entries:
                    try:
                        child = entry.stat(follow_symlinks=False)
                        if stat.S_ISREG(child.st_mode) and child.st_nlink > 1:
                            child = self._watch(entry.path, False, child, keep)
                    except (FileNotFoundError, Unsupported):
                        continue
                    lines.append(entry.name.hex() + " " + _stat_fields(child))
        except PermissionError:
            return ["E access"]
        except FileNotFoundError:
            return ["E noent"]
        return [f"L {len(lines)}"] + lines

    def read(self, virtual: bytes, limit: int) -> tuple[str, bytes]:
        """Whole content of a small regular file, read from one stable inode."""
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        try:
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                         getattr(os, "O_CLOEXEC", 0))
        except FileNotFoundError:
            return "E noent", b""
        except PermissionError:
            return "E access", b""
        except OSError:
            raise Unsupported()
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_size > limit or
                    before.st_dev != self.root_dev):
                raise Unsupported()
            if before.st_nlink > 1:
                self._watch(target, False, os.lstat(target), keep)
            chunks = []
            total = 0
            while total <= before.st_size:
                chunk = os.read(fd, max(65536, before.st_size + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(fd)
            current = os.lstat(target)
        finally:
            os.close(fd)
        if (total != before.st_size or
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) or
                _identity(current) != _identity(after)):
            raise Unsupported()  # changed while reading; the client retries elsewhere
        return f"D {total} " + _stat_fields(after), b"".join(chunks)

    # -- mutations ------------------------------------------------------
    # Each mirrors the backend's shell implementation in one round trip; the
    # path's own watches then report the change like any other.

    def _object(self, target: bytes) -> os.stat_result:
        """lstat of an existing file or directory, as the backend requires."""
        item = os.lstat(target)
        if stat.S_ISLNK(item.st_mode):
            raise Failure("reparse")
        if not (stat.S_ISREG(item.st_mode) or stat.S_ISDIR(item.st_mode)):
            raise Failure("access")
        if item.st_dev != self.root_dev:
            raise Unsupported()
        return item

    def write(self, virtual: bytes, expect: bytes, atime: int, mtime: int,
              data: bytes) -> str:
        """Atomic replace through a sibling temporary, like upload_atomic."""
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        if target == self.root:
            raise Failure("access")
        try:
            current = self._object(target)
        except FileNotFoundError:
            current = None
        if expect == b"-":
            if current is not None:
                raise Failure("exists")
            mode = None
        else:
            dev, ino, size, old_mtime, mode = (int(part) for part in expect.split(b":"))
            if (current is None or not stat.S_ISREG(current.st_mode) or
                    (current.st_dev, current.st_ino, current.st_size,
                     current.st_mtime_ns, stat.S_IMODE(current.st_mode)) !=
                    (dev, ino, size, old_mtime, mode)):
                raise Failure("conflict")
        parent = os.path.dirname(target)
        temp = os.path.join(parent, b".scpfs-tmp-" + os.urandom(16).hex().encode())
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     getattr(os, "O_CLOEXEC", 0), 0o666)
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                if mode is not None:
                    os.fchmod(fd, mode)
                os.utime(fd, ns=(atime, mtime))
            finally:
                os.close(fd)
            if mode is not None:
                os.rename(temp, target)
            else:
                # Publish without clobbering a file created meanwhile.
                try:
                    os.link(temp, target, follow_symlinks=False)
                    os.unlink(temp)
                except FileExistsError:
                    raise Failure("exists")
                except OSError as error:
                    if error.errno not in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP):
                        raise
                    # No hard links here: the check-then-rename of mv -n.
                    if os.path.lexists(target):
                        raise Failure("exists")
                    os.rename(temp, target)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise
        return "S " + _stat_fields(os.lstat(target))

    def setmeta(self, virtual: bytes, flags: int, mode: int, atime: int,
                mtime: int) -> str:
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        if target == self.root:
            raise Failure("access")
        current = self._object(target)
        if flags & 1:
            os.chmod(target, mode & 0o7777)
        if flags & 6:
            os.utime(target, ns=(atime if flags & 2 else current.st_atime_ns,
                                 mtime if flags & 4 else current.st_mtime_ns),
                     follow_symlinks=False)
        return "S " + _stat_fields(os.lstat(target))

    def mkdir(self, virtual: bytes, mode: int) -> str:
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        if target == self.root:
            raise Failure("exists")
        os.mkdir(target, 0o700)
        os.chmod(target, mode & 0o7777)
        return "S " + _stat_fields(os.lstat(target))

    def remove(self, virtual: bytes, directory: bool) -> str:
        keep: set[int] = set()
        target = self._cover_parent(virtual, keep)
        if target == self.root:
            raise Failure("access")
        current = self._object(target)
        if directory != stat.S_ISDIR(current.st_mode):
            raise Failure("notdir" if directory else "isdir")
        if directory:
            os.rmdir(target)
        else:
            os.unlink(target)
        return "OK"

    def rename(self, old_virtual: bytes, new_virtual: bytes, replace: bool) -> str:
        keep: set[int] = set()
        old = self._cover_parent(old_virtual, keep)
        new = self._cover_parent(new_virtual, keep)
        if self.root in (old, new):
            raise Failure("access")
        self._object(old)
        if old == new:
            return "OK"
        try:
            self._object(new)
            if not replace:
                raise Failure("exists")
        except FileNotFoundError:
            pass
        if replace or not _rename_noreplace(old, new):
            os.rename(old, new)
        return "OK"

    def capacity(self) -> str:
        info = os.statvfs(self.root)
        return f"F {info.f_frsize * info.f_blocks} {info.f_frsize * info.f_bavail}"

    # -- events -----------------------------------------------------------

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
                name = data[offset:offset + name_len].rstrip(b"\x00")
                offset += name_len
                if mask & IN_Q_OVERFLOW:
                    self.pending[("R", b"")] = None
                    continue
                watch = self.watches.get(wd)
                if watch is None:
                    continue
                if name and watch.directory:
                    parent = next(iter(watch.paths))
                    child = parent.rstrip(b"/") + b"/" + name
                    if mask & GONE_MASK:
                        self._forget_subtree(child)
                        self._note("T" if mask & IN_ISDIR else "C", child)
                    elif mask & CHANGE_MASK:
                        self._note("C", child)
                    elif mask & IN_ATTRIB:
                        self._note("M", child)
                    continue
                if mask & SELF_GONE_MASK:
                    if watch.directory:
                        for path in list(watch.paths):
                            self._forget_subtree(path)
                    self._forget(watch, not (mask & IN_IGNORED))
                    continue
                for path in watch.paths:
                    if mask & CHANGE_MASK:
                        self._note("C", path)
                    elif mask & IN_ATTRIB:
                        self._note("M", path)

    def flush_events(self) -> None:
        if not self.pending:
            return
        out = []
        if ("R", b"") in self.pending:
            out.append("R")
        else:
            for kind, path in self.pending:
                if kind == "M" and ("C", path) in self.pending:
                    continue
                out.append(f"{kind} {path.hex()}")
        self.pending.clear()
        emit_lines(out)


def emit_lines(lines: list[str]) -> None:
    sys.stdout.write("".join(line + "\n" for line in lines))
    sys.stdout.flush()


def parse_id(value: bytes) -> int:
    if not value.isdigit() or len(value) > 20:
        raise Fatal("invalid-id")
    return int(value)


def parse_path(value: bytes) -> bytes:
    if len(value) > MAX_PATH_BYTES * 2 or len(value) % 2:
        raise Fatal("invalid-path-encoding")
    return bytes.fromhex(value.decode("ascii"))


ARITY = {b"B": 2, b"F": 2, b"S": 3, b"L": 3, b"R": 4,
         b"P": 7, b"M": 7, b"K": 4, b"X": 4, b"N": 5}
MUTATIONS = (b"P", b"M", b"K", b"X", b"N")
MAX_WRITE = 16 * 1024 * 1024


def handle(watcher: Watcher, fields: list[bytes], test_mode: bool,
           data: bytes = b"") -> bool:
    """Process one request; False ends the session."""
    if fields == [b"Q"]:
        emit_lines(["A 0 OK"])
        return False
    if test_mode and fields == [b"T", b"OVERFLOW"]:
        raise Fatal("overflow")
    if len(fields) < 2 or ARITY.get(fields[0]) != len(fields):
        raise Fatal("invalid-frame")
    request_id = parse_id(fields[1])
    op = fields[0]
    watcher.drain_events()
    payload = b""
    try:
        if op == b"B":
            reply = ["OK"]
        elif op == b"F":
            reply = [watcher.capacity()]
        elif op == b"S":
            reply = [watcher.stat(parse_path(fields[2]))]
        elif op == b"L":
            reply = watcher.list(parse_path(fields[2]))
        elif op == b"R":
            line, payload = watcher.read(parse_path(fields[2]), parse_id(fields[3]))
            reply = [line]
        elif op == b"P":
            reply = [watcher.write(parse_path(fields[2]), fields[4], int(fields[5]),
                                   int(fields[6]), data)]
        elif op == b"M":
            reply = [watcher.setmeta(parse_path(fields[2]), int(fields[3]),
                                     int(fields[4], 8), int(fields[5]), int(fields[6]))]
        elif op == b"K":
            reply = [watcher.mkdir(parse_path(fields[2]), int(fields[3], 8))]
        elif op == b"X":
            reply = [watcher.remove(parse_path(fields[2]), fields[3] == b"D")]
        else:
            reply = [watcher.rename(parse_path(fields[2]), parse_path(fields[3]),
                                    fields[4] == b"1")]
    except Unsupported:
        reply = ["U"]
    except Failure as failure:
        reply = [f"E {failure}"]
    except OSError as error:
        # Reads fall back to the backend on "error"; mutations report why.
        reply = [f"E {_errno_reason(error)}" if op in MUTATIONS else "E error"]
    # Events discovered while covering the path precede the reply.
    watcher.flush_events()
    reply[0] = f"A {request_id} {reply[0]}"
    emit_lines(reply)
    if payload:
        # Raw bytes follow a "D size" reply; size was announced on its line.
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    return True


def serve(root: str, test_mode: bool) -> int:
    watcher = Watcher(root)
    # The resolved root lets the client check it watches what it mounted.
    emit_lines([f"G SCPFS-WATCH 2 {watcher.root.hex()}"])
    input_fd = sys.stdin.fileno()
    buffer = bytearray()
    # A "P" request line is followed by its raw content bytes.
    put_fields: list[bytes] | None = None
    put_size = 0
    while True:
        readable, _, _ = select.select((input_fd, watcher.fd), (), ())
        if watcher.fd in readable:
            watcher.drain_events()
            watcher.flush_events()
        if input_fd not in readable:
            continue
        chunk = os.read(input_fd, 1 << 20)
        if not chunk:
            if buffer or put_fields is not None:
                raise Fatal("truncated-frame")
            return 0
        buffer.extend(chunk)
        while True:
            if put_fields is not None:
                if len(buffer) < put_size:
                    break
                data = bytes(buffer[:put_size])
                del buffer[:put_size]
                fields, put_fields = put_fields, None
                handle(watcher, fields, test_mode, data)
                continue
            newline = buffer.find(b"\n")
            if newline < 0:
                break
            if newline > MAX_LINE:
                raise Fatal("frame-too-large")
            line = bytes(buffer[:newline])
            del buffer[:newline + 1]
            fields = line.split(b" ")
            if fields[0] == b"P" and len(fields) == ARITY[b"P"]:
                put_size = parse_id(fields[3])
                if put_size > MAX_WRITE:
                    raise Fatal("frame-too-large")
                put_fields = fields
                continue
            if not handle(watcher, fields, test_mode):
                return 0
        if put_fields is None and len(buffer) > MAX_LINE:
            raise Fatal("frame-too-large")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--root", required=True)
    parser.add_argument("--test-mode", action="store_true")
    args = parser.parse_args()
    try:
        return serve(args.root, args.test_mode)
    except (OSError, ValueError, Fatal) as error:
        emit_lines([f"X {str(error)[:80] or 'error'}"])
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
