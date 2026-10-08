# Session cache and the remote helper

SCPFS mounts are usually far from the server (a 234 ms round trip was the
reference case). Every SSH exec channel costs several round trips, so the
design goal is one round trip per operation that cannot be answered locally,
and zero for everything that can.

## Connections

A mount opens two authenticated SSH sessions, in parallel:

- **Main session.** Resolves the canonical remote root (one exec that runs
  `realpath` and `stat` together), runs SCP transfers for large files and keeps
  one long-lived `/bin/sh` channel for every other remote command. Each command
  runs in a subshell with stdin from `/dev/null`, framed by a per-command random
  nonce, so it costs one round trip instead of a channel open/exec/close. User
  inbox commands still get their own exec channel.
- **Monitor session.** Runs the embedded helper `server/scpfs_watch.py`
  (standard-library Python 3, Linux inotify, stdio only; no daemon or port). It
  greets with the root it resolved, and the client only uses it once that root
  equals the main session's canonical root. Mounting waits up to 8 s for it so
  the first Explorer burst is already served by the helper.

## Helper protocol (v2)

Requests are pipelined: callers on any thread queue them, the monitor thread
writes them in batches and matches the in-order replies. The helper covers a
path before answering about it: it holds a directory watch on every ancestor
(and on the directory itself for stats and listings of directories; on the
inode for hard-linked files). Every later change to an answer is therefore
reported as an event on the same stream, after the reply.

| Request | Purpose |
|---|---|
| `S` | lstat; `N` means absent with the parent covered (cacheable) |
| `L` | directory listing with an lstat of every entry |
| `R` | whole content of a regular file up to 8 MiB |
| `P` | atomic replace through a sibling temporary, up to 8 MiB, with the same expected-snapshot check as the SCP upload |
| `M`, `K`, `X`, `N` | chmod/utime, mkdir, unlink/rmdir, rename (no-clobber via `renameat2` when not replacing) |
| `F` | file system capacity |
| `B` | barrier / heartbeat |

Events name paths: `C` (content or namespace change), `M` (metadata only),
`T` (subtree lost: a covered directory was moved or deleted, or its watch was
evicted) and `R` (queue overflow: everything). Losing a watch never stops the
helper. Watches are kept in LRU order below half of
`fs.inotify.max_user_watches` (at most 32768); evicting one reports `T` for it.
Network and pseudo file systems (NFS, CIFS, 9p, FUSE, proc, ...) are refused.

`U` answers (symlinked or cross-device ancestors, files over the size limits,
a file that changed while being read) send the caller to the main session.
Mutations whose reply is lost report an error instead of falling back, because
they may already have happened.

## Cache

`src/scp_cache.c` holds stats (including negative entries), listings (whose
entries also populate child stats) and clean payload copies, behind its own
lock. Invalidation is per path:

- `M`: the path's stat and its parent's listing.
- `C`: also the path's listing and payload, the parent's stat and the
  grandparent's listing (the parent's mtime moved).
- `T`: also everything below the path.

A reconnect, an overflow or an inbox command clears everything. Admission is
ordered against invalidation by a sequence number: a reply records the cache
sequence at the moment it is parsed (events before it have been applied), and
a put is dropped if an invalidation of a related path (same, ancestor or
descendant) was recorded after that. The last 1024 invalidations are kept for
this check; older observations are rejected.

Payloads are reused when the current (cached) stat matches the copy's inode,
size and mtime. Content events drop the copy; attribute changes do not. Bytes
from `R` are covered by the helper itself; bytes from an SCP download are kept
only when the path's stat was cached (covered) when the transfer started.

## Concurrency

WinFsp runs four dispatcher threads. Remote lookups (`GetSecurityByName`,
`Open`'s stat, `ReadDirectory`, `GetDirInfoByName`, volume capacity) and file
downloads run without the adapter lock. Callbacks that find a conflicting open
handle wait up to 500 ms for a Cleanup still queued on another thread before
reporting a sharing violation.

## Limits

Notifications give eventual invalidation, not a transaction spanning Windows
and Linux: a change made by another client becomes visible one round trip
after it happens. inotify does not see every possible mutation (some mmap
writes, mount replacement). Reads advance the remote atime like any Linux
reader. Without Python 3 on the server the mount works uncached, at the cost
of one shell round trip per lookup.

`SCPFS_TRACE=1` in the environment logs every helper request and shell command
with its latency to stderr.
