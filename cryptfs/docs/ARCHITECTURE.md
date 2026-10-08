# CryptFS v1 architecture

Decision recorded 2026-10-03 before implementation. Luna prepared the frontend,
dependency and persistence briefing; Sol Ultra approved this new persistent
format, crypto boundary and compaction protocol. This is a Windows-only v1,
with one exclusive writer per container and case-sensitive UTF-16 names.

## Public behavior

A single NTFS sparse file contains all persistent filesystem state. New files
and holes read as zeros. Independently compressed 64 KiB logical blocks use
zstd level 3 by default, falling back to raw data if compression does not save
space. The container grows on demand; a background worker reclaims free sparse
ranges and relocates tail pages into lower free slots, then truncates EOF.
Files, names, directories, sizes, attributes and timestamps are encrypted.
Windows security descriptors are synthesized for this v1 volume; persistent
ACLs, reparse points, streams, EA, hard links and service auto-unlock are outside
v1. Unsupported operations must return an explicit unsupported result.

The logical capacity defaults to and is capped at 1 TiB. V1 limits are 65,536 namespace nodes,
depth 64 and 4,000,000 physical pages (about 15.3 GiB). Free volume space considers
the logical limit, physical page budget and host free space. These are product
limits, not claims of unlimited storage. The exclusive file handle prevents
two mounts of the same container. Normal operations and compaction share a lock.

## Cryptography and secret input

Use statically linked libsodium and zstd from vcpkg x64-windows-static, static
CRT, clang-cl C17 and the existing static WinFsp user-mode library. Argon2id13
derives a wrapping key from UTF-8 password bytes (1..1024, no NUL/CR/LF), a fresh
16-byte salt, opslimit 3 and memlimit 256 MiB. Readers reject unknown algorithms
and parameters outside ops 1..6 and memory 64..512 MiB before invoking the KDF.
A random 32-byte master key is wrapped using XChaCha20-Poly1305; independent
record, journal and header keys are derived using crypto_kdf.

Every fresh encryption uses a random 24-byte nonce. AAD covers UUID, format,
record type, logical identity, segment index, physical slot, plaintext length,
codec and every header field that affects interpretation. Journal replay writes
authenticated afterimages without encrypting them again. Relocation decrypts
and authenticates a page and re-encrypts it for the new slot with a fresh nonce.
Authentication failures return no plaintext. Decoding accepts exactly one zstd
frame, at most 64 KiB output and a bounded window, with exact length validation.
Keys, passwords and transient plaintext are explicitly wiped.

Passwords are never command-line arguments, environment variables, plaintext
configuration files or log output. CLI uses a hidden console prompt or explicit
stdin input. The shared frontend receives an additive masked-password field
and an owned, securely wiped stdin blob transported using an inherited pipe
and an explicit handle allowlist. This v1 GUI offers mount/unmount only; secret
input cannot use the ShellExecute elevation/relaunch path.

## Serialized format and graph

All disk structures use explicit little-endian serialization, never dumped C
structs. The fixed front consists of two 4 KiB static superblocks, two 4 KiB
authenticated state markers, a 4 MiB journal and a fixed 4 KiB root inode.
Remaining home pages are 4 KiB-aligned encrypted records. The minimum EOF is
the end of the fixed front. Public superblocks hold magic, version, header
length, UUID, flags, logical capacity, Argon2id parameters, salt and the wrapped
master-key envelope. Envelope AAD covers every other public field; reserved
bytes are zero and checked. Public format/KDF values, container EOF and coarse
allocation patterns are observable. This version provides authentication but
does not provide freshness or rollback detection. An older complete valid
container, or an older authenticated record for the same slot and logical
identity whose surrounding graph remains valid, can be replayed. Detecting
that requires an additional trusted freshness mechanism; it is outside v1.

Inodes form first-child/next-sibling chains. Each file owns a block-map chain;
map entries own compressed/raw fragment chains. Every non-root page has exactly
one physical owner edge, and the graph is acyclic. Redundant parent inode IDs
are validation fields, not physical ownership edges. Directory lookup and
sorting use verified RAM indices. Names compare exact UTF-16 code units.
Rename must prevent moving a directory into its own descendants.

Open-unlinked inodes are owned by root.orphan_head through independent
next_orphan pointers: unlink atomically removes the directory sibling edge,
clears next_sibling and inserts the inode into the orphan chain. The final
handle closes and frees it. Following a crash, orphan cleanup occurs only after
full authenticated mount/recovery validation. All indices, lengths, traversals,
counts, depth, duplicate references and arithmetic have explicit bounds.

## Transactions and mount recovery

Journal transactions are bounded to 2 MiB within the fixed 4 MiB region. The
complete encrypted journal contains home afterimages and the final EOF. State
markers contain format/slot/state, monotonically increasing generation,
journal length/hash and keyed authentication. Select the highest valid marker;
the highest EMPTY means an older COMMITTED marker must not replay.

1. Write the complete encrypted journal; FlushFileBuffers.
2. Write an alternating COMMITTED marker; flush. This is the commit point.
3. Apply authenticated home afterimages; flush.
4. Apply transaction-required truncation (and any immediate punch list); flush.
5. Write an alternating EMPTY marker; flush. Only then start the next transaction.

Before COMMITTED, old home pages are unchanged. After COMMITTED, recovery is
idempotent. For a COMMITTED mount, a shadow resolver overlays afterimages on
home pages and authenticates the entire proposed live graph, including every
data page, before any replay, punch or truncation. An EMPTY mount authenticates
the complete current graph before enabling writes. Failed unlock, journal,
marker, graph, AEAD or bounds checks cause zero container writes. This makes
unlock O(live pages); large-container unlock latency must be measured and
reported rather than concealed. A complete authenticated logical block is
verified before any of its plaintext is returned on reads.

Large writes commit one 64 KiB block at a time and report accurately completed
bytes on later failure. Metadata operations must prove their transaction fits
before modifying persistent state. Delete/truncate commits graph changes;
free pages are reconstructed from reachability, so large deletes need not list
all freed slots in one journal. From the first attempted write of the
COMMITTED marker onward, any unsuccessful transaction has an uncertain
outcome and poisons further writes until remount. A journal write/flush or
resource failure before that attempt leaves the previous EMPTY marker and
old home pages/EOF authoritative; it fails without poisoning the volume.
Never reuse an unresolved transaction or report false success.

Compaction obeys the same commit boundary. Its precommit resource or host-I/O
failure stops that pass, exposes the error, and leaves foreground operations
available; a later wake or bounded backoff retries without a busy loop.
Authenticated-page, owner-link, or graph invariant failure poisons the store.
An outcome-uncertain failure after COMMITTED-marker attempt also poisons the
store. A stopped compaction pass must not be reported as completed reclamation.

## Background convergence and reclamation

The worker moves at most one live 4 KiB page per step from highest live slot H
to lower free slot L, updates its unique owner's pointer and re-encrypts owner
and destination in one WAL transaction. Owner is updated in place, so this
does not create new tail pages. Root never moves. Each move lowers the highest
live page or reduces the number of live pages above the current lowest free
slot; once there are no holes, EOF is minimal for live pages. The worker yields
the lock between steps. Convergence assumes net-stable foreground storage;
unbounded incoming growth cannot promise a shrinking EOF.

Ordinary free-page punching may run after EMPTY, but each step holds the lock,
rechecks that the slot is still unreachable, and is mutually exclusive with
allocation. Never queue a bare slot number for later unchecked punching.
Tail truncation is serialized and durably tracked. Unsupported sparse controls,
host exhaustion and write/flush failures are reported explicitly. Background
failure is visible in statistics/logging and stops unsafe writes.

## Validation gates

Crypto and codec known-answer/bounds tests; wrong password, header/marker/WAL/
page/tag tamper with byte-for-byte no-write verification; crash at every durable
transaction phase; sparse large holes; incompressible and compressible blocks;
rename/delete/open-unlink; timestamp persistence; repeated overwrite and EOF
shrink; actual WinFsp CRUD/concurrency/remount; GUI secret transport; Debug and
Release tests; shared frontend memfs/SCPFS regressions; static imports and signed
driver provenance; final independent storage/security architecture review.

Tests prove only their recorded scope. This format is new: backup important
data until longer operational and power-loss testing establishes confidence.

## Final review implementation constraints (2026-10-03)

Sol's focused final review requires parser-owned block objects to have one
cleanup owner even if fragment authentication fails. Precommit RAM rollback
must never run after a successful WAL commit; failure while publishing page
registrations poisons the store but must leave it safely disposable. Test-only
registration failure injection and fragment-tag tampering exercise these
boundaries under AddressSanitizer.

Namespace changes and later orphan reclamation are separate transactions. Once
unlink or rename commits, its result reports that committed namespace change.
Reclamation failure is recorded independently; uncertain committed I/O stops
further writes until remount. A one-shot test-only reclamation failure verifies
this result contract. These changes do not alter the v1 serialized format.

Sol accepts a v1 allocation boundary: a non-aligned shrink may require new
encrypted boundary fragments and can return CF_NO_SPACE when no physical slots
are available. Such failure preserves the old size, plaintext, map graph and
container bytes. Shrinking to zero, to a 64 KiB boundary, or unlinking requires
no new physical page slots and remains available to release space. A test-only
allocation failure covers the same precommit failure path. Background
compaction may free slots for a later retry. V1 does not add old-slot reuse for
partial-block shrink at this milestone.

The final review also requires controlled write, flush, EOF and sparse-punch
failures. A partial COMMITTED marker write may already leave an authenticated
marker prefix, so the store poisons from the marker-write attempt, including
reported short writes. Reclamation failure after namespace commit does not
change that operation's committed result. Sparse-punch failure is recorded as
a warning; the unreachable source slot remains safe and later EOF truncation
can reclaim it. Test-only hooks verify these failure outcomes without altering
the production format or interrupting existing system volumes.

`cf_store_wait_idle` is a synchronization wait, not a reclamation-success
certificate. A recoverable background failure leaves the worker idle and
records a warning/host error; callers use statistics or explicit compact-step
results to determine whether the desired EOF/reclamation was reached.
