# CryptFS v1 on-disk format

This document fixes the byte layout used by `cryptfs_store.c`. Integers are
unsigned little-endian unless a field is explicitly signed. No C structure is
written to disk. Readers reject unknown format versions, nonzero reserved
bytes, arithmetic overflow, unaligned or out-of-range references, and record
types that do not match the owning edge.

## Fixed front and physical pages

All offsets are absolute byte offsets from the beginning of the container.

| Region | Start | Length | End (exclusive) |
| --- | ---: | ---: | ---: |
| Superblock copy 0 | 0 | 4,096 | 4,096 |
| Superblock copy 1 | 4,096 | 4,096 | 8,192 |
| State marker copy 0 | 8,192 | 4,096 | 12,288 |
| State marker copy 1 | 12,288 | 4,096 | 16,384 |
| Journal | 16,384 | 4,194,304 | 4,210,688 |
| Fixed root inode page | 4,210,688 | 4,096 | 4,214,784 |
| Movable home pages | 4,214,784 | 4,096 each | on demand |

The fixed front therefore ends at 4,214,784 bytes. It is also the minimum
container EOF. The root page is physical page one of the 4,000,000-page limit;
there are at most 3,999,999 movable page slots. Non-root pointers are 1-based
slot numbers. Slot 1 starts at 4,214,784; slot `n` starts at
`4,214,784 + (n - 1) * 4,096`. A zero pointer is null. The root's special AEAD
slot identity is `0xffffffffffffffff` and it is never relocated. Container EOF
must be page aligned and no larger than the end of slot 3,999,999.

Every home page has a 48-byte public record envelope followed by a fixed
4,048-byte authenticated ciphertext. The plaintext is always exactly 4,032
bytes; unused payload bytes are encrypted zeroes. The envelope is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `CFRP` |
| 4 | 2 | format version, 1 |
| 6 | 2 | record type: 1 inode, 2 block map, 3 data fragment |
| 8 | 8 | logical record identity (inode ID for an inode; owning file ID otherwise) |
| 16 | 8 | reserved, zero |
| 24 | 24 | XChaCha20-Poly1305 nonce |
| 48 | 4,048 | ciphertext and 16-byte tag |

The page AEAD associated data is the 16-byte container UUID, the 8-byte
physical slot identity in little-endian form, and all 48 envelope bytes. The
page is rejected if the envelope type, identity, version, or reserved bytes do
not agree with the graph edge and decrypted payload. Relocation uses a fresh
nonce and authenticates the new slot identity. V1 stores no per-record
monotonic generation or trusted freshness counter; replaying an older valid
record at the same slot and identity may pass authentication if its current
graph edges also validate. V1 does not claim record-level rollback detection.

## Superblocks

The two 4 KiB superblocks are identical immutable copies. Each has this public
prefix:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `CRYPTFS1` |
| 8 | 4 | format version, 1 |
| 12 | 4 | public header length, 152 |
| 16 | 16 | random container UUID |
| 32 | 4 | flags; bit 0 means sparse storage is required, all other bits zero |
| 36 | 4 | reserved, zero |
| 40 | 8 | logical capacity in bytes |
| 48 | 8 | Argon2id13 ops limit |
| 56 | 8 | Argon2id13 memory limit in bytes |
| 64 | 16 | random password salt |
| 80 | 24 | XChaCha20-Poly1305 wrapping nonce |
| 104 | 48 | wrapped 32-byte master key plus 16-byte tag |
| 152 | 3,944 | reserved, zero |

The password wrapping key is derived from the supplied UTF-8 password and the
salt. Its AEAD associated data is bytes 0..79 followed by bytes 152..4095;
the nonce and wrapped-key fields are excluded. Supported Argon2 parameters
are ops 1..6 and memory 64..512 MiB. New containers use ops 3 and 256 MiB.
V1 accepts logical capacities from 1 byte through 1 TiB; 1 TiB is the default.
Both copies must be structurally valid and, if both unwrap successfully, byte
identical. A malformed copy can be skipped when the other copy unwraps and
validates. If no structurally valid copy exists, open returns data error; if
valid copies exist but none unwraps, open returns access denied. A valid copy
is never rewritten while opening an existing container. This duplication
protects against a torn/corrupt copy, but cannot detect rollback to an older
complete container.

## Authenticated state markers

Each marker occupies 4,096 bytes. All reserved bytes are zero. The first 112
bytes are:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `CFMARK1` followed by NUL |
| 8 | 4 | format version, 1 |
| 12 | 4 | physical marker copy number, 0 or 1 |
| 16 | 4 | state: 0 EMPTY, 1 COMMITTED |
| 20 | 4 | reserved, zero |
| 24 | 8 | monotonically increasing generation |
| 32 | 4 | encrypted journal byte length; zero for EMPTY |
| 36 | 4 | reserved, zero |
| 40 | 8 | final container EOF after this generation |
| 48 | 32 | unkeyed SHA-256 of the exact encrypted journal bytes; zero for EMPTY |
| 80 | 32 | HMAC-SHA256 over the container UUID followed by bytes 0..79 |
| 112 | 3,984 | reserved, zero |

The MAC uses `cf_mac` with the derived header key over UUID concatenated with
bytes 0..79 (HMAC-SHA256). A marker is eligible only after its
reserved bytes, copy number, state-dependent fields, EOF, version and MAC all
validate. Mount selects the eligible marker with the highest generation. Equal
generation copies are accepted only when their state, length, EOF and journal
hash agree. An invalid newer marker is ignored as a torn write; the preceding
eligible marker remains authoritative. A highest EMPTY marker suppresses any
older COMMITTED marker.

New containers start with marker copy 0 EMPTY generation 0. Each transaction
uses the next generation for COMMITTED and the following generation for
EMPTY, alternating physical marker copies by generation parity.

## Journal

The journal starts at 16,384 and occupies the next 4 MiB. A committed marker's
length selects the exact encrypted journal prefix; bytes after that prefix are
irrelevant stale storage. Total transaction journal length is at most 2 MiB.
The encrypted journal begins with this 40-byte public envelope:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `CFWAL1` followed by two NUL bytes |
| 8 | 4 | format version, 1 |
| 12 | 4 | ciphertext length, including tag |
| 16 | 24 | XChaCha20-Poly1305 nonce |
| 40 | variable | ciphertext and 16-byte tag |

Journal AEAD associated data is the container UUID plus the 40-byte envelope.
The plaintext is a 32-byte header followed by `page_count` ordered afterimages:

| Plain offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `CFJNL1` followed by two NUL bytes |
| 8 | 4 | format version, 1 |
| 12 | 4 | afterimage count, 0..510 |
| 16 | 8 | COMMITTED generation |
| 24 | 8 | final EOF, page aligned and bounded |
| 32 | repeated | slot number (8 bytes), then complete 4,096-byte afterimage |

Zero afterimages are valid only for a pure EOF-trim transaction. Afterimages
must have unique slots and fit within final EOF. Ordinary slots are
1..3,999,999. The special slot `0xffffffffffffffff` refers to the fixed root
page at 4,210,688 and is allowed even though it is not a movable slot.
The encrypted length must exactly equal `40 + 32 + page_count * 4,104 + 16`.
The marker SHA-256 covers the exact public envelope and ciphertext. Replay
copies these already-authenticated afterimages verbatim; it does not encrypt
them again. Free slots do not need WAL entries because reachability is derived
from the authenticated graph.

## Decrypted page payloads

All page payloads are 4,032 bytes. Fields not listed below are zero and checked.

### Inode (type 1)

| Payload offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | inode ID; root is 1 |
| 8 | 8 | parent inode ID; root is 0 |
| 16 | 8 | first child inode slot |
| 24 | 8 | next sibling inode slot |
| 32 | 8 | first block-map slot |
| 40 | 8 | root: first orphan inode slot; non-root: next orphan inode slot |
| 48 | 8 | logical file size |
| 56 | 8 | creation time, Windows FILETIME ticks |
| 64 | 8 | access time, Windows FILETIME ticks |
| 72 | 8 | write time, Windows FILETIME ticks |
| 80 | 8 | change time, Windows FILETIME ticks |
| 88 | 4 | Windows attributes |
| 92 | 2 | UTF-16 code-unit name length, 0..255 |
| 94 | 2 | flags, zero |
| 96 | 510 | exact UTF-16LE name bytes; remainder zero |
| 606 | 2 | zero |
| 608 | 8 | root only: next inode ID |
| 616 | 3,416 | zero |

The root has directory attributes, no name, parent, sibling, or map link. Its
offset 40 field is the head of the orphan chain. For the root only, payload
offset 608 is a required monotonic `next_inode_id` counter; all live inode IDs
are less than it. New IDs come from this counter and it increments in the same
transaction as inode creation. IDs are never reused. Non-root inode payload
bytes 608..4031 are zero.
Directory children are singly owned through `first child` then each child's
`next sibling`; redundant parent IDs must match. Files own a sorted block-map
chain. Unlinked open nodes are singly owned from root's orphan link then each
orphan inode's `next orphan`; orphan nodes have no sibling edge. A node cannot
have both directory and non-directory type, and only directories may have
children.

### Block map (type 2)

| Payload offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | owning file inode ID |
| 8 | 8 | next block-map slot |
| 16 | 2 | entry count, 0..125 |
| 18 | 6 | zero |
| 24 | 32 per entry | sorted logical block entries |

Each 32-byte entry is: logical block index (u64), first fragment slot (u64),
encoded byte length (u32), codec (u32: 0 raw, 1 zstd), raw byte length (u32,
exactly 65,536), and fragment count (u32). Entries are strictly increasing
within and across pages. Empty map pages are invalid. Blocks beyond the file's
logical EOF are invalid after final truncation.
When a map-chain link changes, the transaction stores the page containing that
link together with the referenced new map page. In particular, appending a map
after a full tail map updates the predecessor's `next block-map slot` and the
new map page atomically; a remount must never see the new map without its link.

### Data fragment (type 3)

| Payload offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | owning file inode ID |
| 8 | 8 | logical block index |
| 16 | 8 | next fragment slot |
| 24 | 4 | zero-based fragment sequence |
| 28 | 4 | used data bytes, 1..4,000 |
| 32 | up to 4,000 | encoded block bytes |
| 32 + used length | remainder | zero |

Fragments form an exact singly owned chain. Sequences start at zero, lengths
sum to the entry's encoded length, and the final next pointer is zero. The
complete encoded block is authenticated and decoded (exactly one bounded zstd
frame for codec 1) before any plaintext from it is returned. Unallocated blocks
are sparse logical holes and read as zeroes.

## Transaction and open ordering

For a transaction, write and flush the complete journal, write and flush the
alternating COMMITTED marker (the durable commit point), apply afterimages and
flush, set the final EOF and flush, then write and flush the alternating EMPTY
marker. An error after COMMITTED poisons the live store until remount. Before
COMMITTED, home pages and EOF remain untouched.

A journal write or its first flush failure is a precommit I/O error: the
previous EMPTY marker remains authoritative, home pages and EOF are untouched,
the in-memory operation is rolled back, and the caller receives an I/O error.
Failure from the first attempt to write the COMMITTED marker onward is treated
as uncertain and poisons the live store. This includes a reported short marker
write: the authenticated 112-byte marker prefix could have reached storage even
when the write call reports failure. A later open validates the selected
marker, journal, and complete proposed graph before doing any recovery writes.
An optional sparse-range punch after a committed page move may fail without
invalidating the move; the host error remains available in store diagnostics.

`CRYPTFS_TESTING` builds expose host-I/O fault seams for write, flush, EOF, and
hole-punch operations. Each occurrence counter counts calls to its matching
storage primitive and fails the selected call before invoking the host API. A
separate short-marker seam writes only the first 112 marker bytes at the next
marker write, then reports a write error. These test seams do not change the
v1 on-disk layout and are absent from product builds.

Opening an existing container performs no writes, sparse-control changes,
truncation or metadata flush. After password unwrap, it validates the selected
marker and journal. If COMMITTED, a shadow reader overlays afterimages on home
pages and authenticates every reachable inode, map and fragment, including
decoding every complete data block. Only after the entire proposed graph passes
may recovery write afterimages, EOF and EMPTY. With EMPTY, the complete current
graph is authenticated before enabling writes. A failure during password,
format, marker, WAL, graph, bounds, AEAD or data validation leaves container
bytes unchanged.

New creation uses exclusive create, marks only that new file sparse, writes
both immutable superblocks, initial root and EMPTY marker, and sets the fixed
minimum EOF. If initialization fails, only the newly created file may be
removed. Existing containers are opened exclusively and must already be sparse.
