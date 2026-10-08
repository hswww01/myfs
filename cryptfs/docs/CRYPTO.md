# Crypto and block codec module

`src/cryptfs_crypto.c` implements the interface declared by
`src/cryptfs_crypto.h`. It uses libsodium for random bytes, Argon2id13,
XChaCha20-Poly1305, crypto_kdf, SHA-256, HMAC-SHA-256 and secure erasure; zstd
provides independent block compression.

## Key and password rules

- Call `cf_crypto_init()` before using the module. Other helpers also initialize
  libsodium defensively. `cf_random()` has a void return contract; if library
  initialization fails, it clears the requested buffer and returns. Callers
  must treat initialization failure as fatal before creating or updating a
  container.
- Passwords are 1 to 1024 bytes of valid UTF-8. NUL, CR and LF bytes are
  rejected. `cf_password_key()` accepts only Argon2id13 operations 1 through 6
  and memory 64 through 512 MiB, checked before calling libsodium. Container
  creation uses the header contract's 3 operations and 256 MiB.
- `cf_keys_derive()` derives three distinct 32-byte subkeys from the random
  master key, with separate libsodium KDF IDs and the fixed 8-byte contexts
  `cfrec001`, `cfwal001` and `cfhdr001`.
- Every AEAD call uses XChaCha20-Poly1305-IETF and a caller-generated random
  24-byte nonce. The module does not generate nonces inside encrypt/decrypt;
  container code must persist the nonce beside each ciphertext and never reuse
  one with the same key.
- `cf_decrypt()` writes to a temporary buffer and copies plaintext only after
  authentication succeeds. On every failure it clears the entire supplied
  destination capacity and sets the output length to zero. The caller must
  supply valid writable memory for the full capacity it reports. AEAD input
  and output ranges must not overlap, because the destination is cleared before
  validation/decryption.
- Input and output buffers must be distinct for block codec calls. The
  container's data path uses separate buffers; the fixed-array API does not
  promise in-place operation.

## Block codec rules

Each input and decoded block is exactly 65536 bytes. `cf_block_encode()` accepts
zstd's supported compression-level range, writes a single zstd frame at the
requested level with a maximum 64 KiB window, and chooses codec 1 only when the
complete frame is strictly smaller than 65536 bytes. Otherwise it stores the
raw block as codec 0. `cf_block_decode()` rejects unknown codecs, wrong raw
lengths, compressed lengths beyond `ZSTD_compressBound(65536)`, malformed or
truncated frames, concatenated frames, trailing bytes, unknown or incorrect
frame content sizes, windows over 64 KiB, and output other than exactly 65536
bytes. A failed decode clears the full output block.

The application-owned temporary compressed and decoded buffers are wiped
before release. zstd's API does not promise secure erasure of its internal
context allocations; they contain codec state and may include history bytes.
If the threat model requires verified erasure of library-internal compression
memory, that needs a separate zstd allocator/API decision rather than an
assumption that freeing a context wipes it.

## Relationship to memfs

The dependency/build selection follows the existing `D:\work\fs\memfs` core:
both use static vcpkg libsodium (`unofficial-sodium::sodium`) and zstd
(`zstd::libzstd`) with the static CRT. Reusing these vetted primitives keeps
the projects aligned without copying memfs's storage policy. memfs is volatile
and reserves a process-local monotonic nonce sequence under a random per-mount
prefix; persistent CryptFS instead stores a fresh random nonce with each
ciphertext so nonce uniqueness does not depend on counter recovery after a
crash. memfs adaptively skips some compression attempts based on observed
compression usefulness and requires a 32-byte saving for its pages. CryptFS's
fixed independent 64 KiB format always encodes the block and selects zstd only
when the frame is strictly smaller, as required by its on-disk codec contract.

## Test coverage

`tests/test_crypto.c` contains the public XChaCha20-Poly1305 draft vector,
SHA-256 and HMAC-SHA-256 known answers; AEAD tamper/AAD and failure-zeroing
checks; password validation and KDF bounds; key separation; randomized nonce
uniqueness sampling and AEAD round trips; plus raw/compressed block round trips
and malformed-frame, length, codec and level rejection checks. The KDF test uses
the minimum permitted reader parameters to avoid paying creation cost in the
basic crypto test.
