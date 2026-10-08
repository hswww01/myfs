#include "cryptfs_crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include <sodium.h>
#include <zstd.h>
#include <zstd_errors.h>

#define CF_BLOCK_BYTES 65536u
#define CF_PASSWORD_MAX 1024u
#define CF_KDF_OPS_MIN 1u
#define CF_KDF_OPS_MAX 6u
#define CF_KDF_MEM_MIN (64ULL * 1024ULL * 1024ULL)
#define CF_KDF_MEM_MAX (512ULL * 1024ULL * 1024ULL)
#define CF_ZSTD_WINDOW_LOG_MAX 16

static bool
cf_utf8_valid(const uint8_t *bytes, size_t length)
{
    size_t i = 0;

    while (i < length) {
        uint32_t codepoint;
        uint8_t first = bytes[i++];
        size_t continuation_count;

        if (first <= 0x7f) {
            codepoint = first;
            continuation_count = 0;
        } else if (first >= 0xc2 && first <= 0xdf) {
            codepoint = (uint32_t) (first & 0x1f);
            continuation_count = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            codepoint = (uint32_t) (first & 0x0f);
            continuation_count = 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            codepoint = (uint32_t) (first & 0x07);
            continuation_count = 3;
        } else {
            return false;
        }

        if (continuation_count > length - i) {
            return false;
        }
        while (continuation_count-- != 0) {
            uint8_t next = bytes[i++];
            if ((next & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (uint32_t) (next & 0x3f);
        }

        if ((first >= 0xc2 && first <= 0xdf && codepoint < 0x80) ||
            (first >= 0xe0 && first <= 0xef && codepoint < 0x800) ||
            (first >= 0xf0 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) ||
            codepoint > 0x10ffff) {
            return false;
        }
    }
    return true;
}

bool
cf_crypto_init(void)
{
    return sodium_init() >= 0;
}

void
cf_random(void *buffer, size_t length)
{
    if (buffer == NULL || length == 0) {
        return;
    }
    if (!cf_crypto_init()) {
        cf_wipe(buffer, length);
        return;
    }
    randombytes_buf(buffer, length);
}

void
cf_wipe(void *buffer, size_t length)
{
    if (buffer != NULL && length != 0) {
        sodium_memzero(buffer, length);
    }
}

bool
cf_password_valid(const uint8_t *password, size_t length)
{
    size_t i;

    if (password == NULL || length == 0 || length > CF_PASSWORD_MAX) {
        return false;
    }
    for (i = 0; i < length; ++i) {
        if (password[i] == 0 || password[i] == '\r' || password[i] == '\n') {
            return false;
        }
    }
    return cf_utf8_valid(password, length);
}

bool
cf_password_key(const uint8_t *password, size_t password_length,
                const uint8_t salt[CF_SALT_BYTES], uint64_t ops,
                uint64_t mem_bytes, uint8_t key[CF_KEY_BYTES])
{
    if (key == NULL) {
        return false;
    }
    cf_wipe(key, CF_KEY_BYTES);
    if (!cf_password_valid(password, password_length) || salt == NULL ||
        ops < CF_KDF_OPS_MIN || ops > CF_KDF_OPS_MAX ||
        mem_bytes < CF_KDF_MEM_MIN || mem_bytes > CF_KDF_MEM_MAX ||
        mem_bytes > (uint64_t) SIZE_MAX ||
        ops > (uint64_t) crypto_pwhash_OPSLIMIT_MAX ||
        mem_bytes > (uint64_t) crypto_pwhash_MEMLIMIT_MAX ||
        !cf_crypto_init()) {
        return false;
    }
    if (crypto_pwhash(key, CF_KEY_BYTES, (const char *) password,
                      (unsigned long long) password_length, salt,
                      (unsigned long long) ops, (size_t) mem_bytes,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        cf_wipe(key, CF_KEY_BYTES);
        return false;
    }
    return true;
}

bool
cf_keys_derive(const uint8_t master[CF_KEY_BYTES], CF_KEYS *keys)
{
    static const char records_context[] = "cfrec001";
    static const char journal_context[] = "cfwal001";
    static const char header_context[] = "cfhdr001";

    if (keys == NULL) {
        return false;
    }
    cf_wipe(keys, sizeof(*keys));
    if (master == NULL || !cf_crypto_init()) {
        return false;
    }
    if (crypto_kdf_derive_from_key(keys->records, sizeof(keys->records), 1,
                                   records_context, master) != 0 ||
        crypto_kdf_derive_from_key(keys->journal, sizeof(keys->journal), 2,
                                   journal_context, master) != 0 ||
        crypto_kdf_derive_from_key(keys->header, sizeof(keys->header), 3,
                                   header_context, master) != 0) {
        cf_wipe(keys, sizeof(*keys));
        return false;
    }
    return true;
}

static bool
cf_aead_lengths_valid(size_t aad_length, size_t data_length)
{
    (void) aad_length;
    return data_length <= crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX &&
           data_length <= (size_t) ULLONG_MAX -
           crypto_aead_xchacha20poly1305_ietf_ABYTES &&
           aad_length <= (size_t) ULLONG_MAX;
}

bool
cf_encrypt(const uint8_t key[CF_KEY_BYTES], const uint8_t nonce[CF_NONCE_BYTES],
           const void *aad, size_t aad_length, const void *plain,
           size_t plain_length, void *cipher, size_t cipher_capacity)
{
    static const uint8_t empty = 0;
    uint8_t *temporary = NULL;
    unsigned long long cipher_length = 0;
    size_t required = 0;
    bool success = false;

    if (key == NULL || nonce == NULL || cipher == NULL ||
        (aad_length != 0 && aad == NULL) ||
        (plain_length != 0 && plain == NULL) ||
        !cf_aead_lengths_valid(aad_length, plain_length) ||
        plain_length > SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        goto cleanup;
    }
    required = plain_length + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (cipher_capacity < required || !cf_crypto_init()) {
        goto cleanup;
    }

    temporary = (uint8_t *) malloc(required);
    if (temporary == NULL) {
        goto cleanup;
    }
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            temporary, &cipher_length,
            plain_length != 0 ? (const unsigned char *) plain : &empty,
            (unsigned long long) plain_length,
            aad_length != 0 ? (const unsigned char *) aad : &empty,
            (unsigned long long) aad_length, NULL, nonce, key) != 0 ||
        cipher_length != (unsigned long long) required) {
        goto cleanup;
    }
    memcpy(cipher, temporary, required);
    success = true;

cleanup:
    if (temporary != NULL) {
        cf_wipe(temporary, required);
        free(temporary);
    }
    if (!success && cipher != NULL && cipher_capacity != 0) {
        cf_wipe(cipher, cipher_capacity);
    }
    return success;
}

bool
cf_decrypt(const uint8_t key[CF_KEY_BYTES], const uint8_t nonce[CF_NONCE_BYTES],
           const void *aad, size_t aad_length, const void *cipher,
           size_t cipher_length, void *plain, size_t plain_capacity,
           size_t *plain_length)
{
    static const uint8_t empty = 0;
    uint8_t empty_output = 0;
    uint8_t *temporary = NULL;
    unsigned long long actual_length = 0;
    size_t required = 0;
    bool success = false;

    if (plain_length != NULL) {
        *plain_length = 0;
    }
    if (plain != NULL && plain_capacity != 0) {
        cf_wipe(plain, plain_capacity);
    }
    if (key == NULL || nonce == NULL || plain_length == NULL ||
        (aad_length != 0 && aad == NULL) ||
        (cipher_length != 0 && cipher == NULL) ||
        cipher_length < crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        !cf_aead_lengths_valid(aad_length,
                               cipher_length - crypto_aead_xchacha20poly1305_ietf_ABYTES)) {
        goto cleanup;
    }
    required = cipher_length - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (required > plain_capacity || (required != 0 && plain == NULL) ||
        !cf_crypto_init()) {
        goto cleanup;
    }
    temporary = (uint8_t *) malloc(required == 0 ? 1 : required);
    if (temporary == NULL) {
        goto cleanup;
    }
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            required != 0 ? temporary : &empty_output,
            &actual_length, NULL, (const unsigned char *) cipher,
            (unsigned long long) cipher_length,
            aad_length != 0 ? (const unsigned char *) aad : &empty,
            (unsigned long long) aad_length, nonce, key) != 0 ||
        actual_length != (unsigned long long) required) {
        goto cleanup;
    }
    if (required != 0) {
        memcpy(plain, temporary, required);
    }
    if (plain != NULL && plain_capacity > required) {
        cf_wipe((uint8_t *) plain + required, plain_capacity - required);
    }
    *plain_length = required;
    success = true;

cleanup:
    if (temporary != NULL) {
        cf_wipe(temporary, required);
        free(temporary);
    }
    if (!success) {
        if (plain != NULL && plain_capacity != 0) {
            cf_wipe(plain, plain_capacity);
        }
        if (plain_length != NULL) {
            *plain_length = 0;
        }
    }
    cf_wipe(&empty_output, sizeof(empty_output));
    return success;
}

void
cf_mac(const uint8_t key[CF_KEY_BYTES], const void *data, size_t length,
       uint8_t out[32])
{
    static const uint8_t empty = 0;

    if (out == NULL) {
        return;
    }
    cf_wipe(out, 32);
    if (key == NULL || (length != 0 && data == NULL) ||
        length > (size_t) ULLONG_MAX || !cf_crypto_init()) {
        return;
    }
    if (crypto_auth_hmacsha256(out,
                               length != 0 ? (const unsigned char *) data : &empty,
                               (unsigned long long) length, key) != 0) {
        cf_wipe(out, 32);
    }
}

bool
cf_mac_verify(const uint8_t expected[32], const uint8_t actual[32])
{
    if (expected == NULL || actual == NULL || !cf_crypto_init()) {
        return false;
    }
    return sodium_memcmp(expected, actual, 32) == 0;
}

void
cf_hash(const void *data, size_t length, uint8_t out[32])
{
    static const uint8_t empty = 0;

    if (out == NULL) {
        return;
    }
    cf_wipe(out, 32);
    if ((length != 0 && data == NULL) || length > (size_t) ULLONG_MAX ||
        !cf_crypto_init()) {
        return;
    }
    if (crypto_hash_sha256(out,
                           length != 0 ? (const unsigned char *) data : &empty,
                           (unsigned long long) length) != 0) {
        cf_wipe(out, 32);
    }
}

/*
 * Per-thread codec contexts. Creating a context per 64 KiB block allocated and
 * initialized several hundred KiB of tables on every call. A fiber-local slot
 * frees them when the thread exits. As before (see CRYPTO.md), zstd's internal
 * context memory is not securely erased.
 */
typedef struct CF_CODEC_CACHE {
    ZSTD_CCtx *compress;
    ZSTD_DCtx *decompress;
} CF_CODEC_CACHE;

static INIT_ONCE g_codec_once = INIT_ONCE_STATIC_INIT;
static DWORD g_codec_slot = FLS_OUT_OF_INDEXES;

static void WINAPI
cf_codec_cache_free(void *value)
{
    CF_CODEC_CACHE *cache = (CF_CODEC_CACHE *) value;

    if (cache == NULL) {
        return;
    }
    (void) ZSTD_freeCCtx(cache->compress);
    (void) ZSTD_freeDCtx(cache->decompress);
    free(cache);
}

static BOOL CALLBACK
cf_codec_slot_init(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    (void) once;
    (void) parameter;
    (void) context;
    g_codec_slot = FlsAlloc(cf_codec_cache_free);
    return TRUE;
}

static CF_CODEC_CACHE *
cf_codec_cache(void)
{
    CF_CODEC_CACHE *cache;

    if (!InitOnceExecuteOnce(&g_codec_once, cf_codec_slot_init, NULL, NULL) ||
        g_codec_slot == FLS_OUT_OF_INDEXES) {
        return NULL;
    }
    cache = (CF_CODEC_CACHE *) FlsGetValue(g_codec_slot);
    if (cache == NULL) {
        cache = (CF_CODEC_CACHE *) calloc(1, sizeof(*cache));
        if (cache == NULL) {
            return NULL;
        }
        if (!FlsSetValue(g_codec_slot, cache)) {
            free(cache);
            return NULL;
        }
    }
    return cache;
}

static ZSTD_CCtx *
cf_compress_context(void)
{
    CF_CODEC_CACHE *cache = cf_codec_cache();

    if (cache == NULL) {
        return NULL;
    }
    if (cache->compress == NULL) {
        cache->compress = ZSTD_createCCtx();
    } else {
        (void) ZSTD_CCtx_reset(cache->compress, ZSTD_reset_session_and_parameters);
    }
    return cache->compress;
}

static ZSTD_DCtx *
cf_decompress_context(void)
{
    CF_CODEC_CACHE *cache = cf_codec_cache();

    if (cache == NULL) {
        return NULL;
    }
    if (cache->decompress == NULL) {
        cache->decompress = ZSTD_createDCtx();
    } else {
        (void) ZSTD_DCtx_reset(cache->decompress, ZSTD_reset_session_and_parameters);
    }
    return cache->decompress;
}

bool
cf_block_encode(const uint8_t raw[CF_BLOCK_BYTES], int level,
                uint8_t encoded[CF_BLOCK_BYTES], uint32_t *length,
                uint32_t *codec)
{
    ZSTD_CCtx *context;
    size_t result;

    if (length != NULL) {
        *length = 0;
    }
    if (codec != NULL) {
        *codec = 0;
    }
    if (encoded != NULL) {
        cf_wipe(encoded, CF_BLOCK_BYTES);
    }
    if (raw == NULL || encoded == NULL || length == NULL || codec == NULL ||
        level < ZSTD_minCLevel() || level > ZSTD_maxCLevel()) {
        return false;
    }
    context = cf_compress_context();
    if (context == NULL ||
        ZSTD_isError(ZSTD_CCtx_setParameter(context, ZSTD_c_compressionLevel,
                                             level)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(context, ZSTD_c_windowLog, 16))) {
        return false;
    }
    /* Only a frame strictly smaller than the block is useful, so compress
     * straight into the output with one byte less room; "destination too
     * small" then means the raw codec. */
    result = ZSTD_compress2(context, encoded, CF_BLOCK_BYTES - 1u, raw,
                            CF_BLOCK_BYTES);
    if (!ZSTD_isError(result)) {
        *length = (uint32_t) result;
        *codec = 1;
        return true;
    }
    if (ZSTD_getErrorCode(result) != ZSTD_error_dstSize_tooSmall) {
        cf_wipe(encoded, CF_BLOCK_BYTES);
        return false;
    }
    memcpy(encoded, raw, CF_BLOCK_BYTES);
    *length = CF_BLOCK_BYTES;
    *codec = 0;
    return true;
}

bool
cf_block_decode(const uint8_t *encoded, uint32_t length, uint32_t codec,
                uint8_t raw[CF_BLOCK_BYTES])
{
    ZSTD_DCtx *context;
    ZSTD_inBuffer input;
    ZSTD_outBuffer output;
    size_t frame_size;
    unsigned long long frame_content_size;
    size_t remaining = 1;
    bool success = false;

    if (raw != NULL) {
        cf_wipe(raw, CF_BLOCK_BYTES);
    }
    if (raw == NULL || encoded == NULL || length == 0 ||
        length > ZSTD_compressBound(CF_BLOCK_BYTES)) {
        return false;
    }
    if (codec == 0) {
        if (length != CF_BLOCK_BYTES) {
            return false;
        }
        memcpy(raw, encoded, CF_BLOCK_BYTES);
        return true;
    }
    if (codec != 1) {
        return false;
    }

    frame_size = ZSTD_findFrameCompressedSize(encoded, length);
    frame_content_size = ZSTD_getFrameContentSize(encoded, length);
    if (ZSTD_isError(frame_size) || frame_size != length ||
        frame_content_size != CF_BLOCK_BYTES) {
        return false;
    }

    /* Decode straight into the caller's block; every failure path wipes it. */
    context = cf_decompress_context();
    if (context == NULL) {
        goto cleanup;
    }
    if (ZSTD_isError(ZSTD_DCtx_setParameter(context, ZSTD_d_windowLogMax,
                                             CF_ZSTD_WINDOW_LOG_MAX))) {
        goto cleanup;
    }
    input.src = encoded;
    input.size = length;
    input.pos = 0;
    output.dst = raw;
    output.size = CF_BLOCK_BYTES;
    output.pos = 0;
    while (input.pos < input.size && remaining != 0) {
        size_t old_input_pos = input.pos;
        size_t old_output_pos = output.pos;

        remaining = ZSTD_decompressStream(context, &output, &input);
        if (ZSTD_isError(remaining) || output.pos > CF_BLOCK_BYTES ||
            (old_input_pos == input.pos && old_output_pos == output.pos)) {
            goto cleanup;
        }
        if (remaining != 0 && output.pos == CF_BLOCK_BYTES) {
            goto cleanup;
        }
    }
    if (remaining != 0 || input.pos != input.size ||
        output.pos != CF_BLOCK_BYTES) {
        goto cleanup;
    }
    success = true;

cleanup:
    if (!success) {
        cf_wipe(raw, CF_BLOCK_BYTES);
    }
    return success;
}
