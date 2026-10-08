#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CF_KEY_BYTES 32u
#define CF_NONCE_BYTES 24u
#define CF_TAG_BYTES 16u
#define CF_SALT_BYTES 16u
#define CF_KDF_OPS 3u
#define CF_KDF_MEM (256ULL * 1024 * 1024)

typedef struct CF_KEYS { uint8_t records[32], journal[32], header[32]; } CF_KEYS;
bool cf_crypto_init(void);
void cf_random(void *buffer, size_t length);
void cf_wipe(void *buffer, size_t length);
bool cf_password_valid(const uint8_t *, size_t);
bool cf_password_key(const uint8_t *, size_t, const uint8_t salt[16],
    uint64_t ops, uint64_t mem_bytes, uint8_t key[32]);
bool cf_keys_derive(const uint8_t master[32], CF_KEYS *keys);
bool cf_encrypt(const uint8_t key[32], const uint8_t nonce[24],
    const void *aad, size_t aad_length, const void *plain, size_t plain_length,
    void *cipher, size_t cipher_capacity);
bool cf_decrypt(const uint8_t key[32], const uint8_t nonce[24],
    const void *aad, size_t aad_length, const void *cipher, size_t cipher_length,
    void *plain, size_t plain_capacity, size_t *plain_length);
void cf_mac(const uint8_t key[32], const void *, size_t, uint8_t out[32]);
bool cf_mac_verify(const uint8_t expected[32], const uint8_t actual[32]);
void cf_hash(const void *, size_t, uint8_t out[32]);
/* Input exactly one logical block. codec 0=raw, 1=zstd. */
bool cf_block_encode(const uint8_t raw[65536], int level,
    uint8_t encoded[65536], uint32_t *length, uint32_t *codec);
bool cf_block_decode(const uint8_t *encoded, uint32_t length, uint32_t codec,
    uint8_t raw[65536]);
