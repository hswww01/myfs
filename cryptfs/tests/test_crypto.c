#include "cryptfs_crypto.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

#define BLOCK_BYTES 65536u
#define AAD_BYTES 12u
#define KDF_MEM_MIN (64ULL * 1024ULL * 1024ULL)
#define KDF_MEM_MAX (512ULL * 1024ULL * 1024ULL)

static int
hex_nibble(char value, uint8_t *nibble)
{
    if (value >= '0' && value <= '9') {
        *nibble = (uint8_t) (value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *nibble = (uint8_t) (value - 'a' + 10);
        return 1;
    }
    if (value >= 'A' && value <= 'F') {
        *nibble = (uint8_t) (value - 'A' + 10);
        return 1;
    }
    return 0;
}

static int
hex_decode(const char *hex, uint8_t *out, size_t capacity, size_t *written)
{
    size_t i;
    size_t length;

    if (hex == NULL || out == NULL || written == NULL) {
        return 0;
    }
    length = strlen(hex);
    if ((length & 1u) != 0 || length / 2 > capacity) {
        return 0;
    }
    for (i = 0; i < length / 2; ++i) {
        uint8_t high, low;
        if (!hex_nibble(hex[i * 2], &high) ||
            !hex_nibble(hex[i * 2 + 1], &low)) {
            return 0;
        }
        out[i] = (uint8_t) ((high << 4) | low);
    }
    *written = length / 2;
    return 1;
}

static int
test_xchacha_vector(void)
{
    static const char key_hex[] =
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f";
    static const char nonce_hex[] =
        "404142434445464748494a4b4c4d4e4f5051525354555657";
    static const char aad_hex[] = "50515253c0c1c2c3c4c5c6c7";
    static const char expected_hex[] =
        "bd6d179d3e83d43b9576579493c0e939"
        "572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39"
        "ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e"
        "3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13"
        "b52ec0875924c1c7987947deafd8780acf49";
    static const uint8_t message[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    uint8_t key[CF_KEY_BYTES];
    uint8_t nonce[CF_NONCE_BYTES];
    uint8_t aad[AAD_BYTES];
    uint8_t expected[sizeof(expected_hex) / 2];
    uint8_t cipher[sizeof(expected_hex) / 2];
    uint8_t plain[sizeof(message)];
    size_t key_length = 0, nonce_length = 0, aad_length = 0;
    size_t expected_length = 0, plain_length = 0;

    CHECK(hex_decode(key_hex, key, sizeof(key), &key_length));
    CHECK(hex_decode(nonce_hex, nonce, sizeof(nonce), &nonce_length));
    CHECK(hex_decode(aad_hex, aad, sizeof(aad), &aad_length));
    CHECK(hex_decode(expected_hex, expected, sizeof(expected), &expected_length));
    CHECK(key_length == sizeof(key));
    CHECK(nonce_length == sizeof(nonce));
    CHECK(aad_length == sizeof(aad));
    CHECK(expected_length == sizeof(cipher));
    CHECK(cf_encrypt(key, nonce, aad, sizeof(aad), message,
                     sizeof(message) - 1, cipher, sizeof(cipher)));
    CHECK(memcmp(cipher, expected, sizeof(cipher)) == 0);
    CHECK(cf_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                     plain, sizeof(plain), &plain_length));
    CHECK(plain_length == sizeof(message) - 1);
    CHECK(memcmp(plain, message, plain_length) == 0);

    /* A modified tag and a modified AAD must leave no plaintext behind. */
    memset(plain, 0xa5, sizeof(plain));
    expected[sizeof(expected) - 1] ^= 1;
    CHECK(!cf_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                      plain, sizeof(plain), &plain_length));
    CHECK(plain_length == 0);
    CHECK(memcmp(plain, (uint8_t[sizeof(plain)]){0}, sizeof(plain)) == 0);
    expected[sizeof(expected) - 1] ^= 1;
    aad[0] ^= 1;
    memset(plain, 0xa5, sizeof(plain));
    CHECK(!cf_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                      plain, sizeof(plain), &plain_length));
    CHECK(plain_length == 0);
    CHECK(memcmp(plain, (uint8_t[sizeof(plain)]){0}, sizeof(plain)) == 0);
    aad[0] ^= 1;
    nonce[0] ^= 1;
    memset(plain, 0xa5, sizeof(plain));
    CHECK(!cf_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                      plain, sizeof(plain), &plain_length));
    CHECK(plain_length == 0);
    CHECK(memcmp(plain, (uint8_t[sizeof(plain)]){0}, sizeof(plain)) == 0);
    nonce[0] ^= 1;
    key[0] ^= 1;
    memset(plain, 0xa5, sizeof(plain));
    CHECK(!cf_decrypt(key, nonce, aad, sizeof(aad), expected, sizeof(expected),
                      plain, sizeof(plain), &plain_length));
    CHECK(plain_length == 0);
    CHECK(memcmp(plain, (uint8_t[sizeof(plain)]){0}, sizeof(plain)) == 0);
    key[0] ^= 1;

    cf_wipe(key, sizeof(key));
    cf_wipe(nonce, sizeof(nonce));
    cf_wipe(aad, sizeof(aad));
    cf_wipe(expected, sizeof(expected));
    cf_wipe(cipher, sizeof(cipher));
    cf_wipe(plain, sizeof(plain));
    return 0;
}

static int
test_crypto_bounds_and_keys(void)
{
    static const uint8_t valid_password[] = { 'p', 'a', 's', 's' };
    static const uint8_t invalid_nul[] = { 'a', 0, 'b' };
    static const uint8_t invalid_cr[] = { 'a', '\r' };
    static const uint8_t invalid_lf[] = { 'a', '\n' };
    static const uint8_t invalid_utf8[] = { 0xc0, 0x80 };
    uint8_t salt[CF_SALT_BYTES] = { 0 };
    uint8_t wrap_key[CF_KEY_BYTES];
    uint8_t master[CF_KEY_BYTES];
    uint8_t short_cipher[CF_TAG_BYTES - 1] = { 0 };
    uint8_t output[32];
    uint8_t too_small[2] = { 0xa5, 0xa5 };
    size_t output_length = 99;
    CF_KEYS keys;

    CHECK(cf_password_valid(valid_password, sizeof(valid_password)));
    CHECK(!cf_password_valid(NULL, 1));
    CHECK(!cf_password_valid(valid_password, 0));
    CHECK(!cf_password_valid(invalid_nul, sizeof(invalid_nul)));
    CHECK(!cf_password_valid(invalid_cr, sizeof(invalid_cr)));
    CHECK(!cf_password_valid(invalid_lf, sizeof(invalid_lf)));
    CHECK(!cf_password_valid(invalid_utf8, sizeof(invalid_utf8)));
    CHECK(!cf_password_valid(valid_password, 1025));

    memset(wrap_key, 0xa5, sizeof(wrap_key));
    CHECK(!cf_password_key(valid_password, sizeof(valid_password), salt, 0,
                           KDF_MEM_MIN, wrap_key));
    CHECK(memcmp(wrap_key, (uint8_t[CF_KEY_BYTES]){0}, sizeof(wrap_key)) == 0);
    memset(wrap_key, 0xa5, sizeof(wrap_key));
    CHECK(!cf_password_key(valid_password, sizeof(valid_password), salt, 7,
                           KDF_MEM_MIN, wrap_key));
    CHECK(memcmp(wrap_key, (uint8_t[CF_KEY_BYTES]){0}, sizeof(wrap_key)) == 0);
    CHECK(!cf_password_key(valid_password, sizeof(valid_password), salt, 1,
                           KDF_MEM_MIN - 1, wrap_key));
    CHECK(!cf_password_key(valid_password, sizeof(valid_password), salt, 1,
                           KDF_MEM_MAX + 1, wrap_key));
    CHECK(cf_password_key(valid_password, sizeof(valid_password), salt, 1,
                          KDF_MEM_MIN, wrap_key));
    CHECK(memcmp(wrap_key, (uint8_t[CF_KEY_BYTES]){0}, sizeof(wrap_key)) != 0);

    memset(master, 0x37, sizeof(master));
    memset(&keys, 0xa5, sizeof(keys));
    CHECK(cf_keys_derive(master, &keys));
    CHECK(memcmp(keys.records, keys.journal, sizeof(keys.records)) != 0);
    CHECK(memcmp(keys.records, keys.header, sizeof(keys.records)) != 0);
    CHECK(memcmp(keys.journal, keys.header, sizeof(keys.journal)) != 0);

    memset(output, 0xa5, sizeof(output));
    CHECK(!cf_decrypt(master, salt, NULL, 0, short_cipher, sizeof(short_cipher),
                      output, sizeof(output), &output_length));
    CHECK(output_length == 0);
    CHECK(memcmp(output, (uint8_t[sizeof(output)]){0}, sizeof(output)) == 0);
    output_length = 99;
    memset(output, 0xa5, sizeof(output));
    CHECK(!cf_decrypt(master, salt, NULL, 0, short_cipher, sizeof(short_cipher),
                      output, sizeof(output), &output_length));
    CHECK(output_length == 0);
    CHECK(memcmp(output, (uint8_t[sizeof(output)]){0}, sizeof(output)) == 0);

    memset(too_small, 0xa5, sizeof(too_small));
    CHECK(!cf_encrypt(master, salt, NULL, 0, valid_password,
                      sizeof(valid_password), too_small, sizeof(too_small)));
    CHECK(memcmp(too_small, (uint8_t[sizeof(too_small)]){0}, sizeof(too_small)) == 0);

    cf_wipe(&keys, sizeof(keys));
    cf_wipe(master, sizeof(master));
    cf_wipe(wrap_key, sizeof(wrap_key));
    return 0;
}

static int
test_random_nonces_and_roundtrip(void)
{
    uint8_t key[CF_KEY_BYTES] = { 0 };
    uint8_t aad[32];
    uint8_t plain[128];
    uint8_t cipher[sizeof(plain) + CF_TAG_BYTES];
    uint8_t recovered[sizeof(plain)];
    uint8_t nonces[1024][CF_NONCE_BYTES];
    uint8_t nonce[CF_NONCE_BYTES];
    size_t plain_length;
    unsigned int i;

    for (i = 0; i < sizeof(aad); ++i) {
        aad[i] = (uint8_t) (i * 7u);
    }
    for (i = 0; i < sizeof(plain); ++i) {
        plain[i] = (uint8_t) (i ^ (i >> 2));
    }
    for (i = 0; i < 1024; ++i) {
        cf_random(nonce, sizeof(nonce));
        {
            unsigned int j;
            for (j = 0; j < i; ++j) {
                CHECK(memcmp(nonce, nonces[j], sizeof(nonce)) != 0);
            }
        }
        memcpy(nonces[i], nonce, sizeof(nonce));
        CHECK(cf_encrypt(key, nonce, aad, sizeof(aad), plain, sizeof(plain),
                         cipher, sizeof(cipher)));
        CHECK(cf_decrypt(key, nonce, aad, sizeof(aad), cipher, sizeof(cipher),
                         recovered, sizeof(recovered), &plain_length));
        CHECK(plain_length == sizeof(plain));
        CHECK(memcmp(recovered, plain, sizeof(plain)) == 0);
    }
    cf_wipe(key, sizeof(key));
    cf_wipe(aad, sizeof(aad));
    cf_wipe(plain, sizeof(plain));
    cf_wipe(cipher, sizeof(cipher));
    cf_wipe(recovered, sizeof(recovered));
    cf_wipe(nonces, sizeof(nonces));
    cf_wipe(nonce, sizeof(nonce));
    return 0;
}

static int
test_hash_and_mac(void)
{
    static const char sha256_abc_hex[] =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";
    static const char hmac_sha256_hex[] =
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7";
    static const uint8_t hmac_message[] = "Hi There";
    uint8_t hash[32], expected_hash[32];
    uint8_t mac[32], expected_mac[32];
    uint8_t hmac_key[20];
    size_t hash_length = 0, mac_length = 0;

    memset(hmac_key, 0x0b, sizeof(hmac_key));
    CHECK(hex_decode(sha256_abc_hex, expected_hash, sizeof(expected_hash),
                     &hash_length));
    CHECK(hash_length == sizeof(hash));
    cf_hash("abc", 3, hash);
    CHECK(memcmp(hash, expected_hash, sizeof(hash)) == 0);

    CHECK(hex_decode(hmac_sha256_hex, expected_mac, sizeof(expected_mac),
                     &mac_length));
    CHECK(mac_length == sizeof(mac));
    cf_mac(hmac_key, hmac_message, sizeof(hmac_message) - 1, mac);
    CHECK(cf_mac_verify(expected_mac, mac));
    mac[0] ^= 1;
    CHECK(!cf_mac_verify(expected_mac, mac));
    cf_wipe(hash, sizeof(hash));
    cf_wipe(expected_hash, sizeof(expected_hash));
    cf_wipe(mac, sizeof(mac));
    cf_wipe(expected_mac, sizeof(expected_mac));
    cf_wipe(hmac_key, sizeof(hmac_key));
    return 0;
}

static int
test_block_codec(void)
{
    uint8_t raw[BLOCK_BYTES];
    uint8_t encoded[BLOCK_BYTES];
    uint8_t decoded[BLOCK_BYTES];
    uint8_t saved[BLOCK_BYTES];
    uint32_t length = 0, codec = 0;

    memset(raw, 'A', sizeof(raw));
    CHECK(cf_block_encode(raw, 3, encoded, &length, &codec));
    CHECK(codec == 1);
    CHECK(length > 0 && length < BLOCK_BYTES);
    CHECK(cf_block_decode(encoded, length, codec, decoded));
    CHECK(memcmp(decoded, raw, sizeof(raw)) == 0);

    cf_random(raw, sizeof(raw));
    memcpy(saved, raw, sizeof(saved));
    CHECK(cf_block_encode(raw, 3, encoded, &length, &codec));
    CHECK(codec == 0);
    CHECK(length == BLOCK_BYTES);
    CHECK(memcmp(encoded, saved, sizeof(saved)) == 0);
    CHECK(cf_block_decode(encoded, length, codec, decoded));
    CHECK(memcmp(decoded, saved, sizeof(saved)) == 0);

    /* A compressed block must be exactly one complete frame and one block. */
    memset(raw, 'B', sizeof(raw));
    CHECK(cf_block_encode(raw, 3, encoded, &length, &codec));
    CHECK(codec == 1 && length < BLOCK_BYTES);
    memset(decoded, 0xa5, sizeof(decoded));
    CHECK(!cf_block_decode(encoded, length - 1, 1, decoded));
    CHECK(memcmp(decoded, (uint8_t[BLOCK_BYTES]){0}, sizeof(decoded)) == 0);
    encoded[length] = 0;
    memset(decoded, 0xa5, sizeof(decoded));
    CHECK(!cf_block_decode(encoded, length + 1, 1, decoded));
    CHECK(memcmp(decoded, (uint8_t[BLOCK_BYTES]){0}, sizeof(decoded)) == 0);
    CHECK(!cf_block_decode(encoded, length, 2, decoded));
    CHECK(!cf_block_decode(encoded, length, 99, decoded));
    CHECK(!cf_block_decode(encoded, 0, 1, decoded));
    CHECK(!cf_block_decode(encoded, BLOCK_BYTES + 1, 1, decoded));
    CHECK(!cf_block_decode(encoded, BLOCK_BYTES - 1, 0, decoded));

    memset(encoded, 0xa5, sizeof(encoded));
    length = 7;
    codec = 7;
    CHECK(!cf_block_encode(raw, INT_MAX, encoded, &length, &codec));
    CHECK(length == 0 && codec == 0);
    CHECK(memcmp(encoded, (uint8_t[BLOCK_BYTES]){0}, sizeof(encoded)) == 0);
    cf_wipe(raw, sizeof(raw));
    cf_wipe(encoded, sizeof(encoded));
    cf_wipe(decoded, sizeof(decoded));
    cf_wipe(saved, sizeof(saved));
    return 0;
}

int
main(void)
{
    CHECK(cf_crypto_init());
    CHECK(test_xchacha_vector() == 0);
    CHECK(test_crypto_bounds_and_keys() == 0);
    CHECK(test_random_nonces_and_roundtrip() == 0);
    CHECK(test_hash_and_mac() == 0);
    CHECK(test_block_codec() == 0);
    puts("cryptfs crypto tests passed");
    return 0;
}
