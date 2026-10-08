#include <Windows.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "memfs_cli.h"

static int g_failures;

#define CHECK(expr)                                                            \
    do {                                                                       \
        if (!(expr)) {                                                         \
            fwprintf(stderr, L"CHECK failed: %S:%d: %S\n",                   \
                     __FILE__, __LINE__, #expr);                               \
            g_failures++;                                                      \
        }                                                                      \
    } while (0)

static bool all_zero(const uint8_t* data, size_t size) {
    size_t i;
    for (i = 0; i < size; ++i) {
        if (data[i] != 0)
            return false;
    }
    return true;
}

int wmain(void) {
    uint64_t size = 0;
    uint32_t value = 0;
    bool auto_size = false;
    bool have_fixed_key = true;
    uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE];
    static const wchar_t valid_key[] =
        L"000102030405060708090a0b0c0d0e0f"
        L"101112131415161718191a1b1c1d1e1f";

    CHECK(memfs_cli_parse_size(L"auto", &size, &auto_size));
    CHECK(auto_size);
    CHECK(size == 0);

    auto_size = true;
    CHECK(memfs_cli_parse_size(L"1", &size, &auto_size));
    CHECK(!auto_size);
    CHECK(size == 1);

    CHECK(memfs_cli_parse_size(L"64K", &size, &auto_size));
    CHECK(size == 64ULL * 1024ULL);
    CHECK(memfs_cli_parse_size(L"2m", &size, &auto_size));
    CHECK(size == 2ULL * 1024ULL * 1024ULL);
    CHECK(memfs_cli_parse_size(L"3G", &size, &auto_size));
    CHECK(size == 3ULL * 1024ULL * 1024ULL * 1024ULL);

    CHECK(!memfs_cli_parse_size(NULL, &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"0", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"-1", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"+1", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L" 1", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"1T", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"1KB", &size, &auto_size));
    CHECK(!memfs_cli_parse_size(L"9223372036854775808", &size, &auto_size));
    CHECK(memfs_cli_parse_size(L"9223372036854775807", &size, &auto_size));
    CHECK(size == INT64_MAX);
    CHECK(!memfs_cli_parse_size(L"9007199254740992K", &size, &auto_size));

    CHECK(memfs_cli_parse_u32(L"0", &value));
    CHECK(value == 0);
    CHECK(memfs_cli_parse_u32(L"4294967295", &value));
    CHECK(value == UINT32_MAX);
    CHECK(!memfs_cli_parse_u32(L"4294967296", &value));
    CHECK(!memfs_cli_parse_u32(L"-1", &value));
    CHECK(!memfs_cli_parse_u32(L"+1", &value));
    CHECK(!memfs_cli_parse_u32(L" 1", &value));
    CHECK(!memfs_cli_parse_u32(L"0x10", &value));

    CHECK(memfs_cli_thread_count_valid(0));
    CHECK(!memfs_cli_thread_count_valid(1));
    CHECK(memfs_cli_thread_count_valid(2));
    CHECK(memfs_cli_thread_count_valid(64));
    CHECK(!memfs_cli_thread_count_valid(65));
    CHECK(!memfs_cli_thread_count_valid(UINT32_MAX));

    memset(key, 0xa5, sizeof(key));
    CHECK(memfs_cli_parse_key_hex(valid_key, key));
    CHECK(key[0] == 0x00);
    CHECK(key[1] == 0x01);
    CHECK(key[30] == 0x1e);
    CHECK(key[31] == 0x1f);

    memset(key, 0xa5, sizeof(key));
    CHECK(!memfs_cli_parse_key_hex(L"gg0102030405060708090a0b0c0d0e0f"
                                   L"101112131415161718191a1b1c1d1e1f",
                                   key));
    CHECK(all_zero(key, sizeof(key)));

    memset(key, 0xa5, sizeof(key));
    CHECK(!memfs_cli_parse_key_hex(L"00", key));
    CHECK(all_zero(key, sizeof(key)));

    memset(key, 0xa5, sizeof(key));
    have_fixed_key = true;
    memfs_cli_wipe_fixed_key(key, &have_fixed_key);
    CHECK(!have_fixed_key);
    CHECK(all_zero(key, sizeof(key)));

    if (g_failures != 0) {
        fprintf(stderr, "memfs_cli_test: %d failure(s)\n", g_failures);
        return 1;
    }

    printf("memfs_cli_test: OK\n");
    return 0;
}
