#include "memfs_cli.h"

#include <Windows.h>

#include <errno.h>
#include <limits.h>
#include <wchar.h>
#include <wctype.h>

static bool unsigned_text_start_valid(const wchar_t* text) {
    return text != NULL &&
           text[0] != L'\0' &&
           text[0] != L'+' &&
           text[0] != L'-' &&
           !iswspace(text[0]);
}

bool memfs_cli_parse_size(const wchar_t* text,
                          uint64_t* out,
                          bool* auto_size) {
    wchar_t* end;
    unsigned long long value;
    uint64_t multiplier = 1;

    if (text == NULL || *text == L'\0' || out == NULL)
        return false;

    if (auto_size)
        *auto_size = false;

    if (_wcsicmp(text, L"auto") == 0) {
        if (auto_size)
            *auto_size = true;
        *out = 0;
        return true;
    }

    if (!unsigned_text_start_valid(text))
        return false;

    errno = 0;
    value = wcstoull(text, &end, 10);
    if (errno || end == text)
        return false;

    if (*end) {
        if (end[1] != L'\0')
            return false;

        switch (towupper(*end)) {
        case L'K':
            multiplier = 1024ULL;
            break;
        case L'M':
            multiplier = 1024ULL * 1024ULL;
            break;
        case L'G':
            multiplier = 1024ULL * 1024ULL * 1024ULL;
            break;
        default:
            return false;
        }
    }

    if (value == 0 ||
        value > (unsigned long long)INT64_MAX / multiplier) {
        return false;
    }

    *out = (uint64_t)value * multiplier;
    return true;
}

bool memfs_cli_parse_u32(const wchar_t* text, uint32_t* out) {
    wchar_t* end;
    unsigned long value;

    if (!unsigned_text_start_valid(text) || out == NULL)
        return false;

    errno = 0;
    value = wcstoul(text, &end, 10);
    if (errno || end == text || *end || value > UINT32_MAX)
        return false;

    *out = (uint32_t)value;
    return true;
}

bool memfs_cli_thread_count_valid(uint32_t thread_count) {
    return thread_count == 0U ||
           (thread_count >= 2U &&
            thread_count <= MEMFS_CLI_MAX_DISPATCHER_THREADS);
}

static int hex_value(wchar_t c) {
    if (c >= L'0' && c <= L'9')
        return (int)(c - L'0');
    if (c >= L'a' && c <= L'f')
        return (int)(c - L'a') + 10;
    if (c >= L'A' && c <= L'F')
        return (int)(c - L'A') + 10;
    return -1;
}

bool memfs_cli_parse_key_hex(
    const wchar_t* text,
    uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE]) {
    uint32_t i;

    if (key == NULL)
        return false;

    SecureZeroMemory(key, MEMFS_ENCRYPTION_KEY_SIZE);
    if (text == NULL ||
        wcslen(text) != MEMFS_ENCRYPTION_KEY_SIZE * 2U) {
        return false;
    }

    for (i = 0; i < MEMFS_ENCRYPTION_KEY_SIZE; ++i) {
        int hi = hex_value(text[i * 2U]);
        int lo = hex_value(text[i * 2U + 1U]);

        if (hi < 0 || lo < 0) {
            SecureZeroMemory(key, MEMFS_ENCRYPTION_KEY_SIZE);
            return false;
        }

        key[i] = (uint8_t)((hi << 4) | lo);
    }

    return true;
}

void memfs_cli_wipe_fixed_key(
    uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE],
    bool* have_fixed_key) {
    if (key)
        SecureZeroMemory(key, MEMFS_ENCRYPTION_KEY_SIZE);
    if (have_fixed_key)
        *have_fixed_key = false;
}
