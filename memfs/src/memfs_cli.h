#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "memfs_core.h"

enum { MEMFS_CLI_MAX_DISPATCHER_THREADS = 64 };

bool memfs_cli_parse_size(const wchar_t* text,
                          uint64_t* out,
                          bool* auto_size);
bool memfs_cli_parse_u32(const wchar_t* text, uint32_t* out);
bool memfs_cli_thread_count_valid(uint32_t thread_count);
bool memfs_cli_parse_key_hex(
    const wchar_t* text,
    uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE]);
void memfs_cli_wipe_fixed_key(
    uint8_t key[MEMFS_ENCRYPTION_KEY_SIZE],
    bool* have_fixed_key);
