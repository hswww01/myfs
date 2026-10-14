#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#include "memfs_core.h"

/* Console runner for the block-device mode (--block). */
typedef struct MemfsBlockRunConfig {
	const wchar_t* mount_point;     /* drive letter such as L"X:" */
	const wchar_t* volume_label;
	const wchar_t* aim_ll_path;     /* NULL: next to memfs.exe, then PATH */
	const wchar_t* object_name;     /* NULL: memfs-block-<pid> */
	uint64_t capacity;              /* resident memory limit (fixed mode) */
	bool capacity_auto;
	uint64_t auto_reserve;
	uint64_t disk_size;             /* 0: derived from capacity / RAM */
	uint32_t threads;
	bool compression_enabled;
	int compression_level;
	bool encryption_enabled;
	const uint8_t* encryption_key;  /* optional fixed key */
	size_t encryption_key_size;
	bool stats;
	bool stats_json;
} MemfsBlockRunConfig;

/* Default virtual disk size: the fixed capacity, or total physical memory in
 * auto mode, rounded down to 1 MiB. */
uint64_t memfs_block_default_disk_size(bool capacity_auto, uint64_t capacity);

/* Creates the store, attaches an AIM disk formatted NTFS at mount_point and
 * serves it until stop_event is set; then detaches and frees everything.
 * Returns a process exit code. */
int memfs_block_run(const MemfsBlockRunConfig* config, HANDLE stop_event);
