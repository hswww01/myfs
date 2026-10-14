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
	/* Directories (relative to the volume root) created once the new NTFS
	 * volume is mounted, e.g. a %TEMP% folder. */
	const wchar_t* const* initial_directories;
	uint32_t initial_directory_count;
	/* Optional service hooks. progress extends the start wait while aim_ll
	 * attaches and formats; ready is called once the volume serves I/O and
	 * a false return stops (and detaches) again. */
	void* callback_context;
	bool (*report_progress)(void* context, DWORD wait_hint_ms);
	bool (*report_ready)(void* context);
} MemfsBlockRunConfig;

/* Locates aim_ll.exe: the configured path, next to memfs.exe, then PATH.
 * Writes an absolute path. */
bool memfs_block_find_aim_ll(const wchar_t* configured, wchar_t* path, DWORD count);

/* Default virtual disk size: the fixed capacity, or total physical memory in
 * auto mode, rounded down to 1 MiB. */
uint64_t memfs_block_default_disk_size(bool capacity_auto, uint64_t capacity);

/* Creates the store, attaches an AIM disk formatted NTFS at mount_point and
 * serves it until stop_event is set; then detaches and frees everything.
 * Returns a process exit code: 0 after a requested stop, 8 when the disk
 * was detached by someone else, other values on failures. */
int memfs_block_run(const MemfsBlockRunConfig* config, HANDLE stop_event);
