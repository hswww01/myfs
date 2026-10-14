#pragma once

/*
 * DevIoDrv provider: serves a MemfsBlock as the backing store of an Arsenal
 * Image Mounter (AIM) virtual disk.
 *
 * Only the public ImDisk/DevIoDrv proxy protocol is used (imdproxy.h,
 * MIT-licensed); no AIM code is linked. memfs opens \\?\DevIoDrv\<name> as
 * the server end; AIM's miniport is then attached to the same name
 * ("aim_ll -a -t file -o par -f \\?\DevIoDrv\<name>"). Each worker thread
 * owns one locked exchange buffer, so requests are served in parallel.
 * UNMAP (TRIM) and zero-fill requests free page memory immediately.
 */

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

#include "memfs_block.h"

#define MEMFS_DEVIO_DEFAULT_THREADS 4U
#define MEMFS_DEVIO_MAX_THREADS 64U
#define MEMFS_DEVIO_DEFAULT_BUFFER (4U * 1024U * 1024U)

typedef struct MemfsDevio MemfsDevio;

typedef struct MemfsDevioStats {
	uint64_t reads;
	uint64_t writes;
	uint64_t unmaps;
	uint64_t read_bytes;
	uint64_t written_bytes;
	uint64_t unmapped_bytes;
	uint64_t errors;
	bool connected;
	bool closed;
} MemfsDevioStats;

/* Opens the DevIoDrv server object and starts the exchange workers. Returns a
 * Win32 error code (ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND when the
 * DevIoDrv driver is not installed or not running). */
DWORD memfs_devio_start(MemfsBlock* block, const wchar_t* name, uint32_t threads, uint32_t buffer_bytes,
						MemfsDevio** out_devio);
/* Builds the DevIoDrv path for a name (\\?\DevIoDrv\<name>). */
bool memfs_devio_path(const wchar_t* name, wchar_t* path, size_t path_count);
/* Waits until the disk is attached (first request served), the client closed
 * or the timeout elapsed. */
bool memfs_devio_wait_connected(MemfsDevio* devio, DWORD timeout_ms);
/* Waits for the client to close the disk. */
bool memfs_devio_wait_closed(MemfsDevio* devio, DWORD timeout_ms);
void memfs_devio_get_stats(MemfsDevio* devio, MemfsDevioStats* stats);
/* Closes the server object (pending exchanges fail) and joins the workers.
 * Detach the AIM disk first; closing while attached makes its I/O fail. */
void memfs_devio_stop(MemfsDevio* devio);
