#include "memfs_devio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winioctl.h>

/*
 * Protocol definitions from the ImDisk proxy header (imdproxy.h, MIT
 * license, Copyright (C) 2005-2007 Olof Lagerkvist), as used by Arsenal Image
 * Mounter's DevIoDrv. Redeclared here; field layout must not change.
 */
enum {
	IMDPROXY_REQ_NULL = 0,
	IMDPROXY_REQ_INFO = 1,
	IMDPROXY_REQ_READ = 2,
	IMDPROXY_REQ_WRITE = 3,
	IMDPROXY_REQ_CONNECT = 4,
	IMDPROXY_REQ_CLOSE = 5,
	IMDPROXY_REQ_UNMAP = 6,
	IMDPROXY_REQ_ZERO = 7,
	IMDPROXY_REQ_SCSI = 8,
	IMDPROXY_REQ_SHARED = 9
};

#define IMDPROXY_FLAG_SUPPORTS_UNMAP 0x02ULL
#define IMDPROXY_FLAG_SUPPORTS_ZERO 0x04ULL
#define IMDPROXY_HEADER_SIZE 4096U
#define FILE_DEVICE_IMDISK 0x8372U
#define IOCTL_DEVIODRV_EXCHANGE_IO \
	CTL_CODE(FILE_DEVICE_IMDISK, 0x8D0, METHOD_OUT_DIRECT, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_DEVIODRV_LOCK_MEMORY \
	CTL_CODE(FILE_DEVICE_IMDISK, 0x8D1, METHOD_OUT_DIRECT, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct DevioBufferHeader {
	uint64_t request_code; /* echoed back with the response */
	uint64_t io_tag;       /* echoed back with the response */
	uint64_t flags;
} DevioBufferHeader;

typedef struct DevioInfoResponse {
	uint64_t file_size;
	uint64_t req_alignment;
	uint64_t flags;
} DevioInfoResponse;

typedef struct DevioIoRequest {
	uint64_t request_code;
	uint64_t offset;
	uint64_t length;
} DevioIoRequest;

typedef struct DevioIoResponse {
	uint64_t errorno;
	uint64_t length;
} DevioIoResponse;

typedef struct DevioRangeRequest {
	uint64_t request_code;
	uint64_t length; /* bytes of DEVICE_DATA_SET_RANGE entries at the data area */
} DevioRangeRequest;

typedef struct DevioRangeResponse {
	uint64_t errorno;
} DevioRangeResponse;

typedef struct DevioRange {
	int64_t starting_offset;
	uint64_t length_in_bytes;
} DevioRange;

_Static_assert(sizeof(DevioBufferHeader) == 24, "DevIoDrv header layout");
_Static_assert(sizeof(DevioRange) == sizeof(DEVICE_DATA_SET_RANGE), "range layout");

#define DEVIO_PAYLOAD(buffer) ((uint8_t*)(buffer) + sizeof(DevioBufferHeader))
#define DEVIO_DATA(buffer) ((uint8_t*)(buffer) + IMDPROXY_HEADER_SIZE)

typedef struct DevioWorker {
	MemfsDevio* devio;
	HANDLE thread;
	uint32_t index;
} DevioWorker;

struct MemfsDevio {
	MemfsBlock* block;
	HANDLE device;
	HANDLE connected_event;
	HANDLE closed_event;
	volatile LONG stopping;
	uint32_t buffer_bytes;
	uint32_t worker_count;
	volatile LONG64 reads, writes, unmaps, read_bytes, written_bytes, unmapped_bytes, errors;
	DevioWorker workers[];
};

bool memfs_devio_path(const wchar_t* name, wchar_t* path, size_t path_count) {
	const wchar_t* p;
	int written;

	if (name == NULL || *name == 0 || path == NULL)
		return false;
	for (p = name; *p; p++) {
		if (*p < 32 || *p == L'\\' || *p == L'/' || *p == L':' || *p == L'*' || *p == L'?')
			return false;
	}
	written = _snwprintf(path, path_count, L"\\\\?\\DevIoDrv\\%ls", name);
	return written > 0 && (size_t)written < path_count;
}

static void* devio_buffer_alloc(uint32_t size) {
	return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void devio_buffer_free(void* buffer) {
	if (buffer)
		VirtualFree(buffer, 0, MEM_RELEASE);
}

/* Starts the long-lived LOCK_MEMORY request that pins this buffer for the
 * driver. It stays pending until the exchange ends or the buffer is too
 * small for a request. */
static bool devio_lock_buffer(HANDLE device, void* buffer, uint32_t size, OVERLAPPED* overlapped) {
	ULONG_PTR id = (ULONG_PTR)buffer;

	ResetEvent(overlapped->hEvent);
	if (DeviceIoControl(device, IOCTL_DEVIODRV_LOCK_MEMORY, &id, sizeof(id), buffer, size, NULL, overlapped))
		return false; /* completed at once: the driver refused the buffer */
	return GetLastError() == ERROR_IO_PENDING;
}

static uint64_t devio_status(MemfsResult result) {
	return result == MEMFS_OK ? 0 : 1;
}

/* Serves one request in place; the header is left as received so the driver
 * can match the response. Returns false when the client closed the disk. */
static bool devio_serve(MemfsDevio* devio, void* buffer, uint32_t buffer_size) {
	uint8_t* payload = DEVIO_PAYLOAD(buffer);
	uint64_t code;
	uint64_t max_data = buffer_size - IMDPROXY_HEADER_SIZE;

	memcpy(&code, payload, sizeof(code));
	switch (code) {
	case IMDPROXY_REQ_INFO: {
		DevioInfoResponse info = {memfs_block_size(devio->block), MEMFS_BLOCK_SECTOR_SIZE,
								  IMDPROXY_FLAG_SUPPORTS_UNMAP | IMDPROXY_FLAG_SUPPORTS_ZERO};
		memcpy(payload, &info, sizeof(info));
		return true;
	}
	case IMDPROXY_REQ_READ:
	case IMDPROXY_REQ_WRITE: {
		DevioIoRequest request;
		DevioIoResponse response = {0, 0};
		MemfsResult result;
		uint64_t length;

		memcpy(&request, payload, sizeof(request));
		length = request.length;
		if (length > max_data || length > UINT32_MAX) {
			response.errorno = 1;
		} else if (code == IMDPROXY_REQ_READ) {
			result = memfs_block_read(devio->block, request.offset, DEVIO_DATA(buffer), (uint32_t)length);
			response.errorno = devio_status(result);
			response.length = result == MEMFS_OK ? length : 0;
			InterlockedIncrement64(&devio->reads);
			if (result == MEMFS_OK)
				InterlockedAdd64(&devio->read_bytes, (LONG64)length);
		} else {
			result = memfs_block_write(devio->block, request.offset, DEVIO_DATA(buffer), (uint32_t)length);
			response.errorno = devio_status(result);
			response.length = result == MEMFS_OK ? length : 0;
			InterlockedIncrement64(&devio->writes);
			if (result == MEMFS_OK)
				InterlockedAdd64(&devio->written_bytes, (LONG64)length);
		}
		if (response.errorno)
			InterlockedIncrement64(&devio->errors);
		memcpy(payload, &response, sizeof(response));
		return true;
	}
	case IMDPROXY_REQ_UNMAP:
	case IMDPROXY_REQ_ZERO: {
		DevioRangeRequest request;
		DevioRangeResponse response = {0};
		const uint8_t* data = DEVIO_DATA(buffer);
		uint64_t count;
		uint64_t i;

		memcpy(&request, payload, sizeof(request));
		if (request.length > max_data || request.length % sizeof(DevioRange) != 0) {
			response.errorno = 1;
		} else {
			count = request.length / sizeof(DevioRange);
			for (i = 0; i < count && response.errorno == 0; i++) {
				DevioRange range;

				memcpy(&range, data + i * sizeof(range), sizeof(range));
				if (range.starting_offset < 0) {
					response.errorno = 1;
					break;
				}
				response.errorno = devio_status(
					memfs_block_unmap(devio->block, (uint64_t)range.starting_offset, range.length_in_bytes));
				if (response.errorno == 0)
					InterlockedAdd64(&devio->unmapped_bytes, (LONG64)range.length_in_bytes);
			}
			InterlockedIncrement64(&devio->unmaps);
		}
		if (response.errorno)
			InterlockedIncrement64(&devio->errors);
		memcpy(payload, &response, sizeof(response));
		return true;
	}
	case IMDPROXY_REQ_CLOSE:
		return false;
	default: {
		/* Unsupported (SCSI pass-through, shared reservations): fail it. */
		uint64_t error = ERROR_INVALID_FUNCTION;

		InterlockedIncrement64(&devio->errors);
		memcpy(payload, &error, sizeof(error));
		return true;
	}
	}
}

static DWORD WINAPI devio_worker_main(LPVOID parameter) {
	DevioWorker* worker = parameter;
	MemfsDevio* devio = worker->devio;
	uint32_t size = devio->buffer_bytes;
	void* buffer = devio_buffer_alloc(size);
	OVERLAPPED lock_overlapped = {0};
	OVERLAPPED exchange_overlapped = {0};
	bool locked = false;

	lock_overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	exchange_overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (buffer == NULL || lock_overlapped.hEvent == NULL || exchange_overlapped.hEvent == NULL)
		goto done;
	locked = devio_lock_buffer(devio->device, buffer, size, &lock_overlapped);
	if (!locked)
		goto done;

	/* The first exchange of worker 0 carries the INFO answer the driver
	 * expects when it attaches; other workers start idle. */
	memset(buffer, 0, sizeof(DevioBufferHeader) + sizeof(DevioInfoResponse));
	if (worker->index == 0) {
		uint64_t code = IMDPROXY_REQ_INFO;

		((DevioBufferHeader*)buffer)->request_code = IMDPROXY_REQ_INFO;
		memcpy(DEVIO_PAYLOAD(buffer), &code, sizeof(code));
		(void)devio_serve(devio, buffer, size);
	} else {
		((DevioBufferHeader*)buffer)->request_code = IMDPROXY_REQ_NULL;
	}

	while (!devio->stopping) {
		ULONG_PTR id = (ULONG_PTR)buffer;
		DWORD transferred = 0;
		DWORD error = ERROR_SUCCESS;

		ResetEvent(exchange_overlapped.hEvent);
		if (!DeviceIoControl(devio->device, IOCTL_DEVIODRV_EXCHANGE_IO, &id, sizeof(id), NULL, 0, NULL,
							 &exchange_overlapped)) {
			error = GetLastError();
			if (error == ERROR_IO_PENDING) {
				error = ERROR_SUCCESS;
				if (!GetOverlappedResult(devio->device, &exchange_overlapped, &transferred, TRUE))
					error = GetLastError();
			}
		}

		if (error == ERROR_INSUFFICIENT_BUFFER) {
			/* A request larger than this buffer: the lock request completes;
			 * grow the buffer, lock it again and let the driver retry. */
			void* larger;

			(void)GetOverlappedResult(devio->device, &lock_overlapped, &transferred, TRUE);
			locked = false;
			if (size > (1U << 30))
				break;
			larger = devio_buffer_alloc(size * 2U);
			if (larger == NULL)
				break;
			devio_buffer_free(buffer);
			buffer = larger;
			size *= 2U;
			locked = devio_lock_buffer(devio->device, buffer, size, &lock_overlapped);
			if (!locked)
				break;
			((DevioBufferHeader*)buffer)->request_code = IMDPROXY_REQ_NULL;
			continue;
		}
		if (error != ERROR_SUCCESS)
			break; /* ERROR_DEV_NOT_EXIST: client gone; or handle closed on stop */

		SetEvent(devio->connected_event);
		if (!devio_serve(devio, buffer, size))
			break;
	}

done:
	SetEvent(devio->closed_event);
	/* Never cancel DevIoDrv requests: after the AIM disk is detached, the
	 * driver's cancel routine dereferences a freed (NULL) queue and bugchecks
	 * (DRIVER_IRQL_NOT_LESS_OR_EQUAL in deviodrv.sys, seen 2026-10-14). The
	 * reference AIM service never cancels either; closing the server handle
	 * makes the driver complete the pending lock request during cleanup. The
	 * buffer stays pinned until then, so wait before freeing it. */
	if (lock_overlapped.hEvent) {
		if (locked)
			WaitForSingleObject(lock_overlapped.hEvent, INFINITE);
		CloseHandle(lock_overlapped.hEvent);
	}
	if (exchange_overlapped.hEvent)
		CloseHandle(exchange_overlapped.hEvent);
	devio_buffer_free(buffer);
	return 0;
}

DWORD memfs_devio_start(MemfsBlock* block, const wchar_t* name, uint32_t threads, uint32_t buffer_bytes,
						MemfsDevio** out_devio) {
	MemfsDevio* devio;
	wchar_t path[MAX_PATH];
	uint32_t i;
	DWORD error;

	if (out_devio == NULL)
		return ERROR_INVALID_PARAMETER;
	*out_devio = NULL;
	if (threads == 0)
		threads = MEMFS_DEVIO_DEFAULT_THREADS;
	if (buffer_bytes == 0)
		buffer_bytes = MEMFS_DEVIO_DEFAULT_BUFFER;
	if (block == NULL || threads > MEMFS_DEVIO_MAX_THREADS || buffer_bytes < 2U * IMDPROXY_HEADER_SIZE ||
		(buffer_bytes % IMDPROXY_HEADER_SIZE) != 0 || !memfs_devio_path(name, path, MAX_PATH))
		return ERROR_INVALID_PARAMETER;

	devio = calloc(1, sizeof(*devio) + (size_t)threads * sizeof(devio->workers[0]));
	if (devio == NULL)
		return ERROR_NOT_ENOUGH_MEMORY;
	devio->block = block;
	devio->buffer_bytes = buffer_bytes;
	devio->connected_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	devio->closed_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	devio->device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
								CREATE_NEW, FILE_FLAG_OVERLAPPED, NULL);
	if (devio->device == INVALID_HANDLE_VALUE || devio->connected_event == NULL || devio->closed_event == NULL) {
		error = devio->device == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
		devio->device = INVALID_HANDLE_VALUE;
		memfs_devio_stop(devio);
		return error;
	}

	for (i = 0; i < threads; i++) {
		devio->workers[i].devio = devio;
		devio->workers[i].index = i;
		devio->workers[i].thread = CreateThread(NULL, 0, devio_worker_main, &devio->workers[i], 0, NULL);
		if (devio->workers[i].thread == NULL) {
			error = GetLastError();
			memfs_devio_stop(devio);
			return error;
		}
		devio->worker_count++;
	}

	*out_devio = devio;
	return ERROR_SUCCESS;
}

bool memfs_devio_wait_connected(MemfsDevio* devio, DWORD timeout_ms) {
	HANDLE events[2];

	if (devio == NULL)
		return false;
	events[0] = devio->connected_event;
	events[1] = devio->closed_event;
	return WaitForMultipleObjects(2, events, FALSE, timeout_ms) == WAIT_OBJECT_0;
}

bool memfs_devio_wait_closed(MemfsDevio* devio, DWORD timeout_ms) {
	return devio != NULL && WaitForSingleObject(devio->closed_event, timeout_ms) == WAIT_OBJECT_0;
}

void memfs_devio_get_stats(MemfsDevio* devio, MemfsDevioStats* stats) {
	if (stats == NULL)
		return;
	memset(stats, 0, sizeof(*stats));
	if (devio == NULL)
		return;
	stats->reads = (uint64_t)InterlockedCompareExchange64(&devio->reads, 0, 0);
	stats->writes = (uint64_t)InterlockedCompareExchange64(&devio->writes, 0, 0);
	stats->unmaps = (uint64_t)InterlockedCompareExchange64(&devio->unmaps, 0, 0);
	stats->read_bytes = (uint64_t)InterlockedCompareExchange64(&devio->read_bytes, 0, 0);
	stats->written_bytes = (uint64_t)InterlockedCompareExchange64(&devio->written_bytes, 0, 0);
	stats->unmapped_bytes = (uint64_t)InterlockedCompareExchange64(&devio->unmapped_bytes, 0, 0);
	stats->errors = (uint64_t)InterlockedCompareExchange64(&devio->errors, 0, 0);
	stats->connected = WaitForSingleObject(devio->connected_event, 0) == WAIT_OBJECT_0;
	stats->closed = WaitForSingleObject(devio->closed_event, 0) == WAIT_OBJECT_0;
}

void memfs_devio_stop(MemfsDevio* devio) {
	uint32_t i;

	if (devio == NULL)
		return;
	InterlockedExchange(&devio->stopping, 1);
	/* Close (never cancel, see devio_worker_main) the server handle: the
	 * driver's cleanup completes every pending exchange and lock request,
	 * which wakes the workers; then join them. */
	if (devio->device != INVALID_HANDLE_VALUE && devio->device != NULL) {
		CloseHandle(devio->device);
		devio->device = INVALID_HANDLE_VALUE;
	}
	for (i = 0; i < devio->worker_count; i++) {
		WaitForSingleObject(devio->workers[i].thread, INFINITE);
		CloseHandle(devio->workers[i].thread);
	}
	if (devio->connected_event)
		CloseHandle(devio->connected_event);
	if (devio->closed_event)
		CloseHandle(devio->closed_event);
	free(devio);
}
