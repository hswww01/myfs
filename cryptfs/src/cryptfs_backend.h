#pragma once

#include "cryptfs_store.h"
#include "fs_frontend.h"
#include <winfsp/winfsp.h>

typedef struct CRYPTFS_BACKEND CRYPTFS_BACKEND;

NTSTATUS cryptfs_backend_create(CF_STORE *store, CRYPTFS_BACKEND **backend_out);
NTSTATUS cryptfs_backend_mount(CRYPTFS_BACKEND *backend, PCWSTR mount_point);
NTSTATUS cryptfs_backend_start(CRYPTFS_BACKEND *backend);
HANDLE cryptfs_backend_stopped_event(CRYPTFS_BACKEND *backend);
NTSTATUS cryptfs_backend_dispatcher_result(CRYPTFS_BACKEND *backend);
void cryptfs_backend_stop(CRYPTFS_BACKEND *backend);
NTSTATUS cryptfs_backend_flush(CRYPTFS_BACKEND *backend);
void cryptfs_backend_destroy(CRYPTFS_BACKEND *backend);
