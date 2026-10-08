#include <Windows.h>
#include <winfsp/winfsp.h>

#include <stdio.h>
#include <string.h>

#include "memfs_winfsp.h"

int wmain(void) {
    MemfsOptions options;
    MemfsWinFsp* instance = NULL;
    NTSTATUS status;

    memset(&options, 0, sizeof(options));
    options.capacity = 16ULL * 1024ULL * 1024ULL;
    options.volume_label = L"MEMFS-PROBE";

    status = memfs_winfsp_create(&options, &instance);
    wprintf(L"memfs_winfsp_create=0x%08X sxs='%ls'\n",
            (unsigned)status, FspSxsIdent());

    if (NT_SUCCESS(status) && instance != NULL)
        memfs_winfsp_destroy(instance);

    return NT_SUCCESS(status) ? 0 : 1;
}
