#include <Windows.h>
#include <winfsp/winfsp.h>

#include <stdio.h>

#ifndef MEMFS_EXPECTED_WINFSP_VERSION
#error MEMFS_EXPECTED_WINFSP_VERSION must be defined
#endif

int main(void) {
    UINT32 version = 0;
    NTSTATUS status = FspVersion(&version);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "FspVersion failed: 0x%08X\n", (unsigned)status);
        return 1;
    }

    if (version != (UINT32)MEMFS_EXPECTED_WINFSP_VERSION) {
        fprintf(stderr,
                "WinFsp static version mismatch: got 0x%08X expected 0x%08X\n",
                (unsigned)version,
                (unsigned)MEMFS_EXPECTED_WINFSP_VERSION);
        return 1;
    }

    printf("WinFsp static version: %u.%u (0x%08X)\n",
           (unsigned)(version >> 16),
           (unsigned)(version & 0xffffU),
           (unsigned)version);
    return 0;
}
