#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "memfs_resource.h"

static int read_pe_machine(const uint8_t* data, DWORD size, WORD* machine) {
    int32_t pe_offset;
    uint32_t signature;
    WORD value;

    if (data == NULL || machine == NULL || size < 0x40U)
        return 0;

    memcpy(&value, data, sizeof(value));
    if (value != IMAGE_DOS_SIGNATURE)
        return 0;

    memcpy(&pe_offset, data + 0x3cU, sizeof(pe_offset));
    if (pe_offset < 0 ||
        (uint64_t)(uint32_t)pe_offset + 6U > (uint64_t)size)
        return 0;

    memcpy(&signature, data + (uint32_t)pe_offset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE)
        return 0;

    memcpy(&value, data + (uint32_t)pe_offset + sizeof(signature),
           sizeof(value));
    *machine = value;
    return 1;
}

static int check_resource(HMODULE module,
                          WORD id,
                          DWORD minimum_size,
                          WORD expected_machine,
                          const char* label) {
    HRSRC resource =
        FindResourceW(module, MAKEINTRESOURCEW(id), MAKEINTRESOURCEW(10));
    HGLOBAL loaded;
    const uint8_t* data;
    DWORD size;
    WORD machine = 0;

    if (resource == NULL) {
        fprintf(stderr, "missing resource: %s (id=%u) error=%lu\n",
                label, (unsigned)id, GetLastError());
        return 0;
    }

    size = SizeofResource(module, resource);
    if (size < minimum_size) {
        fprintf(stderr, "resource too small: %s size=%lu expected>=%lu\n",
                label, size, minimum_size);
        return 0;
    }

    loaded = LoadResource(module, resource);
    if (loaded == NULL) {
        fprintf(stderr, "LoadResource failed: %s error=%lu\n",
                label, GetLastError());
        return 0;
    }

    data = (const uint8_t*)LockResource(loaded);
    if (data == NULL || !read_pe_machine(data, size, &machine)) {
        fprintf(stderr, "invalid embedded PE resource: %s\n", label);
        return 0;
    }
    if (machine != expected_machine) {
        fprintf(stderr,
                "wrong PE machine: %s machine=0x%04x expected=0x%04x\n",
                label, (unsigned)machine, (unsigned)expected_machine);
        return 0;
    }

    printf("%s resource size=%lu machine=0x%04x\n",
           label, size, (unsigned)machine);
    return 1;
}

int wmain(int argc, wchar_t** argv) {
    HMODULE module;
    int ok;

    if (argc != 2) {
        fwprintf(stderr, L"usage: %s <memfs.exe>\n", argv[0]);
        return 2;
    }

    module = LoadLibraryExW(argv[1], NULL,
                            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE |
                            LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (module == NULL) {
        fwprintf(stderr, L"LoadLibraryExW(%s) failed: %lu\n", argv[1], GetLastError());
        return 1;
    }

#if defined(MEMFS_WINFSP_STATIC)
    ok = check_resource(module, IDR_MEMFS_WINFSP_SYS_X64,
                        100U * 1024U, IMAGE_FILE_MACHINE_AMD64,
                        "WinFsp x64 SYS") &&
         check_resource(module, IDR_MEMFS_WINFSP_SYS_ARM64,
                        100U * 1024U, IMAGE_FILE_MACHINE_ARM64,
                        "WinFsp ARM64 SYS");
#else
    ok = check_resource(module, IDR_MEMFS_WINFSP_DLL,
                        100U * 1024U, IMAGE_FILE_MACHINE_AMD64,
                        "WinFsp x64 DLL") &&
         check_resource(module, IDR_MEMFS_WINFSP_SYS_X64,
                        100U * 1024U, IMAGE_FILE_MACHINE_AMD64,
                        "WinFsp x64 SYS") &&
         check_resource(module, IDR_MEMFS_WINFSP_SYS_ARM64,
                        100U * 1024U, IMAGE_FILE_MACHINE_ARM64,
                        "WinFsp ARM64 SYS");
#endif

    FreeLibrary(module);
    return ok ? 0 : 1;
}
