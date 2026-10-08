#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ScpfsDelayImportDescriptor {
    DWORD attributes;
    DWORD name_rva;
    DWORD module_handle_rva;
    DWORD iat_rva;
    DWORD int_rva;
    DWORD bound_iat_rva;
    DWORD unload_iat_rva;
    DWORD timestamp;
} ScpfsDelayImportDescriptor;

static const unsigned char* rva_ptr(const unsigned char* image,
                                    size_t image_size,
                                    const IMAGE_NT_HEADERS64* nt,
                                    DWORD rva) {
    const IMAGE_SECTION_HEADER* section;
    WORD i;

    if (rva == 0)
        return NULL;

    if (rva < nt->OptionalHeader.SizeOfHeaders && rva < image_size)
        return image + rva;

    section = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD span = section[i].Misc.VirtualSize;
        DWORD delta;
        size_t offset;

        if (span < section[i].SizeOfRawData)
            span = section[i].SizeOfRawData;
        if (rva < section[i].VirtualAddress ||
            rva >= section[i].VirtualAddress + span) {
            continue;
        }

        delta = rva - section[i].VirtualAddress;
        offset = (size_t)section[i].PointerToRawData + delta;
        if (offset >= image_size)
            return NULL;
        return image + offset;
    }

    return NULL;
}

static int ascii_equal_ci(const char* left, const char* right) {
    while (*left && *right) {
        char a = *left++, b = *right++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return *left == '\0' && *right == '\0';
}

static int is_windows_builtin_dll(const char* name) {
    static const char* const modules[] = {
        "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "cfgmgr32.dll",
        "combase.dll", "comctl32.dll", "comdlg32.dll", "crypt32.dll",
        "gdi32.dll", "gdi32full.dll", "imm32.dll", "kernel32.dll",
        "kernelbase.dll", "msvcrt.dll", "ntdll.dll", "ole32.dll",
        "oleaut32.dll", "rpcrt4.dll", "sechost.dll", "secur32.dll",
        "shlwapi.dll", "shell32.dll", "user32.dll", "version.dll",
        "win32u.dll", "wintrust.dll", "ws2_32.dll", "dnsapi.dll", "iphlpapi.dll", "netapi32.dll",
        "wldap32.dll", "credui.dll", "msvcp_win.dll", "ucrtbase.dll"
    };
    size_t i;
    if (name == NULL)
        return 0;
    if (_strnicmp(name, "api-ms-win-", 11) == 0 ||
        _strnicmp(name, "ext-ms-win-", 11) == 0)
        return 1;
    for (i = 0; i < sizeof(modules) / sizeof(modules[0]); ++i)
        if (ascii_equal_ci(name, modules[i]))
            return 1;
    return 0;
}

static int check_imports(const unsigned char* image,
                         size_t image_size,
                         const IMAGE_NT_HEADERS64* nt) {
    IMAGE_DATA_DIRECTORY dir;
    const IMAGE_IMPORT_DESCRIPTOR* desc;

    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0)
        return 0;

    desc = (const IMAGE_IMPORT_DESCRIPTOR*)rva_ptr(
        image, image_size, nt, dir.VirtualAddress);
    if (desc == NULL)
        return 2;

    while (desc->Name != 0) {
        const char* name = (const char*)rva_ptr(image, image_size, nt, desc->Name);
        if (name == NULL)
            return 2;
        if (!is_windows_builtin_dll(name)) {
            fprintf(stderr, "unexpected non-Windows import: %s\n", name);
            return 1;
        }
        ++desc;
    }

    return 0;
}

static int check_delay_imports(const unsigned char* image,
                               size_t image_size,
                               const IMAGE_NT_HEADERS64* nt) {
    IMAGE_DATA_DIRECTORY dir;
    const ScpfsDelayImportDescriptor* desc;

    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (dir.VirtualAddress == 0)
        return 0;

    desc = (const ScpfsDelayImportDescriptor*)rva_ptr(
        image, image_size, nt, dir.VirtualAddress);
    if (desc == NULL)
        return 2;

    while (desc->name_rva != 0) {
        const char* name = (const char*)rva_ptr(
            image, image_size, nt, desc->name_rva);
        if (name == NULL)
            return 2;
        if (!is_windows_builtin_dll(name)) {
            fprintf(stderr, "unexpected non-Windows delay import: %s\n", name);
            return 1;
        }
        ++desc;
    }

    return 0;
}

int main(int argc, char** argv) {
    FILE* file;
    unsigned char* image;
    long file_size_long;
    size_t image_size;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt;
    int result;

    if (argc != 2) {
        fprintf(stderr, "usage: scpfs_static_import_test <scpfs.exe>\n");
        return 2;
    }

    if (fopen_s(&file, argv[1], "rb") != 0 || file == NULL) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 2;
    }
    file_size_long = ftell(file);
    if (file_size_long <= 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return 2;
    }

    image_size = (size_t)file_size_long;
    image = (unsigned char*)malloc(image_size);
    if (image == NULL) {
        fclose(file);
        return 2;
    }

    if (fread(image, 1, image_size, file) != image_size) {
        free(image);
        fclose(file);
        return 2;
    }
    fclose(file);

    if (image_size < sizeof(IMAGE_DOS_HEADER)) {
        free(image);
        return 2;
    }

    dos = (const IMAGE_DOS_HEADER*)image;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew <= 0 ||
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > image_size) {
        free(image);
        return 2;
    }

    nt = (const IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        free(image);
        return 2;
    }

    result = check_imports(image, image_size, nt);
    if (result == 0)
        result = check_delay_imports(image, image_size, nt);

    if (result == 0)
        printf("only Windows built-in DLL imports (including delay imports): %s\n", argv[1]);

    free(image);
    return result;
}

