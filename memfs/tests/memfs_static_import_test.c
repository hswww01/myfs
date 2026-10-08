#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct MemfsDelayImportDescriptor {
    DWORD attributes;
    DWORD name_rva;
    DWORD module_handle_rva;
    DWORD iat_rva;
    DWORD int_rva;
    DWORD bound_iat_rva;
    DWORD unload_iat_rva;
    DWORD timestamp;
} MemfsDelayImportDescriptor;

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

static int is_winfsp_dll(const char* name) {
    char lower[MAX_PATH];
    size_t i;
    size_t len;

    if (name == NULL)
        return 0;

    len = strlen(name);
    if (len >= sizeof(lower))
        return 0;

    for (i = 0; i <= len; ++i) {
        char ch = name[i];
        lower[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
    }

    return strstr(lower, "winfsp") != NULL && strstr(lower, ".dll") != NULL;
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
        if (is_winfsp_dll(name)) {
            fprintf(stderr, "unexpected WinFsp import: %s\n", name);
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
    const MemfsDelayImportDescriptor* desc;

    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (dir.VirtualAddress == 0)
        return 0;

    desc = (const MemfsDelayImportDescriptor*)rva_ptr(
        image, image_size, nt, dir.VirtualAddress);
    if (desc == NULL)
        return 2;

    while (desc->name_rva != 0) {
        const char* name = (const char*)rva_ptr(
            image, image_size, nt, desc->name_rva);
        if (name == NULL)
            return 2;
        if (is_winfsp_dll(name)) {
            fprintf(stderr, "unexpected delayed WinFsp import: %s\n", name);
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
        fprintf(stderr, "usage: memfs_static_import_test <memfs.exe>\n");
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
        printf("no WinFsp DLL imports: %s\n", argv[1]);

    free(image);
    return result;
}
