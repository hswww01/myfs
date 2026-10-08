#include "memfs_vm.h"

#include <Windows.h>

bool memfs_vm_get_system_info(MemfsVmSystemInfo* info) {
    SYSTEM_INFO system_info;

    if (info == NULL)
        return false;

    GetSystemInfo(&system_info);
    info->page_size = (size_t)system_info.dwPageSize;
    info->allocation_granularity = (size_t)system_info.dwAllocationGranularity;
    return info->page_size != 0 && info->allocation_granularity != 0;
}

void* memfs_vm_reserve(size_t bytes) {
    if (bytes == 0)
        return NULL;
    return VirtualAlloc(NULL, bytes, MEM_RESERVE, PAGE_NOACCESS);
}

bool memfs_vm_commit(void* address, size_t bytes) {
    if (address == NULL || bytes == 0)
        return false;
    return VirtualAlloc(address, bytes, MEM_COMMIT, PAGE_READWRITE) != NULL;
}

bool memfs_vm_decommit(void* address, size_t bytes) {
    if (address == NULL || bytes == 0)
        return false;
    return !!VirtualFree(address, bytes, MEM_DECOMMIT);
}

bool memfs_vm_release(void* address) {
    if (address == NULL)
        return true;
    return !!VirtualFree(address, 0, MEM_RELEASE);
}

void* memfs_vm_reserve_commit(size_t bytes) {
    if (bytes == 0)
        return NULL;
    return VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

uint64_t memfs_vm_region_bytes(const void* address) {
    MEMORY_BASIC_INFORMATION info;

    if (address == NULL ||
        VirtualQuery(address, &info, sizeof(info)) != sizeof(info)) {
        return 0;
    }

    return (uint64_t)info.RegionSize;
}
