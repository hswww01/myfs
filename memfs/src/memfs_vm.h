#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct MemfsVmSystemInfo {
    size_t page_size;
    size_t allocation_granularity;
} MemfsVmSystemInfo;

bool memfs_vm_get_system_info(MemfsVmSystemInfo* info);

void* memfs_vm_reserve(size_t bytes);
bool memfs_vm_commit(void* address, size_t bytes);
bool memfs_vm_decommit(void* address, size_t bytes);
bool memfs_vm_release(void* address);

void* memfs_vm_reserve_commit(size_t bytes);
uint64_t memfs_vm_region_bytes(const void* address);
