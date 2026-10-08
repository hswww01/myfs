#pragma once

#include <wchar.h>

typedef struct Memfs Memfs;
typedef struct MemfsNode MemfsNode;
typedef struct MemfsDir MemfsDir;

MemfsNode* memfs_object_alloc_node(Memfs* fs);
void memfs_object_free_node(Memfs* fs, MemfsNode* node);

MemfsDir* memfs_object_alloc_dir(Memfs* fs);
void memfs_object_free_dir(Memfs* fs, MemfsDir* dir);

wchar_t* memfs_object_dup_name(Memfs* fs, const wchar_t* name);
void memfs_object_free_name(Memfs* fs, wchar_t* name);
