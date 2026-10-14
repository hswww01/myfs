/* Unity-style extension to memfs_temp_probe.c; also runs unchanged on NTFS. */
static const char stream_zone[] = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/test.bin\r\n";
static void stream_path(WCHAR* out, size_t n, const WCHAR* base, const WCHAR* name) {
    WCHAR absolute[2048];
    if (wcslen(base)+wcslen(name)+2 >= MAX_PATH && wcsncmp(base,L"\\\\?\\",4)!=0) {
        CHECK(GetFullPathNameW(base,_countof(absolute),absolute,NULL)!=0);
        CHECK(swprintf_s(out,n,L"\\\\?\\%ls:%ls",absolute,name)>=0);
    } else CHECK(swprintf_s(out, n, L"%ls:%ls", base, name) >= 0);
}
static void stream_write(const WCHAR* file, const void* data, DWORD bytes, DWORD disposition) {
    HANDLE h = open_file(file, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disposition, FILE_ATTRIBUTE_NORMAL);
    DWORD done = 0;
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) return;
    CHECK(WriteFile(h, data, bytes, &done, NULL) && done == bytes);
    CHECK(CloseHandle(h));
}
static void stream_expect(const WCHAR* file, const void* expected, DWORD bytes) {
    BYTE buffer[16384]; DWORD done = 0; LARGE_INTEGER size;
    HANDLE h = open_file(file, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h == INVALID_HANDLE_VALUE) return;
    CHECK(GetFileSizeEx(h, &size) && size.QuadPart == bytes);
    CHECK(bytes <= sizeof(buffer));
    if (bytes <= sizeof(buffer)) {
        CHECK(ReadFile(h, buffer, sizeof(buffer), &done, NULL) && done == bytes);
        CHECK(!memcmp(buffer, expected, bytes));
    }
    CHECK(CloseHandle(h));
}
static BOOL stream_exists(const WCHAR* file) {
    HANDLE h = open_file(file, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    CloseHandle(h); return TRUE;
}
static unsigned stream_enumerate(const WCHAR* base, const WCHAR* wanted, LONGLONG length, BOOL* found) {
    WIN32_FIND_STREAM_DATA entry;
    HANDLE h = FindFirstStreamW(base, FindStreamInfoStandard, &entry, 0);
    unsigned count = 0;
    if (found) *found = FALSE;
    if (h == INVALID_HANDLE_VALUE) { CHECK(GetLastError() == ERROR_HANDLE_EOF); return 0; }
    do {
        ++count;
        if (wanted != NULL && !_wcsicmp(entry.cStreamName, wanted)) {
            if (found) *found = TRUE;
            CHECK(entry.StreamSize.QuadPart == length);
        }
    } while (FindNextStreamW(h, &entry));
    CHECK(GetLastError() == ERROR_HANDLE_EOF);
    CHECK(FindClose(h));
    return count;
}
static void test_zone_stream(void) {
    WCHAR base[2048], zone[2200], alias[2200], renamed[2048], copy[2048], copied_zone[2200];
    BOOL found; WIN32_FIND_DATAW entry; HANDLE find;
    path(base, _countof(base), L"zone.bin");
    stream_path(zone, _countof(zone), base, L"Zone.Identifier");
    stream_write(base, "MAIN", 4, CREATE_NEW);
    stream_write(zone, stream_zone, sizeof(stream_zone)-1, CREATE_NEW);
    stream_expect(zone, stream_zone, sizeof(stream_zone)-1);
    stream_expect(base, "MAIN", 4);
    stream_path(alias, _countof(alias), base, L"zOnE.iDeNtIfIeR:$data");
    stream_expect(alias, stream_zone, sizeof(stream_zone)-1);
    stream_path(alias, _countof(alias), base, L":$DATA");
    stream_expect(alias, "MAIN", 4);
    CHECK(stream_enumerate(base, L":Zone.Identifier:$DATA", sizeof(stream_zone)-1, &found) == 2 && found);
    find = FindFirstFileW(base, &entry);
    CHECK(find != INVALID_HANDLE_VALUE);
    if (find != INVALID_HANDLE_VALUE) { CHECK(entry.nFileSizeLow == 4); FindClose(find); }
    path(copy, _countof(copy), L"zone-copy.bin");
    CHECK(CopyFileW(base, copy, TRUE));
    stream_path(copied_zone, _countof(copied_zone), copy, L"Zone.Identifier");
    stream_expect(copied_zone, stream_zone, sizeof(stream_zone)-1);
    path(renamed, _countof(renamed), L"zone-renamed.bin");
    CHECK(MoveFileExW(base, renamed, 0));
    stream_path(zone, _countof(zone), renamed, L"Zone.Identifier");
    stream_expect(zone, stream_zone, sizeof(stream_zone)-1);
    stream_write(zone, "[ZoneTransfer]\r\nZoneId=3\r\n", 26, CREATE_ALWAYS);
    stream_expect(renamed, "MAIN", 4);
    CHECK(DeleteFileW(zone));
    CHECK(!stream_exists(zone));
    CHECK(stream_enumerate(renamed, NULL, 0, NULL) == 1);
    CHECK(DeleteFileW(renamed)); CHECK(DeleteFileW(copy));
    CHECK(!stream_exists(copied_zone));
}
static void test_directory_and_implicit_stream(void) {
    WCHAR dir[2048], ads[2200], base[2048];
    BOOL found;
    path(dir, _countof(dir), L"dir-ads"); CHECK(CreateDirectoryW(dir, NULL));
    CHECK(stream_enumerate(dir, NULL, 0, NULL) == 0);
    stream_path(ads, _countof(ads), dir, L"metadata");
    stream_write(ads, "DIRECTORY", 9, CREATE_NEW);
    stream_expect(ads, "DIRECTORY", 9);
    CHECK(stream_enumerate(dir, L":metadata:$DATA", 9, &found) == 1 && found);
    CHECK((GetFileAttributesW(dir) & FILE_ATTRIBUTE_DIRECTORY) != 0);
    CHECK(RemoveDirectoryW(dir)); CHECK(!stream_exists(ads));
    path(base, _countof(base), L"implicit.bin");
    stream_path(ads, _countof(ads), base, L"first");
    stream_write(ads, "IMPLICIT", 8, CREATE_NEW);
    CHECK(stream_exists(base));
    stream_expect(base, "", 0); stream_expect(ads, "IMPLICIT", 8);
    CHECK(DeleteFileW(base)); CHECK(!stream_exists(ads));
}
static void test_stream_acl_and_metadata(void) {
    WCHAR base[2048], ads[2200]; HANDLE h, main_handle; BY_HANDLE_FILE_INFORMATION a, b;
    path(base, _countof(base), L"acl-stream.bin"); CHECK(touch(base));
    stream_path(ads, _countof(ads), base, L"private"); stream_write(ads, "ACL", 3, CREATE_NEW);
    CHECK(set_sddl(base, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        L"D:P(D;;0x2;;;WD)(A;;FA;;;WD)"));
    h = open_file(ads, FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
    CHECK(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    stream_expect(ads, "ACL", 3);
    CHECK(set_sddl(ads, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        L"D:P(A;;FA;;;WD)"));
    h = open_file(base, FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
    CHECK(h != INVALID_HANDLE_VALUE); if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    h = open_file(ads, GENERIC_READ | FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
    main_handle = open_file(base, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
    CHECK(h != INVALID_HANDLE_VALUE && main_handle != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE && main_handle != INVALID_HANDLE_VALUE) {
        FILETIME creation = {0x11111111, 0x01d90000};
        CHECK(SetFileTime(h, &creation, NULL, NULL));
        CHECK(GetFileInformationByHandle(h, &a));
        CHECK(GetFileInformationByHandle(main_handle, &b));
        CHECK(a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow);
        CHECK(!memcmp(&b.ftCreationTime, &creation, sizeof(creation)));
        CHECK(a.nFileSizeLow == 3 && b.nFileSizeLow == 0);
    }
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (main_handle != INVALID_HANDLE_VALUE) CloseHandle(main_handle);
    CHECK(DeleteFileW(base));
}
static void test_stream_lifetime_and_overwrite(void) {
    WCHAR base[2048], ads[2200], second[2200]; HANDLE h, main_handle;
    DWORD done; char data[16];
    path(base, _countof(base), L"stream-lifetime.bin"); CHECK(touch(base));
    stream_path(ads, _countof(ads), base, L"keep");
    stream_path(second, _countof(second), base, L"closed");
    stream_write(ads, "OPEN", 4, CREATE_NEW); stream_write(second, "CLOSED", 6, CREATE_NEW);
    h = open_file(ads, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING, 0); CHECK(h != INVALID_HANDLE_VALUE);
    main_handle = open_file(base, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        CREATE_ALWAYS, 0); CHECK(main_handle != INVALID_HANDLE_VALUE);
    if (main_handle != INVALID_HANDLE_VALUE) CloseHandle(main_handle);
    CHECK(!stream_exists(second));
    CHECK(!stream_exists(ads));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED);
    CHECK(stream_enumerate(base, NULL, 0, NULL) == 2);
    if (h != INVALID_HANDLE_VALUE) {
        CHECK(ReadFile(h, data, sizeof(data), &done, NULL) && done == 4 && !memcmp(data,"OPEN",4));
        CHECK(DeleteFileW(base));
        CHECK(SetFilePointer(h, 0, NULL, FILE_BEGIN) == 0);
        CHECK(ReadFile(h, data, sizeof(data), &done, NULL) && done == 4 && !memcmp(data,"OPEN",4));
        CHECK(CloseHandle(h));
    }
    CHECK(!stream_exists(base) && !stream_exists(ads));
    CHECK(touch(base)); stream_write(ads,"DELETE",6,CREATE_NEW);
    h = open_file(ads, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE); CHECK(h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) CHECK(CloseHandle(h));
    CHECK(!stream_exists(ads) && stream_exists(base));
    CHECK(DeleteFileW(base));
}
static void test_stream_sparse_and_mapping(void) {
    WCHAR base[2048], ads[2200]; BYTE buffer[8192], expected[8192]; HANDLE h, map; BYTE* view;
    DWORD done; LARGE_INTEGER pos;
    path(base, _countof(base), L"sparse-stream.bin"); CHECK(touch(base));
    stream_path(ads, _countof(ads), base, L"data");
    h = open_file(ads, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        CREATE_NEW, 0); CHECK(h != INVALID_HANDLE_VALUE); if (h == INVALID_HANDLE_VALUE) return;
    pos.QuadPart=8192; CHECK(SetFilePointerEx(h,pos,NULL,FILE_BEGIN) && SetEndOfFile(h));
    map=CreateFileMappingW(h,NULL,PAGE_READWRITE,0,0,NULL); CHECK(map != NULL);
    if (map) {
        view=MapViewOfFile(map,FILE_MAP_WRITE,0,0,0); CHECK(view != NULL);
        if (view) { memset(view+4090,0x5a,32); CHECK(FlushViewOfFile(view,0)); CHECK(UnmapViewOfFile(view)); }
        CloseHandle(map);
    }
    CHECK(FlushFileBuffers(h)); pos.QuadPart=0; CHECK(SetFilePointerEx(h,pos,NULL,FILE_BEGIN));
    CHECK(ReadFile(h,buffer,sizeof(buffer),&done,NULL) && done==sizeof(buffer));
    memset(expected,0,sizeof(expected)); memset(expected+4090,0x5a,32);
    CHECK(!memcmp(buffer,expected,sizeof(buffer)));
    pos.QuadPart=4096; CHECK(SetFilePointerEx(h,pos,NULL,FILE_BEGIN) && SetEndOfFile(h));
    pos.QuadPart=8192; CHECK(SetFilePointerEx(h,pos,NULL,FILE_BEGIN) && SetEndOfFile(h));
    CHECK(CloseHandle(h)); memset(expected+4096,0,4096);
    stream_expect(ads,expected,sizeof(expected)); stream_expect(base,"",0);
    CHECK(DeleteFileW(base));
}
typedef struct StreamProbeWorker { WCHAR file[2200]; DWORD errors; unsigned slot; } StreamProbeWorker;
static DWORD WINAPI stream_probe_worker(void* context) {
    StreamProbeWorker* worker=context; BYTE data[257], check[257]; DWORD done;
    memset(data,(BYTE)(worker->slot+1),sizeof(data));
    for (unsigned i=0;i<100;++i) {
        HANDLE h=open_file(worker->file,GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,CREATE_ALWAYS,0);
        if (h==INVALID_HANDLE_VALUE) {++worker->errors;continue;}
        if (!WriteFile(h,data,sizeof(data),&done,NULL) || done!=sizeof(data)) ++worker->errors;
        if (SetFilePointer(h,0,NULL,FILE_BEGIN)!=0 || !ReadFile(h,check,sizeof(check),&done,NULL) ||
            done!=sizeof(check) || memcmp(data,check,sizeof(data))) ++worker->errors;
        if (!CloseHandle(h)) ++worker->errors;
    }
    return worker->errors ? 1 : 0;
}
static void test_stream_parallel(void) {
    WCHAR base[2048]; StreamProbeWorker workers[8]; HANDLE threads[8]={0}; DWORD count=0;
    path(base,_countof(base),L"parallel-streams.bin"); CHECK(touch(base));
    for (unsigned i=0;i<8;++i) {
        memset(&workers[i],0,sizeof(workers[i])); workers[i].slot=i;
        swprintf_s(workers[i].file,_countof(workers[i].file),L"%ls:worker-%u",base,i);
        threads[i]=CreateThread(NULL,0,stream_probe_worker,&workers[i],0,NULL);
        CHECK(threads[i]!=NULL); if (!threads[i]) break; ++count;
    }
    if (count) {
        DWORD wait=WaitForMultipleObjects(count,threads,TRUE,30000);
        CHECK(wait==WAIT_OBJECT_0); if (wait!=WAIT_OBJECT_0) ExitProcess(2);
    }
    for (DWORD i=0;i<count;++i) {CHECK(workers[i].errors==0); CloseHandle(threads[i]);}
    CHECK(count==8); CHECK(stream_enumerate(base,NULL,0,NULL)==9);
    CHECK(DeleteFileW(base));
}
#include "memfs_stream_extra_probe.inc"
#include "memfs_zone_com_probe.inc"
static void run_stream_tests(void) {
    STEP("Zone.Identifier read/write, aliases, enumeration, copy, move and delete",test_zone_stream());
    STEP("directory ADS and implicit base-file creation",test_directory_and_implicit_stream());
    STEP("shared stream ACL, file ID and timestamps",test_stream_acl_and_metadata());
    STEP("ADS overwrite, open-handle lifetime and delete-on-close",test_stream_lifetime_and_overwrite());
    STEP("stream sparse/truncate/regrow and memory mapping",test_stream_sparse_and_mapping());
    STEP("8-thread 800 stream write/read cycles",test_stream_parallel());
    STEP("stream share-delete and replace with live old handle",test_stream_share_and_replace());
    STEP("Unicode, long stream names, enumeration and invalid MoveFileEx",test_stream_names_and_enumeration());
    STEP("300 ACL replacements and 600 concurrent stream ACL queries",test_stream_acl_parallel());
    STEP("Windows PersistentZoneIdentifier COM save/load",test_zone_com());
}
