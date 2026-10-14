static void test_stream_share_and_replace(void) {
    WCHAR a[2048],b[2048],ads[2200],bads[2200],renamed[2200];
    HANDLE h; char buf[16]; DWORD done;
    path(a,_countof(a),L"share-ads.bin");path(b,_countof(b),L"replace-ads.bin");
    stream_write(a,"A",1,CREATE_NEW);stream_write(b,"B",1,CREATE_NEW);
    stream_path(ads,_countof(ads),a,L"old");stream_path(bads,_countof(bads),b,L"new");
    stream_write(ads,"ORIGINAL",8,CREATE_NEW);stream_write(bads,"REPLACEMENT",11,CREATE_NEW);
    h=open_file(ads,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,OPEN_EXISTING,0);
    CHECK(h!=INVALID_HANDLE_VALUE);
    CHECK(!DeleteFileW(a) && GetLastError()==ERROR_SHARING_VIOLATION);
    if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
    h=open_file(ads,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,OPEN_EXISTING,0);
    CHECK(h!=INVALID_HANDLE_VALUE);
    /* NTFS refuses replacement while the old named stream is open, even
     * when it shares delete. It succeeds after the last stream handle closes. */
    CHECK(!MoveFileExW(b,a,MOVEFILE_REPLACE_EXISTING) && GetLastError()==ERROR_ACCESS_DENIED);
    stream_expect(a,"A",1);
    if(h!=INVALID_HANDLE_VALUE) {
        CHECK(ReadFile(h,buf,sizeof(buf),&done,NULL) && done==8 && !memcmp(buf,"ORIGINAL",8));
        CHECK(CloseHandle(h));
    }
    CHECK(MoveFileExW(b,a,MOVEFILE_REPLACE_EXISTING));
    stream_expect(a,"B",1);stream_path(renamed,_countof(renamed),a,L"new");
    stream_expect(renamed,"REPLACEMENT",11);
    CHECK(!stream_exists(ads));CHECK(DeleteFileW(a));
}
static void test_stream_names_and_enumeration(void) {
    WCHAR file[2048],ads[2600],name[256],newname[2600];
    BOOL found; HANDLE h;
    path(file,_countof(file),L"names.bin");CHECK(touch(file));
    stream_path(ads,_countof(ads),file,L"\x6570\x636e");
    stream_write(ads,"UNICODE",7,CREATE_NEW);stream_expect(ads,"UNICODE",7);
    stream_path(newname,_countof(newname),file,L"renamed");
    BOOL moved=MoveFileExW(ads,newname,0);
    CHECK(!moved); /* MoveFileEx is not a stream-rename API on NTFS. */
    if(moved) {stream_expect(newname,"UNICODE",7);CHECK(!stream_exists(ads));}
    for(unsigned i=0;i<64;++i) {
        swprintf_s(name,_countof(name),L"number-%03u",i);
        stream_path(ads,_countof(ads),file,name);stream_write(ads,&i,sizeof(i),CREATE_NEW);
    }
    CHECK(stream_enumerate(file,L":number-063:$DATA",sizeof(unsigned),&found)==66 && found);
    for(unsigned i=0;i<240;++i)name[i]=L'x';name[240]=0;
    stream_path(ads,_countof(ads),file,name);stream_write(ads,"MAX",3,CREATE_NEW);
    stream_expect(ads,"MAX",3);
    /* Record, rather than hide, the signed WinFsp 2.1 driver boundary:
     * it counts base:stream together against 255; NTFS accepts this case. */
    for(unsigned i=0;i<255;++i)name[i]=L'y';name[255]=0;
    stream_path(ads,_countof(ads),file,name);
    h=open_file(ads,GENERIC_WRITE,0,CREATE_NEW,0);
    DWORD boundary_error=h==INVALID_HANDLE_VALUE?GetLastError():0;
    printf("BOUNDARY 255-character ADS: accepted=%d win32=%lu (WinFsp 2.1 combined-component limit)\n",
        h!=INVALID_HANDLE_VALUE,boundary_error);
    if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
    else CHECK(boundary_error==ERROR_INVALID_NAME);
    stream_path(ads,_countof(ads),file,L"bad:$INDEX_ALLOCATION");
    h=open_file(ads,GENERIC_WRITE,0,CREATE_NEW,0);
    CHECK(h==INVALID_HANDLE_VALUE);if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);
    CHECK(DeleteFileW(file));
}
typedef struct StreamAclWorker { WCHAR base[2048],stream[2200]; BOOL writer; DWORD errors; DWORD last_error; } StreamAclWorker;
static DWORD WINAPI stream_acl_worker(void* context) {
    StreamAclWorker* w=context;
    for(unsigned i=0;i<300;++i) {
        if(w->writer) {
            if(!set_sddl(w->base,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,
                (i&1)?L"D:P(A;;FA;;;WD)(A;;FR;;;SY)":L"D:P(A;;FA;;;WD)(A;;FA;;;BA)")){w->last_error=GetLastError();++w->errors;}
        } else {
            PSECURITY_DESCRIPTOR sd=get_sd((i&1)?w->base:w->stream,DACL_SECURITY_INFORMATION);
            if(!sd || !IsValidSecurityDescriptor(sd)){w->last_error=GetLastError();++w->errors;}
            if(sd)LocalFree(sd);
        }
    }
    return w->errors?1:0;
}
static void test_stream_acl_parallel(void) {
    StreamAclWorker workers[3]={0};HANDLE threads[3]={0};DWORD count=0;
    path(workers[0].base,_countof(workers[0].base),L"acl-parallel.bin");CHECK(touch(workers[0].base));
    stream_path(workers[0].stream,_countof(workers[0].stream),workers[0].base,L"acl");
    stream_write(workers[0].stream,"ACL",3,CREATE_NEW);
    for(unsigned i=0;i<3;++i) {
        if(i)workers[i]=workers[0];workers[i].writer=i==0;
        threads[i]=CreateThread(NULL,0,stream_acl_worker,&workers[i],0,NULL);
        CHECK(threads[i]!=NULL);if(!threads[i])break;++count;
    }
    if(count) {
        DWORD wait=WaitForMultipleObjects(count,threads,TRUE,30000);
        CHECK(wait==WAIT_OBJECT_0);if(wait!=WAIT_OBJECT_0)ExitProcess(2);
    }
    for(DWORD i=0;i<count;++i){if(workers[i].errors)printf("ACL worker %lu: errors=%lu last=%lu writer=%d\n",i,workers[i].errors,workers[i].last_error,workers[i].writer);CHECK(workers[i].errors==0);CloseHandle(threads[i]);}
    CHECK(count==3);CHECK(DeleteFileW(workers[0].base));
}
