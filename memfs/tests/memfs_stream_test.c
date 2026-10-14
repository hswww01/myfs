#include "memfs_core.h"
#include <sddl.h>
#include <stdio.h>
#include <string.h>
static int failures;
#define CHECK(x) do { if (!(x)) { ++failures; fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); } } while(0)
static void run_mode(bool compress, bool encrypt) {
    MemfsOptions options={0}; Memfs* fs=NULL;
    MemfsNode *base=NULL,*stream=NULL,*other=NULL,*found=NULL;
    PSECURITY_DESCRIPTOR sd=NULL; DWORD sd_bytes=0;
    uint32_t bytes; BYTE data[9000],readback[9000];
    options.capacity=1ULL<<20; options.compression_enabled=compress; options.encryption_enabled=encrypt;
    memset(data,0x64,sizeof(data));
    CHECK(memfs_create_ex(&options,&fs)==MEMFS_OK); if(!fs)return;
    CHECK(sizeof(MemfsNode)==128);
    CHECK(memfs_node_create(fs,fs->root,L"base",false,0,NULL,0,&base)==MEMFS_OK);
    if(!base)goto done;
    CHECK(memfs_stream_create(base,L"Zone.Identifier",0,&stream)==MEMFS_OK);
    if(!stream)goto done;
    CHECK(memfs_node_metadata(stream)==base && memfs_node_get_security(stream)==base->security);
    CHECK(memfs_node_write(stream,data,0,sizeof(data),false,false,&bytes)==MEMFS_OK && bytes==sizeof(data));
    CHECK(base->file_size==0 && stream->file_size==sizeof(data));
    CHECK(memfs_lookup_path(fs,L"\\base:zone.identifier:$DATA",&found)==MEMFS_OK && found==stream);
    CHECK(memfs_lookup_path(fs,L"\\base::$DATA",&found)==MEMFS_OK && found==base);
    CHECK(memfs_lookup_path(fs,L"\\base:bad:$INDEX_ALLOCATION",&found)==MEMFS_ERR_INVALID);
    CHECK(memfs_node_rename(base,fs->root,L"renamed",false)==MEMFS_OK);
    CHECK(memfs_lookup_path(fs,L"\\renamed:Zone.Identifier",&found)==MEMFS_OK && found==stream);
    CHECK(memfs_lookup_path(fs,L"\\base:Zone.Identifier",&found)!=MEMFS_OK);
    CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FA;;;BA)",1,&sd,&sd_bytes));
    if(sd) {CHECK(memfs_node_replace_security(base,sd,sd_bytes)==MEMFS_OK);LocalFree(sd);sd=NULL;}
    CHECK(memfs_node_get_security(stream)==base->security);
    CHECK(memfs_stream_create(base,L"closed",0,&other)==MEMFS_OK);
    if(other) {memfs_node_close(other);other=NULL;}
    memfs_stream_unlink_all(base,true);
    CHECK(memfs_stream_lookup(base,L"closed")==NULL && memfs_stream_lookup(base,L"Zone.Identifier")==stream);
    CHECK(memfs_stream_rename(stream,base,L"zone2",false)==MEMFS_OK);
    CHECK(memfs_lookup_path(fs,L"\\renamed:zone2",&found)==MEMFS_OK && found==stream);
    /* Delete owner while a stream stays open. Only the stream pins owner. */
    CHECK(memfs_node_unlink(base)==MEMFS_OK);
    memfs_node_close(base);base=NULL;
    CHECK(stream->deleted && stream->parent->deleted);
    CHECK(memfs_node_read(stream,readback,0,sizeof(readback),&bytes)==MEMFS_OK && bytes==sizeof(data));
    CHECK(memcmp(data,readback,sizeof(data))==0);
    CHECK(memfs_node_get_security(stream)!=NULL);
    memfs_node_close(stream);stream=NULL;
    CHECK(fs->orphan_head==NULL && fs->used_bytes==0 && memfs_resident_bytes(fs)==0);
    for(unsigned i=0;i<64;++i) CHECK(fs->stream_buckets[i]==NULL);
    /* Quiescent destroy with both attached and orphaned open streams. */
    CHECK(memfs_node_create(fs,fs->root,L"remaining",false,0,NULL,0,&base)==MEMFS_OK);
    if(base) {
        CHECK(memfs_stream_create(base,L"orphan",0,&stream)==MEMFS_OK);
        if(stream)CHECK(memfs_node_unlink(stream)==MEMFS_OK);
        CHECK(memfs_stream_create(base,L"attached",0,&other)==MEMFS_OK);
    }
done:
    memfs_destroy(fs);
}
#ifndef NDEBUG
static void allocation_failure(void) {
    Memfs* fs=NULL; MemfsNode* base=NULL; MemfsNode* stream=NULL;
    CHECK(memfs_create(1ULL<<20,L"ADS_FAIL",&fs)==MEMFS_OK);if(!fs)return;
    CHECK(memfs_node_create(fs,fs->root,L"base",false,0,NULL,0,&base)==MEMFS_OK);
    if(base) {
        MemfsAllocFailPoint points[]={MEMFS_ALLOC_FAIL_NODE,MEMFS_ALLOC_FAIL_NAME};
        for(unsigned i=0;i<_countof(points);++i) {
            uint32_t refs=base->open_count;
            memfs_allocator_test_fail_after(points[i],0,1);
            CHECK(memfs_stream_create(base,L"failed",0,&stream)==MEMFS_ERR_NO_MEMORY);
            memfs_allocator_test_clear_failures();
            CHECK(stream==NULL && base->open_count==refs && memfs_stream_first(base)==NULL);
        }
        CHECK(memfs_node_unlink(base)==MEMFS_OK);memfs_node_close(base);
    }
    memfs_destroy(fs);
}
#endif
/* A synchronous Cleanup is complete but Close is still queued. The old
 * ADS must leave the namespace during overwrite while its data stays alive. */
static void delayed_close_after_cleanup(void) {
    Memfs* fs=NULL; MemfsNode *base=NULL,*ads=NULL,*recreated=NULL;
    uint32_t bytes=0; BYTE value=0;
    CHECK(memfs_create(1ULL<<20,L"ADS_CLEANUP",&fs)==MEMFS_OK);if(!fs)return;
    CHECK(memfs_node_create(fs,fs->root,L"base",false,0,NULL,0,&base)==MEMFS_OK);
    if(base) {
        CHECK(memfs_stream_create(base,L"Zone.Identifier",0,&ads)==MEMFS_OK);
        if(ads) {
            CHECK(memfs_node_write(ads,"Z",0,1,false,false,&bytes)==MEMFS_OK);
            InterlockedExchange(&ads->stream_active_opens,0);
            memfs_stream_unlink_all(base,true);
            CHECK(ads->deleted && ads->open_count==1);
            CHECK(memfs_stream_lookup(base,L"Zone.Identifier")==NULL);
            CHECK(memfs_stream_create(base,L"Zone.Identifier",0,&recreated)==MEMFS_OK);
            CHECK(recreated && recreated!=ads && recreated->file_size==0);
            CHECK(memfs_node_read(ads,&value,0,1,&bytes)==MEMFS_OK && bytes==1 && value=='Z');
            memfs_node_close(ads);
            if(recreated) {CHECK(memfs_node_unlink(recreated)==MEMFS_OK);memfs_node_close(recreated);}
        }
        CHECK(memfs_node_unlink(base)==MEMFS_OK);memfs_node_close(base);
    }
    CHECK(fs->orphan_head==NULL && fs->used_bytes==0);
    memfs_destroy(fs);
}

int main(void) {
    delayed_close_after_cleanup();
    run_mode(false,false);run_mode(true,false);run_mode(true,true);
#ifndef NDEBUG
    allocation_failure();
#endif
    printf("memfs_stream_test: %s\n",failures?"FAIL":"PASS");return failures?1:0;
}
