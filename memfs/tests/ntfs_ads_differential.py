"""Native Win32 ADS contracts compared with a real NTFS directory.

Only GUID-named disposable directories are modified. No installed service is
stopped. --exe owns a fresh private mount; --mounted-root tests an existing
mount without stopping it. Uses only Python's standard library.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

K = C.WinDLL('kernel32', use_last_error=True)
A = C.WinDLL('advapi32', use_last_error=True)
INVALID = C.c_void_p(-1).value
READ, WRITE, DELETE = 0x80000000, 0x40000000, 0x10000
SHARE = 7

def bind(dll, name, restype, *types):
    fn = getattr(dll, name); fn.restype = restype; fn.argtypes = list(types)
    return fn
create = bind(K, 'CreateFileW', W.HANDLE, W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE)
close = bind(K, 'CloseHandle', W.BOOL, W.HANDLE)
read = bind(K, 'ReadFile', W.BOOL, W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p)
write = bind(K, 'WriteFile', W.BOOL, W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p)
delete = bind(K, 'DeleteFileW', W.BOOL, W.LPCWSTR)
move = bind(K, 'MoveFileExW', W.BOOL, W.LPCWSTR, W.LPCWSTR, W.DWORD)
copy = bind(K, 'CopyFileW', W.BOOL, W.LPCWSTR, W.LPCWSTR, W.BOOL)
setattr_ = bind(K, 'SetFileAttributesW', W.BOOL, W.LPCWSTR, W.DWORD)
seek = bind(K, 'SetFilePointerEx', W.BOOL, W.HANDLE, C.c_longlong, C.POINTER(C.c_longlong), W.DWORD)
eof = bind(K, 'SetEndOfFile', W.BOOL, W.HANDLE)
flush = bind(K, 'FlushFileBuffers', W.BOOL, W.HANDLE)
querydev = bind(K, 'QueryDosDeviceW', W.DWORD, W.LPCWSTR, W.LPWSTR, W.DWORD)
setinfo = bind(K, 'SetFileInformationByHandle', W.BOOL, W.HANDLE, C.c_int, C.c_void_p, W.DWORD)
getsecurity = bind(A, 'GetFileSecurityW', W.BOOL, W.LPCWSTR, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD))
setsecurity = bind(A, 'SetFileSecurityW', W.BOOL, W.LPCWSTR, W.DWORD, C.c_void_p)
sddl = bind(A, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', W.BOOL, W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD))
localfree = bind(K, 'LocalFree', C.c_void_p, C.c_void_p)

class StreamInfo(C.Structure):
    _fields_ = [('size', C.c_longlong), ('name', W.WCHAR * 296)]
firststream = bind(K, 'FindFirstStreamW', W.HANDLE, W.LPCWSTR, C.c_int, C.POINTER(StreamInfo), W.DWORD)
nextstream = bind(K, 'FindNextStreamW', W.BOOL, W.HANDLE, C.POINTER(StreamInfo))
findclose = bind(K, 'FindClose', W.BOOL, W.HANDLE)

class FileInfo(C.Structure):
    _fields_ = [('attributes', W.DWORD), ('created', W.FILETIME), ('accessed', W.FILETIME),
                ('written', W.FILETIME), ('serial', W.DWORD), ('size_hi', W.DWORD),
                ('size_lo', W.DWORD), ('links', W.DWORD), ('id_hi', W.DWORD), ('id_lo', W.DWORD)]
getinfo = bind(K, 'GetFileInformationByHandle', W.BOOL, W.HANDLE, C.POINTER(FileInfo))
settime = bind(K, 'SetFileTime', W.BOOL, W.HANDLE, C.POINTER(W.FILETIME), C.POINTER(W.FILETIME), C.POINTER(W.FILETIME))

class RenameInfo(C.Structure):
    _fields_ = [('replace', W.BOOL), ('root', W.HANDLE), ('length', W.DWORD), ('name', W.WCHAR * 1024)]

class Handle:
    def __init__(self, name: str, access: int = READ | WRITE, share: int = SHARE,
                 disposition: int = 3, flags: int = 0):
        self.h = create(name, access, share, None, disposition, flags, None)
        if self.h == INVALID:
            raise OSError(C.get_last_error(), 'CreateFile')
    def __enter__(self): return self.h
    def __exit__(self, *args):
        if self.h != INVALID: close(self.h); self.h = INVALID

def check(ok, what: str):
    if not ok: raise OSError(C.get_last_error(), what)

def put(name: str, data: bytes, disposition: int = 2):
    with Handle(name, WRITE, disposition=disposition) as h:
        done = W.DWORD(); check(write(h, data, len(data), C.byref(done), None), 'WriteFile')
        assert done.value == len(data)

def get(name: str, limit: int = 2 * 1024 * 1024) -> bytes:
    with Handle(name, READ) as h:
        b = C.create_string_buffer(limit); done = W.DWORD()
        check(read(h, b, limit, C.byref(done), None), 'ReadFile')
        return b.raw[:done.value]

def open_status(name: str, access: int, disp: int = 3, share: int = SHARE, flags: int = 0) -> int:
    h = create(name, access, share, None, disp, flags, None)
    if h == INVALID: return C.get_last_error()
    close(h); return 0

def streams(name: str) -> list:
    info = StreamInfo(); h = firststream(name, 0, C.byref(info), 0)
    if h == INVALID:
        error = C.get_last_error()
        if error == 38: return []
        raise OSError(error, 'FindFirstStream')
    found = []
    try:
        while True:
            found.append([info.name, info.size])
            if not nextstream(h, C.byref(info)):
                check(C.get_last_error() == 38, 'FindNextStream')
                break
    finally: findclose(h)
    return sorted(found, key=lambda a: a[0].upper())

def sd(name: str) -> bytes:
    size = W.DWORD(); getsecurity(name, 7, None, 0, C.byref(size))
    check(size.value != 0, 'GetFileSecurity size')
    b = C.create_string_buffer(size.value)
    check(getsecurity(name, 7, b, len(b), C.byref(size)), 'GetFileSecurity')
    return b.raw[:size.value]

def set_sd(name: str, text: str):
    ptr = C.c_void_p()
    check(sddl(text, 1, C.byref(ptr), None), 'Convert SDDL')
    try: check(setsecurity(name, 4 | 0x80000000, ptr), 'SetFileSecurity')
    finally: localfree(ptr)

def basic_suite(root: str) -> dict:
    out = {}
    def run(name, fn):
        try: out[name] = fn()
        except Exception as e:
            out[name] = {'error': getattr(e, 'winerror', None) or getattr(e, 'errno', None), 'operation': str(e).split(':')[0]}
    def p(s): return root + '\\' + s
    zone = b'[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/test\r\n'
    def basics():
        f = p('zone.txt'); put(f, b'base-content'); put(f + ':Zone.Identifier', zone)
        return [get(f).decode(), get(f + ':zone.identifier:$data') == zone,
                os.stat(f).st_size, streams(f), sorted(os.listdir(root)),
                open_status(f + ':ZONE.IDENTIFIER', WRITE, 1)]
    run('Zone.Identifier/read/case/enumeration/size/collision', basics)
    def alias():
        f=p('aliases'); put(f, b'default'); put(f+':$DATA',b'named dollar'); put(f+': spaced 中文 ', b'unicode')
        return [get(f+'::$DATA').decode(), get(f+':$DATA:$DATA').decode(), streams(f)]
    run('default alias/dollar stream/unicode names',alias)
    def implicit():
        f=p('implicit'); put(f+':created',b'created'); return [os.path.isfile(f),os.stat(f).st_size,streams(f)]
    run('creating stream creates missing base',implicit)
    def directory():
        f=p('directory'); os.mkdir(f); put(f+':Zone.Identifier',zone)
        result=[get(f+':Zone.Identifier')==zone,streams(f),os.listdir(f)]
        os.rmdir(f); return result+[os.path.exists(f),open_status(f+':Zone.Identifier',READ)]
    run('directory named stream and deletion',directory)
    def deletion():
        f=p('delete-stream'); put(f,b'main'); put(f+':a',b'a'); put(f+':b',b'b')
        check(delete(f+':a'),'DeleteFile stream'); r=[get(f).decode(),streams(f)]
        check(delete(f),'DeleteFile base'); return r+[open_status(f+':b',READ)]
    run('delete ADS separately and delete all with base',deletion)
    def rename_tree():
        d=p('old-dir'); os.mkdir(d); f=d+'\\old';put(f,b'main');put(f+':Zone.Identifier',zone)
        check(move(f,d+'\\new',0),'rename base'); check(move(d,p('new-dir'),0),'rename parent')
        return [get(p('new-dir\\new:Zone.Identifier'))==zone,streams(p('new-dir\\new')),os.listdir(p('new-dir'))]
    run('base and ancestor rename carries streams',rename_tree)
    def replace():
        f=p('replace-source'); g=p('replace-dest');put(f,b'new');put(f+':new',b'N');put(g,b'old');put(g+':old',b'O')
        check(move(f,g,1),'replace via rename');return [get(g).decode(),streams(g),open_status(g+':old',READ)]
    run('replacement removes old destination ADS',replace)
    def renamed_ads():
        f=p('rename-ads');put(f,b'main');put(f+':old',b'original')
        with Handle(f+':old',DELETE) as h:
            i=RenameInfo();i.replace=False;i.name=':new';i.length=len(i.name.encode('utf-16-le'))
            ok=setinfo(h,3,C.byref(i),RenameInfo.name.offset+i.length)
            error=0 if ok else C.get_last_error()
        return [error,streams(f)]
    run('native stream rename',renamed_ads)
    def overwrite(disp):
        f=p('overwrite-'+str(disp));put(f,b'main');put(f+':a',b'a');put(f+':b',b'keep')
        with Handle(f+':b',READ):
            error=open_status(f,WRITE,disp)
            current=streams(f)
        return [error,current,streams(f)]
    run('CREATE_ALWAYS retains open ADS until last cleanup',lambda:overwrite(2))
    run('TRUNCATE_EXISTING stream semantics',lambda:overwrite(5))
    def eof_only():
        f=p('eof');put(f,b'main');put(f+':Zone.Identifier',zone)
        with Handle(f,WRITE) as h: check(eof(h),'SetEndOfFile')
        return streams(f)
    run('SetEndOfFile preserves ADS',eof_only)
    def no_resurrection():
        f=p('no-resurrection');put(f,b'old');put(f+':gone',b'old stream')
        with Handle(f+':gone',READ) as h:
            put(f,b'new')
            b=C.create_string_buffer(32);n=W.DWORD();check(read(h,b,32,C.byref(n),None),'retired stream handle')
            r=[b.raw[:n.value].decode(),open_status(f+':gone',READ)]
        time.sleep(1.1)  # query again after the one-second WinFsp metadata cache expires
        r += [open_status(f+':gone',READ),streams(f)]
        put(f+':gone',b'recreated',1)
        return r+[get(f+':gone').decode(),get(f).decode()]
    run('overwritten ADS never resurrects after cache expiration',no_resurrection)
    def stream_overwrite():
        f=p('s-overwrite');put(f,b'main');put(f+':a',b'abcdef');put(f+':b',b'sibling');put(f+':a',b'x')
        return [get(f).decode(),streams(f),get(f+':a').decode()]
    run('overwriting ADS preserves other data',stream_overwrite)
    def sharing():
        f=p('share');put(f,b'main');put(f+':a',b'aaa');put(f+':b',b'bbb')
        with Handle(f+':a',READ,share=1):
            r=[open_status(f+':a',WRITE),open_status(f,WRITE),open_status(f+':b',WRITE),
               bool(delete(f))];r.append(0 if r[-1] else C.get_last_error())
        return r
    run('per-stream sharing and base delete denial',sharing)
    def unlinked_handle():
        f=p('unlinked');put(f,b'main');put(f+':live',b'still alive')
        with Handle(f+':live',READ|WRITE) as h:
            ok=bool(delete(f)); error=0 if ok else C.get_last_error()
            b=C.create_string_buffer(64);done=W.DWORD();check(read(h,b,64,C.byref(done),None),'read after delete')
            r=[ok,error,b.raw[:done.value].decode()]
        return r+[os.path.exists(f),open_status(f+':live',READ)]
    run('open ADS lifetime after base deletion',unlinked_handle)
    def readonly():
        f=p('readonly');put(f,b'main');put(f+':zone',b'zone');check(setattr_(f,1),'readonly on')
        try:r=[open_status(f+':zone',WRITE),open_status(f+':new',WRITE,1),get(f+':zone').decode()]
        finally:check(setattr_(f,0x80),'readonly off')
        return r
    run('readonly base protects existing/new ADS',readonly)
    def metadata():
        f=p('metadata');put(f,b'main');put(f+':a',b'123456789')
        with Handle(f,READ) as base, Handle(f+':a',READ|WRITE) as stream:
            t=W.FILETIME(0x12345600,0x01db1000);check(settime(stream,None,None,C.byref(t)),'SetFileTime ADS')
            a=FileInfo();b=FileInfo();check(getinfo(base,C.byref(a)),'base info');check(getinfo(stream,C.byref(b)),'stream info')
            return [(a.id_hi,a.id_lo)==(b.id_hi,b.id_lo),a.size_lo,b.size_lo,
                    (a.written.dwHighDateTime,a.written.dwLowDateTime)==(b.written.dwHighDateTime,b.written.dwLowDateTime)]
    run('shared file id/time with independent sizes',metadata)
    def security():
        f=p('security');put(f,b'main');put(f+':Zone.Identifier',zone); original=sd(f)
        with Handle(f+':Zone.Identifier',READ) as old:
            try:
                set_sd(f,'D:P(D;;0x2;;;WD)(A;;FA;;;WD)')
                same=sd(f)==sd(f+':Zone.Identifier')
                denied=[open_status(f+':Zone.Identifier',WRITE),open_status(f+':new',WRITE,1)]
                set_sd(f+':Zone.Identifier','D:P(D;;0x1;;;WD)(A;;FA;;;WD)')
                denied += [open_status(f,READ),open_status(f+':Zone.Identifier',READ)]
                b=C.create_string_buffer(128);done=W.DWORD();check(read(old,b,128,C.byref(done),None),'existing authorized handle')
                return [same,denied,b.raw[:done.value]==zone]
            finally:check(setsecurity(f,4|0x80000000,original),'restore test DACL')
    run('base/ADS DACL shared; revocation; no privilege bypass',security)
    def sparse_mapping():
        f=p('sparse');put(f,b'main');s=f+':large';put(s,b'')
        with Handle(s) as h:
            check(seek(h,1024*1024+19,None,0),'sparse seek');done=W.DWORD();check(write(h,b'end',3,C.byref(done),None),'sparse tail');check(flush(h),'flush')
        data=get(s)
        with open(s,'r+b') as fobj:
            with mmap.mmap(fobj.fileno(),0,access=mmap.ACCESS_WRITE) as m:
                m[65530:65550]=b'm'*20;m.flush()
        changed=get(s)
        return [len(data),not any(data[:-3]),data[-3:].decode(),changed[65530:65550]==b'm'*20,get(f).decode()]
    run('ADS sparse storage and memory mapping',sparse_mapping)
    def many():
        f=p('many');put(f,b'main')
        for i in range(96):put(f+f':stream-{i:03d}',bytes([i])*i)
        return [len(streams(f)),sum(x[1] for x in streams(f)),all(get(f+f':stream-{i:03d}')==bytes([i])*i for i in range(96))]
    run('96-stream enumeration and readback',many)
    def unusual():
        f=p('unusual');put(f,b'main');result={}
        for name in ['.', '..', 'trailing.', '$DATA', '中文', 'space name', 'x'*255, 'x'*256]:
            native='\\\\?\\'+f+':'+name
            status=open_status(native,WRITE,1);result[name if len(name)<32 else str(len(name))]=status
        return result
    run('stream name limits and special names',unusual)
    def rename_open_base():
        f=p('open-rename');put(f,b'main');put(f+':open',b'open data')
        with Handle(f+':open',READ):
            ok=move(f,f+'-renamed',0)
            error=0 if ok else C.get_last_error()
        actual=f+'-renamed' if ok else f
        return [error,get(actual+':open').decode()]
    run('base rename while an ADS handle is open',rename_open_base)
    def bounded_long_names():
        f=p('long');put(f,b'main');name='x'*230
        put(f+':'+name+':$DATA',b'long stream')
        return [get(f+':'+name)==b'long stream',streams(f),
                open_status(f+':not-data:$INDEX_ALLOCATION',WRITE,1)]
    run('long valid ADS name and invalid stream type',bounded_long_names)
    return out

def copy_roundtrip(reference: str, target: str) -> dict:
    f=reference+'\\copy-source';g=target+'\\copy-in';h=reference+'\\copy-out'
    put(f,b'COPY-MAIN');put(f+':Zone.Identifier',b'[ZoneTransfer]\r\nZoneId=3\r\n');put(f+':binary',bytes(range(256)))
    check(copy(f,g,True),'NTFS -> memfs CopyFile')
    check(copy(g,h,True),'memfs -> NTFS CopyFile')
    expected=streams(f)
    assert streams(g)==expected and streams(h)==expected
    for suffix in ['',':Zone.Identifier',':binary']:
        assert get(f+suffix)==get(g+suffix)==get(h+suffix)
    return {'streams':expected,'all_bytes_equal':True}

def concurrent_stress(root: str, rounds: int) -> dict:
    def worker(worker_id):
        for i in range(rounds):
            name=root+f'\\thread-{worker_id}-{i}'
            put(name,b'base');payload=bytes([worker_id+1])*(8192+i)
            put(name+':Zone.Identifier',payload);put(name+':other',b'other')
            # Legacy rename of a base while ADS handles are open is measured
            # separately as a kernel limitation, not silently retried here.
            check(move(name,name+'-moved',0),'stress rename')
            with Handle(name+'-moved:Zone.Identifier',READ) as h:
                assert get(name+'-moved:Zone.Identifier')==payload
                check(delete(name+'-moved'),'stress delete base')
                b=C.create_string_buffer(len(payload));n=W.DWORD()
                check(read(h,b,len(b),C.byref(n),None),'stress orphan stream read')
                assert b.raw[:n.value]==payload
            assert open_status(name+'-moved:Zone.Identifier',READ)==2
        return rounds
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        count=sum(pool.map(worker,range(8)))
    return {'threads':8,'lifecycle_cycles':count,'checks':'all bytes, renamed streams and orphan handles valid'}

def device_exists(drive: str) -> bool:
    b=C.create_unicode_buffer(32768)
    if querydev(drive,b,len(b)):return True
    if C.get_last_error()!=2:raise OSError(C.get_last_error(),'QueryDosDevice')
    return False

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--exe');group.add_argument('--mounted-root')
    ap.add_argument('--drive',default='V:');ap.add_argument('--reference',required=True)
    ap.add_argument('--output',required=True);ap.add_argument('--compress',action='store_true');ap.add_argument('--encrypt',action='store_true')
    ap.add_argument('--rounds',type=int,default=32)
    ap.add_argument('--allow-known-winfsp-limits',action='store_true',
        help='Report exact known signed-driver differences separately; fail on any new difference. Default is strict NTFS equality.')
    args=ap.parse_args();token=uuid.uuid4().hex
    ref=Path(args.reference).resolve()/('ads-reference-'+token)
    drive_mutex=None;owns_mutex=False
    process=None;event_name='Local\\MemfsADS-'+token
    target=None;log=None;result={'mode':{'compress':args.compress,'encrypt':args.encrypt}}
    try:
        if args.exe:
            # Never invoke memfs's automatic driver-install fallback in CI.
            guard=subprocess.run([shutil.which('pwsh.exe') or 'powershell.exe','-NoLogo','-NoProfile','-NonInteractive',
                '-ExecutionPolicy','Bypass','-File',str(Path(__file__).with_name('private-driver-preflight.ps1')),
                '-Exe',str(Path(args.exe).resolve())],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
            if guard.returncode==77:
                result['skipped']='matching private WinFsp driver is not already running'
                print('SKIP '+result['skipped'],flush=True);return 77
            if guard.returncode!=0:raise RuntimeError('could not verify private driver: '+guard.stderr.decode(errors='replace')+'')
            if len(args.drive)!=2 or args.drive[1]!=':' or not args.drive[0].isalpha():raise ValueError('invalid drive')
            mutex_create=bind(K,'CreateMutexW',W.HANDLE,C.c_void_p,W.BOOL,W.LPCWSTR)
            wait=bind(K,'WaitForSingleObject',W.DWORD,W.HANDLE,W.DWORD)
            drive_mutex=mutex_create(None,False,'Local\\MemfsTestDrive-'+args.drive[0].upper())
            check(drive_mutex,'CreateMutex test drive')
            wait_status=wait(drive_mutex,60000)
            owns_mutex=wait_status in (0,0x80)
            if not owns_mutex:raise TimeoutError('private test drive mutex timeout')
            if device_exists(args.drive):raise RuntimeError('refusing occupied drive '+args.drive)
            log=open(str(args.output)+'.mount.log','w',encoding='utf-8')
            cmd=[str(Path(args.exe).resolve()),'--mount',args.drive,'--size','128M','--mkdir','tmp','--stop-event',event_name]
            if args.compress:cmd+=['--compress']
            if args.encrypt:cmd+=['--encrypt']
            process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
            base=args.drive+'\\tmp'
            for _ in range(150):
                if process.poll() is not None:raise RuntimeError('mount exited '+str(process.returncode))
                if os.path.isdir(base):break
                time.sleep(.1)
            else:raise TimeoutError('mount timeout')
        else:base=str(Path(args.mounted_root).resolve())
        target=Path(base)/('ads-target-'+token)
        ref.mkdir();target.mkdir()
        result['reference']=basic_suite(str(ref))
        result['target']=basic_suite(str(target))
        # Essential features must work on NTFS; matching two setup failures is NOT a pass.
        for name,value in result['reference'].items():
            if isinstance(value,dict) and 'operation' in value:raise AssertionError('NTFS fixture failed: '+name+': '+str(value))
        result['differences']={k:{'ntfs':v,'memfs':result['target'].get(k)} for k,v in result['reference'].items() if v!=result['target'].get(k)}
        # Strict equality remains the default. These are exact observed
        # comparisons, NOT exclusions by test name: new outcomes still fail.
        expected_limits={
            'native stream rename':{
                'ntfs':[0,[['::$DATA',4],[':new:$DATA',8]]],
                'memfs':[87,[['::$DATA',4],[':old:$DATA',8]]]},
            'base rename while an ADS handle is open':{
                'ntfs':[0,'open data'],'memfs':[5,'open data']},
            'stream name limits and special names':{
                'ntfs':{'.':0,'..':0,'trailing.':0,'$DATA':0,'中文':0,'space name':0,'255':0,'256':123},
                'memfs':{'.':0,'..':0,'trailing.':0,'$DATA':0,'中文':0,'space name':0,'255':123,'256':123}}
        }
        # WinFsp rejects unsupported stream types in its name parser (123),
        # while NTFS returns INVALID_PARAMETER (87). Both must reject.
        expected_limits['long valid ADS name and invalid stream type']={
            'ntfs':[True,[['::$DATA',4],[':'+('x'*230)+':$DATA',11]],87],
            'memfs':[True,[['::$DATA',4],[':'+('x'*230)+':$DATA',11]],123]}
        result['known_kernel_limitations']={k:v for k,v in result['differences'].items()
            if v==expected_limits.get(k)}
        result['unexpected_differences']={k:v for k,v in result['differences'].items()
            if k not in result['known_kernel_limitations']}
        result['strict_ntfs_match']=not bool(result['differences'])
        for name in result['reference']:
            label=('KNOWN LIMIT ' if name in result['known_kernel_limitations'] else 'FAIL ') if name in result['differences'] else 'PASS '
            print(label+name,flush=True)
        if result['differences']:
            print(json.dumps(result['differences'],ensure_ascii=True,indent=2),flush=True)
        result['copy_roundtrip']=copy_roundtrip(str(ref),str(target));print('PASS bidirectional NTFS CopyFile with Zone.Identifier',flush=True)
        result['stress']=concurrent_stress(str(target),args.rounds);print('PASS concurrent ADS lifetime stress '+str(result['stress']['lifecycle_cycles']),flush=True)
        result['matching_categories']=len(result['reference'])-len(result['differences'])
        result['total_categories']=len(result['reference'])
        print(f"SUMMARY: {result['matching_categories']}/{result['total_categories']} exact NTFS matches; "
              f"{len(result['known_kernel_limitations'])} known driver limits; "
              f"{len(result['unexpected_differences'])} unexpected differences",flush=True)
        return 1 if (result['unexpected_differences'] or (result['differences'] and not args.allow_known_winfsp_limits)) else 0
    except Exception as e:
        result['fatal']=repr(e);print('FATAL '+repr(e),flush=True);return 1
    finally:
        for path_ in [target,ref]:
            if path_ is not None and path_.exists():
                try:shutil.rmtree(path_)
                except Exception as e:result.setdefault('cleanup_errors',[]).append(str(e))
        if process is not None:
            if process.poll() is None:
                openevent=bind(K,'OpenEventW',W.HANDLE,W.DWORD,W.BOOL,W.LPCWSTR)
                setevent=bind(K,'SetEvent',W.BOOL,W.HANDLE)
                ev=openevent(2,False,event_name)
                if ev:setevent(ev);close(ev)
                try:process.wait(timeout=20)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=10);result.setdefault('cleanup_errors',[]).append('private mount stop timeout')
            result['mount_exit_code']=process.returncode
            if process.returncode!=0:result.setdefault('cleanup_errors',[]).append('nonzero private mount exit')
        if drive_mutex:
            if owns_mutex:
                release=bind(K,'ReleaseMutex',W.BOOL,W.HANDLE);release(drive_mutex)
            close(drive_mutex)
        if log:log.close()
        Path(args.output).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        if result.get('cleanup_errors'):
            print('CLEANUP FAILED '+str(result['cleanup_errors']),flush=True)
            raise RuntimeError('test cleanup failed; see report')

if __name__=='__main__':sys.exit(main())
