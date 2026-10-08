"""Real, isolated WinFsp acceptance; uses only an unused drive and fresh D: files."""
import argparse
import concurrent.futures
import ctypes
from ctypes import wintypes
import hashlib
import json
import msvcrt
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

K = ctypes.WinDLL('kernel32', use_last_error=True)
K.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
K.CreateEventW.restype = wintypes.HANDLE
K.SetEvent.argtypes = [wintypes.HANDLE]
K.ResetEvent.argtypes = [wintypes.HANDLE]
K.CloseHandle.argtypes = [wintypes.HANDLE]
K.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
K.GetCompressedFileSizeW.restype = wintypes.DWORD
K.CopyFileW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.BOOL]
K.CopyFileW.restype = wintypes.BOOL
K.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
K.SetFileInformationByHandle.restype = wintypes.BOOL
FILE_ALLOCATION_INFO_CLASS = 5


def set_allocation(path, size):
    allocation = ctypes.c_longlong(size)
    with open(path, 'r+b') as f:
        if not K.SetFileInformationByHandle(msvcrt.get_osfhandle(f.fileno()),
                                            FILE_ALLOCATION_INFO_CLASS,
                                            ctypes.byref(allocation), ctypes.sizeof(allocation)):
            raise ctypes.WinError(ctypes.get_last_error())


def allocated(path):
    high = wintypes.DWORD()
    low = K.GetCompressedFileSizeW(str(path), ctypes.byref(high))
    if low == 0xffffffff and ctypes.get_last_error():
        raise ctypes.WinError(ctypes.get_last_error())
    return (high.value << 32) | low


def wait_for(predicate, timeout, message):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--drive', default='X:')
    parser.add_argument('--work', type=Path, default=Path(r'D:\work\fs\cryptfs\build\integration'))
    args = parser.parse_args()
    assert len(args.drive) == 2 and args.drive[1] == ':'
    root = Path(args.drive + '\\')
    assert not root.exists(), f'Refuse to touch occupied drive {root}'
    args.work.mkdir(parents=True, exist_ok=True)
    run = args.work / uuid.uuid4().hex
    run.mkdir()
    container = run / 'acceptance.cfs'
    password = 'temporary-test-secret-\u5bc6\u7801-' + uuid.uuid4().hex
    metrics = {}
    event_name = 'Local\\CryptfsAcceptance-' + uuid.uuid4().hex
    event = K.CreateEventW(None, True, False, event_name)
    if not event:
        raise ctypes.WinError(ctypes.get_last_error())
    proc = None
    out = open(run / 'mount.stdout.log', 'wb')
    err = open(run / 'mount.stderr.log', 'wb')

    def mount(create):
        command = [str(args.exe.resolve()), '--container', str(container), '--mount', args.drive,
                   '--password-stdin', '--stop-event', event_name]
        if create:
            command.append('--create')
        K.ResetEvent(event)
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err)
        p.stdin.write((password + '\n').encode('utf-8'))
        p.stdin.close()
        started = time.monotonic()
        wait_for(lambda: root.exists() or p.poll() is not None, 30, 'mount timeout')
        if p.poll() is not None:
            raise AssertionError(f'mount exited {p.returncode}; see {run}')
        metrics['unlock_seconds' if not create else 'create_seconds'] = time.monotonic() - started
        return p

    def stop(p):
        assert K.SetEvent(event)
        p.wait(timeout=30)
        assert p.returncode == 0, f'mount process failed: {p.returncode}'
        wait_for(lambda: not root.exists(), 10, 'drive survived shutdown')

    try:
        proc = mount(True)
        folder = root / 'MixedCase'
        folder.mkdir()
        (folder / 'Foo.txt').write_bytes(b'upper-case')
        (folder / 'foo.txt').write_bytes(b'lower-case')
        assert (folder / 'Foo.txt').read_bytes() == b'upper-case'
        assert (folder / 'foo.txt').read_bytes() == b'lower-case'
        assert not (folder / 'FOO.txt').exists()
        assert {'Foo.txt', 'foo.txt'} <= set(os.listdir(folder))
        (folder / 'Foo.txt').rename(folder / 'Bar.txt')
        assert not (folder / 'Foo.txt').exists()
        data = b'Compressible-data-' * 65536
        (folder / 'compressed.bin').write_bytes(data)
        assert (folder / 'compressed.bin').read_bytes() == data
        # Cross the 125-entry map boundary and keep every block distinct.
        multi_map = b''.join(bytes([(i * 29) & 255]) * 65536 for i in range(130))
        (folder / 'multi-map.bin').write_bytes(multi_map)
        assert (folder / 'multi-map.bin').read_bytes() == multi_map
        metrics['multi_map_size'] = len(multi_map)
        sparse = folder / 'sparse.bin'
        with open(sparse, 'wb') as f:
            f.seek(8 * 1024**3)
            f.write(b'far-away-content')
        assert sparse.stat().st_size == 8 * 1024**3 + 16
        with open(sparse, 'rb') as f:
            f.seek(4 * 1024**3)
            assert f.read(4096) == b'\0' * 4096
            f.seek(8 * 1024**3)
            assert f.read() == b'far-away-content'
        timestamp = 1700000000
        os.utime(folder / 'Bar.txt', (timestamp, timestamp))
        assert abs((folder / 'Bar.txt').stat().st_mtime - timestamp) < .001

        def thread_io(i):
            for j in range(8):
                p = folder / f'thread-{i}-{j}'
                content = hashlib.sha256(f'{i}-{j}'.encode()).digest() * 128
                p.write_bytes(content)
                assert p.read_bytes() == content
                p.unlink()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(thread_io, range(4)))

        random_data = os.urandom(2 * 1024**2)
        tail = folder / 'tail.bin'
        tail.write_bytes(random_data)
        assert hashlib.sha256(tail.read_bytes()).digest() == hashlib.sha256(random_data).digest()
        metrics['logical_sparse_size'] = sparse.stat().st_size
        metrics['eof_with_tail'] = container.stat().st_size
        metrics['allocated_with_tail'] = allocated(container)
        assert metrics['allocated_with_tail'] < 16 * 1024**2, 'sparse/compression allocation bound failed'
        tail.unlink()
        started = time.monotonic()
        wait_for(lambda: container.stat().st_size < metrics['eof_with_tail'] - 1024**2,
                 90, 'background compaction did not shorten EOF')
        metrics['shrink_seconds'] = time.monotonic() - started
        metrics['eof_after_delete'] = container.stat().st_size
        metrics['allocated_after_delete'] = allocated(container)
        assert (folder / 'compressed.bin').read_bytes() == data

        # A listing larger than one WinFsp query buffer spans continuation
        # pages; every name must appear exactly once.
        many = folder / 'many'
        many.mkdir()
        many_names = {f'entry-{i:05d}-listing.bin' for i in range(1000)}
        for name in many_names:
            (many / name).touch()
        listed = os.listdir(many)
        assert len(listed) == len(many_names) and set(listed) == many_names, (
            len(listed), len(set(listed)))
        shutil.rmtree(many)
        # CopyFile and explicit allocation changes must succeed: growing the
        # allocation is advisory, shrinking it below EOF truncates.
        copied = folder / 'copied.bin'
        if not K.CopyFileW(str(folder / 'compressed.bin'), str(copied), True):
            raise ctypes.WinError(ctypes.get_last_error())
        assert copied.read_bytes() == data
        set_allocation(copied, 64 * 1024**2)
        assert copied.stat().st_size == len(data)
        # WinFsp rounds the request up to the 4 KiB allocation unit first.
        set_allocation(copied, 100)
        assert copied.stat().st_size == 4096 and copied.read_bytes() == data[:4096]
        copied.unlink()
        stop(proc)
        proc = None
        sealed = container.read_bytes()
        assert password.encode() not in sealed
        assert b'far-away-content' not in sealed
        assert 'MixedCase'.encode('utf-16le') not in sealed
        assert b'upper-case' not in sealed
        assert data[:128] not in sealed
        proc = mount(False)
        assert (folder / 'Bar.txt').read_bytes() == b'upper-case'
        assert (folder / 'foo.txt').read_bytes() == b'lower-case'
        assert (folder / 'compressed.bin').read_bytes() == data
        assert (folder / 'multi-map.bin').read_bytes() == multi_map
        assert sparse.stat().st_size == metrics['logical_sparse_size']
        assert abs((folder / 'Bar.txt').stat().st_mtime - timestamp) < .001
        shutil.rmtree(folder)
        stop(proc)
        proc = None
        before = hashlib.sha256(container.read_bytes()).hexdigest()
        rejected = subprocess.run([str(args.exe.resolve()), '--container', str(container),
                                   '--check', '--password-stdin'],
                                  input=b'wrong-test-password\n', capture_output=True, timeout=30)
        assert rejected.returncode != 0
        assert hashlib.sha256(container.read_bytes()).hexdigest() == before
        metrics['wrong_password_no_write'] = True
        metrics['passed'] = True
        metrics['exe'] = str(args.exe.resolve())
        metrics['test_directory'] = str(run)
        (run / 'result.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
        print(json.dumps(metrics, indent=2))
    finally:
        if proc is not None and proc.poll() is None:
            K.SetEvent(event)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=10)
        K.CloseHandle(event)
        out.close()
        err.close()


if __name__ == '__main__':
    main()
