"""Bounded real-world temp workloads; creates only a unique child of argv[1]."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import zipfile

def main() -> None:
    base = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="memfs-workload-", dir=base) as temporary:
        root = Path(temporary)
        payload = bytes(range(256)) * 1024
        with zipfile.ZipFile(root / "fixture.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for i in range(16):
                archive.writestr(f"nested/file-{i}.bin", payload + bytes([i]))
        with zipfile.ZipFile(root / "fixture.zip") as archive:
            archive.extractall(root / "unpacked")
        for i in range(16):
            assert (root / "unpacked" / "nested" / f"file-{i}.bin").read_bytes() == payload + bytes([i])
        print("PASS Python tempfile and ZIP extraction: 16 files, hash-verified")
        database = root / "wal.sqlite"
        with sqlite3.connect(database) as writer, sqlite3.connect(database) as reader:
            assert writer.execute("pragma journal_mode=wal").fetchone()[0] == "wal"
            writer.execute("pragma mmap_size=8388608")
            writer.execute("create table records(id integer primary key, payload blob)")
            writer.commit()
            for batch in range(10):
                writer.executemany("insert into records values(?,?)",
                    ((batch * 100 + i, payload[:1024]) for i in range(100)))
                writer.commit()
                assert reader.execute("select count(*) from records").fetchone()[0] == (batch + 1) * 100
            assert writer.execute("pragma integrity_check").fetchone()[0] == "ok"
            writer.execute("pragma wal_checkpoint(truncate)")
        # sqlite connection context managers commit but don't close connections.
        writer.close()
        reader.close()
        print("PASS SQLite WAL: 1000 rows, two connections, integrity_check, checkpoint")
        env = dict(os.environ, TEMP=str(root), TMP=str(root))
        script = "import tempfile, pathlib; p=pathlib.Path(tempfile.gettempdir()); print(p); assert p==pathlib.Path(__import__('sys').argv[1])"
        result = subprocess.run([sys.executable, "-c", script, str(root)], env=env,
                                capture_output=True, text=True, timeout=15, check=True)
        assert str(root).casefold() in result.stdout.casefold()
        print("PASS child-process TEMP/TMP discovery")

if __name__ == "__main__":
    main()
