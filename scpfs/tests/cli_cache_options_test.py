from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def run(exe: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(exe), *arguments], check=False, capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=15,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    args = parser.parse_args()

    default = run(args.exe, "--help")
    if (default.returncode != 0 or "default: 0" not in default.stdout or
            "0 means unlimited" not in default.stdout):
        raise AssertionError(
            f"CLI help does not describe the unlimited zero default:\n"
            f"stdout={default.stdout}\nstderr={default.stderr}"
        )

    # Help terminates before connection setup, while still requiring every
    # supplied numeric option to pass the production parser. Zero is enabled
    # and means unbounded; it is not a disable switch.
    for value in ("0", "256", "16384"):
        result = run(args.exe, "--cache-max-mib", value, "--help")
        if result.returncode != 0 or "--cache-max-mib" not in result.stdout:
            raise AssertionError(
                f"valid cache bound {value} was not accepted by CLI parsing:\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )

    invalid_cases = {
        "negative": ("--cache-max-mib", "-1"),
        "above maximum": ("--cache-max-mib", "16385"),
        "uint32 overflow": ("--cache-max-mib", "4294967296"),
        "duplicate": ("--cache-max-mib", "16", "--cache-max-mib", "16"),
        "missing value": ("--cache-max-mib",),
    }
    for label, options in invalid_cases.items():
        # A complete probe request makes any accidental acceptance continue
        # toward connection setup; parser failures must return usage status 2.
        result = run(
            args.exe,
            "--probe", "--host", "127.0.0.1", "--user", "root",
            "--remote-root", "/", "--known-hosts", "missing-known-hosts",
            *options,
        )
        if result.returncode != 2 or "Usage:" not in result.stderr:
            raise AssertionError(
                f"invalid {label} cache option was not rejected before connection "
                f"(exit {result.returncode}):\nstdout={result.stdout}\nstderr={result.stderr}"
            )

    print("PASS: cache limit defaults and boundaries parse; negative, overflow, duplicate, and missing values fail before connection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
