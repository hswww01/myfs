from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from wsl_sshd_fixture import WslSshdFixture, run_cli


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()

    with WslSshdFixture(args.build_dir) as fixture:
        # Verify the dedicated sshd's classic SCP sink handshake independently from
        # libssh2. Closing stdin immediately is expected to make scp exit nonzero,
        # but its first protocol byte must still be the success ACK (NUL).
        sink = f"{fixture.remote_root}/.scpfs-handshake"
        windows_ssh = Path(r"C:\Windows\System32\OpenSSH\ssh.exe")
        if windows_ssh.is_file():
            handshake = subprocess.run(
                [
                    str(windows_ssh), "-F", "NUL", "-T", "-i", str(fixture.client_key),
                    "-p", str(fixture.port),
                    "-o", "IdentitiesOnly=yes",
                    "-o", "StrictHostKeyChecking=yes",
                    "-o", f"UserKnownHostsFile={fixture.known_hosts}",
                    "-o", "GlobalKnownHostsFile=NUL",
                    "root@127.0.0.1", f"scp -t -- {sink}",
                ],
                input=b"",
                capture_output=True,
                timeout=30,
                check=False,
            )
            if not handshake.stdout.startswith(b"\0"):
                raise RuntimeError(
                    "fixture OpenSSH SCP sink did not send its initial success ACK\n"
                    f"stdout (hex): {handshake.stdout[:128].hex()}\n"
                    f"stderr: {handshake.stderr[:512].decode('utf-8', errors='replace')}"
                )

        # The default identity must honor HOME, and an explicit identity must
        # take precedence over an unusable default key in that directory.
        result = run_cli(fixture.cli(args.exe), timeout=60,
                         env=fixture.default_identity_environment())
        if result.returncode != 0:
            raise RuntimeError(
                "real WSL OpenSSH SCP round trip failed\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}\n"
                f"sshd log: {fixture.log_file}"
            )

        userprofile_result = run_cli(
            fixture.cli(args.exe), timeout=60,
            env=fixture.userprofile_identity_environment(),
        )
        if userprofile_result.returncode != 0:
            raise AssertionError(
                "default USERPROFILE identity lookup failed\n"
                f"stdout: {userprofile_result.stdout}\nstderr: {userprofile_result.stderr}"
            )

        hostile_openssl = run_cli(
            fixture.cli(args.exe, identity=fixture.client_key), timeout=60,
            env=fixture.hostile_openssl_environment(),
        )
        if hostile_openssl.returncode != 0:
            raise AssertionError(
                "SSH probe was affected by fixture OPENSSL_CONF/OPENSSL_MODULES; "
                "config autoload should be disabled before libssh2 initialization\n"
                f"stdout: {hostile_openssl.stdout}\nstderr: {hostile_openssl.stderr}"
            )

        wrong_host = run_cli(
            fixture.cli(args.exe, identity=fixture.client_key,
                        known_hosts=fixture.bad_known_hosts), timeout=30
        )
        if wrong_host.returncode == 0:
            raise AssertionError("--probe accepted a mismatched known_hosts key")

        # libssh2 1.11.1 must receive a span whose delimiter is not inside the
        # key field. Exercise the exact production parser path with valid host
        # pins in the newline/comment layouts commonly emitted by ssh-keygen.
        known_fields = fixture.known_hosts.read_text(encoding="ascii").splitlines()[0].split()
        pinned_line = " ".join(known_fields[:3]).encode("ascii")
        valid_other_host_line = (
            "unrelated.example " + " ".join(known_fields[1:3])
        ).encode("ascii")
        known_hosts_layouts = {
            "knownhosts-no-comment-lf": pinned_line + b"\n",
            "knownhosts-no-comment-crlf": pinned_line + b"\r\n",
            "knownhosts-unrelated-host-line": (
                valid_other_host_line + b"\n" + pinned_line + b"\n"
            ),
            "knownhosts-eof-without-newline": pinned_line,
        }
        for name, contents in known_hosts_layouts.items():
            layout_path = fixture.run_dir / name
            layout_path.write_bytes(contents)
            layout_result = run_cli(
                fixture.cli(args.exe, known_hosts=layout_path), timeout=60,
                env=fixture.default_identity_environment(),
            )
            if layout_result.returncode != 0:
                raise AssertionError(
                    f"--probe rejected the actual trusted key in {name}:\n"
                    f"stdout: {layout_result.stdout}\nstderr: {layout_result.stderr}"
                )

        wrong_fields = fixture.bad_known_hosts.read_text(encoding="ascii").splitlines()[0].split()
        wrong_pin_path = fixture.run_dir / "knownhosts-wrong-pin-no-comment"
        wrong_pin_path.write_bytes(
            (" ".join(wrong_fields[:3]) + "\n").encode("ascii")
        )
        wrong_pin_result = run_cli(
            fixture.cli(args.exe, known_hosts=wrong_pin_path), timeout=30,
            env=fixture.default_identity_environment(),
        )
        if wrong_pin_result.returncode == 0:
            raise AssertionError("--probe accepted a wrong no-comment known_hosts pin")

        unknown_host = run_cli(
            fixture.cli(args.exe, identity=fixture.client_key,
                        known_hosts=fixture.unknown_known_hosts), timeout=30
        )
        if unknown_host.returncode == 0:
            raise AssertionError("--probe accepted a host absent from known_hosts")

        wrong_identity = run_cli(
            fixture.cli(args.exe, identity=fixture.bad_key), timeout=30
        )
        if wrong_identity.returncode == 0:
            raise AssertionError("--probe accepted an unauthorized private key")

        shutil.copyfile(fixture.bad_key, fixture.default_identity)
        explicit_identity = run_cli(
            fixture.cli(args.exe, identity=fixture.client_key), timeout=60,
            env=fixture.default_identity_environment(),
        )
        if explicit_identity.returncode != 0:
            raise AssertionError(
                "explicit --identity did not override default HOME key\n"
                f"stdout: {explicit_identity.stdout}\nstderr: {explicit_identity.stderr}"
            )

        fixture.default_identity.unlink()
        missing_identity = run_cli(
            fixture.cli(args.exe), timeout=15,
            env=fixture.default_identity_environment(),
        )
        if missing_identity.returncode == 0 or "private key file not found" not in missing_identity.stderr:
            raise AssertionError(
                "missing default identity was not rejected clearly\n"
                f"stdout: {missing_identity.stdout}\nstderr: {missing_identity.stderr}"
            )

        print("PASS: GNU OpenSSH SCP round trip, unknown/mismatched host-key rejection, and key auth rejection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
