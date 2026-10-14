"""Temporary, per-test OpenSSH daemon running inside WSL Ubuntu."""

from __future__ import annotations

import contextlib
import getpass
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path


class WslSshdFixture:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir.resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=self.base_dir))
        self.remote_root = ""
        self.outside_sentinel = ""
        self.server_key = self.run_dir / "ssh_host_rsa_key"
        self.client_key = self.run_dir / "client_ed25519_key"
        self.bad_key = self.run_dir / "wrong_client_rsa_key"
        self.known_hosts = self.run_dir / "known_hosts"
        self.bad_known_hosts = self.run_dir / "bad_known_hosts"
        self.unknown_known_hosts = self.run_dir / "unknown_known_hosts"
        self.authorized_keys = self.run_dir / "authorized_keys"
        self.default_home = self.run_dir / "test-home"
        self.default_identity = self.default_home / ".ssh" / "id_ed25519"
        self.openssl_config = self.run_dir / "openssl-fixture.cnf"
        self.openssl_modules = self.run_dir / "openssl-modules"
        self.config = self.run_dir / "sshd_config"
        self.pid_file = self.run_dir / "sshd.pid"
        self.log_file = self.run_dir / "sshd.log"
        self.port = 0
        self.proc: subprocess.Popen | None = None
        self.log = None
        self.linux_dir = ""
        self.linux_sshd_root = ""
        self.linux_sshd_config = ""
        try:
            self._setup()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _run(args: list[str], *, timeout: int = 30, check: bool = True) -> str:
        result = subprocess.run(
            args,
            check=False,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if check and result.returncode != 0:
            raise RuntimeError(
                f"command failed ({result.returncode}): {args!r}\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        return result.stdout.strip()

    def _wsl(self, *args: str, timeout: int = 30, check: bool = True) -> str:
        return self._run(["wsl.exe", "-d", "Ubuntu", "--", *args], timeout=timeout, check=check)

    @staticmethod
    def _windows_to_wsl(path: Path) -> str:
        resolved = path.resolve()
        drive = resolved.drive.rstrip(":").lower()
        if len(drive) != 1:
            raise ValueError(f"fixture path must be on a mounted Windows drive: {resolved}")
        return f"/mnt/{drive}{resolved.as_posix()[2:]}"

    def _setup(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.linux_dir = self._windows_to_wsl(self.run_dir)
        linux_dir = self.linux_dir
        self.linux_sshd_config = f"{linux_dir}/sshd_config"
        token = secrets.token_hex(12)
        self.remote_root = f"/tmp/scpfs-test-{token}"
        self.linux_sshd_root = f"/tmp/scpfs-sshd-{token}"
        self.outside_sentinel = f"/tmp/scpfs-outside-{token}.txt"

        # These keys are throwaway test credentials under this fixture's private build directory.
        self._wsl("ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-f", f"{linux_dir}/ssh_host_rsa_key")
        self._wsl("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{linux_dir}/client_ed25519_key")
        self._wsl("ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-f", f"{linux_dir}/wrong_client_rsa_key")
        for private_key in (self.client_key, self.bad_key):
            self._run([
                "icacls.exe", str(private_key), "/inheritance:r", "/grant:r",
                f"{getpass.getuser()}:(R)",
            ])
        self.default_identity.parent.mkdir(parents=True)
        shutil.copyfile(self.client_key, self.default_identity)
        self._run(["icacls.exe", str(self.default_identity), "/inheritance:r", "/grant:r",
                   f"{getpass.getuser()}:(M)"])

        server_public = Path(f"{self.server_key}.pub").read_text(encoding="ascii").strip().split()
        client_public = Path(f"{self.client_key}.pub").read_text(encoding="ascii").strip()
        bad_public = Path(f"{self.bad_key}.pub").read_text(encoding="ascii").strip().split()
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]

        self.known_hosts.write_text(
            f"[127.0.0.1]:{self.port} {server_public[0]} {server_public[1]} scpfs-test-host-ip\n"
            f"[localhost]:{self.port} {server_public[0]} {server_public[1]} scpfs-test-hostname\n",
            encoding="ascii",
        )
        self.bad_known_hosts.write_text(
            f"[127.0.0.1]:{self.port} {bad_public[0]} {bad_public[1]} scpfs-test-wrong-host\n",
            encoding="ascii",
        )
        self.unknown_known_hosts.write_text("", encoding="ascii")
        self.authorized_keys.write_text(client_public + "\n", encoding="ascii")
        self.openssl_modules.mkdir()
        self.openssl_config.write_text(
            "\n".join([
                "config_diagnostics = 1",
                "openssl_conf = scpfs_fixture_init",
                "[scpfs_fixture_init]",
                "providers = scpfs_fixture_providers",
                "[scpfs_fixture_providers]",
                "scpfs_missing_provider = scpfs_fixture_missing_provider",
                "[scpfs_fixture_missing_provider]",
                "activate = 1",
                "module = scpfs-fixture-provider-that-does-not-exist",
                "",
            ]),
            encoding="ascii",
        )

        conf = "\n".join(
            [
                f"Port {self.port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {self.linux_sshd_root}/ssh_host_rsa_key",
                f"PidFile {self.linux_sshd_root}/sshd.pid",
                f"AuthorizedKeysFile {linux_dir}/authorized_keys",
                "AllowUsers root",
                "PermitRootLogin prohibit-password",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "StrictModes no",
                "PermitUserEnvironment no",
                "PrintMotd no",
                "LogLevel ERROR",
                "",
            ]
        )
        self.config.write_text(conf, encoding="ascii")
        self._wsl("chmod", "700", linux_dir)
        self._wsl("mkdir", "-m", "700", self.remote_root)
        self._wsl("python3", "-c",
                  "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('fixture-owned outside sentinel\\n')",
                  self.outside_sentinel)
        self._wsl("mkdir", "-m", "700", self.linux_sshd_root)
        self._wsl("cp", f"{linux_dir}/ssh_host_rsa_key", f"{self.linux_sshd_root}/ssh_host_rsa_key")
        self._wsl("chmod", "600", f"{self.linux_sshd_root}/ssh_host_rsa_key")
        # sshd needs its privilege separation directory. systemd-tmpfiles
        # normally creates it, but not when the distro's boot is stalled
        # (e.g. by an fstab entry for an absent disk).
        self._wsl("mkdir", "-p", "-m", "0755", "/run/sshd")
        self._wsl("sshd", "-t", "-f", f"{linux_dir}/sshd_config")

        self.log = self.log_file.open("wb")
        self.proc = subprocess.Popen(
            ["wsl.exe", "-d", "Ubuntu", "--", "/usr/sbin/sshd", "-D", "-e", "-f", f"{linux_dir}/sshd_config"],
            stdout=subprocess.DEVNULL,
            stderr=self.log,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.log.flush()
                detail = self.log_file.read_text(encoding="utf-8", errors="replace")
                raise RuntimeError(f"WSL sshd exited early; log:\n{detail}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise TimeoutError(f"WSL sshd did not listen on localhost:{self.port}")

    def cli(self, executable: Path, *, identity: Path | None = None,
            known_hosts: Path | None = None) -> list[str]:
        args = [
            str(executable),
            "--probe",
            "--host", "127.0.0.1",
            "--user", "root",
            "--port", str(self.port),
            "--remote-root", self.remote_root,
            "--known-hosts", str(known_hosts or self.known_hosts),
        ]
        if identity is not None:
            args.extend(["--identity", str(identity)])
        return args

    def default_identity_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(self.default_home)
        env["USERPROFILE"] = str(self.run_dir)
        return env

    def userprofile_identity_environment(self) -> dict[str, str]:
        profile_identity = self.run_dir / ".ssh" / "id_ed25519"
        profile_identity.parent.mkdir(exist_ok=True)
        shutil.copyfile(self.client_key, profile_identity)
        self._run(["icacls.exe", str(profile_identity), "/inheritance:r", "/grant:r",
                   f"{getpass.getuser()}:(M)"])
        env = os.environ.copy()
        env.pop("HOME", None)
        env["USERPROFILE"] = str(self.run_dir)
        return env

    def drop_established_ssh_sessions(self) -> int:
        """Kill only children of this fixture's sshd; leave its listener alive."""
        root_pid = self._wsl("cat", f"{self.linux_sshd_root}/sshd.pid")
        if not root_pid.isdigit():
            raise RuntimeError("fixture sshd pid file did not contain a PID")
        script = (
            "import os,signal,sys\n"
            "root=int(sys.argv[1]); cfg=sys.argv[2].encode();\n"
            "cmd=open(f'/proc/{root}/cmdline','rb').read();\n"
            "if b'/usr/sbin/sshd' not in cmd or cfg not in cmd: raise SystemExit('fixture sshd identity mismatch');\n"
            "parents={};\n"
            "for n in os.listdir('/proc'):\n"
            " if not n.isdigit(): continue\n"
            " try:\n"
            "  s=open('/proc/'+n+'/stat').read(); r=s.rfind(')'); fields=s[r+2:].split(); parents[int(n)]=int(fields[1])\n"
            " except (OSError,ValueError,IndexError): pass\n"
            "desc=set(); changed=True\n"
            "while changed:\n"
            " changed=False\n"
            " for p,pp in parents.items():\n"
            "  if p!=root and (pp==root or pp in desc) and p not in desc: desc.add(p); changed=True\n"
            "for p in sorted(desc, reverse=True):\n"
            " try: os.kill(p, signal.SIGTERM)\n"
            " except ProcessLookupError: pass\n"
            "print(len(desc))\n"
        )
        count = self._wsl("python3", "-c", script, root_pid,
            self.linux_sshd_config)
        if not count.isdigit():
            raise RuntimeError(f"fixture SSH session kill returned invalid count: {count!r}")
        return int(count)

    def hostile_openssl_environment(self) -> dict[str, str]:
        env = self.default_identity_environment()
        env["OPENSSL_CONF"] = str(self.openssl_config)
        env["OPENSSL_MODULES"] = str(self.openssl_modules)
        return env

    def close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            with contextlib.suppress(Exception):
                pid = self._wsl("cat", f"{self.linux_sshd_root}/sshd.pid", check=False)
                if pid.isdigit():
                    self._wsl("kill", "-TERM", pid, check=False)
                self.proc.wait(timeout=8)
            if self.proc.poll() is None:
                with contextlib.suppress(Exception):
                    self.proc.terminate()
                    self.proc.wait(timeout=3)
        if self.log is not None:
            self.log.close()
        if self.remote_root or self.linux_sshd_root or self.outside_sentinel:
            # Remove only the unique directory created below /tmp by this fixture.
            cleanup_code = (
                "import os,shutil,sys\n"
                "for p in sys.argv[1:]:\n"
                " if not ((p.startswith('/tmp/scpfs-test-') or "
                "p.startswith('/tmp/scpfs-sshd-')) and p.count('/') == 2) and not "
                "(p.startswith('/tmp/scpfs-outside-') and p.count('/') == 2):\n"
                "  raise ValueError('unsafe cleanup path: ' + p)\n"
                " if os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)\n"
                " else: os.unlink(p)\n"
            )
            with contextlib.suppress(Exception):
                self._wsl("python3", "-c", cleanup_code,
                          *[p for p in (self.remote_root, self.linux_sshd_root, self.outside_sentinel) if p])
        if self.run_dir.parent == self.base_dir and self.run_dir.name.startswith("run-"):
            with contextlib.suppress(OSError):
                shutil.rmtree(self.run_dir)
        with contextlib.suppress(OSError):
            shutil.rmtree(self.run_dir)

    def __enter__(self) -> "WslSshdFixture":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def run_cli(args: list[str], timeout: int = 45, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=False, timeout=timeout, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
