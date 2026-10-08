from __future__ import annotations

import argparse
import ctypes
import os
import secrets
import subprocess
import time
from pathlib import Path

from wsl_sshd_fixture import WslSshdFixture


SERVICE_NAME = "ScpfsTest"
DRIVE_NO_ROOT_DIR = 1


def run(args: list[str], timeout: int = 30,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False, env=env,
    )


def sc(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run(["sc.exe", *args], timeout=timeout)


def service_state() -> tuple[str | None, int | None, str]:
    result = sc("queryex", SERVICE_NAME)
    text = result.stdout + result.stderr
    if result.returncode != 0:
        return None, None, text
    state = None
    pid = None
    for line in text.splitlines():
        if "STATE" in line and ":" in line:
            fields = line.split()
            if len(fields) >= 4:
                state = fields[3]
        elif "PID" in line and ":" in line:
            fields = line.split()
            try:
                pid = int(fields[-1])
            except ValueError:
                pass
    return state, pid, text


def wait_state(wanted: str, timeout_seconds: int = 60) -> tuple[int | None, str]:
    deadline = time.monotonic() + timeout_seconds
    last = ""
    while time.monotonic() < deadline:
        state, pid, last = service_state()
        if state == wanted:
            return pid, last
        if state == "STOPPED" and wanted == "RUNNING":
            raise RuntimeError(f"service stopped while waiting for RUNNING:\n{last}")
        time.sleep(0.25)
    raise TimeoutError(f"service did not reach {wanted}:\n{last}")


def wait_new_service_process(old_pid: int | None,
		 timeout_seconds: int = 60) -> tuple[int | None, str]:
	deadline = time.monotonic() + timeout_seconds
	last = ""
	while time.monotonic() < deadline:
		state, pid, last = service_state()
		if state == "RUNNING" and pid is not None and pid != old_pid:
			return pid, last
		time.sleep(0.2)
	raise TimeoutError(f"SCM did not launch a fresh RUNNING service process: old PID={old_pid}\n{last}")


def choose_drive() -> str | None:
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
    for letter in "RSTUVWXYZQPON":
        if not (mask & (1 << (ord(letter) - ord("A")))) and \
                get_drive_type(f"{letter}:\\") == DRIVE_NO_ROOT_DIR:
            return f"{letter}:"
    return None


def is_admin() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--build-dir", required=True, type=Path)
    args = parser.parse_args()

    if not is_admin():
        print("SKIP: SCM integration requires an elevated administrator")
        return 77
    if service_state()[0] is not None:
        print(f"SKIP: {SERVICE_NAME} already exists; refusing to modify an existing service")
        return 77
    drive = choose_drive()
    if drive is None:
        print("SKIP: no unused drive letter is available")
        return 77

    args.build_dir = args.build_dir.resolve()
    args.build_dir.mkdir(parents=True, exist_ok=True)
    with WslSshdFixture(args.build_dir) as fixture:
        # The service runs as LocalSystem. Grant it read access only to this
        # disposable fixture key; never alter the user's real SSH credentials.
        for credential in (fixture.default_identity, fixture.known_hosts):
            grant = run([
                "icacls.exe", str(credential), "/grant:r", "*S-1-5-18:(R)"
            ])
            if grant.returncode != 0:
                raise RuntimeError(f"cannot grant SYSTEM read access to fixture credential {credential.name}: {grant.stderr}")
        service_log = args.build_dir / f"service-{secrets.token_hex(8)}.log"
        grant_log_dir = run([
            "icacls.exe", str(args.build_dir), "/grant:r", "*S-1-5-18:(OI)(CI)M"
        ])
        if grant_log_dir.returncode != 0:
            raise RuntimeError(f"cannot prepare fixture service log directory: {grant_log_dir.stderr}")

        install_args = [
            str(args.exe), "--install", "--service-name", SERVICE_NAME,
            "--mount", drive,
            "--host", "127.0.0.1", "--user", "root", "--port", str(fixture.port),
            "--remote-root", fixture.remote_root,
            "--known-hosts", str(fixture.known_hosts),
            "--timeout-ms", "15000", "--command-timeout-ms", "60000",
            "--cache-max-mib", "16",
            "--log-file", str(service_log),
        ]
        installer_environment = fixture.default_identity_environment()
        installed = run(install_args, timeout=120, env=installer_environment)
        if installed.returncode != 0:
            if service_state()[0] is not None:
                # A failed first start can leave the newly created registration
                # behind. The name was checked absent above, so remove only the
                # service this fixture just requested.
                run([str(args.exe), "--uninstall", "--service-name", SERVICE_NAME], timeout=90)
            raise RuntimeError(
                f"native SCM install/start failed\nstdout:\n{installed.stdout}\n"
                f"stderr:\n{installed.stderr}\nservice log:\n"
                f"{service_log.read_text(encoding='utf-8', errors='replace') if service_log.exists() else '(absent)'}"
            )

        try:
            original_pid, query = wait_state("RUNNING")
            # These markers are emitted through the CRT stdout and stderr
            # streams after the service attaches both descriptors to its
            # protected log. SCM RUNNING alone would not prove redirection.
            if not service_log.exists():
                raise AssertionError("service log was not created")
            service_log_bytes = service_log.read_bytes()
            for marker in (
                b"Service stdout diagnostics attached.",
                b"Service stderr diagnostics attached.",
            ):
                if marker not in service_log_bytes:
                    raise AssertionError(
                        f"service stdio marker missing from protected log: {marker!r}; "
                        f"log bytes: {service_log_bytes!r}"
                    )
            qc = sc("qc", SERVICE_NAME)
            failure = sc("qfailure", SERVICE_NAME)
            if qc.returncode != 0 or "AUTO_START" not in qc.stdout:
                raise AssertionError(f"service is not configured for automatic start:\n{qc.stdout}{qc.stderr}")
            resolved_identity = str(fixture.default_identity.resolve())
            if resolved_identity.lower() not in qc.stdout.lower():
                raise AssertionError(
                    f"SCM ImagePath did not persist the resolved default identity path "
                    f"{resolved_identity!r}:\n{qc.stdout}{qc.stderr}"
                )
            if "--cache-max-mib 16" not in qc.stdout.replace('"', ""):
                raise AssertionError(
                    "SCM ImagePath did not preserve the nondefault read-cache limit:\n"
                    f"{qc.stdout}{qc.stderr}"
                )
            delayed = run([
                "reg.exe", "query",
                rf"HKLM\SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}",
                "/v", "DelayedAutoStart",
            ])
            if delayed.returncode != 0 or "0x1" not in delayed.stdout.lower():
                raise AssertionError(
                    f"delayed automatic start is not configured:\n{delayed.stdout}{delayed.stderr}"
                )
            if failure.returncode != 0 or "RESTART" not in failure.stdout:
                raise AssertionError(f"SCM restart policy is missing:\n{failure.stdout}{failure.stderr}")

            # Reinstalling byte-for-byte matching service arguments is idempotent.
            repeated = run(install_args, timeout=120, env=installer_environment)
            if repeated.returncode != 0:
                raise AssertionError(
                    f"matching native --install was not idempotent:\n"
                    f"{repeated.stdout}\n{repeated.stderr}"
                )
            repeated_pid, repeated_state = wait_state("RUNNING")
            if original_pid is not None and repeated_pid != original_pid:
                raise AssertionError(
                    f"idempotent install replaced running service process: "
                    f"{original_pid} -> {repeated_pid}\n{repeated_state}"
                )

            # A valid but different configuration must fail without stopping
            # or rewriting the running service.
            mismatched_args = list(install_args)
            timeout_index = mismatched_args.index("--timeout-ms") + 1
            mismatched_args[timeout_index] = "14000"
            mismatched = run(mismatched_args, timeout=120, env=installer_environment)
            if mismatched.returncode == 0:
                raise AssertionError("mismatched --install unexpectedly succeeded")
            after_mismatch_pid, after_mismatch_state = wait_state("RUNNING")
            if original_pid is not None and after_mismatch_pid != original_pid:
                raise AssertionError(
                    f"mismatched install disturbed running service: "
                    f"{original_pid} -> {after_mismatch_pid}\n{after_mismatch_state}"
                )

            mount_root = drive + "\\"
            visible = False
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if ctypes.windll.kernel32.GetDriveTypeW(mount_root) != DRIVE_NO_ROOT_DIR:
                    visible = True
                    break
                time.sleep(0.1)
            if not visible:
                raise AssertionError(f"LocalSystem mount {mount_root} is not visible to the installer session")

            # A poisoned SSH session should fail the service and let bounded
            # SCM recovery create a fresh process; do not retry any mutation.
            health_name = "service-health-reconnect.txt"
            fixture._wsl(
                "python3", "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('health-read-only\\n')",
                f"{fixture.remote_root}/{health_name}",
            )
            _, before_failure_pid, _ = service_state()
            dropped = fixture.drop_established_ssh_sessions()
            if dropped <= 0:
                raise AssertionError("fixture did not find an established sshd child to terminate")
            try:
                Path(mount_root + health_name).read_bytes()
            except OSError:
                pass
            else:
                # One harmless read may consume a still-buffered response; issue
                # one additional read to force the poisoned session to surface.
                try:
                    Path(mount_root + health_name).read_bytes()
                except OSError:
                    pass
            new_pid, health_state = wait_new_service_process(before_failure_pid)
            if new_pid is None or new_pid == before_failure_pid:
                raise AssertionError(f"SCM recovery did not replace service PID:\n{health_state}")
            if Path(mount_root + health_name).read_text(encoding="utf-8") != "health-read-only\n":
                raise AssertionError("fresh service process could not read after SSH listener recovery")

            test_name = "service-identity-roundtrip.txt"
            local_path = mount_root + test_name
            Path(local_path).write_text("service-session-visible\n", encoding="utf-8")
            if Path(local_path).read_text(encoding="utf-8") != "service-session-visible\n":
                raise AssertionError("service mount readback differed")
            remote = fixture._wsl("cat", f"{fixture.remote_root}/{test_name}")
            if remote != "service-session-visible":
                raise AssertionError(f"remote service upload differed: {remote!r}")
            Path(local_path).unlink()
            fixture._wsl("test", "!", "-e", f"{fixture.remote_root}/{test_name}")

            stopped = sc("stop", SERVICE_NAME)
            if stopped.returncode not in (0, 1062):
                raise RuntimeError(f"sc stop failed:\n{stopped.stdout}{stopped.stderr}")
            wait_state("STOPPED")
            started = sc("start", SERVICE_NAME)
            if started.returncode != 0:
                raise RuntimeError(f"sc start failed:\n{started.stdout}{started.stderr}")
            wait_state("RUNNING")
            print(f"PASS: isolated SCM lifecycle, stdio log capture, SSH-failure recovery, global mount and uninstall on {drive}")
        finally:
            cleanup = run([str(args.exe), "--uninstall", "--service-name", SERVICE_NAME], timeout=90)
            if cleanup.returncode != 0:
                raise RuntimeError(
                    f"native SCM uninstall failed\nstdout:\n{cleanup.stdout}\nstderr:\n{cleanup.stderr}"
                )
            absent, _, details = service_state()
            if absent is not None:
                raise RuntimeError(f"service still exists after uninstall:\n{details}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
