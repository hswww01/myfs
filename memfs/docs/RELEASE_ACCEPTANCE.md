# Local release acceptance

The release acceptance script turns the final local checks into one reproducible,
fail-closed run. It does not treat a skipped check, a test certificate, or an
unavailable ARM64/clean-VM environment as evidence of production readiness.

## Extended local run

From a configured Windows x64 development checkout, using 64-bit PowerShell:

```powershell
.\tests\release_acceptance_test.ps1
.\scripts\verify-release-acceptance.ps1 `
    -RepeatCount 50 -SoakMinutes 10 `
    -IncludeMounted -IncludeServiceRecovery -Package
```

The mounted tests require an unused `R:` DOS device. The service recovery test
requires administrator privileges, a working official WinFsp driver and no
pre-existing `MemfsC` service. They refuse to take over an existing mount/service.
The service test intentionally terminates **only its newly created test service**;
the filesystem is volatile, so post-recovery storage must be empty. This script
never reboots the host, changes Windows test-signing policy, or signs an EXE.

The verification covers:

1. Debug and Release builds and their full registered CTest suites. An empty test
   suite is an error, and the production capacity snapshot test must be registered.
2. Repeated Release core, multithread stress, production capacity snapshot,
   shared-node lifetime/orphan transitions and WinFsp security snapshot tests.
   The last two are mandatory regressions for the intermittent mounted crash
   found during the first full acceptance run; retries alone are not a fix.
3. Seven capacity microbenchmark runs, recording each result and the median.
4. A short fixed-capacity soak followed by the requested **10–60 minute automatic
   capacity** soak. Both use the existing mixed compression/encryption workload;
   the long run explicitly enables `--auto-capacity`, exercising cache refresh and
   cumulative VM-commit debit instead of accidentally testing only fixed capacity.
5. Real mounted plain, compressed, encrypted, combined and automatic-capacity I/O
   when `-IncludeMounted` is supplied.
6. SCM crash/restart/remount/cleanup when `-IncludeServiceRecovery` is supplied.
7. Unchanged Git HEAD and Release EXE throughout acceptance, followed by strict
   packaging/provenance and every SHA-256 manifest entry when `-Package` is supplied.

A second acceptance runner cannot take the same `.agent/release-acceptance.lock`.
Do not edit/commit tracked sources or rebuild the accepted executable from another
session during this run. The runner deliberately fails rather than label a report
with a revision or executable different from the one it exercised.

## Fast script validation

```powershell
.\scripts\verify-release-acceptance.ps1 -Quick -RepeatCount 1
```

This retains the build/test/cache checks but uses 10-second smoke soaks. Its report
is labeled `quick-smoke`, never an extended endurance result. Mounted, service and
package checks omitted by their switches are recorded as `SKIP` with reasons.
The helper test independently checks native quoting, concurrent stdout/stderr,
nonzero exits, owned-child timeout cleanup, script parameter arrays/switches and
failure-report status. It does not launch the real filesystem or alter drivers.

## Evidence artifacts

Each invocation creates a **new** directory under `.agent/acceptance-*`. An explicit
`-ReportDir` must not already exist; the verifier never clears an existing report
directory. Artifacts include `acceptance.json`, Debug/Release JUnit XML and each
native command's stdout/stderr logs. The JSON is updated after each stage and
also on failures. Failed commands/timeouts are exceptions, not warnings.

`all_requested_checks_passed=true` means the checks requested for this invocation
passed. It does **not** mean all supported operating systems have been validated.
`externally_release_ready` remains false: the runner does not establish clean
Win10/Win11 install behavior, Windows 11 ARM64 emulation behavior, real reboot
recovery, production signing identity, or a WinFsp redistribution-license decision.

`-RequireSignedExe` adds an EXE signature gate. Unsigned executables and self-issued
test certificates fail it. This is verification only: the script never selects a
certificate, reads/export a private key, or performs signing.

The soak's reported private-memory and committed-memory slopes are observations
for this bounded workload/run. A zero slope or a passing final allocator baseline
is not a proof that every workload is leak-free. System available-memory sampling
is advisory; it cannot reserve memory against unrelated processes allocating at
the same time.

## Separate platform and release decisions

The product remains one x64 `memfs.exe` with both official signed x64/ARM64 SYS
resources. No native ARM64 EXE or 32-bit product is added by this verifier. Clean
Windows guests, ARM64 hardware/VMs and an actual reboot need their own evidence.
Keep those task records blocked until the corresponding tests have really run.
The official signed WinFsp 2.1 `FSCTL_QUERY_ALLOCATED_RANGES` limitation is separate
from internal sparse storage correctness and remains a documented feature gap.
