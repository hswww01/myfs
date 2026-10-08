"""Produce a portable diagnostic kit from an accepted, unchanged release.

Generated artifacts only: this script never modifies source/build/package files,
installs drivers, starts services, resumes VMs or accesses signing private keys.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'scripts/portable/Run-Validation.ps1'
RUNBOOK = ROOT / 'docs/PORTABLE_VALIDATION.zh-CN.md'
BUILD = ROOT / 'build/x64-release'
PACKAGE = ROOT / 'dist/memfs-x64'

def digest(path: Path) -> str:
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest().upper()

def git(*args: str) -> str:
    return subprocess.run(['git', *args], cwd=ROOT, text=True,
        capture_output=True, check=True,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)).stdout.strip()

def doc(path: Path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def generate(report_path: Path, extended_path: Path | None = None) -> Path:
    head = git('rev-parse', 'HEAD')
    if git('status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('Tracked source must be clean')
    report = doc(report_path)
    if report['status'] != 'passed' or not report['all_requested_checks_passed']:
        raise RuntimeError('Complete passing acceptance is required, not a running report')
    if report['git_commit'] != head:
        raise RuntimeError('Current-HEAD passing acceptance is required')
    extended_path = extended_path or report_path
    extended = doc(extended_path)
    if (extended['profile'] != 'extended-local' or extended['status'] != 'passed'
            or not extended['all_requested_checks_passed']):
        raise RuntimeError('An actual extended passing run is required, not a quick-smoke substitute')
    extended_head = extended['git_commit']
    allowed_handoff_changes = {
        'README.md', 'RELEASE.md',
        'scripts/package-validation-kit.py',
        'scripts/portable/Run-Validation.ps1',
        'tests/portable_validation_test.py',
    }
    if extended_head != head:
        git('merge-base', '--is-ancestor', extended_head, head)
        changed = git('diff', '--name-only', extended_head, head, '--').splitlines()
        unaccepted = [p for p in changed if p not in allowed_handoff_changes and not p.startswith('docs/')]
        if unaccepted:
            raise RuntimeError('Runtime/build inputs changed since extended run: '+', '.join(unaccepted))
    if extended['exe_sha256'].upper() != report['exe_sha256'].upper():
        raise RuntimeError('Extended run exercised a different binary')
    if set(extended['registered_tests']) != set(report['registered_tests']):
        raise RuntimeError('Test registration changed since extended run')
    required_steps={'ctest-debug','ctest-release','repeat-release','soak-auto-capacity',
                    'mount-plain','mount-compress','mount-encrypt','mount-combined',
                    'mount-auto','service-recovery','package-provenance','artifact-stability'}
    passed={x['name'] for x in report['steps'] if x['status']=='PASS'}
    if not required_steps.issubset(passed):
        raise RuntimeError(f'Missing acceptance steps: {required_steps-passed}')
    extended_passed={x['name'] for x in extended['steps'] if x['status']=='PASS'}
    if not required_steps.issubset(extended_passed):
        raise RuntimeError('Extended report did not pass the complete requested matrix')
    provenance = doc(PACKAGE/'BUILD_PROVENANCE.json')
    accepted_hash=report['exe_sha256'].upper()
    if provenance['evidence']['source']['memfs_git_commit'] != head:
        raise RuntimeError('Packaged provenance is from another revision')
    if any(digest(path) != accepted_hash for path in [BUILD/'memfs.exe',PACKAGE/'memfs.exe']):
        raise RuntimeError('Build/package differs from accepted executable')
    if provenance['evidence']['build']['exe_sha256'].upper() != accepted_hash:
        raise RuntimeError('Provenance executable hash mismatch')
    catalog=json.loads(subprocess.run(['ctest','--test-dir',str(BUILD),'--show-only=json-v1'],
        cwd=ROOT,text=True,capture_output=True,check=True,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)).stdout)
    if {x['name'] for x in catalog['tests']} != set(report['registered_tests']):
        raise RuntimeError('Portable test catalog differs from accepted tests')
    if len(catalog['tests']) != 20:
        raise RuntimeError('Review test mapping before changing portable test count')
    dist=ROOT/'dist'
    if dist.is_symlink() or os.path.isjunction(dist):
        raise RuntimeError('Refusing redirected dist root')
    out=dist/('memfs-validation-'+head[:7]+'-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(exist_ok=False)
    def copy(source: Path, relative: str) -> None:
        if not source.is_file(): raise FileNotFoundError(source)
        dest=out/relative
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,dest)
    for source in PACKAGE.rglob('*'):
        if source.is_file() and source.name!='SHA256SUMS.txt':
            copy(source,source.relative_to(PACKAGE).as_posix())
    for relative in git('ls-files', '--', 'src/*.c', 'src/*.h').splitlines():
        copy(ROOT/relative, relative)
    for relative in ['scripts/provenance-common.ps1','scripts/verify-winfsp-drivers.ps1',
                     'scripts/verify-deployment.ps1','scripts/memfs-service.ps1',
                     'tests/integration.ps1','tests/service-recovery.ps1',
                     'tests/fixtures/memfs_guard_good.c','tests/fixtures/memfs_guard_bad.c']:
        copy(ROOT/relative,relative)
    driver_map={}
    for architecture,name in [('driver_x64','winfsp-x64.sys'),('driver_arm64','winfsp-a64.sys')]:
        evidence=provenance['evidence']['winfsp'][architecture]
        source=Path(evidence['path'])
        if digest(source)!=evidence['sha256'].upper():
            raise RuntimeError('Driver source changed after acceptance')
        copy(source,'drivers/'+name)
        driver_map[str(source).replace('\\','/').lower()]='drivers/'+name
    build_prefix=str(BUILD).replace('\\','/').lower()+'/'
    root_prefix=str(ROOT).replace('\\','/').lower()+'/'
    def map_path(value: str, executable: bool=False) -> str:
        normalized=value.replace('\\','/')
        low=normalized.lower()
        if low.startswith(build_prefix):
            name=normalized[len(build_prefix):]
            if '/' in name or not name.endswith('.exe'):
                raise RuntimeError(f'Unsupported build-path test argument: {value}')
            relative='memfs.exe' if name=='memfs.exe' else 'bin/'+name
            if name!='memfs.exe': copy(BUILD/name,relative)
            return relative if executable else '@kit/'+relative
        if low.startswith(root_prefix):
            relative=normalized[len(root_prefix):]
            if not (out/relative).is_file():
                raise RuntimeError(f'Unpackaged source path required by test: {relative}')
            return '@kit/'+relative
        if low in driver_map:
            return '@kit/'+driver_map[low]
        if executable and Path(normalized).name.lower() in {'pwsh.exe','powershell.exe'}:
            return '@powershell'
        if ':/' in normalized:
            raise RuntimeError(f'Unmapped absolute path in portable case: {value}')
        return value
    cases=[]
    for test in catalog['tests']:
        cmd=test['command']; props={x['name']:x['value'] for x in test.get('properties',[])}
        expected=0
        if props.get('WILL_FAIL'):
            if test['name']=='memfs_no_crt_heap_guard_bad_fixture': expected=1
            elif test['name'].startswith('memfs_cli_reject_'): expected=2
            else: raise RuntimeError(f'Unknown expected-failure test: {test["name"]}')
        cases.append({'name':test['name'],'executable':map_path(cmd[0],True),
                      'arguments':[map_path(a) for a in cmd[1:]],
                      'expected_exit':expected,'timeout_seconds':max(60,int(props.get('TIMEOUT',60)))})
    write_json(out/'cases.json',cases)
    copy(RUNNER,'RUN-VALIDATION.ps1')
    copy(RUNBOOK,'RUNBOOK.zh-CN.md')
    copy(report_path,'HOST_ACCEPTANCE.json')
    copy(extended_path,'HOST_EXTENDED_ACCEPTANCE.json')
    info={'schema_version':1,'created_at':dt.datetime.now().astimezone().isoformat(timespec='seconds'),
          'source_commit':head,'exe_sha256':accepted_hash,'test_case_count':len(cases),
          'purpose':'Portable diagnostics corresponding to the accepted Release tests; not a newly certified OS or production-signed release.',
          'runner_source':'scripts/portable/Run-Validation.ps1 at source_commit, copied verbatim; not compiled into memfs.exe.',
          'current_acceptance_profile':report['profile'],'extended_acceptance_commit':extended_head,
          'extended_binary_identical':True,'compiled_inputs_unchanged_from_extended':True,
          'external_release_ready':False,'pending_gates':report['external_gates_not_evaluated'],
          'known_feature_limit':report['known_feature_limit']}
    write_json(out/'KIT_INFO.json',info)
    entries=[]
    for source in sorted(out.rglob('*')):
        if source.is_file(): entries.append(f'{digest(source).lower()}  {source.relative_to(out).as_posix()}')
    (out/'SHA256SUMS.txt').write_text('\n'.join(entries)+'\n',encoding='utf-8')
    if git('rev-parse','HEAD')!=head or digest(BUILD/'memfs.exe')!=accepted_hash:
        raise RuntimeError('Source or build changed while collecting validation kit')
    print(json.dumps({'kit':str(out),'files':len(entries),'source_commit':head,'exe_sha256':accepted_hash},indent=2))
    (ROOT/'.agent/portable-kit-path.txt').write_text(str(out),encoding='utf-8')
    return out

def archive(kit: Path) -> None:
    kit=kit.resolve()
    if kit.parent != (ROOT/'dist').resolve() or not kit.name.startswith('memfs-validation-'):
        raise RuntimeError('Refusing an unmanaged kit path')
    destination=kit.with_suffix('.zip')
    if destination.exists(): raise FileExistsError(destination)
    files=[]
    for line in (kit/'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
        expected,relative=line.split('  ',1)
        path=(kit/relative).resolve()
        if not path.is_relative_to(kit) or digest(path).lower()!=expected:
            raise RuntimeError(f'Invalid or changed kit payload: {relative}')
        files.append(path)
    files.append(kit/'SHA256SUMS.txt')
    with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for file in files: z.write(file,file.relative_to(kit).as_posix())
    with zipfile.ZipFile(destination) as z:
        bad=z.testzip()
        if bad: raise RuntimeError(f'ZIP CRC failed: {bad}')
        for file in files:
            if hashlib.sha256(z.read(file.relative_to(kit).as_posix())).hexdigest().upper()!=digest(file):
                raise RuntimeError(f'ZIP round-trip mismatch: {file.name}')
    h=digest(destination)
    destination.with_name(destination.name+'.sha256').write_text(h.lower()+'  '+destination.name+'\n',encoding='utf-8')
    print(json.dumps({'zip':str(destination),'zip_bytes':destination.stat().st_size,'zip_sha256':h,'file_count':len(files),'results_excluded':True},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--report',type=Path)
    group.add_argument('--zip-kit',type=Path)
    parser.add_argument('--extended-report', type=Path, help='Optional earlier full run; only documentation and this handoff tooling may differ from current HEAD, and EXE hashes must match')
    opts=parser.parse_args()
    if opts.report: generate(opts.report,opts.extended_report)
    else: archive(opts.zip_kit)
