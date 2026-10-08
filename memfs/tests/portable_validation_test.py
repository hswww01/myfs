from pathlib import Path
import datetime,hashlib,json,os,shutil,subprocess,uuid
root=Path(__file__).resolve().parents[1]
fixture=root/'.agent/tmp'/('portable-kit-selftest-'+uuid.uuid4().hex[:10])
fixture.mkdir()
runner=root/'scripts/portable/Run-Validation.ps1'
shutil.copy2(runner,fixture/runner.name)
exe=fixture/'memfs.exe'
original=b'Memfs synthetic hash fixture. This file is never executed.\r\n'
exe.write_bytes(original)
h=hashlib.sha256(original).hexdigest().upper()
(fixture/'KIT_INFO.json').write_text(json.dumps({'source_commit':'0'*40,'exe_sha256':h}),encoding='utf-8')
(fixture/'BUILD_PROVENANCE.json').write_text(json.dumps({'evidence':{'source':{'memfs_git_commit':'0'*40},'build':{'exe_sha256':h}}}),encoding='utf-8')
(fixture/'cases.json').write_text('[]',encoding='utf-8')
lines=[]
for p in sorted(fixture.iterdir()):
 if p.is_file(): lines.append(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name)
manifest='\n'.join(lines)+'\n'
(fixture/'SHA256SUMS.txt').write_text(manifest,encoding='utf-8')
ps5=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
ps7=Path(shutil.which('pwsh') or ps5)
results=[]
def run(name,success,host=ps7,extra=(),scenario="Integrity"):
 p=subprocess.run([str(host),'-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(fixture/runner.name),'-Scenario',scenario,*extra],capture_output=True,encoding='utf-8',errors='replace',timeout=30,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 (fixture/(name+'.outside.log')).write_text(p.stdout+'\n'+p.stderr,encoding='utf-8')
 # Logs are outside the payload trust set; move immediately into results.
 dest=fixture/'results'/(name+'.selftest.log')
 dest.parent.mkdir(exist_ok=True)
 (fixture/(name+'.outside.log')).replace(dest)
 if (p.returncode==0)!=success: raise RuntimeError(name+' unexpected exit '+str(p.returncode)+'\n'+p.stdout+'\n'+p.stderr)
 results.append({'name':name,'expected_success':success,'exit_code':p.returncode,'host':host.name,'pass':True})
 print('PASS',name,'exit',p.returncode)
run('intact-ps7',True)
run('intact-windows-powershell51',True,ps5)
exe.write_bytes(original+b'TAMPER')
run('tampered-exe-rejected',False)
exe.write_bytes(original)
(fixture/'unexpected.ps1').write_text('throw "must never execute"',encoding='utf-8')
run('unlisted-payload-rejected',False)
(fixture/'unexpected.ps1').unlink()
(fixture/'SHA256SUMS.txt').write_text(manifest+lines[0]+'\n',encoding='utf-8')
run('duplicate-manifest-rejected',False)
(fixture/'SHA256SUMS.txt').write_text(manifest+'0'*64+'  ../escape.bin\n',encoding='utf-8')
run('path-traversal-rejected',False)
(fixture/'SHA256SUMS.txt').write_text(manifest,encoding='utf-8')
import ctypes
k32=ctypes.WinDLL('kernel32',use_last_error=True)
k32.GetCurrentProcess.restype=ctypes.c_void_p
k32.IsWow64Process2.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ushort),ctypes.POINTER(ctypes.c_ushort)]
pm=ctypes.c_ushort();nm=ctypes.c_ushort()
if not k32.IsWow64Process2(k32.GetCurrentProcess(),ctypes.byref(pm),ctypes.byref(nm)):
 raise ctypes.WinError(ctypes.get_last_error())
opposite='AMD64' if nm.value==0xAA64 else 'ARM64'
run('wrong-native-architecture-rejected',False,extra=['-ExpectedNativeMachine',opposite])
(fixture/'KIT_INFO.json').write_text(json.dumps({'source_commit':'1'*40,'exe_sha256':h}),encoding='utf-8')
# Refresh just the kit-info hash to exercise provenance mismatch, not only the hash gate.
lines2=[hashlib.sha256((fixture/line.split('  ',1)[1]).read_bytes()).hexdigest()+'  '+line.split('  ',1)[1] for line in lines]
(fixture/'SHA256SUMS.txt').write_text('\n'.join(lines2)+'\n',encoding='utf-8')
run('provenance-revision-mismatch-rejected',False)
# Real Runtime dispatch in both PowerShell versions: 20 harmless child cases.
# In Windows PowerShell 5.1 ConvertFrom-Json emits an array as one pipeline
# item, so @(... | ConvertFrom-Json) incorrectly becomes a one-case catalog.
(fixture/'KIT_INFO.json').write_text(json.dumps({'source_commit':'0'*40,'exe_sha256':h}),encoding='utf-8')
cases=[{'name':'synthetic-case-'+str(i),'executable':'@powershell',
        'arguments':['-NoLogo','-NoProfile','-NonInteractive','-Command','exit 0'],
        'expected_exit':0,'timeout_seconds':15} for i in range(20)]
(fixture/'cases.json').write_text(json.dumps(cases),encoding='utf-8')
lines3=[hashlib.sha256((fixture/line.split('  ',1)[1]).read_bytes()).hexdigest()+'  '+line.split('  ',1)[1] for line in lines]
(fixture/'SHA256SUMS.txt').write_text('\n'.join(lines3)+'\n',encoding='utf-8')
run('runtime-catalog-powershell51',True,ps5,scenario='Runtime')
run('runtime-catalog-powershell7',True,ps7,scenario='Runtime')
out=root/'.agent/portable-runner-selftest.json'
out.write_text(json.dumps({'time':datetime.datetime.now().astimezone().isoformat(),'fixture':str(fixture),'results':results,'passed':True},indent=2),encoding='utf-8')
print(out)
