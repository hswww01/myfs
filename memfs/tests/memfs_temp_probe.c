/* Native Win32 contract tests. The PowerShell harness owns the fresh volume.
 * Never point the harness at an existing production volume. */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <urlmon.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>

static int failures, checks;
static WCHAR root[2048];
#define CHECK(x)                                                                                                       \
	do {                                                                                                               \
		++checks;                                                                                                      \
		if (!(x)) {                                                                                                    \
			++failures;                                                                                                \
			printf("FAIL line %d: %s (win32=%lu)\n", __LINE__, #x, GetLastError());                                    \
		}                                                                                                              \
	} while (0)
#define STEP(name, code)                                                                                               \
	do {                                                                                                               \
		int before = failures;                                                                                         \
		code;                                                                                                          \
		printf("%s %s\n", failures == before ? "PASS" : "FAIL", name);                                                 \
	} while (0)

static void path(WCHAR* out, size_t size, const WCHAR* name) {
	if (swprintf_s(out, size, L"%ls\\%ls", root, name) < 0)
		ExitProcess(2);
}
static HANDLE open_file(const WCHAR* p, DWORD access, DWORD share, DWORD disposition, DWORD flags) {
	return CreateFileW(p, access, share, NULL, disposition, flags, NULL);
}
static BOOL touch(const WCHAR* p) {
	HANDLE h = open_file(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, CREATE_NEW,
						 FILE_ATTRIBUTE_NORMAL);
	if (h == INVALID_HANDLE_VALUE)
		return FALSE;
	return CloseHandle(h);
}
static PSECURITY_DESCRIPTOR get_sd(const WCHAR* p, SECURITY_INFORMATION info) {
    /* Size/query is inherently racy with SetSecurity on NTFS too. */
    for (unsigned attempt=0;attempt<16;++attempt) {
        DWORD size=0;
        if(GetFileSecurityW(p,info,NULL,0,&size) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER)
            return NULL;
        DWORD capacity=size<4096?4096:size;
        PSECURITY_DESCRIPTOR sd=LocalAlloc(LMEM_FIXED,capacity);
        if(!sd)return NULL;
        if(GetFileSecurityW(p,info,sd,capacity,&size))return sd;
        DWORD error=GetLastError();LocalFree(sd);
        if(error!=ERROR_INSUFFICIENT_BUFFER){SetLastError(error);return NULL;}
    }
    SetLastError(ERROR_RETRY);return NULL;
}
static BOOL set_sddl(const WCHAR* p, SECURITY_INFORMATION info, const WCHAR* sddl) {
	PSECURITY_DESCRIPTOR sd = NULL;
	BOOL ok;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
		return FALSE;
	ok = SetFileSecurityW(p, info, sd);
	LocalFree(sd);
	return ok;
}
static BOOL has_ace(PSECURITY_DESCRIPTOR sd, WELL_KNOWN_SID_TYPE type, DWORD mask, BYTE flags) {
	BYTE sid[SECURITY_MAX_SID_SIZE];
	DWORD size = sizeof(sid);
	PACL acl;
	BOOL present, def;
	if (sd == NULL || !CreateWellKnownSid(type, NULL, sid, &size) ||
		!GetSecurityDescriptorDacl(sd, &present, &acl, &def) || !present || acl == NULL)
		return FALSE;
	for (DWORD i = 0; i < acl->AceCount; ++i) {
		ACCESS_ALLOWED_ACE* ace;
		if (!GetAce(acl, i, (void**)&ace))
			return FALSE;
		if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && (ace->Header.AceFlags & flags) == flags &&
			EqualSid(&ace->SidStart, sid) && (ace->Mask & mask) == mask)
			return TRUE;
	}
	return FALSE;
}
static void test_volume_and_bootstrap(const WCHAR* base) {
	WCHAR volume[8], name[64];
	DWORD flags = 0, max_component = 0;
	PSECURITY_DESCRIPTOR sd;
	swprintf_s(volume, _countof(volume), L"%lc:\\", base[0]);
	CHECK(GetVolumeInformationW(volume, NULL, 0, NULL, &max_component, &flags, name, _countof(name)));
	printf("volume: %ls, flags=0x%08lx\n", name, flags);
	CHECK((flags & FILE_PERSISTENT_ACLS) != 0);
	CHECK(wcscmp(name, L"NTFS") == 0);
	CHECK(max_component == 255);
	sd = get_sd(base, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);
	CHECK(sd != NULL);
	CHECK(has_ace(sd, WinLocalSystemSid, FILE_ALL_ACCESS, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE));
	CHECK(has_ace(sd, WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE));
	CHECK(has_ace(sd, WinCreatorOwnerSid, FILE_ALL_ACCESS,
				  OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE));
	CHECK(!has_ace(sd, WinWorldSid, FILE_WRITE_DATA, 0));
	CHECK(!has_ace(sd, WinAuthenticatedUserSid, WRITE_DAC | DELETE, 0));
	if (sd)
		LocalFree(sd);
}
static void test_inherit_and_deny(void) {
	WCHAR p[2048], child[2048];
	HANDLE h;
	PSECURITY_DESCRIPTOR sd;
	SECURITY_DESCRIPTOR_CONTROL control;
	DWORD revision;
	path(p, _countof(p), L"acl");
	CHECK(CreateDirectoryW(p, NULL));
	CHECK(set_sddl(p, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				   L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)"));
	swprintf_s(child, _countof(child), L"%ls\\inherited.tmp", p);
	CHECK(touch(child));
	sd = get_sd(child, DACL_SECURITY_INFORMATION);
	CHECK(has_ace(sd, WinWorldSid, FILE_ALL_ACCESS, INHERITED_ACE));
	if (sd)
		LocalFree(sd);
	CHECK(set_sddl(child, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				   L"D:P(D;;0x2;;;WD)(A;;FA;;;WD)"));
	sd = get_sd(child, DACL_SECURITY_INFORMATION);
	CHECK(sd && GetSecurityDescriptorControl(sd, &control, &revision) && (control & SE_DACL_PROTECTED));
	if (sd)
		LocalFree(sd);
	h = open_file(child, FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
	CHECK(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	h = open_file(child, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
	CHECK(h != INVALID_HANDLE_VALUE);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	CHECK(set_sddl(child, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, L"D:P"));
	h = open_file(child, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
	CHECK(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
	if (h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
	CHECK(set_sddl(child, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;FA;;;WD)"));
	h = open_file(child, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
	CHECK(h != INVALID_HANDLE_VALUE);
	if (h != INVALID_HANDLE_VALUE) {
		sd = get_sd(child, DACL_SECURITY_INFORMATION);
		if (sd) {
			PACL acl;
			BOOL present, def;
			CHECK(GetSecurityDescriptorDacl(sd, &present, &acl, &def));
			CHECK(SetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL) ==
				  ERROR_ACCESS_DENIED);
			LocalFree(sd);
		}
		CloseHandle(h);
	}
	CHECK(DeleteFileW(child));
	CHECK(RemoveDirectoryW(p));
}
static void test_explicit_create_security(void) {
	WCHAR dir[2048], file[2048];
	PSECURITY_DESCRIPTOR creator = NULL, actual = NULL;
	SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, FALSE};
	SECURITY_DESCRIPTOR_CONTROL control;
	DWORD revision;
	HANDLE h;
	path(dir, _countof(dir), L"explicit");
	CHECK(CreateDirectoryW(dir, NULL));
	CHECK(set_sddl(dir, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
				   L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)"));
	for (unsigned protect = 0; protect < 2; ++protect) {
		swprintf_s(file, _countof(file), L"%ls\\create-%u.tmp", dir, protect);
		CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(
			protect ? L"D:P(A;;FR;;;WD)" : L"D:(D;;0x2;;;WD)(A;;FR;;;WD)", SDDL_REVISION_1, &creator, NULL));
		if (!creator)
			continue;
		sa.lpSecurityDescriptor = creator;
		h = CreateFileW(file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_NEW,
						FILE_ATTRIBUTE_NORMAL, NULL);
		CHECK(h != INVALID_HANDLE_VALUE);
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
		LocalFree(creator);
		creator = NULL;
		actual = get_sd(file, DACL_SECURITY_INFORMATION);
		CHECK(actual != NULL);
		if (actual) {
			CHECK(GetSecurityDescriptorControl(actual, &control, &revision));
			CHECK(!!(control & SE_DACL_PROTECTED) == !!protect);
			CHECK(has_ace(actual, WinLocalSystemSid, FILE_ALL_ACCESS, INHERITED_ACE) == !protect);
			LocalFree(actual);
			actual = NULL;
		}
		h = open_file(file, FILE_WRITE_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
		CHECK(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
		CHECK(set_sddl(file, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;FA;;;WD)"));
		CHECK(DeleteFileW(file));
	}
	CHECK(RemoveDirectoryW(dir));
}
static void test_owner_group_label(void) {
	WCHAR p[2048];
	PSECURITY_DESCRIPTOR sd;
	PSID owner, group;
	BOOL def;
	path(p, _countof(p), L"owner.tmp");
	CHECK(touch(p));
	sd = get_sd(p, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION);
	CHECK(sd != NULL);
	if (sd) {
		CHECK(GetSecurityDescriptorOwner(sd, &owner, &def) && owner && IsValidSid(owner));
		CHECK(GetSecurityDescriptorGroup(sd, &group, &def) && group && IsValidSid(group));
		CHECK(SetNamedSecurityInfoW(p, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION, owner,
									group, NULL, NULL) == ERROR_SUCCESS);
		HANDLE limited_handle = open_file(p, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
		CHECK(limited_handle != INVALID_HANDLE_VALUE);
		if (limited_handle != INVALID_HANDLE_VALUE) {
			CHECK(SetSecurityInfo(limited_handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, owner, NULL, NULL,
								  NULL) == ERROR_ACCESS_DENIED);
			CloseHandle(limited_handle);
		}
		LocalFree(sd);
	}
	CHECK(set_sddl(p, LABEL_SECURITY_INFORMATION, L"S:(ML;;NW;;;LW)"));
	sd = get_sd(p, LABEL_SECURITY_INFORMATION);
	CHECK(sd != NULL);
	if (sd) {
		PACL acl = NULL;
		BOOL present = FALSE;
		CHECK(GetSecurityDescriptorSacl(sd, &present, &acl, &def) && present && acl && acl->AceCount == 1);
		LocalFree(sd);
	}
	CHECK(DeleteFileW(p));
}
static void test_temp_and_delete(void) {
	WCHAR p[2048];
	HANDLE first, second;
	DWORD done;
	char data[8] = {0};
	CHECK(GetTempFileNameW(root, L"mfs", 0, p) != 0);
	first = open_file(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING,
					  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE);
	CHECK(first != INVALID_HANDLE_VALUE);
	if (first != INVALID_HANDLE_VALUE) {
		CHECK(WriteFile(first, "temp", 4, &done, NULL) && done == 4);
		second = open_file(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, 0);
		CHECK(second != INVALID_HANDLE_VALUE);
		if (second != INVALID_HANDLE_VALUE) {
			CHECK(CloseHandle(first));
			first = INVALID_HANDLE_VALUE;
			CHECK(ReadFile(second, data, 4, &done, NULL) && done == 4 && !memcmp(data, "temp", 4));
			CHECK(CloseHandle(second));
		}
		if (first != INVALID_HANDLE_VALUE)
			CloseHandle(first);
		CHECK(GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES);
	}
	path(p, _countof(p), L"collision.tmp");
	CHECK(touch(p));
	first = open_file(p, GENERIC_WRITE, 0, CREATE_NEW, 0);
	CHECK(first == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS);
	if (first != INVALID_HANDLE_VALUE)
		CloseHandle(first);
	CHECK(DeleteFileW(p));
}
static void test_mapping_and_locks(void) {
	WCHAR p[2048];
	HANDLE h, map, other;
	BYTE* view;
	OVERLAPPED a = {0}, b = {0};
	LARGE_INTEGER size;
	DWORD done;
	BYTE readback[16];
	path(p, _countof(p), L"mapped.tmp");
	h = open_file(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, CREATE_NEW,
				  FILE_ATTRIBUTE_TEMPORARY);
	CHECK(h != INVALID_HANDLE_VALUE);
	if (h == INVALID_HANDLE_VALUE)
		return;
	size.QuadPart = 131072;
	CHECK(SetFilePointerEx(h, size, NULL, FILE_BEGIN) && SetEndOfFile(h));
	map = CreateFileMappingW(h, NULL, PAGE_READWRITE, 0, 0, NULL);
	CHECK(map != NULL);
	if (map) {
		view = MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0);
		CHECK(view != NULL);
		if (view) {
			memset(view + 65530, 0x6b, sizeof(readback));
			CHECK(FlushViewOfFile(view, 0));
			CHECK(UnmapViewOfFile(view));
		}
		CloseHandle(map);
	}
	CHECK(FlushFileBuffers(h));
	size.QuadPart = 65530;
	CHECK(SetFilePointerEx(h, size, NULL, FILE_BEGIN));
	CHECK(ReadFile(h, readback, sizeof(readback), &done, NULL) && done == sizeof(readback));
	for (size_t i = 0; i < sizeof(readback); ++i)
		CHECK(readback[i] == 0x6b);
	other = open_file(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
	CHECK(other != INVALID_HANDLE_VALUE);
	CHECK(LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 16, 0, &a));
	if (other != INVALID_HANDLE_VALUE) {
		CHECK(!LockFileEx(other, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 16, 0, &b) &&
			  GetLastError() == ERROR_LOCK_VIOLATION);
		CHECK(UnlockFileEx(h, 0, 16, 0, &a));
		CloseHandle(other);
	}
	CloseHandle(h);
	CHECK(DeleteFileW(p));
}
static void test_replace_and_sharing(void) {
	WCHAR a[2048], b[2048], c[2048];
	HANDLE h, conflict;
	path(a, _countof(a), L"original.tmp");
	path(b, _countof(b), L"replacement.tmp");
	path(c, _countof(c), L"backup.tmp");
	CHECK(touch(a));
	CHECK(touch(b));
	CHECK(ReplaceFileW(a, b, c, 0, NULL, NULL));
	CHECK(GetFileAttributesW(b) == INVALID_FILE_ATTRIBUTES);
	CHECK(GetFileAttributesW(c) != INVALID_FILE_ATTRIBUTES);
	CHECK(MoveFileExW(a, b, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
	h = open_file(b, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING, 0);
	CHECK(h != INVALID_HANDLE_VALUE);
	if (h != INVALID_HANDLE_VALUE) {
		conflict = open_file(b, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0);
		CHECK(conflict == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION);
		if (conflict != INVALID_HANDLE_VALUE)
			CloseHandle(conflict);
		CHECK(!DeleteFileW(b) && GetLastError() == ERROR_SHARING_VIOLATION);
		CloseHandle(h);
	}
	CHECK(DeleteFileW(b));
	CHECK(DeleteFileW(c));
}
static void test_images(const WCHAR* dll_source) {
	WCHAR self[2048], exe[2048], dll[2048], cmd[4096];
	STARTUPINFOW si = {.cb = sizeof(si)};
	PROCESS_INFORMATION pi = {0};
	DWORD code = 0;
	HMODULE module;
	CHECK(GetModuleFileNameW(NULL, self, _countof(self)) != 0);
	path(exe, _countof(exe), L"ram-child.exe");
	CHECK(CopyFileW(self, exe, TRUE));
	swprintf_s(cmd, _countof(cmd), L"\"%ls\" --child", exe);
	CHECK(CreateProcessW(exe, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, root, &si, &pi));
	if (pi.hProcess) {
		DWORD wait = WaitForSingleObject(pi.hProcess, 15000);
		CHECK(wait == WAIT_OBJECT_0);
		if (wait != WAIT_OBJECT_0) {
			TerminateProcess(pi.hProcess, 2);
			WaitForSingleObject(pi.hProcess, 5000);
		}
		CHECK(GetExitCodeProcess(pi.hProcess, &code) && code == 37);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	CHECK(DeleteFileW(exe));
	path(dll, _countof(dll), L"ram-fixture.dll");
	CHECK(CopyFileW(dll_source, dll, TRUE));
	module = LoadLibraryExW(dll, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
	CHECK(module != NULL);
	if (module) {
		int (*value)(void) = (int (*)(void))GetProcAddress(module, "memfs_probe_value");
		CHECK(value && value() == 73);
		CHECK(FreeLibrary(module));
	}
	CHECK(DeleteFileW(dll));
}
static void test_restricted_user(const WCHAR* base) {
	HANDLE token = NULL, limited = NULL, isolated = NULL, h;
	BYTE admin[SECURITY_MAX_SID_SIZE], authenticated[SECURITY_MAX_SID_SIZE];
	union {
		void* align;
		BYTE bytes[512];
	} user_buffer;
	DWORD admin_size = sizeof(admin), au_size = sizeof(authenticated), bytes;
	SID_AND_ATTRIBUTES deny_admin, restrict_au;
	TOKEN_OWNER owner;
	WCHAR dir[2048], p[2048];
	BOOL impersonating = FALSE;
	PSECURITY_DESCRIPTOR sd = NULL;
	swprintf_s(dir, _countof(dir), L"%ls\\limited-%lu-%llu", base, GetCurrentProcessId(), GetTickCount64());
	swprintf_s(p, _countof(p), L"%ls\\private.tmp", dir);
	CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token));
	if (!token)
		return;
	CHECK(GetTokenInformation(token, TokenUser, user_buffer.bytes, sizeof(user_buffer.bytes), &bytes));
	CHECK(CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin, &admin_size));
	CHECK(CreateWellKnownSid(WinAuthenticatedUserSid, NULL, authenticated, &au_size));
	deny_admin = (SID_AND_ATTRIBUTES){admin, 0};
	restrict_au = (SID_AND_ATTRIBUTES){authenticated, 0};
	CHECK(CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 1, &deny_admin, 0, NULL, 0, NULL, &limited));
	if (!limited)
		goto end;
	owner.Owner = ((TOKEN_USER*)user_buffer.bytes)->User.Sid;
	CHECK(SetTokenInformation(limited, TokenOwner, &owner, sizeof(owner)));
	CHECK(ImpersonateLoggedOnUser(limited));
	impersonating = TRUE;
	CHECK(CreateDirectoryW(dir, NULL));
	CHECK(touch(p));
	sd = get_sd(p, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION);
	CHECK(sd != NULL);
	if (sd) {
		PSID actual;
		BOOL def;
		CHECK(GetSecurityDescriptorOwner(sd, &actual, &def) && EqualSid(actual, owner.Owner));
		CHECK(has_ace(sd, WinLocalSystemSid, FILE_ALL_ACCESS, INHERITED_ACE));
		CHECK(!has_ace(sd, WinWorldSid, FILE_READ_DATA, 0));
		CHECK(!has_ace(sd, WinAuthenticatedUserSid, FILE_READ_DATA, 0));
		LocalFree(sd);
		sd = NULL;
	}
	CHECK(RevertToSelf());
	impersonating = FALSE;
	/* A second, more restricted token can access only AU grants. It must
	 * not be able to read/change/delete the creator's private file. */
	CHECK(CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 1, &deny_admin, 0, NULL, 1, &restrict_au, &isolated));
	if (isolated) {
		CHECK(ImpersonateLoggedOnUser(isolated));
		impersonating = TRUE;
		h = open_file(p, FILE_READ_DATA | FILE_WRITE_DATA | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING,
					  0);
		CHECK(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
		if (h != INVALID_HANDLE_VALUE)
			CloseHandle(h);
		CHECK(RevertToSelf());
		impersonating = FALSE;
	}
	CHECK(ImpersonateLoggedOnUser(limited));
	impersonating = TRUE;
	CHECK(DeleteFileW(p));
	CHECK(RemoveDirectoryW(dir));
end:
	if (impersonating)
		CHECK(RevertToSelf());
	if (isolated)
		CloseHandle(isolated);
	if (limited)
		CloseHandle(limited);
	CloseHandle(token);
}
static void test_volume_path_resolution(const WCHAR* base) {
    WCHAR volume[8], guid[128], final[4096];
    swprintf_s(volume, _countof(volume), L"%lc:\\", base[0]);
    CHECK(GetVolumeNameForVolumeMountPointW(volume, guid, _countof(guid)));
    HANDLE h = open_file(base, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD n=GetFinalPathNameByHandleW(h,final,_countof(final),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
        CHECK(n != 0 && n < _countof(final));
        n=GetFinalPathNameByHandleW(h,final,_countof(final),FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);
        CHECK(n != 0 && n < _countof(final));
        if(n != 0 && n < _countof(final)) CHECK(_wcsnicmp(final,guid,wcslen(guid))==0);
        CloseHandle(h);
    }
}

#include "memfs_stream_probe.inc"
int wmain(int argc, WCHAR** argv) {
    if (argc == 3 && wcscmp(argv[1], L"--ads-only") == 0) {
        swprintf_s(root, _countof(root), L"%ls\\ads-%lu-%llu", argv[2], GetCurrentProcessId(), GetTickCount64());
        CHECK(CreateDirectoryW(root, NULL));
        run_stream_tests();
        CHECK(RemoveDirectoryW(root));
        printf("ADS RESULT: %d checks, %d failures\n", checks, failures);
        return failures ? 1 : 0;
    }
	if (argc == 2 && wcscmp(argv[1], L"--child") == 0)
		return 37;
	if (argc != 3) {
		fwprintf(stderr, L"usage: memfs_temp_probe <fresh-volume-temp-directory> <fixture-dll>\n");
		return 2;
	}
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	swprintf_s(root, _countof(root), L"%ls\\probe-%lu-%llu", argv[1], GetCurrentProcessId(), GetTickCount64());
	CHECK(CreateDirectoryW(root, NULL));
	STEP("volume capabilities and shared bootstrap policy", test_volume_and_bootstrap(argv[1]));
	STEP("Mount Manager GUID and normalized DOS/GUID paths", test_volume_path_resolution(argv[1]));
	STEP("DACL inheritance, protection, deny, empty ACL, handle access checks", test_inherit_and_deny());
	STEP("explicit create DACL merge and protected create DACL", test_explicit_create_security());
	STEP("owner/group and mandatory integrity label", test_owner_group_label());
	STEP("temporary naming, CREATE_NEW, delete-on-last-close", test_temp_and_delete());
	STEP("memory mapping, flush and byte-range locks", test_mapping_and_locks());
	STEP("ReplaceFile, rename and sharing violations", test_replace_and_sharing());
	STEP("EXE execution and DLL image loading from RAM", test_images(argv[2]));
	STEP("non-admin creator and restricted-token isolation", test_restricted_user(argv[1]));
	run_stream_tests();
	CHECK(RemoveDirectoryW(root));
	printf("RESULT: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
