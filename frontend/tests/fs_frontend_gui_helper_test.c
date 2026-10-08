#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "../src/fs_frontend_gui.c"

static const WCHAR *g_roundtrip[] = {
	L"", L"plain", L"two words", L"C:\\trailing path\\",
	L"quote\"inside", L"backslash\\\"quote", L"中文路径 🧪"
};

static int child_check(int argc, WCHAR **argv) {
	size_t i;
	if (argc != (int)ARRAYSIZE(g_roundtrip) + 2 ||
		wcscmp(argv[1], L"--gui-roundtrip-child") != 0) return 20;
	for (i = 0; i < ARRAYSIZE(g_roundtrip); ++i)
		if (wcscmp(argv[i + 2], g_roundtrip[i]) != 0) return (int)(21 + i);
	return 0;
}

static BOOL verify_argv_roundtrip(void) {
	FSF_GUI_ARGV *args = fsf_gui_argv_create();
	WCHAR executable[MAX_PATH], *command = NULL;
	DWORD n; PROCESS_INFORMATION pi; STARTUPINFOW si; DWORD code = 999;
	size_t i; BOOL ok = FALSE;
	if (args == NULL || !fsf_gui_argv_append(args, L"--gui-roundtrip-child")) goto done;
	for (i = 0; i < ARRAYSIZE(g_roundtrip); ++i)
		if (!fsf_gui_argv_append(args, g_roundtrip[i])) goto done;
	n = GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable));
	if (n == 0 || n >= ARRAYSIZE(executable) ||
		!fsf_gui_argv_build_command_line(executable, args, &command)) goto done;
	memset(&si, 0, sizeof(si)); si.cb = sizeof(si); memset(&pi, 0, sizeof(pi));
	if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
		NULL, NULL, &si, &pi)) goto done;
	CloseHandle(pi.hThread);
	if (WaitForSingleObject(pi.hProcess, 5000) != WAIT_OBJECT_0) {
		CloseHandle(pi.hProcess); goto done;
	}
	if (GetExitCodeProcess(pi.hProcess, &code) && code == 0) ok = TRUE;
	CloseHandle(pi.hProcess);
done:
	fsf_gui_free(command);
	fsf_gui_argv_destroy(args);
	return ok;
}

static BOOL write_fragment(HANDLE pipe, const BYTE *bytes, DWORD length) {
	DWORD written = 0;
	return WriteFile(pipe, bytes, length, &written, NULL) && written == length;
}

static BOOL pipe_case(PCWSTR label, const BYTE *const *parts,
	const DWORD *lengths, size_t part_count, PCWSTR expected) {
	WCHAR pipe_name[128];
	HANDLE reader = INVALID_HANDLE_VALUE, writer = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES sa;
	GUI_STATE state;
	size_t i;
	BOOL ok = FALSE;
	ULONGLONG started = GetTickCount64();
	memset(&state, 0, sizeof(state)); g = &state;
	_snwprintf_s(pipe_name, ARRAYSIZE(pipe_name), _TRUNCATE,
		L"\\\\.\\pipe\\fsf-gui-helper-%lu-%llu", GetCurrentProcessId(), started);
	memset(&sa, 0, sizeof(sa)); sa.nLength = sizeof(sa);
	reader = CreateNamedPipeW(pipe_name, PIPE_ACCESS_INBOUND,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, &sa);
	if (reader == INVALID_HANDLE_VALUE) goto done;
	writer = CreateFileW(pipe_name, GENERIC_WRITE, 0, &sa, OPEN_EXISTING, 0, NULL);
	if (writer == INVALID_HANDLE_VALUE) goto done;
	if (!ConnectNamedPipe(reader, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) goto done;
	for (i = 0; i < part_count; ++i) {
		if (!write_fragment(writer, parts[i], lengths[i])) goto done;
		read_pipe(reader, state.stdout_tail, &state.stdout_tail_len, &state.stdout_encoding);
	}
	CloseHandle(writer); writer = INVALID_HANDLE_VALUE;
	/* Once all bytes are drained, another poll must return promptly with the writer closed. */
	read_pipe(reader, state.stdout_tail, &state.stdout_tail_len, &state.stdout_encoding);
	flush_pipe_tail(state.stdout_tail, &state.stdout_tail_len, state.stdout_encoding);
	if (state.capture == NULL || wcscmp(state.capture, expected) != 0) {
		fwprintf(stderr, L"FAIL %ls: got [%ls], expected [%ls], encoding=%d tail=%zu\n",
			label, state.capture ? state.capture : L"(null)", expected,
			state.stdout_encoding, state.stdout_tail_len);
		goto done;
	}
	if (GetTickCount64() - started > 1000) {
		fwprintf(stderr, L"FAIL %ls: drain exceeded the 1-second bound\n", label);
		goto done;
	}
	ok = TRUE;
done:
	if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
	if (reader != INVALID_HANDLE_VALUE) CloseHandle(reader);
	free(state.capture); g = NULL;
	if (!ok && GetLastError() != ERROR_SUCCESS)
		fwprintf(stderr, L"FAIL %ls: Win32 error %lu\n", label, GetLastError());
	return ok;
}

static BOOL verify_pipe_fragments(void) {
	static const BYTE utf8[] = { 0xe4, 0xb8, 0xad };
	static const BYTE utf8_a[] = { 0xe4 };
	static const BYTE utf8_b[] = { 0xb8, 0xad };
	static const BYTE utf8_c[] = { 0xe4, 0xb8 };
	static const BYTE utf8_d[] = { 0xad };
	static const BYTE utf8_pad[] = { 0xe4, 0xb8, 0xad, 'x' };
	static const BYTE bom_a[] = { 0xff };
	static const BYTE bom_b[] = { 0xfe, 0x2d, 0x4e };
	static const BYTE no_bom_a[] = { 'A' };
	static const BYTE no_bom_b[] = { 0x00, 0x0a, 0x00, 0x2d };
	static const BYTE no_bom_c[] = { 0x4e };
	static const BYTE *p1[] = { utf8_a, utf8_b };
	static const BYTE *p2[] = { utf8_c, utf8_d };
	static const BYTE *p3[] = { utf8 };
	static const BYTE *p4[] = { utf8_a, utf8_pad + 1 };
	static const BYTE *p5[] = { bom_a, bom_b };
	static const BYTE *p6[] = { no_bom_a, no_bom_b, no_bom_c };
	static const DWORD l1[] = { 1, 2 }, l2[] = { 2, 1 }, l3[] = { 3 };
	static const DWORD l4[] = { 1, 3 }, l5[] = { 1, 3 }, l6[] = { 1, 4, 1 };
	return pipe_case(L"UTF-8 1+2", p1, l1, ARRAYSIZE(p1), L"中") &&
		pipe_case(L"UTF-8 2+1", p2, l2, ARRAYSIZE(p2), L"中") &&
		pipe_case(L"short UTF-8 3-byte stream", p3, l3, ARRAYSIZE(p3), L"中") &&
		pipe_case(L"UTF-8 split with printable tail", p4, l4, ARRAYSIZE(p4), L"中x") &&
		pipe_case(L"UTF-16LE BOM split at 0xff", p5, l5, ARRAYSIZE(p5), L"中") &&
		pipe_case(L"UTF-16LE no BOM odd chunks", p6, l6, ARRAYSIZE(p6), L"A\n中");
}

int wmain(int argc, WCHAR **argv) {
	if (argc > 1 && wcscmp(argv[1], L"--gui-roundtrip-child") == 0)
		return child_check(argc, argv);
	if (!verify_pipe_fragments()) return 1;
	wprintf(L"PASS: named-pipe UTF-8/UTF-16LE fragments and drain; real CRT argv child round-trip\n");
	if (!verify_argv_roundtrip()) {
		fwprintf(stderr, L"FAIL: real CRT child argv round-trip\n");
		return 2;
	}
	return 0;
}
