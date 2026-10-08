#include "fs_frontend_gui.h"
#include <commdlg.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#define GUI_CLASS L"FSF.Shared.ConfigWindow.v1"
#define GUI_TIMER 1
#define GUI_CAPTURE_LIMIT (1024u * 1024u)
struct FSF_GUI_ARGV { PCWSTR *items; size_t count, capacity; BYTE *stdin_blob; size_t stdin_length; };
typedef struct GUI_FIELD { const FSF_GUI_FIELD *spec; HWND label, input, browse; WCHAR *value; } GUI_FIELD;
typedef struct GUI_STATE {
	const FSF_GUI_CONFIG *config;
	HWND window, status, output, stop_button;
	HWND *actions;
	GUI_FIELD *fields;
	HANDLE process, stdout_read, stderr_read, stop_event;
	WCHAR stop_event_name[96];
	FSF_GUI_ACTION active_action, elevated_action;
	ULONGLONG deadline;
	WCHAR *capture;
	size_t capture_length, capture_capacity, marker_scanned;
	BOOL mount_marker_seen;
	BYTE stdout_tail[4], stderr_tail[4];
	size_t stdout_tail_len, stderr_tail_len;
	int stdout_encoding, stderr_encoding;
	BOOL close_when_done, elevated_action_pending;
} GUI_STATE;
static GUI_STATE *g;
static HINSTANCE g_instance;
static HFONT g_font;
static BOOL g_owns_font;
static UINT gui_dpi(HWND h) { UINT d = GetDpiForWindow(h); return d ? d : 96; }
static int px(HWND h, int logical) { return MulDiv(logical, (int)gui_dpi(h), 96); }
static WCHAR *make_command(PCWSTR exe, const FSF_GUI_ARGV *args);
static WCHAR *dup_w(PCWSTR s) {
	size_t n; WCHAR *p; if (s == NULL) s = L""; n = wcslen(s) + 1;
	p = (WCHAR *)malloc(n * sizeof(*p)); if (p != NULL) memcpy(p, s, n * sizeof(*p)); return p;
}
static void secure_free_w(WCHAR *s) {
	if (s != NULL) {
		SecureZeroMemory(s, (wcslen(s) + 1) * sizeof(*s));
		free(s);
	}
}
BOOL fsf_gui_argv_append(FSF_GUI_ARGV *a, PCWSTR token) {
	PCWSTR *next; WCHAR *copy; size_t cap;
	if (a == NULL || token == NULL) return FALSE;
	if (a->count == a->capacity) {
		cap = a->capacity == 0 ? 8 : a->capacity * 2;
		if (cap < a->capacity || cap > SIZE_MAX / sizeof(*next)) return FALSE;
		next = (PCWSTR *)realloc((void *)a->items, cap * sizeof(*next)); if (next == NULL) return FALSE;
		a->items = next; a->capacity = cap;
	}
	copy = dup_w(token); if (copy == NULL) return FALSE; a->items[a->count++] = copy; return TRUE;
}
static void argv_clear(FSF_GUI_ARGV *a) {
	size_t i; for (i = 0; i < a->count; ++i) free((void *)a->items[i]);
	free((void *)a->items);
	if (a->stdin_blob != NULL) {
		SecureZeroMemory(a->stdin_blob, a->stdin_length);
		free(a->stdin_blob);
	}
	memset(a, 0, sizeof(*a));
}
FSF_GUI_ARGV *fsf_gui_argv_create(void) { return (FSF_GUI_ARGV *)calloc(1, sizeof(FSF_GUI_ARGV)); }
void fsf_gui_argv_destroy(FSF_GUI_ARGV *a) { if (a) { argv_clear(a); free(a); } }
BOOL fsf_gui_argv_set_stdin(FSF_GUI_ARGV *a, const void *bytes, size_t length) {
	BYTE *copy = NULL;
	if (a == NULL || length > 4096 || (length != 0 && bytes == NULL)) return FALSE;
	if (length != 0) {
		copy = (BYTE *)malloc(length);
		if (copy == NULL) return FALSE;
		memcpy(copy, bytes, length);
	}
	if (a->stdin_blob != NULL) {
		SecureZeroMemory(a->stdin_blob, a->stdin_length);
		free(a->stdin_blob);
	}
	a->stdin_blob = copy;
	a->stdin_length = length;
	return TRUE;
}
size_t fsf_gui_argv_count(const FSF_GUI_ARGV *a) { return a ? a->count : 0; }
PCWSTR fsf_gui_argv_get(const FSF_GUI_ARGV *a, size_t i) { return a && i < a->count ? a->items[i] : NULL; }
BOOL fsf_gui_argv_build_command_line(PCWSTR exe, const FSF_GUI_ARGV *a, PWSTR *out) {
	if (exe == NULL || a == NULL || out == NULL) return FALSE;
	*out = make_command(exe, a);
	return *out != NULL;
}
void fsf_gui_free(PVOID p) { free(p); }
static BOOL append_char(WCHAR **s, size_t *len, size_t *cap, WCHAR ch) {
	WCHAR *p; size_t nc;
	if (*len + 2 > *cap) {
		nc = *cap == 0 ? 64 : *cap * 2; if (nc < *cap || nc > SIZE_MAX / sizeof(WCHAR)) return FALSE;
		p = (WCHAR *)realloc(*s, nc * sizeof(WCHAR)); if (p == NULL) return FALSE; *s = p; *cap = nc;
	}
	(*s)[(*len)++] = ch; (*s)[*len] = 0; return TRUE;
}
/* Microsoft CRT argv quoting rule, including trailing and quote-adjacent backslashes. */
static BOOL quote_arg(WCHAR **s, size_t *len, size_t *cap, PCWSTR arg) {
	BOOL quoted = !*arg; size_t slashes = 0; PCWSTR p;
	for (p = arg; *p; ++p) if (*p == L' ' || *p == L'\t' || *p == L'\n' || *p == L'\v' || *p == L'"') quoted = TRUE;
	if (!quoted) { for (p = arg; *p; ++p) if (!append_char(s, len, cap, *p)) return FALSE; return TRUE; }
	if (!append_char(s, len, cap, L'"')) return FALSE;
	for (p = arg;; ++p) {
		if (*p == L'\\') { ++slashes; continue; }
		if (*p == L'"') {
			size_t i, count = slashes * 2 + 1;
			for (i = 0; i < count; ++i) if (!append_char(s, len, cap, L'\\')) return FALSE;
			slashes = 0;
			if (!append_char(s, len, cap, L'"')) return FALSE;
			continue;
		}
		if (*p == 0) {
			size_t i, count = slashes * 2;
			for (i = 0; i < count; ++i) if (!append_char(s, len, cap, L'\\')) return FALSE;
			break;
		}
		while (slashes-- != 0) if (!append_char(s, len, cap, L'\\')) return FALSE;
		slashes = 0; if (!append_char(s, len, cap, *p)) return FALSE;
	}
	return append_char(s, len, cap, L'"');
}
static WCHAR *make_command(PCWSTR exe, const FSF_GUI_ARGV *args) {
	WCHAR *s = NULL; size_t len = 0, cap = 0, i;
	if (!quote_arg(&s, &len, &cap, exe)) goto fail;
	for (i = 0; i < args->count; ++i)
		if (!append_char(&s, &len, &cap, L' ') || !quote_arg(&s, &len, &cap, args->items[i])) goto fail;
	return s;
fail: free(s); return NULL;
}
static void set_status(PCWSTR s) { if (g && g->status) SetWindowTextW(g->status, s ? s : L""); }
static BOOL append_output(PCWSTR s) {
	static const WCHAR marker[] = L"mounted at";
	const size_t marker_length = ARRAYSIZE(marker) - 1;
	size_t n = wcslen(s), start;
	if (g->capture_length + n > GUI_CAPTURE_LIMIT) return FALSE;
	if (g->capture_length + n + 1 > g->capture_capacity) {
		size_t cap = g->capture_capacity ? g->capture_capacity : 4096; WCHAR *p;
		while (cap < g->capture_length + n + 1) cap *= 2;
		if (cap > GUI_CAPTURE_LIMIT + 1) cap = GUI_CAPTURE_LIMIT + 1;
		p = (WCHAR *)realloc(g->capture, cap * sizeof(WCHAR)); if (!p) return FALSE;
		g->capture = p; g->capture_capacity = cap;
	}
	memcpy(g->capture + g->capture_length, s, n * sizeof(WCHAR));
	g->capture_length += n; g->capture[g->capture_length] = 0;
	/* Append only the new text; resetting the whole control text is quadratic. */
	if (g->output != NULL) {
		int end = GetWindowTextLengthW(g->output);
		SendMessageW(g->output, EM_SETSEL, (WPARAM)end, (LPARAM)end);
		SendMessageW(g->output, EM_REPLACESEL, FALSE, (LPARAM)s);
		SendMessageW(g->output, EM_SCROLLCARET, 0, 0);
	}
	if (g->active_action == FSF_GUI_ACTION_MOUNT && !g->mount_marker_seen) {
		/* Rescan only text that could complete a marker; report readiness once. */
		start = g->marker_scanned;
		for (; start + marker_length <= g->capture_length; ++start) {
			size_t i;
			for (i = 0; i < marker_length && towlower(g->capture[start + i]) == marker[i]; ++i) {}
			if (i == marker_length) {
				g->mount_marker_seen = TRUE;
				set_status(L"挂载程序已报告挂载就绪。");
				break;
			}
		}
		g->marker_scanned = start;
	}
	return TRUE;
}
static void read_pipe(HANDLE h, BYTE *tail, size_t *tail_len, int *encoding) {
	BYTE bytes[4100]; WCHAR wide[4101]; DWORD available = 0, got, budget = 16384; int n; size_t used;
	if (!h || !PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) return;
	while (available && budget) {
		DWORD ask = available < 4096 ? available : 4096;
		if (ask > budget) ask = budget;
		if (*tail_len) memcpy(bytes, tail, *tail_len);
		if (!ReadFile(h, bytes + *tail_len, ask, &got, NULL) || !got) break;
		used = *tail_len + got; budget -= got;
		if (*encoding == 0) {
			if (used < 4) {
				*tail_len = used; memcpy(tail, bytes, used);
				if (!PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) break;
				continue;
			}
			if ((used >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe) ||
				(bytes[1] == 0 && bytes[3] == 0))
				*encoding = (bytes[0] == 0xff && bytes[1] == 0xfe) ? 2 : 3;
			else
				*encoding = 1;
		}
		if (*encoding == 2 || *encoding == 3) {
			size_t start = (*encoding == 2 && used >= 2 &&
				bytes[0] == 0xff && bytes[1] == 0xfe) ? 2 : 0;
			size_t body = used - start, even = body & ~(size_t)1;
			n = (int)(even / sizeof(WCHAR));
			if (n > 0) {
				memcpy(wide, bytes + start, even);
				wide[n] = 0;
				if (!append_output(wide)) set_status(L"输出达到界面上限。");
			}
			*tail_len = body - even;
			if (*tail_len) memcpy(tail, bytes + start + even, *tail_len);
			if (!PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) break;
			continue;
		}
		n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)bytes, (int)used, wide, 4100);
		if (!n) {
			size_t valid;
			for (valid = used; valid > 0 && used - valid < 4; --valid) {
				n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)bytes, (int)valid, wide, 4100);
				if (n > 0) break;
			}
			if (n > 0 && valid < used) {
				*tail_len = used - valid; memcpy(tail, bytes + valid, *tail_len);
			} else if (n == 0 && used <= 3) {
				*tail_len = used; memcpy(tail, bytes, used);
				if (!PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) break;
				continue;
			} else {
				n = MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)bytes, (int)used, wide, 4100);
				*tail_len = 0;
			}
		} else *tail_len = 0;
		if (n) { wide[n] = 0; if (!append_output(wide)) set_status(L"输出达到界面上限。"); }
		if (!PeekNamedPipe(h, NULL, 0, NULL, &available, NULL)) break;
	}
}
static void flush_pipe_tail(BYTE *tail, size_t *tail_len, int encoding) {
	WCHAR wide[8]; int n;
	if (*tail_len == 0) return;
	if (encoding == 2 || encoding == 3) { *tail_len = 0; return; }
	n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCCH)tail,
		(int)*tail_len, wide, ARRAYSIZE(wide) - 1);
	if (n == 0)
		n = MultiByteToWideChar(CP_OEMCP, 0, (LPCCH)tail,
			(int)*tail_len, wide, ARRAYSIZE(wide) - 1);
	if (n > 0) { wide[n] = 0; (void)append_output(wide); }
	*tail_len = 0;
}
static PCWSTR action_name(FSF_GUI_ACTION a) {
	switch (a) { case FSF_GUI_ACTION_MOUNT:return L"mount"; case FSF_GUI_ACTION_UNMOUNT:return L"unmount";
	case FSF_GUI_ACTION_INSTALL:return L"install"; case FSF_GUI_ACTION_UNINSTALL:return L"uninstall";
	case FSF_GUI_ACTION_PROBE:return L"probe"; default:return L""; }
}
static BOOL parse_action(PCWSTR s, FSF_GUI_ACTION *out) {
	FSF_GUI_ACTION a;
	for (a = FSF_GUI_ACTION_MOUNT; a <= FSF_GUI_ACTION_PROBE; ++a) {
		if (_wcsicmp(s, action_name(a)) == 0) { *out = a; return TRUE; }
	}
	return FALSE;
}
static void set_font(HWND h) { if (h) SendMessageW(h, WM_SETFONT, (WPARAM)g_font, TRUE); }
static void update_font(HWND hwnd) {
	LOGFONTW lf; HFONT next, old; BOOL old_owned = g_owns_font;
	memset(&lf, 0, sizeof(lf));
	lf.lfHeight = -MulDiv(9, (int)gui_dpi(hwnd), 72); lf.lfWeight = FW_NORMAL;
	wcscpy_s(lf.lfFaceName, ARRAYSIZE(lf.lfFaceName), L"Microsoft YaHei UI");
	next = CreateFontIndirectW(&lf);
	if (!next) return;
	old = g_font; g_font = next; g_owns_font = TRUE;
	for (size_t i = 0; g && i < g->config->field_count; ++i) {
		set_font(g->fields[i].label); set_font(g->fields[i].input); set_font(g->fields[i].browse);
	}
	for (size_t i = 0; g && i < g->config->action_count; ++i) set_font(g->actions[i]);
	if (g) { set_font(g->stop_button); set_font(g->status); set_font(g->output); }
	if (old && old_owned) DeleteObject(old);
}

static BOOL gui_admin(void) {
	BOOL member = FALSE; PSID sid = NULL;
	SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid)) return FALSE;
	(void)CheckTokenMembership(NULL, sid, &member); FreeSid(sid); return member;
}
static BOOL make_stop_name(void) {
	GUID id; WCHAR guid[40];
	if (CoCreateGuid(&id) != S_OK || StringFromGUID2(&id, guid, ARRAYSIZE(guid)) == 0) return FALSE;
	if (_snwprintf_s(g->stop_event_name, ARRAYSIZE(g->stop_event_name), _TRUNCATE,
		L"Local\\FSF-GUI-%ls", guid) < 0) return FALSE;
	HANDLE token = NULL;
	DWORD token_bytes = 0;
	TOKEN_USER *token_user = NULL;
	LPWSTR user_sid = NULL;
	PSECURITY_DESCRIPTOR descriptor = NULL;
	SECURITY_ATTRIBUTES sa;
	WCHAR sddl[512];
	BOOL ok = FALSE;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
	(void)GetTokenInformation(token, TokenUser, NULL, 0, &token_bytes);
	if (token_bytes == 0) goto done;
	token_user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, token_bytes);
	if (token_user == NULL ||
		!GetTokenInformation(token, TokenUser, token_user, token_bytes, &token_bytes) ||
		!ConvertSidToStringSidW(token_user->User.Sid, &user_sid)) goto done;
	if (_snwprintf_s(sddl, ARRAYSIZE(sddl), _TRUNCATE,
		L"O:%lsG:%lsD:P(A;;GA;;;SY)(A;;GA;;;%ls)", user_sid, user_sid, user_sid) < 0)
		goto done;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		sddl, SDDL_REVISION_1, &descriptor, NULL)) goto done;
	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = descriptor;
	g->stop_event = CreateEventW(&sa, TRUE, FALSE, g->stop_event_name);
	ok = g->stop_event != NULL;
done:
	SecureZeroMemory(sddl, sizeof(sddl));
	if (descriptor != NULL) LocalFree(descriptor);
	if (user_sid != NULL) LocalFree(user_sid);
	if (token_user != NULL) {
		SecureZeroMemory(token_user, token_bytes);
		HeapFree(GetProcessHeap(), 0, token_user);
	}
	if (token != NULL) CloseHandle(token);
	return ok;
}
static BOOL collect_values(void) {
	size_t i;
	for (i = 0; i < g->config->field_count; ++i) {
		GUI_FIELD *f = &g->fields[i]; int n;
		if (f->spec->kind == FSF_GUI_FIELD_BOOLEAN) {
			free(f->value);
			f->value = dup_w(SendMessageW(f->input, BM_GETCHECK, 0, 0) == BST_CHECKED ? L"true" : L"false");
		} else if (f->spec->kind == FSF_GUI_FIELD_ENUM) {
			LRESULT sel = SendMessageW(f->input, CB_GETCURSEL, 0, 0);
			if (sel == CB_ERR || (size_t)sel >= f->spec->choice_count) {
				set_status(L"请选择有效选项。"); SetFocus(f->input); return FALSE;
			}
			free(f->value);
			f->value = dup_w(f->spec->choices[sel]);
		} else {
			n = GetWindowTextLengthW(f->input);
			if (f->spec->kind == FSF_GUI_FIELD_PASSWORD) secure_free_w(f->value);
			else free(f->value);
			f->value = (WCHAR *)malloc(((size_t)n + 1) * sizeof(WCHAR));
			if (f->value != NULL) GetWindowTextW(f->input, f->value, n + 1);
		}
		if (f->value == NULL) return FALSE;
	}
	return TRUE;
}
static void wipe_password_fields(void) {
	size_t i;
	if (g == NULL || g->fields == NULL) return;
	for (i = 0; i < g->config->field_count; ++i) {
		GUI_FIELD *f = &g->fields[i];
		if (f->spec->kind == FSF_GUI_FIELD_PASSWORD) {
			secure_free_w(f->value);
			f->value = dup_w(L"");
			if (f->input != NULL) SetWindowTextW(f->input, L"");
		}
	}
}
static BOOL has_password_field_value(void) {
	size_t i;
	if (g == NULL || g->fields == NULL) return FALSE;
	for (i = 0; i < g->config->field_count; ++i)
		if (g->fields[i].spec->kind == FSF_GUI_FIELD_PASSWORD &&
			g->fields[i].value != NULL && g->fields[i].value[0] != L'\0') return TRUE;
	return FALSE;
}
static PCWSTR find_value(PCWSTR id_fragment) {
	size_t i;
	for (i = 0; i < g->config->field_count; ++i)
		if (wcsstr(g->fields[i].spec->id, id_fragment) != NULL) return g->fields[i].value;
	return NULL;
}
static BOOL confirm_action(FSF_GUI_ACTION action) {
	WCHAR message[512]; PCWSTR value; BOOL confirmed;
	if (action != FSF_GUI_ACTION_UNMOUNT && action != FSF_GUI_ACTION_UNINSTALL)
		return TRUE;
	if (!collect_values()) {
		wipe_password_fields();
		return FALSE;
	}
	if (action == FSF_GUI_ACTION_UNMOUNT) {
		value = find_value(L"mount");
		if (value == NULL || !*value) value = find_value(L"drive");
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"%ls%s%ls%ls",
			g->config->unmount_warning != NULL ? g->config->unmount_warning : L"将停止此窗口启动的挂载",
			value && *value ? L"（目标 " : L"",
			value && *value ? value : L"",
			value && *value ? L"）" : L"");
		confirmed = MessageBoxW(g->window, message, L"确认停止挂载",
			MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND) == IDYES;
		wipe_password_fields();
		return confirmed;
	}
	if (action == FSF_GUI_ACTION_UNINSTALL) {
		value = find_value(L"service_name");
		if (value == NULL) value = find_value(L"service-name");
		if (value == NULL) value = find_value(L"service");
		_snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
			L"将停止并删除服务“%ls”。是否继续？",
			value && *value ? value : L"(默认服务)");
		confirmed = MessageBoxW(g->window, message, L"确认删除服务",
			MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND) == IDYES;
		wipe_password_fields();
		return confirmed;
	}
	return TRUE;
}
static WCHAR *make_parameters(const FSF_GUI_ARGV *args) {
	WCHAR *s = NULL; size_t len = 0, cap = 0, i;
	for (i = 0; i < args->count; ++i)
		if ((i != 0 && !append_char(&s, &len, &cap, L' ')) ||
			!quote_arg(&s, &len, &cap, args->items[i])) { free(s); return NULL; }
	return s != NULL ? s : dup_w(L"");
}
static BOOL append_relaunch_field(FSF_GUI_ARGV *a, PCWSTR id, PCWSTR value) {
	return fsf_gui_argv_append(a, L"--fsf-gui-field") &&
		fsf_gui_argv_append(a, id) && fsf_gui_argv_append(a, value);
}
static BOOL launch_elevated(FSF_GUI_ACTION action) {
	WCHAR exe[MAX_PATH]; DWORD n = GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe));
	FSF_GUI_ARGV args = { 0 }; WCHAR *parameters; SHELLEXECUTEINFOW sx; size_t i;
	if (!n || n >= ARRAYSIZE(exe) || !fsf_gui_argv_append(&args, L"--gui") ||
		!fsf_gui_argv_append(&args, L"--fsf-gui-action") ||
		!fsf_gui_argv_append(&args, action_name(action))) goto fail;
	for (i = 0; i < g->config->field_count; ++i)
		if (g->fields[i].spec->kind != FSF_GUI_FIELD_PASSWORD &&
			!append_relaunch_field(&args, g->fields[i].spec->id, g->fields[i].value)) goto fail;
	parameters = make_parameters(&args); if (!parameters) goto fail;
	memset(&sx, 0, sizeof(sx)); sx.cbSize = sizeof(sx); sx.fMask = SEE_MASK_NOCLOSEPROCESS;
	sx.lpVerb = L"runas"; sx.lpFile = exe; sx.lpParameters = parameters; sx.nShow = SW_SHOWNORMAL;
	if (!ShellExecuteExW(&sx)) { free(parameters); goto fail; }
	if (sx.hProcess) CloseHandle(sx.hProcess);
	free(parameters); argv_clear(&args); set_status(L"已打开管理员窗口；该窗口将执行所选服务操作。"); return TRUE;
fail: argv_clear(&args); return FALSE;
}
static BOOL start_child(FSF_GUI_ACTION action) {
	FSF_GUI_ARGV args = { 0 }; FSF_GUI_VALUE *values = NULL;
	WCHAR exe[MAX_PATH], *command = NULL; DWORD n, error = ERROR_SUCCESS;
	HANDLE stdout_write = NULL, stderr_write = NULL, nul_input = NULL;
	HANDLE stdin_read = NULL, stdin_write = NULL;
	SECURITY_ATTRIBUTES sa; STARTUPINFOEXW si; PROCESS_INFORMATION pi;
	SIZE_T attr_size = 0; LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL; BOOL attrs_initialized = FALSE;
	HANDLE inherited[4]; size_t inherited_count = 0, i; BOOL ok = FALSE;
	if (g->process != NULL) return FALSE;
	if (!collect_values()) { wipe_password_fields(); return FALSE; }
	values = (FSF_GUI_VALUE *)calloc(g->config->field_count, sizeof(*values));
	if (values == NULL && g->config->field_count != 0) goto fail;
	for (i = 0; i < g->config->field_count; ++i) {
		values[i].id = g->fields[i].spec->id; values[i].value = g->fields[i].value;
	}
	g->stop_event_name[0] = 0;
	if (action == FSF_GUI_ACTION_MOUNT && !make_stop_name()) goto fail;
	{
		BOOL built = g->config->build_argv(g->config->context, action, values,
			g->config->field_count, g->stop_event_name, &args);
		BOOL secret_value = has_password_field_value();
		wipe_password_fields();
		if (!built) { set_status(L"字段无效或当前操作缺少必需信息。"); goto done; }
		if ((action == FSF_GUI_ACTION_INSTALL || action == FSF_GUI_ACTION_UNINSTALL) &&
			(!gui_admin()) && (secret_value || args.stdin_length != 0)) {
			set_status(L"包含密码的操作不能通过管理员重启传递；请在当前用户下启动。");
			goto done;
		}
	}
	if ((action == FSF_GUI_ACTION_INSTALL || action == FSF_GUI_ACTION_UNINSTALL) && !gui_admin()) {
		if (launch_elevated(action)) { ok = TRUE; goto done; }
		error = GetLastError(); goto fail;
	}
	n = GetModuleFileNameW(NULL, exe, ARRAYSIZE(exe));
	if (!n || n >= ARRAYSIZE(exe)) goto fail;
	command = make_command(exe, &args); if (!command) goto fail;
	memset(&sa, 0, sizeof(sa)); sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
	if (!CreatePipe(&g->stdout_read, &stdout_write, &sa, 0) ||
		!SetHandleInformation(g->stdout_read, HANDLE_FLAG_INHERIT, 0) ||
		!CreatePipe(&g->stderr_read, &stderr_write, &sa, 0) ||
		!SetHandleInformation(g->stderr_read, HANDLE_FLAG_INHERIT, 0)) goto fail;
	if (args.stdin_length != 0) {
		size_t offset = 0;
		if (!CreatePipe(&stdin_read, &stdin_write, &sa, 4096) ||
			!SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0)) goto fail;
		while (offset < args.stdin_length) {
			DWORD written = 0;
			DWORD request = (DWORD)(args.stdin_length - offset);
			if (!WriteFile(stdin_write, args.stdin_blob + offset, request, &written, NULL) || written == 0)
				goto fail;
			offset += written;
		}
		CloseHandle(stdin_write); stdin_write = NULL;
	} else {
		nul_input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			&sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (nul_input == INVALID_HANDLE_VALUE) { nul_input = NULL; goto fail; }
	}
	InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
	attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
	if (attrs == NULL || !InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) goto fail;
	attrs_initialized = TRUE;
	inherited[inherited_count++] = stdout_write;
	inherited[inherited_count++] = stderr_write;
	if (stdin_read != NULL) inherited[inherited_count++] = stdin_read;
	else inherited[inherited_count++] = nul_input;
	if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		inherited, inherited_count * sizeof(inherited[0]), NULL, NULL)) goto fail;
	memset(&si, 0, sizeof(si)); si.StartupInfo.cb = sizeof(si);
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.StartupInfo.wShowWindow = SW_HIDE; si.StartupInfo.hStdOutput = stdout_write;
	si.StartupInfo.hStdError = stderr_write; si.StartupInfo.hStdInput = stdin_read != NULL ? stdin_read : nul_input;
	si.lpAttributeList = attrs; memset(&pi, 0, sizeof(pi));
	if (!CreateProcessW(exe, command, NULL, NULL, TRUE,
		CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi)) goto fail;
	CloseHandle(stdout_write); stdout_write = NULL; CloseHandle(stderr_write); stderr_write = NULL;
	if (nul_input) { CloseHandle(nul_input); nul_input = NULL; }
	if (stdin_read) { CloseHandle(stdin_read); stdin_read = NULL; }
	DeleteProcThreadAttributeList(attrs); attrs_initialized = FALSE;
	HeapFree(GetProcessHeap(), 0, attrs); attrs = NULL;
	g->process = pi.hProcess; CloseHandle(pi.hThread); g->active_action = action;
	g->deadline = GetTickCount64() + (g->config->action_timeout_ms ? g->config->action_timeout_ms : 300000u);
	g->capture_length = 0; if (g->capture) g->capture[0] = 0; SetWindowTextW(g->output, L"");
	g->marker_scanned = 0; g->mount_marker_seen = FALSE;
	/* Decoder state belongs to one child; never carry a detected encoding over. */
	g->stdout_tail_len = g->stderr_tail_len = 0;
	g->stdout_encoding = g->stderr_encoding = 0;
	EnableWindow(g->stop_button, action == FSF_GUI_ACTION_MOUNT);
	for (i = 0; i < g->config->action_count; ++i)
		EnableWindow(g->actions[i], g->config->actions[i].action == FSF_GUI_ACTION_UNMOUNT &&
			action == FSF_GUI_ACTION_MOUNT);
	for (i = 0; i < g->config->field_count; ++i) {
		EnableWindow(g->fields[i].input, FALSE);
		EnableWindow(g->fields[i].browse, FALSE);
	}
	SetTimer(g->window, GUI_TIMER, 80, NULL);
	set_status(action == FSF_GUI_ACTION_MOUNT ? L"正在启动挂载…" : L"操作正在运行…");
	ok = TRUE; goto done;
fail:
	if (error == ERROR_SUCCESS) error = GetLastError();
	if (stdout_write) CloseHandle(stdout_write);
	if (stderr_write) CloseHandle(stderr_write);
	if (nul_input) CloseHandle(nul_input);
	if (stdin_write) CloseHandle(stdin_write);
	if (stdin_read) CloseHandle(stdin_read);
	if (attrs) { if (attrs_initialized) DeleteProcThreadAttributeList(attrs); HeapFree(GetProcessHeap(), 0, attrs); }
	if (g->stdout_read) { CloseHandle(g->stdout_read); g->stdout_read = NULL; }
	if (g->stderr_read) { CloseHandle(g->stderr_read); g->stderr_read = NULL; }
	if (g->stop_event) { CloseHandle(g->stop_event); g->stop_event = NULL; }
	{
		WCHAR msg[128]; _snwprintf_s(msg, ARRAYSIZE(msg), _TRUNCATE, L"无法启动操作（Win32 错误 %lu）。", error);
		set_status(msg);
	}
done:
	if (!ok && g->stop_event) { CloseHandle(g->stop_event); g->stop_event = NULL; }
	free(command); free(values); argv_clear(&args); return ok;
}
static void finish_child(void) {
	DWORD code = 0; WCHAR msg[128]; size_t i;
	(void)GetExitCodeProcess(g->process, &code);
	for (;;) {
		DWORD available = 0;
		if (!PeekNamedPipe(g->stdout_read, NULL, 0, NULL, &available, NULL) || available == 0) break;
		read_pipe(g->stdout_read, g->stdout_tail, &g->stdout_tail_len, &g->stdout_encoding);
	}
	for (;;) {
		DWORD available = 0;
		if (!PeekNamedPipe(g->stderr_read, NULL, 0, NULL, &available, NULL) || available == 0) break;
		read_pipe(g->stderr_read, g->stderr_tail, &g->stderr_tail_len, &g->stderr_encoding);
	}
	flush_pipe_tail(g->stdout_tail, &g->stdout_tail_len, g->stdout_encoding);
	flush_pipe_tail(g->stderr_tail, &g->stderr_tail_len, g->stderr_encoding);
	_snwprintf_s(msg, ARRAYSIZE(msg), _TRUNCATE, L"操作已结束，退出代码：%lu。", code); set_status(msg);
	CloseHandle(g->process); g->process = NULL;
	if (g->stdout_read) { CloseHandle(g->stdout_read); g->stdout_read = NULL; }
	if (g->stderr_read) { CloseHandle(g->stderr_read); g->stderr_read = NULL; }
	if (g->stop_event) { CloseHandle(g->stop_event); g->stop_event = NULL; }
	EnableWindow(g->stop_button, FALSE);
	for (i = 0; i < g->config->action_count; ++i) EnableWindow(g->actions[i], TRUE);
	EnableWindow(g->stop_button, FALSE);
	for (i = 0; i < g->config->field_count; ++i) {
		EnableWindow(g->fields[i].input, TRUE);
		EnableWindow(g->fields[i].browse, TRUE);
	}
	KillTimer(g->window, GUI_TIMER);
	if (g->close_when_done) DestroyWindow(g->window);
}
static void poll_child(void) {
	DWORD wait;
	read_pipe(g->stdout_read, g->stdout_tail, &g->stdout_tail_len, &g->stdout_encoding);
	read_pipe(g->stderr_read, g->stderr_tail, &g->stderr_tail_len, &g->stderr_encoding);
	wait = WaitForSingleObject(g->process, 0);
	if (wait == WAIT_OBJECT_0) { finish_child(); return; }
	if (wait == WAIT_FAILED) {
		WCHAR msg[128]; _snwprintf_s(msg, ARRAYSIZE(msg), _TRUNCATE,
			L"无法读取子进程状态（Win32 错误 %lu）；不会强制结束该进程。", GetLastError());
		set_status(msg);
		g->deadline = UINT64_MAX;
		return;
	}
	if (GetTickCount64() >= g->deadline) {
		set_status(g->active_action == FSF_GUI_ACTION_MOUNT ?
			L"挂载进程仍在运行；可请求正常停止。" : L"操作仍在运行，等待进程自行结束。");
		g->deadline = UINT64_MAX;
	}
}

static void layout(HWND window) {
	RECT rc; int width, y = 12, button_spacing, button_width; size_t i, rows, col_w, button_count;
	BOOL fallback_stop = TRUE;
	if (g == NULL || g->fields == NULL || g->status == NULL) return;
	GetClientRect(window, &rc); width = rc.right - rc.left;
	rows = (g->config->field_count + 1) / 2;
	col_w = (size_t)(width - px(window, 28)) / 2;
	for (i = 0; i < g->config->field_count; ++i) {
		GUI_FIELD *f = &g->fields[i];
		size_t col = i / rows, row = i % rows;
		int x = px(window, 14) + (int)(col * col_w);
		int fy = px(window, y) + (int)row * px(window, 62);
		int browse_w = (f->browse != NULL) ? px(window, 68) : 0;
		int input_w = (int)col_w;
		int input_h = px(window, 28);
		if (f->spec->kind == FSF_GUI_FIELD_ENUM) {
			size_t visible_choices = f->spec->choice_count > 8 ? 8 : f->spec->choice_count;
			if (visible_choices == 0) visible_choices = 1;
			input_h = px(window, 28 + (int)visible_choices * 24);
		}
		MoveWindow(f->label, x, fy, input_w, px(window, 24), TRUE);
		MoveWindow(f->input, x, fy + px(window, 25), input_w - browse_w - px(window, 4), input_h, TRUE);
		if (f->browse != NULL) MoveWindow(f->browse, x + input_w - browse_w, fy + px(window, 25), browse_w, px(window, 28), TRUE);
	}
	y += (int)rows * 62 + 8;
	button_count = g->config->action_count;
	for (i = 0; i < g->config->action_count; ++i)
		if (g->config->actions[i].action == FSF_GUI_ACTION_UNMOUNT) { fallback_stop = FALSE; break; }
	if (fallback_stop) ++button_count;
	button_spacing = button_count != 0 ? (width - px(window, 28)) / (int)button_count : px(window, 118);
	if (button_spacing < px(window, 88)) button_spacing = px(window, 88);
	button_width = button_spacing - px(window, 6);
	if (button_width > px(window, 130)) button_width = px(window, 130);
	for (i = 0; i < g->config->action_count; ++i)
		MoveWindow(g->actions[i], px(window, 14) + (int)i * button_spacing, px(window, y), button_width, px(window, 32), TRUE);
	if (g->stop_button && fallback_stop)
		MoveWindow(g->stop_button, px(window, 14) + (int)g->config->action_count * button_spacing,
			px(window, y), button_width, px(window, 32), TRUE);
	y += 40;
	MoveWindow(g->status, px(window, 14), px(window, y), width - px(window, 28), px(window, 24), TRUE); y += 28;
	MoveWindow(g->output, px(window, 14), px(window, y), width - px(window, 28), rc.bottom - px(window, y) - px(window, 14), TRUE);
}

static void browse_field(GUI_FIELD *f) {
	if (f->spec->kind == FSF_GUI_FIELD_FILE) {
		WCHAR file[MAX_PATH] = L"";
		OPENFILENAMEW ofn; memset(&ofn, 0, sizeof(ofn));
		ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g->window;
		ofn.lpstrFile = file; ofn.nMaxFile = ARRAYSIZE(file);
		ofn.lpstrFilter = f->spec->browse_filter ? f->spec->browse_filter : L"所有文件\0*.*\0\0";
		ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
		if (GetOpenFileNameW(&ofn)) SetWindowTextW(f->input, file);
	} else if (f->spec->kind == FSF_GUI_FIELD_DIRECTORY) {
		BROWSEINFOW bi; PIDLIST_ABSOLUTE pidl; WCHAR path[MAX_PATH];
		memset(&bi, 0, sizeof(bi)); bi.hwndOwner = g->window; bi.lpszTitle = L"选择文件夹";
		bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_VALIDATE;
		pidl = SHBrowseForFolderW(&bi);
		if (pidl != NULL) {
			if (SHGetPathFromIDListW(pidl, path)) SetWindowTextW(f->input, path);
			CoTaskMemFree((void *)pidl);
		}
	}
}

static BOOL create_controls(HWND hwnd) {
	size_t i;
	g->fields = (GUI_FIELD *)calloc(g->config->field_count, sizeof(*g->fields));
	g->actions = (HWND *)calloc(g->config->action_count, sizeof(*g->actions));
	if ((g->config->field_count && !g->fields) || (g->config->action_count && !g->actions)) return FALSE;
	for (i = 0; i < g->config->field_count; ++i) {
		GUI_FIELD *f = &g->fields[i]; const FSF_GUI_FIELD *d = &g->config->fields[i];
		DWORD input_style = WS_CHILD | WS_VISIBLE | WS_TABSTOP;
		f->spec = d; f->value = dup_w(d->default_value);
		f->label = CreateWindowExW(0, L"STATIC", d->label, WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hwnd, NULL, g_instance, NULL);
		if (d->kind == FSF_GUI_FIELD_BOOLEAN) {
			f->input = CreateWindowExW(0, L"BUTTON", L"启用", input_style | BS_AUTOCHECKBOX, 0, 0, 10, 10, hwnd,
				(HMENU)(UINT_PTR)(1000 + i), g_instance, NULL);
			if (d->default_value && (_wcsicmp(d->default_value, L"true") == 0 || _wcsicmp(d->default_value, L"1") == 0))
				SendMessageW(f->input, BM_SETCHECK, BST_CHECKED, 0);
		} else if (d->kind == FSF_GUI_FIELD_ENUM) {
			LRESULT selected = CB_ERR; size_t j;
			f->input = CreateWindowExW(0, L"COMBOBOX", L"", input_style | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 10, 220,
				hwnd, (HMENU)(UINT_PTR)(1000 + i), g_instance, NULL);
			for (j = 0; j < d->choice_count; ++j) {
				LRESULT ix = SendMessageW(f->input, CB_ADDSTRING, 0, (LPARAM)d->choices[j]);
				if (d->default_value && _wcsicmp(d->default_value, d->choices[j]) == 0) selected = ix;
			}
			if (selected == CB_ERR && d->choice_count) selected = 0;
			if (selected != CB_ERR) SendMessageW(f->input, CB_SETCURSEL, selected, 0);
		} else {
			f->input = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", d->default_value ? d->default_value : L"",
				input_style | ES_AUTOHSCROLL |
				(d->kind == FSF_GUI_FIELD_PASSWORD ? ES_PASSWORD : 0),
				0, 0, 10, 28, hwnd, (HMENU)(UINT_PTR)(1000 + i), g_instance, NULL);
		}
		if (d->kind == FSF_GUI_FIELD_FILE || d->kind == FSF_GUI_FIELD_DIRECTORY)
			f->browse = CreateWindowExW(0, L"BUTTON", L"浏览…", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
				0, 0, 10, 28, hwnd, (HMENU)(UINT_PTR)(3000 + i), g_instance, NULL);
		set_font(f->label); set_font(f->input); set_font(f->browse);
		if (!f->label || !f->input || !f->value) return FALSE;
	}
	for (i = 0; i < g->config->action_count; ++i) {
		g->actions[i] = CreateWindowExW(0, L"BUTTON", g->config->actions[i].label,
			WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 32, hwnd,
			(HMENU)(UINT_PTR)(2000 + i), g_instance, NULL);
		set_font(g->actions[i]); if (!g->actions[i]) return FALSE;
	}
	for (i = 0; i < g->config->action_count; ++i)
		if (g->config->actions[i].action == FSF_GUI_ACTION_UNMOUNT) g->stop_button = g->actions[i];
	if (g->stop_button == NULL)
		g->stop_button = CreateWindowExW(0, L"BUTTON", L"停止挂载", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
			0, 0, 10, 32, hwnd, (HMENU)4000, g_instance, NULL);
	g->status = CreateWindowExW(0, L"STATIC", L"就绪。", WS_CHILD | WS_VISIBLE, 0, 0, 10, 24, hwnd, (HMENU)5000, g_instance, NULL);
	g->output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL |
		ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 10, 10, hwnd, (HMENU)5001, g_instance, NULL);
	if (g->output != NULL) SendMessageW(g->output, EM_SETLIMITTEXT, GUI_CAPTURE_LIMIT + 1, 0);
	set_font(g->stop_button); set_font(g->status); set_font(g->output);
	EnableWindow(g->stop_button, FALSE);
	return g->stop_button && g->status && g->output;
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
	size_t i;
	switch (msg) {
	case WM_SIZE: layout(hwnd); return 0;
	case WM_DPICHANGED: {
		RECT *r = (RECT *)lp;
		SetWindowPos(hwnd, NULL, r->left, r->top, r->right-r->left, r->bottom-r->top, SWP_NOZORDER|SWP_NOACTIVATE);
		update_font(hwnd); layout(hwnd);
		return 0;
	}
	case WM_GETMINMAXINFO: {
		MINMAXINFO *m = (MINMAXINFO *)lp;
		m->ptMinTrackSize.x = px(hwnd, 600); m->ptMinTrackSize.y = px(hwnd, 500); return 0;
	}
	case WM_TIMER:
		if (wp == GUI_TIMER && g->process) poll_child();
		return 0;
	case WM_COMMAND:
		if (HIWORD(wp) == BN_CLICKED) {
			if ((HWND)lp == g->stop_button) {
				if (g->active_action == FSF_GUI_ACTION_MOUNT && g->stop_event &&
					confirm_action(FSF_GUI_ACTION_UNMOUNT)) {
					if (g->process && g->stop_event) {
						SetEvent(g->stop_event); set_status(L"已请求正常停止，等待挂载进程清理。");
					} else set_status(L"挂载进程已在确认期间结束。");
				}
				return 0;
			}
			for (i = 0; i < g->config->field_count; ++i)
				if ((HWND)lp == g->fields[i].browse) { browse_field(&g->fields[i]); return 0; }
			for (i = 0; i < g->config->action_count; ++i) if ((HWND)lp == g->actions[i]) {
				FSF_GUI_ACTION a = g->config->actions[i].action;
				if (a == FSF_GUI_ACTION_UNMOUNT) {
					if (!g->process || g->active_action != FSF_GUI_ACTION_MOUNT || !g->stop_event) {
						set_status(L"当前窗口没有运行中的挂载。");
					} else if (confirm_action(FSF_GUI_ACTION_UNMOUNT)) {
						if (g->process && g->stop_event) {
							SetEvent(g->stop_event); set_status(L"已请求正常停止，等待挂载进程清理。");
						} else set_status(L"挂载进程已在确认期间结束。");
					}
				} else if (confirm_action(a)) (void)start_child(a);
				return 0;
			}
		}
		break;
	case WM_CLOSE:
		if (g->process) {
			if (g->active_action == FSF_GUI_ACTION_MOUNT && g->stop_event) {
				if (!confirm_action(FSF_GUI_ACTION_UNMOUNT)) return 0;
				if (g->process == NULL) { DestroyWindow(hwnd); return 0; }
				g->close_when_done = TRUE;
				if (g->stop_event != NULL) SetEvent(g->stop_event);
				set_status(L"正在正常停止挂载，清理完成后关闭窗口。");
			} else set_status(L"操作完成后关闭窗口；子进程不会被强制结束。");
			g->close_when_done = TRUE;
			return 0;
		}
		DestroyWindow(hwnd); return 0;
	case WM_DESTROY:
		KillTimer(hwnd, GUI_TIMER);
		if (g->process && g->active_action == FSF_GUI_ACTION_MOUNT && g->stop_event) SetEvent(g->stop_event);
		if (g->process) { CloseHandle(g->process); g->process = NULL; }
		if (g->stdout_read) { CloseHandle(g->stdout_read); g->stdout_read = NULL; }
		if (g->stderr_read) { CloseHandle(g->stderr_read); g->stderr_read = NULL; }
		if (g->stop_event) { CloseHandle(g->stop_event); g->stop_event = NULL; }
		g->window = NULL;
		PostQuitMessage(0); return 0;
	}
	return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL restore_internal_args(int argc, WCHAR **argv) {
	FSF_GUI_ACTION action; int i; size_t j;
	if (argc < 4 || _wcsicmp(argv[1], L"--gui") != 0 ||
		_wcsicmp(argv[2], L"--fsf-gui-action") != 0 ||
		!parse_action(argv[3], &action) || action == FSF_GUI_ACTION_UNMOUNT)
		return FALSE;
	for (j = 0; j < g->config->action_count; ++j)
		if (g->config->actions[j].action == action) break;
	if (j == g->config->action_count) return FALSE;
	g->elevated_action = action;
	g->elevated_action_pending = TRUE;
	for (i = 4; i < argc; ++i) {
		if (_wcsicmp(argv[i], L"--fsf-gui-field") != 0 || i + 2 >= argc) return FALSE;
		for (j = 0; j < g->config->field_count; ++j)
			if (_wcsicmp(argv[i + 1], g->fields[j].spec->id) == 0) break;
		if (j == g->config->field_count) return FALSE;
		if (g->fields[j].spec->kind == FSF_GUI_FIELD_PASSWORD) return FALSE;
		if (g->fields[j].spec->kind == FSF_GUI_FIELD_BOOLEAN &&
			_wcsicmp(argv[i + 2], L"true") != 0 && _wcsicmp(argv[i + 2], L"false") != 0 &&
			wcscmp(argv[i + 2], L"1") != 0 && wcscmp(argv[i + 2], L"0") != 0)
			return FALSE;
		if (g->fields[j].spec->kind == FSF_GUI_FIELD_ENUM) {
			size_t k;
			for (k = 0; k < g->fields[j].spec->choice_count; ++k)
				if (_wcsicmp(argv[i + 2], g->fields[j].spec->choices[k]) == 0) break;
			if (k == g->fields[j].spec->choice_count) return FALSE;
		}
		free(g->fields[j].value); g->fields[j].value = dup_w(argv[i + 2]);
		if (g->fields[j].value == NULL) return FALSE;
		i += 2;
	}
	return TRUE;
}

int fsf_gui_run(const FSF_GUI_CONFIG *config) {
	WNDCLASSEXW wc; RECT work; MSG msg; WCHAR title[256];
	int argc = 0, result = 1; WCHAR **argv = NULL;
	HRESULT com_hr; BOOL com_ready = FALSE; DWORD style = WS_OVERLAPPEDWINDOW;
	UINT initial_dpi; int width = 1000, height = 620, x = CW_USEDEFAULT, y = CW_USEDEFAULT;
	if (config == NULL || config->struct_size < sizeof(*config) ||
		config->abi_version != FSF_GUI_ABI_VERSION || config->build_argv == NULL ||
		(config->field_count && config->fields == NULL) ||
		(config->action_count && config->actions == NULL) || config->action_count == 0)
		return 1;
	g = (GUI_STATE *)calloc(1, sizeof(*g));
	if (g == NULL) return 1;
	g->config = config;
	(void)SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	FreeConsole();
	com_hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	com_ready = SUCCEEDED(com_hr);
	g_instance = GetModuleHandleW(NULL);
	g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
	memset(&wc, 0, sizeof(wc)); wc.cbSize = sizeof(wc);
	wc.lpfnWndProc = window_proc; wc.hInstance = g_instance;
	wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
	wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
	wc.lpszClassName = GUI_CLASS;
	if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) goto cleanup;
	_snwprintf_s(title, ARRAYSIZE(title), _TRUNCATE, L"%ls",
		config->title != NULL ? config->title : L"文件系统配置");
	initial_dpi = GetDpiForSystem(); if (initial_dpi == 0) initial_dpi = 96;
	width = MulDiv(width, (int)initial_dpi, 96);
	height = MulDiv(height, (int)initial_dpi, 96);
	if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0)) {
		int max_width = (work.right - work.left) - 32;
		int max_height = (work.bottom - work.top) - 48;
		if (max_width < 600) max_width = 600;
		if (max_height < 440) max_height = 440;
		if (width > max_width) width = max_width;
		if (height > max_height) height = max_height;
		x = work.left + ((work.right - work.left) - width) / 2;
		y = work.top + ((work.bottom - work.top) - height) / 2;
	}
	if (width < MulDiv(600, (int)initial_dpi, 96) && width > MulDiv(450, (int)initial_dpi, 96))
		width = MulDiv(600, (int)initial_dpi, 96);
	if (height < MulDiv(500, (int)initial_dpi, 96) && height > MulDiv(400, (int)initial_dpi, 96))
		height = MulDiv(500, (int)initial_dpi, 96);
	g->window = CreateWindowExW(0, GUI_CLASS, title, style, x, y, width, height,
		NULL, NULL, g_instance, NULL);
	if (g->window == NULL || !create_controls(g->window)) goto cleanup;
	update_font(g->window);
	layout(g->window);
	ShowWindow(g->window, SW_SHOW); UpdateWindow(g->window);
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv != NULL && argc > 1 && _wcsicmp(argv[1], L"--gui") == 0 &&
		restore_internal_args(argc, argv)) {
		for (size_t i = 0; i < config->field_count; ++i) {
			GUI_FIELD *f = &g->fields[i];
			if (f->spec->kind == FSF_GUI_FIELD_BOOLEAN)
				SendMessageW(f->input, BM_SETCHECK,
					(_wcsicmp(f->value, L"true") == 0 || _wcsicmp(f->value, L"1") == 0) ? BST_CHECKED : BST_UNCHECKED, 0);
			else if (f->spec->kind == FSF_GUI_FIELD_ENUM) {
				for (size_t j = 0; j < f->spec->choice_count; ++j)
					if (_wcsicmp(f->value, f->spec->choices[j]) == 0)
						SendMessageW(f->input, CB_SETCURSEL, j, 0);
			} else SetWindowTextW(f->input, f->value);
		}
		PostMessageW(g->window, WM_APP + 1, 0, 0);
	} else if (argv != NULL && argc > 1 && _wcsicmp(argv[1], L"--gui") == 0 &&
		argc > 2 && _wcsicmp(argv[2], L"--fsf-gui-action") == 0) {
		set_status(L"管理员启动参数无效；请从主窗口重新执行服务操作。");
	}
	if (argv != NULL) { LocalFree(argv); argv = NULL; }
	result = 0;
	for (;;) {
		BOOL got = GetMessageW(&msg, NULL, 0, 0);
		if (got <= 0) {
			if (got == 0) result = (int)msg.wParam;
			else result = 1;
			break;
		}
		if (msg.message == WM_APP + 1) {
			if (g->elevated_action_pending) {
				g->elevated_action_pending = FALSE;
				(void)start_child(g->elevated_action);
			}
			continue;
		}
		if (!IsDialogMessageW(g->window, &msg)) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
	}
cleanup:
	if (argv != NULL) LocalFree(argv);
	if (g != NULL && g->window != NULL && IsWindow(g->window)) DestroyWindow(g->window);
	if (com_ready) CoUninitialize();
	if (g != NULL) {
		if (g->fields != NULL) {
			for (size_t i = 0; i < config->field_count; ++i) {
				if (g->fields[i].spec != NULL &&
					g->fields[i].spec->kind == FSF_GUI_FIELD_PASSWORD)
					secure_free_w(g->fields[i].value);
				else
					free(g->fields[i].value);
			}
			free(g->fields);
		}
		free(g->actions); free(g->capture); free(g);
		g = NULL;
	}
	if (g_owns_font && g_font != NULL) DeleteObject(g_font);
	g_font = NULL; g_owns_font = FALSE;
	return result;
}
