#include "memfs_gui.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct FSF_GUI_ARGV {
	PCWSTR tokens[64];
	size_t count;
};

BOOL fsf_gui_argv_append(FSF_GUI_ARGV *argv, PCWSTR token)
{
	if (argv == NULL || token == NULL || argv->count >= _countof(argv->tokens))
		return FALSE;
	argv->tokens[argv->count++] = _wcsdup(token);
	return argv->tokens[argv->count - 1] != NULL;
}

int fsf_gui_run(const FSF_GUI_CONFIG *config)
{
	(void)config;
	return 97;
}

static void clear_argv(FSF_GUI_ARGV *argv)
{
	size_t index;
	for (index = 0; index < argv->count; ++index)
		free((void *)argv->tokens[index]);
	memset(argv, 0, sizeof(*argv));
}

static BOOL has_pair(const FSF_GUI_ARGV *argv, PCWSTR option, PCWSTR value)
{
	size_t index;
	for (index = 0; index + 1 < argv->count; ++index) {
		if (_wcsicmp(argv->tokens[index], option) == 0 &&
			_wcsicmp(argv->tokens[index + 1], value) == 0)
			return TRUE;
	}
	return FALSE;
}

static BOOL has_token(const FSF_GUI_ARGV *argv, PCWSTR token)
{
	size_t index;
	for (index = 0; index < argv->count; ++index)
		if (_wcsicmp(argv->tokens[index], token) == 0)
			return TRUE;
	return FALSE;
}

int wmain(void)
{
	FSF_GUI_ARGV argv = { 0 };
	FSF_GUI_VALUE mount_values[] = {
		{ L"mount", L"Q:" },
		{ L"size", L"512M" },
		{ L"label", L"my volume" },
		{ L"threads", L"4" },
		{ L"compression", L"true" },
		{ L"compression_level", L"7" },
		{ L"encryption", L"环境变量密钥" },
		{ L"key_environment", L"MEMFS_TEST_KEY_NAME" },
		{ L"debug", L"true" },
		{ L"statistics", L"JSON" },
		{ L"service_name", L"MemfsGuiTest" },
		{ L"service_log", L"" },
	};
	FSF_GUI_VALUE install_values[] = {
		{ L"mount", L"Q:" },
		{ L"size", L"auto" },
		{ L"label", L"MEMFS" },
		{ L"threads", L"0" },
		{ L"compression", L"false" },
		{ L"compression_level", L"1" },
		{ L"encryption", L"随机临时密钥" },
		{ L"key_environment", L"MEMFS_TEST_KEY_NAME" },
		{ L"debug", L"false" },
		{ L"statistics", L"文本" },
		{ L"service_name", L"MemfsGuiTest" },
		{ L"service_log", L"" },
	};
	FSF_GUI_VALUE uninstall_values[] = {
		{ L"service_name", L"MemfsGuiTest" },
		{ L"mount", L"" },
		{ L"size", L"nonsense" },
	};
	FSF_GUI_VALUE invalid_encryption[] = {
		{ L"mount", L"Q:" }, { L"size", L"auto" },
		{ L"label", L"MEMFS" }, { L"threads", L"0" },
		{ L"encryption", L"unsupported" },
		{ L"compression", L"false" }, { L"compression_level", L"1" },
		{ L"debug", L"false" }, { L"statistics", L"关闭" },
	};
	FSF_GUI_VALUE invalid_install[] = {
		{ L"mount", L"Q:" }, { L"size", L"not-a-size" },
		{ L"label", L"MEMFS" }, { L"threads", L"0" },
		{ L"compression", L"false" }, { L"compression_level", L"1" },
		{ L"encryption", L"关闭" }, { L"debug", L"false" },
		{ L"statistics", L"关闭" }, { L"service_name", L"bad/name" },
	};

	if (!memfs_gui_build_argv(NULL, FSF_GUI_ACTION_MOUNT, mount_values,
		_countof(mount_values), L"Local\\FSF-GUI-test", &argv) ||
		!has_pair(&argv, L"--mount", L"Q:") ||
		!has_pair(&argv, L"--size", L"512M") ||
		!has_pair(&argv, L"--label", L"my volume") ||
		!has_pair(&argv, L"--threads", L"4") ||
		!has_pair(&argv, L"--compression-level", L"7") ||
		!has_pair(&argv, L"--key-env", L"MEMFS_TEST_KEY_NAME") ||
		!has_pair(&argv, L"--stop-event", L"Local\\FSF-GUI-test") ||
		!has_token(&argv, L"--debug") || !has_token(&argv, L"--stats-json") ||
		has_token(&argv, L"MEMFS_TEST_KEY_VALUE")) {
		fwprintf(stderr, L"mount action argv contract failed\n");
		clear_argv(&argv);
		return 1;
	}
	clear_argv(&argv);

	if (!memfs_gui_build_argv(NULL, FSF_GUI_ACTION_INSTALL, install_values,
		_countof(install_values), L"", &argv) ||
		!has_token(&argv, L"--install") || !has_token(&argv, L"--encrypt") ||
		!has_pair(&argv, L"--service-name", L"MemfsGuiTest") ||
		has_token(&argv, L"--stats") || has_token(&argv, L"--stats-json") ||
		has_token(&argv, L"--stop-event")) {
		fwprintf(stderr, L"install action argv contract failed\n");
		clear_argv(&argv);
		return 2;
	}
	clear_argv(&argv);

	if (memfs_gui_build_argv(NULL, FSF_GUI_ACTION_INSTALL, mount_values,
		_countof(mount_values), L"", &argv)) {
		fwprintf(stderr, L"encrypted environment-key install was not rejected\n");
		clear_argv(&argv);
		return 3;
	}
	clear_argv(&argv);

	if (!memfs_gui_build_argv(NULL, FSF_GUI_ACTION_UNINSTALL, uninstall_values,
		_countof(uninstall_values), L"", &argv) || argv.count != 3 ||
		!has_token(&argv, L"--uninstall") ||
		!has_pair(&argv, L"--service-name", L"MemfsGuiTest") ||
		has_token(&argv, L"--mount") || has_token(&argv, L"--size")) {
		fwprintf(stderr, L"uninstall action should require only service name\n");
		clear_argv(&argv);
		return 4;
	}
	clear_argv(&argv);

	if (memfs_gui_build_argv(NULL, FSF_GUI_ACTION_MOUNT, invalid_encryption,
		_countof(invalid_encryption), L"Local\\FSF-GUI-test", &argv)) {
		fwprintf(stderr, L"unknown encryption choice was accepted\n");
		clear_argv(&argv);
		return 5;
	}
	clear_argv(&argv);
	if (memfs_gui_build_argv(NULL, FSF_GUI_ACTION_INSTALL, invalid_install,
		_countof(invalid_install), L"", &argv)) {
		fwprintf(stderr, L"invalid install settings passed validation\n");
		clear_argv(&argv);
		return 6;
	}
	clear_argv(&argv);
	return 0;
}
