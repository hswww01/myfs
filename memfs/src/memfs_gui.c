#include "memfs_gui.h"
#include "memfs_cli.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const PCWSTR g_encryption_choices[] = {
	L"关闭",
	L"随机临时密钥",
	L"环境变量密钥",
};

static const PCWSTR g_stats_choices[] = {
	L"关闭",
	L"文本",
	L"JSON",
};

static const FSF_GUI_FIELD g_fields[] = {
	{ L"mount", L"挂载点", FSF_GUI_FIELD_TEXT, L"W:", NULL, 0, NULL, FALSE },
	{ L"size", L"容量 (auto/字节/K/M/G)", FSF_GUI_FIELD_TEXT, L"auto", NULL, 0, NULL, FALSE },
	{ L"label", L"卷标", FSF_GUI_FIELD_TEXT, L"MEMFS", NULL, 0, NULL, FALSE },
	{ L"threads", L"线程数 (0=自动, 2–64)", FSF_GUI_FIELD_TEXT, L"0", NULL, 0, NULL, FALSE },
	{ L"compression", L"启用压缩", FSF_GUI_FIELD_BOOLEAN, L"false", NULL, 0, NULL, FALSE },
	{ L"compression_level", L"压缩级别 (1–22)", FSF_GUI_FIELD_TEXT, L"1", NULL, 0, NULL, FALSE },
	{ L"encryption", L"加密", FSF_GUI_FIELD_ENUM, L"关闭", g_encryption_choices, 3, NULL, FALSE },
	{ L"key_environment", L"密钥环境变量名", FSF_GUI_FIELD_TEXT, L"MEMFS_KEY", NULL, 0, NULL, FALSE },
	{ L"debug", L"WinFsp 调试日志", FSF_GUI_FIELD_BOOLEAN, L"false", NULL, 0, NULL, FALSE },
	{ L"statistics", L"运行统计", FSF_GUI_FIELD_ENUM, L"关闭", g_stats_choices, 3, NULL, FALSE },
	{ L"service_name", L"服务名", FSF_GUI_FIELD_TEXT, L"MemfsC", NULL, 0, NULL, FALSE },
	{ L"service_log", L"服务日志 (空=默认)", FSF_GUI_FIELD_TEXT, L"", NULL, 0, NULL, FALSE },
};

static const FSF_GUI_ACTION_DESC g_actions[] = {
	{ FSF_GUI_ACTION_MOUNT, L"挂载" },
	{ FSF_GUI_ACTION_UNMOUNT, L"卸载临时挂载" },
	{ FSF_GUI_ACTION_INSTALL, L"安装并启动服务" },
	{ FSF_GUI_ACTION_UNINSTALL, L"卸载服务" },
};

static const FSF_GUI_CONFIG g_config = {
	.struct_size = sizeof(FSF_GUI_CONFIG),
	.abi_version = FSF_GUI_ABI_VERSION,
	.title = L"Memfs 配置",
	.unmount_warning = L"停止或卸载后，内存盘中的数据会丢失。",
	.fields = g_fields,
	.field_count = _countof(g_fields),
	.actions = g_actions,
	.action_count = _countof(g_actions),
	.action_timeout_ms = 120000u,
	.context = NULL,
	.build_argv = memfs_gui_build_argv,
};

static PCWSTR
memfs_gui_value(const FSF_GUI_VALUE *values, size_t value_count, PCWSTR id)
{
	size_t index;
	if (values == NULL || id == NULL)
		return NULL;
	for (index = 0; index < value_count; ++index) {
		if (values[index].id != NULL && _wcsicmp(values[index].id, id) == 0)
			return values[index].value;
	}
	return NULL;
}

static BOOL
memfs_gui_is_true(PCWSTR value)
{
	return value != NULL && _wcsicmp(value, L"true") == 0;
}

static BOOL
memfs_gui_boolean_valid(PCWSTR value)
{
	return value != NULL &&
		(_wcsicmp(value, L"true") == 0 || _wcsicmp(value, L"false") == 0);
}

static BOOL
memfs_gui_service_name_valid(PCWSTR name)
{
	const WCHAR *cursor;
	size_t length;
	if (name == NULL)
		return FALSE;
	length = wcslen(name);
	if (length == 0 || length > 256)
		return FALSE;
	for (cursor = name; *cursor != L'\0'; ++cursor) {
		if (!((*cursor >= L'a' && *cursor <= L'z') ||
			(*cursor >= L'A' && *cursor <= L'Z') ||
			(*cursor >= L'0' && *cursor <= L'9') || *cursor == L'_' ||
			*cursor == L'-' || *cursor == L'.'))
			return FALSE;
	}
	return TRUE;
}

static BOOL
memfs_gui_append(FSF_GUI_ARGV *argv, PCWSTR token)
{
	return token != NULL && fsf_gui_argv_append(argv, token);
}

static BOOL
memfs_gui_append_pair(FSF_GUI_ARGV *argv, PCWSTR option, PCWSTR value)
{
	return memfs_gui_append(argv, option) && memfs_gui_append(argv, value);
}

static BOOL
memfs_gui_append_mount_options(
	const FSF_GUI_VALUE *values,
	size_t value_count,
	BOOL installing,
	PCWSTR stop_event_name,
	FSF_GUI_ARGV *argv)
{
	PCWSTR mount = memfs_gui_value(values, value_count, L"mount");
	PCWSTR size = memfs_gui_value(values, value_count, L"size");
	PCWSTR label = memfs_gui_value(values, value_count, L"label");
	PCWSTR threads = memfs_gui_value(values, value_count, L"threads");
	PCWSTR encryption = memfs_gui_value(values, value_count, L"encryption");
	PCWSTR key_environment = memfs_gui_value(values, value_count, L"key_environment");
	PCWSTR compression_level = memfs_gui_value(values, value_count, L"compression_level");
	PCWSTR statistics = memfs_gui_value(values, value_count, L"statistics");
	PCWSTR service_name = memfs_gui_value(values, value_count, L"service_name");
	PCWSTR service_log = memfs_gui_value(values, value_count, L"service_log");
	PCWSTR compression_value = memfs_gui_value(values, value_count, L"compression");
	PCWSTR debug_value = memfs_gui_value(values, value_count, L"debug");
	BOOL compression;
	uint64_t parsed_capacity;
	uint32_t parsed_count;
	bool capacity_auto;
	if (mount == NULL || mount[0] == L'\0' || size == NULL || size[0] == L'\0' ||
		label == NULL || label[0] == L'\0' || threads == NULL ||
		!memfs_gui_boolean_valid(compression_value) ||
		!memfs_gui_boolean_valid(debug_value))
		return FALSE;
	if (!memfs_cli_parse_size(size, &parsed_capacity, &capacity_auto) ||
		!memfs_cli_parse_u32(threads, &parsed_count) ||
		!memfs_cli_thread_count_valid(parsed_count))
		return FALSE;
	compression = memfs_gui_is_true(compression_value);
	if (compression) {
		if (compression_level == NULL ||
			!memfs_cli_parse_u32(compression_level, &parsed_count) ||
			parsed_count < 1 || parsed_count > 22)
			return FALSE;
	}
	(void)parsed_capacity;
	(void)capacity_auto;
	if (!memfs_gui_append_pair(argv, L"--mount", mount) ||
		!memfs_gui_append_pair(argv, L"--size", size) ||
		!memfs_gui_append_pair(argv, L"--label", label) ||
		!memfs_gui_append_pair(argv, L"--threads", threads))
		return FALSE;
	if (compression) {
		if (compression_level == NULL || compression_level[0] == L'\0')
			return FALSE;
		if (_wcsicmp(compression_level, L"1") == 0) {
			if (!memfs_gui_append(argv, L"--compress"))
				return FALSE;
		} else if (!memfs_gui_append_pair(argv, L"--compression-level", compression_level)) {
			return FALSE;
		}
	}
	if (encryption == NULL)
		return FALSE;
	if (_wcsicmp(encryption, L"随机临时密钥") == 0) {
		if (!memfs_gui_append(argv, L"--encrypt"))
			return FALSE;
	} else if (_wcsicmp(encryption, L"环境变量密钥") == 0) {
		if (installing || key_environment == NULL || key_environment[0] == L'\0' ||
			!memfs_gui_append_pair(argv, L"--key-env", key_environment))
			return FALSE;
	} else if (_wcsicmp(encryption, L"关闭") != 0) {
		return FALSE;
	}
	if (memfs_gui_is_true(debug_value) && !memfs_gui_append(argv, L"--debug"))
		return FALSE;
	if (statistics == NULL)
		return FALSE;
	if (!installing && _wcsicmp(statistics, L"文本") == 0) {
		if (!memfs_gui_append(argv, L"--stats"))
			return FALSE;
	} else if (!installing && _wcsicmp(statistics, L"JSON") == 0) {
		if (!memfs_gui_append(argv, L"--stats-json"))
			return FALSE;
	} else if (_wcsicmp(statistics, L"关闭") != 0 &&
		_wcsicmp(statistics, L"JSON") != 0 &&
		_wcsicmp(statistics, L"文本") != 0) {
		return FALSE;
	}
	if (installing) {
		if (!memfs_gui_service_name_valid(service_name) ||
			!memfs_gui_append_pair(argv, L"--service-name", service_name))
			return FALSE;
		if (service_log != NULL && service_log[0] != L'\0' &&
			!memfs_gui_append_pair(argv, L"--log-file", service_log))
			return FALSE;
		if (!memfs_gui_append(argv, L"--install"))
			return FALSE;
	} else {
		if (stop_event_name == NULL || stop_event_name[0] == L'\0' ||
			!memfs_gui_append_pair(argv, L"--stop-event", stop_event_name))
			return FALSE;
	}
	return TRUE;
}

BOOL
memfs_gui_build_argv(
	void *context,
	FSF_GUI_ACTION action,
	const FSF_GUI_VALUE *values,
	size_t value_count,
	PCWSTR stop_event_name,
	FSF_GUI_ARGV *argv)
{
	PCWSTR service_name;
	(void)context;
	if (argv == NULL)
		return FALSE;
	switch (action) {
	case FSF_GUI_ACTION_MOUNT:
		return memfs_gui_append_mount_options(values, value_count, FALSE,
			stop_event_name, argv);
	case FSF_GUI_ACTION_INSTALL:
		return memfs_gui_append_mount_options(values, value_count, TRUE,
			NULL, argv);
	case FSF_GUI_ACTION_UNINSTALL:
		service_name = memfs_gui_value(values, value_count, L"service_name");
		return memfs_gui_service_name_valid(service_name) &&
			memfs_gui_append(argv, L"--uninstall") &&
			memfs_gui_append_pair(argv, L"--service-name", service_name);
	default:
		return FALSE;
	}
}

int
memfs_gui_run(void)
{
	return fsf_gui_run(&g_config);
}
