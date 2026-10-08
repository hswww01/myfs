#ifndef FS_FRONTEND_GUI_H
#define FS_FRONTEND_GUI_H

#include <windows.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FSF_GUI_ABI_VERSION 1u

typedef enum FSF_GUI_FIELD_KIND {
	FSF_GUI_FIELD_TEXT = 1,
	FSF_GUI_FIELD_BOOLEAN = 2,
	FSF_GUI_FIELD_ENUM = 3,
	FSF_GUI_FIELD_FILE = 4,
	FSF_GUI_FIELD_DIRECTORY = 5,
	FSF_GUI_FIELD_PASSWORD = 6
} FSF_GUI_FIELD_KIND;

typedef enum FSF_GUI_ACTION {
	FSF_GUI_ACTION_MOUNT = 1,
	FSF_GUI_ACTION_UNMOUNT = 2,
	FSF_GUI_ACTION_INSTALL = 3,
	FSF_GUI_ACTION_UNINSTALL = 4,
	FSF_GUI_ACTION_PROBE = 5
} FSF_GUI_ACTION;

typedef struct FSF_GUI_FIELD {
	PCWSTR id;
	PCWSTR label;
	FSF_GUI_FIELD_KIND kind;
	PCWSTR default_value;
	const PCWSTR *choices;
	size_t choice_count;
	PCWSTR browse_filter;
	BOOL required;
} FSF_GUI_FIELD;

typedef struct FSF_GUI_VALUE {
	PCWSTR id;
	PCWSTR value;
} FSF_GUI_VALUE;

typedef struct FSF_GUI_ARGV FSF_GUI_ARGV;

/* The builder copies each token and is owned by the GUI until process start. */
BOOL fsf_gui_argv_append(FSF_GUI_ARGV *argv, PCWSTR token);
FSF_GUI_ARGV *fsf_gui_argv_create(void);
void fsf_gui_argv_destroy(FSF_GUI_ARGV *argv);
/* Copies a bounded secret blob for child stdin and wipes it on argv destruction. */
BOOL fsf_gui_argv_set_stdin(FSF_GUI_ARGV *argv, const void *bytes, size_t length);
size_t fsf_gui_argv_count(const FSF_GUI_ARGV *argv);
PCWSTR fsf_gui_argv_get(const FSF_GUI_ARGV *argv, size_t index);
BOOL fsf_gui_argv_build_command_line(PCWSTR executable,
	const FSF_GUI_ARGV *argv, PWSTR *command_line_out);
void fsf_gui_free(PVOID allocation);

typedef BOOL (*FSF_GUI_BUILD_ARGV_FN)(
	void *context,
	FSF_GUI_ACTION action,
	const FSF_GUI_VALUE *values,
	size_t value_count,
	PCWSTR stop_event_name,
	FSF_GUI_ARGV *argv);

typedef struct FSF_GUI_ACTION_DESC {
	FSF_GUI_ACTION action;
	PCWSTR label;
} FSF_GUI_ACTION_DESC;

typedef struct FSF_GUI_CONFIG {
	uint32_t struct_size;
	uint32_t abi_version;
	PCWSTR title;
	/* Optional product-specific data-loss warning shown for GUI-owned unmount. */
	PCWSTR unmount_warning;
	const FSF_GUI_FIELD *fields;
	size_t field_count;
	const FSF_GUI_ACTION_DESC *actions;
	size_t action_count;
	uint32_t action_timeout_ms;
	void *context;
	FSF_GUI_BUILD_ARGV_FN build_argv;
} FSF_GUI_CONFIG;

/* Run the native configuration window. Also consumes internal --fsf-gui-* relaunch arguments. */
int fsf_gui_run(const FSF_GUI_CONFIG *config);

#ifdef __cplusplus
}
#endif

#endif /* FS_FRONTEND_GUI_H */
