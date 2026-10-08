#ifndef MEMFS_GUI_H
#define MEMFS_GUI_H

#include "fs_frontend_gui.h"

#ifdef __cplusplus
extern "C" {
#endif

int memfs_gui_run(void);

/* Kept visible so the schema-to-CLI contract can be tested without a window. */
BOOL memfs_gui_build_argv(
	void *context,
	FSF_GUI_ACTION action,
	const FSF_GUI_VALUE *values,
	size_t value_count,
	PCWSTR stop_event_name,
	FSF_GUI_ARGV *argv);

#ifdef __cplusplus
}
#endif

#endif /* MEMFS_GUI_H */
