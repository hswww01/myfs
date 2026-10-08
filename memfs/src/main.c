#include <Windows.h>
#include <sddl.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "memfs_winfsp.h"
#include "memfs_cli.h"
#include "memfs_driver.h"
#include "memfs_gui.h"

#define MEMFS_SERVICE_NAME L"MemfsC"
#define MEMFS_SERVICE_DEFAULT_START_TIMEOUT_MS 120000u
#define MEMFS_SERVICE_STOP_TIMEOUT_MS 90000u
#define MEMFS_SERVICE_ARGUMENT_CAPACITY 32768u

typedef struct MemfsRunConfig {
    const wchar_t* mount_point;
    const wchar_t* volume_label;
    const wchar_t* stop_event_name;
    const wchar_t* service_name;
    const wchar_t* log_file;
    const wchar_t* authorized_user_sid;
    uint64_t capacity;
    bool capacity_auto;
    uint32_t thread_count;
    uint32_t compression_level;
    bool compression_enabled;
    bool encryption_enabled;
    bool have_fixed_key;
    bool debug;
    bool service_mode;
    bool install_service;
    bool uninstall_service;
    bool service_name_set;
    bool uninstall_private_driver;
    bool stats_enabled;
    bool stats_json;
    uint8_t encryption_key[MEMFS_ENCRYPTION_KEY_SIZE];
} MemfsRunConfig;

static HANDLE g_stop_event;
static MemfsRunConfig g_config;

static BOOL WINAPI console_handler(DWORD control_type) {
    switch (control_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (g_stop_event)
            SetEvent(g_stop_event);
        return TRUE;
    default:
        return FALSE;
    }
}

static void print_usage(const wchar_t* exe) {
    fwprintf(stderr,
             L"Usage: %s [--gui]  (no arguments opens the configuration window)\n"
             L"       %s --mount M: [options]\n"
             L"       %s --install --mount M: [options]\n"
             L"       %s --uninstall [--service-name name]\n"
             L"       %s --service --mount M: [options]\n"
             L"\n"
             L"Options:\n"
             L"  --mount <path>          Drive letter or directory mount point.\n"
             L"  --size <bytes|auto>     Capacity 1..INT64_MAX; supports K/M/G suffix. Default: auto.\n"
             L"  --label <name>          Volume label. Default: MEMFS.\n"
             L"  --threads <n>           Dispatcher threads: 0=automatic, otherwise 2..64.\n"
             L"  --stop-event <name>     Optional named event for graceful console shutdown/automation.\n"
             L"  --compress              Enable per-page Zstd compression (level 1).\n"
             L"  --compression-level <n> Enable compression with level 1..22.\n"
             L"  --encrypt               Enable authenticated encryption (hardware AES-256-GCM, else XChaCha20-Poly1305).\n"
             L"  --key-hex <64hex>       Enable encryption with a fixed 256-bit key.\n"
             L"  --key-env <name>        Read the 64-hex encryption key from an env variable.\n"
             L"  --debug                 Enable all WinFsp debug logging.\n"
             L"  --service               Run under the Windows Service Control Manager.\n"
             L"  --service-name <name>   Service name. Default: MemfsC.\n"
             L"  --log-file <path>       Absolute protected service log path.\n"
             L"  --install               Install an automatic LocalSystem service and start it.\n"
             L"  --uninstall             Stop and remove only the named service.\n"
             L"  --uninstall-private-driver  Remove only MemfsC private WinFsp driver files/service.\n"
             L"  --stats                 Print human-readable runtime stats at mount/stop.\n"
             L"  --stats-json            Print machine-readable JSON stats at mount/stop.\n"
             L"  --gui                   Open the native configuration window.\n"
             L"  --help                  Show this help.\n"
             L"\n"
             L"Service install/uninstall examples (run from an elevated shell):\n"
             L"  %s --install --mount M: --size auto\n"
             L"  %s --uninstall\n",
             exe, exe, exe, exe, exe, exe, exe);
}

static int parse_config(int argc, wchar_t** argv, MemfsRunConfig* config) {
    int i;

    memset(config, 0, sizeof(*config));
    config->volume_label = L"MEMFS";
    config->service_name = MEMFS_SERVICE_NAME;
    config->capacity_auto = true;
    config->compression_level = 1;

    for (i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"--mount") == 0 && i + 1 < argc) {
            config->mount_point = argv[++i];
        } else if (_wcsicmp(argv[i], L"--size") == 0 && i + 1 < argc) {
            if (!memfs_cli_parse_size(argv[++i], &config->capacity, &config->capacity_auto)) {
                fwprintf(stderr, L"Invalid --size value.\n");
                return 2;
            }
        } else if (_wcsicmp(argv[i], L"--auto-size") == 0) {
            config->capacity = 0;
            config->capacity_auto = true;
        } else if (_wcsicmp(argv[i], L"--label") == 0 && i + 1 < argc) {
            config->volume_label = argv[++i];
        } else if (_wcsicmp(argv[i], L"--threads") == 0 && i + 1 < argc) {
            if (!memfs_cli_parse_u32(argv[++i], &config->thread_count) ||
                !memfs_cli_thread_count_valid(config->thread_count)) {
                fwprintf(stderr,
                         L"Invalid --threads value; use 0 (automatic) or 2..%u.\n",
                         MEMFS_CLI_MAX_DISPATCHER_THREADS);
                return 2;
            }
        } else if (_wcsicmp(argv[i], L"--stop-event") == 0 && i + 1 < argc) {
            config->stop_event_name = argv[++i];
        } else if (_wcsicmp(argv[i], L"--compress") == 0) {
            config->compression_enabled = true;
        } else if (_wcsicmp(argv[i], L"--compression-level") == 0 && i + 1 < argc) {
            if (!memfs_cli_parse_u32(argv[++i], &config->compression_level) ||
                config->compression_level < 1 || config->compression_level > 22) {
                fwprintf(stderr, L"Invalid compression level; use 1..22.\n");
                return 2;
            }
            config->compression_enabled = true;
        } else if (_wcsicmp(argv[i], L"--encrypt") == 0) {
            config->encryption_enabled = true;
        } else if (_wcsicmp(argv[i], L"--key-hex") == 0 && i + 1 < argc) {
            if (!memfs_cli_parse_key_hex(argv[++i], config->encryption_key)) {
                fwprintf(stderr, L"Invalid --key-hex; expected exactly 64 hex characters.\n");
                return 2;
            }
            config->encryption_enabled = true;
            config->have_fixed_key = true;
        } else if (_wcsicmp(argv[i], L"--key-env") == 0 && i + 1 < argc) {
            const wchar_t* value = _wgetenv(argv[++i]);

            if (!memfs_cli_parse_key_hex(value, config->encryption_key)) {
                fwprintf(stderr, L"Invalid or missing encryption-key environment variable.\n");
                return 2;
            }
            config->encryption_enabled = true;
            config->have_fixed_key = true;
        } else if (_wcsicmp(argv[i], L"--debug") == 0) {
            config->debug = true;
        } else if (_wcsicmp(argv[i], L"--service") == 0) {
            config->service_mode = true;
        } else if (_wcsicmp(argv[i], L"--service-name") == 0 && i + 1 < argc) {
            if (config->service_name_set) {
                fwprintf(stderr, L"--service-name may only be specified once.\n");
                return 2;
            }
            config->service_name = argv[++i];
            config->service_name_set = true;
        } else if (_wcsicmp(argv[i], L"--log-file") == 0 && i + 1 < argc) {
            if (config->log_file != NULL) {
                fwprintf(stderr, L"--log-file may only be specified once.\n");
                return 2;
            }
            config->log_file = argv[++i];
        } else if (_wcsicmp(argv[i], L"--authorized-user-sid") == 0 && i + 1 < argc) {
            if (config->authorized_user_sid != NULL) {
                fwprintf(stderr, L"--authorized-user-sid may only be specified once.\n");
                return 2;
            }
            config->authorized_user_sid = argv[++i];
        } else if (_wcsicmp(argv[i], L"--install") == 0) {
            config->install_service = true;
        } else if (_wcsicmp(argv[i], L"--uninstall") == 0) {
            config->uninstall_service = true;
        } else if (_wcsicmp(argv[i], L"--uninstall-private-driver") == 0) {
            config->uninstall_private_driver = true;
        } else if (_wcsicmp(argv[i], L"--stats") == 0) {
            config->stats_enabled = true;
        } else if (_wcsicmp(argv[i], L"--stats-json") == 0) {
            config->stats_enabled = true;
            config->stats_json = true;
        } else if (_wcsicmp(argv[i], L"--help") == 0 ||
                   _wcsicmp(argv[i], L"-h") == 0 ||
                   _wcsicmp(argv[i], L"/?") == 0) {
            return 1;
        } else {
            fwprintf(stderr, L"Unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    if (config->service_name == NULL || config->service_name[0] == L'\0') {
        fwprintf(stderr, L"--service-name must not be empty.\n");
        return 2;
    }
    if ((config->service_mode ? 1 : 0) + (config->install_service ? 1 : 0) +
        (config->uninstall_service ? 1 : 0) > 1) {
        fwprintf(stderr, L"--service, --install and --uninstall are mutually exclusive.\n");
        return 2;
    }
    if (config->uninstall_private_driver &&
        (config->service_mode || config->install_service || config->uninstall_service)) {
        fwprintf(stderr, L"--uninstall-private-driver cannot be combined with service commands.\n");
        return 2;
    }
    if (config->install_service && config->have_fixed_key) {
        fwprintf(stderr,
            L"--install cannot persist --key-hex/--key-env credentials in the LocalSystem service.\n");
        return 2;
    }
    if (config->install_service && config->authorized_user_sid != NULL) {
        fwprintf(stderr, L"--authorized-user-sid is assigned by --install.\n");
        return 2;
    }
    if (config->uninstall_service && config->mount_point != NULL) {
        fwprintf(stderr, L"--mount is not valid with --uninstall.\n");
        return 2;
    }
    if ((config->log_file != NULL || config->authorized_user_sid != NULL) &&
        !config->service_mode && !config->install_service) {
        fwprintf(stderr, L"--log-file and --authorized-user-sid are service-only options.\n");
        return 2;
    }
    if (config->service_mode && config->stop_event_name != NULL) {
        fwprintf(stderr, L"--stop-event is only valid in console mode.\n");
        return 2;
    }
    if (config->install_service && config->stop_event_name != NULL) {
        fwprintf(stderr, L"--stop-event cannot be saved in a service installation.\n");
        return 2;
    }
    if (config->service_name_set && !config->service_mode &&
        !config->install_service && !config->uninstall_service) {
        fwprintf(stderr, L"--service-name is only valid with a service command.\n");
        return 2;
    }

    if (!config->uninstall_private_driver && !config->uninstall_service &&
        config->mount_point == NULL) {
        fwprintf(stderr, L"--mount is required.\n");
        return 2;
    }

    return 0;
}

static bool valid_service_name(PCWSTR name) {
    const wchar_t* cursor;
    size_t length;

    if (name == NULL)
        return false;
    length = wcslen(name);
    if (length == 0 || length > 256)
        return false;
    for (cursor = name; *cursor != L'\0'; ++cursor) {
        if (!((*cursor >= L'a' && *cursor <= L'z') ||
              (*cursor >= L'A' && *cursor <= L'Z') ||
              (*cursor >= L'0' && *cursor <= L'9') ||
              *cursor == L'_' || *cursor == L'-' || *cursor == L'.'))
            return false;
    }
    return true;
}

/* MEMFS_CONTROL_PLANE_HEAP_BEGIN */
static wchar_t* absolute_path_copy(PCWSTR path) {
    DWORD required;
    DWORD written;
    wchar_t* absolute_path;

    if (path == NULL || path[0] == L'\0')
        return NULL;
    required = GetFullPathNameW(path, 0, NULL, NULL);
    if (required == 0)
        return NULL;
    absolute_path = (wchar_t*)malloc((size_t)(required + 1) * sizeof(*absolute_path));
    if (absolute_path == NULL)
        return NULL;
    written = GetFullPathNameW(path, required + 1, absolute_path, NULL);
    if (written == 0 || written > required) {
        free(absolute_path);
        return NULL;
    }
    return absolute_path;
}

static wchar_t* current_executable_path(void) {
    DWORD capacity = MAX_PATH;

    while (capacity <= MEMFS_SERVICE_ARGUMENT_CAPACITY) {
        wchar_t* path = (wchar_t*)malloc((size_t)capacity * sizeof(*path));
        DWORD length;

        if (path == NULL)
            return NULL;
        length = GetModuleFileNameW(NULL, path, capacity);
        if (length == 0) {
            free(path);
            return NULL;
        }
        if (length < capacity) {
            wchar_t* absolute_path = absolute_path_copy(path);
            free(path);
            return absolute_path;
        }
        free(path);
        if (capacity > MEMFS_SERVICE_ARGUMENT_CAPACITY / 2)
            break;
        capacity *= 2;
    }
    return NULL;
}

static wchar_t* default_service_log_path(PCWSTR service_name) {
    DWORD required;
    DWORD written;
    wchar_t* program_data;
    wchar_t* path;
    wchar_t* absolute_path;
    size_t path_capacity;
    int path_length;

    if (!valid_service_name(service_name))
        return NULL;
    required = GetEnvironmentVariableW(L"ProgramData", NULL, 0);
    if (required == 0)
        return NULL;
    program_data = (wchar_t*)malloc((size_t)required * sizeof(*program_data));
    if (program_data == NULL)
        return NULL;
    written = GetEnvironmentVariableW(L"ProgramData", program_data, required);
    if (written == 0 || written >= required) {
        free(program_data);
        return NULL;
    }

    path_capacity = (size_t)written + wcslen(service_name) + 16;
    path = (wchar_t*)malloc(path_capacity * sizeof(*path));
    if (path == NULL) {
        free(program_data);
        return NULL;
    }
    path_length = _snwprintf_s(path, path_capacity, _TRUNCATE,
        L"%ls\\MemfsC\\%ls.log", program_data, service_name);
    free(program_data);
    if (path_length < 0) {
        free(path);
        return NULL;
    }
    absolute_path = absolute_path_copy(path);
    free(path);
    return absolute_path;
}

static wchar_t* capture_user_sid(void) {
    HANDLE token = NULL;
    TOKEN_USER* user = NULL;
    DWORD bytes = 0;
    wchar_t* sid = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return NULL;
    (void)GetTokenInformation(token, TokenUser, NULL, 0, &bytes);
    if (bytes == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        goto done;
    user = (TOKEN_USER*)malloc(bytes);
    if (user == NULL || !GetTokenInformation(token, TokenUser, user, bytes, &bytes))
        goto done;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid))
        sid = NULL;

done:
    free(user);
    CloseHandle(token);
    return sid;
}

static bool append_quoted_argument(
    wchar_t* buffer,
    size_t capacity,
    size_t* used,
    PCWSTR value) {
    size_t index = 0;

    if (buffer == NULL || used == NULL || value == NULL || *used >= capacity)
        return false;
    if (*used != 0) {
        if (*used + 1 >= capacity)
            return false;
        buffer[(*used)++] = L' ';
    }
    if (*used + 1 >= capacity)
        return false;
    buffer[(*used)++] = L'"';

    while (true) {
        size_t slashes = 0;
        size_t count;

        while (value[index] == L'\\') {
            ++slashes;
            ++index;
        }
        if (value[index] == L'"') {
            count = slashes * 2 + 1;
            if (*used + count + 1 >= capacity)
                return false;
            while (count-- != 0)
                buffer[(*used)++] = L'\\';
            buffer[(*used)++] = L'"';
            ++index;
        } else if (value[index] == L'\0') {
            count = slashes * 2;
            if (*used + count + 2 > capacity)
                return false;
            while (count-- != 0)
                buffer[(*used)++] = L'\\';
            break;
        } else {
            if (*used + slashes + 1 >= capacity)
                return false;
            while (slashes-- != 0)
                buffer[(*used)++] = L'\\';
            buffer[(*used)++] = value[index++];
        }
    }

    if (*used + 2 > capacity)
        return false;
    buffer[(*used)++] = L'"';
    buffer[*used] = L'\0';
    return true;
}

static bool build_service_arguments(
    const MemfsRunConfig* config,
    PCWSTR log_file,
    PCWSTR authorized_user_sid,
    wchar_t arguments[MEMFS_SERVICE_ARGUMENT_CAPACITY]) {
    const wchar_t* parts[32];
    wchar_t size_text[32];
    wchar_t threads_text[16];
    wchar_t compression_text[16];
    size_t count = 0;
    size_t used = 0;
    size_t index;

    if (config->capacity_auto) {
        parts[count++] = L"auto";
    } else {
        if (_snwprintf_s(size_text, _countof(size_text), _TRUNCATE,
                         L"%llu", (unsigned long long)config->capacity) < 0)
            return false;
        parts[count++] = size_text;
    }
    if (_snwprintf_s(threads_text, _countof(threads_text), _TRUNCATE,
                     L"%u", config->thread_count) < 0)
        return false;
    if (_snwprintf_s(compression_text, _countof(compression_text), _TRUNCATE,
                     L"%u", config->compression_level) < 0)
        return false;

    arguments[0] = L'\0';
    count = 0;
    parts[count++] = L"--service";
    parts[count++] = L"--service-name";
    parts[count++] = config->service_name;
    parts[count++] = L"--mount";
    parts[count++] = config->mount_point;
    parts[count++] = L"--size";
    parts[count++] = config->capacity_auto ? L"auto" : size_text;
    parts[count++] = L"--label";
    parts[count++] = config->volume_label;
    parts[count++] = L"--threads";
    parts[count++] = threads_text;
    if (config->compression_enabled) {
        if (config->compression_level == 1) {
            parts[count++] = L"--compress";
        } else {
            parts[count++] = L"--compression-level";
            parts[count++] = compression_text;
        }
    }
    if (config->encryption_enabled)
        parts[count++] = L"--encrypt";
    if (config->debug)
        parts[count++] = L"--debug";
    if (config->stats_enabled)
        parts[count++] = config->stats_json ? L"--stats-json" : L"--stats";
    parts[count++] = L"--log-file";
    parts[count++] = log_file;
    parts[count++] = L"--authorized-user-sid";
    parts[count++] = authorized_user_sid;

    for (index = 0; index < count; ++index) {
        if (!append_quoted_argument(arguments, MEMFS_SERVICE_ARGUMENT_CAPACITY,
                                    &used, parts[index]))
            return false;
    }
    return true;
}
/* MEMFS_CONTROL_PLANE_HEAP_END */

/* MEMFS_CONTROL_PLANE_HEAP_BEGIN */
static int install_memfs_service(const MemfsRunConfig* config) {
    static const SC_ACTION actions[] = {
        {SC_ACTION_RESTART, 1000},
        {SC_ACTION_RESTART, 5000},
        {SC_ACTION_RESTART, 30000},
        {SC_ACTION_NONE, 0},
    };
    FSF_SERVICE_INSTALL_CONFIG install_config;
    wchar_t* log_file = NULL;
    wchar_t* executable = NULL;
    wchar_t* sid = NULL;
    wchar_t arguments[MEMFS_SERVICE_ARGUMENT_CAPACITY];
    DWORD error;
    int result = 1;

    if (!valid_service_name(config->service_name)) {
        fwprintf(stderr, L"Invalid service name.\n");
        return 2;
    }
    log_file = config->log_file != NULL
        ? absolute_path_copy(config->log_file)
        : default_service_log_path(config->service_name);
    executable = current_executable_path();
    sid = capture_user_sid();
    if (log_file == NULL || executable == NULL || sid == NULL) {
        fwprintf(stderr,
                 L"Cannot resolve the executable, protected log path, or installer SID (Win32 %lu).\n",
                 GetLastError());
        goto done;
    }
    if (!build_service_arguments(config, log_file, sid, arguments)) {
        fwprintf(stderr, L"Service arguments exceed the Windows command-line limit.\n");
        goto done;
    }

    memset(&install_config, 0, sizeof(install_config));
    install_config.struct_size = sizeof(install_config);
    install_config.abi_version = FS_FRONTEND_ABI_VERSION;
    install_config.service_name = config->service_name;
    install_config.display_name = L"MemfsC volatile memory file system";
    install_config.description = L"Mounts a volatile in-memory file system through WinFsp.";
    install_config.absolute_executable = executable;
    install_config.exact_service_arguments = arguments;
    install_config.log_path = log_file;
    install_config.authorized_user_sid = sid;
    install_config.delayed_auto_start = TRUE;
    install_config.start_timeout_ms = MEMFS_SERVICE_DEFAULT_START_TIMEOUT_MS;
    install_config.failure_reset_seconds = 86400;
    install_config.failure_action_count = (DWORD)_countof(actions);
    install_config.failure_actions = actions;

    error = fsf_service_install(&install_config);
    if (error != ERROR_SUCCESS) {
        fwprintf(stderr,
                 L"Native service installation/start failed for %ls (Win32 %lu).\n",
                 config->service_name, error);
        goto done;
    }
    wprintf(L"Service %ls is installed and running.\n", config->service_name);
    result = 0;

done:
    free(log_file);
    free(executable);
    if (sid != NULL)
        LocalFree(sid);
    return result;
}
/* MEMFS_CONTROL_PLANE_HEAP_END */

static int uninstall_memfs_service(PCWSTR service_name) {
    DWORD error;

    if (!valid_service_name(service_name)) {
        fwprintf(stderr, L"Invalid service name.\n");
        return 2;
    }
    error = fsf_service_uninstall(service_name, MEMFS_SERVICE_STOP_TIMEOUT_MS);
    if (error != ERROR_SUCCESS) {
        fwprintf(stderr, L"Cannot stop and remove service %ls (Win32 %lu).\n",
                 service_name, error);
        return 1;
    }
    wprintf(L"Service %ls is removed. No driver or file system data was changed.\n",
            service_name);
    return 0;
}


static void print_runtime_stats(Memfs* fs, const char* phase, bool json) {
    MemfsRuntimeStats stats;
    HANDLE output;
    DWORD written = 0;
    char line[4096];
    int length;

    if (fs == NULL || phase == NULL)
        return;

    memfs_get_runtime_stats(fs, &stats);

    if (json) {
        length = _snprintf_s(
            line, sizeof(line), _TRUNCATE,
            "{\"type\":\"memfs_stats\",\"phase\":\"%s\","
            "\"capacity_auto\":%s,\"capacity_bytes\":%llu,"
            "\"logical_used_bytes\":%llu,\"free_bytes\":%llu,"
            "\"resident_bytes\":%llu,\"auto_allowance_bytes\":%llu,"
            "\"auto_hard_margin_bytes\":%llu,\"auto_soft_margin_bytes\":%llu,"
            "\"allocator_live_bytes\":%llu,\"allocator_live_objects\":%llu,"
            "\"allocator_reserved_bytes\":%llu,\"allocator_committed_bytes\":%llu,"
            "\"allocator_physical_bytes\":%llu,\"slab_count\":%u,"
            "\"area_count\":%u,\"area_cached_count\":%u,"
            "\"area_cached_bytes\":%llu,\"allocator_scavenge_count\":%llu,"
            "\"allocator_scavenged_bytes\":%llu}\r\n",
            phase,
            stats.capacity_auto ? "true" : "false",
            (unsigned long long)stats.capacity_bytes,
            (unsigned long long)stats.logical_used_bytes,
            (unsigned long long)stats.free_bytes,
            (unsigned long long)stats.resident_bytes,
            (unsigned long long)stats.auto_allowance_bytes,
            (unsigned long long)stats.auto_hard_margin_bytes,
            (unsigned long long)stats.auto_soft_margin_bytes,
            (unsigned long long)stats.allocator_live_bytes,
            (unsigned long long)stats.allocator_live_objects,
            (unsigned long long)stats.allocator_reserved_bytes,
            (unsigned long long)stats.allocator_committed_bytes,
            (unsigned long long)stats.allocator_physical_bytes,
            stats.slab_count,
            stats.area_count,
            stats.area_cached_count,
            (unsigned long long)stats.area_cached_bytes,
            (unsigned long long)stats.allocator_scavenge_count,
            (unsigned long long)stats.allocator_scavenged_bytes);
    } else {
        length = _snprintf_s(
            line, sizeof(line), _TRUNCATE,
            "stats phase=%s capacity_auto=%u capacity_bytes=%llu "
            "logical_used_bytes=%llu free_bytes=%llu resident_bytes=%llu "
            "auto_allowance_bytes=%llu auto_hard_margin_bytes=%llu "
            "auto_soft_margin_bytes=%llu allocator_live_bytes=%llu "
            "allocator_live_objects=%llu allocator_reserved_bytes=%llu "
            "allocator_committed_bytes=%llu allocator_physical_bytes=%llu "
            "slab_count=%u area_count=%u area_cached_count=%u "
            "area_cached_bytes=%llu allocator_scavenge_count=%llu "
            "allocator_scavenged_bytes=%llu\r\n",
            phase,
            stats.capacity_auto ? 1U : 0U,
            (unsigned long long)stats.capacity_bytes,
            (unsigned long long)stats.logical_used_bytes,
            (unsigned long long)stats.free_bytes,
            (unsigned long long)stats.resident_bytes,
            (unsigned long long)stats.auto_allowance_bytes,
            (unsigned long long)stats.auto_hard_margin_bytes,
            (unsigned long long)stats.auto_soft_margin_bytes,
            (unsigned long long)stats.allocator_live_bytes,
            (unsigned long long)stats.allocator_live_objects,
            (unsigned long long)stats.allocator_reserved_bytes,
            (unsigned long long)stats.allocator_committed_bytes,
            (unsigned long long)stats.allocator_physical_bytes,
            stats.slab_count,
            stats.area_count,
            stats.area_cached_count,
            (unsigned long long)stats.area_cached_bytes,
            (unsigned long long)stats.allocator_scavenge_count,
            (unsigned long long)stats.allocator_scavenged_bytes);
    }

    if (length <= 0)
        return;

    output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output == NULL || output == INVALID_HANDLE_VALUE)
        return;

    (void)WriteFile(output, line, (DWORD)length, &written, NULL);
}

static void set_service_status_failure(FSF_SERVICE_EXIT* result, NTSTATUS status) {
    if (result == NULL)
        return;
    result->normal_stop = FALSE;
    result->win32_error = ERROR_SERVICE_SPECIFIC_ERROR;
    result->service_specific_error = status != STATUS_SUCCESS
        ? (DWORD)status : ERROR_GEN_FAILURE;
}

static void set_service_win32_failure(FSF_SERVICE_EXIT* result, DWORD error) {
    if (result == NULL)
        return;
    result->normal_stop = FALSE;
    result->win32_error = error != ERROR_SUCCESS ? error : ERROR_GEN_FAILURE;
    result->service_specific_error = 0;
}

static int run_filesystem(MemfsRunConfig* config,
                          HANDLE stop_event,
                          FSF_SERVICE* service,
                          bool console_mode,
                          FSF_SERVICE_EXIT* service_result) {
    MemfsOptions options;
    MemfsWinFsp* instance = NULL;
    NTSTATUS status;
    DWORD create_detail = ERROR_SUCCESS;
    int exit_code = 1;

    if (service_result != NULL) {
        service_result->normal_stop = FALSE;
        service_result->win32_error = ERROR_SUCCESS;
        service_result->service_specific_error = 0;
    }

    memset(&options, 0, sizeof(options));
    options.capacity = config->capacity;
    options.capacity_auto = config->capacity_auto;
    options.volume_label = config->volume_label;
    options.compression_enabled = config->compression_enabled;
    options.compression_level = (int)config->compression_level;
    options.encryption_enabled = config->encryption_enabled;

    if (config->have_fixed_key) {
        options.encryption_key = config->encryption_key;
        options.encryption_key_size = sizeof(config->encryption_key);
    }

    status = memfs_winfsp_create_ex(&options, &instance, &create_detail);

    /*
     * memfs_create_ex() copies a fixed key into the filesystem object before
     * memfs_winfsp_create_ex() returns. Do not retain the CLI/config copy for
     * the lifetime of the mount.
     */
    memfs_cli_wipe_fixed_key(config->encryption_key, &config->have_fixed_key);
    options.encryption_key = NULL;
    options.encryption_key_size = 0;

    if (!NT_SUCCESS(status)) {
        if (create_detail != ERROR_SUCCESS)
            set_service_win32_failure(service_result, create_detail);
        else
            set_service_status_failure(service_result, status);
        if (service != NULL)
            fsf_service_log(service, FSF_SERVICE_LOG_ERROR,
                create_detail != ERROR_SUCCESS ? create_detail : (DWORD)status,
                L"memfs WinFsp/backend creation failed.");
        if (console_mode) {
            if (create_detail == ERROR_SUCCESS_REBOOT_REQUIRED) {
                fwprintf(stderr,
                         L"WinFsp private driver upgrade is staged but the "
                         L"currently loaded driver cannot be replaced safely; "
                         L"reboot is required.\n");
            } else if (create_detail != ERROR_SUCCESS) {
                fwprintf(stderr,
                         L"memfs_winfsp_create failed: 0x%08X "
                         L"(driver/runtime Win32 error=%lu)\n",
                         (unsigned)status, create_detail);
            } else {
                fwprintf(stderr,
                         L"memfs_winfsp_create failed: 0x%08X\n",
                         (unsigned)status);
            }
        }
        return 3;
    }

    if (config->debug)
        FspFileSystemSetDebugLog(instance->file_system, (ULONG)-1);

    status = memfs_winfsp_mount(instance, config->mount_point);
    if (!NT_SUCCESS(status)) {
        set_service_status_failure(service_result, status);
        if (service != NULL)
            fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status,
                L"memfs mount failed.");
        if (console_mode)
            fwprintf(stderr, L"Cannot mount %s: 0x%08X\n",
                     config->mount_point, (unsigned)status);
        exit_code = 4;
        goto exit;
    }

    status = memfs_winfsp_start(instance, config->thread_count);
    if (!NT_SUCCESS(status)) {
        set_service_status_failure(service_result, status);
        if (service != NULL)
            fsf_service_log(service, FSF_SERVICE_LOG_ERROR, (DWORD)status,
                L"memfs WinFsp dispatcher failed to start.");
        if (console_mode)
            fwprintf(stderr, L"Cannot start WinFsp dispatcher: 0x%08X\n", (unsigned)status);
        exit_code = 5;
        goto exit;
    }

    if (service != NULL) {
        DWORD report_error = ERROR_SUCCESS;
        if (!fsf_service_report_running(service, &report_error)) {
            set_service_win32_failure(service_result, report_error);
            fsf_service_log(service, FSF_SERVICE_LOG_ERROR, report_error,
                L"SCM rejected the RUNNING status after mount startup.");
            exit_code = 6;
            goto exit;
        }
    }

    if (console_mode) {
        if (config->stats_json && config->stop_event_name != NULL &&
            _wcsnicmp(config->stop_event_name, L"Local\\FSF-GUI-", 14) == 0)
            fwprintf(stderr, L"MEMFS mounted at %s (JSON statistics ready).\n",
                     config->mount_point);
        if (!config->stats_json) {
            if (config->capacity_auto)
                wprintf(L"MEMFS mounted at %s (auto capacity)%s%s. Press Ctrl+C to stop.\n",
                        config->mount_point,
                        config->compression_enabled ? L", compressed" : L"",
                        config->encryption_enabled ? L", encrypted" : L"");
            else
                wprintf(L"MEMFS mounted at %s (%llu MiB)%s%s. Press Ctrl+C to stop.\n",
                        config->mount_point,
                        (unsigned long long)(config->capacity / (1024ULL * 1024ULL)),
                        config->compression_enabled ? L", compressed" : L"",
                        config->encryption_enabled ? L", encrypted" : L"");
        }
        if (config->stats_enabled)
            print_runtime_stats(instance->store, "mounted", config->stats_json);
        fflush(stdout);
        fflush(stderr);
    }

    {
        HANDLE wait_handles[2];
        DWORD wait_result;

        wait_handles[0] = stop_event;
        wait_handles[1] = memfs_winfsp_dispatcher_stopped_event(instance);
        wait_result = WaitForMultipleObjects(
            (DWORD)_countof(wait_handles), wait_handles, FALSE, INFINITE);

        if (wait_result == WAIT_OBJECT_0) {
            if (console_mode && config->stats_enabled)
                print_runtime_stats(instance->store, "stopping", config->stats_json);
            exit_code = 0;
            memfs_winfsp_stop(instance);
        } else if (wait_result == WAIT_OBJECT_0 + 1U) {
            NTSTATUS dispatcher_status =
                memfs_winfsp_dispatcher_result(instance);
            bool normal =
                memfs_winfsp_dispatcher_stopped_normally(instance);

            /*
             * A normal callback should only follow our own StopDispatcher,
             * which is issued after the stop event wins the wait above. If it
             * arrives here without a stop request, treat it as an unexpected
             * lifetime break rather than silently leaving a "running" service.
             */
            if (normal &&
                WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
                exit_code = 0;
            } else {
                if (NT_SUCCESS(dispatcher_status))
                    dispatcher_status = STATUS_DEVICE_NOT_CONNECTED;
                set_service_status_failure(service_result, dispatcher_status);
                if (service != NULL)
                    fsf_service_log(service, FSF_SERVICE_LOG_ERROR,
                        (DWORD)dispatcher_status,
                        L"memfs WinFsp dispatcher stopped unexpectedly.");
                if (console_mode) {
                    fwprintf(stderr,
                             L"WinFsp dispatcher stopped unexpectedly: "
                             L"0x%08X\n",
                             (unsigned)dispatcher_status);
                }
                exit_code = 7;
            }
        } else {
            DWORD wait_error =
                wait_result == WAIT_FAILED ? GetLastError()
                                           : ERROR_GEN_FAILURE;
            set_service_win32_failure(service_result, wait_error);
            if (service != NULL)
                fsf_service_log(service, FSF_SERVICE_LOG_ERROR, wait_error,
                    L"memfs service/dispatcher wait failed.");
            if (console_mode)
                fwprintf(stderr,
                         L"Dispatcher/stop wait failed: %lu\n",
                         wait_error);
            exit_code = 8;
        }
    }

exit:
    if (exit_code == 0 && service_result != NULL) {
        service_result->normal_stop = TRUE;
        service_result->win32_error = ERROR_SUCCESS;
        service_result->service_specific_error = 0;
    }
    memfs_winfsp_destroy(instance);
    return exit_code;
}

static FSF_SERVICE_EXIT memfs_service_run(void* app_context, FSF_SERVICE* service) {
    MemfsRunConfig* config = (MemfsRunConfig*)app_context;
    FSF_SERVICE_EXIT result;
    HANDLE stop_event = fsf_service_stop_event(service);

    memset(&result, 0, sizeof(result));
    if (config == NULL || stop_event == NULL) {
        set_service_win32_failure(&result, ERROR_INVALID_HANDLE);
        return result;
    }
    (void)run_filesystem(config, stop_event, service, false, &result);
    memfs_cli_wipe_fixed_key(config->encryption_key, &config->have_fixed_key);
    return result;
}

/* MEMFS_CONTROL_PLANE_HEAP_BEGIN */
static int run_service(MemfsRunConfig* config) {
    FSF_SERVICE_RUN_CONFIG service_config;
    FSF_SERVICE_EXIT service_result;
    wchar_t* log_file = NULL;
    DWORD error;

    if (!valid_service_name(config->service_name)) {
        fwprintf(stderr, L"Invalid service name.\n");
        return 2;
    }
    if (config->log_file == NULL) {
        log_file = default_service_log_path(config->service_name);
        if (log_file == NULL) {
            fwprintf(stderr, L"Cannot resolve the default ProgramData service log path.\n");
            return 1;
        }
        config->log_file = log_file;
    } else {
        log_file = absolute_path_copy(config->log_file);
        if (log_file == NULL) {
            fwprintf(stderr, L"Cannot resolve the service log path (Win32 %lu).\n",
                     GetLastError());
            return 1;
        }
        config->log_file = log_file;
    }

    memset(&service_config, 0, sizeof(service_config));
    service_config.struct_size = sizeof(service_config);
    service_config.abi_version = FS_FRONTEND_ABI_VERSION;
    service_config.service_name = config->service_name;
    service_config.log_path = config->log_file;
    service_config.authorized_user_sid = config->authorized_user_sid;
    service_config.app_context = config;
    service_config.run = memfs_service_run;
    error = fsf_service_run(&service_config, &service_result);
    free(log_file);
    if (error != ERROR_SUCCESS) {
        fwprintf(stderr, L"Service Control Manager startup failed (Win32 %lu).\n", error);
        memfs_cli_wipe_fixed_key(config->encryption_key, &config->have_fixed_key);
        return 1;
    }
    memfs_cli_wipe_fixed_key(config->encryption_key, &config->have_fixed_key);
    return service_result.normal_stop ? 0 : 1;
}
/* MEMFS_CONTROL_PLANE_HEAP_END */

int wmain(int argc, wchar_t** argv) {
    int parse_result;

    if (argc == 1 || (argc > 1 && _wcsicmp(argv[1], L"--gui") == 0))
        return memfs_gui_run();

    parse_result = parse_config(argc, argv, &g_config);
    if (parse_result == 1) {
        print_usage(argv[0]);
        memfs_cli_wipe_fixed_key(
            g_config.encryption_key, &g_config.have_fixed_key);
        return 0;
    }
    if (parse_result != 0) {
        print_usage(argv[0]);
        memfs_cli_wipe_fixed_key(
            g_config.encryption_key, &g_config.have_fixed_key);
        return parse_result;
    }

    if (g_config.uninstall_private_driver) {
        DWORD error;

        memfs_cli_wipe_fixed_key(
            g_config.encryption_key, &g_config.have_fixed_key);
        error = memfs_winfsp_uninstall_embedded_driver();

        if (error == ERROR_SUCCESS) {
            wprintf(L"MemfsC private WinFsp driver is removed.\n");
            return 0;
        }
        if (error == ERROR_SUCCESS_REBOOT_REQUIRED) {
            wprintf(L"MemfsC private WinFsp driver removal is scheduled; reboot required.\n");
            return 0;
        }

        fwprintf(stderr, L"Cannot remove MemfsC private WinFsp driver: %lu\n", error);
        return 6;
    }

    if (g_config.install_service) {
        int result;
        memfs_cli_wipe_fixed_key(
            g_config.encryption_key, &g_config.have_fixed_key);
        result = install_memfs_service(&g_config);
        return result;
    }

    if (g_config.uninstall_service) {
        memfs_cli_wipe_fixed_key(
            g_config.encryption_key, &g_config.have_fixed_key);
        return uninstall_memfs_service(g_config.service_name);
    }

    if (g_config.service_mode) {
        return run_service(&g_config);
    }

    g_stop_event = CreateEventW(NULL, TRUE, FALSE, g_config.stop_event_name);
    if (g_stop_event == NULL) {
        fwprintf(stderr, L"CreateEvent failed: %lu\n", GetLastError());
        memfs_cli_wipe_fixed_key(
            g_config.encryption_key, &g_config.have_fixed_key);
        return 1;
    }

    SetConsoleCtrlHandler(console_handler, TRUE);
    parse_result = run_filesystem(&g_config, g_stop_event, NULL, true, NULL);
    SetConsoleCtrlHandler(console_handler, FALSE);

    CloseHandle(g_stop_event);
    g_stop_event = NULL;
    memfs_cli_wipe_fixed_key(
        g_config.encryption_key, &g_config.have_fixed_key);
    return parse_result;
}
