#include "memfs_block_run.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memfs_block.h"
#include "memfs_devio.h"

#define MIB (1024ULL * 1024ULL)

uint64_t memfs_block_default_disk_size(bool capacity_auto, uint64_t capacity) {
	MEMORYSTATUSEX status;
	uint64_t size = capacity;

	if (capacity_auto) {
		status.dwLength = sizeof(status);
		size = GlobalMemoryStatusEx(&status) ? status.ullTotalPhys : 0;
	}
	return size & ~(MIB - 1U);
}

bool memfs_block_find_aim_ll(const wchar_t* configured, wchar_t* path, DWORD count) {
	wchar_t* slash;
	DWORD length;

	if (configured != NULL) {
		length = GetFullPathNameW(configured, count, path, NULL);
		return length != 0 && length < count && GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
	}
	length = GetModuleFileNameW(NULL, path, count);
	if (length != 0 && length < count && (slash = wcsrchr(path, L'\\')) != NULL) {
		if ((size_t)(slash + 1 - path) + wcslen(L"aim_ll.exe") < count) {
			wcscpy(slash + 1, L"aim_ll.exe");
			if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
				return true;
		}
	}
	length = SearchPathW(NULL, L"aim_ll.exe", NULL, count, path, NULL);
	return length != 0 && length < count;
}

/* Runs aim_ll with the given arguments and returns its exit code (or -1).
 * Its output is passed through to our stdout and, when `captured` is given,
 * also kept (NUL-terminated, truncated to capacity) for parsing. */
static int run_aim_ll(const wchar_t* exe, const wchar_t* arguments, char* captured, size_t capacity) {
	wchar_t* command;
	size_t length = wcslen(exe) + wcslen(arguments) + 8;
	STARTUPINFOW startup;
	PROCESS_INFORMATION process = {0};
	SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
	HANDLE read_end = NULL;
	HANDLE write_end = NULL;
	DWORD exit_code = (DWORD)-1;
	size_t kept = 0;

	if (captured != NULL && capacity != 0)
		captured[0] = 0;
	memset(&startup, 0, sizeof(startup));
	startup.cb = sizeof(startup);
	if (!CreatePipe(&read_end, &write_end, &inherit, 0))
		return -1;
	SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
	startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	startup.hStdOutput = write_end;
	startup.hStdError = write_end;
	command = malloc(length * sizeof(wchar_t));
	if (command != NULL) {
		_snwprintf(command, length, L"\"%ls\" %ls", exe, arguments);
		command[length - 1] = 0;
		if (CreateProcessW(exe, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &process)) {
			char chunk[1024];
			DWORD got;

			CloseHandle(write_end);
			write_end = NULL;
			while (ReadFile(read_end, chunk, sizeof(chunk), &got, NULL) && got != 0) {
				fwrite(chunk, 1, got, stdout);
				if (captured != NULL && kept + 1 < capacity) {
					size_t take = got < capacity - 1 - kept ? got : capacity - 1 - kept;

					memcpy(captured + kept, chunk, take);
					kept += take;
					captured[kept] = 0;
				}
			}
			fflush(stdout);
			WaitForSingleObject(process.hProcess, INFINITE);
			GetExitCodeProcess(process.hProcess, &exit_code);
			CloseHandle(process.hThread);
			CloseHandle(process.hProcess);
		}
		free(command);
	}
	if (write_end)
		CloseHandle(write_end);
	CloseHandle(read_end);
	return (int)exit_code;
}

/* aim_ll -a prints "Created device 000000 -> ..."; the six hex digits are the
 * unit used for detaching. Detaching by unit avoids aim_ll's mount-point
 * lookup, which resolves a wrong unit once the volume is dismounted. */
static bool parse_created_unit(const char* output, wchar_t unit[16]) {
	const char* found = output ? strstr(output, "Created device ") : NULL;
	int i;

	if (found == NULL)
		return false;
	found += strlen("Created device ");
	for (i = 0; i < 6; i++) {
		char c = found[i];

		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
			return false;
		unit[i] = (wchar_t)c;
	}
	unit[6] = 0;
	return true;
}

static bool valid_drive_letter(const wchar_t* mount_point) {
	return mount_point != NULL &&
		   ((mount_point[0] >= L'A' && mount_point[0] <= L'Z') || (mount_point[0] >= L'a' && mount_point[0] <= L'z')) &&
		   mount_point[1] == L':' && (mount_point[2] == 0 || (mount_point[2] == L'\\' && mount_point[3] == 0));
}

static bool valid_label(const wchar_t* label) {
	const wchar_t* p;

	if (label == NULL || *label == 0 || wcslen(label) > 32)
		return false;
	for (p = label; *p; p++)
		/* No spaces: aim_ll passes the format options as one quoted
		 * argument, so a label with a space cannot reach format's /v. */
		if (*p <= 32 || wcschr(L"\"\\/:*?<>|", *p) != NULL)
			return false;
	return true;
}

/* Creates drive\path for every configured directory, nested parts too. */
static bool create_initial_directories(const MemfsBlockRunConfig* config, const wchar_t* drive) {
	uint32_t index;

	for (index = 0; index < config->initial_directory_count; index++) {
		wchar_t path[MAX_PATH];
		const wchar_t* source = config->initial_directories[index];
		size_t used;

		if (_snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%ls\\", drive) < 0)
			return false;
		used = wcslen(path);
		while (*source == L'\\' || *source == L'/')
			source++;
		for (;;) {
			bool end = *source == 0 || *source == L'\\' || *source == L'/';

			if (end && used > 3) {
				path[used] = 0;
				if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
					fwprintf(stderr, L"Cannot create directory %ls (Win32 %lu).\n", path, GetLastError());
					return false;
				}
			}
			if (*source == 0)
				break;
			if (used + 2 >= MAX_PATH)
				return false;
			path[used++] = end ? L'\\' : *source;
			source++;
			while (end && (*source == L'\\' || *source == L'/'))
				source++;
		}
	}
	return true;
}

static void print_block_stats(Memfs* fs, MemfsDevio* devio, const char* phase, bool json) {
	MemfsRuntimeStats stats;
	MemfsDevioStats io;

	memfs_get_runtime_stats(fs, &stats);
	memfs_devio_get_stats(devio, &io);
	if (json) {
		printf("{\"type\":\"memfs_block_stats\",\"phase\":\"%s\",\"resident_bytes\":%llu,"
			   "\"allocator_committed_bytes\":%llu,\"reads\":%llu,\"writes\":%llu,\"unmaps\":%llu,"
			   "\"read_bytes\":%llu,\"written_bytes\":%llu,\"unmapped_bytes\":%llu,\"errors\":%llu}\n",
			   phase, (unsigned long long)stats.resident_bytes,
			   (unsigned long long)stats.allocator_committed_bytes, (unsigned long long)io.reads,
			   (unsigned long long)io.writes, (unsigned long long)io.unmaps, (unsigned long long)io.read_bytes,
			   (unsigned long long)io.written_bytes, (unsigned long long)io.unmapped_bytes,
			   (unsigned long long)io.errors);
	} else {
		printf("[%s] resident=%llu bytes committed=%llu bytes reads=%llu writes=%llu unmaps=%llu "
			   "unmapped=%llu bytes errors=%llu\n",
			   phase, (unsigned long long)stats.resident_bytes,
			   (unsigned long long)stats.allocator_committed_bytes, (unsigned long long)io.reads,
			   (unsigned long long)io.writes, (unsigned long long)io.unmaps,
			   (unsigned long long)io.unmapped_bytes, (unsigned long long)io.errors);
	}
	fflush(stdout);
}

int memfs_block_run(const MemfsBlockRunConfig* config, HANDLE stop_event) {
	MemfsOptions options;
	Memfs* fs = NULL;
	MemfsBlock* block = NULL;
	MemfsDevio* devio = NULL;
	wchar_t aim_ll[MAX_PATH];
	wchar_t object_name[64];
	wchar_t devio_path[MAX_PATH];
	wchar_t arguments[1024];
	wchar_t drive[3];
	wchar_t unit[16] = {0};
	char* attach_output = NULL;
	uint64_t disk_size;
	int exit_code = 1;
	int aim_result;
	DWORD error;
	bool attached = false;

	if (config == NULL || stop_event == NULL || !valid_drive_letter(config->mount_point)) {
		fwprintf(stderr, L"--block requires a drive letter mount point such as X:.\n");
		return 2;
	}
	if (!valid_label(config->volume_label)) {
		fwprintf(stderr, L"--block needs a volume label of 1..32 characters without spaces or \\/:*?\"<>|.\n");
		return 2;
	}
	drive[0] = (wchar_t)towupper(config->mount_point[0]);
	drive[1] = L':';
	drive[2] = 0;
	if (!memfs_block_find_aim_ll(config->aim_ll_path, aim_ll, MAX_PATH)) {
		fwprintf(stderr, L"aim_ll.exe (Arsenal Image Mounter command line) was not found. "
						 L"Use --aim-ll <path> or place it next to memfs.exe.\n");
		return 4;
	}
	if (config->object_name != NULL)
		_snwprintf(object_name, 64, L"%ls", config->object_name);
	else
		_snwprintf(object_name, 64, L"memfs-block-%lu", GetCurrentProcessId());
	object_name[63] = 0;
	if (!memfs_devio_path(object_name, devio_path, MAX_PATH)) {
		fwprintf(stderr, L"Invalid --block-name.\n");
		return 2;
	}

	disk_size = config->disk_size ? config->disk_size
								  : memfs_block_default_disk_size(config->capacity_auto, config->capacity);
	if (disk_size < 64 * MIB || (disk_size % MEMFS_BLOCK_SECTOR_SIZE) != 0) {
		fwprintf(stderr, L"The virtual disk size must be at least 64 MiB and a multiple of 512 bytes.\n");
		return 2;
	}

	memset(&options, 0, sizeof(options));
	options.capacity = config->capacity;
	options.capacity_auto = config->capacity_auto;
	options.auto_reserve_bytes = config->capacity_auto ? config->auto_reserve : 0;
	options.volume_label = config->volume_label;
	options.compression_enabled = config->compression_enabled;
	options.compression_level = config->compression_level;
	options.encryption_enabled = config->encryption_enabled;
	options.encryption_key = config->encryption_key;
	options.encryption_key_size = config->encryption_key_size;
	options.block_backing = true;
	if (memfs_create_ex(&options, &fs) != MEMFS_OK) {
		fwprintf(stderr, L"Cannot create the memory store.\n");
		return 3;
	}
	if (memfs_block_create(fs, disk_size, 0, &block) != MEMFS_OK) {
		fwprintf(stderr, L"Cannot create the block store.\n");
		goto cleanup;
	}

	error = memfs_devio_start(block, object_name, config->threads, 0, &devio);
	if (error != ERROR_SUCCESS) {
		if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
			fwprintf(stderr, L"The DevIoDrv driver is not available. Install Arsenal Image Mounter "
							 L"(aim_ll --install <driver files>) and start the deviodrv service.\n");
		else
			fwprintf(stderr, L"Cannot open %ls: Win32 error %lu.\n", devio_path, error);
		exit_code = 4;
		goto cleanup;
	}

	/* Attach as a parallel-I/O file disk on our DevIoDrv object, then let
	 * aim_ll partition, quick-format NTFS and assign the drive letter. */
	_snwprintf(arguments, 1024, L"-a -t file -o par,fix -f \"%ls\" -p \"/fs:ntfs /q /y /v:%ls\" -m %ls", devio_path,
			   config->volume_label, drive);
	arguments[1023] = 0;
	attach_output = calloc(1, 16384);
	/* Attaching and formatting a large disk can take a while. */
	if (config->report_progress != NULL)
		(void)config->report_progress(config->callback_context, 120000);
	aim_result = run_aim_ll(aim_ll, arguments, attach_output, attach_output ? 16384 : 0);
	/* Once the device exists it must be detached on every path, even if a
	 * later step (partitioning, formatting, drive letter) failed. */
	attached = parse_created_unit(attach_output, unit);
	if (aim_result == 0 && !attached) {
		fwprintf(stderr, L"aim_ll did not report the created device number.\n");
		aim_result = -1;
	}
	if (aim_result != 0) {
		fwprintf(stderr, L"aim_ll could not attach the disk (exit %d).\n", aim_result);
		exit_code = 5;
		goto cleanup;
	}
	if (!memfs_devio_wait_connected(devio, 10000)) {
		fwprintf(stderr, L"The attached disk did not start I/O.\n");
		exit_code = 5;
		goto cleanup;
	}

	if (!create_initial_directories(config, drive)) {
		exit_code = 4;
		goto cleanup;
	}
	if (config->report_ready != NULL && !config->report_ready(config->callback_context)) {
		exit_code = 6;
		goto cleanup;
	}

	wprintf(L"memfs block device %ls is ready: %llu bytes virtual NTFS disk, capacity %ls.\n", drive,
			(unsigned long long)disk_size, config->capacity_auto ? L"auto (follows free memory)" : L"fixed");
	fflush(stdout);
	if (config->stats)
		print_block_stats(fs, devio, "mounted", config->stats_json);

	{
		HANDLE events[1] = {stop_event};

		for (;;) {
			DWORD wait = WaitForMultipleObjects(1, events, FALSE, 1000);

			if (wait == WAIT_OBJECT_0)
				break;
			if (memfs_devio_wait_closed(devio, 0)) {
				MemfsDevioStats io;

				memfs_devio_get_stats(devio, &io);
				if (io.client_closed) {
					/* Not a requested stop: report failure so a service
					 * restarts and brings the volume back. */
					fwprintf(stderr, L"The disk was detached externally.\n");
					attached = false;
					exit_code = 8;
				} else {
					/* Workers failed while the disk is attached: detach it
					 * below rather than leave a dead device behind. */
					fwprintf(stderr, L"The block I/O workers stopped; detaching the disk.\n");
					exit_code = 7;
				}
				break;
			}
		}
	}
	if (exit_code != 7 && exit_code != 8)
		exit_code = 0;

cleanup:
	if (attached) {
		int attempt;

		if (config->stats)
			print_block_stats(fs, devio, "stopping", config->stats_json);
		_snwprintf(arguments, 1024, L"-d -u %ls", unit);
		for (attempt = 0; attempt < 3 && run_aim_ll(aim_ll, arguments, NULL, 0) != 0; attempt++)
			Sleep(1000);
		if (attempt == 3) {
			/* Still in use: force removal so the process can exit. */
			_snwprintf(arguments, 1024, L"-D -u %ls", unit);
			if (run_aim_ll(aim_ll, arguments, NULL, 0) != 0 && exit_code == 0)
				exit_code = 6;
		}
		(void)memfs_devio_wait_closed(devio, 10000);
	}
	free(attach_output);
	memfs_devio_stop(devio);
	memfs_block_destroy(block);
	memfs_destroy(fs);
	return exit_code;
}
