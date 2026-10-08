#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "cryptfs_backend.h"

BOOL cryptfs_test_parse_options(int argc, WCHAR **argv);
BOOL cryptfs_test_dispatcher_result_success(NTSTATUS status, BOOL explicit_stop_request);

static int expect_parse(BOOL expected, int argc, WCHAR **argv, const WCHAR *label)
{
	BOOL actual = cryptfs_test_parse_options(argc, argv);
	if (actual != expected) {
		fwprintf(stderr, L"CLI parser case failed: %ls\n", label);
		return 1;
	}
	return 0;
}

int wmain(void)
{
	int failures = 0;
	WCHAR *valid[] = { L"cryptfs", L"--container", L"a.cfs", L"--mount", L"X:",
		L"--create", L"--capacity", L"1099511627776", L"--compression-level", L"3",
		L"--password-stdin" };
	WCHAR *bad_level[] = { L"cryptfs", L"--container", L"a.cfs", L"--mount", L"X:",
		L"--compression-level", L"3junk", L"--password-stdin" };
	WCHAR *bad_capacity[] = { L"cryptfs", L"--container", L"a.cfs", L"--mount", L"X:",
		L"--create", L"--capacity", L"10x", L"--password-stdin" };
	WCHAR *bad_check_mount[] = { L"cryptfs", L"--container", L"a.cfs", L"--check",
		L"--mount", L"X:", L"--password-stdin" };
	WCHAR *check_args[] = { L"cryptfs", L"--container", L"a.cfs", L"--check", L"--password-stdin" };
	WCHAR *compact[] = { L"cryptfs", L"--container", L"a.cfs", L"--compact", L"--password-stdin" };
	WCHAR *help[] = { L"cryptfs", L"--help" };
	failures += expect_parse(TRUE, _countof(valid), valid, L"valid create mount");
	failures += expect_parse(FALSE, _countof(bad_level), bad_level, L"strict compression integer");
	failures += expect_parse(FALSE, _countof(bad_capacity), bad_capacity, L"strict capacity integer");
	failures += expect_parse(FALSE, _countof(bad_check_mount), bad_check_mount, L"check excludes mount");
	failures += expect_parse(TRUE, _countof(check_args), check_args, L"check mode");
	failures += expect_parse(TRUE, _countof(compact), compact, L"compact mode");
	failures += expect_parse(TRUE, _countof(help), help, L"help mode");
	if (!cryptfs_test_dispatcher_result_success(STATUS_SUCCESS, FALSE)) {
		fwprintf(stderr, L"CLI dispatcher case failed: successful stop without request\n");
		++failures;
	}
	if (!cryptfs_test_dispatcher_result_success(STATUS_CANCELLED, TRUE)) {
		fwprintf(stderr, L"CLI dispatcher case failed: explicit stop cancellation\n");
		++failures;
	}
	if (cryptfs_test_dispatcher_result_success(STATUS_CANCELLED, FALSE)) {
		fwprintf(stderr, L"CLI dispatcher case failed: unsolicited cancellation\n");
		++failures;
	}
	if (cryptfs_test_dispatcher_result_success((NTSTATUS)0xC0000001L, TRUE)) {
		fwprintf(stderr, L"CLI dispatcher case failed: explicit stop masks unrelated error\n");
		++failures;
	}
	return failures == 0 ? 0 : 1;
}
